package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"boxedai/internal/evidence"
)

const (
	// batchFlushInterval and batchMaxCoalesced implement DESIGN.md's "ordered
	// micro-batches": flush as soon as the queue goes idle, at most
	// batchMaxCoalesced events per POST, with the timed flush as the floor.
	batchFlushInterval = 500 * time.Millisecond
	batchMaxCoalesced  = 500

	backoffInitial = 1 * time.Second
	backoffMax     = 30 * time.Second

	// finalDrainAttempts/finalDrainDelay bound the best-effort "final
	// drain" POST DESIGN.md asks for on stop; buffering otherwise
	// continues indefinitely across ordinary flush cycles.
	finalDrainAttempts = 3
	finalDrainDelay    = 500 * time.Millisecond
)

// Batcher accumulates evidence events and flushes them to the broker in
// batches, retrying with backoff on failure. Events are never dropped on a
// transient broker error: they stay queued for the next flush.
type Batcher struct {
	submit   func([]evidence.Event) error
	incoming chan batchItem
}

type batchItem struct {
	event   evidence.Event
	flushed chan struct{}
}

// NewBatcher builds a Batcher that flushes via submit (typically
// (*EventClient).Submit).
func NewBatcher(submit func([]evidence.Event) error) *Batcher {
	return &Batcher{
		submit:   submit,
		incoming: make(chan batchItem, 4096),
	}
}

// Add queues an event for the next flush. It blocks only if the internal
// queue is saturated, which is deliberate backpressure rather than a drop.
func (b *Batcher) Add(ev evidence.Event) {
	b.incoming <- batchItem{event: ev}
}

// AddAndFlush queues an event and waits until the broker has accepted it and
// everything queued ahead of it. Integrity events that the caller must not
// outrun use this path (sensor.loss before the mechanism it describes changes);
// high-rate observations use Add and rely on the queue's FIFO order instead, so
// one round trip per event cannot cap the sensor's throughput. Cancellation
// stops the wait but leaves the already-queued event available to the final drain.
func (b *Batcher) AddAndFlush(ctx context.Context, ev evidence.Event) error {
	flushed := make(chan struct{})
	select {
	case b.incoming <- batchItem{event: ev, flushed: flushed}:
	case <-ctx.Done():
		return fmt.Errorf("agent: queue lifecycle event: %w", ctx.Err())
	}
	select {
	case <-flushed:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("agent: flush lifecycle event: %w", ctx.Err())
	}
}

// Run drains the incoming queue, flushing whatever is queued as soon as the
// queue goes idle (with the interval tick as the floor and batchMaxCoalesced as
// the per-POST ceiling), until ctx is cancelled, then makes a bounded
// best-effort final drain before returning.
func (b *Batcher) Run(ctx context.Context) {
	ticker := time.NewTicker(batchFlushInterval)
	defer ticker.Stop()

	var pending []evidence.Event
	var flushWaiters []chan struct{}
	backoff := backoffInitial
	nextAttempt := time.Now()

	trySend := func() {
		for len(pending) > 0 && !time.Now().Before(nextAttempt) {
			chunk := nextChunk(pending)
			if err := b.submit(chunk); err != nil {
				log.Printf("agent: submit %d events failed, will retry: %v", len(chunk), err)
				nextAttempt = time.Now().Add(backoff)
				backoff = min(backoff*2, backoffMax)
				return
			}
			pending = pending[len(chunk):]
			backoff = backoffInitial
		}
		// Waiters are satisfied only once nothing is left queued ahead of them.
		if len(pending) == 0 {
			for _, waiter := range flushWaiters {
				close(waiter)
			}
			flushWaiters = nil
		}
	}

	// coalesce absorbs everything already queued into the pending batch, up to
	// batchMaxCoalesced. It only takes what is buffered, so a lone event is not
	// delayed while a burst of consecutive events becomes a single POST. One POST
	// per event was the guest's throughput ceiling (~30 events/s), far below the
	// rate a fork storm writes Tetragon lines.
	coalesce := func() {
		for len(pending) < batchMaxCoalesced {
			select {
			case item := <-b.incoming:
				pending = append(pending, item.event)
				if item.flushed != nil {
					flushWaiters = append(flushWaiters, item.flushed)
				}
			default:
				return
			}
		}
	}

	for {
		select {
		case item := <-b.incoming:
			pending = append(pending, item.event)
			if item.flushed != nil {
				flushWaiters = append(flushWaiters, item.flushed)
			}
			coalesce()
			trySend()
		case <-ticker.C:
			trySend()
		case <-ctx.Done():
			b.finalDrain(&pending, &flushWaiters)
			return
		}
	}
}

// finalDrain collects whatever is already queued and makes a short,
// bounded series of delivery attempts (DESIGN.md main: "POST a final
// drain and exit 0"). Anything still undelivered afterward is logged and
// given up on, since there is no later flush cycle once the process exits.
func (b *Batcher) finalDrain(pending *[]evidence.Event, flushWaiters *[]chan struct{}) {
	draining := true
	for draining {
		select {
		case item := <-b.incoming:
			*pending = append(*pending, item.event)
			if item.flushed != nil {
				*flushWaiters = append(*flushWaiters, item.flushed)
			}
		default:
			draining = false
		}
	}
	// Consecutive failures are what bound the drain: a chunk that lands resets
	// the count, so a backlog larger than one POST still gets delivered whole.
	failures := 0
	for len(*pending) > 0 && failures < finalDrainAttempts {
		chunk := nextChunk(*pending)
		if err := b.submit(chunk); err != nil {
			failures++
			log.Printf("agent: final drain attempt %d/%d failed: %v", failures, finalDrainAttempts, err)
			time.Sleep(finalDrainDelay)
			continue
		}
		*pending = (*pending)[len(chunk):]
		failures = 0
	}
	if len(*pending) > 0 {
		log.Printf("agent: final drain gave up with %d events undelivered", len(*pending))
		b.reportUndelivered(len(*pending))
		return
	}
	for _, waiter := range *flushWaiters {
		close(waiter)
	}
	*flushWaiters = nil
}

// reportUndelivered spends the agent's last act on saying that count events are being
// abandoned. Nothing else will: the process is exiting, so those events are gone, and a
// gap nobody reported is the worst outcome available — a fork storm that outran the
// pipeline used to seal as a clean session at 8% fidelity. One event fits in whatever
// grace is left even when the backlog did not, and the loss makes verification report
// INCOMPLETE with the count in the reason.
func (b *Batcher) reportUndelivered(count int) {
	loss := newSensorLossEvent("process", fmt.Sprintf("%d event(s) undelivered at teardown: the guest agent exited with them still queued for the broker", count))
	if err := b.submit([]evidence.Event{loss}); err != nil {
		log.Printf("agent: could not report %d undelivered events: %v", count, err)
	}
}

// nextChunk is the leading slice of events one POST may carry, so a large
// backlog is delivered as several bounded batches instead of one body the
// broker's ingest limit would reject outright.
func nextChunk(pending []evidence.Event) []evidence.Event {
	if len(pending) > batchMaxCoalesced {
		return pending[:batchMaxCoalesced]
	}
	return pending
}
