package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"boxedai/internal/evidence"
)

const (
	// batchFlushInterval and batchMaxSize implement DESIGN.md's "batched
	// (flush every ~500ms or 50 events)".
	batchFlushInterval = 500 * time.Millisecond
	batchMaxSize       = 50

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

// AddAndFlush queues an event, triggers an immediate flush, and waits until
// the broker accepts the batch. Tetragon lifecycle events use this path so the
// watcher cannot advance past an exec/exit line while that observation still
// sits in the guest's timed batch. Cancellation stops the wait but leaves the
// already-queued event available to the batcher's final drain.
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

// Run drains the incoming queue, flushing batches on size or interval,
// until ctx is cancelled, then makes a bounded best-effort final drain
// before returning.
func (b *Batcher) Run(ctx context.Context) {
	ticker := time.NewTicker(batchFlushInterval)
	defer ticker.Stop()

	var pending []evidence.Event
	var flushWaiters []chan struct{}
	backoff := backoffInitial
	nextAttempt := time.Now()

	trySend := func() {
		if len(pending) == 0 || time.Now().Before(nextAttempt) {
			return
		}
		if err := b.submit(pending); err != nil {
			log.Printf("agent: submit %d events failed, will retry: %v", len(pending), err)
			nextAttempt = time.Now().Add(backoff)
			backoff = min(backoff*2, backoffMax)
			return
		}
		pending = nil
		for _, waiter := range flushWaiters {
			close(waiter)
		}
		flushWaiters = nil
		backoff = backoffInitial
	}

	for {
		select {
		case item := <-b.incoming:
			pending = append(pending, item.event)
			if item.flushed != nil {
				flushWaiters = append(flushWaiters, item.flushed)
			}
			if item.flushed != nil || len(pending) >= batchMaxSize {
				trySend()
			}
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
	for attempt := 1; attempt <= finalDrainAttempts && len(*pending) > 0; attempt++ {
		if err := b.submit(*pending); err != nil {
			log.Printf("agent: final drain attempt %d/%d failed: %v", attempt, finalDrainAttempts, err)
			time.Sleep(finalDrainDelay)
			continue
		}
		*pending = nil
		for _, waiter := range *flushWaiters {
			close(waiter)
		}
		*flushWaiters = nil
	}
	if len(*pending) > 0 {
		log.Printf("agent: final drain gave up with %d events undelivered", len(*pending))
	}
}
