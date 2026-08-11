package main

import (
	"context"
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
	incoming chan evidence.Event
}

// NewBatcher builds a Batcher that flushes via submit (typically
// (*EventClient).Submit).
func NewBatcher(submit func([]evidence.Event) error) *Batcher {
	return &Batcher{
		submit:   submit,
		incoming: make(chan evidence.Event, 4096),
	}
}

// Add queues an event for the next flush. It blocks only if the internal
// queue is saturated, which is deliberate backpressure rather than a drop.
func (b *Batcher) Add(ev evidence.Event) {
	b.incoming <- ev
}

// Run drains the incoming queue, flushing batches on size or interval,
// until ctx is cancelled, then makes a bounded best-effort final drain
// before returning.
func (b *Batcher) Run(ctx context.Context) {
	ticker := time.NewTicker(batchFlushInterval)
	defer ticker.Stop()

	var pending []evidence.Event
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
		backoff = backoffInitial
	}

	for {
		select {
		case ev := <-b.incoming:
			pending = append(pending, ev)
			if len(pending) >= batchMaxSize {
				trySend()
			}
		case <-ticker.C:
			trySend()
		case <-ctx.Done():
			b.finalDrain(&pending)
			return
		}
	}
}

// finalDrain collects whatever is already queued and makes a short,
// bounded series of delivery attempts (DESIGN.md main: "POST a final
// drain and exit 0"). Anything still undelivered afterward is logged and
// given up on, since there is no later flush cycle once the process exits.
func (b *Batcher) finalDrain(pending *[]evidence.Event) {
	draining := true
	for draining {
		select {
		case ev := <-b.incoming:
			*pending = append(*pending, ev)
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
	}
	if len(*pending) > 0 {
		log.Printf("agent: final drain gave up with %d events undelivered", len(*pending))
	}
}
