package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func TestBatcherAddAndFlushPreservesAcceptedSourceOrder(t *testing.T) {
	accepted := make(chan []evidence.Event, 2)
	release := make(chan struct{})
	batch := NewBatcher(func(events []evidence.Event) error {
		copyOfEvents := append([]evidence.Event(nil), events...)
		accepted <- copyOfEvents
		<-release
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	batchDone := make(chan struct{})
	go func() {
		batch.Run(ctx)
		close(batchDone)
	}()

	sourceDone := make(chan struct{})
	go func() {
		batch.AddAndFlush(ctx, evidence.Event{Name: evidence.EventProcessExecuted})
		batch.AddAndFlush(ctx, evidence.Event{Name: evidence.EventProcessExited})
		close(sourceDone)
	}()

	first := receiveBatch(t, accepted)
	if len(first) != 1 || first[0].Name != evidence.EventProcessExecuted {
		t.Fatalf("first accepted batch = %+v, want process.executed", first)
	}
	select {
	case second := <-accepted:
		t.Fatalf("second batch submitted before first was accepted: %+v", second)
	default:
	}
	release <- struct{}{}

	second := receiveBatch(t, accepted)
	if len(second) != 1 || second[0].Name != evidence.EventProcessExited {
		t.Fatalf("second accepted batch = %+v, want process.exited", second)
	}
	release <- struct{}{}

	select {
	case <-sourceDone:
	case <-time.After(time.Second):
		t.Fatal("source did not resume after both lifecycle events were accepted")
	}
	cancel()
	select {
	case <-batchDone:
	case <-time.After(time.Second):
		t.Fatal("batcher did not stop")
	}
}

func TestBatcherAddAndFlushReportsBoundedDeliveryFailure(t *testing.T) {
	batch := NewBatcher(func([]evidence.Event) error { return errors.New("broker unavailable") })
	batchCtx, cancelBatch := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		batch.Run(batchCtx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := batch.AddAndFlush(ctx, evidence.Event{Name: evidence.EventProcessExecuted}); err == nil {
		t.Fatal("AddAndFlush succeeded without broker acceptance")
	}
	cancelBatch()
	<-done
}

// TestBatcherCoalescesAQueuedBurstIntoBoundedBatches is the throughput
// regression guard: one POST per event capped process evidence near 30 events/s, so
// a fork storm outran the guest and its unread export tail was dropped. A burst that
// is already queued must leave as whole batches, in source order, bounded by
// batchMaxCoalesced so no single body can exceed the broker's ingest limit.
func TestBatcherCoalescesAQueuedBurstIntoBoundedBatches(t *testing.T) {
	const burst = 2 * batchMaxCoalesced
	var mu sync.Mutex
	var sizes []int
	var order []string
	delivered := make(chan struct{}, 1)
	batch := NewBatcher(func(events []evidence.Event) error {
		mu.Lock()
		sizes = append(sizes, len(events))
		for _, ev := range events {
			order = append(order, ev.Body)
		}
		done := len(order) == burst
		mu.Unlock()
		if done {
			delivered <- struct{}{}
		}
		return nil
	})

	// Queue the whole burst before the batcher runs, so what it observes is a
	// backlog rather than a race with the producer.
	for i := 0; i < burst; i++ {
		batch.Add(evidence.Event{Name: evidence.EventProcessExecuted, Body: strconv.Itoa(i)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		batch.Run(ctx)
	}()

	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		mu.Lock()
		got := len(order)
		mu.Unlock()
		t.Fatalf("delivered %d of %d events", got, burst)
	}
	cancel()
	<-batchDone

	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 2 {
		t.Fatalf("submissions = %v, want two batches of %d", sizes, batchMaxCoalesced)
	}
	for _, size := range sizes {
		if size != batchMaxCoalesced {
			t.Fatalf("batch size = %d, want %d", size, batchMaxCoalesced)
		}
	}
	for i, body := range order {
		if body != strconv.Itoa(i) {
			t.Fatalf("event %d = %q, want source order preserved", i, body)
		}
	}
}

// TestBatcherFlushesALoneEventWithoutWaitingForTheInterval keeps the coalescing
// above from turning into added latency: with nothing else queued there is nothing
// to wait for, so the event goes out immediately rather than on the next tick.
func TestBatcherFlushesALoneEventWithoutWaitingForTheInterval(t *testing.T) {
	submitted := make(chan time.Time, 1)
	batch := NewBatcher(func([]evidence.Event) error {
		submitted <- time.Now()
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		batch.Run(ctx)
	}()

	start := time.Now()
	batch.Add(evidence.Event{Name: evidence.EventProcessExecuted})
	select {
	case at := <-submitted:
		if waited := at.Sub(start); waited >= batchFlushInterval {
			t.Fatalf("lone event waited %s, want a flush well inside the %s interval", waited, batchFlushInterval)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lone event was never submitted")
	}
	cancel()
	<-batchDone
}

// TestFinalDrainReportsTheEventsItCouldNotDeliver is the last-gasp honesty guard: when
// the agent exits with events still queued they are gone, and a gap nobody reported is
// the failure mode that let a storm seal as a clean session at 8% fidelity. One
// single-event POST fits in a grace the backlog itself did not.
func TestFinalDrainReportsTheEventsItCouldNotDeliver(t *testing.T) {
	var mu sync.Mutex
	var lastGasp []evidence.Event
	batch := NewBatcher(func(events []evidence.Event) error {
		mu.Lock()
		defer mu.Unlock()
		// Only the one-event loss report is accepted; the backlog itself never lands.
		if len(events) == 1 && events[0].Name == evidence.EventSensorLoss {
			lastGasp = append([]evidence.Event(nil), events...)
			return nil
		}
		return errors.New("broker unavailable")
	})

	const queued = 7
	for i := 0; i < queued; i++ {
		batch.Add(evidence.Event{Name: evidence.EventProcessExecuted, Body: strconv.Itoa(i)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		batch.Run(ctx)
	}()
	cancel()
	select {
	case <-batchDone:
	case <-time.After(10 * time.Second):
		t.Fatal("batcher did not finish its bounded final drain")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(lastGasp) != 1 {
		t.Fatalf("last-gasp submissions = %+v, want a single sensor.loss event", lastGasp)
	}
	reason, _ := lastGasp[0].Attrs[attrSensorReason].(string)
	if !strings.Contains(reason, "7 event(s) undelivered at teardown") {
		t.Fatalf("sensor.loss reason = %q, want the undelivered count", reason)
	}
}

func receiveBatch(t *testing.T, batches <-chan []evidence.Event) []evidence.Event {
	t.Helper()
	select {
	case batch := <-batches:
		return batch
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for batch submission")
		return nil
	}
}
