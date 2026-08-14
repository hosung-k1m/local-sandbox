package main

import (
	"context"
	"errors"
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
