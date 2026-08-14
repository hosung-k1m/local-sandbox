package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func TestTetragonHealthy_MissingFile(t *testing.T) {
	healthy, size := tetragonHealthy(filepath.Join(t.TempDir(), "nope.log"), -1, time.Now())
	if healthy {
		t.Error("want unhealthy for a missing file")
	}
	if size != -1 {
		t.Errorf("size = %d, want -1", size)
	}
}

func TestTetragonMetricsLostRecognizesV12LossCounters(t *testing.T) {
	for name := range tetragonLossMetrics {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, "%s 1\n", name)
			}))
			defer server.Close()
			lost, err := tetragonMetricsLost(context.Background(), server.URL, 0)
			if err != nil || !lost {
				t.Fatalf("tetragonMetricsLost = %v, %v, want true, nil", lost, err)
			}
		})
	}
}

func TestTetragonMetricsLostIsBaselineRelative(t *testing.T) {
	value := 5.0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "tetragon_bpf_missed_events_total{error=\"ENOENT\"} %g\n", value)
	}))
	defer server.Close()

	// Boot noise captured as the baseline is not loss.
	baseline, err := tetragonLossTotal(context.Background(), server.URL)
	if err != nil || baseline != 5 {
		t.Fatalf("tetragonLossTotal = %v, %v, want 5, nil", baseline, err)
	}
	if lost, err := tetragonMetricsLost(context.Background(), server.URL, baseline); err != nil || lost {
		t.Fatalf("tetragonMetricsLost at baseline = %v, %v, want false, nil", lost, err)
	}

	// A post-baseline increase is genuine loss.
	value = 6
	if lost, err := tetragonMetricsLost(context.Background(), server.URL, baseline); err != nil || !lost {
		t.Fatalf("tetragonMetricsLost after increase = %v, %v, want true, nil", lost, err)
	}
}

func TestTetragonMetricsLostAcceptsZeroCounters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, `tetragon_bpf_missed_events_total{opcode="1",error="ENOENT"} 0`)
	}))
	defer server.Close()
	lost, err := tetragonMetricsLost(context.Background(), server.URL, 0)
	if err != nil || lost {
		t.Fatalf("tetragonMetricsLost = %v, %v, want false, nil", lost, err)
	}
}

func TestTetragonHealthy_FirstObservationExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	healthy, size := tetragonHealthy(path, -1, time.Now())
	if !healthy {
		t.Error("want healthy on first observation of an existing file")
	}
	if size != 3 {
		t.Errorf("size = %d, want 3", size)
	}
}

func TestTetragonHealthy_FirstObservationRejectsStaleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	staleTime := time.Now().Add(-2 * tetragonStaleAfter)
	if err := os.Chtimes(path, staleTime, staleTime); err != nil {
		t.Fatalf("age fixture: %v", err)
	}

	healthy, _ := tetragonHealthy(path, -1, time.Now())
	if healthy {
		t.Error("want unhealthy for a stale file on first observation")
	}
}

func TestTetragonHealthy_Growth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	healthy, _ := tetragonHealthy(path, 3, time.Now())
	if !healthy {
		t.Error("want healthy when the file has grown since the last poll")
	}
}

func TestTetragonHealthy_StaleNoGrowth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// No growth, and the last check was well past the stale window.
	healthy, _ := tetragonHealthy(path, 3, time.Now().Add(-2*tetragonStaleAfter))
	if healthy {
		t.Error("want unhealthy when stale with no growth")
	}
}

func TestTetragonHealthy_QuietButRecent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// No growth, but still within the grace window: a quiet workload is
	// not the same as a dead sensor.
	healthy, _ := tetragonHealthy(path, 3, time.Now())
	if !healthy {
		t.Error("want healthy within the grace window even without growth")
	}
}

func TestProcfsSensorEvidenceReportsIncompleteCoverage(t *testing.T) {
	for _, ev := range []struct {
		name  string
		event map[string]any
	}{
		{"started", newSensorStartedEvent("procfs").Attrs},
		{"restarted", newSensorRestartedEvent("process", "procfs").Attrs},
	} {
		t.Run(ev.name, func(t *testing.T) {
			if got := ev.event[attrSensorCoverage]; got != "incomplete: polling can miss short-lived processes" {
				t.Errorf("sensor.coverage = %v", got)
			}
		})
	}
	if _, ok := newSensorStartedEvent("tetragon").Attrs[attrSensorCoverage]; ok {
		t.Error("tetragon sensor.started unexpectedly reports procfs coverage")
	}
}

func TestProcfsWatcherSignalsReadyAfterInitialScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = runProcfsWatcher(ctx, Config{WorkloadUID: 9_999_999}, NewBatcher(func([]evidence.Event) error { return nil }), func() {
			close(ready)
		})
		close(done)
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("procfs watcher did not signal readiness after its initial scan")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("procfs watcher did not stop")
	}
}

func TestMonitorTetragonHealthUsesLastGrowthTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := monitorTetragonHealthWithIntervalsAndProbe(ctx, path, "tetragon", time.Millisecond, 10*time.Millisecond, func(context.Context) error {
		return nil
	})
	if got != "procfs" {
		t.Fatalf("monitorTetragonHealthWithIntervals = %q, want procfs after no growth", got)
	}
}

func TestTetragonLossStopsWorkloadBeforeRecordingLoss(t *testing.T) {
	readyPath := filepath.Join(t.TempDir(), "process-sensor-ready")
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("write readiness marker: %v", err)
	}
	submitted := false
	batch := NewBatcher(func(events []evidence.Event) error {
		if len(events) != 1 || events[0].Name != evidence.EventSensorLoss {
			t.Fatalf("submitted events = %+v, want sensor.loss", events)
		}
		submitted = true
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		batch.Run(ctx)
	}()

	handleTetragonLoss(ctx, batch, readyPath, "test loss", func(context.Context) error {
		if _, err := os.Stat(readyPath); !os.IsNotExist(err) {
			t.Fatalf("readiness marker still exists: %v", err)
		}
		return nil
	})
	if !submitted {
		t.Fatal("sensor.loss was not accepted after workload stopped")
	}
	cancel()
	<-done
}

func TestTetragonLossStopsWorkloadWhenBrokerDoesNotAcceptFlush(t *testing.T) {
	oldTimeout := sensorLossFlushTimeout
	sensorLossFlushTimeout = 10 * time.Millisecond
	t.Cleanup(func() { sensorLossFlushTimeout = oldTimeout })

	var stopped atomic.Bool
	batch := NewBatcher(func([]evidence.Event) error {
		if stopped.Load() {
			return nil
		}
		return errors.New("broker unavailable")
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		batch.Run(ctx)
	}()

	handleTetragonLoss(ctx, batch, filepath.Join(t.TempDir(), "missing-ready"), "test loss", func(context.Context) error {
		stopped.Store(true)
		return nil
	})
	if !stopped.Load() {
		t.Fatal("workload was not stopped after bounded sensor.loss flush")
	}
	cancel()
	<-done
}

func TestStopWorkloadKillsAllTasksBeforeStoppingUnit(t *testing.T) {
	var calls [][]string
	err := stopWorkloadWithRun(context.Background(), func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	})
	if err != nil {
		t.Fatalf("stopWorkloadWithRun: %v", err)
	}
	want := [][]string{
		{"kill", "--kill-whom=all", "--signal=SIGKILL", "boxedai-session.service"},
		{"stop", "boxedai-session.service"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("systemctl calls = %v, want %v", calls, want)
	}
}

func TestTetragonLossPropagatesWorkloadStopFailure(t *testing.T) {
	readyPath := filepath.Join(t.TempDir(), "process-sensor-ready")
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("write readiness marker: %v", err)
	}
	batch := NewBatcher(func([]evidence.Event) error { return nil })
	err := handleTetragonLoss(context.Background(), batch, readyPath, "test loss", func(context.Context) error {
		return errors.New("kill failed")
	})
	if err == nil || !strings.Contains(err.Error(), "kill failed") {
		t.Fatalf("handleTetragonLoss error = %v", err)
	}
	if _, statErr := os.Stat(readyPath); !os.IsNotExist(statErr) {
		t.Fatalf("readiness marker remains after fatal stop failure: %v", statErr)
	}
}

func TestMonitorTetragonHealthProbeGrowthKeepsQuietStreamHealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	probeCalls := 0
	got := monitorTetragonHealthWithIntervalsAndProbe(ctx, path, "tetragon", time.Millisecond, 5*time.Millisecond, func(context.Context) error {
		probeCalls++
		return appendLogLine(path, "{}\n")
	})
	if got != "tetragon" {
		t.Fatalf("monitorTetragonHealthWithIntervalsAndProbe = %q, want tetragon while probes grow the quiet export", got)
	}
	if probeCalls < 2 {
		t.Fatalf("probe calls = %d, want repeated liveness probes", probeCalls)
	}
}

func TestMonitorTetragonRecoveryRequiresGrowthAfterBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	got := monitorTetragonHealthWithIntervalsAndProbe(ctx, path, "procfs", time.Millisecond, time.Second, func(context.Context) error {
		return nil
	})
	if got != "procfs" {
		t.Fatalf("monitorTetragonHealthWithIntervals = %q, want procfs for fresh non-growing baseline", got)
	}

	probeCalls := 0
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got = monitorTetragonHealthWithIntervalsAndProbe(ctx, path, "procfs", time.Millisecond, time.Second, func(context.Context) error {
		probeCalls++
		if probeCalls == 1 {
			return nil
		}
		return appendLogLine(path, "{}\n")
	})
	if got != "tetragon" {
		t.Fatalf("monitorTetragonHealthWithIntervalsAndProbe = %q, want tetragon after post-baseline probe growth", got)
	}
	if probeCalls < 2 {
		t.Fatalf("probe calls = %d, want baseline followed by a growing probe", probeCalls)
	}
}
