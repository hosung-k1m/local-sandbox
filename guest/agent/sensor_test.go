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
	"sync"
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

func TestTetragonLossTotalRecognizesV12LossCounters(t *testing.T) {
	for name := range tetragonLossMetrics {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, "%s 1\n", name)
			}))
			defer server.Close()
			total, err := tetragonLossTotal(context.Background(), server.URL, tetragonLossMetrics)
			if err != nil || total != 1 {
				t.Fatalf("tetragonLossTotal = %v, %v, want 1, nil", total, err)
			}
		})
	}
}

func TestTetragonLossTotalIsBaselineRelative(t *testing.T) {
	value := 5.0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "tetragon_bpf_missed_events_total{error=\"ENOENT\"} %g\n", value)
	}))
	defer server.Close()

	// Boot noise captured as the baseline is not loss.
	baseline, err := tetragonLossTotal(context.Background(), server.URL, tetragonLossMetrics)
	if err != nil || baseline != 5 {
		t.Fatalf("tetragonLossTotal = %v, %v, want 5, nil", baseline, err)
	}
	if total, err := tetragonLossTotal(context.Background(), server.URL, tetragonLossMetrics); err != nil || total > baseline {
		t.Fatalf("tetragonLossTotal at baseline = %v, %v, want %v, nil", total, err, baseline)
	}

	// A post-baseline increase is genuine loss.
	value = 6
	if total, err := tetragonLossTotal(context.Background(), server.URL, tetragonLossMetrics); err != nil || total <= baseline {
		t.Fatalf("tetragonLossTotal after increase = %v, %v, want > %v, nil", total, err, baseline)
	}
}

func TestTetragonLossTotalAcceptsZeroCounters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, `tetragon_bpf_missed_events_total{opcode="1",error="ENOENT"} 0`)
	}))
	defer server.Close()
	total, err := tetragonLossTotal(context.Background(), server.URL, tetragonLossMetrics)
	if err != nil || total != 0 {
		t.Fatalf("tetragonLossTotal = %v, %v, want 0, nil", total, err)
	}
}

// The readiness gate must not see the counters a fresh VM bumps just by booting, or a
// healthy session degrades to procfs before the workload launches.
func TestTetragonReadinessLossMetricsExcludeBootNoise(t *testing.T) {
	for name := range tetragonReadinessLossMetrics {
		if !tetragonLossMetrics[name] {
			t.Errorf("readiness-blocking counter %s is not in the ongoing loss set", name)
		}
	}
	for _, bootNoisy := range []string{"tetragon_bpf_missed_events_total", "tetragon_events_missing_process_info_total"} {
		if !tetragonLossMetrics[bootNoisy] {
			t.Errorf("%s should still be watched for ongoing loss", bootNoisy)
		}
		if tetragonReadinessLossMetrics[bootNoisy] {
			t.Errorf("%s is boot noise and must not block readiness", bootNoisy)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, `tetragon_bpf_missed_events_total{error="ENOENT"} 17`)
		_, _ = fmt.Fprintln(w, `tetragon_events_missing_process_info_total 4`)
	}))
	defer server.Close()
	if total, err := tetragonLossTotal(context.Background(), server.URL, tetragonReadinessLossMetrics); err != nil || total != 0 {
		t.Fatalf("readiness loss total under boot noise = %v, %v, want 0, nil", total, err)
	}
	if total, err := tetragonLossTotal(context.Background(), server.URL, tetragonLossMetrics); err != nil || total != 21 {
		t.Fatalf("ongoing loss total under boot noise = %v, %v, want 21, nil", total, err)
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

// TestMonitorTetragonHealthRequiresConsecutiveBadPolls guards the hair trigger:
// declaring loss on one bad poll degraded healthy sessions on nothing more than a
// slow probe or a metrics endpoint that had not come up yet.
func TestMonitorTetragonHealthRequiresConsecutiveBadPolls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	polls := 0
	got := monitorTetragonHealthWithPollsBeforeLoss(ctx, path, "tetragon", time.Millisecond, time.Second, 3, func(context.Context) error {
		polls++
		if polls == 1 {
			return errors.New("metrics endpoint not up yet")
		}
		return appendLogLine(path, "{}\n")
	})
	if got != "tetragon" {
		t.Fatalf("monitorTetragonHealthWithPollsBeforeLoss = %q, want tetragon across an isolated bad poll", got)
	}
	if polls < 3 {
		t.Fatalf("polls = %d, want the monitor to keep polling past the hiccup", polls)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	polls = 0
	got = monitorTetragonHealthWithPollsBeforeLoss(ctx, path, "tetragon", time.Millisecond, time.Second, 3, func(context.Context) error {
		polls++
		return errors.New("probe failed")
	})
	if got != "procfs" {
		t.Fatalf("monitorTetragonHealthWithPollsBeforeLoss = %q, want procfs after sustained failure", got)
	}
	if polls != 3 {
		t.Fatalf("polls before declaring loss = %d, want exactly 3", polls)
	}
}

func TestSensorLossIsRecordedWithoutTouchingTheWorkload(t *testing.T) {
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
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		batch.Run(ctx)
	}()

	recordSensorLoss(ctx, batch, "test loss")
	if !submitted {
		t.Fatal("sensor.loss was not accepted")
	}
	// Degradation must leave both the running workload and the readiness marker
	// alone: procfs keeps recording, so yanking readiness would only block a
	// session from launching (or restarting) for no evidentiary gain.
	if _, err := os.Stat(readyPath); err != nil {
		t.Fatalf("readiness marker withdrawn on degradation: %v", err)
	}
}

// TestProcessSensorFallsBackToProcfsReadinessWithoutStoppingTheWorkload drives the
// real degradation path and is the regression guard for both halves of last night's
// failures: a Tetragon that never satisfies the readiness gate used to leave the
// marker unpublished until the host's health gate aborted the session, and the loss
// handling used to SIGKILL the workload on the way.
func TestProcessSensorFallsBackToProcfsReadinessWithoutStoppingTheWorkload(t *testing.T) {
	oldFallback := readinessFallbackAfter
	readinessFallbackAfter = 20 * time.Millisecond
	t.Cleanup(func() { readinessFallbackAfter = oldFallback })
	var stopCalls atomic.Int64
	stopWorkloadFunc = func(context.Context) error {
		stopCalls.Add(1)
		return nil
	}
	t.Cleanup(func() { stopWorkloadFunc = stopWorkload })

	recorded := make(chan evidence.Event, 64)
	batch := NewBatcher(func(events []evidence.Event) error {
		for _, ev := range events {
			recorded <- ev
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		batch.Run(ctx)
	}()

	ready := make(chan struct{})
	var readyOnce sync.Once
	sensorDone := make(chan error, 1)
	go func() {
		// A Tetragon export that never appears stands in for a Tetragon that
		// cannot satisfy readiness (no fork policy, no metrics endpoint, dead BPF).
		sensorDone <- runProcessSensor(ctx, Config{
			TetragonLog: filepath.Join(t.TempDir(), "never-created.log"),
			WorkloadUID: 9_999_999,
		}, batch, func() { readyOnce.Do(func() { close(ready) }) })
	}()

	select {
	case <-ready:
	case err := <-sensorDone:
		t.Fatalf("process sensor returned before publishing readiness: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("process sensor never published readiness after the bounded Tetragon window")
	}
	cancel()
	if err := <-sensorDone; err != nil {
		t.Fatalf("runProcessSensor: %v", err)
	}
	<-batchDone

	if got := stopCalls.Load(); got != 0 {
		t.Fatalf("workload stop attempts during degradation = %d, want 0", got)
	}
	close(recorded)
	var started, loss, restarted *evidence.Event
	for ev := range recorded {
		event := ev
		switch event.Name {
		case evidence.EventSensorStarted:
			started = &event
		case evidence.EventSensorLoss:
			loss = &event
		case evidence.EventSensorRestarted:
			restarted = &event
		}
	}
	if started == nil || started.Attrs[attrSensorMechanism] != "tetragon" {
		t.Fatalf("sensor.started = %+v, want mechanism tetragon", started)
	}
	if loss == nil || !strings.Contains(fmt.Sprint(loss.Attrs[attrSensorReason]), "readiness") {
		t.Fatalf("sensor.loss = %+v, want a readiness-window reason", loss)
	}
	if restarted == nil || restarted.Attrs[attrSensorMechanism] != "procfs" {
		t.Fatalf("sensor.restarted = %+v, want mechanism procfs", restarted)
	}
	if got := restarted.Attrs[attrSensorCoverage]; got != "incomplete: polling can miss short-lived processes" {
		t.Fatalf("procfs sensor.coverage = %v, want the incomplete-coverage marking", got)
	}
}

// TestReadinessFallbackRetiresOnceReadinessIsPublished is the regression guard for the
// zombie fallback timer: it was armed before readiness could possibly land and nothing
// disarmed it, so every session still running at the deadline recorded a spurious
// sensor.loss ("did not establish process-sensor readiness within 30s") and flipped a
// Tetragon sensor that had published readiness two seconds in over to procfs. Sessions
// that happened to finish inside the window masked it entirely.
func TestReadinessFallbackRetiresOnceReadinessIsPublished(t *testing.T) {
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "tetragon_observer_ringbuf_events_lost_total 0")
	}))
	defer metrics.Close()
	oldURL := tetragonMetricsURL
	tetragonMetricsURL = metrics.URL
	t.Cleanup(func() { tetragonMetricsURL = oldURL })
	oldInterval := readinessMetricsRetryInterval
	readinessMetricsRetryInterval = time.Millisecond
	t.Cleanup(func() { readinessMetricsRetryInterval = oldInterval })
	oldFallback := readinessFallbackAfter
	readinessFallbackAfter = 200 * time.Millisecond
	t.Cleanup(func() { readinessFallbackAfter = oldFallback })

	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	recorded := make(chan evidence.Event, 64)
	batch := NewBatcher(func(events []evidence.Event) error {
		for _, ev := range events {
			recorded <- ev
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		batch.Run(ctx)
	}()
	ready := make(chan struct{})
	var readyOnce sync.Once
	sensorDone := make(chan error, 1)
	go func() {
		sensorDone <- runProcessSensor(ctx, Config{TetragonLog: path, WorkloadUID: 4242}, batch, func() {
			readyOnce.Do(func() { close(ready) })
		})
	}()

	// Root-owned probe rounds satisfy the fork/exec/exit gate and keep feeding the
	// export until the settling scrape agrees, exactly as the liveness probe does.
	probeLifecycleUntilReady(t, path, ready)
	select {
	case <-ready:
	case err := <-sensorDone:
		t.Fatalf("process sensor returned before publishing Tetragon readiness: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Tetragon never published readiness against a healthy metrics endpoint")
	}

	// Outlive the fallback window by a wide margin: this is the whole bug.
	time.Sleep(3 * readinessFallbackAfter)
	cancel()
	if err := <-sensorDone; err != nil {
		t.Fatalf("runProcessSensor: %v", err)
	}
	<-batchDone

	close(recorded)
	var losses, restarts int
	for ev := range recorded {
		switch ev.Name {
		case evidence.EventSensorLoss:
			t.Errorf("sensor.loss after readiness was established: %v", ev.Attrs[attrSensorReason])
			losses++
		case evidence.EventSensorRestarted:
			t.Errorf("sensor.restarted after readiness was established: %v", ev.Attrs[attrSensorMechanism])
			restarts++
		}
	}
	if losses != 0 || restarts != 0 {
		t.Fatalf("healthy session past the fallback window recorded %d loss(es) and %d restart(s), want none", losses, restarts)
	}
}

func TestSensorLossSurvivesABrokerThatDoesNotAcceptTheFlush(t *testing.T) {
	oldTimeout := sensorLossFlushTimeout
	sensorLossFlushTimeout = 10 * time.Millisecond
	t.Cleanup(func() { sensorLossFlushTimeout = oldTimeout })

	var accept atomic.Bool
	batch := NewBatcher(func([]evidence.Event) error {
		if accept.Load() {
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

	// The bounded flush gives up without blocking the sensor; the event stays
	// queued for the batcher's retry, which the final drain then delivers.
	recordSensorLoss(ctx, batch, "test loss")
	accept.Store(true)
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

// TestStopWorkloadToleratesUnitThatIsNotLoaded covers the pre-launch case: before
// the harness starts (and after it exits and is collected) systemctl kill/stop both
// exit nonzero for "no such unit". Treating that as a failure is what crash-looped
// the supervisor until systemd retired it, so readiness was never published.
func TestStopWorkloadToleratesUnitThatIsNotLoaded(t *testing.T) {
	var calls [][]string
	err := stopWorkloadWithRun(context.Background(), func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		// is-active exits nonzero for inactive, failed, and not-found alike.
		return errors.New("Unit boxedai-session.service not loaded")
	})
	if err != nil {
		t.Fatalf("stopWorkloadWithRun on a not-loaded unit = %v, want nil", err)
	}
	if len(calls) != 3 || !reflect.DeepEqual(calls[2], []string{"is-active", "--quiet", "boxedai-session.service"}) {
		t.Fatalf("systemctl calls = %v, want kill, stop, then an is-active confirmation", calls)
	}
}

func TestStopWorkloadReportsFailureWhileTheUnitIsStillActive(t *testing.T) {
	err := stopWorkloadWithRun(context.Background(), func(_ context.Context, args ...string) error {
		if args[0] == "is-active" {
			return nil // still running: the stop genuinely failed
		}
		return errors.New("kill failed")
	})
	if err == nil || !strings.Contains(err.Error(), "kill failed") {
		t.Fatalf("stopWorkloadWithRun error = %v, want the kill failure", err)
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
