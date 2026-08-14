package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func TestParseTetragonLine_Exec(t *testing.T) {
	line := []byte(`{"time":"2026-08-13T19:00:00Z","process_exec":{"process":{"exec_id":"abc","pid":100,"uid":4242,"binary":"/usr/bin/node","arguments":"index.js","docker":"cg-1"},"parent":{"pid":1,"exec_id":"root"}}}`)

	tl, err := parseTetragonLine(line)
	if err != nil {
		t.Fatalf("parseTetragonLine: %v", err)
	}
	if tl.ProcessExec == nil {
		t.Fatal("ProcessExec is nil")
	}
	if tl.ProcessExit != nil {
		t.Fatal("ProcessExit should be nil for an exec line")
	}
	p := tl.ProcessExec.Process
	if p.Pid != 100 || p.Uid != 4242 || p.Binary != "/usr/bin/node" || p.Arguments != "index.js" || p.ExecID != "abc" || p.Docker != "cg-1" {
		t.Errorf("unexpected process fields: %+v", p)
	}
	if tl.ProcessExec.Parent.Pid != 1 {
		t.Errorf("Parent.Pid = %d, want 1", tl.ProcessExec.Parent.Pid)
	}
	if want := time.Date(2026, 8, 13, 19, 0, 0, 0, time.UTC); !tl.Time.Equal(want) {
		t.Fatalf("Time = %s, want %s", tl.Time, want)
	}
}

func TestTetragonEventTimeFallsBackOnlyWhenSourceAbsent(t *testing.T) {
	source := time.Date(2026, 8, 13, 19, 0, 0, 0, time.UTC)
	if got := tetragonEventTime(source); !got.Equal(source) {
		t.Fatalf("source time = %s, want %s", got, source)
	}
	before := time.Now()
	got := tetragonEventTime(time.Time{})
	if got.Before(before) || got.After(time.Now()) {
		t.Fatalf("fallback time = %s, want receipt time", got)
	}
}

func TestParseTetragonLine_Exit(t *testing.T) {
	line := []byte(`{"process_exit":{"process":{"exec_id":"abc","pid":100,"uid":4242,"binary":"/usr/bin/node"},"parent":{"pid":1},"status":1}}`)

	tl, err := parseTetragonLine(line)
	if err != nil {
		t.Fatalf("parseTetragonLine: %v", err)
	}
	if tl.ProcessExit == nil {
		t.Fatal("ProcessExit is nil")
	}
	if tl.ProcessExit.Status == nil || *tl.ProcessExit.Status != 1 {
		t.Errorf("Status = %v, want 1", tl.ProcessExit.Status)
	}
}

func TestParseTetragonLine_ExitSignalWithoutStatus(t *testing.T) {
	line := []byte(`{"process_exit":{"process":{"exec_id":"abc","pid":100,"uid":4242},"parent":{"exec_id":"root"},"signal":"SIGKILL"}}`)

	tl, err := parseTetragonLine(line)
	if err != nil {
		t.Fatalf("parseTetragonLine: %v", err)
	}
	if tl.ProcessExit.Status != nil || tl.ProcessExit.Signal != "SIGKILL" {
		t.Fatalf("exit status = %v signal = %q, want unknown code and SIGKILL", tl.ProcessExit.Status, tl.ProcessExit.Signal)
	}
}

func TestTetragonExitStatusTreatsOmittedProtojsonStatusAsZero(t *testing.T) {
	status := tetragonExitStatus(tetragonExitEvent{})
	if status.Code == nil || *status.Code != 0 || status.Signal != "" {
		t.Fatalf("status = %+v, want known zero exit", status)
	}
}

func TestTetragonExitStatusSignalTakesPrecedence(t *testing.T) {
	code := int64(0)
	status := tetragonExitStatus(tetragonExitEvent{Status: &code, Signal: "SIGKILL"})
	if status.Code != nil || status.Signal != "SIGKILL" {
		t.Fatalf("status = %+v, want signal only", status)
	}
}

func TestTetragonParentExecIDPrefersChildPayload(t *testing.T) {
	got := tetragonParentExecID(
		tetragonProcess{ParentExecID: "child-parent"},
		tetragonProcess{ExecID: "parent-object"},
	)
	if got != "child-parent" {
		t.Fatalf("parent exec id = %q, want child-parent", got)
	}
	if got := tetragonParentExecID(tetragonProcess{}, tetragonProcess{ExecID: "parent-object"}); got != "parent-object" {
		t.Fatalf("fallback parent exec id = %q, want parent-object", got)
	}
}

func TestParseTetragonLine_UnknownEventType(t *testing.T) {
	line := []byte(`{"process_kprobe":{"process":{"pid":5}}}`)

	tl, err := parseTetragonLine(line)
	if err != nil {
		t.Fatalf("parseTetragonLine: %v", err)
	}
	if tl.ProcessExec != nil || tl.ProcessExit != nil {
		t.Fatal("want both nil for an unrecognized event type")
	}
}

func TestParseTetragonLine_MalformedJSON(t *testing.T) {
	if _, err := parseTetragonLine([]byte(`{not json`)); err == nil {
		t.Fatal("parseTetragonLine: want error for malformed JSON, got nil")
	}
}

func TestValidateBuiltinLifecycleRejectsMissingIdentity(t *testing.T) {
	// A workload event missing pid or exec_id is fatal: evidence integrity
	// requires a resolved identity.
	for _, process := range []tetragonProcess{
		{Pid: 100, Uid: 4242},
		{ExecID: "exec", Uid: 4242},
	} {
		if resolved, err := validateBuiltinLifecycle(process, 4242); err == nil || resolved {
			t.Fatalf("validateBuiltinLifecycle(%+v) = %v, %v, want false, error", process, resolved, err)
		}
	}
	// A non-workload event Tetragon has not backfilled (pid 0 / no exec_id) is
	// unresolved: skipped, not fatal, so a system process cannot crash the sensor.
	if resolved, err := validateBuiltinLifecycle(tetragonProcess{Pid: 100, Uid: 0}, 4242); err != nil || resolved {
		t.Fatalf("validateBuiltinLifecycle unresolved non-workload = %v, %v, want false, nil", resolved, err)
	}
	if resolved, err := validateBuiltinLifecycle(tetragonProcess{Pid: 100, Uid: 0, ExecID: "exec"}, 4242); err != nil || !resolved {
		t.Fatalf("validateBuiltinLifecycle valid probe = %v, %v, want true, nil", resolved, err)
	}
}

func TestTetragonWatcherTreatsAnyMalformedCompleteJSONAsLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runTetragonWatcherWithMetrics(ctx, Config{TetragonLog: path, WorkloadUID: 4242}, NewBatcher(nil), func() {}, func(context.Context) (float64, error) { return 0, nil })
	}()
	time.Sleep(100 * time.Millisecond)
	if err := appendLogLine(path, "{malformed complete line}\n"); err != nil {
		t.Fatalf("append malformed line: %v", err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "malformed complete Tetragon JSON line") {
			t.Fatalf("watcher error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("watcher did not fail on malformed complete JSON")
	}
}

// TestTetragonWatcherSurvivesUnenrichedForkTracepoint is the other half of the S4
// regression: the unenriched fork must not end the watch, and the workload events that
// follow it must still be recorded — a healthy git workload cannot produce sensor.loss.
func TestTetragonWatcherSurvivesUnenrichedForkTracepoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	recorded := make(chan evidence.Event, 8)
	batch := NewBatcher(func(events []evidence.Event) error {
		for _, ev := range events {
			recorded <- ev
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		batch.Run(ctx)
	}()
	done := make(chan error, 1)
	go func() {
		done <- runTetragonWatcherWithMetrics(ctx, Config{TetragonLog: path, WorkloadUID: 4242}, batch, func() {}, func(context.Context) (float64, error) { return 0, nil })
	}()
	time.Sleep(100 * time.Millisecond)

	// A workload fork whose parent Tetragon has not enriched yet, then the child's own
	// exec, which carries the full identity the fork observation lacked.
	for _, line := range []string{
		`{"process_tracepoint":{"process":{"pid":4242,"uid":4242},"subsys":"sched","event":"sched_process_fork","args":[{"uint_arg":4242},{"uint_arg":4317}],"policy_name":"boxedai-process-fork"}}`,
		`{"process_exec":{"process":{"exec_id":"child-exec","pid":4317,"uid":4242,"binary":"/usr/bin/git"},"parent":{"pid":4242}}}`,
	} {
		if err := appendLogLine(path, line+"\n"); err != nil {
			t.Fatalf("append line: %v", err)
		}
	}

	select {
	case ev := <-recorded:
		if ev.Name != evidence.EventProcessExecuted {
			t.Fatalf("recorded %s, want only the child's process.executed", ev.Name)
		}
	case err := <-done:
		t.Fatalf("watcher died on an unenriched fork tracepoint: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("child exec after an unenriched fork was never recorded")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runTetragonWatcherWithMetrics: %v", err)
	}
	<-batchDone
}

func TestBelongsToWorkload(t *testing.T) {
	if !belongsToWorkload(4242, 4242) {
		t.Error("want uid 4242 to belong to workload 4242")
	}
	if belongsToWorkload(0, 4242) {
		t.Error("want uid 0 to not belong to workload 4242")
	}
}

func TestTetragonWatcherReadinessRequiresFreshProcessEvent(t *testing.T) {
	oldInterval := readinessMetricsRetryInterval
	readinessMetricsRetryInterval = time.Millisecond
	t.Cleanup(func() { readinessMetricsRetryInterval = oldInterval })

	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runTetragonWatcherWithMetrics(ctx, Config{TetragonLog: path, WorkloadUID: 4242}, NewBatcher(nil), func() {
			close(ready)
		}, func(context.Context) (float64, error) { return 0, nil })
	}()

	// Attachment and a parsed non-process line are not process-sensor
	// readiness. The delay gives the watcher time to establish its initial EOF.
	time.Sleep(100 * time.Millisecond)
	if err := appendLogLine(path, `{"process_kprobe":{"process":{"pid":5}}}`+"\n"); err != nil {
		t.Fatalf("append non-process event: %v", err)
	}
	select {
	case <-ready:
		t.Fatal("Tetragon watcher became ready without a process lifecycle event")
	case <-time.After(100 * time.Millisecond):
	}

	// Built-in lifecycle and fork-policy observations are both required. Root-owned
	// probe events prove both BPF paths but are filtered from workload evidence.
	if err := appendLogLine(path, `{"process_exec":{"process":{"exec_id":"probe","pid":100,"uid":0,"binary":"/usr/bin/test"},"parent":{"pid":1}}}`+"\n"); err != nil {
		t.Fatalf("append non-workload process event: %v", err)
	}
	select {
	case <-ready:
		t.Fatal("built-in lifecycle event established readiness without fork policy")
	case <-time.After(100 * time.Millisecond):
	}
	if err := appendLogLine(path, `{"process_tracepoint":{"process":{"exec_id":"probe","pid":100,"uid":0},"subsys":"sched","event":"sched_process_fork","args":[{"uint_arg":100},{"uint_arg":101}],"policy_name":"boxedai-process-fork"}}`+"\n"); err != nil {
		t.Fatalf("append fork-policy event: %v", err)
	}
	select {
	case <-ready:
		t.Fatal("fork and exec established readiness without built-in exit")
	case <-time.After(100 * time.Millisecond):
	}
	if err := appendLogLine(path, `{"process_exit":{"process":{"exec_id":"probe","pid":100,"uid":0},"parent":{"pid":1}}}`+"\n"); err != nil {
		t.Fatalf("append non-workload exit event: %v", err)
	}
	select {
	case <-ready:
		t.Fatal("readiness published on the scrape that only anchored the loss counters")
	case <-time.After(100 * time.Millisecond):
	}

	// The full gate needs one more scrape agreeing the loss counters have not moved
	// since that anchor (DESIGN.md session-time provisioning step 4).
	if err := appendLogLine(path, `{"process_exit":{"process":{"exec_id":"probe","pid":101,"uid":0},"parent":{"pid":1}}}`+"\n"); err != nil {
		t.Fatalf("append settled-scrape event: %v", err)
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("fresh non-workload process event did not establish readiness")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runTetragonWatcher: %v", err)
	}
}

// TestTetragonWatcherSurvivesExportRotation is the regression guard for the
// mid-session crash: Tetragon's own export rotation used to end the watcher, which
// the sensor treated as loss and answered by SIGKILLing the running workload. The
// rotation is now recorded as a coverage gap and the watch continues.
func TestTetragonWatcherSurvivesExportRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tetragon.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	recorded := make(chan evidence.Event, 32)
	batch := NewBatcher(func(events []evidence.Event) error {
		for _, ev := range events {
			recorded <- ev
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		batch.Run(ctx)
	}()
	done := make(chan error, 1)
	go func() {
		done <- runTetragonWatcherWithMetrics(ctx, Config{TetragonLog: path, WorkloadUID: 4242}, batch, func() {}, func(context.Context) (float64, error) { return 0, nil })
	}()
	time.Sleep(100 * time.Millisecond)

	// Exactly what lumberjack does at the size threshold.
	if err := os.Rename(path, filepath.Join(dir, "tetragon.log.1")); err != nil {
		t.Fatalf("rotate export: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"process_exec":{"process":{"exec_id":"abc","pid":100,"uid":4242,"binary":"/usr/bin/node"},"parent":{"pid":1}}}`+"\n"), 0o600); err != nil {
		t.Fatalf("write replacement export: %v", err)
	}

	loss, restarted, executed := false, false, false
	deadline := time.After(3 * time.Second)
	for !loss || !restarted || !executed {
		select {
		case ev := <-recorded:
			switch ev.Name {
			case evidence.EventSensorLoss:
				loss = true
			case evidence.EventSensorRestarted:
				restarted = true
			case evidence.EventProcessExecuted:
				executed = true
			}
		case err := <-done:
			t.Fatalf("watcher stopped on export rotation: %v", err)
		case <-deadline:
			t.Fatalf("rotation not recorded: loss=%v restarted=%v executed=%v", loss, restarted, executed)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runTetragonWatcherWithMetrics: %v", err)
	}
	<-batchDone
}

// TestTetragonReadinessRetriesWhenMetricsAreNotUpYet covers the bootstrap window: a
// metrics endpoint still refusing connections means Tetragon has not finished coming
// up, which used to fail the whole watcher on the first attempt.
func TestTetragonReadinessRetriesWhenMetricsAreNotUpYet(t *testing.T) {
	oldInterval := readinessMetricsRetryInterval
	readinessMetricsRetryInterval = time.Millisecond
	t.Cleanup(func() { readinessMetricsRetryInterval = oldInterval })

	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	var scrapes atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runTetragonWatcherWithMetrics(ctx, Config{TetragonLog: path, WorkloadUID: 4242}, NewBatcher(nil), func() {
			close(ready)
		}, func(context.Context) (float64, error) {
			if scrapes.Add(1) == 1 {
				return 0, errors.New("dial 127.0.0.1:2112: connection refused")
			}
			return 0, nil
		})
	}()
	time.Sleep(100 * time.Millisecond)

	// Root-owned probe events satisfy the exec/fork/exit gate; the first readiness
	// scrape then fails.
	for _, line := range []string{
		`{"process_exec":{"process":{"exec_id":"probe","pid":100,"uid":0,"binary":"/usr/bin/test"},"parent":{"pid":1}}}`,
		`{"process_tracepoint":{"process":{"exec_id":"probe","pid":100,"uid":0},"subsys":"sched","event":"sched_process_fork","args":[{"uint_arg":100},{"uint_arg":101}],"policy_name":"boxedai-process-fork"}}`,
		`{"process_exit":{"process":{"exec_id":"probe","pid":100,"uid":0},"parent":{"pid":1}}}`,
	} {
		if err := appendLogLine(path, line+"\n"); err != nil {
			t.Fatalf("append probe event: %v", err)
		}
	}
	select {
	case <-ready:
		t.Fatal("readiness published while the metrics endpoint was still down")
	case err := <-done:
		t.Fatalf("watcher died on an unavailable metrics endpoint: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Later lifecycle observations retry the gate: one scrape anchors the loss
	// counters and the next agrees they have not moved, so readiness publishes.
	probeLifecycleUntilReady(t, path, ready)
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("watcher died before retrying readiness: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("readiness was never retried after the metrics endpoint came up")
	}
	if got := scrapes.Load(); got < 3 {
		t.Fatalf("readiness scrapes = %d, want the failure plus an anchor and an agreeing scrape", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runTetragonWatcherWithMetrics: %v", err)
	}
}

// TestTetragonReadinessRebaselinesWhileLossCountersStillClimb is the round-2 regression
// guard: a fresh VM keeps bumping its loss counters for as long as it is booting, and a
// readiness scrape that saw growth over the baseline used to fail the whole watcher.
// Every retry hit the same growth, so healthy sessions burned the readiness window and
// launched on procfs — an INCOMPLETE verdict for a sensor that was working.
func TestTetragonReadinessRebaselinesWhileLossCountersStillClimb(t *testing.T) {
	oldInterval := readinessMetricsRetryInterval
	readinessMetricsRetryInterval = time.Millisecond
	t.Cleanup(func() { readinessMetricsRetryInterval = oldInterval })

	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	var scrapes atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runTetragonWatcherWithMetrics(ctx, Config{TetragonLog: path, WorkloadUID: 4242}, NewBatcher(nil), func() {
			close(ready)
		}, func(context.Context) (float64, error) {
			// Boot noise: climbs on the first three scrapes, then settles.
			if n := scrapes.Add(1); n <= 3 {
				return float64(n), nil
			}
			return 3, nil
		})
	}()
	time.Sleep(100 * time.Millisecond)

	for _, line := range []string{
		`{"process_exec":{"process":{"exec_id":"probe","pid":100,"uid":0,"binary":"/usr/bin/test"},"parent":{"pid":1}}}`,
		`{"process_tracepoint":{"process":{"exec_id":"probe","pid":100,"uid":0},"subsys":"sched","event":"sched_process_fork","args":[{"uint_arg":100},{"uint_arg":101}],"policy_name":"boxedai-process-fork"}}`,
		`{"process_exit":{"process":{"exec_id":"probe","pid":100,"uid":0},"parent":{"pid":1}}}`,
	} {
		if err := appendLogLine(path, line+"\n"); err != nil {
			t.Fatalf("append probe event: %v", err)
		}
	}
	probeLifecycleUntilReady(t, path, ready)
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("watcher died while the loss counters were still settling: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("readiness never published after the loss counters settled")
	}
	if got := scrapes.Load(); got < 4 {
		t.Fatalf("readiness scrapes = %d, want the three climbing scrapes plus one agreeing with the last", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runTetragonWatcherWithMetrics: %v", err)
	}
}

// probeLifecycleUntilReady keeps appending the root-owned fork/exec/exit round the real
// liveness probe produces, so a readiness gate that needs more than one lifecycle
// observation has something to retry on. Every round is complete, so it does not matter
// whether the tailer had attached yet when the caller wrote its own fixture lines. It
// stops at readiness or when the test ends, whichever comes first.
func probeLifecycleUntilReady(t *testing.T, path string, ready <-chan struct{}) {
	t.Helper()
	stop := make(chan struct{})
	stopped := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		<-stopped
	})
	go func() {
		defer close(stopped)
		for pid := 200; ; pid++ {
			select {
			case <-stop:
				return
			case <-ready:
				return
			case <-time.After(5 * time.Millisecond):
			}
			for _, line := range []string{
				fmt.Sprintf(`{"process_tracepoint":{"process":{"exec_id":"probe","pid":%d,"uid":0},"subsys":"sched","event":"sched_process_fork","args":[{"uint_arg":%d},{"uint_arg":%d}],"policy_name":"boxedai-process-fork"}}`, pid, pid, pid+1),
				fmt.Sprintf(`{"process_exec":{"process":{"exec_id":"probe","pid":%d,"uid":0,"binary":"/bin/true"},"parent":{"pid":%d}}}`, pid+1, pid),
				fmt.Sprintf(`{"process_exit":{"process":{"exec_id":"probe","pid":%d,"uid":0},"parent":{"pid":%d}}}`, pid+1, pid),
			} {
				if err := appendLogLine(path, line+"\n"); err != nil {
					t.Errorf("append liveness probe event: %v", err)
					return
				}
			}
		}
	}()
}

// TestTetragonTeardownDrainsTheBacklogItNeverRead is the storm regression guard: the
// tailer stops the instant the stop sentinel appears, so every line Tetragon had
// already written but nobody had read used to be dropped — 15k forks in, ~9% of the
// process events became evidence and verification still passed. The watcher now
// finishes reading the export before it returns, from exactly where the tail
// stopped: no gap, no duplicates.
func TestTetragonTeardownDrainsTheBacklogItNeverRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var mu sync.Mutex
	executed := map[int64]int{}
	losses := 0
	batch := NewBatcher(func(events []evidence.Event) error {
		mu.Lock()
		defer mu.Unlock()
		for _, ev := range events {
			switch ev.Name {
			case evidence.EventProcessExecuted:
				pid, _ := ev.Attrs[evidence.AttrProcessPID].(int64)
				executed[pid]++
			case evidence.EventSensorLoss:
				losses++
			}
		}
		return nil
	})
	// The batcher outlives the watcher, exactly as the agent's main does, so the
	// drain's events still have somewhere to go.
	batchCtx, cancelBatch := context.WithCancel(context.Background())
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		batch.Run(batchCtx)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runTetragonWatcherWithMetrics(ctx, Config{TetragonLog: path, WorkloadUID: 4242}, batch, func() {}, func(context.Context) (float64, error) { return 0, nil })
	}()
	time.Sleep(100 * time.Millisecond)

	// A burst too large for the tailer to have finished, then an immediate stop.
	const storm = 2000
	var lines strings.Builder
	for pid := 0; pid < storm; pid++ {
		fmt.Fprintf(&lines, `{"process_exec":{"process":{"exec_id":"e%d","pid":%d,"uid":4242,"binary":"/usr/bin/node"},"parent":{"pid":1}}}`+"\n", pid, pid+1)
	}
	if err := appendLogLine(path, lines.String()); err != nil {
		t.Fatalf("append storm: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runTetragonWatcherWithMetrics: %v", err)
	}
	cancelBatch()
	<-batchDone

	mu.Lock()
	defer mu.Unlock()
	if len(executed) != storm {
		t.Fatalf("process.executed events = %d, want every one of the %d source lines", len(executed), storm)
	}
	for pid, count := range executed {
		if count != 1 {
			t.Fatalf("pid %d recorded %d times, want exactly once", pid, count)
		}
	}
	if losses != 0 {
		t.Fatalf("sensor.loss recorded %d time(s) after a complete drain", losses)
	}
}

// TestTetragonTeardownReportsAnUndrainedBacklog covers the honesty half: when the
// drain window is not enough, the unread remainder becomes sensor.loss (so the
// verifier says INCOMPLETE) instead of vanishing.
func TestTetragonTeardownReportsAnUndrainedBacklog(t *testing.T) {
	oldWindow := tetragonDrainWindow
	tetragonDrainWindow = 0
	t.Cleanup(func() { tetragonDrainWindow = oldWindow })
	oldTolerance := tetragonBacklogTolerance
	tetragonBacklogTolerance = 16
	t.Cleanup(func() { tetragonBacklogTolerance = oldTolerance })

	path := filepath.Join(t.TempDir(), "tetragon.log")
	backlog := strings.Repeat("x", 4096)
	if err := os.WriteFile(path, []byte(backlog), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	var reasons []string
	batch := NewBatcher(nil)
	drainTetragonExport(path, 0, batch, func(string) { t.Fatal("no line should be read once the window has expired") })
	for len(batch.incoming) > 0 {
		item := <-batch.incoming
		if item.event.Name == evidence.EventSensorLoss {
			reason, _ := item.event.Attrs[attrSensorReason].(string)
			reasons = append(reasons, reason)
		}
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "backlog not drained at teardown") {
		t.Fatalf("sensor.loss events = %v, want one undrained-backlog report", reasons)
	}
	if !strings.Contains(reasons[0], "4096 unread byte(s)") {
		t.Fatalf("sensor.loss reason = %q, want the unread byte count", reasons[0])
	}
}

// TestTetragonTeardownToleratesTheExportsOwnTail keeps the honesty above from firing
// on every session: teardown itself makes Tetragon write (the shell that touches the
// stop sentinel, the liveness probe, a partial line), and reporting that handful of
// records as loss would make every verdict INCOMPLETE.
func TestTetragonTeardownToleratesTheExportsOwnTail(t *testing.T) {
	oldWindow := tetragonDrainWindow
	tetragonDrainWindow = 0
	t.Cleanup(func() { tetragonDrainWindow = oldWindow })

	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1024)), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	batch := NewBatcher(nil)
	drainTetragonExport(path, 0, batch, func(string) {})
	if len(batch.incoming) != 0 {
		t.Fatalf("queued %d event(s) for an unread tail inside the tolerance", len(batch.incoming))
	}
}

func TestParseForkTracepointCreatesProvisionalTaskIdentity(t *testing.T) {
	line := []byte(`{"process_tracepoint":{"process":{"exec_id":"parent-exec","pid":4242,"uid":4242},"subsys":"sched","event":"sched_process_fork","args":[{"uint_arg":4242},{"uint_arg":4317}],"policy_name":"boxedai-process-fork"}}`)
	tl, err := parseTetragonLine(line)
	if err != nil {
		t.Fatalf("parseTetragonLine: %v", err)
	}
	pi, relevant, err := parseForkTracepoint(tl.ProcessTracepoint)
	if err != nil || !relevant {
		t.Fatalf("parseForkTracepoint = %+v, %v, %v", pi, relevant, err)
	}
	if pi.Pid != 4317 || pi.Ppid != 4242 || pi.ParentExecID != "parent-exec" || pi.ExecID != "" {
		t.Fatalf("fork identity = %+v", pi)
	}
	event := newProcessCreatedEvent(pi)
	if event.Name != evidence.EventProcessCreated || event.Attrs[attrProcessClassification] != "provisional_unknown_process_or_thread" {
		t.Fatalf("created event = %+v", event)
	}
}

// Only a malformed *shape* for our own policy is corruption: the arguments the
// TracingPolicy pins are either there with the right types or the export is not what
// the agent asked for, and that must stay fatal.
func TestParseForkTracepointRejectsRelevantMalformedRecord(t *testing.T) {
	parent, child := uint32(4242), uint32(4317)
	for _, event := range []*tetragonTracepointEvent{
		// No args at all.
		{Process: tetragonProcess{ExecID: "parent-exec", Pid: parent}, Subsys: "sched", Event: "sched_process_fork", PolicyName: "boxedai-process-fork"},
		// One arg where the policy pins two.
		{Process: tetragonProcess{ExecID: "parent-exec", Pid: parent}, Subsys: "sched", Event: "sched_process_fork", PolicyName: "boxedai-process-fork", Args: []tetragonTracepointArg{{UintArg: &parent}}},
		// Two args, but one carries no uint payload.
		{Process: tetragonProcess{ExecID: "parent-exec", Pid: parent}, Subsys: "sched", Event: "sched_process_fork", PolicyName: "boxedai-process-fork", Args: []tetragonTracepointArg{{UintArg: &parent}, {}}},
		// Our policy name on somebody else's tracepoint.
		{Process: tetragonProcess{ExecID: "parent-exec", Pid: parent}, Subsys: "raw_syscalls", Event: "sys_enter", PolicyName: "boxedai-process-fork", Args: []tetragonTracepointArg{{UintArg: &parent}, {UintArg: &child}}},
	} {
		if _, relevant, err := parseForkTracepoint(event); !relevant || err == nil {
			t.Fatalf("parseForkTracepoint(%+v) relevant/error = %v/%v, want true/error", event, relevant, err)
		}
	}
}

// TestParseForkTracepointSkipsUnenrichedParentIdentity is the S4 regression guard: a
// fork burst followed by git subprocess work reproducibly delivered structurally valid
// tracepoints whose attached parent had not been enriched yet, and treating that known
// gap as corruption killed the watcher — 13 spurious sensor.loss events across three
// runs, each self-healing through procfs but leaving healthy sessions INCOMPLETE.
func TestParseForkTracepointSkipsUnenrichedParentIdentity(t *testing.T) {
	parent, child := uint32(4242), uint32(4317)
	for _, tc := range []struct {
		name  string
		event *tetragonTracepointEvent
	}{
		{
			// Tetragon has the pid but has not attached the parent's execve yet.
			name:  "empty parent exec id",
			event: &tetragonTracepointEvent{Process: tetragonProcess{Pid: parent, Uid: 4242}, Subsys: "sched", Event: "sched_process_fork", PolicyName: "boxedai-process-fork", Args: []tetragonTracepointArg{{UintArg: &parent}, {UintArg: &child}}},
		},
		{
			name:  "zero parent pid with an unenriched context",
			event: &tetragonTracepointEvent{Process: tetragonProcess{ExecID: "parent-exec"}, Subsys: "sched", Event: "sched_process_fork", PolicyName: "boxedai-process-fork", Args: []tetragonTracepointArg{{UintArg: new(uint32)}, {UintArg: &child}}},
		},
		{
			// pid 0 is the idle task, never a forked child: unusable as lineage.
			name:  "zero child pid",
			event: &tetragonTracepointEvent{Process: tetragonProcess{ExecID: "parent-exec", Pid: parent}, Subsys: "sched", Event: "sched_process_fork", PolicyName: "boxedai-process-fork", Args: []tetragonTracepointArg{{UintArg: &parent}, {UintArg: new(uint32)}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pi, relevant, err := parseForkTracepoint(tc.event)
			if err != nil {
				t.Fatalf("parseForkTracepoint returned error for an unenriched parent: %v", err)
			}
			if relevant {
				t.Fatalf("parseForkTracepoint = %+v, want skipped (relevant=false)", pi)
			}
		})
	}
}

// Early in boot Tetragon reports sched_process_fork for procfs-discovered
// parents (that predate it) with the kernel placeholder as `process` (pid 0,
// exec_id of the boot pseudo-process) while the real parent pid is in args[0].
// These are unattributable and never the workload, so they must be skipped, not
// treated as corruption that kills the watcher.
func TestParseForkTracepointSkipsUnresolvedKernelPlaceholderParent(t *testing.T) {
	line := []byte(`{"process_tracepoint":{"process":{"exec_id":"boot-pseudo","pid":0,"uid":0,"binary":"<kernel>"},"subsys":"sched","event":"sched_process_fork","args":[{"uint_arg":1},{"uint_arg":1656}],"policy_name":"boxedai-process-fork"}}`)
	tl, err := parseTetragonLine(line)
	if err != nil {
		t.Fatalf("parseTetragonLine: %v", err)
	}
	pi, relevant, err := parseForkTracepoint(tl.ProcessTracepoint)
	if err != nil {
		t.Fatalf("parseForkTracepoint returned error for unresolved parent: %v", err)
	}
	if relevant {
		t.Fatalf("parseForkTracepoint = %+v, want skipped (relevant=false)", pi)
	}
}

func TestRateLimitDroppedAcceptsProtojsonStringAndNumber(t *testing.T) {
	for _, raw := range []string{
		`{"number_of_dropped_process_events":"2"}`,
		`{"number_of_dropped_process_events":2}`,
	} {
		dropped, err := rateLimitDropped([]byte(raw))
		if err != nil || !dropped {
			t.Fatalf("rateLimitDropped(%s) = %v, %v", raw, dropped, err)
		}
	}
}
