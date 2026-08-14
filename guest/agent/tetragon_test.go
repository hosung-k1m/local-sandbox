package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
		done <- runTetragonWatcherWithMetrics(ctx, Config{TetragonLog: path, WorkloadUID: 4242}, NewBatcher(nil), func() {}, func(context.Context) (bool, error) { return false, nil })
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

func TestBelongsToWorkload(t *testing.T) {
	if !belongsToWorkload(4242, 4242) {
		t.Error("want uid 4242 to belong to workload 4242")
	}
	if belongsToWorkload(0, 4242) {
		t.Error("want uid 0 to not belong to workload 4242")
	}
}

func TestTetragonWatcherReadinessRequiresFreshProcessEvent(t *testing.T) {
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
		}, func(context.Context) (bool, error) { return false, nil })
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
	case <-time.After(time.Second):
		t.Fatal("fresh non-workload process event did not establish readiness")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runTetragonWatcher: %v", err)
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

func TestParseForkTracepointRejectsRelevantMalformedRecord(t *testing.T) {
	parent, child := uint32(4242), uint32(4317)
	for _, event := range []*tetragonTracepointEvent{
		{Process: tetragonProcess{ExecID: "parent-exec", Pid: parent}, Subsys: "sched", Event: "sched_process_fork", PolicyName: "boxedai-process-fork"},
		{Process: tetragonProcess{ExecID: "parent-exec"}, Subsys: "sched", Event: "sched_process_fork", PolicyName: "boxedai-process-fork", Args: []tetragonTracepointArg{{UintArg: new(uint32)}, {UintArg: &child}}},
		{Process: tetragonProcess{ExecID: "parent-exec", Pid: parent}, Subsys: "sched", Event: "sched_process_fork", PolicyName: "boxedai-process-fork", Args: []tetragonTracepointArg{{UintArg: &parent}, {UintArg: new(uint32)}}},
	} {
		if _, relevant, err := parseForkTracepoint(event); !relevant || err == nil {
			t.Fatalf("parseForkTracepoint(%+v) relevant/error = %v/%v, want true/error", event, relevant, err)
		}
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
