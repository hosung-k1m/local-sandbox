package view

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protodelim"

	"boxedai/internal/evidence"
	"boxedai/internal/session"
	"boxedai/internal/verify"
)

// testEvent describes one synthetic evidence record to write into a segment
// file for testing. It intentionally does NOT depend on internal/recorder:
// the OTLP LogRecord is built directly with protodelim, exactly as the real
// recorder's WAL format is documented (DESIGN.md "Recorder" step 2), so
// Rebuild is exercised against the real wire format independent of the
// recorder implementation.
type testEvent struct {
	seq            int64
	name           string
	class          evidence.Class
	producer       evidence.Channel
	actionID       string
	parentActionID string
	outcome        evidence.Outcome
	body           string
	attrs          map[string]any // extra event-specific attrs, e.g. process.pid
}

// anyStringValue/anyIntValue build OTLP AnyValues for the scalar kinds used by
// BoxedAi attrs.
func anyStringValue(s string) *commonv1.AnyValue {
	return &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: s}}
}

func anyIntValue(n int64) *commonv1.AnyValue {
	return &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: n}}
}

func toAnyValue(v any) *commonv1.AnyValue {
	switch t := v.(type) {
	case string:
		return anyStringValue(t)
	case int:
		return anyIntValue(int64(t))
	case int64:
		return anyIntValue(t)
	default:
		return anyStringValue("")
	}
}

// writeSegment marshals events as length-delimited OTLP LogsData frames (one
// frame per event, matching the recorder's documented WAL format) into a new
// segment file under sessionDir/evidence/segments.
func writeSegment(t *testing.T, sessionDir, segmentName string, sessionID, policyDigest string, events []testEvent) {
	t.Helper()

	segDir := filepath.Join(sessionDir, "evidence", "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatalf("mkdir segments dir: %v", err)
	}
	f, err := os.Create(filepath.Join(segDir, segmentName))
	if err != nil {
		t.Fatalf("create segment file: %v", err)
	}
	defer f.Close()

	resourceAttrs := []*commonv1.KeyValue{
		{Key: evidence.AttrSchemaVersion, Value: anyStringValue(evidence.SchemaVersion)},
		{Key: evidence.AttrSessionID, Value: anyStringValue(sessionID)},
		{Key: evidence.AttrPolicyDigest, Value: anyStringValue(policyDigest)},
	}

	for _, ev := range events {
		recordAttrs := []*commonv1.KeyValue{
			{Key: evidence.AttrSequence, Value: anyIntValue(ev.seq)},
			{Key: evidence.AttrEvidenceClass, Value: anyStringValue(string(ev.class))},
			{Key: evidence.AttrProducer, Value: anyStringValue(string(ev.producer))},
			{Key: evidence.AttrOutcome, Value: anyStringValue(string(ev.outcome))},
		}
		if ev.actionID != "" {
			recordAttrs = append(recordAttrs, &commonv1.KeyValue{Key: evidence.AttrActionID, Value: anyStringValue(ev.actionID)})
		}
		if ev.parentActionID != "" {
			recordAttrs = append(recordAttrs, &commonv1.KeyValue{Key: evidence.AttrParentActionID, Value: anyStringValue(ev.parentActionID)})
		}
		for k, v := range ev.attrs {
			recordAttrs = append(recordAttrs, &commonv1.KeyValue{Key: k, Value: toAnyValue(v)})
		}

		data := &logsv1.LogsData{
			ResourceLogs: []*logsv1.ResourceLogs{{
				Resource: &resourcev1.Resource{Attributes: resourceAttrs},
				ScopeLogs: []*logsv1.ScopeLogs{{
					LogRecords: []*logsv1.LogRecord{{
						TimeUnixNano: uint64(time.Date(2026, 1, 1, 0, 0, int(ev.seq), 0, time.UTC).UnixNano()),
						EventName:    ev.name,
						Body:         anyStringValue(ev.body),
						Attributes:   recordAttrs,
					}},
				}},
			}},
		}
		if _, err := protodelim.MarshalTo(f, data); err != nil {
			t.Fatalf("marshal test event %q: %v", ev.name, err)
		}
	}
}

func TestRebuildProjectsEvents(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventSessionGranted, class: evidence.ClassIntegrity,
			producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess, body: "session granted",
		},
		{
			seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, actionID: "act-1", outcome: evidence.OutcomeSuccess,
			body: "npm install", attrs: map[string]any{evidence.AttrProcessPID: int64(100), evidence.AttrProcessPPID: int64(1)},
		},
	})

	db, err := Rebuild(sessionDir)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	defer db.Close()

	rows, err := queryEvents(db, Filter{})
	if err != nil {
		t.Fatalf("queryEvents: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}

	if rows[0].Seq != 1 || rows[0].Name != evidence.EventSessionGranted || rows[0].Class != string(evidence.ClassIntegrity) {
		t.Errorf("row 0 = %+v, want seq=1 name=%s class=%s", rows[0], evidence.EventSessionGranted, evidence.ClassIntegrity)
	}
	if rows[0].Producer != string(evidence.ChannelController) || rows[0].Outcome != string(evidence.OutcomeSuccess) {
		t.Errorf("row 0 producer/outcome = %q/%q, want %q/%q", rows[0].Producer, rows[0].Outcome, evidence.ChannelController, evidence.OutcomeSuccess)
	}

	row1 := rows[1]
	if row1.Seq != 2 || row1.Name != evidence.EventProcessExecuted || row1.ActionID != "act-1" {
		t.Errorf("row 1 = %+v, want seq=2 name=%s action_id=act-1", row1, evidence.EventProcessExecuted)
	}
	if !strings.Contains(row1.AttrsJSON, `"process.pid":100`) {
		t.Errorf("row 1 attrs_json = %s, want process.pid=100", row1.AttrsJSON)
	}
	if row1.Body != "npm install" {
		t.Errorf("row 1 body = %q, want %q", row1.Body, "npm install")
	}

	excluded, err := queryEvents(db, Filter{ExcludeNames: []string{evidence.EventProcessExecuted}})
	if err != nil {
		t.Fatalf("queryEvents with ExcludeNames: %v", err)
	}
	if len(excluded) != 1 || excluded[0].Name != evidence.EventSessionGranted {
		t.Errorf("queryEvents with ExcludeNames = %+v, want only %s", excluded, evidence.EventSessionGranted)
	}
}

func TestTimelineOutput(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventNetworkDenied, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeDenied, body: "egress blocked",
			attrs: map[string]any{"network.address": "93.184.216.34:443"},
		},
		{
			seq: 2, name: evidence.EventEffectApproved, class: evidence.ClassBrokerMediated,
			producer: evidence.ChannelBroker, outcome: evidence.OutcomeSuccess, body: "pr-comment approved",
			attrs: map[string]any{
				"vm.id":                  "vm-0123456789abcdef0123456789abcdef",
				"process.parent_exec_id": "cGFyZW50LWV4ZWMtaWQtYmFzZTY0LXBheWxvYWQtZm9yLXRlc3Rpbmc=",
				"harness.tool.input":     strings.Repeat("x", 250),
			},
		},
	})

	var buf bytes.Buffer
	if err := Timeline(sessionDir, Filter{}, &buf); err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		evidence.EventNetworkDenied, evidence.EventEffectApproved,
		"[KERNEL]", "[BROKER]", "network.address=93.184.216.34:443",
		"harness.tool.input=" + strings.Repeat("x", 200) + "...",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Timeline output missing %q; got:\n%s", want, out)
		}
	}
	for _, notWant := range []string{"vm.id=", "process.parent_exec_id=", strings.Repeat("x", 201)} {
		if strings.Contains(out, notWant) {
			t.Errorf("Timeline output should not contain %q; got:\n%s", notWant, out)
		}
	}

	// Name filter narrows to the matching event only.
	buf.Reset()
	if err := Timeline(sessionDir, Filter{Name: evidence.EventEffectApproved}, &buf); err != nil {
		t.Fatalf("Timeline with filter: %v", err)
	}
	filtered := buf.String()
	if strings.Contains(filtered, evidence.EventNetworkDenied) {
		t.Errorf("filtered Timeline output should not contain %q; got:\n%s", evidence.EventNetworkDenied, filtered)
	}
	if !strings.Contains(filtered, evidence.EventEffectApproved) {
		t.Errorf("filtered Timeline output missing %q; got:\n%s", evidence.EventEffectApproved, filtered)
	}
}

// TestTimelineDefaultHidesProcessCreatedNoise exercises the CLI's default
// filter (ExcludeNames: []string{"process.created"}): the noisy events must
// be hidden and a trailer must report how many were hidden.
func TestTimelineDefaultHidesProcessCreatedNoise(t *testing.T) {
	sessionDir := t.TempDir()
	events := []testEvent{
		{seq: 1, name: evidence.EventSessionGranted, class: evidence.ClassIntegrity, producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess},
	}
	for i := 0; i < 3; i++ {
		events = append(events, testEvent{
			seq: int64(2 + i), name: evidence.EventProcessCreated, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess,
		})
	}
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", events)

	var buf bytes.Buffer
	if err := Timeline(sessionDir, Filter{ExcludeNames: []string{evidence.EventProcessCreated}}, &buf); err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "[KERNEL]") {
		t.Errorf("default Timeline output contains hidden process.created rows; got:\n%s", out)
	}
	if !strings.Contains(out, "showing 1 of 4 events (3 process.created hidden; --all to show)") {
		t.Errorf("Timeline output missing trailer; got:\n%s", out)
	}
}

// TestTimelineAllShowsEverythingWithNoTrailer exercises the --all case: an
// empty Filter must show every event and print no trailer.
func TestTimelineAllShowsEverythingWithNoTrailer(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionGranted, class: evidence.ClassIntegrity, producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess},
		{seq: 2, name: evidence.EventProcessCreated, class: evidence.ClassKernelObserved, producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess},
	})

	var buf bytes.Buffer
	if err := Timeline(sessionDir, Filter{}, &buf); err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, evidence.EventProcessCreated) {
		t.Errorf("--all Timeline output should include %q; got:\n%s", evidence.EventProcessCreated, out)
	}
	if strings.Contains(out, "showing") {
		t.Errorf("--all Timeline output should have no trailer; got:\n%s", out)
	}
}

// TestTimelineAgentActivityPreset exercises Filter.AgentActivity: it must
// include real agent activity, exclude process.created/process.exited churn,
// and drop process.executed rows for the guest agent's own binary (hook
// subprocesses observing themselves) in both shapes Claude Code actually
// produces: a direct exec, and — the common case — invoked via a shell
// wrapper (process.binary=/bin/sh, process.argv containing the full guest
// agent path), since Claude Code runs hooks through `sh -c`.
func TestTimelineAgentActivityPreset(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventToolRequested, class: evidence.ClassHarnessObserved,
			producer: evidence.ChannelWorkload, outcome: evidence.OutcomeSuccess,
		},
		{
			seq: 2, name: evidence.EventProcessCreated, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess,
		},
		{
			seq: 3, name: evidence.EventProcessExited, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess,
		},
		{
			seq: 4, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "npm ci",
			attrs: map[string]any{"process.binary": "/usr/bin/npm"},
		},
		{
			// Direct exec of the guest agent binary.
			seq: 5, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "boxedai-guest-agent righthook",
			attrs: map[string]any{"process.binary": "/usr/local/bin/boxedai-guest-agent"},
		},
		{
			// Real shape: Claude Code invokes hooks via a shell, so tetragon/procfs
			// observe /bin/sh with the guest agent invocation in argv, not as
			// process.binary.
			seq: 6, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "sh -c '/usr/local/bin/boxedai-guest-agent lefthook'",
			attrs: map[string]any{"process.binary": "/bin/sh", "process.argv": `-c "/usr/local/bin/boxedai-guest-agent lefthook"`},
		},
	})

	var buf bytes.Buffer
	if err := Timeline(sessionDir, Filter{AgentActivity: true}, &buf); err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, evidence.EventToolRequested) {
		t.Errorf("agent-activity output missing %q; got:\n%s", evidence.EventToolRequested, out)
	}
	if strings.Contains(out, evidence.EventProcessCreated) || strings.Contains(out, evidence.EventProcessExited) {
		t.Errorf("agent-activity output should exclude process.created/process.exited; got:\n%s", out)
	}
	if !strings.Contains(out, "npm ci") {
		t.Errorf("agent-activity output missing real process.executed row; got:\n%s", out)
	}
	if strings.Contains(out, "boxedai-guest-agent") {
		t.Errorf("agent-activity output should drop every guest-agent-binary process.executed row (direct exec and shell wrapper); got:\n%s", out)
	}
	if !strings.Contains(out, "showing 2 of 6 events (4 hidden; --all to show)") {
		t.Errorf("Timeline output missing trailer; got:\n%s", out)
	}
}

func TestProcessTree(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "bash -lc 'npm ci'",
			attrs: map[string]any{evidence.AttrProcessPID: int64(100), evidence.AttrProcessPPID: int64(1)},
		},
		{
			seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "npm",
			attrs: map[string]any{evidence.AttrProcessPID: int64(200), evidence.AttrProcessPPID: int64(100)},
		},
	})

	tree, err := ProcessTree(sessionDir)
	if err != nil {
		t.Fatalf("ProcessTree: %v", err)
	}

	lines := strings.Split(strings.TrimRight(tree, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("ProcessTree lines = %v, want 2 lines", lines)
	}
	if !strings.Contains(lines[0], "pid 100") || strings.HasPrefix(lines[0], " ") {
		t.Errorf("root line = %q, want unindented pid 100", lines[0])
	}
	if !strings.Contains(lines[1], "pid 200") || !strings.HasPrefix(lines[1], "  ") {
		t.Errorf("child line = %q, want indented pid 200", lines[1])
	}
}

// TestProcessTreeFlagsForgedProducer is the regression test for the forgery-
// display hole: a process.executed reported on any channel but the trusted
// guest_supervisor kernel sensor is workload-forgeable and must be rendered as
// unverified, never as an indistinguishable real process. A genuine kernel node
// stays unannotated.
func TestProcessTreeFlagsForgedProducer(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "bash -lc 'real'",
			attrs: map[string]any{evidence.AttrProcessPID: int64(100), evidence.AttrProcessPPID: int64(1)},
		},
		{
			// Workload-forged: a process.executed submitted on the workload channel.
			seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassHarnessObserved,
			producer: evidence.ChannelWorkload, outcome: evidence.OutcomeSuccess, body: "sneaky",
			attrs: map[string]any{evidence.AttrProcessPID: int64(200), evidence.AttrProcessPPID: int64(1)},
		},
	})

	tree, err := ProcessTree(sessionDir)
	if err != nil {
		t.Fatalf("ProcessTree: %v", err)
	}
	lines := strings.Split(strings.TrimRight(tree, "\n"), "\n")

	var real, forged string
	for _, l := range lines {
		if strings.Contains(l, "pid 100") {
			real = l
		}
		if strings.Contains(l, "pid 200") {
			forged = l
		}
	}
	if real == "" || forged == "" {
		t.Fatalf("tree = %q, want both pid 100 and pid 200 lines", tree)
	}
	if strings.Contains(real, "unverified") {
		t.Errorf("kernel-observed node was flagged unverified: %q", real)
	}
	if !strings.Contains(forged, "unverified producer: workload") {
		t.Errorf("forged node = %q, want an [unverified producer: workload] annotation", forged)
	}
}

func TestProcessTreeKeepsReusedPIDIncarnations(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "first",
			attrs: map[string]any{evidence.AttrProcessPID: int64(42), evidence.AttrProcessPPID: int64(1)},
		},
		{
			seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "second",
			attrs: map[string]any{evidence.AttrProcessPID: int64(42), evidence.AttrProcessPPID: int64(1)},
		},
	})

	tree, err := ProcessTree(sessionDir)
	if err != nil {
		t.Fatalf("ProcessTree: %v", err)
	}
	if tree != "pid 42: first\npid 42: second\n" {
		t.Fatalf("tree = %q, want both pid incarnations", tree)
	}
}

func TestProcessTreePrefersExecIDLineageAcrossPIDReuse(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "old parent",
			attrs: map[string]any{evidence.AttrProcessPID: int64(100), evidence.AttrProcessPPID: int64(1), evidence.AttrProcessExecID: "old"},
		},
		{
			seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "new parent",
			attrs: map[string]any{evidence.AttrProcessPID: int64(100), evidence.AttrProcessPPID: int64(1), evidence.AttrProcessExecID: "new"},
		},
		{
			seq: 3, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "child of old",
			attrs: map[string]any{
				evidence.AttrProcessPID:          int64(200),
				evidence.AttrProcessPPID:         int64(100),
				evidence.AttrProcessExecID:       "child",
				evidence.AttrProcessParentExecID: "old",
			},
		},
	})

	tree, err := ProcessTree(sessionDir)
	if err != nil {
		t.Fatalf("ProcessTree: %v", err)
	}
	want := "pid 100: old parent\n  pid 200: child of old\npid 100: new parent\n"
	if tree != want {
		t.Fatalf("tree = %q, want %q", tree, want)
	}
}

func TestProcessTreeFallsBackToLatestPriorParentPID(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "old parent",
			attrs: map[string]any{evidence.AttrProcessPID: int64(100), evidence.AttrProcessPPID: int64(1)},
		},
		{
			seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "old child",
			attrs: map[string]any{evidence.AttrProcessPID: int64(200), evidence.AttrProcessPPID: int64(100)},
		},
		{
			seq: 3, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "new parent",
			attrs: map[string]any{evidence.AttrProcessPID: int64(100), evidence.AttrProcessPPID: int64(1)},
		},
		{
			seq: 4, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "new child",
			attrs: map[string]any{evidence.AttrProcessPID: int64(201), evidence.AttrProcessPPID: int64(100)},
		},
	})

	tree, err := ProcessTree(sessionDir)
	if err != nil {
		t.Fatalf("ProcessTree: %v", err)
	}
	want := "pid 100: old parent\n  pid 200: old child\npid 100: new parent\n  pid 201: new child\n"
	if tree != want {
		t.Fatalf("tree = %q, want %q", tree, want)
	}
}

func TestProcessTreeRenderingIsDeterministic(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "root",
			attrs: map[string]any{evidence.AttrProcessPID: int64(100), evidence.AttrProcessPPID: int64(1)},
		},
		{
			seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "larger child",
			attrs: map[string]any{evidence.AttrProcessPID: int64(20), evidence.AttrProcessPPID: int64(100)},
		},
		{
			seq: 3, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess, body: "smaller child",
			attrs: map[string]any{evidence.AttrProcessPID: int64(3), evidence.AttrProcessPPID: int64(100)},
		},
	})

	first, err := ProcessTree(sessionDir)
	if err != nil {
		t.Fatalf("ProcessTree: %v", err)
	}
	second, err := ProcessTree(sessionDir)
	if err != nil {
		t.Fatalf("ProcessTree second render: %v", err)
	}
	want := "pid 100: root\n  pid 3: smaller child\n  pid 20: larger child\n"
	if first != want || second != want {
		t.Fatalf("renders = %q and %q, want %q", first, second, want)
	}
}

func TestBuildWebPayloadIncludesProofAndActionTimeline(t *testing.T) {
	sessionDir := t.TempDir()
	writeSegment(t, sessionDir, "segment-000001.otlp", "bx-test-session", "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventAuthorizationDecided, class: evidence.ClassBrokerMediated,
			producer: evidence.ChannelBroker, actionID: "act-parent", outcome: evidence.OutcomeSuccess,
			body: "approved",
		},
		{
			seq: 2, name: evidence.EventInternalToolDispatched, class: evidence.ClassBrokerMediated,
			producer: evidence.ChannelBroker, actionID: "act-child", parentActionID: "act-parent",
			outcome: evidence.OutcomeSuccess, body: "tool dispatched", attrs: map[string]any{"tool.name": "github/repo_view"},
		},
	})

	payload, err := buildWebPayload(sessionDir)
	if err != nil {
		t.Fatalf("buildWebPayload: %v", err)
	}
	if payload.SessionID != "bx-test-session" {
		t.Fatalf("SessionID = %q, want bx-test-session", payload.SessionID)
	}
	if !payload.Proof.Provisional || payload.Proof.Status != "provisional" {
		t.Fatalf("proof = %+v, want provisional for unsealed segment", payload.Proof)
	}
	if len(payload.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(payload.Events))
	}
	ev := payload.Events[1]
	if ev.ActionID != "act-child" || ev.ParentActionID != "act-parent" || ev.Producer != string(evidence.ChannelBroker) {
		t.Errorf("event relationships = %+v, want child/parent broker event", ev)
	}
	if ev.Attrs["tool.name"] != "github/repo_view" {
		t.Errorf("attrs = %+v, want tool.name", ev.Attrs)
	}
	// The web viewer's client-side agent-activity toggle mirrors this include-set
	// from the payload rather than hand-maintaining a second copy in app.js.
	if !containsStr(payload.AgentActivityNames, evidence.EventToolRequested) {
		t.Errorf("AgentActivityNames = %v, want it to include %s", payload.AgentActivityNames, evidence.EventToolRequested)
	}
	if containsStr(payload.AgentActivityNames, evidence.EventProcessCreated) {
		t.Errorf("AgentActivityNames = %v, should not include %s", payload.AgentActivityNames, evidence.EventProcessCreated)
	}
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestBuildProofStateSurfacesTrustRecordFacets(t *testing.T) {
	report := verify.Report{
		Verdict: verify.VerdictLocalOnly,
		Facets: verify.Facets{
			TrustRecordStatus:    "verified",
			TrustRecordProfile:   "boxedai.trust-record/v1",
			TrustRecordAssurance: "Level 0 (software-only)",
			TrustRecordSignature: true,
			TrustRecordDerived:   true,
		},
	}

	proof := buildProofState(t.TempDir(), session.StateSealed, report, nil)
	if proof.TrustRecordStatus != "verified" || proof.TrustRecordProfile != "boxedai.trust-record/v1" {
		t.Fatalf("trust record status/profile = %q/%q", proof.TrustRecordStatus, proof.TrustRecordProfile)
	}
	if proof.TrustRecordAssurance != "Level 0 (software-only)" || proof.TrustRecordSignature == nil || !*proof.TrustRecordSignature || proof.TrustRecordDerived == nil || !*proof.TrustRecordDerived {
		t.Fatalf("trust record facets = %+v", proof)
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	for _, want := range []string{`"trust_record_signature_valid":true`, `"trust_record_cross_derived":true`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("proof JSON missing %s: %s", want, encoded)
		}
	}
}

func TestBuildWebPayloadUsesRunningLifecycleStateForProof(t *testing.T) {
	sessionDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sessionDir, "session.state"), []byte(session.StateRunning), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	payload, err := buildWebPayload(sessionDir)
	if err != nil {
		t.Fatalf("buildWebPayload: %v", err)
	}
	if !payload.Proof.Provisional || payload.Proof.Status != "provisional" {
		t.Fatalf("proof = %+v, want provisional for a running session even before an open segment is visible", payload.Proof)
	}
	// The same lifecycle marker is also published verbatim so the viewer can tell
	// "still running" from "ended without a session.stopped event" without
	// guessing from event presence alone.
	if payload.State != string(session.StateRunning) {
		t.Fatalf("payload state = %q, want %q", payload.State, session.StateRunning)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if !strings.Contains(string(encoded), `"state":"running"`) {
		t.Errorf("payload JSON missing lifecycle state field: %s", encoded)
	}
}

// TestDashboardSessionsExposeRepositoryAndBranch pins the provenance the sidebar
// cards render: the grant's repository and branch have to survive session.json ->
// SessionInfo -> /api/sessions so a previous-session card can label the branch the
// work happened on.
func TestDashboardSessionsExposeRepositoryAndBranch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	resetDashboardCacheForTest(t)

	id := "bx-20260812-090000-eeee5555"
	dir := filepath.Join(home, "sessions", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	grant := map[string]any{
		"schema":     "boxedai.session-grant/v1",
		"session_id": id,
		"harness":    "claude",
		"profile":    "dev",
		"repository": "git@github.com:boxedai/boxedai.git",
		"branch":     "agents-tab-revamp",
		"commit":     "9f2c1a7d4b6e8f0a2c4d6e8f0a2c4d6e8f0a2c4d",
		"created_at": "2026-08-12T09:00:00Z",
	}
	grantBytes, err := json.Marshal(grant)
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.json"), grantBytes, 0o644); err != nil {
		t.Fatalf("write grant: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.state"), []byte(session.StateSealed), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	recorder := httptest.NewRecorder()
	newDashboardMux().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("/api/sessions status = %d, want 200", recorder.Code)
	}
	var payload dashboardPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if len(payload.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(payload.Sessions))
	}
	if payload.Sessions[0].Repository != "git@github.com:boxedai/boxedai.git" || payload.Sessions[0].Branch != "agents-tab-revamp" {
		t.Fatalf("session provenance = %+v, want the grant's repository and branch", payload.Sessions[0])
	}
	for _, want := range []string{`"repository":"git@github.com:boxedai/boxedai.git"`, `"branch":"agents-tab-revamp"`} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("/api/sessions body missing %s: %s", want, recorder.Body.String())
		}
	}
}

func TestDashboardPayloadOrdersRunningSessionsFirst(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	historical := filepath.Join(home, "sessions", "bx-20260810-000000-aaaa1111")
	running := filepath.Join(home, "sessions", "bx-20260811-000000-bbbb2222")
	if err := os.MkdirAll(historical, 0o755); err != nil {
		t.Fatalf("mkdir historical: %v", err)
	}
	if err := os.MkdirAll(running, 0o755); err != nil {
		t.Fatalf("mkdir running: %v", err)
	}
	if err := os.WriteFile(filepath.Join(historical, "session.state"), []byte(session.StateSealed), 0o644); err != nil {
		t.Fatalf("write historical state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(running, "session.state"), []byte(session.StateRunning), 0o644); err != nil {
		t.Fatalf("write running state: %v", err)
	}
	writeSegment(t, historical, "segment-000001.otlp", "bx-20260810-000000-aaaa1111", "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionGranted, class: evidence.ClassIntegrity, producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess},
	})
	if err := os.WriteFile(filepath.Join(historical, "evidence", "segments", "segment-000001.manifest.json"), []byte(`{"segment_number":1,"first_sequence":1,"last_sequence":1,"segment_digest":"sha256:test"}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(historical, "evidence", "segments", "segment-000001.manifest.cose"), []byte("cose"), 0o644); err != nil {
		t.Fatalf("write cose: %v", err)
	}
	writeSegment(t, running, "segment-000001.otlp", "bx-20260811-000000-bbbb2222", "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess},
		{seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved, producer: evidence.ChannelGuestSupervisor, outcome: evidence.OutcomeSuccess},
	})

	payload, err := buildDashboardPayload()
	if err != nil {
		t.Fatalf("buildDashboardPayload: %v", err)
	}
	if len(payload.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(payload.Sessions))
	}
	if payload.Sessions[0].SessionID != "bx-20260811-000000-bbbb2222" || payload.Sessions[0].State != string(session.StateRunning) {
		t.Fatalf("first session = %+v, want running session first", payload.Sessions[0])
	}
	if payload.Sessions[0].EventCount != 2 || payload.Sessions[0].LastEventSeq != 2 {
		t.Errorf("running event summary = %+v, want 2 events last seq 2", payload.Sessions[0])
	}
	if !payload.Sessions[0].Proof.Provisional || !payload.Sessions[0].Proof.UnsealedTail {
		t.Errorf("running proof = %+v, want provisional unsealed tail", payload.Sessions[0].Proof)
	}
	if payload.Sessions[1].Proof.Status != "sealed_unverified" {
		t.Errorf("historical proof status = %q, want sealed_unverified summary", payload.Sessions[1].Proof.Status)
	}
}

func TestDashboardSummaryUsesDeclaredSegmentDigestName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	resetDashboardCacheForTest(t)

	id := "bx-20260810-000000-abcd7777"
	dir := filepath.Join(home, "sessions", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.state"), []byte(session.StateSealed), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	writeSegment(t, dir, "segment-000001.otlp", id, "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionGranted, class: evidence.ClassIntegrity, producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess},
	})
	writeDashboardManifest(t, dir, 1, 1, "sha256:declared-segment", "2026-08-10T00:00:01Z")

	payload, err := buildDashboardPayload()
	if err != nil {
		t.Fatalf("buildDashboardPayload: %v", err)
	}
	if payload.Sessions[0].Proof.Status != "sealed_unverified" {
		t.Fatalf("summary proof status = %q, want sealed_unverified", payload.Sessions[0].Proof.Status)
	}
	if payload.Sessions[0].Proof.ChainValid {
		t.Fatal("summary proof must not report chain_valid=true without running the verifier")
	}
	if payload.Sessions[0].Proof.Verdict != "" || len(payload.Sessions[0].Proof.Checks) != 0 || payload.Sessions[0].Proof.RecorderFingerprint != "" {
		t.Fatalf("summary proof contains verifier-only fields: %+v", payload.Sessions[0].Proof)
	}

	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	jsonText := string(b)
	if !strings.Contains(jsonText, `"declared_segment_digest":"sha256:declared-segment"`) {
		t.Fatalf("payload missing declared_segment_digest; got %s", jsonText)
	}
	if strings.Contains(jsonText, "manifest_digest") {
		t.Fatalf("payload contains ambiguous manifest_digest field; got %s", jsonText)
	}
}

func TestDashboardPayloadDoesNotRebuildSealedHistoricalSessions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	resetDashboardCacheForTest(t)
	var rebuilds int
	restore := rebuildDashboardProjection
	rebuildDashboardProjection = func(sessionDir string) (*sql.DB, error) {
		rebuilds++
		return Rebuild(sessionDir)
	}
	t.Cleanup(func() { rebuildDashboardProjection = restore })

	id := "bx-20260810-000000-eeee5555"
	dir := filepath.Join(home, "sessions", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.state"), []byte(session.StateSealed), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	writeSegment(t, dir, "segment-000001.otlp", id, "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionGranted, class: evidence.ClassIntegrity, producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess},
	})
	writeDashboardManifest(t, dir, 1, 1, "sha256:segment-one", "2026-08-10T00:00:01Z")

	first, err := buildDashboardPayload()
	if err != nil {
		t.Fatalf("first buildDashboardPayload: %v", err)
	}
	second, err := buildDashboardPayload()
	if err != nil {
		t.Fatalf("second buildDashboardPayload: %v", err)
	}
	if rebuilds != 0 {
		t.Fatalf("sealed dashboard polls rebuilt projection %d times, want 0", rebuilds)
	}
	if first.Sessions[0].EventCount != 1 || second.Sessions[0].EventCount != 1 {
		t.Fatalf("event counts = %d/%d, want manifest-derived 1", first.Sessions[0].EventCount, second.Sessions[0].EventCount)
	}
}

func TestDashboardSealedCacheInvalidatesWhenManifestMetadataChanges(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	resetDashboardCacheForTest(t)

	id := "bx-20260810-000000-ffff6666"
	dir := filepath.Join(home, "sessions", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.state"), []byte(session.StateSealed), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	writeSegment(t, dir, "segment-000001.otlp", id, "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionGranted, class: evidence.ClassIntegrity, producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess},
	})
	writeDashboardManifest(t, dir, 1, 1, "sha256:segment-one", "2026-08-10T00:00:01Z")

	first, err := buildDashboardPayload()
	if err != nil {
		t.Fatalf("first buildDashboardPayload: %v", err)
	}
	writeDashboardManifest(t, dir, 3, 3, "sha256:segment-one-updated-longer", "2026-08-10T00:00:03Z")
	second, err := buildDashboardPayload()
	if err != nil {
		t.Fatalf("second buildDashboardPayload: %v", err)
	}
	if first.Sessions[0].EventCount != 1 || first.Sessions[0].LastEventSeq != 1 {
		t.Fatalf("first summary = %+v, want count 1 seq 1", first.Sessions[0])
	}
	if second.Sessions[0].EventCount != 3 || second.Sessions[0].LastEventSeq != 3 {
		t.Fatalf("second summary = %+v, want invalidated count 3 seq 3", second.Sessions[0])
	}
}

func TestDashboardAPIsServePollingPayloads(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	id := "bx-20260811-120000-cccc3333"
	dir := filepath.Join(home, "sessions", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.state"), []byte(session.StateRunning), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	writeSegment(t, dir, "segment-000001.otlp", id, "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess},
	})

	server := httptest.NewServer(newDashboardMux())
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/sessions")
	if err != nil {
		t.Fatalf("GET /api/sessions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/sessions status = %d, want 200", resp.StatusCode)
	}
	var sessions dashboardPayload
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if len(sessions.Sessions) != 1 || sessions.Sessions[0].SessionID != id {
		t.Fatalf("sessions payload = %+v, want %s", sessions, id)
	}

	resp, err = http.Get(server.URL + "/api/session?id=" + id)
	if err != nil {
		t.Fatalf("GET /api/session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/session status = %d, want 200", resp.StatusCode)
	}
	var timeline webPayload
	if err := json.NewDecoder(resp.Body).Decode(&timeline); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if timeline.SessionID != id || len(timeline.Events) != 1 || !timeline.Proof.Provisional {
		t.Fatalf("timeline payload = %+v, want selected provisional session", timeline)
	}
}

func TestDashboardAPIRejectsUnknownSessionWithoutCreatingIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	id := "bx-20260811-120000-dddd4444"
	recorder := httptest.NewRecorder()
	newDashboardMux().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/session?id="+id, nil))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if _, err := os.Stat(filepath.Join(home, "sessions", id)); !os.IsNotExist(err) {
		t.Fatalf("unknown session path was created: %v", err)
	}
}

func TestDashboardDeleteEndpointRemovesFinishedSessions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	sealed := "bx-20260810-000000-aaaa1111"
	running := "bx-20260811-000000-bbbb2222"
	sealedDir := filepath.Join(home, "sessions", sealed)
	runningDir := filepath.Join(home, "sessions", running)
	if err := os.MkdirAll(filepath.Join(sealedDir, "evidence", "segments"), 0o755); err != nil {
		t.Fatalf("mkdir sealed: %v", err)
	}
	if err := os.MkdirAll(runningDir, 0o755); err != nil {
		t.Fatalf("mkdir running: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sealedDir, "session.state"), []byte(session.StateSealed), 0o644); err != nil {
		t.Fatalf("write sealed state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runningDir, "session.state"), []byte(session.StateRunning), 0o644); err != nil {
		t.Fatalf("write running state: %v", err)
	}

	body := `{"ids":["` + sealed + `","` + running + `","bad/id"]}`
	rec := httptest.NewRecorder()
	newDashboardMux().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/sessions/delete", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp deleteSessionsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Deleted) != 1 || resp.Deleted[0] != sealed {
		t.Fatalf("deleted = %v, want [%s]", resp.Deleted, sealed)
	}
	if resp.Errors[running] == "" || resp.Errors["bad/id"] == "" {
		t.Fatalf("errors = %v, want running + bad/id refused", resp.Errors)
	}
	if _, err := os.Stat(sealedDir); !os.IsNotExist(err) {
		t.Fatalf("sealed session dir still present: %v", err)
	}
	if _, err := os.Stat(runningDir); err != nil {
		t.Fatalf("running session dir was removed: %v", err)
	}
}

func TestDashboardDeleteEndpointRejectsGET(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())
	rec := httptest.NewRecorder()
	newDashboardMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/sessions/delete", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// TestAssetsServedByBothMuxes verifies the shared vanilla-JS/CSS client
// (registerAssets) is wired into both the single-session viewer mux and the
// dashboard mux with the right content types, and that each mux's thin HTML
// shell references /assets/app.js, /assets/processes.js and
// /assets/agentgraph.js.
func TestAssetsServedByBothMuxes(t *testing.T) {
	muxes := map[string]*http.ServeMux{
		"web":       newWebMux(t.TempDir()),
		"dashboard": newDashboardMux(),
	}
	for name, mux := range muxes {
		t.Run(name, func(t *testing.T) {
			cssRec := httptest.NewRecorder()
			mux.ServeHTTP(cssRec, httptest.NewRequest(http.MethodGet, "/assets/app.css", nil))
			if cssRec.Code != http.StatusOK {
				t.Fatalf("/assets/app.css status = %d, want 200", cssRec.Code)
			}
			if ct := cssRec.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
				t.Errorf("/assets/app.css Content-Type = %q, want text/css; charset=utf-8", ct)
			}
			if !strings.Contains(cssRec.Body.String(), "BoxedAi") {
				t.Errorf("/assets/app.css body missing BoxedAi marker")
			}

			jsRec := httptest.NewRecorder()
			mux.ServeHTTP(jsRec, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
			if jsRec.Code != http.StatusOK {
				t.Fatalf("/assets/app.js status = %d, want 200", jsRec.Code)
			}
			if ct := jsRec.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
				t.Errorf("/assets/app.js Content-Type = %q, want application/javascript; charset=utf-8", ct)
			}
			if !strings.Contains(jsRec.Body.String(), "BoxedAi") {
				t.Errorf("/assets/app.js body missing BoxedAi marker")
			}

			procRec := httptest.NewRecorder()
			mux.ServeHTTP(procRec, httptest.NewRequest(http.MethodGet, "/assets/processes.js", nil))
			if procRec.Code != http.StatusOK {
				t.Fatalf("/assets/processes.js status = %d, want 200", procRec.Code)
			}
			if ct := procRec.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
				t.Errorf("/assets/processes.js Content-Type = %q, want application/javascript; charset=utf-8", ct)
			}
			if procRec.Body.Len() == 0 {
				t.Errorf("/assets/processes.js body is empty")
			}
			if !strings.Contains(procRec.Body.String(), "BoxedAiProc") {
				t.Errorf("/assets/processes.js body missing BoxedAiProc marker")
			}

			graphRec := httptest.NewRecorder()
			mux.ServeHTTP(graphRec, httptest.NewRequest(http.MethodGet, "/assets/agentgraph.js", nil))
			if graphRec.Code != http.StatusOK {
				t.Fatalf("/assets/agentgraph.js status = %d, want 200", graphRec.Code)
			}
			if ct := graphRec.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
				t.Errorf("/assets/agentgraph.js Content-Type = %q, want application/javascript; charset=utf-8", ct)
			}
			if graphRec.Body.Len() == 0 {
				t.Errorf("/assets/agentgraph.js body is empty")
			}
			if !strings.Contains(graphRec.Body.String(), "BoxedAiAgentGraph") {
				t.Errorf("/assets/agentgraph.js body missing BoxedAiAgentGraph marker")
			}

			indexRec := httptest.NewRecorder()
			mux.ServeHTTP(indexRec, httptest.NewRequest(http.MethodGet, "/", nil))
			if indexRec.Code != http.StatusOK {
				t.Fatalf("/ status = %d, want 200", indexRec.Code)
			}
			if !strings.Contains(indexRec.Body.String(), "/assets/app.js") {
				t.Errorf("/ body missing reference to /assets/app.js: %s", indexRec.Body.String())
			}
			if !strings.Contains(indexRec.Body.String(), "/assets/processes.js") {
				t.Errorf("/ body missing reference to /assets/processes.js: %s", indexRec.Body.String())
			}
			if !strings.Contains(indexRec.Body.String(), "/assets/agentgraph.js") {
				t.Errorf("/ body missing reference to /assets/agentgraph.js: %s", indexRec.Body.String())
			}
		})
	}
}

func TestEmbeddedProcessesSplitChangedLiveExecID(t *testing.T) {
	source := string(processesJS)
	for _, want := range []string{
		"if (node && ev.name === EVENT_EXECUTED)",
		"hasVal(nextExecId) && node.execId && String(nextExecId) !== node.execId",
		"live.delete(pid)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("processes.js missing changed-exec incarnation guard %q", want)
		}
	}
	guard := strings.Index(source, "if (node && ev.name === EVENT_EXECUTED)")
	create := strings.Index(source[guard:], "if (!node)")
	if guard < 0 || create < 0 {
		t.Fatal("processes.js must split a changed exec id before selecting the live node")
	}
}

func TestEmbeddedAgentsRenderUnattributedActivityWithoutRegistrations(t *testing.T) {
	source := string(appJS)
	for _, want := range []string{
		"if (indices.length === 0)",
		"if (info.agentCount === 0)",
		"agent decomposition unavailable: no lifecycle registrations recorded",
		"members: indices",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("app.js missing zero-registration activity behavior %q", want)
		}
	}
	if strings.Contains(source, "indices.length === 0 || info.agentCount === 0") {
		t.Fatal("app.js still hides tool activity when lifecycle registrations are absent")
	}
}

func TestEmbeddedAgentGroupsKeepOrphansAndRootlessComponentsVisible(t *testing.T) {
	source := string(appJS)
	for _, want := range []string{
		"if (parent && groups.has(parent))",
		"renderedKeys.push(key)",
		"if (!seen.has(key)) visit(key, 0)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("app.js missing adversarial agent-group traversal behavior %q", want)
		}
	}
	if strings.Contains(source, "if (parent && meta.has(parent))") {
		t.Fatal("app.js still attaches visible groups beneath filtered-out metadata-only parents")
	}
}

// TestEmbeddedAgentsSplitActiveAndPastSections pins the Agents tab's two-section
// rendering: liveness is decided by one shared predicate that is clamped by the
// session's own lifecycle marker, and splitting the single pre-order walk into
// two lists re-roots any agent whose parent landed in the other section instead
// of leaving it indented under a parent that is no longer above it.
func TestEmbeddedAgentsSplitActiveAndPastSections(t *testing.T) {
	source := string(appJS)
	for _, want := range []string{
		"function agentIsActive(m, sessionEnded) {",
		"if (sessionEnded) return false;",
		`var sessionEnded = lifecycle === "sealed" || lifecycle === "incomplete";`,
		`agentsSectionHdrHtml("Active Agents"`,
		`agentsSectionHdrHtml("Past Agents"`,
		"var nested = parentID && sectionOf.get(parentID) === section && renderedDepth.has(parentID);",
		"var depth = nested ? renderedDepth.get(parentID) + 1 : 0;",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("app.js missing active/past agent partition behavior %q", want)
		}
	}
	// The walk is partitioned, never filtered: dropping entries would hide agents
	// from the tab entirely instead of moving them into the other section.
	if strings.Contains(source, "agentGroups.filter(") {
		t.Fatal("app.js filters the agent walk instead of partitioning it, which hides agents from both sections")
	}
	// Every liveness question has to pass the session lifecycle in, so a sealed
	// session can never leave an unclosed agent advertised as running.
	if strings.Contains(source, "agentIsActive(m)") {
		t.Fatal("app.js calls agentIsActive without the session-ended clamp")
	}
	// Indentation inside a section is derived from the parent that is actually
	// rendered above, not carried over from the walk: a re-rooted parent whose
	// own subtree kept the walk's depth would leave that subtree indented under
	// nothing (visible as soon as the tree is more than one level deep).
	if strings.Contains(source, "var depth = og.depth;") {
		t.Fatal("app.js reuses the walk's depth inside a section instead of recomputing it from the rendered parent")
	}
}

// TestEmbeddedAgentsDeriveNestingFromSpawnEdges pins the join that gives the tab
// true nesting: a completed spawn call carries agent.spawned.id (the child it
// created) beside its own agent.id (the spawner), and the two are joined SET-WISE
// after the scan. agent.parent.id on the wire always names the Primary, so
// without this join every generation renders flat under it.
func TestEmbeddedAgentsDeriveNestingFromSpawnEdges(t *testing.T) {
	source := string(appJS)
	for _, want := range []string{
		`var spawnedID = attrRaw(ev, "agent.spawned.id");`,
		`var spawnerID = attrRaw(ev, "agent.id");`,
		"if (spawnerID && !spawnEdges.has(spawnedID)) spawnEdges.set(spawnedID, spawnerID);",
		"spawnEdges.forEach(function (spawnerID, childID) {",
		"m.parentID = spawnerID;",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("app.js missing derived spawn-edge nesting %q", want)
		}
	}
	// The join is applied after the whole scan, alongside the closures, and never
	// while walking: a synchronous spawn's edge is sequenced after its child's
	// registration and a backgrounded one before it, so no seq/timing/adjacency
	// relationship between the two events may be relied on.
	scan := strings.Index(source, `var spawnedID = attrRaw(ev, "agent.spawned.id");`)
	join := strings.Index(source, "spawnEdges.forEach(function (spawnerID, childID) {")
	if scan < 0 || join < 0 || join < scan {
		t.Fatal("app.js applies spawn edges during the scan instead of set-wise after it")
	}
	// An edge naming an id that never registered must not invent an agent, the
	// same rule the orphan-closure path follows.
	if !strings.Contains(source[join:], "if (!m) return;") {
		t.Fatal("app.js does not drop spawn edges whose child never registered")
	}
	// The tree is derived narration joined to narration: same trust ceiling, so
	// no view may hand the joined agents a stronger attribution than the harness
	// claimed for them.
	if strings.Contains(source, `m.strength = "strong"`) || strings.Contains(source, "m.strength = spawner") {
		t.Fatal("app.js promotes attribution strength off the derived spawn-edge join")
	}
}

// TestEmbeddedAgentActivityLineNoArgumentMatchesRowStructure pins the Agents
// tab list view's no-argument row to the SAME structural slot a normal row's
// argument text gets: nested inside the agent-line-text/ellipsis flex-item
// wrapper, never handed to .agent-line-row (a flex container) as a bare
// .empty span. A bare .empty span there is a direct flex child, so it gets
// blockified, and .dash-main .empty's unrelated 24px padding (styling the
// dashboard's own "Select a session." placeholder) then applies to it in
// full -- roughly doubling this one row's height whenever the tab is viewed
// inside the embedded dashboard, while every neighboring row stays at the
// table's 30px floor.
func TestEmbeddedAgentActivityLineNoArgumentMatchesRowStructure(t *testing.T) {
	source := string(appJS)
	start := strings.Index(source, "function agentActivityLineHtml(")
	end := strings.Index(source, "function agentActivityTableHtml(")
	if start < 0 || end <= start {
		t.Fatal("app.js has no agentActivityLineHtml renderer to pin")
	}
	line := source[start:end]
	for _, want := range []string{
		`'<span class="agent-line-text ellipsis">' + esc(textVal) + "</span>"`,
		`'<span class="agent-line-text ellipsis"><span class="empty">(no argument)</span></span>'`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("app.js agentActivityLineHtml missing uniform no-argument row structure %q", want)
		}
	}
	// The regression itself: the no-argument branch must never hand the bare
	// .empty span straight to the flex row.
	if strings.Contains(line, `: '<span class="empty">(no argument)</span>'`) {
		t.Fatal("app.js hands the bare .empty span straight to the agent-line-row flex container instead of nesting it inside agent-line-text")
	}
}

// TestEmbeddedAgentGraphConsumesPrecomputedGroups pins the graph sub-view's
// contract with app.js: it renders the grouping/liveness decisions it is handed
// (so the orphan- and cycle-safety of computeAgentGroups is not re-litigated
// here) and tracks departures in module state so a node can fade out after the
// container has been wiped and rebuilt.
func TestEmbeddedAgentGraphConsumesPrecomputedGroups(t *testing.T) {
	source := string(agentGraphJS)
	for _, want := range []string{
		"window.BoxedAiAgentGraph",
		"data.groups",
		"data.meta",
		"api.agentIsActive(",
		"uiState.exiting",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("agentgraph.js missing precomputed-group/exit-state behavior %q", want)
		}
	}
	// Cards are found by scanning rendered nodes and comparing dataset values;
	// building a selector out of a workload-controlled agent id would let a
	// crafted id break out of the query.
	if strings.Contains(source, `[data-agent-id="`) {
		t.Fatal("agentgraph.js builds an attribute selector from a workload-controlled agent id")
	}
	// The graph is a presentation layer over derived data; re-deriving agents
	// from raw event names here would fork the honesty rules in computeAgentGroups.
	if strings.Contains(source, "ev.name") {
		t.Fatal("agentgraph.js re-derives agents from raw events instead of the grouping it is handed")
	}
}

// TestEmbeddedAgentGraphTickerShowsFullSummaryLines pins the node ticker's
// shape: each line renders the whole tool summary and wraps, because a command
// or path cut mid-token tells a reader nothing. Timestamps belong to the hover
// popover, which is the "more detail" surface; the ticker answers what an agent
// is doing, not when.
func TestEmbeddedAgentGraphTickerShowsFullSummaryLines(t *testing.T) {
	source := string(agentGraphJS)
	start := strings.Index(source, "function tickerHtml(")
	end := strings.Index(source, "function statusHtml(")
	if start < 0 || end <= start {
		t.Fatal("agentgraph.js has no tickerHtml renderer to pin")
	}
	ticker := source[start:end]
	for _, want := range []string{
		`'<span class="agraph-tick-text">'`,
		"api.esc(text)",
	} {
		if !strings.Contains(ticker, want) {
			t.Fatalf("agentgraph.js ticker missing full-summary rendering %q", want)
		}
	}
	// The ticker line is never clipped by the renderer: no ellipsis helper, and
	// no timestamp column stealing width from the summary.
	if strings.Contains(ticker, "truncateEnd") {
		t.Fatal("agentgraph.js ticker truncates the summary instead of wrapping it")
	}
	if strings.Contains(ticker, "tsLabel") {
		t.Fatal("agentgraph.js ticker still renders a timestamp; timestamps belong to the hover popover")
	}

	css := string(appCSS)
	for _, want := range []string{
		"overflow-wrap: anywhere;",
		"-webkit-line-clamp: 10;",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("app.css ticker missing wrap/clamp rule %q", want)
		}
	}
	if strings.Contains(css, ".agraph-tick-ts") {
		t.Fatal("app.css still styles a ticker timestamp column")
	}
}

// cssRuleBody returns the declarations of the first rule with the given
// selector, so a test can assert about one rule instead of the whole file.
func cssRuleBody(t *testing.T, css, selector string) string {
	t.Helper()
	start := strings.Index(css, selector+" {")
	if start < 0 {
		t.Fatalf("app.css has no %q rule", selector)
	}
	rest := css[start+len(selector)+2:]
	end := strings.Index(rest, "}")
	if end < 0 {
		t.Fatalf("app.css rule %q is unterminated", selector)
	}
	return rest[:end]
}

// TestEmbeddedViewerPanesFillTheViewport pins the full-height layout: the shell
// is a flex column that runs to the bottom of the window and the scroller
// inside the active tab takes whatever the toolbars left, on both pages. The
// panes used to stop at a fixed 70vh, which left a dead band under every tab.
func TestEmbeddedViewerPanesFillTheViewport(t *testing.T) {
	css := string(appCSS)

	app := cssRuleBody(t, css, "#app")
	for _, want := range []string{"height: 100%;", "display: flex;", "flex-direction: column;"} {
		if !strings.Contains(app, want) {
			t.Fatalf("app.css #app is not a full-height flex column: missing %q", want)
		}
	}
	pane := cssRuleBody(t, css, ".tab-content")
	for _, want := range []string{"flex: 1 1 auto;", "min-height: 0;", "flex-direction: column;"} {
		if !strings.Contains(pane, want) {
			t.Fatalf("app.css .tab-content does not fill the shell column: missing %q", want)
		}
	}
	// Every scrollable region grows into the pane instead of capping itself at
	// a fraction of the viewport. The Proof tab has no table, so its own body
	// is the scroller (activeScrollEl saves the position of both).
	for _, selector := range []string{".table-wrap", ".proof-body", ".agraph-pane", ".proc-layout"} {
		body := cssRuleBody(t, css, selector)
		if !strings.Contains(body, "flex: 1 1 auto;") {
			t.Fatalf("app.css %s does not flex to fill its pane", selector)
		}
		if strings.Contains(body, "vh;") {
			t.Fatalf("app.css %s still sizes itself as a fraction of the viewport: %q", selector, body)
		}
	}
	if !strings.Contains(string(appJS), `.querySelector(".table-wrap, .proof-body")`) {
		t.Fatal("app.js activeScrollEl no longer finds both tab scrollers, so scroll position is lost across a re-render")
	}
	// A height derived by subtracting the chrome would go wrong the moment the
	// header or a filter bar wrapped onto a second line.
	if strings.Contains(css, "calc(100vh") {
		t.Fatal("app.css hardcodes a viewport-height offset instead of letting the flex chain size the panes")
	}
}

// TestEmbeddedAgentGraphPansAndZoomsOneSharedLayer pins the navigation contract:
// the pane is clipped by a viewport and moved by a transform on ONE inner layer
// that carries both the cards and their SVG edge underlay, so nodes and edges
// can never drift apart. The framing survives a live poll (it lives in module
// state, not the DOM) and the user's own panning outranks a recomputed fit.
func TestEmbeddedAgentGraphPansAndZoomsOneSharedLayer(t *testing.T) {
	source := string(agentGraphJS)
	for _, want := range []string{
		`data-role="viewport"`,
		`data-role="canvas"`,
		"canvas.style.transform =",
		"uiState.transform",
		"uiState.userAdjusted",
		`{ passive: false }`, // the wheel handler preventDefaults, so it cannot be passive
		`data-act="graph-fit"`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("agentgraph.js missing pan/zoom behavior %q", want)
		}
	}
	// The wheel handler is delegated on the whole pane and must cancel the
	// gesture everywhere in it, header strip included. Gating on the target
	// being inside the viewport (a SIBLING of the header) let a wheel that
	// landed on the counts text or the fit button bubble to the document and
	// scroll the page out from under the graph.
	wheelStart := strings.Index(source, "function handleWheel(")
	wheelEnd := strings.Index(source, "function handlePointerDown(")
	if wheelStart < 0 || wheelEnd <= wheelStart {
		t.Fatal("agentgraph.js has no handleWheel to pin")
	}
	wheel := source[wheelStart:wheelEnd]
	if !strings.Contains(wheel, "e.preventDefault();") {
		t.Fatal("agentgraph.js handleWheel does not cancel the gesture, so the page scrolls under the graph")
	}
	if strings.Contains(wheel, "e.target.closest(") {
		t.Fatal("agentgraph.js handleWheel gates on where in the pane the wheel landed; the whole pane is the gesture surface")
	}

	// The edge underlay lives INSIDE the transformed layer, so it must be
	// measured in untransformed layout coordinates. A client rect reports scaled
	// screen pixels and would put every edge in the wrong place at any zoom
	// other than 1.
	start := strings.Index(source, "function drawEdges(")
	end := strings.Index(source, "// ---- pan / zoom ----")
	if start < 0 || end <= start {
		t.Fatal("agentgraph.js has no drawEdges renderer to pin")
	}
	edges := source[start:end]
	if !strings.Contains(edges, "offsetLeft") {
		t.Fatal("agentgraph.js drawEdges does not measure cards from layout offsets")
	}
	if strings.Contains(edges, "getBoundingClientRect") {
		t.Fatal("agentgraph.js drawEdges measures screen rects, which are wrong inside the zoomed layer")
	}

	css := string(appCSS)
	for _, want := range []string{
		".agraph-viewport {",
		"transform-origin: 0 0;",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("app.css missing agent graph viewport rule %q", want)
		}
	}
}

// TestEmbeddedAgentGraphSatelliteRidesTopBandAndPopoverIsReachable pins the two
// layout honesty rules that survived the refinement pass: unattributed activity
// is a dashed peer in the TOP band (never a child of the Primary, and never a
// divider that renders when there is nothing to divide), and the hover panel
// takes pointer events so its scrollback can actually be read.
func TestEmbeddedAgentGraphSatelliteRidesTopBandAndPopoverIsReachable(t *testing.T) {
	source := string(agentGraphJS)
	for _, want := range []string{
		"model.levels[0].push(satellite)",
		"if (!g || !g.members || !g.members.length) return null;", // no activity, no satellite, nothing extra
		"HOVER_GRACE_MS",
		"scheduleHidePopover",
		"stillWithinPopoverPair",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("agentgraph.js missing satellite/hover-intent behavior %q", want)
		}
	}
	// The satellite is appended to a band, never to the node list, so it can
	// never acquire an edge — it belongs to no agent, and drawing one would make
	// exactly the attribution claim the record refuses to make.
	if strings.Contains(source, "nodes.push(satellite)") {
		t.Fatal("agentgraph.js puts the unattributed satellite in the node list, where it can acquire an edge")
	}

	css := string(appCSS)
	if strings.Contains(css, "agraph-satellite-row") {
		t.Fatal("app.css still styles a separate satellite row; the satellite rides in the top band")
	}
	popStart := strings.Index(css, ".agraph-popover {")
	if popStart < 0 {
		t.Fatal("app.css has no agent graph popover rule to pin")
	}
	popEnd := strings.Index(css[popStart:], "}")
	if popEnd < 0 {
		t.Fatal("app.css agent graph popover rule is unterminated")
	}
	popover := css[popStart : popStart+popEnd]
	for _, want := range []string{
		"pointer-events: auto;",
		"overflow-y: auto;",
		"overscroll-behavior: contain;",
	} {
		if !strings.Contains(popover, want) {
			t.Fatalf("app.css popover missing reachable/scrollable rule %q", want)
		}
	}
	if strings.Contains(popover, "pointer-events: none;") {
		t.Fatal("app.css popover is transparent to the pointer, so it can never be moved into or scrolled")
	}
}

// TestEmbeddedAgentGraphAnimationsRespectReducedMotion pins that every animation
// the graph introduces is decoration: each new keyframe has a matching entry in
// the prefers-reduced-motion kill switch, the same guard the pulse animations
// near the top of app.css carry.
func TestEmbeddedAgentGraphAnimationsRespectReducedMotion(t *testing.T) {
	source := string(appCSS)
	for _, want := range []string{
		"@keyframes agraph-pop",
		"@keyframes agraph-vanish",
		"@keyframes agraph-slide",
		"@keyframes agraph-edge-pulse",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("app.css missing agent graph keyframes %q", want)
		}
	}
	guard := strings.LastIndex(source, "@media (prefers-reduced-motion: reduce)")
	if guard < 0 {
		t.Fatal("app.css has no reduced-motion guard for the agent graph animations")
	}
	for _, want := range []string{
		".agraph-card-enter",
		".agraph-card-exit",
		".agraph-tick-new",
		".agraph-edge-live",
	} {
		if !strings.Contains(source[guard:], want) {
			t.Fatalf("app.css reduced-motion guard does not disable %q", want)
		}
	}
	// The graph section must resolve every color through the existing :root
	// tokens so the dark theme (and the evidence-class colors) stay in one place.
	start := strings.Index(source, "/* ---- agents tab: live agent graph ---- */")
	if start < 0 {
		t.Fatal("app.css has no agent graph section header comment")
	}
	if hex := strings.Index(source[start:], "#"); hex >= 0 {
		t.Fatalf("app.css agent graph section introduces a raw color literal instead of a token: %q", source[start+hex:])
	}
}

func resetDashboardCacheForTest(t *testing.T) {
	t.Helper()
	dashboardCacheMu.Lock()
	dashboardCache = map[string]cachedDashboardSession{}
	dashboardCacheMu.Unlock()
}

func writeDashboardManifest(t *testing.T, sessionDir string, recordCount int, lastSeq int64, digest, sealedAt string) {
	t.Helper()
	manifest := map[string]any{
		"segment_number":    1,
		"record_count":      recordCount,
		"first_sequence":    int64(1),
		"last_sequence":     lastSeq,
		"segment_digest":    digest,
		"sealed_at":         sealedAt,
		"policy_digest":     "sha256:policydigest",
		"schema":            "boxedai.segment/v1",
		"session_id":        "bx-test",
		"created_at":        "2026-08-10T00:00:00Z",
		"sensor_loss_count": 0,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	segDir := filepath.Join(sessionDir, "evidence", "segments")
	if err := os.WriteFile(filepath.Join(segDir, "segment-000001.manifest.json"), manifestBytes, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(segDir, "segment-000001.manifest.cose"), []byte("cose"), 0o644); err != nil {
		t.Fatalf("write cose: %v", err)
	}
}
