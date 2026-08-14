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
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Timeline output missing %q; got:\n%s", want, out)
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

// TestAssetsServedByBothMuxes verifies the shared vanilla-JS/CSS client
// (registerAssets) is wired into both the single-session viewer mux and the
// dashboard mux with the right content types, and that each mux's thin HTML
// shell references /assets/app.js and /assets/processes.js.
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
		})
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
