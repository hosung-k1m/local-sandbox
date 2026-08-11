package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	cose "github.com/veraison/go-cose"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protodelim"

	"boxedai/internal/evidence"
)

// The fixtures below are built entirely by hand from go-cose / protodelim (never
// via internal/recorder) so the test exercises the verifier as a genuinely
// independent reader of the on-disk evidence.

const (
	testSessionID    = "bx-20260810-000000-abcdef01"
	testPolicyDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

// eventSpec is a minimal description of one evidence event to synthesize.
type eventSpec struct {
	name          string
	outcome       string
	actionID      string
	contentDigest string
}

// fixture holds the trust material and paths for one synthesized session.
type fixture struct {
	t          *testing.T
	dir        string
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	outDigest  string // digest of the output-manifest.json file we write
	segmentDir string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dir := t.TempDir()
	segDir := filepath.Join(dir, "evidence", "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatalf("mkdir segments: %v", err)
	}

	// Write an output manifest and record its digest so the happy-path
	// workspace.manifested(output) event can reference the real file bytes.
	outBytes := []byte(`{"schema":"boxedai.snapshot/v1","files":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "output-manifest.json"), outBytes, 0o644); err != nil {
		t.Fatalf("write output manifest: %v", err)
	}

	f := &fixture{t: t, dir: dir, priv: priv, pub: pub, outDigest: evidence.SHA256Hex(outBytes), segmentDir: segDir}
	f.writeSessionJSON()
	return f
}

func (f *fixture) writeSessionJSON() {
	pubDER, err := x509.MarshalPKIXPublicKey(f.pub)
	if err != nil {
		f.t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	g := map[string]any{
		"schema":        "boxedai.session/v1",
		"session_id":    testSessionID,
		"policy_digest": testPolicyDigest,
		"recorder_pub":  string(pubPEM),
	}
	b, err := json.Marshal(g)
	if err != nil {
		f.t.Fatalf("marshal grant: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "session.json"), b, 0o644); err != nil {
		f.t.Fatalf("write session.json: %v", err)
	}
}

func kvStr(k, v string) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: v}}}
}

func kvInt(k string, v int64) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: k, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: v}}}
}

// writeSegment synthesizes a single sealed segment from the event specs: assigns
// sequences 1..N in order, writes the length-delimited OTLP WAL, then the
// canonical manifest and its COSE Sign1. Session id and policy digest live on the
// Resource (constant), per-record fields on the LogRecord, exercising the
// verifier's resource/record attribute merge.
func (f *fixture) writeSegment(events []eventSpec) {
	f.t.Helper()
	resAttrs := []*commonv1.KeyValue{
		kvStr(evidence.AttrSchemaVersion, evidence.SchemaVersion),
		kvStr(evidence.AttrSessionID, testSessionID),
		kvStr(evidence.AttrPolicyDigest, testPolicyDigest),
	}

	var buf bytes.Buffer
	for i, ev := range events {
		seq := int64(i + 1)
		recAttrs := []*commonv1.KeyValue{kvInt(evidence.AttrSequence, seq)}
		if ev.outcome != "" {
			recAttrs = append(recAttrs, kvStr(evidence.AttrOutcome, ev.outcome))
		}
		if ev.actionID != "" {
			recAttrs = append(recAttrs, kvStr(evidence.AttrActionID, ev.actionID))
		}
		if ev.contentDigest != "" {
			recAttrs = append(recAttrs, kvStr(evidence.AttrContentDigest, ev.contentDigest))
		}
		ld := &logsv1.LogsData{ResourceLogs: []*logsv1.ResourceLogs{{
			Resource: &resourcev1.Resource{Attributes: resAttrs},
			ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: []*logsv1.LogRecord{{
				TimeUnixNano: uint64(1_700_000_000_000_000_000 + seq),
				EventName:    ev.name,
				Attributes:   recAttrs,
			}}}},
		}}}
		if _, err := protodelim.MarshalTo(&buf, ld); err != nil {
			f.t.Fatalf("marshal frame: %v", err)
		}
	}

	otlpPath := filepath.Join(f.segmentDir, "segment-000001.otlp")
	if err := os.WriteFile(otlpPath, buf.Bytes(), 0o644); err != nil {
		f.t.Fatalf("write otlp: %v", err)
	}

	man := segmentManifest{
		Schema:            "boxedai.segment/v1",
		SessionID:         testSessionID,
		SegmentNumber:     1,
		FirstSequence:     1,
		LastSequence:      int64(len(events)),
		RecordCount:       len(events),
		PrevSegmentDigest: "",
		SegmentDigest:     evidence.SHA256Hex(buf.Bytes()),
		PolicyDigest:      testPolicyDigest,
		CreatedAt:         "2026-08-10T00:00:00Z",
		SealedAt:          "2026-08-10T00:00:01Z",
	}
	manBytes, err := evidence.CanonicalJSON(man)
	if err != nil {
		f.t.Fatalf("canonical manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.segmentDir, "segment-000001.manifest.json"), manBytes, 0o644); err != nil {
		f.t.Fatalf("write manifest: %v", err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, f.priv)
	if err != nil {
		f.t.Fatalf("new signer: %v", err)
	}
	headers := cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA}}
	coseBytes, err := cose.Sign1(rand.Reader, signer, headers, manBytes, nil)
	if err != nil {
		f.t.Fatalf("sign manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.segmentDir, "segment-000001.manifest.cose"), coseBytes, 0o644); err != nil {
		f.t.Fatalf("write cose: %v", err)
	}
}

// happyEvents is a complete, valid session that must verify as LOCAL_ONLY: full
// lifecycle in order, sensor up before the first process, a gated tool call and a
// gated effect, and an output manifest matching the recorded digest.
func happyEvents(outDigest string) []eventSpec {
	return []eventSpec{
		{name: evidence.EventSessionGranted},
		{name: evidence.EventSessionStarted},
		{name: evidence.EventSensorStarted},
		{name: evidence.EventAuthorizationDecided, outcome: string(evidence.OutcomeSuccess), actionID: "act-tool"},
		{name: evidence.EventInternalToolDispatched, actionID: "act-tool"},
		{name: evidence.EventProcessExecuted},
		{name: evidence.EventEffectApproved, actionID: "act-eff", contentDigest: "sha256:deadbeef"},
		{name: evidence.EventEffectDispatched, actionID: "act-eff", contentDigest: "sha256:deadbeef"},
		{name: evidence.EventWorkspaceManifested, contentDigest: outDigest},
		{name: evidence.EventSessionStopped},
		{name: evidence.EventSessionSealed},
	}
}

func TestVerify_LocalOnly(t *testing.T) {
	f := newFixture(t)
	f.writeSegment(happyEvents(f.outDigest))

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictLocalOnly {
		t.Fatalf("verdict = %s, want LOCAL_ONLY\n%s", rep.Verdict, rep.String())
	}
	if !rep.Facets.SignatureValid || !rep.Facets.ChainValid || !rep.Facets.SequenceContinuous {
		t.Errorf("facets not all valid: %+v", rep.Facets)
	}
	if rep.Facets.CloseStatus != "sealed" {
		t.Errorf("close status = %q, want sealed", rep.Facets.CloseStatus)
	}
	if rep.Facets.UngatedActivityCount != 0 {
		t.Errorf("ungated activity = %d, want 0", rep.Facets.UngatedActivityCount)
	}
	for _, c := range rep.Checks {
		if !c.Passed {
			t.Errorf("check %s failed: %s", c.Name, c.Detail)
		}
	}
	// VERIFIED must be unreachable and explained.
	if rep.Facets.VerifiedUnreachable == "" {
		t.Error("VerifiedUnreachable reason is empty")
	}
}

func TestVerify_TamperSuspected_MutatedSegment(t *testing.T) {
	f := newFixture(t)
	f.writeSegment(happyEvents(f.outDigest))

	// Flip one ASCII byte inside a string value in the WAL. The frame still
	// decodes (same length, valid UTF-8), but the recomputed segment digest no
	// longer matches the signed manifest.
	otlpPath := filepath.Join(f.segmentDir, "segment-000001.otlp")
	data, err := os.ReadFile(otlpPath)
	if err != nil {
		t.Fatalf("read otlp: %v", err)
	}
	idx := bytes.Index(data, []byte("abcdef01"))
	if idx < 0 {
		t.Fatal("marker not found in segment; cannot mutate deterministically")
	}
	data[idx] = 'X' // 'a' -> 'X', still ASCII
	if err := os.WriteFile(otlpPath, data, 0o644); err != nil {
		t.Fatalf("rewrite otlp: %v", err)
	}

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictTamperSuspected {
		t.Fatalf("verdict = %s, want TAMPER_SUSPECTED\n%s", rep.Verdict, rep.String())
	}
	if passed := checkPassed(rep, stepDigests); passed {
		t.Error("segment-digests check should have failed")
	}
}

func TestVerify_Incomplete_MissingSeal(t *testing.T) {
	f := newFixture(t)
	events := happyEvents(f.outDigest)
	events = events[:len(events)-1] // drop session.sealed (last event)
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %s, want INCOMPLETE\n%s", rep.Verdict, rep.String())
	}
	if rep.Facets.CloseStatus == "sealed" {
		t.Error("close status should not be sealed when session.sealed is missing")
	}
	if checkPassed(rep, stepLifecycle) {
		t.Error("session-lifecycle check should have failed")
	}
	// Integrity checks must still pass — this is not tamper.
	if !rep.Facets.SignatureValid || !rep.Facets.SequenceContinuous {
		t.Errorf("integrity facets should hold: %+v", rep.Facets)
	}
}

func TestVerify_BypassDetected_UngatedEffect(t *testing.T) {
	f := newFixture(t)
	// Full, valid, sealed session, but with an effect.dispatched that has no
	// preceding effect.approved.
	events := []eventSpec{
		{name: evidence.EventSessionGranted},
		{name: evidence.EventSessionStarted},
		{name: evidence.EventSensorStarted},
		{name: evidence.EventProcessExecuted},
		{name: evidence.EventEffectDispatched, actionID: "act-rogue", contentDigest: "sha256:unapproved"},
		{name: evidence.EventSessionStopped},
		{name: evidence.EventSessionSealed},
	}
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictBypassDetected {
		t.Fatalf("verdict = %s, want BYPASS_DETECTED\n%s", rep.Verdict, rep.String())
	}
	if rep.Facets.UngatedActivityCount != 1 {
		t.Errorf("ungated activity = %d, want 1", rep.Facets.UngatedActivityCount)
	}
	if checkPassed(rep, stepFlow) {
		t.Error("flow-invariants check should have failed")
	}
	// Not tamper: signatures and digests are intact.
	if !rep.Facets.SignatureValid {
		t.Error("signature should still be valid under a bypass")
	}
}

func checkPassed(rep Report, name string) bool {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c.Passed
		}
	}
	return false
}
