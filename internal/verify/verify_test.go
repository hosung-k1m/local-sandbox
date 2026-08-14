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
	"strings"
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
	class         string
	outcome       string
	actionID      string
	contentDigest string
	producer      string
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
	_ = f.writeSessionJSONWithSchema(sessionGrantV1)
}

func (f *fixture) writeSessionJSONWithSchema(schema string) string {
	f.t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(f.pub)
	if err != nil {
		f.t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	g := map[string]any{
		"schema":        schema,
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
	return evidence.SHA256Hex(b)
}

func (f *fixture) writeSessionJSONV2() string {
	f.t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(f.pub)
	if err != nil {
		f.t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	g := map[string]any{
		"schema":        "boxedai.session/v2",
		"session_id":    testSessionID,
		"policy_digest": testPolicyDigest,
		"recorder_pub":  string(pubPEM),
		"trust_record": map[string]any{
			"schema":   "boxedai.trust-record/v1",
			"path":     "trust-record.json",
			"required": true,
		},
	}
	b, err := json.Marshal(g)
	if err != nil {
		f.t.Fatalf("marshal v2 grant: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "session.json"), b, 0o644); err != nil {
		f.t.Fatalf("write v2 session.json: %v", err)
	}
	return evidence.SHA256Hex(b)
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
		producer := ev.producer
		if producer == "" {
			producer = producerForTestEvent(ev.name)
		}
		class := ev.class
		if class == "" {
			class = classForTestEvent(ev.name, producer)
		}
		recAttrs := []*commonv1.KeyValue{
			kvInt(evidence.AttrSequence, seq),
			kvStr(evidence.AttrProducer, producer),
			kvStr(evidence.AttrEvidenceClass, class),
		}
		if ev.outcome != "" {
			recAttrs = append(recAttrs, kvStr(evidence.AttrOutcome, ev.outcome))
		}
		if ev.actionID != "" {
			recAttrs = append(recAttrs, kvStr(evidence.AttrActionID, ev.actionID))
		}
		if ev.contentDigest != "" {
			recAttrs = append(recAttrs, kvStr(evidence.AttrContentDigest, ev.contentDigest))
		}
		if ev.name == evidence.EventProcessCreated || ev.name == evidence.EventProcessExecuted || ev.name == evidence.EventProcessExited {
			recAttrs = append(recAttrs, kvStr("observer", "tetragon"))
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

func classForTestProducer(producer string) string {
	switch producer {
	case string(evidence.ChannelBroker):
		return string(evidence.ClassBrokerMediated)
	case string(evidence.ChannelGuestSupervisor):
		return string(evidence.ClassKernelObserved)
	case string(evidence.ChannelWorkload):
		return string(evidence.ClassModelSelfReported)
	default:
		return string(evidence.ClassIntegrity)
	}
}

func classForTestEvent(name, producer string) string {
	if producer == string(evidence.ChannelGuestSupervisor) {
		switch name {
		case evidence.EventSensorStarted, evidence.EventSensorLoss, evidence.EventSensorRestarted:
			return string(evidence.ClassIntegrity)
		}
	}
	return classForTestProducer(producer)
}

func producerForTestEvent(name string) string {
	switch name {
	case evidence.EventAuthorizationDecided,
		evidence.EventModelRequested,
		evidence.EventModelCompleted,
		evidence.EventInternalToolDispatched,
		evidence.EventInternalToolCompleted,
		evidence.EventInternalToolFailed,
		evidence.EventEffectRequested,
		evidence.EventEffectApproved,
		evidence.EventEffectDenied,
		evidence.EventEffectDispatched,
		evidence.EventEffectCompleted,
		evidence.EventEffectFailed:
		return string(evidence.ChannelBroker)
	case evidence.EventSensorStarted,
		evidence.EventSensorLoss,
		evidence.EventSensorRestarted,
		evidence.EventProcessExecuted,
		evidence.EventProcessExited,
		evidence.EventFileChanged,
		evidence.EventFileDeleted,
		evidence.EventNetworkConnected,
		evidence.EventNetworkDenied:
		return string(evidence.ChannelGuestSupervisor)
	default:
		return string(evidence.ChannelController)
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
		{name: evidence.EventProcessExited},
		{name: evidence.EventEffectApproved, outcome: string(evidence.OutcomeSuccess), actionID: "act-eff", contentDigest: "sha256:deadbeef"},
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

func TestVerify_Incomplete_WorkloadCannotForgeSensorStart(t *testing.T) {
	f := newFixture(t)
	events := happyEvents(f.outDigest)
	for i := range events {
		if events[i].name == evidence.EventSensorStarted {
			events[i].producer = string(evidence.ChannelWorkload)
		}
	}
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %s, want INCOMPLETE\n%s", rep.Verdict, rep.String())
	}
	if checkPassed(rep, stepSensor) {
		t.Error("sensor-invariants check should reject workload-produced sensor.started")
	}
}

func TestVerify_Incomplete_StartedSessionRequiresTetragonExecAndExit(t *testing.T) {
	for _, missing := range []string{evidence.EventProcessExecuted, evidence.EventProcessExited} {
		t.Run(missing, func(t *testing.T) {
			f := newFixture(t)
			var events []eventSpec
			for _, event := range happyEvents(f.outDigest) {
				if event.name != missing {
					events = append(events, event)
				}
			}
			f.writeSegment(events)
			rep, err := Verify(f.dir)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if rep.Verdict != VerdictIncomplete || checkPassed(rep, stepSensor) {
				t.Fatalf("verdict/sensor = %s/%v, want INCOMPLETE/failed\n%s", rep.Verdict, checkPassed(rep, stepSensor), rep.String())
			}
		})
	}
}

func TestVerify_Incomplete_IntegrityClassSensorLossIsCounted(t *testing.T) {
	f := newFixture(t)
	events := happyEvents(f.outDigest)
	events = append(events[:len(events)-2], append([]eventSpec{{name: evidence.EventSensorLoss}}, events[len(events)-2:]...)...)
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictIncomplete || rep.Facets.SensorLossCount != 1 {
		t.Fatalf("verdict/facets = %s/%+v, want INCOMPLETE with one sensor loss", rep.Verdict, rep.Facets)
	}
	if checkPassed(rep, stepSensor) {
		t.Error("sensor-invariants check should fail for guest integrity sensor.loss")
	}
}

func TestCheckSensor_ProcfsCoverageIsIncomplete(t *testing.T) {
	guestIntegrity := map[string]any{
		evidence.AttrProducer:      string(evidence.ChannelGuestSupervisor),
		evidence.AttrEvidenceClass: string(evidence.ClassIntegrity),
		"sensor.mechanism":         "procfs",
	}
	guestKernel := map[string]any{
		evidence.AttrProducer:      string(evidence.ChannelGuestSupervisor),
		evidence.AttrEvidenceClass: string(evidence.ClassKernelObserved),
		"observer":                 "procfs",
	}
	for _, tc := range []struct {
		name    string
		records []record
	}{
		{
			name: "sensor reports procfs",
			records: []record{
				{seq: 1, name: evidence.EventSensorStarted, attrs: guestIntegrity},
			},
		},
		{
			name: "process reports procfs",
			records: []record{
				{seq: 1, name: evidence.EventSensorStarted, attrs: map[string]any{
					evidence.AttrProducer:      string(evidence.ChannelGuestSupervisor),
					evidence.AttrEvidenceClass: string(evidence.ClassIntegrity),
					"sensor.mechanism":         "tetragon",
				}},
				{seq: 2, name: evidence.EventProcessExecuted, attrs: guestKernel},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, _, detail := checkSensor(tc.records)
			if ok {
				t.Fatalf("checkSensor = ok, want incomplete for procfs coverage: %s", detail)
			}
			if !strings.Contains(detail, "authoritative process coverage used procfs polling") {
				t.Fatalf("checkSensor detail = %q, want procfs coverage reason", detail)
			}
		})
	}
}

func TestCheckSensor_StartedSessionRequiresTetragonExecAndExit(t *testing.T) {
	controller := map[string]any{evidence.AttrProducer: string(evidence.ChannelController)}
	guestIntegrity := map[string]any{
		evidence.AttrProducer:      string(evidence.ChannelGuestSupervisor),
		evidence.AttrEvidenceClass: string(evidence.ClassIntegrity),
		"sensor.mechanism":         "tetragon",
	}
	guestKernel := map[string]any{
		evidence.AttrProducer:      string(evidence.ChannelGuestSupervisor),
		evidence.AttrEvidenceClass: string(evidence.ClassKernelObserved),
		"observer":                 "tetragon",
	}
	base := []record{
		{seq: 1, name: evidence.EventSessionStarted, attrs: controller},
		{seq: 2, name: evidence.EventSensorStarted, attrs: guestIntegrity},
	}
	for _, tc := range []struct {
		name    string
		records []record
	}{
		{name: "no lifecycle", records: base},
		{name: "exec only", records: append(append([]record(nil), base...), record{seq: 3, name: evidence.EventProcessExecuted, attrs: guestKernel})},
		{name: "exit only", records: append(append([]record(nil), base...), record{seq: 3, name: evidence.EventProcessExited, attrs: guestKernel})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, _, detail := checkSensor(tc.records)
			if ok || !strings.Contains(detail, "lacks trusted Tetragon") {
				t.Fatalf("checkSensor = %v, %q, want incomplete lifecycle coverage", ok, detail)
			}
		})
	}
	complete := append(append([]record(nil), base...),
		record{seq: 3, name: evidence.EventProcessExecuted, attrs: guestKernel},
		record{seq: 4, name: evidence.EventProcessExited, attrs: guestKernel},
	)
	if ok, _, detail := checkSensor(complete); !ok {
		t.Fatalf("complete checkSensor = false: %s", detail)
	}
}

func TestCheckSensor_PreLaunchAbortDoesNotRequireProcessLifecycle(t *testing.T) {
	records := []record{{seq: 1, name: evidence.EventSensorStarted, attrs: map[string]any{
		evidence.AttrProducer:      string(evidence.ChannelGuestSupervisor),
		evidence.AttrEvidenceClass: string(evidence.ClassIntegrity),
		"sensor.mechanism":         "tetragon",
	}}}
	if ok, _, detail := checkSensor(records); !ok {
		t.Fatalf("pre-launch checkSensor = false: %s", detail)
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

func TestVerify_BypassDetected_NonSuccessfulAuthorizationDoesNotAllowTool(t *testing.T) {
	f := newFixture(t)
	events := happyEvents(f.outDigest)
	for i := range events {
		if events[i].name == evidence.EventAuthorizationDecided {
			events[i].outcome = string(evidence.OutcomeFailure)
		}
	}
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictBypassDetected || rep.Facets.UngatedActivityCount != 1 {
		t.Fatalf("verdict/facets = %s/%+v, want BYPASS_DETECTED with one ungated tool", rep.Verdict, rep.Facets)
	}
}

func TestVerify_BypassDetected_NonSuccessfulApprovalDoesNotAllowEffect(t *testing.T) {
	f := newFixture(t)
	events := happyEvents(f.outDigest)
	for i := range events {
		if events[i].name == evidence.EventEffectApproved {
			events[i].outcome = string(evidence.OutcomeInterrupted)
		}
	}
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictBypassDetected || rep.Facets.UngatedActivityCount != 1 {
		t.Fatalf("verdict/facets = %s/%+v, want BYPASS_DETECTED with one ungated effect", rep.Verdict, rep.Facets)
	}
}

func TestVerify_Incomplete_MissingRequiredTrustRecord(t *testing.T) {
	f := newFixture(t)
	grantDigest := f.writeSessionJSONV2()
	events := happyEvents(f.outDigest)
	events[0].contentDigest = grantDigest
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %s, want INCOMPLETE\n%s", rep.Verdict, rep.String())
	}
	if rep.Facets.TrustRecordStatus != "missing_required" {
		t.Errorf("trust record status = %q, want missing_required", rep.Facets.TrustRecordStatus)
	}
}

func TestVerify_TamperSuspected_GrantDowngradeCannotHideMissingRecord(t *testing.T) {
	f := newFixture(t)
	grantDigest := f.writeSessionJSONV2()
	events := happyEvents(f.outDigest)
	events[0].contentDigest = grantDigest
	f.writeSegment(events)

	f.writeSessionJSON()
	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictTamperSuspected {
		t.Fatalf("verdict = %s, want TAMPER_SUSPECTED\n%s", rep.Verdict, rep.String())
	}
	if checkPassed(rep, stepGrantRecord) {
		t.Error("session-grant-binding check should have failed")
	}
}

func TestVerify_UnsupportedGrantSchemaFailsClosed(t *testing.T) {
	f := newFixture(t)
	grantDigest := f.writeSessionJSONWithSchema("boxedai.session/v99")
	events := happyEvents(f.outDigest)
	events[0].contentDigest = grantDigest
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict == VerdictLocalOnly {
		t.Fatalf("verdict = %s, want fail-closed verdict\n%s", rep.Verdict, rep.String())
	}
	if rep.Facets.TrustRecordStatus != "unsupported_grant_schema" || checkPassed(rep, stepGrantRecord) {
		t.Fatalf("grant/trust checks = %+v, want unsupported schema failure", rep)
	}
}

func TestDeriveActivityClaimRejectsFractionalTokenUsage(t *testing.T) {
	_, err := deriveActivityClaim([]record{{
		name: evidence.EventModelCompleted,
		attrs: map[string]any{
			evidence.AttrProducer:      string(evidence.ChannelBroker),
			evidence.AttrEvidenceClass: string(evidence.ClassBrokerMediated),
			"model.provider":           "openai",
			"llm.usage.input_tokens":   1.5,
		},
	}})
	if err == nil {
		t.Fatal("deriveActivityClaim accepted fractional token usage")
	}
}

func TestDeriveEvidenceClaimRejectsTraceIDMismatch(t *testing.T) {
	dir := t.TempDir()
	otlpPath := filepath.Join(dir, "segment-000001.otlp")
	manifestPath := filepath.Join(dir, "segment-000001.manifest.json")
	segmentBytes := []byte("sealed segment")
	if err := os.WriteFile(otlpPath, segmentBytes, 0o600); err != nil {
		t.Fatalf("write segment: %v", err)
	}
	if err := os.WriteFile(manifestPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	g := grant{SessionID: testSessionID, TraceID: "11111111111111111111111111111111", PolicyDigest: testPolicyDigest}
	manifest := segmentManifest{
		Schema: "boxedai.segment/v1", SessionID: testSessionID, SegmentNumber: 1,
		FirstSequence: 1, LastSequence: 1, RecordCount: 1,
		SegmentDigest: evidence.SHA256Hex(segmentBytes), PolicyDigest: testPolicyDigest,
		SealedAt: "2026-08-10T00:00:01Z",
	}
	records := []record{{
		seq: 1, seg: 0, traceID: "22222222222222222222222222222222",
		attrs: map[string]any{
			evidence.AttrSchemaVersion: evidence.SchemaVersion,
			evidence.AttrSessionID:     testSessionID,
			evidence.AttrPolicyDigest:  testPolicyDigest,
		},
	}}
	_, err := deriveEvidenceClaim(g, []segFiles{{number: 1, otlp: otlpPath, manifest: manifestPath}}, []segmentManifest{manifest}, records)
	if err == nil {
		t.Fatal("deriveEvidenceClaim accepted an OTLP trace ID that differs from the grant")
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
