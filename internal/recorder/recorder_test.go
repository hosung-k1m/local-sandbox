package recorder

import (
	"bufio"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"boxedai/internal/evidence"

	cose "github.com/veraison/go-cose"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protodelim"
)

// readRecord is a minimally-decoded LogRecord used by the independent re-reader.
type readRecord struct {
	segment  int
	name     string
	sequence int64
	class    string
	producer string
}

// TestRecorderRoundTrip emits events across a forced seal and Close, then re-reads the
// raw segments (protodelim), verifies each manifest's COSE signature and segment
// digest, checks the prev-digest chain, and asserts sequence continuity 1..N.
func TestRecorderRoundTrip(t *testing.T) {
	root := t.TempDir()
	key, err := LoadOrGenerateKey(filepath.Join(root, "keys"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}

	meta := SessionMeta{
		SessionID:      "bx-20260810-193004-a1b2c3d4",
		TraceID:        "000102030405060708090a0b0c0d0e0f",
		PolicyDigest:   "sha256:0000000000000000000000000000000000000000000000000000000000000001",
		VMImage:        "ubuntu-24.04",
		VMID:           "bx-20260810-193004-a1b2c3d4",
		RecorderPubPEM: key.PubPEM,
	}
	evDir := filepath.Join(root, "evidence")
	rec, err := NewRecorder(evDir, key, meta)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}

	mustEmit := func(ch evidence.Channel, ev evidence.Event) {
		t.Helper()
		if err := rec.Emit(ch, ev); err != nil {
			t.Fatalf("Emit %s: %v", ev.Name, err)
		}
	}

	// Segment 1.
	mustEmit(evidence.ChannelController, evidence.Event{
		Name: evidence.EventSessionGranted, Class: evidence.ClassIntegrity, Outcome: evidence.OutcomeSuccess,
		Body: "session granted",
	})
	mustEmit(evidence.ChannelController, evidence.Event{
		Name: evidence.EventPolicyLoaded, Class: evidence.ClassIntegrity, Outcome: evidence.OutcomeSuccess,
	})
	// Workload may only assert model_self_reported|harness_observed; requesting
	// kernel_observed must clamp to model_self_reported and emit an integrity note.
	mustEmit(evidence.ChannelWorkload, evidence.Event{
		Name: evidence.EventModelRequested, Class: evidence.ClassKernelObserved, Outcome: evidence.OutcomeSuccess,
		Attrs: map[string]any{evidence.AttrContentDigest: "sha256:abc"},
	})
	// A workload may use a sensor event name, but it cannot contribute to the
	// authoritative per-segment sensor-loss counter.
	mustEmit(evidence.ChannelWorkload, evidence.Event{
		Name: evidence.EventSensorLoss, Class: evidence.ClassModelSelfReported, Outcome: evidence.OutcomeFailure,
	})

	if err := rec.SealSegment("test-rotate"); err != nil {
		t.Fatalf("SealSegment: %v", err)
	}

	// Segment 2 (already contains the segment.sealed note for segment 1).
	mustEmit(evidence.ChannelGuestSupervisor, evidence.Event{
		Name: evidence.EventProcessExecuted, Class: evidence.ClassKernelObserved, Outcome: evidence.OutcomeSuccess,
		Attrs: map[string]any{evidence.AttrProcessPID: int64(4242)},
	})
	mustEmit(evidence.ChannelGuestSupervisor, evidence.Event{
		Name: evidence.EventSensorLoss, Class: evidence.ClassIntegrity, Outcome: evidence.OutcomeInterrupted,
	})

	manifests, err := rec.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(manifests) != 2 {
		t.Fatalf("Close returned %d manifests, want 2", len(manifests))
	}

	// --- Independent re-read of the raw segments. ---
	segFiles, err := filepath.Glob(filepath.Join(evDir, "segments", "segment-*.otlp"))
	if err != nil {
		t.Fatalf("glob segments: %v", err)
	}
	sort.Strings(segFiles)
	if len(segFiles) != 2 {
		t.Fatalf("found %d segment files, want 2", len(segFiles))
	}

	var records []readRecord
	for i, seg := range segFiles {
		records = append(records, readSegment(t, seg, i+1)...)
	}

	// Sequence continuity: exactly 1..N, no gaps, no duplicates, in file order.
	if len(records) != 8 {
		t.Fatalf("read %d records, want 8", len(records))
	}
	for i, r := range records {
		if want := int64(i + 1); r.sequence != want {
			t.Fatalf("record %d (%s) has sequence %d, want %d", i, r.name, r.sequence, want)
		}
	}

	// The clamped model.requested was recorded as model_self_reported...
	clampedSubject := findRecord(records, evidence.EventModelRequested)
	if clampedSubject == nil {
		t.Fatal("model.requested not found")
	}
	if clampedSubject.class != string(evidence.ClassModelSelfReported) {
		t.Fatalf("clamped model.requested class = %q, want %q", clampedSubject.class, evidence.ClassModelSelfReported)
	}
	// ...and produced exactly one recorder-attributed integrity note.
	note := findRecord(records, eventClassClamped)
	if note == nil {
		t.Fatal("class-clamp integrity note not found")
	}
	if note.producer != string(evidence.ChannelRecorder) || note.class != string(evidence.ClassIntegrity) {
		t.Fatalf("clamp note producer/class = %q/%q, want recorder/integrity", note.producer, note.class)
	}

	// segment.sealed for segment 1 must appear in segment 2.
	sealed := findRecord(records, evidence.EventSegmentSealed)
	if sealed == nil || sealed.segment != 2 {
		t.Fatalf("segment.sealed not found in segment 2: %+v", sealed)
	}

	// --- Verify each manifest: COSE signature, digest of file bytes, prev-digest chain. ---
	verifier, err := loadVerifier(key.PubPEM)
	if err != nil {
		t.Fatalf("loadVerifier: %v", err)
	}
	var prevDigest string
	var totalRecords int64
	for i, seg := range segFiles {
		segNum := i + 1
		base := filepath.Join(evDir, "segments", "segment-000001")
		if segNum == 2 {
			base = filepath.Join(evDir, "segments", "segment-000002")
		}
		manBytes, err := os.ReadFile(base + ".manifest.json")
		if err != nil {
			t.Fatalf("read manifest %d: %v", segNum, err)
		}
		coseBytes, err := os.ReadFile(base + ".manifest.cose")
		if err != nil {
			t.Fatalf("read cose %d: %v", segNum, err)
		}

		// COSE Sign1 over the exact manifest bytes.
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(coseBytes); err != nil {
			t.Fatalf("decode cose %d: %v", segNum, err)
		}
		if err := msg.Verify(nil, verifier); err != nil {
			t.Fatalf("cose verify %d: %v", segNum, err)
		}
		if string(msg.Payload) != string(manBytes) {
			t.Fatalf("cose payload for segment %d does not equal manifest bytes", segNum)
		}

		var man segmentManifest
		if err := json.Unmarshal(manBytes, &man); err != nil {
			t.Fatalf("unmarshal manifest %d: %v", segNum, err)
		}

		// Digest must match the exact segment file bytes.
		fileBytes, err := os.ReadFile(seg)
		if err != nil {
			t.Fatalf("read segment file %d: %v", segNum, err)
		}
		if got := evidence.SHA256Hex(fileBytes); got != man.SegmentDigest {
			t.Fatalf("segment %d digest mismatch: manifest=%s recomputed=%s", segNum, man.SegmentDigest, got)
		}

		// prev-digest chain.
		if man.PrevSegmentDigest != prevDigest {
			t.Fatalf("segment %d prev_segment_digest = %q, want %q", segNum, man.PrevSegmentDigest, prevDigest)
		}
		prevDigest = man.SegmentDigest

		// Manifest metadata sanity.
		if man.Schema != manifestSchema {
			t.Fatalf("segment %d schema = %q, want %q", segNum, man.Schema, manifestSchema)
		}
		if man.SessionID != meta.SessionID || man.PolicyDigest != meta.PolicyDigest {
			t.Fatalf("segment %d session/policy mismatch: %+v", segNum, man)
		}
		if man.FirstSequence != totalRecords+1 {
			t.Fatalf("segment %d first_sequence = %d, want %d", segNum, man.FirstSequence, totalRecords+1)
		}
		totalRecords += man.RecordCount
		if man.LastSequence != totalRecords {
			t.Fatalf("segment %d last_sequence = %d, want %d", segNum, man.LastSequence, totalRecords)
		}
	}
	if totalRecords != int64(len(records)) {
		t.Fatalf("manifest record totals %d != read records %d", totalRecords, len(records))
	}

	// sensor.loss occurred in segment 2, so its manifest counts one loss.
	seg2Man := readManifest(t, filepath.Join(evDir, "segments", "segment-000002.manifest.json"))
	if seg2Man.SensorLossCount != 1 {
		t.Fatalf("segment 2 sensor_loss_count = %d, want 1", seg2Man.SensorLossCount)
	}
	seg1Man := readManifest(t, filepath.Join(evDir, "segments", "segment-000001.manifest.json"))
	if seg1Man.SensorLossCount != 0 {
		t.Fatalf("segment 1 sensor_loss_count = %d, want 0", seg1Man.SensorLossCount)
	}
}

// TestEmitAfterCloseFails asserts the recorder fails closed once sealed.
func TestEmitAfterCloseFails(t *testing.T) {
	root := t.TempDir()
	key, err := LoadOrGenerateKey(filepath.Join(root, "keys"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	rec, err := NewRecorder(filepath.Join(root, "evidence"), key, SessionMeta{SessionID: "bx-x"})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	if _, err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := rec.Emit(evidence.ChannelController, evidence.Event{Name: evidence.EventSessionStopped}); err == nil {
		t.Fatal("Emit after Close should error")
	}
}

// TestLoadOrGenerateKeyReuse asserts a second load returns the same key material.
func TestLoadOrGenerateKeyReuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	k1, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	k2, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !k1.Priv.Equal(k2.Priv) {
		t.Fatal("reloaded private key differs from generated key")
	}
	if k1.PubPEM != k2.PubPEM {
		t.Fatal("reloaded public PEM differs")
	}
	if _, err := os.Stat(filepath.Join(dir, privKeyFile)); err != nil {
		t.Fatalf("recorder.key missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, pubKeyFile)); err != nil {
		t.Fatalf("recorder.pub missing: %v", err)
	}
}

// readSegment decodes every length-delimited LogsData in a segment file and returns
// the minimally-decoded records, in file order.
func readSegment(t *testing.T, path string, segNum int) []readRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	br := bufio.NewReader(f)
	var out []readRecord
	for {
		var ld logspb.LogsData
		if err := protodelim.UnmarshalFrom(br, &ld); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("unmarshal record in %s: %v", path, err)
		}
		for _, rl := range ld.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				for _, lr := range sl.LogRecords {
					out = append(out, readRecord{
						segment:  segNum,
						name:     lr.EventName,
						sequence: attrInt(lr.Attributes, evidence.AttrSequence),
						class:    attrStr(lr.Attributes, evidence.AttrEvidenceClass),
						producer: attrStr(lr.Attributes, evidence.AttrProducer),
					})
				}
			}
		}
	}
	return out
}

func readManifest(t *testing.T, path string) segmentManifest {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest %s: %v", path, err)
	}
	var m segmentManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal manifest %s: %v", path, err)
	}
	return m
}

func loadVerifier(pubPEM string) (cose.Verifier, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("public PEM did not decode")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ed25519")
	}
	return cose.NewVerifier(cose.AlgorithmEdDSA, pub)
}

func findRecord(records []readRecord, name string) *readRecord {
	for i := range records {
		if records[i].name == name {
			return &records[i]
		}
	}
	return nil
}

func attrStr(kvs []*commonpb.KeyValue, key string) string {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value.GetStringValue()
		}
	}
	return ""
}

func attrInt(kvs []*commonpb.KeyValue, key string) int64 {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value.GetIntValue()
		}
	}
	return 0
}
