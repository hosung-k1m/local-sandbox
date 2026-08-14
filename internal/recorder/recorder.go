// Package recorder is the BoxedAi evidence recorder: it owns audit sequencing,
// writes OTLP length-delimited WAL segments, and seals each segment with a
// canonical-JSON manifest COSE-signed by the recorder's Ed25519 key. It is the sole
// assigner of audit.sequence and of the evidence class/producer per authenticated
// channel. See DESIGN.md "Recorder", "Evidence storage", "Host filesystem layout".
package recorder

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"boxedai/internal/evidence"

	"google.golang.org/protobuf/encoding/protodelim"
)

// segmentSizeThreshold is the default WAL size (bytes) that triggers an automatic seal.
const segmentSizeThreshold = 8 << 20 // 8 MiB

// eventClassClamped is the recorder-internal integrity note emitted when a producer's
// requested evidence class is clamped to its channel maximum. It is not part of the
// producer event catalog (only the recorder emits it); see the deviation note.
const eventClassClamped = "integrity.class_clamped"

// Attribute keys for recorder-generated integrity notes.
const (
	attrAttemptedClass  = "audit.class.attempted"
	attrAssignedClass   = "audit.class.assigned"
	attrSubjectSequence = "audit.subject.sequence"
	attrSubjectEvent    = "audit.subject.event"
	attrSubjectProducer = "audit.subject.producer"
	attrSealedSegment   = "segment.number"
	attrSealedDigest    = "segment.digest"
	attrSealReason      = "segment.seal_reason"
)

// Recorder ingests evidence events, serializes them into signed OTLP segments, and
// seals segments on demand. Emit never silently drops: a non-nil error means the
// event was not durably recorded and the session must fail closed.
type Recorder interface {
	evidence.Emitter                             // Emit(ch, ev) error
	SealSegment(reason string) error             // rotate: seal current WAL, open next
	Close() (finalManifests []string, err error) // drain, seal final segment
}

// resolvedRecord is one record after the recorder has resolved its producer, class,
// clocks and outcome, ready to be assigned a sequence and written.
type resolvedRecord struct {
	name           string
	producer       evidence.Channel
	class          evidence.Class
	wall           time.Time
	observed       time.Time
	mono           int64
	outcome        evidence.Outcome
	actionID       string
	parentActionID string
	body           string
	attrs          map[string]any
}

// recorder is the single-writer implementation of Recorder. All mutable state is
// guarded by mu, so writes are serialized (one logical writer) while Emit still
// returns write errors synchronously.
type recorder struct {
	segDir    string
	key       SigningKey
	meta      SessionMeta
	traceID   []byte
	monoStart time.Time

	mu            sync.Mutex
	seq           int64 // last assigned audit.sequence (session-global, from 1)
	segNum        int   // current segment number (from 1)
	f             *os.File
	segPath       string
	segBytes      int64
	firstSeq      int64 // first sequence in the current segment (0 if none yet)
	lastSeq       int64 // last sequence in the current segment
	recordCount   int64 // records in the current segment
	lossCount     int64 // sensor.loss events in the current segment
	restartCount  int64 // sensor.restarted events in the current segment
	createdAt     time.Time
	prevDigest    string // segment_digest of the previously sealed segment ("" for first)
	manifestPaths []string
	closed        bool
}

// NewRecorder creates a recorder writing segments under <dir>/segments/. dir is the
// session evidence directory (sessions/<id>/evidence). The first segment is opened
// immediately.
func NewRecorder(dir string, key SigningKey, meta SessionMeta) (Recorder, error) {
	if key.Priv == nil {
		return nil, fmt.Errorf("recorder: signing key is empty")
	}
	if meta.SessionID == "" {
		return nil, fmt.Errorf("recorder: session meta missing session_id")
	}
	var traceID []byte
	if meta.TraceID != "" {
		b, err := hex.DecodeString(meta.TraceID)
		if err != nil {
			return nil, fmt.Errorf("recorder: invalid trace_id %q: %w", meta.TraceID, err)
		}
		traceID = b
	}
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o700); err != nil {
		return nil, fmt.Errorf("recorder: create segments dir: %w", err)
	}
	r := &recorder{
		segDir:    segDir,
		key:       key,
		meta:      meta,
		traceID:   traceID,
		monoStart: time.Now(),
		segNum:    1,
	}
	if err := r.openSegmentLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

// Emit assigns sequence/producer/class, writes the record (plus a clamp integrity
// note if the requested class was out of allowance), and rotates the segment if the
// size threshold is crossed. Any marshal/write/fsync failure is returned; the event
// must be treated as not recorded.
func (r *recorder) Emit(ch evidence.Channel, ev evidence.Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	allowed, ok := evidence.AllowedClasses[ch]
	if !ok || len(allowed) == 0 {
		return fmt.Errorf("recorder: unknown producer channel %q", ch)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("recorder: recorder is closed")
	}

	class, clamped := resolveClass(ev.Class, allowed)
	attempted := ev.Class

	now := time.Now()
	wall := ev.Time
	if wall.IsZero() {
		wall = now
	}
	mono := ev.MonotonicNS
	if mono == 0 {
		mono = int64(time.Since(r.monoStart))
	}

	if err := r.writeLocked(resolvedRecord{
		name:           ev.Name,
		producer:       ch,
		class:          class,
		wall:           wall,
		observed:       now,
		mono:           mono,
		outcome:        ev.Outcome,
		actionID:       ev.ActionID,
		parentActionID: ev.ParentActionID,
		body:           ev.Body,
		attrs:          ev.Attrs,
	}); err != nil {
		return err
	}
	subjectSeq := r.lastSeq

	// A clamped class is an integrity anomaly: record it, attributed to the recorder.
	if clamped {
		noteNow := time.Now()
		if err := r.writeLocked(resolvedRecord{
			name:     eventClassClamped,
			producer: evidence.ChannelRecorder,
			class:    evidence.ClassIntegrity,
			wall:     noteNow,
			observed: noteNow,
			mono:     int64(time.Since(r.monoStart)),
			outcome:  evidence.OutcomeFailure,
			body:     "requested evidence class not permitted on producer channel; clamped to channel maximum",
			attrs: map[string]any{
				attrAttemptedClass:  string(attempted),
				attrAssignedClass:   string(class),
				attrSubjectSequence: subjectSeq,
				attrSubjectEvent:    ev.Name,
				attrSubjectProducer: string(ch),
			},
		}); err != nil {
			return err
		}
	}

	if r.segBytes >= segmentSizeThreshold {
		if err := r.sealLocked("size_threshold", true); err != nil {
			return err
		}
	}
	return nil
}

// SealSegment seals the current WAL, writes+signs its manifest, opens the next
// segment, and records a segment.sealed integrity event into it.
func (r *recorder) SealSegment(reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("recorder: recorder is closed")
	}
	return r.sealLocked(reason, true)
}

// Close drains, seals the final open segment (without opening a successor), and
// returns every manifest path produced over the recorder's lifetime, in order.
func (r *recorder) Close() ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return append([]string(nil), r.manifestPaths...), nil
	}
	if err := r.sealLocked("close", false); err != nil {
		return nil, err
	}
	r.closed = true
	return append([]string(nil), r.manifestPaths...), nil
}

// resolveClass returns the class to record and whether it was clamped. An empty
// request defaults to the channel maximum (allowed[0]) without being flagged; a
// disallowed request is clamped to allowed[0] and flagged.
func resolveClass(requested evidence.Class, allowed []evidence.Class) (evidence.Class, bool) {
	if requested == "" {
		return allowed[0], false
	}
	for _, c := range allowed {
		if c == requested {
			return requested, false
		}
	}
	return allowed[0], true
}

// openSegmentLocked opens segments/segment-NNNNNN.otlp for the current segNum and
// resets per-segment counters. Callers must hold mu.
func (r *recorder) openSegmentLocked() error {
	path := filepath.Join(r.segDir, fmt.Sprintf("segment-%06d.otlp", r.segNum))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("recorder: open segment %s: %w", filepath.Base(path), err)
	}
	r.f = f
	r.segPath = path
	r.segBytes = 0
	r.firstSeq = 0
	r.lastSeq = 0
	r.recordCount = 0
	r.lossCount = 0
	r.restartCount = 0
	r.createdAt = time.Now().UTC()
	return nil
}

// writeLocked assigns the next sequence, marshals the record length-delimited, writes
// it in one shot, fsyncs, and updates per-segment counters. Callers must hold mu.
func (r *recorder) writeLocked(rr resolvedRecord) error {
	r.seq++
	seq := r.seq

	eventID, err := newUUIDv4()
	if err != nil {
		r.seq-- // nothing written; keep sequence contiguous
		return fmt.Errorf("recorder: generate event id: %w", err)
	}

	data := r.buildLogsData(seq, eventID, rr)

	// Marshal to a buffer first so a write error never leaves a partial frame on disk.
	var buf bytes.Buffer
	if _, err := protodelim.MarshalTo(&buf, data); err != nil {
		r.seq-- // nothing written
		return fmt.Errorf("recorder: marshal record seq %d: %w", seq, err)
	}
	n, err := r.f.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("recorder: write record seq %d: %w", seq, err)
	}
	if err := r.f.Sync(); err != nil {
		return fmt.Errorf("recorder: fsync segment: %w", err)
	}

	r.segBytes += int64(n)
	if r.recordCount == 0 {
		r.firstSeq = seq
	}
	r.lastSeq = seq
	r.recordCount++
	if rr.producer == evidence.ChannelGuestSupervisor && rr.class == evidence.ClassIntegrity {
		switch rr.name {
		case evidence.EventSensorLoss:
			r.lossCount++
		case evidence.EventSensorRestarted:
			r.restartCount++
		}
	}
	return nil
}

// sealLocked closes the current WAL, digests its exact bytes, writes and COSE-signs
// the manifest, and (when openNext) opens the successor segment and records a
// segment.sealed integrity event into it. Callers must hold mu.
func (r *recorder) sealLocked(reason string, openNext bool) error {
	if r.f == nil {
		return fmt.Errorf("recorder: no open segment to seal")
	}
	sealedNum := r.segNum

	if err := r.f.Sync(); err != nil {
		return fmt.Errorf("recorder: fsync before seal: %w", err)
	}
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("recorder: close segment: %w", err)
	}
	r.f = nil

	fileBytes, err := os.ReadFile(r.segPath)
	if err != nil {
		return fmt.Errorf("recorder: read segment for digest: %w", err)
	}
	segDigest := evidence.SHA256Hex(fileBytes)

	man := segmentManifest{
		Schema:             manifestSchema,
		SessionID:          r.meta.SessionID,
		SegmentNumber:      sealedNum,
		FirstSequence:      r.firstSeq,
		LastSequence:       r.lastSeq,
		RecordCount:        r.recordCount,
		PrevSegmentDigest:  r.prevDigest,
		SegmentDigest:      segDigest,
		PolicyDigest:       r.meta.PolicyDigest,
		SensorLossCount:    r.lossCount,
		SensorRestartCount: r.restartCount,
		CreatedAt:          r.createdAt.Format(time.RFC3339Nano),
		SealedAt:           time.Now().UTC().Format(time.RFC3339Nano),
	}
	manBytes, err := evidence.CanonicalJSON(man)
	if err != nil {
		return fmt.Errorf("recorder: canonicalize manifest: %w", err)
	}
	base := fmt.Sprintf("segment-%06d", sealedNum)
	manPath := filepath.Join(r.segDir, base+".manifest.json")
	if err := writeSyncedFile(manPath, manBytes); err != nil {
		return fmt.Errorf("recorder: write manifest: %w", err)
	}
	coseBytes, err := signManifest(r.key, manBytes)
	if err != nil {
		return err
	}
	if err := writeSyncedFile(filepath.Join(r.segDir, base+".manifest.cose"), coseBytes); err != nil {
		return fmt.Errorf("recorder: write cose signature: %w", err)
	}
	dir, err := os.Open(r.segDir)
	if err != nil {
		return fmt.Errorf("recorder: open segment directory for fsync: %w", err)
	}
	if err := dir.Sync(); err != nil {
		dir.Close()
		return fmt.Errorf("recorder: fsync segment directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("recorder: close segment directory: %w", err)
	}

	r.manifestPaths = append(r.manifestPaths, manPath)
	r.prevDigest = segDigest

	if !openNext {
		return nil
	}
	r.segNum++
	if err := r.openSegmentLocked(); err != nil {
		return err
	}
	// segment.sealed lands in the NEXT segment (DESIGN "Recorder" step in Seal).
	now := time.Now()
	return r.writeLocked(resolvedRecord{
		name:     evidence.EventSegmentSealed,
		producer: evidence.ChannelRecorder,
		class:    evidence.ClassIntegrity,
		wall:     now,
		observed: now,
		mono:     int64(time.Since(r.monoStart)),
		outcome:  evidence.OutcomeSuccess,
		body:     fmt.Sprintf("sealed segment %06d (%s)", sealedNum, reason),
		attrs: map[string]any{
			attrSealedSegment: sealedNum,
			attrSealedDigest:  segDigest,
			attrSealReason:    reason,
		},
	})
}

func writeSyncedFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// newUUIDv4 returns a random RFC 4122 version 4 UUID string sourced from crypto/rand.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
