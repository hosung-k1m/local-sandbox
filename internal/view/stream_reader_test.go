package view

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"boxedai/internal/evidence"
)

func TestStreamReaderReadsCompleteFramesLikeRebuild(t *testing.T) {
	sessionDir := t.TempDir()
	sessionID := "bx-stream-reader"
	writeSegment(t, sessionDir, "segment-000001.otlp", sessionID, "sha256:policydigest", []testEvent{
		{
			seq: 1, name: evidence.EventSessionGranted, class: evidence.ClassIntegrity,
			producer: evidence.ChannelController, outcome: evidence.OutcomeSuccess, body: "session granted",
		},
		{
			seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor, actionID: "act-1", outcome: evidence.OutcomeSuccess,
			body: "command", attrs: map[string]any{evidence.AttrProcessPID: int64(42)},
		},
	})

	reader := newStreamReader(sessionDir, sessionID, 0)
	got, err := reader.read(100)
	if err != nil {
		t.Fatalf("read complete frames: %v", err)
	}

	db, err := Rebuild(sessionDir)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	defer db.Close()
	want, err := queryEvents(db, Filter{})
	if err != nil {
		t.Fatalf("query rebuilt events: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stream rows = %#v, want rebuilt rows %#v", got, want)
	}

	info, err := os.Stat(filepath.Join(sessionDir, "evidence", "segments", "segment-000001.otlp"))
	if err != nil {
		t.Fatalf("stat segment: %v", err)
	}
	position := reader.position()
	if position.sessionID != sessionID || position.segment != 1 || position.offset != info.Size() || position.sequence != 2 {
		t.Fatalf("position = %+v, want session %q segment 1 offset %d sequence 2", position, sessionID, info.Size())
	}
}

func TestStreamReaderRetainsPartialFrame(t *testing.T) {
	sessionDir := t.TempDir()
	sessionID := "bx-stream-partial"
	writeSegment(t, sessionDir, "segment-000001.otlp", sessionID, "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	segmentPath := filepath.Join(sessionDir, "evidence", "segments", "segment-000001.otlp")
	completeSize := fileSize(t, segmentPath)
	frame := testFrameBytes(t, sessionID, testEvent{
		seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
		producer: evidence.ChannelGuestSupervisor,
	})
	appendFile(t, segmentPath, frame[:len(frame)/2])

	reader := newStreamReader(sessionDir, sessionID, 0)
	rows, err := reader.read(100)
	if err != nil {
		t.Fatalf("read with partial tail: %v", err)
	}
	if len(rows) != 1 || rows[0].Seq != 1 {
		t.Fatalf("rows = %+v, want only complete sequence 1", rows)
	}
	if position := reader.position(); position.offset != completeSize || position.sequence != 1 {
		t.Fatalf("position after partial tail = %+v, want offset %d sequence 1", position, completeSize)
	}

	appendFile(t, segmentPath, frame[len(frame)/2:])
	rows, err = reader.read(100)
	if err != nil {
		t.Fatalf("read completed tail: %v", err)
	}
	if len(rows) != 1 || rows[0].Seq != 2 {
		t.Fatalf("rows = %+v, want completed sequence 2", rows)
	}
	if position := reader.position(); position.offset != completeSize+int64(len(frame)) || position.sequence != 2 {
		t.Fatalf("position after completed tail = %+v, want offset %d sequence 2", position, completeSize+int64(len(frame)))
	}
}

func TestStreamReaderSuppressesDeliveredOverlap(t *testing.T) {
	sessionDir := t.TempDir()
	sessionID := "bx-stream-overlap"
	writeSegment(t, sessionDir, "segment-000001.otlp", sessionID, "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
		{seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved, producer: evidence.ChannelGuestSupervisor},
	})

	reader := newStreamReader(sessionDir, sessionID, 1)
	rows, err := reader.read(100)
	if err != nil {
		t.Fatalf("read overlap: %v", err)
	}
	if len(rows) != 1 || rows[0].Seq != 2 {
		t.Fatalf("rows = %+v, want only sequence 2", rows)
	}
}

func TestStreamReaderRejectsSequenceDiscontinuity(t *testing.T) {
	sessionDir := t.TempDir()
	sessionID := "bx-stream-gap"
	writeSegment(t, sessionDir, "segment-000001.otlp", sessionID, "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
		{seq: 3, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved, producer: evidence.ChannelGuestSupervisor},
	})

	reader := newStreamReader(sessionDir, sessionID, 0)
	rows, err := reader.read(100)
	if !errors.Is(err, errStreamDiscontinuity) {
		t.Fatalf("read error = %v, want stream discontinuity", err)
	}
	if rows != nil {
		t.Fatalf("rows = %+v, want no rows from discontinuous read", rows)
	}
	if position := reader.position(); position.segment != 0 || position.offset != 0 || position.sequence != 0 {
		t.Fatalf("position advanced after discontinuity: %+v", position)
	}
}

func TestStreamReaderRejectsMissingResumeSequence(t *testing.T) {
	sessionDir := t.TempDir()
	sessionID := "bx-stream-resume-gap"
	writeSegment(t, sessionDir, "segment-000001.otlp", sessionID, "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	writeStreamManifest(t, sessionDir, sessionID, 1, 1, 1)
	writeSegment(t, sessionDir, "segment-000002.otlp", sessionID, "sha256:policydigest", []testEvent{
		{seq: 3, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved, producer: evidence.ChannelGuestSupervisor},
	})

	reader := newStreamReader(sessionDir, sessionID, 2)
	rows, err := reader.read(100)
	if !errors.Is(err, errStreamDiscontinuity) {
		t.Fatalf("read error = %v, want stream discontinuity", err)
	}
	if rows != nil {
		t.Fatalf("rows = %+v, want no rows from discontinuous resume", rows)
	}
	if position := reader.position(); position != (streamPosition{sessionID: sessionID, sequence: 2}) {
		t.Fatalf("position advanced after discontinuous resume: %+v", position)
	}
}

func TestStreamReaderResumesAcrossSealedRotation(t *testing.T) {
	sessionDir := t.TempDir()
	sessionID := "bx-stream-rotation"
	writeSegment(t, sessionDir, "segment-000001.otlp", sessionID, "sha256:policydigest", []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	writeStreamManifest(t, sessionDir, sessionID, 1, 1, 1)
	writeSegment(t, sessionDir, "segment-000002.otlp", sessionID, "sha256:policydigest", []testEvent{
		{seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved, producer: evidence.ChannelGuestSupervisor},
		{seq: 3, name: evidence.EventSessionStopped, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})

	reader := newStreamReader(sessionDir, sessionID, 1)
	rows, err := reader.read(1)
	if err != nil {
		t.Fatalf("read first rotated record: %v", err)
	}
	if len(rows) != 1 || rows[0].Seq != 2 {
		t.Fatalf("first rotated rows = %+v, want sequence 2", rows)
	}
	if position := reader.position(); position.segment != 2 || position.sequence != 2 {
		t.Fatalf("position after first rotated record = %+v, want segment 2 sequence 2", position)
	}

	rows, err = reader.read(1)
	if err != nil {
		t.Fatalf("read second rotated record: %v", err)
	}
	if len(rows) != 1 || rows[0].Seq != 3 {
		t.Fatalf("second rotated rows = %+v, want sequence 3", rows)
	}
}

func testFrameBytes(t *testing.T, sessionID string, event testEvent) []byte {
	t.Helper()
	sourceDir := t.TempDir()
	writeSegment(t, sourceDir, "segment-000001.otlp", sessionID, "sha256:policydigest", []testEvent{event})
	frame, err := os.ReadFile(filepath.Join(sourceDir, "evidence", "segments", "segment-000001.otlp"))
	if err != nil {
		t.Fatalf("read test frame: %v", err)
	}
	return frame
}

func appendFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open segment for append: %v", err)
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		t.Fatalf("append segment: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close appended segment: %v", err)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

func writeStreamManifest(t *testing.T, sessionDir, sessionID string, segment int, firstSequence, lastSequence int64) {
	t.Helper()
	manifest, err := json.Marshal(streamSegmentManifest{
		SessionID:     sessionID,
		Segment:       segment,
		FirstSequence: firstSequence,
		LastSequence:  lastSequence,
		RecordCount:   lastSequence - firstSequence + 1,
	})
	if err != nil {
		t.Fatalf("marshal stream manifest: %v", err)
	}
	path := filepath.Join(sessionDir, "evidence", "segments", "segment-000001.manifest.json")
	if err := os.WriteFile(path, manifest, 0o644); err != nil {
		t.Fatalf("write stream manifest: %v", err)
	}
}
