package session

import (
	"os"
	"path/filepath"
	"testing"

	"boxedai/internal/evidence"
	"boxedai/internal/policy"
)

func TestCaptureEmitterReDerivesMediatedMutationFromHostWorkspace(t *testing.T) {
	workspace := t.TempDir()
	content := []byte("host workspace result")
	if err := os.WriteFile(filepath.Join(workspace, "main.go"), content, 0o600); err != nil {
		t.Fatalf("write workspace fixture: %v", err)
	}
	inner := &fakeEmitter{}
	capture := newCaptureEmitter(inner, workspace, t.TempDir(), policy.FileCapture{MaxBytes: 1024})
	event := evidence.Event{Name: evidence.EventWorkspaceMutated, Attrs: map[string]any{
		evidence.AttrMutationUID:          int64(4242),
		evidence.AttrMutationActorClass:   string(evidence.MutationActorAgent),
		evidence.AttrMutationBasis:        "opener",
		evidence.AttrMutationOpenMode:     string(evidence.MutationOpenWriteOnly),
		evidence.AttrMutationOperation:    string(evidence.MutationOperationWrite),
		evidence.AttrMutationPath:         "main.go",
		evidence.AttrMutationPosition:     int64(0),
		evidence.AttrMutationPositionKind: string(evidence.MutationPositionPositional),
		evidence.AttrContentDigest:        evidence.SHA256Hex([]byte("guest candidate")),
	}}
	if err := capture.Emit(evidence.ChannelGuestSupervisor, event); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	attrs := inner.all()[0].ev.Attrs
	if got := attrs[evidence.AttrContentDigest]; got != evidence.SHA256Hex(content) {
		t.Fatalf("host-derived digest = %v, want %s", got, evidence.SHA256Hex(content))
	}
	if got := attrs["mutation.host.rederived"]; got != true {
		t.Fatalf("host re-derivation marker = %v, want true", got)
	}
}

// TestCaptureEmitterRejectsMediatedMutationItCannotReDerive covers a write whose
// host re-read fails for a reason other than the file vanishing (permission
// denied here): unlike the orphaned-write race below, the file is still there
// and unreadable, so this must still fail the session rather than being folded
// into the orphaned/empty-digest path.
func TestCaptureEmitterRejectsMediatedMutationItCannotReDerive(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "unreadable.go"), []byte("secret"), 0o000); err != nil {
		t.Fatalf("write unreadable fixture: %v", err)
	}
	inner := &fakeEmitter{}
	capture := newCaptureEmitter(inner, workspace, t.TempDir(), policy.FileCapture{MaxBytes: 1024})
	event := evidence.Event{Name: evidence.EventWorkspaceMutated, Attrs: map[string]any{
		evidence.AttrMutationUID:          int64(4242),
		evidence.AttrMutationActorClass:   string(evidence.MutationActorAgent),
		evidence.AttrMutationBasis:        "opener",
		evidence.AttrMutationOpenMode:     string(evidence.MutationOpenWriteOnly),
		evidence.AttrMutationOperation:    string(evidence.MutationOperationWrite),
		evidence.AttrMutationPath:         "unreadable.go",
		evidence.AttrMutationPosition:     int64(0),
		evidence.AttrMutationPositionKind: string(evidence.MutationPositionPositional),
		evidence.AttrContentDigest:        evidence.SHA256Hex([]byte("guest candidate")),
	}}
	if err := capture.Emit(evidence.ChannelGuestSupervisor, event); err == nil {
		t.Fatal("Emit: want host re-derivation error")
	}
	if len(inner.all()) != 0 {
		t.Fatal("unre-derived mutation reached recorder")
	}
}

// TestCaptureEmitterOrphansMediatedWriteToVanishedFile pins the legal POSIX
// create -> write -> unlink -> write-to-the-still-open-fd idiom (editors, build
// tools, atomic temp-file swaps). Once writes actually succeed on the
// write-through mount, the host's re-read of a write mutation can race a
// legitimate unlink, and that race must record an orphaned, empty-content
// mutation rather than kill the session.
func TestCaptureEmitterOrphansMediatedWriteToVanishedFile(t *testing.T) {
	inner := &fakeEmitter{}
	capture := newCaptureEmitter(inner, t.TempDir(), t.TempDir(), policy.FileCapture{MaxBytes: 1024})
	event := evidence.Event{Name: evidence.EventWorkspaceMutated, Attrs: map[string]any{
		evidence.AttrMutationUID:          int64(4242),
		evidence.AttrMutationActorClass:   string(evidence.MutationActorAgent),
		evidence.AttrMutationBasis:        "opener",
		evidence.AttrMutationOpenMode:     string(evidence.MutationOpenWriteOnly),
		evidence.AttrMutationOperation:    string(evidence.MutationOperationWrite),
		evidence.AttrMutationPath:         "vanished.go",
		evidence.AttrMutationPosition:     int64(0),
		evidence.AttrMutationPositionKind: string(evidence.MutationPositionPositional),
		evidence.AttrContentDigest:        evidence.SHA256Hex([]byte("guest candidate")),
	}}
	if err := capture.Emit(evidence.ChannelGuestSupervisor, event); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	attrs := inner.all()[0].ev.Attrs
	if got := attrs[evidence.AttrContentDigest]; got != evidence.SHA256Hex(nil) {
		t.Fatalf("host-derived digest = %v, want empty digest", got)
	}
	if got := attrs["mutation.host.rederived"]; got != true {
		t.Fatalf("host re-derivation marker = %v, want true", got)
	}
	if got := attrs["mutation.host.orphaned"]; got != true {
		t.Fatalf("host orphaned-write marker = %v, want true", got)
	}
}

func TestCaptureEmitterAcceptsMissingNonWriteMutation(t *testing.T) {
	inner := &fakeEmitter{}
	capture := newCaptureEmitter(inner, t.TempDir(), t.TempDir(), policy.FileCapture{MaxBytes: 1024})
	event := evidence.Event{Name: evidence.EventWorkspaceMutated, Attrs: map[string]any{
		evidence.AttrMutationUID:          int64(4242),
		evidence.AttrMutationActorClass:   string(evidence.MutationActorAgent),
		evidence.AttrMutationBasis:        "fallback",
		evidence.AttrMutationOpenMode:     string(evidence.MutationOpenWriteOnly),
		evidence.AttrMutationOperation:    string(evidence.MutationOperationReplace),
		evidence.AttrMutationPath:         "new.go",
		evidence.AttrMutationPositionKind: string(evidence.MutationPositionNonPositional),
		evidence.AttrContentDigest:        evidence.SHA256Hex([]byte("guest candidate")),
	}}
	if err := capture.Emit(evidence.ChannelGuestSupervisor, event); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := inner.all()[0].ev.Attrs[evidence.AttrContentDigest]; got != evidence.SHA256Hex(nil) {
		t.Fatalf("host-derived digest = %v, want empty digest", got)
	}
}

func TestCaptureEmitterRejectsMediatedMutationThroughEscapingSymlink(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside fixture: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "escape")); err != nil {
		t.Fatalf("create escape symlink: %v", err)
	}
	capture := newCaptureEmitter(&fakeEmitter{}, workspace, t.TempDir(), policy.FileCapture{MaxBytes: 1024})
	event := evidence.Event{Name: evidence.EventWorkspaceMutated, Attrs: map[string]any{
		evidence.AttrMutationUID:          int64(4242),
		evidence.AttrMutationActorClass:   string(evidence.MutationActorAgent),
		evidence.AttrMutationBasis:        "opener",
		evidence.AttrMutationOpenMode:     string(evidence.MutationOpenWriteOnly),
		evidence.AttrMutationOperation:    string(evidence.MutationOperationWrite),
		evidence.AttrMutationPath:         "escape/secret.txt",
		evidence.AttrMutationPosition:     int64(0),
		evidence.AttrMutationPositionKind: string(evidence.MutationPositionPositional),
		evidence.AttrContentDigest:        evidence.SHA256Hex([]byte("guest candidate")),
	}}
	if err := capture.Emit(evidence.ChannelGuestSupervisor, event); err == nil {
		t.Fatal("Emit: want escaping symlink rejection")
	}
}
