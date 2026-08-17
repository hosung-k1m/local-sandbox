package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"boxedai/internal/blobstore"
	"boxedai/internal/evidence"
	"boxedai/internal/policy"
)

// fakeEmitter is a real in-memory evidence.Emitter recording every (channel,
// event) pair it receives, per the evidence.Emitter contract (never silently
// drop). failOn simulates a downstream recorder failure for one event name, so
// captureEmitter's error-propagation contract can be exercised without a real
// recorder. Safe for concurrent use: the concurrency smoke test below drives
// Emit from multiple goroutines, mirroring how the broker calls it from its
// HTTP handlers.
type fakeEmitter struct {
	mu     sync.Mutex
	events []captured
	failOn string
}

type captured struct {
	ch evidence.Channel
	ev evidence.Event
}

// errFakeEmit is what fakeEmitter.Emit returns when failOn matches, so tests
// can assert propagation with errors.Is instead of string matching.
var errFakeEmit = errors.New("fake emitter: simulated failure")

func (f *fakeEmitter) Emit(ch evidence.Channel, ev evidence.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn != "" && ev.Name == f.failOn {
		return errFakeEmit
	}
	f.events = append(f.events, captured{ch: ch, ev: ev})
	return nil
}

func (f *fakeEmitter) all() []captured {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]captured, len(f.events))
	copy(out, f.events)
	return out
}

// arbitraryDigest returns a syntactically valid content digest for ladder steps
// that decide an outcome before ever comparing bytes to a digest (policy
// checks, the size cap, a missing file): the value is well-formed but
// otherwise inert.
func arbitraryDigest() string {
	return evidence.SHA256Hex([]byte("arbitrary"))
}

// fileChangedEvent returns a guest-shaped file.changed event: the wire attrs a
// real guest supervisor would send, with audit.content.capture already
// "digest_only" exactly as the guest leaves it before this host-side
// middleware runs.
func fileChangedEvent(relPath, digest string) evidence.Event {
	return evidence.Event{
		Name: evidence.EventFileChanged,
		Attrs: map[string]any{
			attrFilePath:                relPath,
			evidence.AttrContentDigest:  digest,
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
		},
	}
}

// cloneAttrs snapshots an event's attrs map so a test can prove later that
// captureEmitter did not mutate the original in place.
func cloneAttrs(attrs map[string]any) map[string]any {
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	return out
}

// mustBlobPath resolves the on-disk path a digest would occupy under blobDir
// without touching the filesystem.
func mustBlobPath(t *testing.T, blobDir, digest string) string {
	t.Helper()
	path, err := blobstore.Path(blobDir, digest)
	if err != nil {
		t.Fatalf("blobstore.Path(%q, %q): %v", blobDir, digest, err)
	}
	return path
}

// assertNoBlob fails the test if digest's blob exists under blobDir.
func assertNoBlob(t *testing.T, blobDir, digest string) {
	t.Helper()
	path := mustBlobPath(t, blobDir, digest)
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("blob at %s: stat err = %v, want fs.ErrNotExist", path, err)
	}
}

// assertBlobStoreEmpty fails the test if anything at all was written under
// blobDir, without assuming knowledge of the store's internal layout.
func assertBlobStoreEmpty(t *testing.T, blobDir string) {
	t.Helper()
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return // store never materialized; that is the passing state
		}
		t.Fatalf("read blob dir %s: %v", blobDir, err)
	}
	if len(entries) != 0 {
		t.Errorf("blob dir %s not empty: %v", blobDir, entries)
	}
}

// TestCaptureEmitterSuccessfulCapture asserts the happy path: a workspace file
// whose on-disk content hashes to the event's digest is stored under
// blobDir/sha256/<hex>, and the forwarded event is stamped capture="full" plus
// file.size with no reason attr.
func TestCaptureEmitterSuccessfulCapture(t *testing.T) {
	workspaceDir := t.TempDir()
	blobDir := t.TempDir()
	content := "package fixture\n\nfunc main() {}\n"
	writeFile(t, filepath.Join(workspaceDir, "main.go"), content)
	digest := evidence.SHA256Hex([]byte(content))

	fe := &fakeEmitter{}
	c := newCaptureEmitter(fe, workspaceDir, blobDir, policy.FileCapture{MaxBytes: 1024})

	if err := c.Emit(evidence.ChannelGuestSupervisor, fileChangedEvent("main.go", digest)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	got := fe.all()
	if len(got) != 1 {
		t.Fatalf("forwarded %d events, want 1", len(got))
	}
	attrs := got[0].ev.Attrs
	if capture, _ := attrs[evidence.AttrContentCapture].(string); capture != string(evidence.CaptureFull) {
		t.Errorf("audit.content.capture = %q, want %q", capture, evidence.CaptureFull)
	}
	if size, _ := attrs[attrFileSize].(int64); size != int64(len(content)) {
		t.Errorf("file.size = %v, want %d", attrs[attrFileSize], len(content))
	}
	if reason, ok := attrs[attrFileCaptureReason]; ok {
		t.Errorf("file.capture.reason = %v, want absent on success", reason)
	}

	stored, err := os.ReadFile(mustBlobPath(t, blobDir, digest))
	if err != nil {
		t.Fatalf("read stored blob: %v", err)
	}
	if string(stored) != content {
		t.Errorf("stored blob = %q, want %q", stored, content)
	}
}

// TestCaptureEmitterSecretPolicy asserts a path matching a secret glob is
// rejected on the path alone: no workspace file is ever created, so a
// capture that read the filesystem anyway would surface as a different
// reason (missing_before_capture) instead of secret_policy.
func TestCaptureEmitterSecretPolicy(t *testing.T) {
	workspaceDir := t.TempDir()
	blobDir := t.TempDir()
	fc := policy.FileCapture{MaxBytes: 1024, SecretGlobs: []string{".env*"}}
	fe := &fakeEmitter{}
	c := newCaptureEmitter(fe, workspaceDir, blobDir, fc)

	digest := arbitraryDigest()
	if err := c.Emit(evidence.ChannelGuestSupervisor, fileChangedEvent(".env.local", digest)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	attrs := fe.all()[0].ev.Attrs
	if reason, _ := attrs[attrFileCaptureReason].(string); reason != reasonSecretPolicy {
		t.Errorf("reason = %q, want %q", reason, reasonSecretPolicy)
	}
	if capture, _ := attrs[evidence.AttrContentCapture].(string); capture != string(evidence.CaptureDigestOnly) {
		t.Errorf("audit.content.capture = %q, want unchanged %q", capture, evidence.CaptureDigestOnly)
	}
	if _, ok := attrs[attrFileSize]; ok {
		t.Error("file.size set despite secret_policy withholding")
	}
	assertNoBlob(t, blobDir, digest)
}

// TestCaptureEmitterExcludedByPolicy asserts a path under an excluded
// directory is rejected the same way secret_policy is: on the path alone, no
// file ever created or read.
func TestCaptureEmitterExcludedByPolicy(t *testing.T) {
	workspaceDir := t.TempDir()
	blobDir := t.TempDir()
	fc := policy.FileCapture{MaxBytes: 1024, ExcludeDirs: []string{"node_modules"}}
	fe := &fakeEmitter{}
	c := newCaptureEmitter(fe, workspaceDir, blobDir, fc)

	digest := arbitraryDigest()
	if err := c.Emit(evidence.ChannelGuestSupervisor, fileChangedEvent("node_modules/leftpad/index.js", digest)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	attrs := fe.all()[0].ev.Attrs
	if reason, _ := attrs[attrFileCaptureReason].(string); reason != reasonExcludedByPolicy {
		t.Errorf("reason = %q, want %q", reason, reasonExcludedByPolicy)
	}
	if capture, _ := attrs[evidence.AttrContentCapture].(string); capture != string(evidence.CaptureDigestOnly) {
		t.Errorf("audit.content.capture = %q, want unchanged %q", capture, evidence.CaptureDigestOnly)
	}
	assertNoBlob(t, blobDir, digest)
}

// TestCaptureEmitterSizeCap asserts a file over MaxBytes is withheld with
// reason size_cap. The digest is deliberately arbitrary: the ladder must
// reject on length before it ever reaches the hash comparison.
func TestCaptureEmitterSizeCap(t *testing.T) {
	workspaceDir := t.TempDir()
	blobDir := t.TempDir()
	content := strings.Repeat("a", 100)
	writeFile(t, filepath.Join(workspaceDir, "big.txt"), content)
	digest := arbitraryDigest()

	fe := &fakeEmitter{}
	c := newCaptureEmitter(fe, workspaceDir, blobDir, policy.FileCapture{MaxBytes: 64})
	if err := c.Emit(evidence.ChannelGuestSupervisor, fileChangedEvent("big.txt", digest)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	attrs := fe.all()[0].ev.Attrs
	if reason, _ := attrs[attrFileCaptureReason].(string); reason != reasonSizeCap {
		t.Errorf("reason = %q, want %q", reason, reasonSizeCap)
	}
	if capture, _ := attrs[evidence.AttrContentCapture].(string); capture != string(evidence.CaptureDigestOnly) {
		t.Errorf("audit.content.capture = %q, want unchanged %q", capture, evidence.CaptureDigestOnly)
	}
	assertNoBlob(t, blobDir, digest)
}

// TestCaptureEmitterChangedBeforeCapture asserts a file whose on-disk content
// no longer matches the guest's digest is reported changed_before_capture:
// the scan-to-ingest race the captureEmitter doc comment describes.
func TestCaptureEmitterChangedBeforeCapture(t *testing.T) {
	workspaceDir := t.TempDir()
	blobDir := t.TempDir()
	writeFile(t, filepath.Join(workspaceDir, "notes.txt"), "content the host will actually read")
	digest := evidence.SHA256Hex([]byte("content the guest hashed at scan time"))

	fe := &fakeEmitter{}
	c := newCaptureEmitter(fe, workspaceDir, blobDir, policy.FileCapture{MaxBytes: 1024})
	if err := c.Emit(evidence.ChannelGuestSupervisor, fileChangedEvent("notes.txt", digest)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	attrs := fe.all()[0].ev.Attrs
	if reason, _ := attrs[attrFileCaptureReason].(string); reason != reasonChangedBeforeCapture {
		t.Errorf("reason = %q, want %q", reason, reasonChangedBeforeCapture)
	}
	if capture, _ := attrs[evidence.AttrContentCapture].(string); capture != string(evidence.CaptureDigestOnly) {
		t.Errorf("audit.content.capture = %q, want unchanged %q", capture, evidence.CaptureDigestOnly)
	}
	assertNoBlob(t, blobDir, digest)
}

// TestCaptureEmitterMissingBeforeCapture asserts a file.changed event for a
// path with no file on disk is reported missing_before_capture.
func TestCaptureEmitterMissingBeforeCapture(t *testing.T) {
	workspaceDir := t.TempDir()
	blobDir := t.TempDir()
	digest := arbitraryDigest()

	fe := &fakeEmitter{}
	c := newCaptureEmitter(fe, workspaceDir, blobDir, policy.FileCapture{MaxBytes: 1024})
	if err := c.Emit(evidence.ChannelGuestSupervisor, fileChangedEvent("gone.txt", digest)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	attrs := fe.all()[0].ev.Attrs
	if reason, _ := attrs[attrFileCaptureReason].(string); reason != reasonMissingBeforeCapture {
		t.Errorf("reason = %q, want %q", reason, reasonMissingBeforeCapture)
	}
	if capture, _ := attrs[evidence.AttrContentCapture].(string); capture != string(evidence.CaptureDigestOnly) {
		t.Errorf("audit.content.capture = %q, want unchanged %q", capture, evidence.CaptureDigestOnly)
	}
	assertNoBlob(t, blobDir, digest)
}

// TestCaptureEmitterReadErrorRefusesPathEscape asserts a relative path that
// would resolve outside the workspace is refused as read_error before any
// open is attempted. A real file sits exactly where "../escape.txt" would
// resolve, with content that WOULD satisfy the digest check if it were ever
// opened: if the filepath.IsLocal guard in capture() were ever weakened, this
// test would start seeing a blob appear instead of a read_error reason.
func TestCaptureEmitterReadErrorRefusesPathEscape(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	blobDir := t.TempDir()
	outsideContent := "content that must never be read by the host"
	writeFile(t, filepath.Join(root, "escape.txt"), outsideContent)
	digest := evidence.SHA256Hex([]byte(outsideContent))

	fe := &fakeEmitter{}
	c := newCaptureEmitter(fe, workspaceDir, blobDir, policy.FileCapture{MaxBytes: 1024})
	if err := c.Emit(evidence.ChannelGuestSupervisor, fileChangedEvent("../escape.txt", digest)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	attrs := fe.all()[0].ev.Attrs
	if reason, _ := attrs[attrFileCaptureReason].(string); reason != reasonReadError {
		t.Errorf("reason = %q, want %q", reason, reasonReadError)
	}
	if capture, _ := attrs[evidence.AttrContentCapture].(string); capture != string(evidence.CaptureDigestOnly) {
		t.Errorf("audit.content.capture = %q, want unchanged %q", capture, evidence.CaptureDigestOnly)
	}
	assertNoBlob(t, blobDir, digest)
}

// TestCaptureEmitterPassthroughUntouched asserts the four cases where
// captureEmitter must leave an event completely alone: no attrs mutated, no
// blob-store activity, but still forwarded exactly once. The workload-channel
// case uses a real file that WOULD be captured on the guest supervisor
// channel, so the assertion proves the channel check gates capture rather
// than merely that these particular attrs looked unpromising.
func TestCaptureEmitterPassthroughUntouched(t *testing.T) {
	workspaceDir := t.TempDir()
	content := "would be captured if this arrived on the guest supervisor channel"
	writeFile(t, filepath.Join(workspaceDir, "workload.txt"), content)
	digest := evidence.SHA256Hex([]byte(content))

	tests := []struct {
		name string
		ch   evidence.Channel
		ev   evidence.Event
	}{
		{
			name: "file.deleted",
			ch:   evidence.ChannelGuestSupervisor,
			ev: evidence.Event{
				Name:  evidence.EventFileDeleted,
				Attrs: map[string]any{attrFilePath: "notes.txt"},
			},
		},
		{
			name: "file.changed on workload channel",
			ch:   evidence.ChannelWorkload,
			ev:   fileChangedEvent("workload.txt", digest),
		},
		{
			name: "file.changed missing file.path",
			ch:   evidence.ChannelGuestSupervisor,
			ev: evidence.Event{
				Name:  evidence.EventFileChanged,
				Attrs: map[string]any{evidence.AttrContentDigest: digest},
			},
		},
		{
			name: "file.changed missing digest",
			ch:   evidence.ChannelGuestSupervisor,
			ev: evidence.Event{
				Name:  evidence.EventFileChanged,
				Attrs: map[string]any{attrFilePath: "workload.txt"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blobDir := t.TempDir()
			fe := &fakeEmitter{}
			c := newCaptureEmitter(fe, workspaceDir, blobDir, policy.FileCapture{MaxBytes: 1024})
			want := cloneAttrs(tt.ev.Attrs)

			if err := c.Emit(tt.ch, tt.ev); err != nil {
				t.Fatalf("Emit: %v", err)
			}
			if !reflect.DeepEqual(tt.ev.Attrs, want) {
				t.Errorf("attrs mutated: got %+v, want unchanged %+v", tt.ev.Attrs, want)
			}
			got := fe.all()
			if len(got) != 1 || got[0].ch != tt.ch || got[0].ev.Name != tt.ev.Name {
				t.Fatalf("forwarded = %+v, want exactly one event with ch=%q name=%q", got, tt.ch, tt.ev.Name)
			}
			assertBlobStoreEmpty(t, blobDir)
		})
	}
}

// TestCaptureEmitterInnerEmitterErrorPropagates asserts a failing inner
// emitter's error surfaces from Emit verbatim (fail-closed, like
// countingEmitter): a capture problem never fails an Emit, but the inner
// emitter's own error always does.
func TestCaptureEmitterInnerEmitterErrorPropagates(t *testing.T) {
	fe := &fakeEmitter{failOn: evidence.EventFileDeleted}
	c := newCaptureEmitter(fe, t.TempDir(), t.TempDir(), policy.FileCapture{MaxBytes: 1024})

	ev := evidence.Event{Name: evidence.EventFileDeleted, Attrs: map[string]any{attrFilePath: "notes.txt"}}
	err := c.Emit(evidence.ChannelGuestSupervisor, ev)
	if !errors.Is(err, errFakeEmit) {
		t.Fatalf("Emit error = %v, want %v", err, errFakeEmit)
	}
	if got := fe.all(); len(got) != 0 {
		t.Errorf("fake emitter recorded %d events despite returning an error, want 0", len(got))
	}
}

// TestCaptureEmitterEmitForwardsOnceWithSameShape asserts Emit forwards
// exactly once per call, preserving the channel and event name regardless of
// which branch (captured, withheld, or passthrough) handled it.
func TestCaptureEmitterEmitForwardsOnceWithSameShape(t *testing.T) {
	workspaceDir := t.TempDir()
	blobDir := t.TempDir()
	content := "shape check"
	writeFile(t, filepath.Join(workspaceDir, "shape.txt"), content)
	digest := evidence.SHA256Hex([]byte(content))

	fe := &fakeEmitter{}
	c := newCaptureEmitter(fe, workspaceDir, blobDir, policy.FileCapture{MaxBytes: 1024})

	calls := []struct {
		ch evidence.Channel
		ev evidence.Event
	}{
		{evidence.ChannelGuestSupervisor, fileChangedEvent("shape.txt", digest)},
		{evidence.ChannelGuestSupervisor, evidence.Event{Name: evidence.EventFileDeleted, Attrs: map[string]any{attrFilePath: "shape.txt"}}},
		{evidence.ChannelWorkload, fileChangedEvent("shape.txt", digest)},
	}
	for i, call := range calls {
		if err := c.Emit(call.ch, call.ev); err != nil {
			t.Fatalf("Emit[%d]: %v", i, err)
		}
		got := fe.all()
		if len(got) != i+1 {
			t.Fatalf("after Emit[%d], forwarded %d events, want %d", i, len(got), i+1)
		}
		last := got[i]
		if last.ch != call.ch || last.ev.Name != call.ev.Name {
			t.Errorf("Emit[%d] forwarded ch=%q name=%q, want ch=%q name=%q", i, last.ch, last.ev.Name, call.ch, call.ev.Name)
		}
	}
}

// TestCaptureEmitterConcurrentEmitsOverDistinctFiles is a -race smoke test:
// captureEmitter holds no mutable state of its own, so parallel Emits over
// distinct files (the broker calls Emit from its HTTP handlers) must be safe
// without any locking here.
func TestCaptureEmitterConcurrentEmitsOverDistinctFiles(t *testing.T) {
	workspaceDir := t.TempDir()
	blobDir := t.TempDir()
	fe := &fakeEmitter{}
	c := newCaptureEmitter(fe, workspaceDir, blobDir, policy.FileCapture{MaxBytes: 1024})

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	digests := make([]string, n)
	for i := 0; i < n; i++ {
		content := fmt.Sprintf("concurrent file body #%d", i)
		name := fmt.Sprintf("file-%d.txt", i)
		writeFile(t, filepath.Join(workspaceDir, name), content)
		digest := evidence.SHA256Hex([]byte(content))
		digests[i] = digest

		wg.Add(1)
		go func(i int, name, digest string) {
			defer wg.Done()
			errs[i] = c.Emit(evidence.ChannelGuestSupervisor, fileChangedEvent(name, digest))
		}(i, name, digest)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Emit[%d]: %v", i, err)
		}
	}
	if got := len(fe.all()); got != n {
		t.Fatalf("forwarded %d events, want %d", got, n)
	}
	for i, digest := range digests {
		if _, err := os.Stat(mustBlobPath(t, blobDir, digest)); err != nil {
			t.Errorf("blob %d missing: %v", i, err)
		}
	}
}
