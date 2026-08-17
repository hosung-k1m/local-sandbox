package session

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"boxedai/internal/blobstore"
	"boxedai/internal/evidence"
	"boxedai/internal/policy"
)

// Wire attribute names for file content capture. attrFilePath mirrors the guest
// supervisor's "file.path" key on file.changed; attrFileSize and
// attrFileCaptureReason are stamped here and read by internal/verify. All three
// are duplicated rather than exported from another package for the same reason as
// emitter.go's attrToolName: they are stable wire attribute names, not an API. The
// verifier mirrors the reason vocabulary a third time on purpose — producer and
// verifier must agree on the wire, not on a shared Go symbol that a rename could
// carry both sides through in lockstep.
const (
	attrFilePath          = "file.path"
	attrFileSize          = "file.size"
	attrFileCaptureReason = "file.capture.reason"
)

// Reasons a file.changed event kept digest-only content. The two groups say
// opposite things about the blob store and the verifier counts them separately:
// withheld means the store is complete with respect to what it was allowed to
// hold, missed means it holds less than the session intended.
const (
	// Policy withheld the bytes. Capture could have run and deliberately did not,
	// so the absence of a blob is the policy working, not a gap. size_cap belongs
	// here too: MaxBytes is a policy number, not an I/O accident.
	reasonSecretPolicy     = "secret_policy"
	reasonExcludedByPolicy = "excluded_by_policy"
	reasonSizeCap          = "size_cap"
	// Capture was attempted and missed. The host meant to store the bytes and
	// could not: the file had moved on, vanished, or would not read or store.
	reasonChangedBeforeCapture = "changed_before_capture"
	reasonMissingBeforeCapture = "missing_before_capture"
	reasonReadError            = "read_error"
	reasonStoreError           = "store_error"
)

// captureEmitter stamps host-side content capture onto guest file.changed events
// on their way to the recorder: it reads the changed file from the host's view of
// the session workspace, stores the bytes in the session's content-addressed blob
// store, and marks the event audit.content.capture="full" before it is sealed.
//
// The trust split is the whole point. The digest on the event stays the GUEST's
// kernel_observed claim — this middleware never recomputes it, never overwrites
// it, and never invents one where the guest left none. audit.content.capture,
// file.size and file.capture.reason are the HOST's own assertion about an action
// the host itself performed, stamped before sealing so they ride inside the
// signature rather than beside it. That is what turns capture="full" from a note
// into a checkable claim: the blob it names must exist and must still hash to the
// signed digest, which is exactly what verify's file-content-store check enforces
// (an absent blob is INCOMPLETE, a present-but-mismatched one is
// TAMPER_SUSPECTED).
//
// Capture is a side effect and is treated as one. Nothing here drops, reorders or
// rewrites an event beyond those three attributes, and no capture problem can fail
// an Emit — only the inner emitter's error propagates (fail-closed, like
// countingEmitter). A signed record of the change must flow even when its bytes
// could not be kept, because that is precisely the case where an observer most
// needs the record.
//
// The scan → ingest window is real and is reported honestly rather than papered
// over. The guest hashes a file during its ~2s scan tick; the host reads it some
// milliseconds later, by which time the file may have changed again
// ("changed_before_capture") or been removed ("missing_before_capture"). Those are
// races, not faults, and they self-heal: if the file still exists in some state,
// the next scan tick emits a fresh file.changed for its new content and capture
// gets another attempt against a digest that matches.
//
// captureEmitter holds no mutable state, so Emit is safe for concurrent use by
// multiple goroutines — the broker calls it from its HTTP handlers — and needs no
// mutex.
type captureEmitter struct {
	inner evidence.Emitter
	// workspaceDir is the host-side session workspace that the guest's relative
	// file.path values resolve against: the same directory virtiofs exports into
	// the guest as /workspace.
	workspaceDir string
	// blobDir is the session's blob store root. It is not created here; the store
	// materializes on the first successful Put, so a session that captured nothing
	// simply has no blobs directory.
	blobDir string
	// fc is the resolved policy's capture rules, covered by the policy digest
	// stamped on every record — so the rules in force when this ran are attested.
	fc policy.FileCapture
}

func newCaptureEmitter(inner evidence.Emitter, workspaceDir, blobDir string, fc policy.FileCapture) *captureEmitter {
	return &captureEmitter{inner: inner, workspaceDir: workspaceDir, blobDir: blobDir, fc: fc}
}

// Emit stamps the capture outcome onto a guest-supervisor file.changed event and
// forwards it. Everything else passes through untouched: file.deleted has no
// content to capture, and a file.changed on any other channel is workload
// narration rather than an observation of the workspace, where a host capture
// stamp would not be the producer's to make.
func (c *captureEmitter) Emit(ch evidence.Channel, ev evidence.Event) error {
	if ch == evidence.ChannelGuestSupervisor && ev.Name == evidence.EventFileChanged {
		// ev.Attrs is mutated in place. Each event arrives freshly decoded from the
		// guest's JSON batch and is referenced by nothing else, so the map is this
		// goroutine's to write: there is no shared attrs map to race on, and no
		// producer upstream that could observe the stamp.
		c.stamp(ev.Attrs)
	}
	return c.inner.Emit(ch, ev)
}

// stamp records the capture outcome on one file.changed event's attributes.
func (c *captureEmitter) stamp(attrs map[string]any) {
	relPath, _ := attrs[attrFilePath].(string)
	digest, _ := attrs[evidence.AttrContentDigest].(string)
	if relPath == "" || digest == "" {
		// Both attributes belong to the guest. Without a path there is no file to
		// read, and without a digest there is nothing to check the bytes against, so
		// there is nothing honest to stamp — a reason here would describe the host's
		// confusion rather than the capture policy. Leave the event as produced.
		return
	}
	size, reason := c.capture(relPath, digest)
	if reason != "" {
		// Not captured: audit.content.capture keeps the guest's "digest_only" and the
		// reason carries which of the two very different things happened. The change
		// stays fully attested either way — the digest is on the record.
		attrs[attrFileCaptureReason] = reason
		return
	}
	attrs[evidence.AttrContentCapture] = string(evidence.CaptureFull)
	attrs[attrFileSize] = size
}

// capture runs the capture decision ladder for one changed file and reports either
// how many bytes were stored (reason "") or why nothing was. It deliberately
// returns no error: a capture problem is an outcome to record on the event, never
// something to propagate into the emit path.
func (c *captureEmitter) capture(relPath, digest string) (size int64, reason string) {
	// Policy is consulted before the file is opened at all. A secret's bytes should
	// never be read into this process just to be discarded, and an excluded tree's
	// churn should cost no I/O to ignore.
	switch {
	case c.fc.Secret(relPath):
		return 0, reasonSecretPolicy
	case c.fc.Excluded(relPath):
		return 0, reasonExcludedByPolicy
	}
	// file.path is workspace-relative and slash-separated on the wire. IsLocal is
	// checked on the converted path before the join, not after: the supervisor
	// channel is authenticated, but authentication is not a containment argument,
	// and a path that would escape the workspace (a "..", an absolute path, a
	// volume name) must never be opened by the host no matter who sent it. That is
	// a read the host refused, not content it withheld, so it reads as a read error
	// rather than a policy outcome.
	rel := filepath.FromSlash(relPath)
	if !filepath.IsLocal(rel) {
		return 0, reasonReadError
	}
	// One byte past the cap, so a file sitting exactly at MaxBytes is captured while
	// a larger one is detectably over without reading (or buffering) all of it.
	content, err := readCapped(filepath.Join(c.workspaceDir, rel), c.fc.MaxBytes+1)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 0, reasonMissingBeforeCapture
	case err != nil:
		return 0, reasonReadError
	case int64(len(content)) > c.fc.MaxBytes:
		return 0, reasonSizeCap
	}
	// The bytes must hash to the digest the guest recorded, or they are not the
	// content this event describes. MaxBytes equals the guest scanner's digest cap
	// (the invariant policy.defaultFileCapture spells out), so any file that fits
	// under the bound here was hashed whole by the guest too: a full hash of these
	// bytes is byte-for-byte the same domain as the guest's capped digest. A
	// mismatch therefore means the file genuinely changed between the scan and this
	// read — never that the two sides hashed different amounts of the same file.
	if evidence.SHA256Hex(content) != digest {
		return 0, reasonChangedBeforeCapture
	}
	// Put re-verifies the digest and installs the blob atomically, so a crash mid
	// capture can leave no truncated file wearing a verified name.
	if err := blobstore.Put(c.blobDir, digest, content); err != nil {
		return 0, reasonStoreError
	}
	return int64(len(content)), ""
}

// readCapped reads at most limit bytes from path. It is its own function so the
// file handle is closed before the caller hashes and stores the bytes, instead of
// being held open across the blob store write.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}
