package blobstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"boxedai/internal/evidence"
)

// Dir joins onto the session directory without touching the filesystem; the store
// materializes on the first Put.
func TestDirDoesNotCreateDirectory(t *testing.T) {
	sessionDir := t.TempDir()
	dir := Dir(sessionDir)
	want := filepath.Join(sessionDir, "blobs")
	if dir != want {
		t.Errorf("Dir(%q) = %q, want %q", sessionDir, dir, want)
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Dir must not create the directory; stat err = %v", err)
	}
}

// TestPathValidatesDigestStrictly pins the strict digest grammar Path enforces:
// exactly "sha256:" followed by 64 lowercase hex characters. That strictness is
// what makes the joined path provably free of traversal, so every rejection case
// here is a security property, not a cosmetic validation choice.
func TestPathValidatesDigestStrictly(t *testing.T) {
	validHex := strings.Repeat("a", 64)
	cases := []struct {
		name    string
		digest  string
		wantErr bool
	}{
		{"valid sha256 digest", "sha256:" + validHex, false},
		{"uppercase hex", "sha256:" + strings.Repeat("A", 64), true},
		{"too short", "sha256:" + strings.Repeat("a", 63), true},
		{"too long", "sha256:" + strings.Repeat("a", 65), true},
		{"bare hex, no prefix", validHex, true},
		{"sha256 without colon separator", "sha256" + validHex, true},
		{"other algorithm", "sha1:" + validHex, true},
		{"traversal attempt, wrong length", "sha256:../../x", true},
		{"traversal characters padded to digest length", "sha256:" + "../../" + strings.Repeat("a", 58), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path, err := Path(dir, c.digest)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Path(%q) = %q, want error", c.digest, path)
				}
				return
			}
			if err != nil {
				t.Fatalf("Path(%q): %v", c.digest, err)
			}
			want := filepath.Join(dir, "sha256", validHex)
			if path != want {
				t.Errorf("Path(%q) = %q, want %q", c.digest, path, want)
			}
		})
	}
}

func TestPutGetRoundtrip(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello, blobstore")
	digest := evidence.SHA256Hex(content)

	if err := Put(dir, digest, content); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := Get(dir, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("Get content = %q, want %q", got, content)
	}
}

// TestPutWritesBlobAtExpectedPathWithOwnerOnlyPerms guards the on-disk layout and
// permissions documented on Put: one file per blob under <dir>/sha256/<hex>, mode
// 0600 — this is workload file content and is no less sensitive here than it was
// in the workspace.
func TestPutWritesBlobAtExpectedPathWithOwnerOnlyPerms(t *testing.T) {
	dir := t.TempDir()
	content := []byte("permissions matter")
	digest := evidence.SHA256Hex(content)

	if err := Put(dir, digest, content); err != nil {
		t.Fatalf("Put: %v", err)
	}
	digestHex := strings.TrimPrefix(digest, "sha256:")
	wantPath := filepath.Join(dir, "sha256", digestHex)
	info, err := os.Stat(wantPath)
	if err != nil {
		t.Fatalf("stat %s: %v", wantPath, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("blob mode = %o, want 600", info.Mode().Perm())
	}
}

// TestPutRefusesContentDigestMismatch guards the invariant the whole package rests
// on: content that does not hash to the claimed digest must never be filed under
// that digest's name, or content addressing is poisoned for every later reader.
func TestPutRefusesContentDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	digest := evidence.SHA256Hex([]byte("expected content"))
	if err := Put(dir, digest, []byte("different content")); err == nil {
		t.Fatal("Put: expected error for content/digest mismatch, got nil")
	}
	blobPath := filepath.Join(dir, "sha256", strings.TrimPrefix(digest, "sha256:"))
	if _, err := os.Stat(blobPath); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Put must not write a blob on mismatch; stat err = %v", err)
	}
}

// TestPutIdempotentOnExistingBlob pins Put's documented idempotency: a second Put
// of a digest that already has a blob on disk returns nil without rewriting.
// Existence, not content, is what short-circuits, so a blob corrupted after being
// stored is left alone by a same-content re-Put — Get, not Put, is what catches
// that (see TestGetDetectsCorruptedBlob).
func TestPutIdempotentOnExistingBlob(t *testing.T) {
	dir := t.TempDir()
	content := []byte("idempotent content")
	digest := evidence.SHA256Hex(content)
	if err := Put(dir, digest, content); err != nil {
		t.Fatalf("Put (1st): %v", err)
	}
	if err := Put(dir, digest, content); err != nil {
		t.Fatalf("Put (2nd, identical content): %v", err)
	}
	got, err := Get(dir, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("Get content = %q, want %q", got, content)
	}

	path, err := Path(dir, digest)
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if err := os.WriteFile(path, []byte("corrupted after store"), 0o600); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}
	if err := Put(dir, digest, content); err != nil {
		t.Fatalf("Put (3rd, path now corrupted on disk): %v", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if string(onDisk) != "corrupted after store" {
		t.Errorf("Put rewrote an existing blob; got %q, want the untouched corrupted bytes", onDisk)
	}
}

// TestGetDetectsCorruptedBlob guards the re-verification Get performs on every
// read: serving bytes that no longer hash to the digest they are stored under
// would hand a caller unverified content wearing a verified label. The error must
// name both the digest the caller asked for and the digest the bytes actually hash
// to, so a reader can tell what happened.
func TestGetDetectsCorruptedBlob(t *testing.T) {
	dir := t.TempDir()
	content := []byte("original content")
	digest := evidence.SHA256Hex(content)
	if err := Put(dir, digest, content); err != nil {
		t.Fatalf("Put: %v", err)
	}

	path, err := Path(dir, digest)
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	tampered := []byte("tampered content")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	_, err = Get(dir, digest)
	if err == nil {
		t.Fatal("Get: expected error for corrupted blob, got nil")
	}
	tamperedDigest := evidence.SHA256Hex(tampered)
	if !strings.Contains(err.Error(), digest) || !strings.Contains(err.Error(), tamperedDigest) {
		t.Errorf("Get error = %q, want it to name both the expected digest %q and the actual %q", err, digest, tamperedDigest)
	}
}

// TestGetOnNeverPutDigestReturnsErrNotExist guards the distinction callers rely on
// between "never captured" (an expected state for any file the capture policy
// declined) and "captured and corrupt": the former must satisfy
// errors.Is(err, fs.ErrNotExist).
func TestGetOnNeverPutDigestReturnsErrNotExist(t *testing.T) {
	dir := t.TempDir()
	digest := evidence.SHA256Hex([]byte("never stored"))
	if _, err := Get(dir, digest); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Get error = %v, want it to satisfy errors.Is(err, fs.ErrNotExist)", err)
	}
}
