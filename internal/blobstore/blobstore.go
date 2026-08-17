// Package blobstore implements the per-session, content-addressed store that holds
// the workload file bytes captured when a file.changed event is emitted. See
// DESIGN.md "File content capture".
//
// The store is an UNSIGNED side artifact: nothing in it is covered by a COSE
// signature and nothing in it is required for a session to verify. Its integrity
// comes entirely from its addressing. Every blob is named by the sha256 digest that
// the recorder already wrote into a file.changed event, and that event lives in a
// sealed, signed segment — so a blob is trustworthy exactly to the degree that its
// bytes still hash to the digest a signed segment claims. That check is cheap, so
// this package performs it on the way in (Put) and again on the way out (Get)
// rather than trusting the filesystem to have kept the bytes it was handed.
//
// The practical consequences of being unsigned and derivable:
//
//   - Losing the store loses only convenience (a viewer can no longer show what a
//     file contained); it never invalidates evidence, because the digests that
//     matter are in the signed stream, not here.
//   - Tampering with the store is detectable without any key material: rehash the
//     blob and compare against the signed digest. A modified blob simply stops
//     resolving.
//   - The store lives inside the session directory and is deleted with it. There is
//     no global cache and no cross-session dedup: workload file contents are
//     session-scoped data and must not outlive, or leak between, sessions.
//
// Layout is one file per blob under an algorithm-named subdirectory, which leaves
// room for a second digest algorithm to land beside sha256 without a migration:
//
//	<sessionDir>/blobs/sha256/<64 lowercase hex>
package blobstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"boxedai/internal/evidence"
)

const (
	// dirName is the store root inside a session directory.
	dirName = "blobs"
	// algoDir is the subdirectory for sha256-addressed blobs; it matches the
	// algorithm label in the digest so the on-disk path is readable next to the
	// "sha256:<hex>" strings that appear in evidence.
	algoDir = "sha256"
	// digestPrefix is the algorithm label evidence.SHA256Hex emits.
	digestPrefix = "sha256:"
	// hexLen is the length of a sha256 digest rendered as hex.
	hexLen = 64
)

// Dir returns the blob store root for a session directory. It does not create it;
// the store materializes on the first Put, so a session that captured no content
// simply has no blobs directory.
func Dir(sessionDir string) string {
	return filepath.Join(sessionDir, dirName)
}

// Path returns the on-disk path of a blob without touching the filesystem.
//
// The digest must be exactly "sha256:" followed by 64 lowercase hex characters;
// everything else — uppercase hex, wrong length, another algorithm, a bare hex
// string — is an error rather than something this package tries to normalize.
// That strictness is load-bearing, not pedantry: digests reach this function from
// HTTP handlers serving user-supplied query parameters, and a validated digest can
// contain no path separators, no "..", and no absolute-path prefix, so the joined
// result provably stays inside dir. Validating the key is what makes traversal
// impossible; do not relax this into a cleanup step.
func Path(dir, digest string) (string, error) {
	hex, ok := strings.CutPrefix(digest, digestPrefix)
	if !ok {
		return "", fmt.Errorf("blobstore: digest %q must start with %q", digest, digestPrefix)
	}
	if len(hex) != hexLen {
		return "", fmt.Errorf("blobstore: digest %q must have %d hex characters, has %d", digest, hexLen, len(hex))
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("blobstore: digest %q contains non-lowercase-hex character %q", digest, string(c))
		}
	}
	return filepath.Join(dir, algoDir, hex), nil
}

// Put stores content under digest, which must be the digest of content.
//
// The mismatch check is the invariant this whole package rests on: a blob filed
// under a key it does not hash to would resolve, look verified, and be wrong —
// poisoning content addressing for every later reader, including Get, which would
// then reject bytes it was handed in good faith. Refusing at write time keeps the
// damage at "this capture failed" instead of "this store lies".
//
// Put is idempotent. If the blob already exists it returns nil without rewriting:
// content-addressed names mean an existing file with this name either has these
// exact bytes or is already corrupt, and rewriting would fix nothing Get does not
// already catch. Concurrent Puts of the same digest are safe for the same reason —
// each writes its own temp file and the winning rename installs identical content.
//
// The write is atomic: a temp file in the destination directory is synced, then
// renamed into place, so a crash mid-capture leaves either no blob or a complete
// one, never a truncated file masquerading as captured content. Blobs are 0600 and
// directories 0700, matching the rest of the session directory — this is workload
// file content, and it is no less sensitive here than it was in the workspace.
func Put(dir, digest string, content []byte) error {
	path, err := Path(dir, digest)
	if err != nil {
		return err
	}
	if got := evidence.SHA256Hex(content); got != digest {
		return fmt.Errorf("blobstore: content does not match digest: want %s, content hashes to %s", digest, got)
	}
	if _, err := os.Stat(path); err == nil {
		return nil // already stored; same name means same content
	}

	blobDir := filepath.Dir(path)
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return fmt.Errorf("blobstore: create blob directory: %w", err)
	}
	tmp, err := os.CreateTemp(blobDir, ".blob-*.tmp")
	if err != nil {
		return fmt.Errorf("blobstore: create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	// Harmless once the rename succeeds; essential on every error path below.
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("blobstore: chmod temporary file: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("blobstore: write temporary file: %w", err)
	}
	// Sync before the rename so the rename can never publish a name whose bytes are
	// still in flight. The directory entry itself is deliberately not fsynced: a
	// blob lost to a host crash is a capture that simply did not happen, which the
	// unsigned store tolerates, whereas a visible-but-incomplete blob would not be.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("blobstore: fsync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("blobstore: close temporary file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("blobstore: install blob %s: %w", digest, err)
	}
	return nil
}

// Get reads the blob stored under digest and re-verifies its hash before returning
// it. Serving content that does not hash to the digest recorded in a signed segment
// would hand a caller unverified bytes wearing a verified label, which is strictly
// worse than returning nothing — so a mismatch is an error, never a warning.
//
// A missing blob is reported by wrapping the underlying os error, so callers can
// distinguish "never captured" (fs.ErrNotExist, an expected state for any file the
// capture policy declined) from "captured and corrupt".
func Get(dir, digest string) ([]byte, error) {
	path, err := Path(dir, digest)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("blobstore: read blob %s: %w", digest, err)
	}
	if got := evidence.SHA256Hex(content); got != digest {
		return nil, fmt.Errorf("blobstore: blob is corrupt: expected %s, got %s", digest, got)
	}
	return content, nil
}
