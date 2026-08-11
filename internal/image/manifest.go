package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Manifest describes one built golden image: which arch it targets, where its
// disk lives, and what went into it. Build writes one alongside disk.img;
// Resolve reads it back.
type Manifest struct {
	// Tag is a human-readable image identifier, e.g. "boxedai-base-arm64".
	Tag string `json:"tag"`
	// Arch is the Go GOARCH the image was built for ("arm64" or "amd64").
	Arch string `json:"arch"`
	// BuiltAt is when Build finished copying the disk out of the bake VM.
	BuiltAt time.Time `json:"built_at"`
	// DiskPath is the absolute host path to the disk file
	// (imagesDir()/<arch>/disk.img).
	DiskPath string `json:"disk_path"`
	// DiskDigest is "sha256:<hex>" of DiskPath's contents at build time.
	// Resolve recomputes and compares this on every read (see Resolve's doc
	// comment for the cost tradeoff) so a corrupted or hand-edited image
	// never goes unnoticed.
	DiskDigest string `json:"disk_digest"`
	// UbuntuImageURL is the stock cloud image the bake boot started from
	// (see vm.GenerateBakeLimaYAML's ubuntuImageURL).
	UbuntuImageURL string `json:"ubuntu_image_url"`
	// ClaudeCodePackage is the npm package Build installed for the "claude"
	// harness, "@anthropic-ai/claude-code".
	ClaudeCodePackage string `json:"claude_code_package"`
	// CodexPackage is the npm package Build installed for the "codex"
	// harness, "@openai/codex".
	CodexPackage string `json:"codex_package"`
	// ExtraCADigest identifies the corporate CA baked into the guest without
	// storing another copy of the certificate in the image manifest.
	ExtraCADigest string `json:"extra_ca_digest,omitempty"`
	// NPMRegistry records the registry used to install the harness CLIs so
	// setup can rebuild an image when corporate configuration changes.
	NPMRegistry string `json:"npm_registry,omitempty"`
}

// Well-known package/manifest constants recorded in every built Manifest.
// Precise installed version strings (npm package version, Tetragon release)
// are deliberately NOT captured here: getting them would mean shelling into
// the bake VM to read them back before Stop, which is real complexity for a
// v0.1 nicety. Recording the package names/URL that produced the image is
// enough to know what a given image *should* contain; if pinned versions
// become load-bearing later, add a provisioning step that writes them to a
// file in the guest and `limactl copy`s it out before Stop.
const (
	claudeCodePackage = "@anthropic-ai/claude-code"
	codexPackage      = "@openai/codex"
)

// errManifestMissing is wrapped into Resolve's "run build-image" error so
// callers can still distinguish "never built" from other failures via
// errors.Is if needed.
var errManifestMissing = errors.New("image: no manifest")

// Resolve reads back the golden image manifest for arch, verifying that the
// on-disk image still matches what Build recorded.
//
// A missing manifest is a fail-fast, actionable error: there is no sensible
// default image to fall back to, so callers (internal/session resolving
// vm.Config.ImagePath) should surface this to the user directly rather than
// attempting a session boot that can only fail deeper in Lima.
//
// A present-but-malformed manifest, a missing disk file, or a disk whose
// recomputed sha256 no longer matches DiskDigest are all fail-closed errors:
// a corrupted or hand-edited image must never be booted silently.
//
// Hashing cost: recomputing sha256 reads the full disk file each call. The
// bake disk is logically sized at ~20GiB but physically sparse (a couple GB
// allocated in practice), and the OS page cache makes repeat reads within a
// run cheap — this is an acceptable one-time-per-run cost, not an oversight;
// a future caller worried about it could cache Resolve's result for the
// process lifetime instead of re-deriving trust another way.
func Resolve(arch string) (Manifest, error) {
	mPath := manifestPath(arch)
	b, err := os.ReadFile(mPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Manifest{}, fmt.Errorf(
				"image: no golden image for arch %q (%w); run `boxedai build-image` first", arch, errManifestMissing)
		}
		return Manifest{}, fmt.Errorf("image: read manifest %s: %w", mPath, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf(
			"image: manifest %s is malformed: %w; run `boxedai build-image` to rebuild", mPath, err)
	}

	digest, err := sha256File(m.DiskPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Manifest{}, fmt.Errorf(
				"image: golden image disk %s is missing; run `boxedai build-image` to rebuild", m.DiskPath)
		}
		return Manifest{}, fmt.Errorf("image: hash disk %s: %w", m.DiskPath, err)
	}
	if digest != m.DiskDigest {
		return Manifest{}, fmt.Errorf(
			"image: golden image disk %s digest mismatch (manifest says %s, actual %s); "+
				"the image may be corrupted or hand-edited — run `boxedai build-image` to rebuild",
			m.DiskPath, m.DiskDigest, digest)
	}
	return m, nil
}

// sha256File streams path's contents through sha256 without loading the
// whole (potentially multi-GB) file into memory, returning "sha256:<hex>".
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
