package image

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"boxedai/internal/vm"
)

const bakeCleanupTimeout = 30 * time.Second

// ubuntuImageURL mirrors vm's own (unexported) ubuntuImageURL in
// internal/vm/lima.go exactly: the stock Ubuntu 24.04 cloud image the bake
// boot starts from. It is duplicated here (rather than exported from
// internal/vm) because this is the only other place that needs it, purely to
// record it in the Manifest — keep the two in sync if Ubuntu's release or
// naming scheme ever changes.
func ubuntuImageURL(goArch string) string {
	return fmt.Sprintf("https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-%s.img", goArch)
}

// bakeVM is the narrow slice of *vm.BakeVM that Build drives. Isolating it
// behind an interface lets tests inject a fake that never boots Lima, mirroring
// internal/session/run.go's vmController seam.
type bakeVM interface {
	Start(ctx context.Context) error
	Verify(ctx context.Context) error
	Stop(ctx context.Context) error
	Delete(ctx context.Context) error
}

func runBakeCleanup(action func(context.Context) error) error {
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), bakeCleanupTimeout)
	defer cancelCleanup()
	return action(cleanupCtx)
}

// newBakeVM builds the bakeVM driver for a given instance name and rendered
// lima.yaml path. A package-level var, like internal/session's vmFactory, so
// tests can substitute a fake.
var newBakeVM = func(name, yamlPath string, stdout, stderr io.Writer) bakeVM {
	return &vm.BakeVM{Name: name, LimaYAMLPath: yamlPath, Stdout: stdout, Stderr: stderr}
}

// bakeInstanceDiskPath returns the host path to a stopped bake instance's
// exported Lima disk file, ~/.lima/<name>/disk. This is a fixed path Lima
// itself owns — independent of BOXEDAI_HOME (see package doc comment) — so it
// resolves against the real home directory, not home(). A package-level var,
// like internal/session's lookupClaudeKeychain/codexAuthPath, so tests can
// point it at a fixture file instead of a real Lima instance directory.
var bakeInstanceDiskPath = func(name string) (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("image: resolve home dir for lima instance disk: %w", err)
	}
	return filepath.Join(dir, ".lima", name, "disk"), nil
}

// newBuildSuffix returns 8 random hex characters used to make a build's
// scratch dir and instance name unique.
func newBuildSuffix() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("image: generate build id randomness: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Build drives the one-off, throwaway bake VM (internal/vm's
// BakeConfig/BakeVM) through a full provisioning boot, then exports its
// stopped disk as the golden image for arch, overwriting any previous build.
// This is the `boxedai build-image` implementation.
//
// extraCAPEM, if non-empty, is trusted inside the guest before npm runs
// (passed straight through to vm.BakeConfig.ExtraCAPEM).
//
// npmRegistry, if non-empty, overrides npm's default registry inside the
// guest before npm runs (passed straight through to
// vm.BakeConfig.NPMRegistry).
//
// v0.1 does not lock against concurrent builds: two `boxedai build-image`
// runs for the same arch racing each other will each boot their own bake VM
// (harmless — distinct instance names) but may interleave their final
// disk.img/manifest.json writes. Each individual write is atomic (temp file +
// rename), so no reader ever sees a torn file, but the "last Build to finish
// wins" outcome is unspecified. Acceptable for v0.1: builds are rare,
// deliberate, operator-driven actions, not something to design real locking
// around yet.
func Build(ctx context.Context, arch, extraCAPEM, npmRegistry string) (Manifest, error) {
	return BuildWithOutput(ctx, arch, extraCAPEM, npmRegistry, os.Stdout, os.Stderr)
}

// BuildWithOutput is Build with explicit writers for Lima's provisioning
// output. Machine-readable callers use stderr so stdout remains valid JSON.
func BuildWithOutput(ctx context.Context, arch, extraCAPEM, npmRegistry string, stdout, stderr io.Writer) (Manifest, error) {
	dir := archDir(arch)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Manifest{}, fmt.Errorf("image: create %s: %w", dir, err)
	}

	// Scratch dir for the bake boot's own lima.yaml (not a real session dir —
	// see vm.BakeConfig.SessionDir's doc comment). Colocating it under
	// archDir with a unique MkdirTemp suffix keeps it out of the way of a
	// concurrent build (see doc comment above) without needing a lock.
	scratchDir, err := os.MkdirTemp(dir, ".build-")
	if err != nil {
		return Manifest{}, fmt.Errorf("image: create build scratch dir: %w", err)
	}
	defer os.RemoveAll(scratchDir)

	suffix, err := newBuildSuffix()
	if err != nil {
		return Manifest{}, err
	}
	// Distinct from real session names ("bx-<timestamp>-<hex>") and
	// recognizable in `limactl list` if a human needs to clean up a failed
	// build by hand.
	instanceName := fmt.Sprintf("boxedai-image-build-%s-%s", arch, suffix)

	yamlPath, err := vm.WriteBakeLimaYAML(vm.BakeConfig{
		Arch:        arch,
		ExtraCAPEM:  extraCAPEM,
		NPMRegistry: npmRegistry,
		SessionDir:  scratchDir,
	})
	if err != nil {
		return Manifest{}, err
	}

	bv := newBakeVM(instanceName, yamlPath, stdout, stderr)

	// Start bounds Lima's unreliable internal readiness wait, then blocks on
	// independent shell probes until Lima's boot-complete marker exists. It
	// streams progress straight to the terminal (vm.BakeVM.Start hardcodes
	// os.Stdout/os.Stderr), exactly like a real session's VM.Start — so
	// `boxedai build-image` shows the same live provisioning log UX as
	// `boxedai run`.
	if err := bv.Start(ctx); err != nil {
		// Best-effort teardown of a half-built instance so a failed build
		// doesn't leak a stopped-but-undeleted Lima instance. Cleanup
		// failures are swallowed: they must not mask the original error.
		_ = runBakeCleanup(bv.Stop)
		_ = runBakeCleanup(bv.Delete)
		return Manifest{}, fmt.Errorf("image: bake VM %s failed to provision: %w", instanceName, err)
	}

	// Start returning nil means Lima reached its boot-complete marker — it does
	// NOT mean every provisioning script succeeded, since Lima's
	// provision.system mode logs a WARNING and moves on when an individual
	// script fails rather than failing the boot (confirmed empirically: an npm
	// install failure left limactl start exiting 0). Verify is the actual gate
	// against silently shipping a golden image missing the Claude Code
	// executable.
	if err := bv.Verify(ctx); err != nil {
		_ = runBakeCleanup(bv.Stop)
		_ = runBakeCleanup(bv.Delete)
		return Manifest{}, fmt.Errorf("image: bake VM %s provisioned but failed CLI verification: %w", instanceName, err)
	}

	if err := runBakeCleanup(bv.Stop); err != nil {
		return Manifest{}, fmt.Errorf(
			"image: stop bake VM %s after provisioning succeeded: %w (instance left for manual cleanup: ./bin/limactl delete %s)",
			instanceName, err, instanceName)
	}

	srcDisk, err := bakeInstanceDiskPath(instanceName)
	if err != nil {
		return Manifest{}, err
	}
	dstDisk := diskPath(arch)
	if err := copyDisk(srcDisk, dstDisk); err != nil {
		return Manifest{}, fmt.Errorf(
			"image: copy golden disk from %s: %w (instance left for manual cleanup: ./bin/limactl delete %s)",
			srcDisk, err, instanceName)
	}

	digest, err := sha256File(dstDisk)
	if err != nil {
		return Manifest{}, fmt.Errorf(
			"image: hash golden disk %s: %w (instance left for manual cleanup: ./bin/limactl delete %s)",
			dstDisk, err, instanceName)
	}

	m := Manifest{
		Tag:               fmt.Sprintf("boxedai-base-%s", arch),
		Arch:              arch,
		BuiltAt:           time.Now().UTC(),
		DiskPath:          dstDisk,
		DiskDigest:        digest,
		UbuntuImageURL:    ubuntuImageURL(arch),
		ClaudeCodePackage: claudeCodePackage,
		CodexPackage:      codexPackage,
		ExtraCADigest:     valueDigest(extraCAPEM),
		NPMRegistry:       npmRegistry,
	}
	if err := writeManifest(arch, m); err != nil {
		return Manifest{}, fmt.Errorf(
			"%w (instance left for manual cleanup: ./bin/limactl delete %s)", err, instanceName)
	}

	if err := runBakeCleanup(bv.Delete); err != nil {
		return Manifest{}, fmt.Errorf(
			"image: delete bake VM %s after copying disk: %w (manual cleanup: ./bin/limactl delete %s)",
			instanceName, err, instanceName)
	}

	return m, nil
}

func valueDigest(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeManifest marshals m as indented JSON and writes it to
// archDir(arch)/manifest.json via temp file + rename, so a concurrent Resolve
// never observes a partially written manifest.
func writeManifest(arch string, m Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("image: marshal manifest: %w", err)
	}
	path := manifestPath(arch)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("image: write manifest temp file %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("image: rename manifest into place: %w", err)
	}
	return nil
}

// copyDisk copies src to dst via a temp file + rename, so a concurrent
// Resolve never observes a partially written disk image. It prefers an APFS
// copy-on-write clone (cp -c, the single-file analog of internal/snapshot's
// cloneAPFS), falling back to a plain streamed copy when cloning isn't
// available (different volume, non-APFS, etc.).
func copyDisk(src, dst string) error {
	tmp := dst + ".tmp"
	// Clear any stale temp file left by a previously failed build attempt;
	// cp -c and the fallback both expect to create dst fresh.
	_ = os.Remove(tmp)

	if err := cloneFileAPFS(src, tmp); err != nil {
		_ = os.Remove(tmp)
		if ferr := copyFileStream(src, tmp); ferr != nil {
			return fmt.Errorf("clone failed (%v), fallback copy also failed: %w", err, ferr)
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp, dst, err)
	}
	return nil
}

// cloneFileAPFS attempts an APFS copy-on-write clone of src into dst via
// `cp -c src dst`. It fails (returning an error) on non-APFS volumes or when
// cp doesn't support -c — mirrors internal/snapshot's cloneAPFS, adapted for
// a single file instead of a directory tree.
func cloneFileAPFS(src, dst string) error {
	cmd := exec.Command("cp", "-c", src, dst)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cp -c: %w: %s", err, stderr.String())
	}
	return nil
}

// copyFileStream copies src to dst without loading the whole (potentially
// multi-GB) file into memory. Used as the fallback when APFS cloning isn't
// available.
func copyFileStream(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()

	if _, err = io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	return nil
}
