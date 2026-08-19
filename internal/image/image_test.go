package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// fakeBakeVM is an in-process bakeVM that never boots Lima. It records which
// lifecycle calls ran (mirroring internal/session/session_test.go's fakeVM)
// so tests can assert Build drives it correctly.
type fakeBakeVM struct {
	startErr                            error
	verifyErr                           error
	stopContextErr                      error
	deleteContextErr                    error
	stopContextBounded                  bool
	deleteContextBounded                bool
	started, verified, stopped, deleted bool
}

func (f *fakeBakeVM) Start(context.Context) error  { f.started = true; return f.startErr }
func (f *fakeBakeVM) Verify(context.Context) error { f.verified = true; return f.verifyErr }
func (f *fakeBakeVM) Stop(ctx context.Context) error {
	f.stopped = true
	f.stopContextErr = ctx.Err()
	_, f.stopContextBounded = ctx.Deadline()
	return nil
}
func (f *fakeBakeVM) Delete(ctx context.Context) error {
	f.deleted = true
	f.deleteContextErr = ctx.Err()
	_, f.deleteContextBounded = ctx.Deadline()
	return nil
}

// withFakeBake overrides the newBakeVM and bakeInstanceDiskPath seams for the
// duration of one test: newBakeVM always returns fake, and the bake
// instance's "disk" resolves to a fixture file at diskFixture the test
// controls directly, rather than any real ~/.lima path.
func withFakeBake(t *testing.T, fake *fakeBakeVM, diskFixture string) {
	t.Helper()
	origNewBakeVM := newBakeVM
	origDiskPath := bakeInstanceDiskPath
	newBakeVM = func(name, yamlPath string, stdout, stderr io.Writer) bakeVM { return fake }
	bakeInstanceDiskPath = func(name string) (string, error) { return diskFixture, nil }
	t.Cleanup(func() {
		newBakeVM = origNewBakeVM
		bakeInstanceDiskPath = origDiskPath
	})
}

// sha256Hex hashes b and returns "sha256:<hex>", matching sha256File's format.
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// TestBuildSuccess drives Build with a fake bake VM and a fixture disk file,
// asserting the manifest and disk land correctly and every lifecycle call
// (Start, Stop, Delete) ran.
func TestBuildSuccess(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())

	diskContent := []byte("fake golden disk contents\n")
	diskFixture := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(diskFixture, diskContent, 0o644); err != nil {
		t.Fatalf("write disk fixture: %v", err)
	}

	fake := &fakeBakeVM{}
	withFakeBake(t, fake, diskFixture)

	m, err := Build(context.Background(), "arm64", "fixture-ca", "https://registry.example.internal/npm/")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if !fake.started || !fake.verified || !fake.stopped || !fake.deleted {
		t.Errorf("fake bake VM lifecycle = %+v, want all true", fake)
	}

	wantDigest := sha256Hex(diskContent)
	if m.DiskDigest != wantDigest {
		t.Errorf("DiskDigest = %q, want %q", m.DiskDigest, wantDigest)
	}
	if m.Arch != "arm64" {
		t.Errorf("Arch = %q, want arm64", m.Arch)
	}
	if m.Tag != "boxedai-base-arm64" {
		t.Errorf("Tag = %q, want boxedai-base-arm64", m.Tag)
	}
	if m.DiskPath != diskPath("arm64") {
		t.Errorf("DiskPath = %q, want %q", m.DiskPath, diskPath("arm64"))
	}
	if m.ClaudeCodePackage != claudeCodePackage || m.CodexPackage != codexPackage {
		t.Errorf("package fields = %+v, want %s/%s", m, claudeCodePackage, codexPackage)
	}
	if !m.FUSE3 || !m.FUSEPassthrough || !m.HWEKernel {
		t.Errorf("FUSE prerequisites = FUSE3:%t FUSEPassthrough:%t HWEKernel:%t, want all true", m.FUSE3, m.FUSEPassthrough, m.HWEKernel)
	}
	if m.ExtraCADigest != valueDigest("fixture-ca") || m.NPMRegistry != "https://registry.example.internal/npm/" {
		t.Errorf("corporate image inputs = %+v", m)
	}

	// The disk was actually copied (not just referenced).
	got, err := os.ReadFile(m.DiskPath)
	if err != nil {
		t.Fatalf("read copied disk: %v", err)
	}
	if string(got) != string(diskContent) {
		t.Errorf("copied disk content = %q, want %q", got, diskContent)
	}

	// No leftover temp files from the atomic rename dance.
	for _, p := range []string{m.DiskPath + ".tmp", manifestPath("arm64") + ".tmp"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("leftover temp file %s (err=%v)", p, err)
		}
	}

	// The scratch dir was cleaned up.
	entries, err := os.ReadDir(archDir("arm64"))
	if err != nil {
		t.Fatalf("read archDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == "" && len(e.Name()) > 0 && e.Name()[0] == '.' {
			t.Errorf("leftover scratch dir %s", e.Name())
		}
	}

	// Resolve reads back exactly what Build wrote.
	resolved, err := Resolve("arm64")
	if err != nil {
		t.Fatalf("Resolve after Build: %v", err)
	}
	if resolved.DiskDigest != m.DiskDigest || resolved.Tag != m.Tag || resolved.DiskPath != m.DiskPath {
		t.Errorf("Resolve = %+v, want %+v", resolved, m)
	}
}

// TestBuildStartFailure asserts that a failed provisioning boot still
// best-effort tears down the half-built instance (Stop + Delete both called)
// and that no manifest/disk are left behind for a later Resolve to trip over.
func TestBuildStartFailure(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())

	diskFixture := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(diskFixture, []byte("unused"), 0o644); err != nil {
		t.Fatalf("write disk fixture: %v", err)
	}

	wantErr := errors.New("boom: provisioning failed")
	fake := &fakeBakeVM{startErr: wantErr}
	withFakeBake(t, fake, diskFixture)

	_, err := Build(context.Background(), "arm64", "", "")
	if err == nil {
		t.Fatal("Build: want error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Build error = %v, want wrapping %v", err, wantErr)
	}

	if !fake.started || !fake.stopped || !fake.deleted {
		t.Errorf("fake bake VM lifecycle = %+v, want all true (best-effort cleanup)", fake)
	}

	if _, err := os.Stat(manifestPath("arm64")); !os.IsNotExist(err) {
		t.Errorf("manifest.json should not exist after a failed build (err=%v)", err)
	}
	if _, err := os.Stat(diskPath("arm64")); !os.IsNotExist(err) {
		t.Errorf("disk.img should not exist after a failed build (err=%v)", err)
	}
}

func TestBuildCancellationStillCleansUpBakeVM(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())

	diskFixture := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(diskFixture, []byte("unused"), 0o644); err != nil {
		t.Fatalf("write disk fixture: %v", err)
	}

	fake := &fakeBakeVM{startErr: context.Canceled}
	withFakeBake(t, fake, diskFixture)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Build(ctx, "arm64", "", "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Build error = %v, want context cancellation", err)
	}
	if !fake.started || !fake.stopped || !fake.deleted {
		t.Fatalf("fake bake VM lifecycle = %+v, want Stop and Delete after cancellation", fake)
	}
	if fake.stopContextErr != nil || fake.deleteContextErr != nil {
		t.Errorf("cleanup contexts were already canceled: Stop=%v Delete=%v", fake.stopContextErr, fake.deleteContextErr)
	}
	if !fake.stopContextBounded || !fake.deleteContextBounded {
		t.Errorf("cleanup contexts bounded = Stop:%t Delete:%t, want both true", fake.stopContextBounded, fake.deleteContextBounded)
	}
}

// TestBuildVerifyFailure asserts that a bake boot which reports success
// (Start returns nil) but fails CLI verification is still treated as a
// failed build: Build returns an error, no manifest/disk are written, and
// the half-built instance is still torn down (Stop + Delete called),
// mirroring TestBuildStartFailure's shape for the Verify gate.
func TestBuildVerifyFailure(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())

	diskFixture := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(diskFixture, []byte("unused"), 0o644); err != nil {
		t.Fatalf("write disk fixture: %v", err)
	}

	wantErr := errors.New("boom: Claude Code executable verification failed")
	fake := &fakeBakeVM{verifyErr: wantErr}
	withFakeBake(t, fake, diskFixture)

	_, err := Build(context.Background(), "arm64", "", "")
	if err == nil {
		t.Fatal("Build: want error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Build error = %v, want wrapping %v", err, wantErr)
	}

	if !fake.started || !fake.verified || !fake.stopped || !fake.deleted {
		t.Errorf("fake bake VM lifecycle = %+v, want all true (best-effort cleanup)", fake)
	}

	if _, err := os.Stat(manifestPath("arm64")); !os.IsNotExist(err) {
		t.Errorf("manifest.json should not exist after a failed build (err=%v)", err)
	}
	if _, err := os.Stat(diskPath("arm64")); !os.IsNotExist(err) {
		t.Errorf("disk.img should not exist after a failed build (err=%v)", err)
	}
}

// TestResolveMissingManifest checks the fail-fast, actionable error path when
// no image has ever been built for an arch.
func TestResolveMissingManifest(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())

	_, err := Resolve("arm64")
	if err == nil {
		t.Fatal("Resolve: want error, got nil")
	}
	if !errors.Is(err, errManifestMissing) {
		t.Errorf("Resolve error = %v, want wrapping errManifestMissing", err)
	}
}

// TestResolveMalformedManifest checks the fail-closed path for a present but
// unparsable manifest.json.
func TestResolveMalformedManifest(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())

	if err := os.MkdirAll(archDir("arm64"), 0o700); err != nil {
		t.Fatalf("mkdir archDir: %v", err)
	}
	if err := os.WriteFile(manifestPath("arm64"), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}

	if _, err := Resolve("arm64"); err == nil {
		t.Fatal("Resolve: want error for malformed manifest, got nil")
	}
}

// TestResolveDigestMismatch checks the fail-closed path when the disk file no
// longer matches the digest recorded at build time (corruption or a hand
// edit).
func TestResolveDigestMismatch(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())

	if err := os.MkdirAll(archDir("arm64"), 0o700); err != nil {
		t.Fatalf("mkdir archDir: %v", err)
	}
	if err := os.WriteFile(diskPath("arm64"), []byte("original contents"), 0o644); err != nil {
		t.Fatalf("write disk: %v", err)
	}
	m := Manifest{
		Tag:        "boxedai-base-arm64",
		Arch:       "arm64",
		DiskPath:   diskPath("arm64"),
		DiskDigest: sha256Hex([]byte("original contents")),
	}
	if err := writeManifest("arm64", m); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	// Corrupt the disk after the manifest was written.
	if err := os.WriteFile(diskPath("arm64"), []byte("corrupted!!"), 0o644); err != nil {
		t.Fatalf("corrupt disk: %v", err)
	}

	if _, err := Resolve("arm64"); err == nil {
		t.Fatal("Resolve: want digest mismatch error, got nil")
	}
}

// TestResolveValid checks the happy path: a manifest whose recorded digest
// still matches the disk file resolves cleanly.
func TestResolveValid(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())

	if err := os.MkdirAll(archDir("arm64"), 0o700); err != nil {
		t.Fatalf("mkdir archDir: %v", err)
	}
	content := []byte("a valid golden disk")
	if err := os.WriteFile(diskPath("arm64"), content, 0o644); err != nil {
		t.Fatalf("write disk: %v", err)
	}
	want := Manifest{
		Tag:               "boxedai-base-arm64",
		Arch:              "arm64",
		DiskPath:          diskPath("arm64"),
		DiskDigest:        sha256Hex(content),
		UbuntuImageURL:    ubuntuImageURL("arm64"),
		ClaudeCodePackage: claudeCodePackage,
		CodexPackage:      codexPackage,
	}
	if err := writeManifest("arm64", want); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}

	got, err := Resolve("arm64")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve = %+v, want %+v", got, want)
	}
}
