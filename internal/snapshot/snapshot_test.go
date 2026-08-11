package snapshot

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// runGit runs a git command in dir, configured with a throwaway identity so `commit`
// works regardless of the host's global git config.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=boxedai-test", "GIT_AUTHOR_EMAIL=test@boxedai.invalid",
		"GIT_COMMITTER_NAME=boxedai-test", "GIT_COMMITTER_EMAIL=test@boxedai.invalid",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// writeFile creates a file (and its parent dirs) with the given content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// newFakeRepo builds a small repo tree (including a .git dir with content that must
// never be walked into) and returns its root.
func newFakeRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "README.md"), "hello\n")
	writeFile(t, filepath.Join(root, "src", "main.go"), "package main\n")
	writeFile(t, filepath.Join(root, ".git", "HEAD"), "ref: refs/heads/main\n")
	writeFile(t, filepath.Join(root, ".git", "objects", "pack", "pack-abc.pack"), "not a real pack\n")
	if err := os.Symlink("README.md", filepath.Join(root, "link-to-readme")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	return root
}

func TestSnapshotClonesContents(t *testing.T) {
	repo := newFakeRepo(t)
	dest := filepath.Join(t.TempDir(), "workspace")

	if err := Snapshot(repo, dest); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "README.md"))
	if err != nil {
		t.Fatalf("read cloned README.md: %v", err)
	}
	if string(got) != "hello\n" {
		t.Errorf("README.md content = %q, want %q", got, "hello\n")
	}
	if _, err := os.Stat(filepath.Join(dest, ".git", "objects", "pack", "pack-abc.pack")); err != nil {
		t.Errorf("expected .git contents to be cloned too (excludes nothing): %v", err)
	}
	target, err := os.Readlink(filepath.Join(dest, "link-to-readme"))
	if err != nil {
		t.Fatalf("readlink cloned symlink: %v", err)
	}
	if target != "README.md" {
		t.Errorf("symlink target = %q, want %q", target, "README.md")
	}
}

func TestSnapshotRefusesExistingDest(t *testing.T) {
	repo := newFakeRepo(t)
	dest := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}

	if err := Snapshot(repo, dest); err == nil {
		t.Fatal("Snapshot: expected error for existing dest, got nil")
	}
}

func TestManifestDeterministic(t *testing.T) {
	repo := newFakeRepo(t)

	m1, err := ManifestOf(repo)
	if err != nil {
		t.Fatalf("ManifestOf (1st): %v", err)
	}
	m2, err := ManifestOf(repo)
	if err != nil {
		t.Fatalf("ManifestOf (2nd): %v", err)
	}

	d1, err := ManifestDigest(m1)
	if err != nil {
		t.Fatalf("ManifestDigest (1st): %v", err)
	}
	d2, err := ManifestDigest(m2)
	if err != nil {
		t.Fatalf("ManifestDigest (2nd): %v", err)
	}
	if d1 != d2 {
		t.Errorf("manifest digest not deterministic: %s != %s", d1, d2)
	}
	if !strings.HasPrefix(d1, "sha256:") {
		t.Errorf("digest %q missing sha256: prefix", d1)
	}

	// Files must be sorted by path.
	if !slices.IsSortedFunc(m1.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) }) {
		t.Errorf("manifest files not sorted: %+v", m1.Files)
	}
}

func TestManifestSkipsGitContents(t *testing.T) {
	repo := newFakeRepo(t)

	m, err := ManifestOf(repo)
	if err != nil {
		t.Fatalf("ManifestOf: %v", err)
	}

	sawGitPresence := false
	for _, f := range m.Files {
		if f.Path == ".git" {
			sawGitPresence = true
			continue
		}
		if strings.HasPrefix(f.Path, ".git/") {
			t.Errorf("manifest should not walk .git contents, found %q", f.Path)
		}
	}
	if !sawGitPresence {
		t.Error("manifest should record .git presence as an entry")
	}
}

func TestManifestSymlinkEntry(t *testing.T) {
	repo := newFakeRepo(t)

	m, err := ManifestOf(repo)
	if err != nil {
		t.Fatalf("ManifestOf: %v", err)
	}

	var found *File
	for i := range m.Files {
		if m.Files[i].Path == "link-to-readme" {
			found = &m.Files[i]
		}
	}
	if found == nil {
		t.Fatal("expected link-to-readme entry in manifest")
	}
	if found.Symlink != "README.md" {
		t.Errorf("symlink target = %q, want %q", found.Symlink, "README.md")
	}
	if found.SHA256 != "" {
		t.Errorf("symlink entries should not carry a sha256, got %q", found.SHA256)
	}
}

// TestSnapshotSkipsSocket is the regression guard for a real bug: a repo with a
// live git fsmonitor unix socket (.git/fsmonitor--daemon.ipc) got that socket
// copied into workspace.orig, and at session teardown `git diff --no-index` aborted
// with "unsupported file type ... cannot hash". Sockets (like fifos and device
// nodes) cannot be meaningfully snapshotted or restored, so Snapshot, ManifestOf
// and Diff must all skip them silently instead of erroring.
func TestSnapshotSkipsSocket(t *testing.T) {
	// net.Listen("unix", ...) enforces the sockaddr_un sun_path limit (~104 bytes
	// on macOS/BSD). t.TempDir() embeds the test name in its path and can exceed
	// that, so the repo lives under a short os.MkdirTemp root instead.
	repo, err := os.MkdirTemp("", "bxsnap")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(repo) })

	writeFile(t, filepath.Join(repo, "README.md"), "hello\n")

	sockPath := filepath.Join(repo, "s")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen(unix): %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	sessionDir := t.TempDir()
	orig := filepath.Join(sessionDir, "workspace.orig")
	cur := filepath.Join(sessionDir, "workspace")

	if err := Snapshot(repo, orig); err != nil {
		t.Fatalf("Snapshot(orig): %v", err)
	}
	if err := Snapshot(repo, cur); err != nil {
		t.Fatalf("Snapshot(cur): %v", err)
	}
	if _, err := os.Lstat(filepath.Join(orig, "s")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket should be absent from snapshot copy, lstat err = %v", err)
	}

	m, err := ManifestOf(repo)
	if err != nil {
		t.Fatalf("ManifestOf: %v", err)
	}
	for _, f := range m.Files {
		if f.Path == "s" {
			t.Errorf("socket should be absent from manifest, got entry %+v", f)
		}
	}

	if _, err := Diff(orig, cur); err != nil {
		t.Fatalf("Diff: %v", err)
	}
}

// TestDiffSkipsSocketAppearingAfterSnapshot is the regression guard for the
// second half of the same real bug: a background `git fsmonitor--daemon`
// respawns its IPC socket the moment anything touches a worktree, so a clone
// that was socket-free right after Snapshot can still have one by the time
// Diff runs moments later. Pruning only at Snapshot time missed this — Diff
// itself (via unifiedDiff, right before invoking `git diff --no-index`, which
// ignores pathspecs and fatals on any non-regular file) must re-prune too.
func TestDiffSkipsSocketAppearingAfterSnapshot(t *testing.T) {
	sessionDir, err := os.MkdirTemp("", "bxdiff")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sessionDir) })

	orig := filepath.Join(sessionDir, "workspace.orig")
	cur := filepath.Join(sessionDir, "workspace")
	if err := os.MkdirAll(orig, 0o755); err != nil {
		t.Fatalf("MkdirAll(orig): %v", err)
	}
	if err := os.MkdirAll(cur, 0o755); err != nil {
		t.Fatalf("MkdirAll(cur): %v", err)
	}
	writeFile(t, filepath.Join(orig, "README.md"), "hello\n")
	writeFile(t, filepath.Join(cur, "README.md"), "hello\n")

	// No socket exists in either tree when Snapshot would have run; one shows
	// up in cur only afterward, simulating a respawned fsmonitor daemon.
	sockPath := filepath.Join(cur, "s")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen(unix): %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	if _, err := Diff(orig, cur); err != nil {
		t.Fatalf("Diff: %v", err)
	}
}

func TestDiffClassifiesChanges(t *testing.T) {
	repo := newFakeRepo(t)
	sessionDir := t.TempDir()
	orig := filepath.Join(sessionDir, "workspace.orig")
	cur := filepath.Join(sessionDir, "workspace")

	if err := Snapshot(repo, orig); err != nil {
		t.Fatalf("Snapshot(orig): %v", err)
	}
	if err := Snapshot(repo, cur); err != nil {
		t.Fatalf("Snapshot(cur): %v", err)
	}

	// Modify an existing file.
	writeFile(t, filepath.Join(cur, "README.md"), "hello again\n")
	// Add a new file.
	writeFile(t, filepath.Join(cur, "NEW.md"), "new file\n")
	// Delete an existing file.
	if err := os.Remove(filepath.Join(cur, "src", "main.go")); err != nil {
		t.Fatalf("remove src/main.go: %v", err)
	}

	report, err := Diff(orig, cur)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if !slices.Contains(report.Modified, "README.md") {
		t.Errorf("Modified = %v, want to contain README.md", report.Modified)
	}
	if !slices.Contains(report.Added, "NEW.md") {
		t.Errorf("Added = %v, want to contain NEW.md", report.Added)
	}
	if !slices.Contains(report.Deleted, "src/main.go") {
		t.Errorf("Deleted = %v, want to contain src/main.go", report.Deleted)
	}
	for _, p := range slices.Concat(report.Added, report.Modified, report.Deleted) {
		if isGitPath(p) {
			t.Errorf("diff classification leaked a .git path: %s", p)
		}
	}

	if !strings.Contains(report.UnifiedDiff, "README.md") {
		t.Errorf("UnifiedDiff missing README.md hunk:\n%s", report.UnifiedDiff)
	}
	if strings.Contains(report.UnifiedDiff, ".git/") {
		t.Errorf("UnifiedDiff should not include .git internals:\n%s", report.UnifiedDiff)
	}
	// Header paths should be plain a/<relpath> b/<relpath>, not the absolute
	// snapshot directory paths, so the diff can be git-applied against a real repo.
	if strings.Contains(report.UnifiedDiff, orig) || strings.Contains(report.UnifiedDiff, cur) {
		t.Errorf("UnifiedDiff leaked snapshot directory paths:\n%s", report.UnifiedDiff)
	}
}

func TestWriteDiffAndApply(t *testing.T) {
	repo := newFakeRepo(t)
	sessionDir := t.TempDir()
	orig := filepath.Join(sessionDir, "workspace.orig")
	cur := filepath.Join(sessionDir, "workspace")

	if err := Snapshot(repo, orig); err != nil {
		t.Fatalf("Snapshot(orig): %v", err)
	}
	if err := Snapshot(repo, cur); err != nil {
		t.Fatalf("Snapshot(cur): %v", err)
	}
	writeFile(t, filepath.Join(cur, "README.md"), "hello again\n")

	report, err := Diff(orig, cur)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if err := WriteDiff(sessionDir, report); err != nil {
		t.Fatalf("WriteDiff: %v", err)
	}

	diffPath := filepath.Join(sessionDir, "workspace.diff")
	data, err := os.ReadFile(diffPath)
	if err != nil {
		t.Fatalf("read workspace.diff: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("workspace.diff is empty")
	}

	// Apply against a fresh, clean git checkout of the original (pre-modification)
	// repo content: same relative layout as orig, but a real git repo.
	applyRepo := t.TempDir()
	writeFile(t, filepath.Join(applyRepo, "README.md"), "hello\n")
	writeFile(t, filepath.Join(applyRepo, "src", "main.go"), "package main\n")
	runGit(t, applyRepo, "init")
	runGit(t, applyRepo, "add", "README.md", "src/main.go")
	runGit(t, applyRepo, "commit", "-m", "init", "--no-gpg-sign")

	if err := Apply(sessionDir, applyRepo); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(applyRepo, "README.md"))
	if err != nil {
		t.Fatalf("read applied README.md: %v", err)
	}
	if string(got) != "hello again\n" {
		t.Errorf("applied README.md = %q, want %q", got, "hello again\n")
	}
}

func TestApplyRefusesDirtyRepo(t *testing.T) {
	repo := newFakeRepo(t)
	sessionDir := t.TempDir()
	orig := filepath.Join(sessionDir, "workspace.orig")
	cur := filepath.Join(sessionDir, "workspace")
	if err := Snapshot(repo, orig); err != nil {
		t.Fatalf("Snapshot(orig): %v", err)
	}
	if err := Snapshot(repo, cur); err != nil {
		t.Fatalf("Snapshot(cur): %v", err)
	}
	writeFile(t, filepath.Join(cur, "README.md"), "hello again\n")
	report, err := Diff(orig, cur)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if err := WriteDiff(sessionDir, report); err != nil {
		t.Fatalf("WriteDiff: %v", err)
	}

	dirtyRepo := t.TempDir()
	runGit(t, dirtyRepo, "init")
	writeFile(t, filepath.Join(dirtyRepo, "README.md"), "hello\n")
	runGit(t, dirtyRepo, "add", "README.md")
	runGit(t, dirtyRepo, "commit", "-m", "init", "--no-gpg-sign")
	// Leave an uncommitted change so git status --porcelain is non-empty.
	writeFile(t, filepath.Join(dirtyRepo, "README.md"), "dirty\n")

	if err := Apply(sessionDir, dirtyRepo); err == nil {
		t.Fatal("Apply: expected error against a dirty repo, got nil")
	}
}
