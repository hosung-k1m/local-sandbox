package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// diffFileName is the file workspace.diff is written under inside a session dir.
const diffFileName = "workspace.diff"

// DiffReport summarizes the workspace changes between two snapshots of the same
// logical tree: the sets of added, modified and deleted repo-relative paths, and a
// human-readable unified diff of the actual content changes.
type DiffReport struct {
	Added       []string `json:"added"`
	Modified    []string `json:"modified"`
	Deleted     []string `json:"deleted"`
	UnifiedDiff string   `json:"unified_diff"`
}

// Diff compares the content manifests of orig and cur (e.g. the pristine input
// snapshot and the post-session workspace) and reports added/modified/deleted paths
// plus a unified text diff of the changes. .git is ignored throughout.
func Diff(orig, cur string) (DiffReport, error) {
	origManifest, err := ManifestOf(orig)
	if err != nil {
		return DiffReport{}, fmt.Errorf("snapshot: manifest %s: %w", orig, err)
	}
	curManifest, err := ManifestOf(cur)
	if err != nil {
		return DiffReport{}, fmt.Errorf("snapshot: manifest %s: %w", cur, err)
	}

	origFiles := make(map[string]File, len(origManifest.Files))
	for _, f := range origManifest.Files {
		if isGitPath(f.Path) {
			continue
		}
		origFiles[f.Path] = f
	}
	curFiles := make(map[string]File, len(curManifest.Files))
	for _, f := range curManifest.Files {
		if isGitPath(f.Path) {
			continue
		}
		curFiles[f.Path] = f
	}

	var report DiffReport
	for path, cf := range curFiles {
		of, existed := origFiles[path]
		switch {
		case !existed:
			report.Added = append(report.Added, path)
		case of.SHA256 != cf.SHA256 || of.Symlink != cf.Symlink || of.Mode != cf.Mode:
			report.Modified = append(report.Modified, path)
		}
	}
	for path := range origFiles {
		if _, ok := curFiles[path]; !ok {
			report.Deleted = append(report.Deleted, path)
		}
	}
	sort.Strings(report.Added)
	sort.Strings(report.Modified)
	sort.Strings(report.Deleted)

	report.UnifiedDiff, err = unifiedDiff(orig, cur)
	if err != nil {
		return DiffReport{}, err
	}
	return report, nil
}

// diffGitHeaderRE matches a `diff --git a/<path> b/<path>` header line so the two
// embedded paths can be checked against isGitPath and stripped of their snapshot
// directory prefixes.
var diffGitHeaderRE = regexp.MustCompile(`^diff --git a/(.*) b/(.*)$`)

// unifiedDiff runs `git diff --no-index` over the two snapshot directories and
// rewrites the resulting headers so paths read as plain "a/<relpath>" / "b/<relpath>"
// (stripping the orig/cur absolute-directory prefixes git embeds), dropping any
// hunks under .git. The rewritten form is a standard patch applicable with `git
// apply` from within the original repo (see Apply).
func unifiedDiff(orig, cur string) (string, error) {
	origAbs, err := filepath.Abs(orig)
	if err != nil {
		return "", fmt.Errorf("snapshot: absolute path of %s: %w", orig, err)
	}
	curAbs, err := filepath.Abs(cur)
	if err != nil {
		return "", fmt.Errorf("snapshot: absolute path of %s: %w", cur, err)
	}

	// `git diff --no-index` walks and hashes every entry itself, ignoring
	// pathspecs entirely (confirmed empirically: `:(exclude)` and `:!` under
	// --no-index still fail on a non-regular file) — so it fatals on a socket,
	// fifo, or device node even though isGitPath above already excludes .git
	// content from the report. A background `git fsmonitor--daemon` can also
	// respawn its IPC socket in either tree's .git between snapshot time and
	// here (observed in practice: a corp macOS git config with core.fsmonitor
	// enabled recreates it the moment anything touches the worktree), so
	// pruning once at Snapshot time is not enough — it must happen again right
	// before the diff runs.
	if err := pruneNonRegular(origAbs); err != nil {
		return "", fmt.Errorf("snapshot: prune non-regular files in %s: %w", origAbs, err)
	}
	if err := pruneNonRegular(curAbs); err != nil {
		return "", fmt.Errorf("snapshot: prune non-regular files in %s: %w", curAbs, err)
	}

	out, err := gitDiffNoIndex(origAbs, curAbs)
	if err != nil {
		return "", err
	}
	return normalizeDiffPaths(out, origAbs, curAbs), nil
}

// gitDiffNoIndex runs `git diff --no-index --no-color` over two paths (directories
// for unifiedDiff, single files for DiffContents) and returns its stdout verbatim.
// Header rewriting is each caller's job, because they embed different paths and
// want different labels back.
func gitDiffNoIndex(a, b string) (string, error) {
	cmd := exec.Command("git", "diff", "--no-index", "--no-color", "--", a, b)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		// git diff --no-index exits 1 when it found differences; that's not failure.
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			return "", fmt.Errorf("snapshot: git diff --no-index: %w: %s", err, stderr.String())
		}
	}
	return stdout.String(), nil
}

// normalizeDiffPaths strips the origAbs/curAbs directory prefixes that `git diff
// --no-index` embeds in every header/hunk-marker line, leaving plain repo-relative
// paths behind the standard a/ b/ prefixes, and drops any file section under .git.
func normalizeDiffPaths(diff, origAbs, curAbs string) string {
	if diff == "" {
		return diff
	}
	origPrefix := strings.TrimPrefix(origAbs, "/") + "/"
	curPrefix := strings.TrimPrefix(curAbs, "/") + "/"
	stripPrefixes := func(s string) string {
		s = strings.ReplaceAll(s, "a/"+origPrefix, "a/")
		s = strings.ReplaceAll(s, "a/"+curPrefix, "a/")
		s = strings.ReplaceAll(s, "b/"+origPrefix, "b/")
		s = strings.ReplaceAll(s, "b/"+curPrefix, "b/")
		return s
	}

	lines := strings.Split(diff, "\n")
	out := make([]string, 0, len(lines))
	skip := false
	for _, line := range lines {
		line = stripPrefixes(line)
		if m := diffGitHeaderRE.FindStringSubmatch(line); m != nil {
			skip = isGitPath(m[1]) || isGitPath(m[2])
		}
		if !skip {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// DiffContents renders a unified diff between two in-memory versions of the single
// file at relPath. It is the per-file counterpart to unifiedDiff above, for callers
// that hold content rather than two trees on disk — the viewer's /api/filediff
// diffing a captured blob against the session-start copy of the same path.
//
// Both sides are always written as real files, an empty side included. Diffing two
// files that exist keeps this function free of /dev/null special cases: an empty
// "from" already renders as an all-additions hunk and an empty "to" as all
// deletions, which is what a creation and a deletion look like to a reader. The
// cost is that the result is a plain content diff rather than a patch carrying
// "new file mode"/"deleted file mode" metadata — nothing produced here is meant to
// be applied (that is Apply's job, from the whole-tree workspace.diff).
//
// relPath is a label only: it names the two sides in the rewritten headers and is
// never joined to a filesystem path. Identical content yields "".
//
// The sides go through an os.MkdirTemp directory (0700, removed on every return)
// because git diffs paths, not pipes. That briefly places workload file content on
// the host's temp filesystem — the same content the caller is about to serve.
func DiffContents(relPath string, from, to []byte) (string, error) {
	dir, err := os.MkdirTemp("", "boxedai-filediff-")
	if err != nil {
		return "", fmt.Errorf("snapshot: create temporary diff directory: %w", err)
	}
	defer os.RemoveAll(dir)

	fromPath := filepath.Join(dir, "from")
	toPath := filepath.Join(dir, "to")
	if err := os.WriteFile(fromPath, from, 0o600); err != nil {
		return "", fmt.Errorf("snapshot: write %s: %w", fromPath, err)
	}
	if err := os.WriteFile(toPath, to, 0o600); err != nil {
		return "", fmt.Errorf("snapshot: write %s: %w", toPath, err)
	}

	out, err := gitDiffNoIndex(fromPath, toPath)
	if err != nil {
		return "", err
	}
	return rewriteContentDiffPaths(out, fromPath, toPath, relPath), nil
}

// rewriteContentDiffPaths replaces the temporary file paths git embedded in the
// headers with relPath, so the diff reads as "a/<relPath>" / "b/<relPath>" — the
// path the content actually came from — instead of exposing a scratch directory
// that no longer exists by the time anyone reads the output.
//
// Like normalizeDiffPaths, it accounts for git rendering an absolute path inside an
// a/ b/ prefix with the leading slash dropped (a/tmp/... for /tmp/...). The two
// temp paths differ in their final component, so each side rewrites to exactly one
// target and the substitutions cannot collide.
func rewriteContentDiffPaths(diff, fromPath, toPath, relPath string) string {
	if diff == "" {
		return diff
	}
	return strings.NewReplacer(
		"a/"+strings.TrimPrefix(fromPath, "/"), "a/"+relPath,
		"b/"+strings.TrimPrefix(toPath, "/"), "b/"+relPath,
	).Replace(diff)
}

// WriteDiff writes r's unified diff to workspace.diff inside sessionDir.
func WriteDiff(sessionDir string, r DiffReport) error {
	path := filepath.Join(sessionDir, diffFileName)
	if err := os.WriteFile(path, []byte(r.UnifiedDiff), 0o644); err != nil {
		return fmt.Errorf("snapshot: write %s: %w", path, err)
	}
	return nil
}

// Apply applies sessionDir's workspace.diff onto repoPath via `git apply`. It refuses
// if repoPath has uncommitted changes (`git status --porcelain` is non-empty). This
// is an explicit, user-invoked operation only — never called automatically.
func Apply(sessionDir, repoPath string) error {
	dirty, err := gitDirty(repoPath)
	if err != nil {
		return fmt.Errorf("snapshot: check git status of %s: %w", repoPath, err)
	}
	if dirty {
		return fmt.Errorf("snapshot: refusing to apply: %s has uncommitted changes", repoPath)
	}

	diffPath := filepath.Join(sessionDir, diffFileName)
	cmd := exec.Command("git", "apply", diffPath)
	cmd.Dir = repoPath
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("snapshot: git apply %s: %w: %s", diffPath, err, stderr.String())
	}
	return nil
}

// gitDirty reports whether repoPath has any uncommitted changes.
func gitDirty(repoPath string) (bool, error) {
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = repoPath
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("git status: %w: %s", err, stderr.String())
	}
	return len(strings.TrimSpace(string(out))) > 0, nil
}
