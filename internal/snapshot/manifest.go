// Package snapshot implements workspace snapshotting: cloning a repo into a session
// workspace, computing a content manifest of a directory tree, diffing two workspace
// states, and applying the resulting diff back onto the original repo. See
// DESIGN.md "Snapshot / workspace".
package snapshot

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"boxedai/internal/evidence"
)

// gitDirName is the directory whose contents are excluded from manifests (but whose
// presence is still recorded).
const gitDirName = ".git"

// File describes one entry in a workspace content manifest.
type File struct {
	Path    string `json:"path"`              // repo-relative, slash-separated
	Size    int64  `json:"size"`              // bytes; 0 for directory-presence entries
	Mode    uint32 `json:"mode"`              // raw fs.FileMode bits (type + permissions)
	SHA256  string `json:"sha256,omitempty"`  // "sha256:<hex>" for regular files, empty otherwise
	Symlink string `json:"symlink,omitempty"` // link target, only set for symlink entries
}

// Manifest is a deterministic, ordered content listing of a directory tree.
type Manifest struct {
	Root  string `json:"root"`  // the directory the manifest was computed over
	Files []File `json:"files"` // sorted by Path
}

// ManifestOf walks dir and computes a deterministic content manifest: every regular
// file's relative path, size, mode and sha256 digest; every symlink's target; and the
// presence of a top-level ".git" entry without descending into it. Non-regular,
// non-directory, non-symlink entries (unix sockets, fifos, device nodes — e.g. a live
// git fsmonitor socket) are silently skipped: they cannot be meaningfully hashed or
// restored, and erroring the whole manifest over one such entry would be worse than
// just omitting it. Files are sorted by path for deterministic output.
func ManifestOf(dir string) (Manifest, error) {
	var files []File
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil // root itself is not an entry
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("snapshot: relativize %s: %w", path, err)
		}
		rel = filepath.ToSlash(rel)

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("snapshot: stat %s: %w", path, err)
		}

		if d.IsDir() {
			if d.Name() == gitDirName {
				// Record presence, but skip walking its contents: git internals are
				// not meaningful workspace content and can be large.
				files = append(files, File{Path: rel, Mode: uint32(info.Mode())})
				return fs.SkipDir
			}
			return nil
		}

		if info.Mode()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("snapshot: readlink %s: %w", path, err)
			}
			files = append(files, File{Path: rel, Mode: uint32(info.Mode()), Symlink: target})
			return nil
		}

		if !info.Mode().IsRegular() {
			// Socket, fifo, device node, etc. — cannot be meaningfully hashed. Skip
			// rather than erroring the whole manifest.
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("snapshot: read %s: %w", path, err)
		}
		files = append(files, File{
			Path:   rel,
			Size:   info.Size(),
			Mode:   uint32(info.Mode()),
			SHA256: evidence.SHA256Hex(data),
		})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return Manifest{Root: dir, Files: files}, nil
}

// ManifestDigest returns the canonical-JSON sha256 digest of a manifest, the value
// recorded as input_manifest_digest / used in workspace.manifested events.
func ManifestDigest(m Manifest) (string, error) {
	b, err := evidence.CanonicalJSON(m)
	if err != nil {
		return "", fmt.Errorf("snapshot: canonicalize manifest: %w", err)
	}
	return evidence.SHA256Hex(b), nil
}

// isGitPath reports whether a manifest-relative path is the top-level .git entry or
// something inside it.
func isGitPath(p string) bool {
	return p == gitDirName || strings.HasPrefix(p, gitDirName+"/")
}
