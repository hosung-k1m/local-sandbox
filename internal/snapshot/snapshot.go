package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

// Snapshot copies repo's contents into dest, so that dest ends up an independent copy
// of repo (excludes nothing meaningful: the VM sees exactly the repo state, aside from
// non-regular files — see copyTree). It prefers an APFS copy-on-write clone (`cp
// -Rc`), which is cheap regardless of repo size, and falls back to a plain recursive
// copy (preserving file modes and symlinks) when the destination volume doesn't
// support cloning. Snapshot refuses if dest already exists. Callers needing a second,
// pristine copy for later diffing (see Diff) just call Snapshot again into a different
// dest — cloning is cheap on APFS.
func Snapshot(repo, dest string) error {
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("snapshot: destination %s already exists", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("snapshot: stat destination %s: %w", dest, err)
	}

	if err := cloneAPFS(repo, dest); err == nil {
		// Unlike copyTree, `cp -Rc` clones non-regular entries (sockets, fifos,
		// device nodes — e.g. a live git fsmonitor socket) as-is rather than
		// skipping them, so the same exclusion has to be applied afterward here.
		if err := pruneNonRegular(dest); err != nil {
			return fmt.Errorf("snapshot: prune non-regular files in %s: %w", dest, err)
		}
		return nil
	}

	// cp -Rc may have left a partial copy behind (e.g. failed partway through a
	// non-APFS volume); clear it before falling back to a plain recursive copy.
	if err := os.RemoveAll(dest); err != nil {
		return fmt.Errorf("snapshot: clean up failed clone at %s: %w", dest, err)
	}
	if err := copyTree(repo, dest); err != nil {
		return fmt.Errorf("snapshot: copy %s to %s: %w", repo, dest, err)
	}
	return nil
}

// pruneNonRegular removes any directory, symlink-preserving copy's leftover
// non-regular entries (sockets, fifos, device nodes) that `cp -Rc` cloned
// verbatim: they cannot be meaningfully diffed or restored, so Snapshot omits
// them the same way copyTree's fallback path already does.
func pruneNonRegular(dest string) error {
	return filepath.WalkDir(dest, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 || d.Type().IsRegular() {
			return nil
		}
		return os.Remove(path)
	})
}

// cloneAPFS attempts an APFS copy-on-write clone of repo's contents into dest via
// `cp -Rc repo/. dest`. It fails (returning an error) on non-APFS volumes or when cp
// doesn't support -c.
func cloneAPFS(repo, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return fmt.Errorf("snapshot: create %s: %w", dest, err)
	}
	cmd := exec.Command("cp", "-Rc", repo+"/.", dest)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cp -Rc: %w: %s", err, stderr.String())
	}
	return nil
}

// copyTree recursively copies src into dst, preserving file modes and symlinks
// (not followed). Used as the fallback when APFS cloning isn't available.
// Non-regular, non-directory, non-symlink entries (unix sockets, fifos, device
// nodes — e.g. a live git fsmonitor socket) are silently skipped: they cannot be
// meaningfully copied or restored, and erroring the whole snapshot over one such
// entry would be worse than just omitting it.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return fmt.Errorf("snapshot: relativize %s: %w", path, err)
		}
		target := filepath.Join(dst, rel)

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("snapshot: stat %s: %w", path, err)
		}

		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		case info.Mode()&fs.ModeSymlink != 0:
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("snapshot: readlink %s: %w", path, err)
			}
			return os.Symlink(linkTarget, target)
		case !info.Mode().IsRegular():
			// Socket, fifo, device node, etc. — skip rather than erroring the copy.
			return nil
		default:
			return copyFile(path, target, info.Mode().Perm())
		}
	})
}

// copyFile copies a single regular file, applying mode exactly (os.WriteFile applies
// the process umask, so mode is re-asserted with Chmod).
func copyFile(src, dst string, mode fs.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("snapshot: read %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
		return fmt.Errorf("snapshot: write %s: %w", dst, err)
	}
	if err := os.Chmod(dst, mode); err != nil {
		return fmt.Errorf("snapshot: chmod %s: %w", dst, err)
	}
	return nil
}
