package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	// scanInterval is how often the workspace is re-walked for changes.
	// inotify/fsnotify does not deliver events on the virtiofs mount BoxedAi
	// uses for /workspace, so a periodic content scan is the file sensor: it
	// works on every filesystem at the cost of sub-interval granularity. The
	// final host-side workspace manifest/diff remains authoritative for
	// persistent output (DESIGN.md "internal/snapshot"); these live events are
	// the timeline view of what changed while the session ran.
	scanInterval = 2 * time.Second
	// fileDigestCapBytes bounds how much of a file is hashed; DESIGN.md asks
	// for a "content digest (sha256 of the file, capped)" without a size.
	fileDigestCapBytes = 8 * 1024 * 1024
)

// runFileWatcher periodically scans workspacePath and emits file.changed (with
// a capped sha256 content digest) for files that appear or change and
// file.deleted for files that disappear, relative to the previous scan. The
// first scan seeds the baseline silently: pre-existing input files are the
// snapshot, not workspace effects. .git is skipped — its internal churn is not
// a meaningful workspace effect and the final manifest/diff excludes it too.
func runFileWatcher(ctx context.Context, workspacePath string, batch *Batcher) error {
	prev := scanWorkspace(workspacePath) // baseline; no events for the input tree

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cur := scanWorkspace(workspacePath)
			for rel, digest := range cur {
				if prev[rel] != digest {
					batch.Add(newFileChangedEvent(rel, digest))
				}
			}
			for rel := range prev {
				if _, ok := cur[rel]; !ok {
					batch.Add(newFileDeletedEvent(rel))
				}
			}
			prev = cur
		}
	}
}

// scanWorkspace walks workspacePath and returns a map of workspace-relative
// path -> capped sha256 digest for every regular file, skipping .git. Symlinks
// and unreadable files are skipped; this is a best-effort observation sensor,
// not the authoritative manifest.
func scanWorkspace(workspacePath string) map[string]string {
	out := map[string]string{}
	_ = filepath.WalkDir(workspacePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks, devices, sockets
		}
		digest, err := digestFileCapped(path, fileDigestCapBytes)
		if err != nil {
			return nil
		}
		out[relWorkspacePath(workspacePath, path)] = digest
		return nil
	})
	return out
}

// relWorkspacePath returns path relative to workspacePath, falling back to the
// absolute path if it cannot be made relative.
func relWorkspacePath(workspacePath, path string) string {
	rel, err := filepath.Rel(workspacePath, path)
	if err != nil {
		return path
	}
	return rel
}

// digestFileCapped returns the "sha256:<hex>" digest (evidence.SHA256Hex's
// format) of the first limit bytes of path.
func digestFileCapped(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, f, limit); err != nil && err != io.EOF {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
