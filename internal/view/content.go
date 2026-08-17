package view

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"boxedai/internal/blobstore"
	"boxedai/internal/policy"
	"boxedai/internal/session"
	"boxedai/internal/snapshot"
)

// Session-directory layout this file reads. Both names are mirrored from
// internal/session (run.go's workspaceOrigDirName and policyFileName) rather than
// imported, for the same reason collectProofSegments knows "evidence/segments"
// without asking internal/recorder: the viewer is an independent reader of a
// session directory, and these are stable on-disk layout names, not an API.
const (
	// workspaceOrigDirName holds the pristine copy of the workspace taken at
	// session start. It is the only source for a file's pre-session content —
	// there is no file.changed event, and therefore no captured blob, for the
	// state a file was already in when the session began.
	workspaceOrigDirName = "workspace.orig"
	// sessionPolicyFileName is the resolved policy the session wrote at start.
	// Its canonical-JSON digest is the audit.policy.digest stamped on every
	// record, which is what makes the file — rather than any viewer-side default
	// — the authority on what this session consented to have served back.
	sessionPolicyFileName = "policy.json"
)

const (
	// baselineSelector is the from= value asking for the file as it stood at
	// session start (read out of workspace.orig).
	baselineSelector = "baseline"
	// emptySelector is the to= value asking for no content at all, which is how a
	// deletion renders: captured content diffed against nothing.
	emptySelector = "empty"
)

// fileDiffResponse is the JSON document served at /api/filediff: the request
// echoed back beside the rendered diff. Echoing path/from/to lets a client that
// fired several diffs concurrently match each response to the row it belongs to
// without tracking request order.
type fileDiffResponse struct {
	Path string `json:"path"`
	From string `json:"from"`
	To   string `json:"to"`
	Diff string `json:"diff"`
}

// sessionResolver yields the session directory a content request applies to. The
// two muxes disagree on where that comes from — the single-session viewer was
// pointed at one directory when it started, the dashboard takes an ?id= — so the
// handlers below take resolution as a function and are otherwise identical. A
// resolver returning ok=false has already written its own error response.
type sessionResolver func(http.ResponseWriter, *http.Request) (sessionDir string, ok bool)

// fixedSessionResolver is the single-session viewer's resolver: the directory was
// chosen by the operator who started the server, so there is no id parameter to
// honor and nothing to validate.
func fixedSessionResolver(sessionDir string) sessionResolver {
	return func(http.ResponseWriter, *http.Request) (string, bool) { return sessionDir, true }
}

// querySessionResolver is the dashboard's resolver. It mirrors /api/session
// exactly — the same isSessionID check, the same "missing or not a directory is a
// 404" behavior — so a content request against a deleted session fails the same
// way that session's timeline request does, and an id that is not a session id
// never reaches session.SessionDir.
func querySessionResolver(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.URL.Query().Get("id")
	if !isSessionID(id) {
		http.Error(w, "view: missing or invalid session id", http.StatusBadRequest)
		return "", false
	}
	sessionDir := session.SessionDir(id)
	info, err := os.Lstat(sessionDir)
	if os.IsNotExist(err) || err == nil && !info.IsDir() {
		http.NotFound(w, r)
		return "", false
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("view: inspect session: %v", err), http.StatusInternalServerError)
		return "", false
	}
	return sessionDir, true
}

// registerContentRoutes mounts the two workload-content endpoints on mux, which
// both the single-session viewer and the dashboard serve (they differ only in
// resolve).
//
// These are the one part of the API that hands back workload bytes rather than
// evidence metadata, so both are GET-only, both answer no-store, and neither reads
// anything the session's own capture policy declined to keep.
func registerContentRoutes(mux *http.ServeMux, resolve sessionResolver) {
	mux.HandleFunc("/api/blob", func(w http.ResponseWriter, r *http.Request) {
		serveBlob(w, r, resolve)
	})
	mux.HandleFunc("/api/filediff", func(w http.ResponseWriter, r *http.Request) {
		serveFileDiff(w, r, resolve)
	})
}

// serveBlob answers GET /api/blob?digest=sha256:<64hex> with one captured blob's
// raw bytes.
//
// The response is deliberately opaque: application/octet-stream plus
// X-Content-Type-Options: nosniff, so a browser can never be talked into rendering
// captured workload content as HTML or script inside the viewer's own origin. It
// is also no-store — this is the content of files from someone's workspace, and it
// must not outlive the session directory in a shared proxy or an on-disk browser
// cache.
func serveBlob(w http.ResponseWriter, r *http.Request, resolve sessionResolver) {
	if r.Method != http.MethodGet {
		http.Error(w, "view: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionDir, ok := resolve(w, r)
	if !ok {
		return
	}

	digest := r.URL.Query().Get("digest")
	dir := blobstore.Dir(sessionDir)
	// blobstore.Path is the traversal guard for the only user-supplied value here:
	// it accepts nothing but "sha256:" plus 64 lowercase hex, which cannot contain
	// a separator, a "..", or a rooted prefix. Calling it up front is what
	// separates "that is not a digest" (the caller's mistake, 400) from "no such
	// blob" (404) — blobstore.Get alone folds both into one error.
	if _, err := blobstore.Path(dir, digest); err != nil {
		http.Error(w, fmt.Sprintf("view: %v", err), http.StatusBadRequest)
		return
	}
	content, err := blobstore.Get(dir, digest)
	if errors.Is(err, fs.ErrNotExist) {
		// Expected, not exceptional: the capture policy declines files (secret,
		// oversized, excluded directory) whose file.changed events still carry a
		// digest, so a client can legitimately hold a digest nothing ever stored.
		http.Error(w, "view: blob not captured", http.StatusNotFound)
		return
	}
	if err != nil {
		// The dominant case is the one blobstore.Get exists to catch: bytes that
		// no longer hash to the name they are filed under. Its message already
		// names the corruption (expected vs. got), so pass it through rather than
		// flattening it into something less useful.
		http.Error(w, fmt.Sprintf("view: blob content is corrupt or unreadable: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(content)
}

// serveFileDiff answers GET /api/filediff?path=&from=&to= with a unified diff
// between two versions of one workspace file, as JSON.
//
// The two sides are selected from closed vocabularies rather than free-form
// locations: from is "baseline" (the session-start copy) or a blob digest, to is
// "empty" (deleted) or a blob digest. Everything a client can ask for is therefore
// either content the session already captured under its own policy, or content
// that policy is re-checked against here before it is read.
func serveFileDiff(w http.ResponseWriter, r *http.Request, resolve sessionResolver) {
	if r.Method != http.MethodGet {
		http.Error(w, "view: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionDir, ok := resolve(w, r)
	if !ok {
		return
	}

	query := r.URL.Query()
	relPath := query.Get("path")
	from := query.Get("from")
	to := query.Get("to")
	if err := validateRelPath(relPath); err != nil {
		http.Error(w, fmt.Sprintf("view: %v", err), http.StatusBadRequest)
		return
	}
	blobDir := blobstore.Dir(sessionDir)
	if err := validateSelector("from", from, baselineSelector, blobDir); err != nil {
		http.Error(w, fmt.Sprintf("view: %v", err), http.StatusBadRequest)
		return
	}
	if err := validateSelector("to", to, emptySelector, blobDir); err != nil {
		http.Error(w, fmt.Sprintf("view: %v", err), http.StatusBadRequest)
		return
	}

	capture, err := loadCapturePolicy(sessionDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("view: %v", err), http.StatusInternalServerError)
		return
	}
	// A policy with no size cap is a session recorded before content capture
	// existed (or one that ran without it). It never agreed to have workspace
	// content served back, yet its workspace.orig is sitting on disk all the same
	// — so refusing here is what keeps a baseline diff from reading the pristine
	// copy of a session that predates the contract.
	if capture.MaxBytes == 0 {
		http.Error(w, "view: session has no file-capture policy", http.StatusForbidden)
		return
	}
	// Capture withheld this file's bytes from the blob store, but workspace.orig
	// still holds its session-start copy. Without this check a "baseline" diff
	// would hand back the very .env or private key the capture policy refused to
	// keep: withholding only counts if it also holds on the read side.
	if capture.Secret(relPath) {
		http.Error(w, "view: content withheld by policy", http.StatusForbidden)
		return
	}

	fromContent, status, err := resolveDiffSide(sessionDir, capture, relPath, from)
	if err != nil {
		http.Error(w, fmt.Sprintf("view: %v", err), status)
		return
	}
	toContent, status, err := resolveDiffSide(sessionDir, capture, relPath, to)
	if err != nil {
		http.Error(w, fmt.Sprintf("view: %v", err), status)
		return
	}

	diff, err := snapshot.DiffContents(relPath, fromContent, toContent)
	if err != nil {
		http.Error(w, fmt.Sprintf("view: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// The diff body quotes both versions of the file line by line, so it is every
	// bit as sensitive as the blobs it was built from and gets the same no-store.
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(fileDiffResponse{Path: relPath, From: from, To: to, Diff: diff}); err != nil {
		http.Error(w, fmt.Sprintf("view: encode response: %v", err), http.StatusInternalServerError)
	}
}

// validateRelPath checks the path parameter before anything touches the disk with
// it. The contract is a workspace-relative, slash-separated path — the same shape
// file.changed events carry and policy.FileCapture.Secret matches against — so a
// backslash is rejected outright rather than guessed at, and filepath.IsLocal must
// accept the host-separator form. That rules out absolute paths, "..", and (on
// Windows) reserved device names, leaving a path that provably stays under
// whichever directory it is later joined to.
func validateRelPath(relPath string) error {
	if relPath == "" {
		return errors.New("path is required")
	}
	if strings.Contains(relPath, `\`) {
		return fmt.Errorf("path %q must be slash-separated", relPath)
	}
	if !filepath.IsLocal(filepath.FromSlash(relPath)) {
		return fmt.Errorf("path %q must be workspace-relative", relPath)
	}
	return nil
}

// validateSelector checks one side's selector against its exact vocabulary: that
// side's own keyword, or a blob digest. The vocabularies are closed sets, so
// anything else is a client bug and never a lookup worth attempting — and running
// the digest through blobstore.Path here means a malformed one is a 400 rather
// than a 404 for a blob that could not have existed under that name.
func validateSelector(param, value, keyword, blobDir string) error {
	if value == keyword {
		return nil
	}
	if _, err := blobstore.Path(blobDir, value); err != nil {
		return fmt.Errorf("%s must be %q or a blob digest: %w", param, keyword, err)
	}
	return nil
}

// loadCapturePolicy reads the policy the session wrote at start and returns its
// file-capture rules.
//
// A plain json.Unmarshal is right here: this is a gate on what may be served, not
// a digest computation, and whether the file still matches the attested policy
// digest is internal/verify's question. An unreadable or unparsable policy is a
// hard failure rather than a fallback to defaults — serving content under rules
// the session never agreed to is exactly the outcome this gate exists to prevent.
func loadCapturePolicy(sessionDir string) (policy.FileCapture, error) {
	b, err := os.ReadFile(filepath.Join(sessionDir, sessionPolicyFileName))
	if err != nil {
		return policy.FileCapture{}, fmt.Errorf("read session policy: %w", err)
	}
	var p policy.Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return policy.FileCapture{}, fmt.Errorf("decode session policy: %w", err)
	}
	return p.FileCapture, nil
}

// resolveDiffSide turns one already-validated selector into the bytes to diff,
// returning the HTTP status to answer with when it cannot. The three cases are the
// whole vocabulary: the empty keyword is no bytes at all, the baseline keyword is
// the session-start copy, and anything else is a digest validation already proved
// well-formed.
func resolveDiffSide(sessionDir string, capture policy.FileCapture, relPath, selector string) ([]byte, int, error) {
	switch selector {
	case emptySelector:
		return nil, 0, nil
	case baselineSelector:
		return readBaseline(sessionDir, capture.MaxBytes, relPath)
	default:
		content, err := blobstore.Get(blobstore.Dir(sessionDir), selector)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, http.StatusNotFound, errors.New("blob not captured")
		}
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("blob content is corrupt or unreadable: %w", err)
		}
		return content, 0, nil
	}
}

// readBaseline reads relPath out of the session's pristine session-start copy of
// the workspace, bounded to the capture policy's size cap.
//
// The read goes through os.Root rather than a bare filepath.Join: relPath is
// caller-supplied, and validateRelPath settles the literal string while saying
// nothing about symlinks, which workspace.orig preserves verbatim from the
// snapshot. Rooting the open is what makes "workspace-relative" true of the bytes
// actually read and not merely of the string that was asked for.
//
// A missing file is not an error. A path created during the session has no
// session-start version, and empty content is the honest answer: the diff renders
// as a new file, which is what happened. The same goes for a session directory
// with no workspace.orig at all.
func readBaseline(sessionDir string, maxBytes int64, relPath string) ([]byte, int, error) {
	root, err := os.OpenRoot(filepath.Join(sessionDir, workspaceOrigDirName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("open workspace baseline: %w", err)
	}
	defer root.Close()

	f, err := root.Open(filepath.FromSlash(relPath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("read workspace baseline: %w", err)
	}
	defer f.Close()

	// Read one byte past the cap so an oversized baseline is detected rather than
	// silently truncated: half a file rendered as a diff would misrepresent the
	// change, and the cap is there precisely because content beyond it is content
	// no recorded digest attests.
	content, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("read workspace baseline: %w", err)
	}
	if int64(len(content)) > maxBytes {
		return nil, http.StatusUnprocessableEntity, errors.New("baseline exceeds capture size cap")
	}
	return content, 0, nil
}
