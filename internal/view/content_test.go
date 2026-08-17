package view

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"boxedai/internal/blobstore"
	"boxedai/internal/evidence"
	"boxedai/internal/policy"
)

// unknownDigest is well-formed (passes blobstore.Path validation) but never
// stored, for exercising "not captured" (404) distinctly from "malformed
// input" (400).
var unknownDigest = "sha256:" + strings.Repeat("0", 64)

// testFileCapturePolicy is the fixture session policy used by most
// /api/filediff success-path tests: an 8MiB cap (matching the guest scanner's
// digest cap, see policy.defaultFileCapture) and ".env*" withheld as a secret.
func testFileCapturePolicy() policy.Policy {
	return policy.Policy{
		FileCapture: policy.FileCapture{
			MaxBytes:    8 << 20,
			SecretGlobs: []string{".env*"},
		},
	}
}

// writeSessionPolicy marshals p as sessionDir's policy.json, the file
// loadCapturePolicy reads.
func writeSessionPolicy(t *testing.T, sessionDir string, p policy.Policy) {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, sessionPolicyFileName), b, 0o600); err != nil {
		t.Fatalf("write %s: %v", sessionPolicyFileName, err)
	}
}

// putBlob stores content in sessionDir's blob store and returns its digest.
func putBlob(t *testing.T, sessionDir string, content []byte) string {
	t.Helper()
	digest := evidence.SHA256Hex(content)
	if err := blobstore.Put(blobstore.Dir(sessionDir), digest, content); err != nil {
		t.Fatalf("blobstore.Put: %v", err)
	}
	return digest
}

// writeBaseline writes relPath's session-start content under
// sessionDir/workspace.orig.
func writeBaseline(t *testing.T, sessionDir, relPath string, content []byte) {
	t.Helper()
	full := filepath.Join(sessionDir, workspaceOrigDirName, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatalf("mkdir baseline parent for %s: %v", relPath, err)
	}
	if err := os.WriteFile(full, content, 0o600); err != nil {
		t.Fatalf("write baseline %s: %v", relPath, err)
	}
}

// serveHTTP runs one request against mux and returns the recorded response,
// the common shape every case below needs regardless of method or outcome.
func serveHTTP(mux *http.ServeMux, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

// --- /api/blob, single-session viewer mux ---

func TestServeBlobReturnsStoredContent(t *testing.T) {
	sessionDir := t.TempDir()
	content := []byte("package main\n\nfunc main() {}\n")
	digest := putBlob(t, sessionDir, content)

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/blob?digest="+digest)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Errorf("body = %q, want %q", rec.Body.Bytes(), content)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestServeBlobRejectsMalformedDigest(t *testing.T) {
	rec := serveHTTP(newWebMux(t.TempDir()), http.MethodGet, "/api/blob?digest=not-a-digest")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeBlobReturnsNotFoundForUnknownDigest(t *testing.T) {
	rec := serveHTTP(newWebMux(t.TempDir()), http.MethodGet, "/api/blob?digest="+unknownDigest)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeBlobReturnsServerErrorForCorruptBlob(t *testing.T) {
	sessionDir := t.TempDir()
	digest := putBlob(t, sessionDir, []byte("original content"))
	blobPath, err := blobstore.Path(blobstore.Dir(sessionDir), digest)
	if err != nil {
		t.Fatalf("blobstore.Path: %v", err)
	}
	if err := os.WriteFile(blobPath, []byte("different bytes that do not hash to the digest"), 0o600); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/blob?digest="+digest)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeBlobRejectsNonGET(t *testing.T) {
	rec := serveHTTP(newWebMux(t.TempDir()), http.MethodPost, "/api/blob?digest="+unknownDigest)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
}

// --- /api/filediff, single-session viewer mux ---

func TestServeFileDiffModifiedFile(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, testFileCapturePolicy())
	v1 := []byte("line one\nline two\n")
	v2 := []byte("line one\nline TWO changed\n")
	fromDigest := putBlob(t, sessionDir, v1)
	toDigest := putBlob(t, sessionDir, v2)

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=src/main.go&from="+fromDigest+"&to="+toDigest)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out fileDiffResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Path != "src/main.go" || out.From != fromDigest || out.To != toDigest {
		t.Errorf("response = %+v, want path/from/to echoed back", out)
	}
	for _, want := range []string{"a/src/main.go", "b/src/main.go", "-line two", "+line TWO changed"} {
		if !strings.Contains(out.Diff, want) {
			t.Errorf("diff missing %q; got:\n%s", want, out.Diff)
		}
	}
}

func TestServeFileDiffBaselineAgainstBlob(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, testFileCapturePolicy())
	writeBaseline(t, sessionDir, "README.md", []byte("original\n"))
	toDigest := putBlob(t, sessionDir, []byte("changed\n"))

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=README.md&from=baseline&to="+toDigest)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out fileDiffResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, want := range []string{"a/README.md", "b/README.md", "-original", "+changed"} {
		if !strings.Contains(out.Diff, want) {
			t.Errorf("diff missing %q; got:\n%s", want, out.Diff)
		}
	}
}

// TestServeFileDiffNewFileNoBaselineEntry covers a path created during the
// session: workspace.orig exists (populated at session start) but has no
// entry for this particular path, so readBaseline's root.Open must treat that
// as "no baseline" rather than an error, rendering an all-additions diff.
func TestServeFileDiffNewFileNoBaselineEntry(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, testFileCapturePolicy())
	writeBaseline(t, sessionDir, "unrelated.txt", []byte("pre-existing\n"))
	toDigest := putBlob(t, sessionDir, []byte("brand new content\n"))

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=new/file.go&from=baseline&to="+toDigest)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out fileDiffResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(out.Diff, "+brand new content") {
		t.Errorf("diff missing addition line; got:\n%s", out.Diff)
	}
}

// TestServeFileDiffNewFileNoWorkspaceOrigDir is the other half of the "new
// file" shape: a session directory with no workspace.orig at all (readBaseline's
// os.OpenRoot branch, distinct from the entry-missing branch above) must also
// render as a plain addition rather than failing.
func TestServeFileDiffNewFileNoWorkspaceOrigDir(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, testFileCapturePolicy())
	toDigest := putBlob(t, sessionDir, []byte("brand new content\n"))

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=new/file.go&from=baseline&to="+toDigest)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out fileDiffResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(out.Diff, "+brand new content") {
		t.Errorf("diff missing addition line; got:\n%s", out.Diff)
	}
}

func TestServeFileDiffIdenticalContentYieldsEmptyDiff(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, testFileCapturePolicy())
	digest := putBlob(t, sessionDir, []byte("unchanged content\n"))

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=same.txt&from="+digest+"&to="+digest)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out fileDiffResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Diff != "" {
		t.Errorf("diff = %q, want empty for identical content on both sides", out.Diff)
	}
}

func TestServeFileDiffRejectsSecretPath(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, testFileCapturePolicy()) // SecretGlobs: [".env*"]

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=.env&from=baseline&to=empty")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeFileDiffRejectsWhenNoFileCapturePolicy(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, policy.Policy{}) // zero-value FileCapture: MaxBytes 0

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=README.md&from=baseline&to=empty")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeFileDiffBaselineExceedsCapReturnsUnprocessable(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, policy.Policy{FileCapture: policy.FileCapture{MaxBytes: 4}})
	writeBaseline(t, sessionDir, "big.txt", []byte("this baseline is well over four bytes"))
	toDigest := putBlob(t, sessionDir, []byte("new"))

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=big.txt&from=baseline&to="+toDigest)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeFileDiffUnknownToDigestReturnsNotFound(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, testFileCapturePolicy())

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=README.md&from=baseline&to="+unknownDigest)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeFileDiffRejectsMissingPath(t *testing.T) {
	rec := serveHTTP(newWebMux(t.TempDir()), http.MethodGet, "/api/filediff?from=baseline&to=empty")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeFileDiffRejectsTraversalPath(t *testing.T) {
	rec := serveHTTP(newWebMux(t.TempDir()), http.MethodGet, "/api/filediff?path=../x&from=baseline&to=empty")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeFileDiffRejectsBadFromVocabulary(t *testing.T) {
	rec := serveHTTP(newWebMux(t.TempDir()), http.MethodGet, "/api/filediff?path=README.md&from=not-a-digest&to=empty")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeFileDiffRejectsBadToVocabulary(t *testing.T) {
	rec := serveHTTP(newWebMux(t.TempDir()), http.MethodGet, "/api/filediff?path=README.md&from=baseline&to=not-a-digest")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServeFileDiffRejectsNonGET(t *testing.T) {
	rec := serveHTTP(newWebMux(t.TempDir()), http.MethodPost, "/api/filediff?path=README.md&from=baseline&to=empty")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
}

// TestServeFileDiffBaselineSymlinkEscapeIsRejected is the regression guard for
// readBaseline's os.OpenRoot use: workspace.orig preserves symlinks verbatim
// from the snapshot, so a link planted (or landing) inside it that points
// outside the session directory must not let a "baseline" diff read arbitrary
// host content. os.Root refuses to follow a symlink that escapes its root with
// an error distinct from fs.ErrNotExist, so readBaseline's generic err-path
// answers 500 rather than quietly resolving external content as 200.
func TestServeFileDiffBaselineSymlinkEscapeIsRejected(t *testing.T) {
	sessionDir := t.TempDir()
	writeSessionPolicy(t, sessionDir, testFileCapturePolicy())

	outside := t.TempDir()
	secretContent := []byte("outside secret content, must never be served")
	if err := os.WriteFile(filepath.Join(outside, "file"), secretContent, 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	origDir := filepath.Join(sessionDir, workspaceOrigDirName)
	if err := os.MkdirAll(origDir, 0o700); err != nil {
		t.Fatalf("mkdir workspace.orig: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(origDir, "escape")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	toDigest := putBlob(t, sessionDir, []byte("new content\n"))

	rec := serveHTTP(newWebMux(sessionDir), http.MethodGet, "/api/filediff?path=escape/file&from=baseline&to="+toDigest)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (os.OpenRoot escape guard); body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), string(secretContent)) {
		t.Errorf("response leaked content from outside the session directory: %s", rec.Body.String())
	}
}

// --- dashboard mux: id-resolution (querySessionResolver) ---
//
// The dashboard's resolver differs from the single-session viewer's only in
// how it finds sessionDir (an ?id= query parameter, validated and joined
// under session.SessionDir, vs. a directory fixed at server-start), so these
// cases exercise resolution itself rather than repeating the full
// blob/filediff behavior matrix above. They reuse the same
// BOXEDAI_HOME-pointed-at-a-temp-dir mechanism the existing dashboard tests
// in view_test.go already use for session.SessionDir to resolve into a temp
// directory.

func TestDashboardServeBlobResolvesSessionByID(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	id := "bx-20260812-000000-cccc4444"
	dir := filepath.Join(home, "sessions", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	content := []byte("dashboard-resolved blob content\n")
	digest := putBlob(t, dir, content)

	rec := serveHTTP(newDashboardMux(), http.MethodGet, "/api/blob?id="+id+"&digest="+digest)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Errorf("body = %q, want %q", rec.Body.Bytes(), content)
	}
}

func TestDashboardServeBlobRejectsInvalidSessionID(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())
	rec := serveHTTP(newDashboardMux(), http.MethodGet, "/api/blob?id=not-a-session&digest="+unknownDigest)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardServeBlobReturnsNotFoundForUnknownSession(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())
	rec := serveHTTP(newDashboardMux(), http.MethodGet, "/api/blob?id=bx-20260101-000000-deadbeef&digest="+unknownDigest)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardServeFileDiffResolvesSessionByID(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	id := "bx-20260812-000000-dddd5555"
	dir := filepath.Join(home, "sessions", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	writeSessionPolicy(t, dir, testFileCapturePolicy())
	writeBaseline(t, dir, "README.md", []byte("old\n"))
	toDigest := putBlob(t, dir, []byte("new\n"))

	rec := serveHTTP(newDashboardMux(), http.MethodGet, "/api/filediff?id="+id+"&path=README.md&from=baseline&to="+toDigest)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var out fileDiffResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(out.Diff, "-old") || !strings.Contains(out.Diff, "+new") {
		t.Errorf("diff missing expected +/- lines; got:\n%s", out.Diff)
	}
}
