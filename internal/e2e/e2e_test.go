package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"boxedai/internal/evidence"
	"boxedai/internal/image"
	"boxedai/internal/policy"
	"boxedai/internal/recorder"
	"boxedai/internal/session"
	"boxedai/internal/trustrecord"
	"boxedai/internal/verify"
	"boxedai/internal/view"
	"boxedai/internal/vm"
)

// workloadFile is the file the fake guest writes into the mounted workspace so
// the output manifest and diff are non-empty. Its name is also a stable ASCII
// marker used by the tamper case to flip a byte inside a sealed segment.
const workloadFile = "harness-output.txt"

// fakeGuestVM is an in-process vmController that never boots Lima. Instead of a
// hypervisor it behaves like a REAL guest supervisor: it POSTs evidence batches
// to the live host broker over HTTP with the supervisor bearer token, so the
// full multi-producer recording path (guest_supervisor channel → recorder) is
// exercised end to end. It gets the broker port, supervisor token and workspace
// path from the vm.Config the session builds for it.
type fakeGuestVM struct {
	cfg vm.Config
}

// Start is a no-op: there is no VM to boot.
func (f *fakeGuestVM) Start(context.Context) error { return nil }

// WaitHealthy reports the guest sensor coming up, exactly as the real guest
// agent does on startup (DESIGN.md provisioning step 6), then returns healthy.
// The mechanism is tetragon because this fixture stands in for an undegraded
// session: procfs coverage is a sensor invariant failure by design (verify check 8),
// which would make every clean run of this pipeline INCOMPLETE.
func (f *fakeGuestVM) WaitHealthy(context.Context, time.Duration) error {
	return f.postEvents([]evidence.Event{{
		Name:    evidence.EventSensorStarted,
		Class:   evidence.ClassIntegrity,
		Outcome: evidence.OutcomeSuccess,
		Body:    "guest sensor started",
		Attrs:   map[string]any{"sensor.mechanism": "tetragon"},
	}})
}

// LaunchHarness mutates the mounted workspace (so the diff is non-empty) and
// forwards a realistic guest event batch as the supervisor: a process executed
// with pid/parent/cgroup/exec identity and a tetragon observer, its exit, and a
// workspace file change carrying a content digest. It returns a clean exit code.
func (f *fakeGuestVM) LaunchHarness(context.Context) (int, error) {
	content := []byte("written by the sandboxed workload\n")
	if err := os.WriteFile(filepath.Join(f.cfg.WorkspacePath, workloadFile), content, 0o644); err != nil {
		return 0, fmt.Errorf("fake guest: write workspace file: %w", err)
	}

	batch := []evidence.Event{
		{
			Name:    evidence.EventProcessExecuted,
			Outcome: evidence.OutcomeSuccess,
			Body:    "sh -lc true",
			Attrs: map[string]any{
				evidence.AttrProcessPID:      int64(4242),
				evidence.AttrProcessPPID:     int64(1),
				evidence.AttrProcessCgroupID: "boxedai-session.slice",
				evidence.AttrProcessExecID:   "exec-0001",
				"observer":                   "tetragon",
			},
		},
		{
			Name:    evidence.EventProcessExited,
			Outcome: evidence.OutcomeSuccess,
			Body:    "process exited 0",
			Attrs: map[string]any{
				evidence.AttrProcessPID:    int64(4242),
				evidence.AttrProcessExecID: "exec-0001",
				"process.exit_code":        int64(0),
				"observer":                 "tetragon",
			},
		},
		{
			Name:    evidence.EventFileChanged,
			Outcome: evidence.OutcomeSuccess,
			Body:    "workspace file changed",
			Attrs: map[string]any{
				evidence.AttrContentDigest:  evidence.SHA256Hex(content),
				evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
				"observer":                  "fsnotify",
				"file.path":                 "/workspace/" + workloadFile,
			},
		},
	}
	if err := f.postEvents(batch); err != nil {
		return 0, err
	}
	return 0, nil
}

// Stop is a no-op.
func (f *fakeGuestVM) Stop(context.Context) error { return nil }

// Delete is a no-op.
func (f *fakeGuestVM) Delete(context.Context) error { return nil }

// postEvents submits an evidence batch to the broker's guest ingest route with
// the supervisor bearer token, exactly as the real guest agent would. A non-200
// (or any error emitting) is surfaced so a broken evidence path fails the run
// closed rather than silently losing events.
func (f *fakeGuestVM) postEvents(events []evidence.Event) error {
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return fmt.Errorf("fake guest: marshal events: %w", err)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/v1/events", f.cfg.BrokerPort)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("fake guest: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.cfg.SupervisorToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fake guest: POST /v1/events: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fake guest: broker /v1/events returned %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}

// writeFakeGoldenImage writes a manifest.json + disk.img under
// home/images/<arch> that the real image.Resolve accepts, so runPipeline
// exercises session.Run's actual image-resolution path without booting a real
// bake VM (internal/image.Build) just to produce one.
func writeFakeGoldenImage(t *testing.T, home, arch string) {
	t.Helper()
	dir := filepath.Join(home, "images", arch)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir fake golden image dir: %v", err)
	}
	diskContent := []byte("fake golden disk\n")
	diskPath := filepath.Join(dir, "disk.img")
	if err := os.WriteFile(diskPath, diskContent, 0o644); err != nil {
		t.Fatalf("write fake disk: %v", err)
	}
	sum := sha256.Sum256(diskContent)
	m := image.Manifest{
		Tag:        "boxedai-base-test",
		Arch:       arch,
		BuiltAt:    time.Now().UTC(),
		DiskPath:   diskPath,
		DiskDigest: "sha256:" + hex.EncodeToString(sum[:]),
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal fake manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644); err != nil {
		t.Fatalf("write fake manifest: %v", err)
	}
}

// runPipeline stands up a fresh isolated BOXEDAI_HOME and a tiny fake git repo,
// then drives one full session with the HTTP-driven fake guest injected in place
// of Lima. It returns the finished result; every step of session.Run (policy,
// recorder, broker, snapshot, verify hint, teardown) runs for real.
func runPipeline(t *testing.T) session.Result {
	t.Helper()

	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	// Pin dummy provider keys so resolveUpstreams short-circuits before its
	// device-credential fallback: without these, the test would exec the real
	// macOS `security` binary and read the real ~/.codex/auth.json.
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	// session.Run now resolves the golden image (internal/image) before VM
	// boot; write a fixture manifest+disk the real image.Resolve accepts
	// rather than booting a bake VM just to exercise this pipeline.
	writeFakeGoldenImage(t, home, runtime.GOARCH)

	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "README.md"), "# fixture repo\n")
	writeFile(t, filepath.Join(repo, "src", "main.go"), "package main\n")
	// A minimal .git presence so the workspace looks like a real repo; snapshot
	// records .git presence but never descends into it.
	writeFile(t, filepath.Join(repo, ".git", "HEAD"), "ref: refs/heads/main\n")

	res, err := session.RunWithVMFactory(context.Background(), session.RunOptions{
		Harness:  "exec",
		RepoPath: repo,
		Profile:  policy.ProfileDevelop,
		Cmd:      "true",
	}, func(cfg vm.Config) session.VMController {
		return &fakeGuestVM{cfg: cfg}
	})
	if err != nil {
		t.Fatalf("RunWithVMFactory: %v", err)
	}
	return res
}

// TestEndToEndHostPipeline drives broker auth + recorder sequencing/COSE signing
// + verify + view together, without booting Lima, using the fake guest to cover
// the full multi-producer recording path. It then proves the verifier bites on
// both tampered and truncated evidence.
func TestEndToEndHostPipeline(t *testing.T) {
	res := runPipeline(t)
	dir := res.SessionDir

	// The session sealed cleanly and observed the workspace mutation.
	if res.State != session.StateSealed {
		t.Errorf("State = %q, want %q", res.State, session.StateSealed)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
	if res.FilesChanged != 1 {
		t.Errorf("FilesChanged = %d, want 1 (the file the fake guest wrote)", res.FilesChanged)
	}

	// --- Sealed evidence artifacts exist (DESIGN.md host filesystem layout). ---
	segDir := filepath.Join(dir, "evidence", "segments")
	for _, rel := range []string{
		"segment-000001.otlp",
		"segment-000001.manifest.json",
		"segment-000001.manifest.cose",
	} {
		if _, err := os.Stat(filepath.Join(segDir, rel)); err != nil {
			t.Errorf("expected evidence artifact %s: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, trustrecord.FileName)); err != nil {
		t.Errorf("expected session trust record: %v", err)
	}

	// --- The offline verifier accepts the clean session as LOCAL_ONLY. ---
	rep, err := verify.Verify(dir)
	if err != nil {
		t.Fatalf("verify.Verify: %v", err)
	}
	if rep.Verdict != verify.VerdictLocalOnly {
		t.Fatalf("verdict = %s, want LOCAL_ONLY\n%s", rep.Verdict, rep.String())
	}
	if !rep.Facets.SignatureValid {
		t.Errorf("signature facet = false, want valid signatures")
	}
	if !rep.Facets.ChainValid || !rep.Facets.SequenceContinuous {
		t.Errorf("chain/sequence facets not valid: %+v", rep.Facets)
	}
	if rep.Facets.CloseStatus != "sealed" {
		t.Errorf("close status = %q, want sealed", rep.Facets.CloseStatus)
	}
	if rep.Facets.UngatedActivityCount != 0 {
		t.Errorf("ungated activity = %d, want 0 (no bypass)", rep.Facets.UngatedActivityCount)
	}
	if rep.Facets.TrustRecordStatus != "verified" || !rep.Facets.TrustRecordSignature || !rep.Facets.TrustRecordDerived {
		t.Errorf("trust record facets = %+v, want signed and cross-derived", rep.Facets)
	}
	recordBytes, err := os.ReadFile(filepath.Join(dir, trustrecord.FileName))
	if err != nil {
		t.Fatalf("read trust record: %v", err)
	}
	record, err := trustrecord.Decode(recordBytes)
	if err != nil {
		t.Fatalf("decode trust record: %v", err)
	}
	if len(record.Evidence.SensorMechanisms) != 1 || record.Evidence.SensorMechanisms[0] != "tetragon" {
		t.Errorf("sensor mechanisms = %v, want [tetragon]", record.Evidence.SensorMechanisms)
	}
	if res.Verdict != string(verify.VerdictLocalOnly) {
		t.Errorf("Result.Verdict hint = %q, want %q", res.Verdict, verify.VerdictLocalOnly)
	}

	// --- The view projection renders the guest events with their class badges. ---
	// Rebuild projects the raw segments into SQLite; the process/file events the
	// fake guest reported must land as kernel_observed.
	db, err := view.Rebuild(dir)
	if err != nil {
		t.Fatalf("view.Rebuild: %v", err)
	}
	for _, name := range []string{evidence.EventProcessExecuted, evidence.EventFileChanged} {
		var class string
		if err := db.QueryRow("SELECT class FROM events WHERE name = ?", name).Scan(&class); err != nil {
			db.Close()
			t.Fatalf("projection query for %s: %v", name, err)
		}
		if class != string(evidence.ClassKernelObserved) {
			t.Errorf("event %s projected class = %q, want %q", name, class, evidence.ClassKernelObserved)
		}
	}
	db.Close()

	// Timeline renders one line per event with the short KERNEL badge for the
	// guest-observed process execution and file change.
	var timeline bytes.Buffer
	if err := view.Timeline(dir, view.Filter{}, &timeline); err != nil {
		t.Fatalf("view.Timeline: %v", err)
	}
	out := timeline.String()
	for _, want := range []string{
		"[KERNEL] " + evidence.EventProcessExecuted,
		"[KERNEL] " + evidence.EventFileChanged,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("timeline missing %q\n---\n%s", want, out)
		}
	}

	// --- The workspace diff reflects the file the fake guest mutated. ---
	diffBytes, err := os.ReadFile(filepath.Join(dir, "workspace.diff"))
	if err != nil {
		t.Fatalf("read workspace.diff: %v", err)
	}
	if !strings.Contains(string(diffBytes), workloadFile) {
		t.Errorf("workspace.diff does not mention %s\n---\n%s", workloadFile, diffBytes)
	}

	// --- NEGATIVE: a flipped byte in a sealed segment is caught as tamper. ---
	t.Run("tamper flips a sealed segment byte", func(t *testing.T) {
		td := runPipeline(t)
		otlp := filepath.Join(td.SessionDir, "evidence", "segments", "segment-000001.otlp")
		data, err := os.ReadFile(otlp)
		if err != nil {
			t.Fatalf("read segment: %v", err)
		}
		// Flip one ASCII byte inside the file.changed path attr. The protobuf frame
		// still decodes (same length, valid ASCII) but the recomputed segment digest
		// no longer matches the COSE-signed manifest.
		idx := bytes.Index(data, []byte(workloadFile))
		if idx < 0 {
			t.Fatalf("marker %q not present in segment; cannot mutate deterministically", workloadFile)
		}
		data[idx] = 'H' // 'h' -> 'H'
		if err := os.WriteFile(otlp, data, 0o600); err != nil {
			t.Fatalf("rewrite segment: %v", err)
		}

		rep, err := verify.Verify(td.SessionDir)
		if err != nil {
			t.Fatalf("verify.Verify: %v", err)
		}
		if rep.Verdict != verify.VerdictTamperSuspected {
			t.Fatalf("verdict = %s, want TAMPER_SUSPECTED\n%s", rep.Verdict, rep.String())
		}
		// The mutation is what drives the verdict: the recomputed segment digest no
		// longer matches the signed manifest.
		if checkPassed(rep, "segment-digests") {
			t.Error("segment-digests check should have failed under a flipped byte")
		}
	})

	t.Run("valid signature cannot hide a drifted trust-record claim", func(t *testing.T) {
		td := runPipeline(t)
		path := filepath.Join(td.SessionDir, trustrecord.FileName)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read trust record: %v", err)
		}
		envelope, err := trustrecord.Decode(data)
		if err != nil {
			t.Fatalf("decode trust record: %v", err)
		}
		envelope.Activity.NetworkDenialCount++
		key, err := recorder.LoadOrGenerateKey(filepath.Join(os.Getenv("BOXEDAI_HOME"), "keys"))
		if err != nil {
			t.Fatalf("load recorder key: %v", err)
		}
		if err := trustrecord.Sign(&envelope, key.Priv); err != nil {
			t.Fatalf("re-sign changed trust record: %v", err)
		}
		data, err = json.MarshalIndent(envelope, "", "  ")
		if err != nil {
			t.Fatalf("marshal changed trust record: %v", err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("rewrite trust record: %v", err)
		}
		rep, err := verify.Verify(td.SessionDir)
		if err != nil {
			t.Fatalf("verify.Verify: %v", err)
		}
		if rep.Verdict != verify.VerdictTamperSuspected {
			t.Fatalf("verdict = %s, want TAMPER_SUSPECTED\n%s", rep.Verdict, rep.String())
		}
		if checkPassed(rep, "session-trust-record") {
			t.Error("session-trust-record check should have failed under a changed claim")
		}
		if !rep.Facets.TrustRecordSignature || rep.Facets.TrustRecordDerived || rep.Facets.TrustRecordStatus != "claim_mismatch" {
			t.Errorf("trust record facets = %+v, want valid signature with failed cross-derivation", rep.Facets)
		}
	})

	// --- NEGATIVE: the signed record turns post-seal segment removal into tamper. ---
	t.Run("missing bound final manifest yields tamper", func(t *testing.T) {
		id := runPipeline(t)
		segs := filepath.Join(id.SessionDir, "evidence", "segments")
		// Delete the last sealed segment's manifest + signature, leaving an
		// unresolved (unsealed) tail.
		for _, rel := range []string{"segment-000001.manifest.json", "segment-000001.manifest.cose"} {
			if err := os.Remove(filepath.Join(segs, rel)); err != nil {
				t.Fatalf("remove %s: %v", rel, err)
			}
		}

		rep, err := verify.Verify(id.SessionDir)
		if err != nil {
			t.Fatalf("verify.Verify: %v", err)
		}
		if rep.Verdict != verify.VerdictTamperSuspected {
			t.Fatalf("verdict = %s, want TAMPER_SUSPECTED\n%s", rep.Verdict, rep.String())
		}
		// The surviving evidence still verifies, but the independently signed trust
		// record proves a sealed manifest was present when the session was sealed.
		if !rep.Facets.SignatureValid || !rep.Facets.SequenceContinuous {
			t.Errorf("integrity facets should still hold (truncation, not tamper): %+v", rep.Facets)
		}
		if !containsSubstring(rep.Facets.Messages, "unresolved tail") {
			t.Errorf("expected an unsealed/unresolved-tail note in facets, got %v", rep.Facets.Messages)
		}
	})
}

// containsSubstring reports whether any element of ss contains sub.
func containsSubstring(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// checkPassed reports whether the named verifier check passed in rep.
func checkPassed(rep verify.Report, name string) bool {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c.Passed
		}
	}
	return false
}

// writeFile writes content at path, creating parent directories as needed.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
