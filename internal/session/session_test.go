package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"boxedai/internal/broker"
	"boxedai/internal/evidence"
	"boxedai/internal/image"
	"boxedai/internal/policy"
	"boxedai/internal/trustrecord"
	"boxedai/internal/verify"
	"boxedai/internal/vm"

	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protodelim"
)

// fakeManifest is the golden-image manifest withResolveImage's default fake
// returns: enough shape (a real-looking DiskPath/DiskDigest/Tag) for the
// fields it feeds into recorder.SessionMeta, the session grant, and
// vm.Config.ImagePath to round-trip through Run without touching any real
// $BOXEDAI_HOME/images state.
var fakeManifest = image.Manifest{
	Tag:        "boxedai-base-test",
	Arch:       "test",
	DiskPath:   "/fake/boxedai-image/disk.img",
	DiskDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
}

// withResolveImage swaps resolveImage for fn and restores the real
// implementation when the test ends, mirroring devicecred_test.go's
// withClaudeKeychain/withCodexAuthFile seam pattern — so no test here execs
// the real image.Resolve against real $BOXEDAI_HOME/images state (which is
// never populated in the test environment).
func withResolveImage(t *testing.T, fn func(arch string) (image.Manifest, error)) {
	t.Helper()
	orig := resolveImage
	resolveImage = fn
	t.Cleanup(func() { resolveImage = orig })
}

// fakeVM is a real, in-process vmController that never boots Lima. Start and the
// health gate succeed immediately; LaunchHarness simulates the sandboxed workload
// making a workspace change (so the output manifest and diff are non-trivial) and
// returns a clean exit. It records which lifecycle calls ran so the test can
// assert the orchestration drove the VM as DESIGN.md's session flow requires.
type fakeVM struct {
	cfg                  vm.Config
	launchCancel         context.CancelFunc
	launchErr            error
	exitCode             int
	stopErr              error
	deleteErr            error
	stopContextErr       error
	deleteContextErr     error
	stopContextBounded   bool
	deleteContextBounded bool
	beforeDelete         func()
	emitLifecycle        bool
	hangIngestOnStop     bool
	releaseIngest        func()
	started              bool
	healthy              bool
	launched             bool
	stopped              bool
	deleted              bool
}

func (f *fakeVM) Start(context.Context) error { f.started = true; return nil }

func (f *fakeVM) WaitHealthy(ctx context.Context, _ time.Duration) error {
	f.healthy = true
	if f.emitLifecycle {
		return f.emitEvents(ctx, []evidence.Event{{
			Name:    evidence.EventSensorStarted,
			Time:    time.Now(),
			Class:   evidence.ClassIntegrity,
			Outcome: evidence.OutcomeSuccess,
			Body:    "sensor started: tetragon",
			Attrs: map[string]any{
				"sensor.mechanism": "tetragon",
			},
		}})
	}
	return nil
}

func (f *fakeVM) LaunchHarness(ctx context.Context) (int, error) {
	f.launched = true
	if f.emitLifecycle {
		if err := f.emitProcessLifecycle(ctx); err != nil {
			return -1, err
		}
	}
	// Simulate the harness writing a new file into the mounted workspace.
	_ = os.WriteFile(filepath.Join(f.cfg.WorkspacePath, "harness-output.txt"), []byte("written by workload\n"), 0o644)
	if f.launchCancel != nil {
		f.launchCancel()
	}
	return f.exitCode, f.launchErr
}

func (f *fakeVM) emitProcessLifecycle(ctx context.Context) error {
	events := []evidence.Event{
		{
			Name:    evidence.EventProcessExecuted,
			Time:    time.Now(),
			Class:   evidence.ClassKernelObserved,
			Outcome: evidence.OutcomeSuccess,
			Body:    "exec /bin/true",
			Attrs: map[string]any{
				evidence.AttrProcessPID:    int64(100),
				evidence.AttrProcessPPID:   int64(1),
				evidence.AttrProcessExecID: "test-exec",
				"observer":                 "tetragon",
			},
		},
		{
			Name:    evidence.EventProcessExited,
			Time:    time.Now(),
			Class:   evidence.ClassKernelObserved,
			Outcome: evidence.OutcomeSuccess,
			Body:    "exit pid=100 code=0",
			Attrs: map[string]any{
				evidence.AttrProcessPID:    int64(100),
				evidence.AttrProcessExecID: "test-exec",
				"observer":                 "tetragon",
			},
		},
	}
	return f.emitEvents(ctx, events)
}

func (f *fakeVM) emitEvents(ctx context.Context, events []evidence.Event) error {
	body, err := json.Marshal(struct {
		Events []evidence.Event `json:"events"`
	}{Events: events})
	if err != nil {
		return fmt.Errorf("marshal fake lifecycle: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/events", f.cfg.BrokerPort), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build fake lifecycle request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.cfg.SupervisorToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("submit fake lifecycle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("submit fake lifecycle: status %d", resp.StatusCode)
	}
	return nil
}

func (f *fakeVM) Stop(ctx context.Context) error {
	f.stopped = true
	f.stopContextErr = ctx.Err()
	_, f.stopContextBounded = ctx.Deadline()
	if f.hangIngestOnStop {
		f.startHangingIngest()
	}
	return f.stopErr
}

// startHangingIngest leaves an /v1/events POST in flight whose body never ends, so
// the broker still has an ingest handler running when teardown shuts it down. That is
// the shape of the real failure: a guest final drain still posting while the
// controller wants the broker gone.
func (f *fakeVM) startHangingIngest() {
	body, writer := io.Pipe()
	f.releaseIngest = func() { _ = writer.Close() }
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/events", f.cfg.BrokerPort), body)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+f.cfg.SupervisorToken)
	req.Header.Set("Content-Type", "application/json")
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
	if _, err := writer.Write([]byte(`{"events":[`)); err != nil {
		return
	}
	// The handler has to be reading that body before teardown calls Stop.
	time.Sleep(50 * time.Millisecond)
}

func (f *fakeVM) Delete(ctx context.Context) error {
	f.deleted = true
	f.deleteContextErr = ctx.Err()
	_, f.deleteContextBounded = ctx.Deadline()
	if f.beforeDelete != nil {
		f.beforeDelete()
	}
	return f.deleteErr
}

func primaryCompletionOutcome(t *testing.T, sessionDir string) evidence.Outcome {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(sessionDir, evidenceDirName, "segments", "segment-*.otlp"))
	if err != nil {
		t.Fatalf("glob evidence segments: %v", err)
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open evidence segment: %v", err)
		}
		reader := bufio.NewReader(f)
		for {
			var logs logspb.LogsData
			if err := protodelim.UnmarshalFrom(reader, &logs); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				f.Close()
				t.Fatalf("decode evidence segment: %v", err)
			}
			for _, resourceLogs := range logs.ResourceLogs {
				for _, scopeLogs := range resourceLogs.ScopeLogs {
					for _, record := range scopeLogs.LogRecords {
						if record.EventName != evidence.EventAgentCompleted {
							continue
						}
						for _, attr := range record.Attributes {
							if attr.Key == evidence.AttrAgentOutcome {
								f.Close()
								return evidence.Outcome(attr.Value.GetStringValue())
							}
						}
					}
				}
			}
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close evidence segment: %v", err)
		}
	}
	t.Fatal("primary agent.completed outcome not found")
	return ""
}

// TestRunOrchestration exercises the full session wiring with an injected fake VM:
// no Lima boot, an isolated BOXEDAI_HOME, and a tiny fixture repo. It asserts the
// on-disk artifacts DESIGN.md's layout requires are produced and that the offline
// verifier accepts the evidence with a non-tamper verdict.
func TestRunOrchestration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	// Pin dummy provider keys so resolveUpstreams short-circuits before its
	// device-credential fallback: without these, the test would exec the real
	// macOS `security` binary and read the real ~/.codex/auth.json.
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	withResolveImage(t, func(arch string) (image.Manifest, error) { return fakeManifest, nil })

	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "README.md"), "# fixture repo\n")
	if err := os.MkdirAll(filepath.Join(repo, "src"), 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	writeFile(t, filepath.Join(repo, "src", "main.go"), "package main\n")

	var fake *fakeVM
	r := &Runner{newVM: func(cfg vm.Config) vmController {
		fake = &fakeVM{cfg: cfg, emitLifecycle: true}
		return fake
	}}

	res, err := r.Run(context.Background(), RunOptions{
		Harness:  "exec",
		RepoPath: repo,
		Profile:  policy.ProfileDevelop,
		Cmd:      "true",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Result surface.
	if !strings.HasPrefix(res.SessionID, "bx-") {
		t.Errorf("SessionID = %q, want bx- prefix", res.SessionID)
	}
	if res.SessionDir != SessionDir(res.SessionID) {
		t.Errorf("SessionDir = %q, want %q", res.SessionDir, SessionDir(res.SessionID))
	}
	if res.State != StateSealed {
		t.Errorf("State = %q, want %q", res.State, StateSealed)
	}
	if res.FilesChanged != 1 {
		t.Errorf("FilesChanged = %d, want 1 (the harness-added file)", res.FilesChanged)
	}

	// The VM factory was invoked and every lifecycle stage ran (Delete because
	// KeepVM defaulted false).
	if fake == nil {
		t.Fatal("injected VM factory was never called")
	}
	for name, got := range map[string]bool{
		"Start": fake.started, "WaitHealthy": fake.healthy, "LaunchHarness": fake.launched,
		"Stop": fake.stopped, "Delete": fake.deleted,
	} {
		if !got {
			t.Errorf("fake VM %s was not called", name)
		}
	}

	// DESIGN.md host filesystem layout: the session dir holds these artifacts.
	dir := res.SessionDir
	for _, rel := range []string{
		grantFileName, policyFileName, inputManifestFileName, outputManifestFileName,
		trustrecord.FileName, "workspace.diff",
		filepath.Join(workspaceDirName, "harness-output.txt"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("expected artifact %s: %v", rel, err)
		}
	}

	// At least one sealed evidence segment with its manifest and COSE signature.
	segDir := filepath.Join(dir, evidenceDirName, "segments")
	for _, rel := range []string{
		"segment-000001.otlp", "segment-000001.manifest.json", "segment-000001.manifest.cose",
	} {
		if _, err := os.Stat(filepath.Join(segDir, rel)); err != nil {
			t.Errorf("expected evidence file %s: %v", rel, err)
		}
	}

	// State file persisted as sealed.
	if st, err := LoadState(res.SessionID); err != nil {
		t.Errorf("LoadState: %v", err)
	} else if st != StateSealed {
		t.Errorf("persisted state = %q, want %q", st, StateSealed)
	}

	// The offline verifier accepts the evidence without tamper/bypass.
	rep, err := verify.Verify(dir)
	if err != nil {
		t.Fatalf("verify.Verify: %v", err)
	}
	if rep.Verdict == verify.VerdictTamperSuspected || rep.Verdict == verify.VerdictBypassDetected {
		t.Errorf("verdict = %s (facets: %v), want non-tamper", rep.Verdict, rep.Facets.Messages)
	}
	if rep.Verdict != verify.VerdictLocalOnly {
		t.Errorf("verdict = %s, want %s (clean local session)", rep.Verdict, verify.VerdictLocalOnly)
	}
	if rep.Facets.TrustRecordStatus != "verified" || !rep.Facets.TrustRecordSignature || !rep.Facets.TrustRecordDerived {
		t.Errorf("trust record facets = %+v, want signed and cross-derived", rep.Facets)
	}
	if res.Verdict != string(verify.VerdictLocalOnly) {
		t.Errorf("Result.Verdict hint = %q, want %q", res.Verdict, verify.VerdictLocalOnly)
	}
	if got := primaryCompletionOutcome(t, res.SessionDir); got != evidence.OutcomeSuccess {
		t.Errorf("Primary completion outcome = %q, want %q", got, evidence.OutcomeSuccess)
	}

	// ListSessions surfaces the session with its grant metadata and state.
	sessions, err := ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("ListSessions returned %d sessions, want 1", len(sessions))
	}
	if sessions[0].SessionID != res.SessionID || sessions[0].State != StateSealed || sessions[0].Harness != "exec" {
		t.Errorf("SessionInfo = %+v, want id=%s state=sealed harness=exec", sessions[0], res.SessionID)
	}
	grant, err := readGrant(res.SessionID)
	if err != nil {
		t.Fatalf("readGrant: %v", err)
	}
	if grant.Schema != grantSchema || grant.TrustRecord.Schema != trustrecord.Profile || !grant.TrustRecord.Required {
		t.Errorf("grant trust-record marker = %+v (schema %q), want required %s", grant.TrustRecord, grant.Schema, trustrecord.Profile)
	}
}

func TestRunCancellationStillCleansUpVM(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	withResolveImage(t, func(arch string) (image.Manifest, error) { return fakeManifest, nil })

	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "README.md"), "# fixture repo\n")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var fake *fakeVM
	r := &Runner{newVM: func(cfg vm.Config) vmController {
		fake = &fakeVM{
			cfg:          cfg,
			launchCancel: cancel,
			launchErr:    context.Canceled,
		}
		return fake
	}}

	res, err := r.Run(ctx, RunOptions{
		Harness:  "exec",
		RepoPath: repo,
		Profile:  policy.ProfileDevelop,
		Cmd:      "true",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context cancellation", err)
	}
	if res.State != StateIncomplete {
		t.Errorf("State = %q, want %q", res.State, StateIncomplete)
	}
	if fake == nil || !fake.stopped || !fake.deleted {
		t.Fatalf("fake VM lifecycle = %+v, want Stop and Delete after cancellation", fake)
	}
	if fake.stopContextErr != nil || fake.deleteContextErr != nil {
		t.Errorf("cleanup contexts were already canceled: Stop=%v Delete=%v", fake.stopContextErr, fake.deleteContextErr)
	}
	if !fake.stopContextBounded || !fake.deleteContextBounded {
		t.Errorf("cleanup contexts bounded = Stop:%t Delete:%t, want both true", fake.stopContextBounded, fake.deleteContextBounded)
	}
	if got := primaryCompletionOutcome(t, res.SessionDir); got != evidence.OutcomeInterrupted {
		t.Errorf("Primary completion outcome = %q, want %q", got, evidence.OutcomeInterrupted)
	}
}

func TestRunPrimaryCompletionFailureOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		exitCode  int
		launchErr error
	}{
		{name: "nonzero harness exit", exitCode: 17},
		{name: "launch failure", launchErr: errors.New("launch failed")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("BOXEDAI_HOME", home)
			t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
			t.Setenv("OPENAI_API_KEY", "test-openai-key")
			withResolveImage(t, func(arch string) (image.Manifest, error) { return fakeManifest, nil })

			repo := t.TempDir()
			writeFile(t, filepath.Join(repo, "README.md"), "# fixture repo\n")
			r := &Runner{newVM: func(cfg vm.Config) vmController {
				return &fakeVM{cfg: cfg, exitCode: tt.exitCode, launchErr: tt.launchErr}
			}}

			res, err := r.Run(context.Background(), RunOptions{
				Harness: "exec", RepoPath: repo, Profile: policy.ProfileDevelop, Cmd: "true",
			})
			if tt.launchErr != nil && !errors.Is(err, tt.launchErr) {
				t.Fatalf("Run error = %v, want %v", err, tt.launchErr)
			}
			if tt.launchErr == nil && err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got := primaryCompletionOutcome(t, res.SessionDir); got != evidence.OutcomeFailure {
				t.Errorf("Primary completion outcome = %q, want %q", got, evidence.OutcomeFailure)
			}
		})
	}
}

func TestRunVMStopFailureLeavesSessionIncomplete(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	withResolveImage(t, func(arch string) (image.Manifest, error) { return fakeManifest, nil })

	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "README.md"), "# fixture repo\n")
	wantErr := errors.New("guest drain failed")
	var fake *fakeVM
	r := &Runner{newVM: func(cfg vm.Config) vmController {
		fake = &fakeVM{cfg: cfg, stopErr: wantErr}
		return fake
	}}

	res, err := r.Run(context.Background(), RunOptions{Harness: "exec", RepoPath: repo, Profile: policy.ProfileDevelop, Cmd: "true"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run error = %v, want VM stop failure", err)
	}
	if res.State != StateIncomplete {
		t.Errorf("State = %q, want %q", res.State, StateIncomplete)
	}
	if fake == nil || !fake.stopped || !fake.deleted {
		t.Fatalf("fake VM lifecycle = %+v, want Stop and Delete", fake)
	}
	if _, statErr := os.Stat(filepath.Join(res.SessionDir, trustrecord.FileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("trust record stat error = %v, want absent after failed drain", statErr)
	}
	// The reason has to survive on disk: a session that fails before or during
	// teardown is otherwise attributable only from whatever consumed the CLI's
	// stderr (DESIGN.md "Crash safety").
	breadcrumb, readErr := os.ReadFile(filepath.Join(res.SessionDir, "session.error"))
	if readErr != nil {
		t.Fatalf("read session.error: %v", readErr)
	}
	if !strings.Contains(string(breadcrumb), wantErr.Error()) {
		t.Errorf("session.error = %q, want the failure reason", breadcrumb)
	}
}

// TestRunSealsEvidenceWhenTheBrokerWillNotShutDown is the teardown regression
// guard: a storm-sized guest drain left an ingest handler in flight, `stop broker`
// returned a deadline error, and teardown abandoned the trust record and marked a
// perfectly completed session incomplete. The broker is now force-closed and the
// error only logged — the seal, the record, and the sealed state all still happen.
// It deliberately pays the broker's real shutdown grace once.
func TestRunSealsEvidenceWhenTheBrokerWillNotShutDown(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	withResolveImage(t, func(arch string) (image.Manifest, error) { return fakeManifest, nil })

	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "README.md"), "# fixture repo\n")
	var fake *fakeVM
	r := &Runner{newVM: func(cfg vm.Config) vmController {
		fake = &fakeVM{cfg: cfg, emitLifecycle: true, hangIngestOnStop: true}
		return fake
	}}

	res, err := r.Run(context.Background(), RunOptions{Harness: "exec", RepoPath: repo, Profile: policy.ProfileDevelop, Cmd: "true"})
	if fake != nil && fake.releaseIngest != nil {
		fake.releaseIngest()
	}
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.State != StateSealed {
		t.Errorf("State = %q, want %q despite the broker shutdown", res.State, StateSealed)
	}
	if _, statErr := os.Stat(filepath.Join(res.SessionDir, trustrecord.FileName)); statErr != nil {
		t.Errorf("trust record stat error = %v, want it written despite the broker shutdown", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(res.SessionDir, "session.error")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("session.error stat error = %v, want no error breadcrumb for a sealed session", statErr)
	}
}

func TestRunVMDeleteFailurePersistsOnlyFinalIncompleteState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	withResolveImage(t, func(arch string) (image.Manifest, error) { return fakeManifest, nil })

	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "README.md"), "# fixture repo\n")
	wantErr := errors.New("VM deletion failed")
	stateDuringDelete := State("")
	r := &Runner{newVM: func(cfg vm.Config) vmController {
		return &fakeVM{
			cfg:       cfg,
			deleteErr: wantErr,
			beforeDelete: func() {
				state, stateErr := LoadState(cfg.SessionID)
				if stateErr != nil {
					t.Fatalf("LoadState during VM deletion: %v", stateErr)
				}
				stateDuringDelete = state
			},
		}
	}}

	res, err := r.Run(context.Background(), RunOptions{Harness: "exec", RepoPath: repo, Profile: policy.ProfileDevelop, Cmd: "true"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run error = %v, want VM delete failure", err)
	}
	if res.State != StateIncomplete {
		t.Errorf("State = %q, want %q", res.State, StateIncomplete)
	}
	if stateDuringDelete != StateRunning {
		t.Errorf("state during VM deletion = %q, want %q until cleanup determines the final state", stateDuringDelete, StateRunning)
	}
	if state, stateErr := LoadState(res.SessionID); stateErr != nil {
		t.Fatalf("LoadState: %v", stateErr)
	} else if state != StateIncomplete {
		t.Errorf("persisted state = %q, want %q", state, StateIncomplete)
	}
}

func TestRunPreapprovesGitHubPushBeforeVMStartup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	withResolveImage(t, func(arch string) (image.Manifest, error) { return fakeManifest, nil })
	withGitHubLookups(
		t,
		func(context.Context, string) ([]byte, error) {
			return []byte("org-49461806@github.com:squareup/boxedai.git\n"), nil
		},
		func(context.Context, string) ([]byte, error) {
			return []byte(`{"nameWithOwner":"squareup/boxedai","sshUrl":"org-49461806@github.com:squareup/boxedai.git"}`), nil
		},
	)

	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "README.md"), "# fixture repo\n")
	promptCalls := 0
	approvedBeforeVM := false
	var fake *fakeVM
	r := &Runner{
		approvalPrompt: func(action broker.NormalizedAction) bool {
			promptCalls++
			if fake != nil {
				t.Error("approval prompt ran after VM construction")
			}
			if action.Adapter != "github" || action.Op != "push" || action.Args["repository"] != "squareup/boxedai" {
				t.Errorf("approval action = %+v, want github/push for squareup/boxedai", action)
			}
			approvedBeforeVM = true
			return true
		},
		newVM: func(cfg vm.Config) vmController {
			if !approvedBeforeVM {
				t.Error("VM constructed before GitHub push approval")
			}
			fake = &fakeVM{cfg: cfg}
			return fake
		},
	}

	if _, err := r.Run(context.Background(), RunOptions{
		Harness:  "claude",
		RepoPath: repo,
		Profile:  policy.ProfileDevelop,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if promptCalls != 1 {
		t.Errorf("approval prompt calls = %d, want 1", promptCalls)
	}
}

// TestValidateHarness covers the harness/cmd/HarnessArgs combinations the CLI
// relies on: claude/codex accept passthrough HarnessArgs, exec requires --cmd
// and rejects HarnessArgs (it already has --cmd for scripting).
func TestValidateHarness(t *testing.T) {
	cases := []struct {
		name        string
		harness     string
		cmd         string
		harnessArgs []string
		wantErr     bool
	}{
		{name: "claude with no harness args", harness: "claude", wantErr: false},
		{name: "claude with harness args", harness: "claude", harnessArgs: []string{"-p", "ping pong"}, wantErr: false},
		{name: "codex with harness args", harness: "codex", harnessArgs: []string{"exec", "ping pong"}, wantErr: false},
		{name: "exec with cmd", harness: "exec", cmd: "true", wantErr: false},
		{name: "exec without cmd", harness: "exec", wantErr: true},
		{name: "exec with cmd and harness args", harness: "exec", cmd: "true", harnessArgs: []string{"-p", "ping"}, wantErr: true},
		{name: "unknown harness", harness: "bogus", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHarness(tc.harness, tc.cmd, tc.harnessArgs)
			if tc.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}

func TestClaudeTelemetryDirIsHostOnlySibling(t *testing.T) {
	sessionDir := filepath.Join(t.TempDir(), "session")
	if got, want := claudeTelemetryDir(sessionDir, "claude"), filepath.Join(sessionDir, "claude-telemetry"); got != want {
		t.Errorf("Claude telemetry dir = %q, want %q", got, want)
	}
	if got := claudeTelemetryDir(sessionDir, "codex"); got != "" {
		t.Errorf("Codex telemetry dir = %q, want disabled", got)
	}
	if got, want := codexTelemetryDir(sessionDir, "codex"), filepath.Join(sessionDir, "codex-telemetry"); got != want {
		t.Errorf("codex telemetry dir = %q, want %q", got, want)
	}
	if got := codexTelemetryDir(sessionDir, "claude"); got != "" {
		t.Errorf("claude Codex telemetry dir = %q, want empty", got)
	}
}

func TestDeleteSessionRemovesEntireDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv(homeEnv, home)
	id := "bx-20260810-000000-abcd1234"
	dir := SessionDir(id)
	if err := os.MkdirAll(filepath.Join(dir, "evidence", "segments"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(dir, stateFileName), string(StateSealed))
	writeFile(t, filepath.Join(dir, "evidence", "segments", "segment-000001.otlp"), "otlp")
	writeFile(t, filepath.Join(dir, "workspace.orig", "file.txt"), "content")

	if err := DeleteSession(id); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("session dir still present after delete: stat err = %v", err)
	}
}

func TestDeleteSessionRefusesRunningSession(t *testing.T) {
	home := t.TempDir()
	t.Setenv(homeEnv, home)
	id := "bx-20260810-000000-abcd5678"
	dir := SessionDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(dir, stateFileName), string(StateRunning))

	if err := DeleteSession(id); err == nil {
		t.Fatal("DeleteSession on running session = nil, want refusal")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("running session dir was removed: %v", err)
	}
}

func TestDeleteSessionRejectsTraversalIDs(t *testing.T) {
	t.Setenv(homeEnv, t.TempDir())
	for _, id := range []string{"", ".", "..", "../escape", "a/b"} {
		if err := DeleteSession(id); err == nil {
			t.Errorf("DeleteSession(%q) = nil, want rejection", id)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
