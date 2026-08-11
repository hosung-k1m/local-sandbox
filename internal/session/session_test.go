package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"boxedai/internal/broker"
	"boxedai/internal/image"
	"boxedai/internal/policy"
	"boxedai/internal/verify"
	"boxedai/internal/vm"
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
	DiskDigest: "sha256:test-digest",
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
	stopContextErr       error
	deleteContextErr     error
	stopContextBounded   bool
	deleteContextBounded bool
	started              bool
	healthy              bool
	launched             bool
	stopped              bool
	deleted              bool
}

func (f *fakeVM) Start(context.Context) error { f.started = true; return nil }

func (f *fakeVM) WaitHealthy(context.Context, time.Duration) error { f.healthy = true; return nil }

func (f *fakeVM) LaunchHarness(context.Context) (int, error) {
	f.launched = true
	// Simulate the harness writing a new file into the mounted workspace.
	_ = os.WriteFile(filepath.Join(f.cfg.WorkspacePath, "harness-output.txt"), []byte("written by workload\n"), 0o644)
	if f.launchCancel != nil {
		f.launchCancel()
	}
	return 0, f.launchErr
}

func (f *fakeVM) Stop(ctx context.Context) error {
	f.stopped = true
	f.stopContextErr = ctx.Err()
	_, f.stopContextBounded = ctx.Deadline()
	return nil
}

func (f *fakeVM) Delete(ctx context.Context) error {
	f.deleted = true
	f.deleteContextErr = ctx.Err()
	_, f.deleteContextBounded = ctx.Deadline()
	return nil
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
		fake = &fakeVM{cfg: cfg}
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
		"workspace.diff",
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
	if res.Verdict != string(verify.VerdictLocalOnly) {
		t.Errorf("Result.Verdict hint = %q, want %q", res.Verdict, verify.VerdictLocalOnly)
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
}

// TestRunAbortsOnImageResolveFailure asserts that a resolveImage failure
// aborts Run fail-closed before any VM boot: the fake vmFactory must never be
// invoked (mirroring how TestRunOrchestration asserts the fake VM's lifecycle
// calls), and the error Run returns must wrap resolveImage's error.
func TestRunAbortsOnImageResolveFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")

	wantErr := errors.New("no golden image for arch")
	withResolveImage(t, func(arch string) (image.Manifest, error) { return image.Manifest{}, wantErr })

	var factoryCalled bool
	r := &Runner{newVM: func(cfg vm.Config) vmController {
		factoryCalled = true
		return &fakeVM{cfg: cfg}
	}}

	res, err := r.Run(context.Background(), RunOptions{
		Harness:  "exec",
		RepoPath: t.TempDir(),
		Profile:  policy.ProfileDevelop,
		Cmd:      "true",
	})
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Run error = %v, want it to wrap %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "session:") {
		t.Errorf("Run error = %q, want it wrapped in the session: ... convention", err.Error())
	}
	if factoryCalled {
		t.Error("vmFactory was invoked despite resolveImage failing; Run must abort before VM boot")
	}
	if res.State == StateSealed {
		t.Errorf("State = %q, want anything but sealed on an aborted session", res.State)
	}
}

// TestRunThreadsImagePath asserts that a resolved manifest's DiskPath reaches
// the vm.Config the VM factory is built with, the same way the workspace path
// and tokens do.
func TestRunThreadsImagePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	withResolveImage(t, func(arch string) (image.Manifest, error) { return fakeManifest, nil })

	var fake *fakeVM
	r := &Runner{newVM: func(cfg vm.Config) vmController {
		fake = &fakeVM{cfg: cfg}
		return fake
	}}

	if _, err := r.Run(context.Background(), RunOptions{
		Harness:  "exec",
		RepoPath: t.TempDir(),
		Profile:  policy.ProfileDevelop,
		Cmd:      "true",
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fake == nil {
		t.Fatal("injected VM factory was never called")
	}
	if fake.cfg.ImagePath != fakeManifest.DiskPath {
		t.Errorf("vm.Config.ImagePath = %q, want %q", fake.cfg.ImagePath, fakeManifest.DiskPath)
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
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
