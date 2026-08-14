package cli

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"boxedai/internal/evidence"
	"boxedai/internal/image"
	"boxedai/internal/policy"
	"boxedai/internal/session"
	"boxedai/internal/view"
)

// allSubcommands is every subcommand exposed by the root command.
var allSubcommands = []string{"setup", "doctor", "run", "build-image", "sessions", "view", "diff", "verify", "verify-record", "apply", "stop"}

// `boxedai --help` must list every mandated subcommand.
func TestHelpListsAllSubcommands(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute --help: %v", err)
	}
	got := out.String()
	for _, sub := range allSubcommands {
		if !strings.Contains(got, sub) {
			t.Errorf("help output does not list subcommand %q\n---\n%s", sub, got)
		}
	}
}

func TestRootWebFlagServesDashboard(t *testing.T) {
	var gotAddr string
	var called bool
	restore := serveDashboard
	serveDashboard = func(addr string) error {
		called = true
		gotAddr = addr
		return nil
	}
	t.Cleanup(func() { serveDashboard = restore })

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--web", "--addr", "127.0.0.1:9999"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute --web: %v", err)
	}
	if !called {
		t.Fatal("serveDashboard was not invoked")
	}
	if gotAddr != "127.0.0.1:9999" {
		t.Errorf("addr = %q, want 127.0.0.1:9999", gotAddr)
	}
}

// Flag parsing for `run` must map through cobra to the RunOptions the session
// layer expects. runSession is stubbed so no VM is ever launched.
func TestRunFlagsMapToRunOptions(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want session.RunOptions
	}{
		{
			name: "claude with path, profile, cap and keep-vm",
			args: []string{"run", "claude", "/tmp/repo", "--profile", "restricted", "--cap", "external-write:github", "--keep-vm"},
			want: session.RunOptions{
				Harness:   "claude",
				RepoPath:  "/tmp/repo",
				Profile:   policy.ProfileRestricted,
				ExtraCaps: []string{"external-write:github"},
				KeepVM:    true,
			},
		},
		{
			name: "exec with cmd, default profile, no path",
			args: []string{"run", "exec", "--cmd", "echo hi"},
			want: session.RunOptions{
				Harness: "exec",
				Profile: policy.ProfileDevelop,
				Cmd:     "echo hi",
			},
		},
		{
			name: "codex review with repeated caps",
			args: []string{"run", "codex", "/repo", "--profile", "review", "--cap", "external-write:github", "--cap", "external-write:github"},
			want: session.RunOptions{
				Harness:   "codex",
				RepoPath:  "/repo",
				Profile:   policy.ProfileReview,
				ExtraCaps: []string{"external-write:github", "external-write:github"},
			},
		},
		{
			name: "claude with dash-separated passthrough args",
			args: []string{"run", "claude", "/tmp/repo", "--", "-p", "ping pong"},
			want: session.RunOptions{
				Harness:     "claude",
				RepoPath:    "/tmp/repo",
				Profile:     policy.ProfileDevelop,
				HarnessArgs: []string{"-p", "ping pong"},
			},
		},
		{
			name: "claude with dash-separated passthrough args and no path",
			args: []string{"run", "claude", "--", "-p", "ping pong"},
			want: session.RunOptions{
				Harness:     "claude",
				Profile:     policy.ProfileDevelop,
				HarnessArgs: []string{"-p", "ping pong"},
			},
		},
		{
			name: "codex with fresh remote branch",
			args: []string{"run", "codex", "--repo", "org-49461806@github.com:squareup/boxedai.git", "--branch", "feature"},
			want: session.RunOptions{
				Harness:    "codex",
				Repository: "org-49461806@github.com:squareup/boxedai.git",
				Branch:     "feature",
				Profile:    policy.ProfileDevelop,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got session.RunOptions
			var called bool
			restore := runSession
			runSession = func(_ context.Context, opts session.RunOptions) (session.Result, error) {
				called = true
				got = opts
				return session.Result{SessionID: "bx-test", State: session.StateSealed, Verdict: "LOCAL_ONLY"}, nil
			}
			t.Cleanup(func() { runSession = restore })

			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(tc.args)
			if err := root.Execute(); err != nil {
				t.Fatalf("execute run: %v", err)
			}
			if !called {
				t.Fatal("runSession was never invoked")
			}
			if got.Progress == nil {
				t.Fatal("RunOptions.Progress was not configured")
			}
			got.Progress = nil
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("RunOptions mismatch:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// The exec harness already has --cmd for scripting; dash-separated passthrough
// args must be rejected before runSession is ever invoked.
func TestRunDashArgsRejectedForExecHarness(t *testing.T) {
	var called bool
	restore := runSession
	runSession = func(_ context.Context, opts session.RunOptions) (session.Result, error) {
		called = true
		return session.Result{}, nil
	}
	t.Cleanup(func() { runSession = restore })

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"run", "exec", "--cmd", "echo hi", "--", "extra"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error for exec harness with dash-separated passthrough args")
	}
	if called {
		t.Error("runSession must not be invoked when validation fails")
	}
}

// buildRunOptions validates the harness and profile before any session setup.
func TestBuildRunOptionsValidation(t *testing.T) {
	if _, err := buildRunOptions([]string{"bogus"}, "develop", nil, "", false, "", "", nil); err == nil {
		t.Error("expected error for unknown harness")
	}
	if _, err := buildRunOptions([]string{"claude"}, "bogus", nil, "", false, "", "", nil); err == nil {
		t.Error("expected error for unknown profile")
	}
	if _, err := buildRunOptions([]string{"exec"}, "develop", nil, "true", false, "", "", []string{"-p", "ping"}); err == nil {
		t.Error("expected error for exec harness with passthrough args")
	}
	opts, err := buildRunOptions([]string{"claude"}, "develop", nil, "", false, "", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Harness != "claude" || opts.Profile != policy.ProfileDevelop || opts.RepoPath != "" {
		t.Errorf("unexpected options: %+v", opts)
	}
	opts, err = buildRunOptions([]string{"claude"}, "develop", nil, "", false, "", "", []string{"-p", "ping pong"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts.HarnessArgs) != 2 || opts.HarnessArgs[0] != "-p" || opts.HarnessArgs[1] != "ping pong" {
		t.Errorf("HarnessArgs = %v, want [-p, ping pong]", opts.HarnessArgs)
	}
	if _, err := buildRunOptions([]string{"claude", "."}, "develop", nil, "", false, "remote", "main", nil); err == nil {
		t.Error("expected error when [path] and --repo are combined")
	}
	if _, err := buildRunOptions([]string{"claude"}, "develop", nil, "", false, "", "main", nil); err == nil {
		t.Error("expected error when --branch is used without --repo")
	}
}

// Flag parsing for `build-image` must default --arch to runtime.GOARCH and
// pass an explicit override through unchanged. buildImage is stubbed so no
// bake VM is ever booted.
func TestBuildImageFlagsMapToArch(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantArch string
	}{
		{name: "default arch is runtime.GOARCH", args: []string{"build-image"}, wantArch: runtime.GOARCH},
		{name: "explicit arm64", args: []string{"build-image", "--arch", "arm64"}, wantArch: "arm64"},
		{name: "explicit amd64", args: []string{"build-image", "--arch", "amd64"}, wantArch: "amd64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BOXEDAI_HOME", t.TempDir())
			var gotArch string
			var called bool
			restore := buildImage
			buildImage = func(_ context.Context, arch, extraCAPEM, npmRegistry string) (image.Manifest, error) {
				called = true
				gotArch = arch
				return image.Manifest{Tag: "t", Arch: arch}, nil
			}
			t.Cleanup(func() { buildImage = restore })

			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(tc.args)
			if err := root.Execute(); err != nil {
				t.Fatalf("execute build-image: %v", err)
			}
			if !called {
				t.Fatal("buildImage was never invoked")
			}
			if gotArch != tc.wantArch {
				t.Errorf("arch = %q, want %q", gotArch, tc.wantArch)
			}
		})
	}
}

// An unknown --arch value must be rejected before buildImage is ever invoked.
func TestBuildImageRejectsUnknownArch(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())
	var called bool
	restore := buildImage
	buildImage = func(_ context.Context, arch, extraCAPEM, npmRegistry string) (image.Manifest, error) {
		called = true
		return image.Manifest{}, nil
	}
	t.Cleanup(func() { buildImage = restore })

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"build-image", "--arch", "mips"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error for unknown arch")
	}
	if called {
		t.Error("buildImage must not be invoked when arch validation fails")
	}
}

// Flag parsing for `view` must build the right view.Filter, defaulting to
// hiding process.created noise; viewTimeline is stubbed so no session
// directory is ever read.
func TestViewFlagsMapToFilter(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want view.Filter
	}{
		{
			name: "defaults hide process.created noise",
			args: []string{"view", "bx-test"},
			want: view.Filter{ExcludeNames: []string{evidence.EventProcessCreated}},
		},
		{
			name: "--all disables default noise hiding",
			args: []string{"view", "bx-test", "--all"},
			want: view.Filter{},
		},
		{
			name: "--agent-activity sets the preset instead of ExcludeNames",
			args: []string{"view", "bx-test", "--agent-activity"},
			want: view.Filter{AgentActivity: true},
		},
		{
			name: "--name/--class/--since pass through alongside default hiding",
			args: []string{"view", "bx-test", "--name", "tool.requested", "--class", "harness_observed", "--since", "2026-01-01T00:00:00Z"},
			want: view.Filter{
				Name: "tool.requested", Class: "harness_observed", Since: "2026-01-01T00:00:00Z",
				ExcludeNames: []string{evidence.EventProcessCreated},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got view.Filter
			var called bool
			restore := viewTimeline
			viewTimeline = func(_ string, filter view.Filter, _ io.Writer) error {
				called = true
				got = filter
				return nil
			}
			t.Cleanup(func() { viewTimeline = restore })

			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(tc.args)
			if err := root.Execute(); err != nil {
				t.Fatalf("execute view: %v", err)
			}
			if !called {
				t.Fatal("viewTimeline was never invoked")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Filter mismatch:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// --all and --agent-activity are mutually exclusive: the CLI must reject the
// combination before ever invoking viewTimeline.
func TestViewAllAndAgentActivityMutuallyExclusive(t *testing.T) {
	var called bool
	restore := viewTimeline
	viewTimeline = func(_ string, _ view.Filter, _ io.Writer) error {
		called = true
		return nil
	}
	t.Cleanup(func() { viewTimeline = restore })

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"view", "bx-test", "--all", "--agent-activity"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error for --all combined with --agent-activity")
	}
	if called {
		t.Error("viewTimeline must not be invoked when validation fails")
	}
}
