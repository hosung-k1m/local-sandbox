package vm

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"boxedai/internal/policy"
)

func testConfig(t *testing.T, writable bool) Config {
	t.Helper()
	return Config{
		SessionID:       "bx-20260810-193004-a1b2c3d4",
		SessionDir:      t.TempDir(),
		WorkspacePath:   "/Users/tester/.boxedai/sessions/bx-test/workspace",
		Writable:        writable,
		BrokerHost:      "host.lima.internal",
		BrokerPort:      41830,
		WorkloadToken:   "workload-token",
		SupervisorToken: "supervisor-token",
		Harness:         "claude",
		Limits:          policy.Limits{MemoryMax: "8G", CPUQuota: "400%", TasksMax: 512},
		ImagePath:       "/Users/tester/.boxedai/images/golden-arm64.img",
		Arch:            "arm64",
	}
}

func testBakeConfig(t *testing.T) BakeConfig {
	t.Helper()
	return BakeConfig{
		Arch:       "arm64",
		SessionDir: t.TempDir(),
	}
}

func TestStartAndWaitForBootUsesShellWhenLimaStartTimesOut(t *testing.T) {
	var calls [][]string
	run := func(ctx context.Context, _, _ io.Writer, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		switch args[0] {
		case "start":
			if _, ok := ctx.Deadline(); !ok {
				t.Errorf("limactl start context has no deadline")
			}
			return errors.New("Lima readiness wait timed out")
		case "shell":
			return nil
		default:
			t.Fatalf("unexpected limactl command: %v", args)
			return nil
		}
	}

	if err := startAndWaitForBoot(context.Background(), "test-instance", time.Second, run, io.Discard, io.Discard); err != nil {
		t.Fatalf("startAndWaitForBoot: %v", err)
	}

	want := [][]string{
		{"start", "--timeout=15s", "test-instance"},
		{"shell", "test-instance", "--", "test", "-f", "/run/lima-boot-done"},
	}
	if len(calls) != len(want) {
		t.Fatalf("limactl calls = %v, want %v", calls, want)
	}
	for i := range want {
		if strings.Join(calls[i], "\x00") != strings.Join(want[i], "\x00") {
			t.Errorf("limactl call %d = %v, want %v", i, calls[i], want[i])
		}
	}
}

func TestWaitForBootDoneRetriesPlainShell(t *testing.T) {
	probes := 0
	run := func(ctx context.Context, _, _ io.Writer, args ...string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Errorf("limactl shell context has no deadline")
		}
		want := []string{"shell", "test-instance", "--", "test", "-f", "/run/lima-boot-done"}
		if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("limactl shell args = %v, want %v", args, want)
		}
		probes++
		if probes == 1 {
			return errors.New("guest not ready")
		}
		return nil
	}

	if err := waitForBootDone(context.Background(), "test-instance", time.Second, time.Millisecond, run); err != nil {
		t.Fatalf("waitForBootDone: %v", err)
	}
	if probes != 2 {
		t.Errorf("shell probes = %d, want 2", probes)
	}
}

func TestWaitForBootDoneIsBounded(t *testing.T) {
	run := func(context.Context, io.Writer, io.Writer, ...string) error {
		return errors.New("guest not ready")
	}

	err := waitForBootDone(context.Background(), "test-instance", 5*time.Millisecond, time.Millisecond, run)
	if err == nil {
		t.Fatal("waitForBootDone returned nil, want timeout error")
	}
	if !strings.Contains(err.Error(), "Lima boot marker not ready after 5ms") {
		t.Errorf("waitForBootDone error = %q, want boot marker timeout", err)
	}
}

func TestWaitForGuestHealthyRequiresProcessSensorReadiness(t *testing.T) {
	readinessProbes := 0
	run := func(_ context.Context, stdout, _ io.Writer, args ...string) error {
		switch args[3] {
		case "systemctl":
			_, _ = io.WriteString(stdout, "active\n")
			return nil
		case "test":
			readinessProbes++
			if readinessProbes == 1 {
				return errors.New("process sensor not ready")
			}
			want := []string{"shell", "test-instance", "--", "test", "-f", guestProcessSensorReadyPath}
			if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
				t.Errorf("readiness probe args = %v, want %v", args, want)
			}
			return nil
		default:
			t.Fatalf("unexpected health probe: %v", args)
			return nil
		}
	}

	if err := waitForGuestHealthy(context.Background(), "test-instance", time.Second, time.Millisecond, run); err != nil {
		t.Fatalf("waitForGuestHealthy: %v", err)
	}
	if readinessProbes != 2 {
		t.Fatalf("readiness probes = %d, want 2", readinessProbes)
	}
}

func TestWaitForGuestHealthyRequiresActiveTetragon(t *testing.T) {
	readinessProbes := 0
	run := func(_ context.Context, stdout, _ io.Writer, args ...string) error {
		if args[3] == "test" {
			readinessProbes++
			return nil
		}
		if args[len(args)-1] == "boxedai-guest-agent" {
			_, _ = io.WriteString(stdout, "active\n")
		} else {
			_, _ = io.WriteString(stdout, "inactive\n")
		}
		return nil
	}

	err := waitForGuestHealthy(context.Background(), "test-instance", 5*time.Millisecond, time.Millisecond, run)
	if err == nil {
		t.Fatal("waitForGuestHealthy succeeded with inactive Tetragon")
	}
	if readinessProbes != 0 {
		t.Fatalf("readiness probes = %d, want 0 while Tetragon is inactive", readinessProbes)
	}
}

func TestHarnessUnitBindsToAuthoritativeServices(t *testing.T) {
	vm := &VM{Cfg: testConfig(t, true)}
	argv, err := vm.harnessArgv(false)
	if err != nil {
		t.Fatalf("harnessArgv: %v", err)
	}
	joined := strings.Join(argv, "\n")
	for _, want := range []string{
		"--property=BindsTo=tetragon.service boxedai-guest-agent.service",
		"--property=After=tetragon.service boxedai-guest-agent.service",
		"--property=ConditionPathExists=" + guestProcessSensorReadyPath,
		"--property=KillMode=control-group",
		"--property=KillSignal=SIGKILL",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("harness argv missing %q", want)
		}
	}
}

func TestLimaCreateArgsDisablesTTY(t *testing.T) {
	want := []string{"create", "--tty=false", "--name=test-instance", "/path/to/lima.yaml"}
	got := limaCreateArgs("test-instance", "/path/to/lima.yaml")
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("limactl create args = %v, want %v", got, want)
	}
}

func TestVerifyBakeVerifiesCleansCloudInitThenSyncs(t *testing.T) {
	var calls [][]string
	run := func(_ context.Context, _, _ io.Writer, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}

	if err := verifyBake(context.Background(), "test-bake", run); err != nil {
		t.Fatalf("verifyBake: %v", err)
	}

	want := [][]string{
		bakeVerificationArgs("test-bake"),
		{"shell", "test-bake", "--", "sudo", "cloud-init", "clean", "--logs", "--seed"},
		{"shell", "test-bake", "--", "sudo", "sync"},
	}
	if len(calls) != len(want) {
		t.Fatalf("limactl calls = %v, want %v", calls, want)
	}
	for i := range want {
		if strings.Join(calls[i], "\x00") != strings.Join(want[i], "\x00") {
			t.Errorf("limactl call %d = %v, want %v", i, calls[i], want[i])
		}
	}
}

func TestVerifyBakeFetchesProvisioningLogAfterExecutableFailure(t *testing.T) {
	wantErr := errors.New("invalid executable")
	var calls [][]string
	run := func(_ context.Context, stdout, stderr io.Writer, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		if len(calls) == 1 {
			_, _ = io.WriteString(stdout, "verification output\n")
			_, _ = io.WriteString(stderr, "verification error\n")
			return wantErr
		}
		_, _ = io.WriteString(stdout, "npm install failed\n")
		_, _ = io.WriteString(stderr, "tail warning\n")
		return nil
	}

	err := verifyBake(context.Background(), "test-bake", run)
	if !errors.Is(err, wantErr) {
		t.Fatalf("verifyBake error = %v, want wrapped %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "required component verification failed") {
		t.Errorf("verifyBake error = %q, want component verification context", err)
	}
	for _, want := range []string{"verification output", "verification error", "npm install failed", "tail warning"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("verifyBake error = %q, want diagnostic %q", err, want)
		}
	}
	wantCalls := [][]string{
		bakeVerificationArgs("test-bake"),
		{"shell", "test-bake", "--", "sudo", "tail", "-n", "500", "/var/log/cloud-init-output.log"},
	}
	if len(calls) != len(wantCalls) {
		t.Fatalf("limactl calls = %v, want verification and provisioning log fetch", calls)
	}
	for i := range wantCalls {
		if strings.Join(calls[i], "\x00") != strings.Join(wantCalls[i], "\x00") {
			t.Errorf("limactl call %d = %v, want %v", i, calls[i], wantCalls[i])
		}
	}
}

func TestVerifyBakePreservesExecutableFailureWhenProvisioningLogFetchFails(t *testing.T) {
	wantErr := errors.New("invalid executable")
	logErr := errors.New("tail failed")
	calls := 0
	run := func(_ context.Context, _, _ io.Writer, _ ...string) error {
		calls++
		if calls == 1 {
			return wantErr
		}
		return logErr
	}

	err := verifyBake(context.Background(), "test-bake", run)
	if !errors.Is(err, wantErr) {
		t.Fatalf("verifyBake error = %v, want wrapped %v", err, wantErr)
	}
	if errors.Is(err, logErr) {
		t.Fatalf("verifyBake error wraps secondary log error %v, want original verification error", logErr)
	}
	if !strings.Contains(err.Error(), "could not retrieve cloud-init provisioning log: tail failed") {
		t.Errorf("verifyBake error = %q, want secondary log retrieval context", err)
	}
	if calls != 2 {
		t.Fatalf("limactl calls = %d, want verification and provisioning log fetch", calls)
	}
}

func TestVerifyBakeReturnsCloudInitCleanFailureBeforeSync(t *testing.T) {
	wantErr := errors.New("clean failed")
	calls := 0
	run := func(context.Context, io.Writer, io.Writer, ...string) error {
		calls++
		if calls == 2 {
			return wantErr
		}
		return nil
	}

	err := verifyBake(context.Background(), "test-bake", run)
	if !errors.Is(err, wantErr) {
		t.Fatalf("verifyBake error = %v, want wrapped %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "cloud-init cleanup failed") {
		t.Errorf("verifyBake error = %q, want cloud-init cleanup context", err)
	}
	if calls != 2 {
		t.Fatalf("limactl calls = %d, want verification then cloud-init cleanup", calls)
	}
}

func TestVerifyBakeReturnsSyncFailureAfterExecutableSuccess(t *testing.T) {
	wantErr := errors.New("sync failed")
	calls := 0
	run := func(context.Context, io.Writer, io.Writer, ...string) error {
		calls++
		if calls == 3 {
			return wantErr
		}
		return nil
	}

	err := verifyBake(context.Background(), "test-bake", run)
	if !errors.Is(err, wantErr) {
		t.Fatalf("verifyBake error = %v, want wrapped %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "guest filesystem sync failed") {
		t.Errorf("verifyBake error = %q, want filesystem sync context", err)
	}
	if calls != 3 {
		t.Fatalf("limactl calls = %d, want verification, cloud-init cleanup, then sync", calls)
	}
}

func TestGenerateLimaYAML_ParsesAndShapesMount(t *testing.T) {
	cfg := testConfig(t, true)
	out, err := GenerateLimaYAML(cfg)
	if err != nil {
		t.Fatalf("GenerateLimaYAML: %v", err)
	}

	// Must parse as generic YAML (independent of our own struct tags).
	var generic map[string]any
	if err := yaml.Unmarshal([]byte(out), &generic); err != nil {
		t.Fatalf("generated YAML does not parse: %v\n%s", err, out)
	}
	if _, ok := generic["portForwards"]; ok {
		t.Errorf("portForwards present in generated YAML, want none per DESIGN.md")
	}

	var tmpl limaTemplate
	if err := yaml.Unmarshal([]byte(out), &tmpl); err != nil {
		t.Fatalf("generated YAML does not unmarshal into lima template: %v", err)
	}
	if tmpl.VMType != "vz" {
		t.Errorf("vmType = %q, want vz", tmpl.VMType)
	}
	if tmpl.Arch != "aarch64" {
		t.Errorf("arch = %q, want aarch64 for host arm64", tmpl.Arch)
	}
	if len(tmpl.Images) != 1 || tmpl.Images[0].Location != cfg.ImagePath {
		t.Errorf("images = %+v, want a single entry at cfg.ImagePath %q", tmpl.Images, cfg.ImagePath)
	}
	if strings.Contains(tmpl.Images[0].Location, "cloud-images.ubuntu.com") {
		t.Errorf("session image location = %q, must not be the stock Ubuntu download", tmpl.Images[0].Location)
	}
	if len(tmpl.Mounts) != 2 {
		t.Fatalf("mounts = %d entries, want workspace and Claude diagnostics", len(tmpl.Mounts))
	}
	m := tmpl.Mounts[0]
	if m.MountPoint != "/workspace" {
		t.Errorf("mount point = %q, want /workspace", m.MountPoint)
	}
	if m.Location != cfg.WorkspacePath {
		t.Errorf("mount location = %q, want %q", m.Location, cfg.WorkspacePath)
	}
	if !m.Writable {
		t.Errorf("mount writable = false, want true for a writable profile")
	}
	claudeMount := tmpl.Mounts[1]
	if claudeMount.Location != filepath.Join(cfg.SessionDir, claudeArtifactsDirName) {
		t.Errorf("Claude diagnostics location = %q, want session-local directory", claudeMount.Location)
	}
	if claudeMount.MountPoint != guestClaudeConfigDir {
		t.Errorf("Claude diagnostics mount point = %q, want %q", claudeMount.MountPoint, guestClaudeConfigDir)
	}
	if !claudeMount.Writable {
		t.Errorf("Claude diagnostics mount writable = false, want true")
	}

	found := false
	for _, s := range tmpl.MountTypesUnsupported {
		if s == "reverse-sshfs" {
			found = true
		}
	}
	if !found {
		t.Errorf("mountTypesUnsupported missing reverse-sshfs, got %v", tmpl.MountTypesUnsupported)
	}
	if tmpl.Containerd.System || tmpl.Containerd.User {
		t.Errorf("containerd = %+v, want both system and user disabled", tmpl.Containerd)
	}
}

func TestGenerateLimaYAML_ReviewProfileIsReadOnly(t *testing.T) {
	cfg := testConfig(t, false)
	out, err := GenerateLimaYAML(cfg)
	if err != nil {
		t.Fatalf("GenerateLimaYAML: %v", err)
	}
	var tmpl limaTemplate
	if err := yaml.Unmarshal([]byte(out), &tmpl); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(tmpl.Mounts) != 2 {
		t.Fatalf("mounts = %d, want workspace and Claude diagnostics", len(tmpl.Mounts))
	}
	if tmpl.Mounts[0].Writable {
		t.Errorf("review profile mount is writable, want read-only")
	}
	if !tmpl.Mounts[1].Writable {
		t.Errorf("Claude diagnostics mount is read-only, want writable")
	}
}

func TestGenerateLimaYAML_CodexMountsSessionHome(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.Harness = "codex"
	out, err := GenerateLimaYAML(cfg)
	if err != nil {
		t.Fatalf("GenerateLimaYAML: %v", err)
	}
	var tmpl limaTemplate
	if err := yaml.Unmarshal([]byte(out), &tmpl); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(tmpl.Mounts) != 2 {
		t.Fatalf("mounts = %+v, want workspace and session-scoped Codex home", tmpl.Mounts)
	}
	if tmpl.Mounts[0].MountPoint != guestWorkspaceMount {
		t.Errorf("mount point = %q, want %q", tmpl.Mounts[0].MountPoint, guestWorkspaceMount)
	}
	if tmpl.Mounts[1].MountPoint != guestCodexConfigDir {
		t.Errorf("Codex home mount point = %q, want %q", tmpl.Mounts[1].MountPoint, guestCodexConfigDir)
	}
}

// TestGenerateLimaYAML_RequiresImagePath is the regression guard for the
// golden-image switchover: a real session must never silently fall back to
// booting nothing (or the stock Ubuntu image) when the caller forgot to
// resolve a golden image path.
func TestGenerateLimaYAML_RequiresImagePath(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.ImagePath = ""
	if _, err := GenerateLimaYAML(cfg); err == nil {
		t.Errorf("expected error for empty ImagePath, got nil")
	}
}

func TestGenerateLimaYAML_ProvisioningStepsPresent(t *testing.T) {
	cfg := testConfig(t, true)
	out, err := GenerateLimaYAML(cfg)
	if err != nil {
		t.Fatalf("GenerateLimaYAML: %v", err)
	}
	var tmpl limaTemplate
	if err := yaml.Unmarshal([]byte(out), &tmpl); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(tmpl.Provision) == 0 {
		t.Fatalf("no provisioning entries generated")
	}

	var combined strings.Builder
	for _, p := range tmpl.Provision {
		if p.Mode != "system" {
			t.Errorf("provision mode = %q, want system", p.Mode)
		}
		combined.WriteString(p.Script)
		combined.WriteString("\n")
	}
	got := combined.String()

	for _, want := range []string{
		"useradd",                   // idempotent user guard
		"--uid 4242",                // agent uid
		"boxedai-guest-agent",       // guest agent binary + unit
		"RuntimeDirectory=boxedai",  // process sensor readiness directory
		"/etc/boxedai/agent.json",   // guest agent config
		"nftables",                  // nftables ruleset
		"systemctl restart rsyslog", // rsyslog-restart: confirm the log sink is live this session
		"policy drop",               // default-deny
		"boxedai-denied",            // deny log prefix
		"meta skuid 4242",           // log only the workload's denials
		"udp dport 53 ip daddr ${UPSTREAM_DNS} drop", // silently drop the workload's dead-resolver DNS (noise, not evidence)
		"systemctl restart nftables",                 // ruleset applied
		"systemctl enable --now boxedai-guest-agent", // guest agent enable
	} {
		if !strings.Contains(got, want) {
			t.Errorf("session provisioning scripts missing expected content %q", want)
		}
	}

	// Session provisioning must never apt-get/npm/curl-install anything: all
	// binaries and packages are baked into the golden image once. Restarting
	// the baked Tetragon service above is session initialization, not install.
	for _, banned := range []string{
		"apt-get install",
		"npm install",
		"nodesource",
		"nodejs",
		"@anthropic-ai/claude-code",
		"@openai/codex",
		"BOXEDAI_CA_EOF",
		"NODE_EXTRA_CA_CERTS",
	} {
		if strings.Contains(got, banned) {
			t.Errorf("session provisioning should not contain %q (belongs to bake provisioning)", banned)
		}
	}
}

func TestSessionProvisioningEstablishesFreshTetragonLogBeforeAgent(t *testing.T) {
	provs, err := provisionScripts(testConfig(t, true))
	if err != nil {
		t.Fatalf("provisionScripts: %v", err)
	}
	script := provs[len(provs)-1].Script
	for _, want := range []string{
		"systemctl stop tetragon",
		"rm -f /var/log/tetragon/tetragon.log",
		"systemctl start tetragon",
		"for TETRAGON_WAIT in 1 2 3 4 5",
		"systemctl is-active --quiet tetragon",
		"if [ -e /var/log/tetragon/tetragon.log ]",
		"TETRAGON_READY=true",
		"systemctl enable --now boxedai-guest-agent",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("agent enable script missing %q", want)
		}
	}
	boundary := strings.Index(script, "rm -f /var/log/tetragon/tetragon.log")
	restart := strings.Index(script, "systemctl start tetragon")
	wait := strings.Index(script, "for TETRAGON_WAIT in 1 2 3 4 5")
	validation := strings.Index(script, "systemctl is-active --quiet tetragon")
	exportReady := strings.Index(script, "if [ -e /var/log/tetragon/tetragon.log ]")
	decision := strings.Index(script, "if [ \"$TETRAGON_READY\" != true ]")
	agentStart := strings.Index(script, "systemctl enable --now boxedai-guest-agent")
	if !(boundary < restart && restart < wait && wait < validation && validation < exportReady && exportReady < decision && decision < agentStart) {
		t.Errorf("Tetragon boundary/restart/validation must precede guest agent start:\n%s", script)
	}
}

// TestProvisionScripts_SessionNeverInstallsRegardlessOfHarness verifies that,
// post golden-image split, session provisioning is identical (no npm/node) no
// matter which harness the session requests — the image is harness-agnostic,
// so there is nothing left for the harness value to select at provision time.
func TestProvisionScripts_SessionNeverInstallsRegardlessOfHarness(t *testing.T) {
	render := func(harness string) string {
		cfg := testConfig(t, true)
		cfg.Harness = harness
		if harness == "exec" {
			cfg.Cmd = "true"
		}
		provs, err := provisionScripts(cfg)
		if err != nil {
			t.Fatalf("provisionScripts(%s): %v", harness, err)
		}
		var b strings.Builder
		for _, p := range provs {
			b.WriteString(p.Script)
		}
		return b.String()
	}

	for _, harness := range []string{"claude", "codex", "exec"} {
		got := render(harness)
		for _, banned := range []string{"@anthropic-ai/claude-code", "@openai/codex", "nodesource", "nodejs", "npm install"} {
			if strings.Contains(got, banned) {
				t.Errorf("harness %q session provisioning should not contain %q", harness, banned)
			}
		}
	}
}

func TestGenerateLimaYAML_UnsupportedArch(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.Arch = "riscv64"
	if _, err := GenerateLimaYAML(cfg); err == nil {
		t.Errorf("expected error for unsupported arch, got nil")
	}
}

func TestWriteLimaYAML_WritesToVMDir(t *testing.T) {
	cfg := testConfig(t, true)
	path, err := WriteLimaYAML(cfg)
	if err != nil {
		t.Fatalf("WriteLimaYAML: %v", err)
	}
	want := filepath.Join(cfg.SessionDir, "vm", "lima.yaml")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("lima.yaml not written: %v", err)
	}
	debugDir := filepath.Join(cfg.SessionDir, claudeArtifactsDirName, "debug")
	info, err := os.Stat(debugDir)
	if err != nil {
		t.Fatalf("Claude debug directory not created: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("Claude debug directory mode = %o, want 700", info.Mode().Perm())
	}
	rawBodiesDir := filepath.Join(cfg.SessionDir, claudeArtifactsDirName, "raw-api-bodies")
	info, err = os.Stat(rawBodiesDir)
	if err != nil {
		t.Fatalf("Claude raw API body directory not created: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("Claude raw API body directory mode = %o, want 700", info.Mode().Perm())
	}
}

// TestGenerateBakeLimaYAML_UsesUbuntuImageNoMountsAndSmallDisk verifies the
// bake boot is the one remaining place that downloads stock Ubuntu, mounts
// nothing from the host, and requests a smaller-than-default disk so the
// exported golden image stays small.
func TestGenerateBakeLimaYAML_UsesUbuntuImageNoMountsAndSmallDisk(t *testing.T) {
	cfg := testBakeConfig(t)
	out, err := GenerateBakeLimaYAML(cfg)
	if err != nil {
		t.Fatalf("GenerateBakeLimaYAML: %v", err)
	}
	var tmpl limaTemplate
	if err := yaml.Unmarshal([]byte(out), &tmpl); err != nil {
		t.Fatalf("generated bake YAML does not unmarshal: %v", err)
	}
	if tmpl.VMType != "vz" {
		t.Errorf("vmType = %q, want vz", tmpl.VMType)
	}
	if tmpl.Arch != "aarch64" {
		t.Errorf("arch = %q, want aarch64 for host arm64", tmpl.Arch)
	}
	wantImage := ubuntuImageURL(cfg.Arch)
	if len(tmpl.Images) != 1 || tmpl.Images[0].Location != wantImage {
		t.Errorf("images = %+v, want a single entry at %q", tmpl.Images, wantImage)
	}
	if len(tmpl.Mounts) != 0 {
		t.Errorf("mounts = %+v, want none for the bake boot", tmpl.Mounts)
	}
	if tmpl.Disk != bakeDiskSize {
		t.Errorf("disk = %q, want %q", tmpl.Disk, bakeDiskSize)
	}
}

func TestGenerateBakeLimaYAML_UnsupportedArch(t *testing.T) {
	cfg := testBakeConfig(t)
	cfg.Arch = "riscv64"
	if _, err := GenerateBakeLimaYAML(cfg); err == nil {
		t.Errorf("expected error for unsupported arch, got nil")
	}
}

func TestWriteBakeLimaYAML_WritesToVMDir(t *testing.T) {
	cfg := testBakeConfig(t)
	path, err := WriteBakeLimaYAML(cfg)
	if err != nil {
		t.Fatalf("WriteBakeLimaYAML: %v", err)
	}
	want := filepath.Join(cfg.SessionDir, "vm", "lima.yaml")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("lima.yaml not written: %v", err)
	}
}

// TestBakeProvisionScripts_ContainsBakeContent verifies bake provisioning has
// everything session provisioning no longer does: both harness CLIs
// (harness-agnostic image), Node, Tetragon, and the nftables/rsyslog package
// install+enable — but none of the session-only nftables ruleset or guest
// agent content, since bake time has no broker, session, or tokens.
func TestBakeProvisionScripts_ContainsBakeContent(t *testing.T) {
	cfg := testBakeConfig(t)
	provs, err := bakeProvisionScripts(cfg)
	if err != nil {
		t.Fatalf("bakeProvisionScripts: %v", err)
	}
	var b strings.Builder
	for _, p := range provs {
		if p.Mode != "system" {
			t.Errorf("provision mode = %q, want system", p.Mode)
		}
		b.WriteString(p.Script)
	}
	got := b.String()

	for _, want := range []string{
		"useradd",    // agent user
		"--uid 4242", // agent uid
		"nodesource", // node install
		"nodejs",
		"@anthropic-ai/claude-code", // both CLIs, unconditionally
		"@openai/codex",
		"@anthropic-ai/claude-code-linux-arm64/claude",
		"/usr/local/bin/claude",
		"tetragon",                                             // tetragon install
		"rm -rf /var/lib/boxedai/tetragon-install",             // exact fixed staging cleanup
		"cp -a tetragon-*/usr/local/. /usr/local/",             // complete release payload
		"/usr/local/lib/tetragon/bpftool",                      // packaged helper
		"/usr/local/lib/tetragon/tetragon.conf.d/bpf-lib",      // packaged config
		"/usr/local/lib/tetragon/bpf/bpf_execve_event.o",       // exec capture object
		"/usr/local/lib/tetragon/bpf/bpf_exit.o",               // exit capture object
		"/usr/local/lib/tetragon/bpf/bpf_generic_tracepoint.o", // fork tracepoint capture object
		"/usr/local/lib/tetragon/bpf/bpf_generic_tracepoint_v53.o",
		"/usr/local/lib/tetragon/bpf/bpf_generic_tracepoint_v511.o",
		"/usr/local/lib/tetragon/bpf/bpf_generic_tracepoint_v61.o",
		"name: boxedai-process-fork", // static fork policy
		"event: sched_process_fork",
		"--tracing-policy=/etc/boxedai/tetragon/boxedai-process-fork.yaml",
		"--export-rate-limit=-1",
		"--metrics-server=127.0.0.1:2112",
		"PATH=/usr/local/lib/tetragon/:",                              // helper lookup
		"--bpf-lib=/usr/local/lib/tetragon/bpf",                       // explicit service path
		"systemctl enable tetragon",                                   // baked enable state
		"apt-get install -y --no-install-recommends nftables rsyslog", // package install
		"systemctl enable rsyslog",                                    // baked enable state
	} {
		if !strings.Contains(got, want) {
			t.Errorf("bake provisioning scripts missing expected content %q", want)
		}
	}
	if strings.Contains(got, "cloud-init clean") {
		t.Errorf("bake provisioning should not clean cloud-init before CLI verification")
	}
	if strings.Contains(got, "mktemp -d") {
		t.Errorf("bake provisioning should use the fixed Tetragon staging directory")
	}

	// Session-only content (broker/token/ruleset/guest-agent) must never
	// appear at bake time: none of it exists yet.
	for _, banned := range []string{
		"boxedai-guest-agent",
		"/etc/boxedai/agent.json",
		"getent hosts",
		"boxedai-denied",
		"policy drop",
		"/etc/nftables.conf",
		"resolv.conf",
	} {
		if strings.Contains(got, banned) {
			t.Errorf("bake provisioning should not contain %q (session-only)", banned)
		}
	}
}

func TestBakeVerificationChecksTetragonRuntimePayloadWhenInstalled(t *testing.T) {
	for _, want := range []string{
		"if command -v tetragon",
		"test -x /usr/local/lib/tetragon/bpftool",
		"test -s /usr/local/lib/tetragon/tetragon.conf.d/bpf-lib",
		"test -s /usr/local/lib/tetragon/bpf/bpf_execve_event.o",
		"test -s /usr/local/lib/tetragon/bpf/bpf_exit.o",
		"test -s /usr/local/lib/tetragon/bpf/bpf_generic_tracepoint.o",
		"test -s /usr/local/lib/tetragon/bpf/bpf_generic_tracepoint_v53.o",
		"test -s /usr/local/lib/tetragon/bpf/bpf_generic_tracepoint_v511.o",
		"test -s /usr/local/lib/tetragon/bpf/bpf_generic_tracepoint_v61.o",
		"test -s /etc/boxedai/tetragon/boxedai-process-fork.yaml",
		"PATH=/usr/local/lib/tetragon/:",
		"--bpf-lib=/usr/local/lib/tetragon/bpf",
		"--tracing-policy=/etc/boxedai/tetragon/boxedai-process-fork.yaml",
		"--export-rate-limit=-1",
		"--metrics-server=127.0.0.1:2112",
	} {
		if !strings.Contains(bakeVerificationScript, want) {
			t.Errorf("bake verification missing Tetragon runtime check %q", want)
		}
	}
}

func TestBakeProvisionScripts_ClaudeNativeArchitecture(t *testing.T) {
	for _, tc := range []struct {
		arch        string
		packageArch string
	}{
		{arch: "arm64", packageArch: "arm64"},
		{arch: "amd64", packageArch: "x64"},
	} {
		t.Run(tc.arch, func(t *testing.T) {
			cfg := testBakeConfig(t)
			cfg.Arch = tc.arch
			provs, err := bakeProvisionScripts(cfg)
			if err != nil {
				t.Fatalf("bakeProvisionScripts: %v", err)
			}
			var b strings.Builder
			for _, p := range provs {
				b.WriteString(p.Script)
			}
			want := "@anthropic-ai/claude-code-linux-" + tc.packageArch + "/claude"
			if !strings.Contains(b.String(), want) {
				t.Errorf("bake provisioning for %s missing %q", tc.arch, want)
			}
		})
	}
}

// TestBakeProvisionScripts_NPMTrustsExtraCA is the regression guard for
// corporate TLS interception: node bundles its own CA set and ignores
// update-ca-certificates, so npm install needs NODE_EXTRA_CA_CERTS pointed at
// the installed corporate CA or it fails certificate verification even
// though curl/apt (system store) succeed. This only ever runs at bake time
// now, since session provisioning never touches npm.
func TestBakeProvisionScripts_NPMTrustsExtraCA(t *testing.T) {
	cfg := testBakeConfig(t)
	cfg.ExtraCAPEM = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
	provs, err := bakeProvisionScripts(cfg)
	if err != nil {
		t.Fatalf("bakeProvisionScripts: %v", err)
	}
	var b strings.Builder
	for _, p := range provs {
		b.WriteString(p.Script)
	}
	got := b.String()
	if !strings.Contains(got, "export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/boxedai-extra-ca.crt") {
		t.Errorf("bake provisioning with extra CA missing NODE_EXTRA_CA_CERTS export, got:\n%s", got)
	}
	caIndex := strings.Index(got, "update-ca-certificates")
	firstNetworkIndex := strings.Index(got, "apt-get update -y")
	if caIndex == -1 || firstNetworkIndex == -1 || caIndex > firstNetworkIndex {
		t.Errorf("corporate CA trust must be installed before the first network operation")
	}
}

// TestBakeProvisionScripts_NoExtraCA_NoNPMCAExport verifies the
// NODE_EXTRA_CA_CERTS export is only emitted when a corporate CA was
// actually configured.
func TestBakeProvisionScripts_NoExtraCA_NoNPMCAExport(t *testing.T) {
	cfg := testBakeConfig(t)
	cfg.ExtraCAPEM = ""
	provs, err := bakeProvisionScripts(cfg)
	if err != nil {
		t.Fatalf("bakeProvisionScripts: %v", err)
	}
	var b strings.Builder
	for _, p := range provs {
		b.WriteString(p.Script)
	}
	got := b.String()
	if strings.Contains(got, "NODE_EXTRA_CA_CERTS") {
		t.Errorf("bake provisioning without extra CA should not mention NODE_EXTRA_CA_CERTS, got:\n%s", got)
	}
}

// TestBakeProvisionScripts_NPMRegistryOverride is the regression guard for
// networks that block the public npm registry (e.g. a corporate
// dependency-confusion Cloudflare Gateway policy): when an NPMRegistry
// override is configured, bake provisioning must point npm at it before
// installing the harness CLIs.
func TestBakeProvisionScripts_NPMRegistryOverride(t *testing.T) {
	cfg := testBakeConfig(t)
	cfg.NPMRegistry = "https://registry.example.internal/npm/"
	provs, err := bakeProvisionScripts(cfg)
	if err != nil {
		t.Fatalf("bakeProvisionScripts: %v", err)
	}
	var b strings.Builder
	for _, p := range provs {
		b.WriteString(p.Script)
	}
	got := b.String()
	if !strings.Contains(got, "npm config set registry https://registry.example.internal/npm/") {
		t.Errorf("bake provisioning with npm registry override missing npm config set registry, got:\n%s", got)
	}
}

// TestBakeProvisionScripts_NoNPMRegistry_NoOverride verifies the npm config
// set registry line is only emitted when an override was actually
// configured.
func TestBakeProvisionScripts_NoNPMRegistry_NoOverride(t *testing.T) {
	cfg := testBakeConfig(t)
	cfg.NPMRegistry = ""
	provs, err := bakeProvisionScripts(cfg)
	if err != nil {
		t.Fatalf("bakeProvisionScripts: %v", err)
	}
	var b strings.Builder
	for _, p := range provs {
		b.WriteString(p.Script)
	}
	got := b.String()
	if strings.Contains(got, "npm config set registry") {
		t.Errorf("bake provisioning without npm registry override should not mention npm config set registry, got:\n%s", got)
	}
}

func TestHarnessEnv_Claude(t *testing.T) {
	cfg := testConfig(t, true)
	env, err := harnessEnv(cfg)
	if err != nil {
		t.Fatalf("harnessEnv: %v", err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"ANTHROPIC_BASE_URL=http://host.lima.internal:41830/v1/model/anthropic",
		"ANTHROPIC_AUTH_TOKEN=workload-token",
		"CLAUDE_CONFIG_DIR=/home/agent/.claude",
		"CLAUDE_CODE_DEBUG_LOG_LEVEL=verbose",
		"CLAUDE_CODE_ENABLE_TELEMETRY=1",
		"CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1",
		"CLAUDE_CODE_PROPAGATE_TRACEPARENT=1",
		"DISABLE_AUTOUPDATER=1",
		"DISABLE_ERROR_REPORTING=1",
		"DISABLE_FEEDBACK_COMMAND=1",
		"CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY=1",
		"CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1",
		"OTEL_METRICS_EXPORTER=otlp",
		"OTEL_LOGS_EXPORTER=otlp",
		"OTEL_TRACES_EXPORTER=otlp",
		"OTEL_EXPORTER_OTLP_PROTOCOL=http/json",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://host.lima.internal:41830/v1/telemetry/claude/metrics",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://host.lima.internal:41830/v1/telemetry/claude/logs",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://host.lima.internal:41830/v1/telemetry/claude/traces",
		"OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer workload-token",
		"OTEL_LOG_USER_PROMPTS=1",
		"OTEL_LOG_ASSISTANT_RESPONSES=1",
		"OTEL_LOG_TOOL_DETAILS=1",
		"OTEL_LOG_TOOL_CONTENT=1",
		"OTEL_LOG_RAW_API_BODIES=file:/home/agent/.claude/raw-api-bodies",
		"BOXEDAI_BROKER_URL=http://host.lima.internal:41830",
		"BOXEDAI_WORKLOAD_TOKEN=workload-token",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("claude env missing %q, got %v", want, env)
		}
	}
	for _, conflicting := range []string{
		"DISABLE_TELEMETRY",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
	} {
		if strings.Contains(joined, conflicting) {
			t.Errorf("Claude telemetry is enabled but env contains %q: %v", conflicting, env)
		}
	}
}

func TestHarnessEnv_ClaudeBrokeredGitHub(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.GitHubRepository = "squareup/secret-repo"
	cfg.GitHubRemote = "org-49461806@github.com:squareup/secret-repo.git"
	cfg.GitHubSSHURL = "org-49461806@github.com:squareup/secret-repo.git"
	env, err := harnessEnv(cfg)
	if err != nil {
		t.Fatalf("harnessEnv: %v", err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"=url.ext::/usr/local/bin/boxedai-guest-agent git-bridge %S.insteadOf",
		"=org-49461806@github.com:squareup/secret-repo.git",
		"=https://github.com/squareup/secret-repo.git",
		"=protocol.ext.allow",
		"=user",
		"BOXEDAI_BROKER_URL=http://host.lima.internal:41830",
		"BOXEDAI_WORKLOAD_TOKEN=workload-token",
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=never",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("Claude GitHub env missing %q, got %v", want, env)
		}
	}
	for _, forbidden := range []string{"host-gh-token", "/v1/github/", "extraHeader", "squareup/other"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Claude GitHub env contains %q outside the SSH bridge scope: %v", forbidden, env)
		}
	}
}

func TestHarnessEnv_Codex(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.Harness = "codex"
	env, err := harnessEnv(cfg)
	if err != nil {
		t.Fatalf("harnessEnv: %v", err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"OPENAI_BASE_URL=http://host.lima.internal:41830/v1/model/openai",
		"OPENAI_API_KEY=workload-token",
		"CODEX_HOME=/home/agent/.codex",
		"BOXEDAI_BROKER_URL=http://host.lima.internal:41830",
		"BOXEDAI_WORKLOAD_TOKEN=workload-token",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("codex env missing %q, got %v", want, env)
		}
	}
}

func TestHarnessEnv_CodexBrokeredGitHub(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.Harness = "codex"
	cfg.GitHubRepository = "squareup/secret-repo"
	cfg.GitHubRemote = "org-49461806@github.com:squareup/secret-repo.git"
	cfg.GitHubSSHURL = cfg.GitHubRemote
	env, err := harnessEnv(cfg)
	if err != nil {
		t.Fatalf("harnessEnv: %v", err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"=url.ext::/usr/local/bin/boxedai-guest-agent git-bridge %S.insteadOf",
		"BOXEDAI_BROKER_URL=http://host.lima.internal:41830",
		"BOXEDAI_WORKLOAD_TOKEN=workload-token",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("Codex GitHub env missing %q, got %v", want, env)
		}
	}
}

func TestHarnessArgv_Claude(t *testing.T) {
	cfg := testConfig(t, true)
	v := &VM{Cfg: cfg}
	argv, err := v.harnessArgv(true)
	if err != nil {
		t.Fatalf("harnessArgv: %v", err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"shell " + cfg.SessionID,
		"sudo systemd-run",
		"--unit=boxedai-session",
		"--pty",
		"--uid=agent",
		"--property=MemoryMax=8G",
		"--property=CPUQuota=400%",
		"--property=TasksMax=512",
		"--property=ReadWritePaths=/workspace /home/agent /tmp",
		"--property=WorkingDirectory=/workspace",
		"--property=CapabilityBoundingSet=",
		"--setenv=ANTHROPIC_AUTH_TOKEN=workload-token",
		"/usr/local/bin/claude --debug-file /home/agent/.claude/debug/claude-code.log",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv missing %q, got: %v", want, argv)
		}
	}
}

// TestHarnessArgv_NonInteractive checks the scripted path uses --pipe (which
// returns on unit exit) instead of --pty (which hangs without a controlling
// terminal). This is the regression guard for the boot-time teardown hang.
func TestHarnessArgv_NonInteractive(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.Harness = "exec"
	cfg.Cmd = "echo hi"
	v := &VM{Cfg: cfg}
	argv, err := v.harnessArgv(false)
	if err != nil {
		t.Fatalf("harnessArgv: %v", err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--pipe") {
		t.Errorf("non-interactive argv should use --pipe, got: %v", argv)
	}
	if strings.Contains(joined, "--pty") {
		t.Errorf("non-interactive argv must not use --pty, got: %v", argv)
	}
}

func TestHarnessArgv_Exec(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.Harness = "exec"
	cfg.Cmd = "echo hi"
	v := &VM{Cfg: cfg}
	argv, err := v.harnessArgv(true)
	if err != nil {
		t.Fatalf("harnessArgv: %v", err)
	}
	if len(argv) < 3 {
		t.Fatalf("argv too short: %v", argv)
	}
	tail := argv[len(argv)-3:]
	want := []string{"sh", "-lc", "echo hi"}
	for i := range want {
		if tail[i] != want[i] {
			t.Errorf("argv tail = %v, want %v", tail, want)
		}
	}
}

// TestHarnessArgv_ClaudeWithHarnessArgs is the regression guard for passthrough
// scripting (`boxedai run claude <path> -- -p 'ping pong'`): HarnessArgs must
// land as plain argv elements after BoxedAi's Claude debug flags, so a space
// inside one arg survives as a single element instead of being split by a
// shell.
func TestHarnessArgv_ClaudeWithHarnessArgs(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.HarnessArgs = []string{"-p", "ping pong"}
	v := &VM{Cfg: cfg}
	argv, err := v.harnessArgv(true)
	if err != nil {
		t.Fatalf("harnessArgv: %v", err)
	}
	if len(argv) < 5 {
		t.Fatalf("argv too short: %v", argv)
	}
	tail := argv[len(argv)-5:]
	want := []string{guestClaudeExecutable, "--debug-file", guestClaudeDebugFile, "-p", "ping pong"}
	for i := range want {
		if tail[i] != want[i] {
			t.Errorf("argv tail = %v, want %v", tail, want)
		}
	}
}

func TestHarnessArgv_UnknownHarness(t *testing.T) {
	cfg := testConfig(t, true)
	cfg.Harness = "bogus"
	v := &VM{Cfg: cfg}
	if _, err := v.harnessArgv(true); err == nil {
		t.Errorf("expected error for unknown harness")
	}
}
