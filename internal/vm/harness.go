package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/mattn/go-isatty"
)

// harnessUnit is the systemd-run transient unit name for the interactive
// workload; the guest agent correlates process-tree evidence to it.
const harnessUnit = "boxedai-session"

// LaunchHarness execs the configured harness (claude, codex, or exec) inside
// the guest under a hardened systemd-run transient unit, with the current
// process's stdio wired straight through for interactive pty passthrough. It
// returns the harness's own exit code; a non-nil error means BoxedAi itself
// failed to launch it (the harness never ran).
func (vm *VM) LaunchHarness(ctx context.Context) (int, error) {
	argv, err := vm.harnessArgv(stdinIsTTY())
	if err != nil {
		return -1, err
	}
	cmd := exec.CommandContext(ctx, vm.binary(), argv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), nil
	default:
		return -1, fmt.Errorf("vm: launch harness: %w", err)
	}
}

// stdinIsTTY reports whether the controller's stdin is an interactive
// terminal. Interactive harnesses (claude, codex) need systemd-run --pty for a
// real pty; scripted/background runs (exec, CI) have no controlling terminal,
// where --pty never returns because the master side never sees the session
// close. Those use --pipe instead, which streams stdio and exits on completion.
//
// isatty.IsTerminal does the real TCGETS ioctl: os.ModeCharDevice is NOT enough
// because /dev/null (a background run's stdin) is a character device yet not a
// terminal, which would wrongly select --pty and hang teardown.
func stdinIsTTY() bool {
	return isatty.IsTerminal(os.Stdin.Fd())
}

// harnessArgv builds the full `limactl shell ... -- sudo systemd-run ...
// <harness argv>` command line per DESIGN.md "Harness launch". It is plain
// argv (no shell involved), so property values containing spaces (e.g.
// ReadWritePaths) do not need quoting. interactive selects --pty (real
// terminal) vs --pipe (non-TTY, returns on unit exit).
func (vm *VM) harnessArgv(interactive bool) ([]string, error) {
	cfg := vm.Cfg
	env, err := harnessEnv(cfg)
	if err != nil {
		return nil, err
	}

	// --pty needs --wait to block; --pipe implies --wait on its own.
	streamMode := []string{"--pipe", "--collect"}
	if interactive {
		streamMode = []string{"--pty", "--wait", "--collect"}
	}

	argv := []string{
		"shell", cfg.SessionID, "--",
		"sudo", "systemd-run",
		"--unit=" + harnessUnit,
	}
	argv = append(argv, streamMode...)
	argv = append(argv,
		"--uid=agent",
		"--property=BindsTo=tetragon.service boxedai-guest-agent.service",
		"--property=After=tetragon.service boxedai-guest-agent.service",
		"--property=ConditionPathExists="+guestProcessSensorReadyPath,
		"--property=KillMode=control-group",
		"--property=KillSignal=SIGKILL",
		"--property=NoNewPrivileges=yes",
		"--property=TasksMax="+strconv.Itoa(cfg.Limits.TasksMax),
		"--property=MemoryMax="+cfg.Limits.MemoryMax,
		"--property=CPUQuota="+cfg.Limits.CPUQuota,
		"--property=ProtectSystem=strict",
		"--property=ReadWritePaths="+guestWorkspaceMount+" /home/agent /tmp",
		"--property=WorkingDirectory="+guestWorkspaceMount,
		"--property=PrivateDevices=yes",
		"--property=RestrictNamespaces=yes",
		"--property=SystemCallFilter=@system-service",
		"--property=CapabilityBoundingSet=",
	)
	for _, kv := range env {
		argv = append(argv, "--setenv="+kv)
	}

	switch cfg.Harness {
	case "claude":
		argv = append(argv, guestClaudeExecutable, "--debug-file", guestClaudeDebugFile)
		argv = append(argv, cfg.HarnessArgs...)
	case "codex":
		argv = append(argv, "codex")
		argv = append(argv, cfg.HarnessArgs...)
	case "exec":
		argv = append(argv, "sh", "-lc", cfg.Cmd)
	default:
		return nil, fmt.Errorf("vm: unknown harness %q", cfg.Harness)
	}
	return argv, nil
}

// harnessEnv returns "NAME=VALUE" pairs for --setenv, per DESIGN.md "Harness
// launch". The workload token (W) never appears anywhere else.
func harnessEnv(cfg Config) ([]string, error) {
	base := fmt.Sprintf("http://%s:%d", cfg.BrokerHost, cfg.BrokerPort)
	switch cfg.Harness {
	case "claude":
		env := []string{
			"ANTHROPIC_BASE_URL=" + base + "/v1/model/anthropic",
			"ANTHROPIC_AUTH_TOKEN=" + cfg.WorkloadToken,
			"CLAUDE_CONFIG_DIR=" + guestClaudeConfigDir,
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
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=" + base + "/v1/telemetry/claude/metrics",
			"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=" + base + "/v1/telemetry/claude/logs",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=" + base + "/v1/telemetry/claude/traces",
			"OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer " + cfg.WorkloadToken,
			"OTEL_LOG_USER_PROMPTS=1",
			"OTEL_LOG_ASSISTANT_RESPONSES=1",
			"OTEL_LOG_TOOL_DETAILS=1",
			"OTEL_LOG_TOOL_CONTENT=1",
			"OTEL_LOG_RAW_API_BODIES=file:" + guestClaudeRawBodiesDir,
			// Hook capture (DESIGN.md "Harness hook capture — lefthook /
			// righthook"): the staged settings.json wires PreToolUse/PostToolUse
			// to the guest agent's lefthook/righthook subcommands, which need
			// these two vars to reach the broker as the workload (token W). The
			// git bridge reads the same pair.
			"BOXEDAI_BROKER_URL=" + base,
			"BOXEDAI_WORKLOAD_TOKEN=" + cfg.WorkloadToken,
		}
		githubEnv, err := githubHarnessEnv(cfg)
		if err != nil {
			return nil, err
		}
		return append(env, githubEnv...), nil
	case "codex":
		env := []string{
			"OPENAI_BASE_URL=" + base + "/v1/model/openai",
			"OPENAI_API_KEY=" + cfg.WorkloadToken,
			"CODEX_HOME=" + guestCodexConfigDir,
			// The git bridge reads this pair (codex has no capture hooks in v0.1).
			"BOXEDAI_BROKER_URL=" + base,
			"BOXEDAI_WORKLOAD_TOKEN=" + cfg.WorkloadToken,
		}
		githubEnv, err := githubHarnessEnv(cfg)
		if err != nil {
			return nil, err
		}
		return append(env, githubEnv...), nil
	case "exec":
		return nil, nil
	default:
		return nil, fmt.Errorf("vm: unknown harness %q", cfg.Harness)
	}
}
