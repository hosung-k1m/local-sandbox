package vm

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// defaultLimactl is used when VM.Binary is unset.
const defaultLimactl = "./bin/limactl"

// stopGrace is how long Stop waits after writing the stop sentinel, matching
// the guest agent's 5s freeze+drain window (DESIGN.md "Kill switch").
const stopGrace = 5 * time.Second

const (
	// limaStartTimeout bounds Lima's unreliable internal SSH readiness wait.
	// The host agent keeps the VM running after this client-side timeout, so
	// BoxedAi can check the guest with its own plain limactl shell probes.
	limaStartTimeout        = 15 * time.Second
	limaStartCommandTimeout = 20 * time.Second
	limaShellProbeTimeout   = 10 * time.Second
	limaBootPollInterval    = 2 * time.Second
	sessionBootTimeout      = 2 * time.Minute
	bakeBootTimeout         = 10 * time.Minute
	// healthPollInterval is how often WaitHealthy re-checks the guest agent.
	healthPollInterval = 2 * time.Second
)

// VM manages the Lima instance for one BoxedAi session: config generation,
// lifecycle (start/stop/delete), health gating, and harness launch.
type VM struct {
	Cfg Config
	// Binary is the path to the limactl executable; defaults to
	// "./bin/limactl" when empty.
	Binary string
}

// New returns a VM bound to cfg, using the default limactl binary path.
func New(cfg Config) *VM {
	return &VM{Cfg: cfg}
}

func (vm *VM) binary() string {
	if vm.Binary == "" {
		return defaultLimactl
	}
	return vm.Binary
}

// runLimactl execs the limactl binary with args, streaming to stdout/stderr
// as given. Both VM and BakeVM share this rather than each shelling out
// independently, since limactl argv plumbing (binary resolution, stdio
// wiring) is identical regardless of which instance is being driven.
func runLimactl(ctx context.Context, binary string, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func limaCreateArgs(name, yamlPath string) []string {
	return []string{"create", "--tty=false", "--name=" + name, yamlPath}
}

type limactlRunFunc func(context.Context, io.Writer, io.Writer, ...string) error

// startAndWaitForBoot starts a Lima instance with a bounded version of
// Lima's own readiness wait, then independently checks the boot-complete
// marker using plain limactl shell commands. Lima's internal readiness SSH
// command can hang even when these ordinary shell commands work.
func startAndWaitForBoot(ctx context.Context, name string, bootTimeout time.Duration, run limactlRunFunc) error {
	startCtx, cancelStart := context.WithTimeout(ctx, limaStartCommandTimeout)
	startErr := run(startCtx, os.Stdout, os.Stderr, "start", "--timeout="+limaStartTimeout.String(), name)
	cancelStart()
	if ctx.Err() != nil {
		return ctx.Err()
	}

	bootErr := waitForBootDone(ctx, name, bootTimeout, limaBootPollInterval, run)
	if bootErr == nil {
		return nil
	}
	if startErr != nil {
		return fmt.Errorf("limactl start: %v; %w", startErr, bootErr)
	}
	return bootErr
}

func waitForBootDone(
	ctx context.Context,
	name string,
	timeout time.Duration,
	pollInterval time.Duration,
	run limactlRunFunc,
) error {
	waitCtx, cancelWait := context.WithTimeout(ctx, timeout)
	defer cancelWait()

	for {
		probeCtx, cancelProbe := context.WithTimeout(waitCtx, limaShellProbeTimeout)
		err := run(probeCtx, io.Discard, io.Discard, "shell", name, "--", "test", "-f", "/run/lima-boot-done")
		cancelProbe()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("Lima boot marker not ready after %s", timeout)
		case <-time.After(pollInterval):
		}
	}
}

// run execs limactl with args, streaming to stdout/stderr as given.
func (vm *VM) run(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	return runLimactl(ctx, vm.binary(), stdout, stderr, args...)
}

// Start writes the session's lima.yaml, creates the instance, and boots it,
// streaming limactl's own progress straight to the user. It does not trust
// Lima's internal SSH readiness loop as the final boot signal.
func (vm *VM) Start(ctx context.Context) error {
	yamlPath, err := WriteLimaYAML(vm.Cfg)
	if err != nil {
		return err
	}
	if err := vm.run(ctx, os.Stdout, os.Stderr, limaCreateArgs(vm.Cfg.SessionID, yamlPath)...); err != nil {
		return fmt.Errorf("vm: limactl create: %w", err)
	}
	if err := startAndWaitForBoot(ctx, vm.Cfg.SessionID, sessionBootTimeout, vm.run); err != nil {
		return fmt.Errorf("vm: start instance %s: %w", vm.Cfg.SessionID, err)
	}
	return nil
}

// WaitHealthy polls until the guest's boxedai-guest-agent systemd unit
// reports active, or timeout elapses. The session layer calls this after
// Start and before emitting session.started / launching the harness
// (DESIGN.md session flow step 6: "abort, INCOMPLETE" on timeout).
func (vm *VM) WaitHealthy(ctx context.Context, timeout time.Duration) error {
	waitCtx, cancelWait := context.WithTimeout(ctx, timeout)
	defer cancelWait()

	for {
		var out strings.Builder
		// Best-effort: a not-yet-booted guest simply won't answer "active"
		// yet, so errors here are not fatal — only the deadline is.
		probeCtx, cancelProbe := context.WithTimeout(waitCtx, limaShellProbeTimeout)
		_ = vm.run(probeCtx, &out, io.Discard, "shell", vm.Cfg.SessionID, "--", "systemctl", "is-active", "boxedai-guest-agent")
		cancelProbe()
		if strings.TrimSpace(out.String()) == "active" {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("vm: guest agent not healthy after %s", timeout)
		case <-time.After(healthPollInterval):
		}
	}
}

// Stop is the kill switch: it asks the guest agent to freeze and drain via a
// sentinel file, waits out its grace window, then force-stops the instance.
// Delete is a separate call and must only happen after evidence is sealed.
func (vm *VM) Stop(ctx context.Context) error {
	// Best-effort: a half-provisioned or already-unhealthy guest may not
	// have a shell to run this against, but we still force-stop below.
	_ = vm.run(ctx, io.Discard, io.Discard, "shell", vm.Cfg.SessionID, "--", "sudo", "sh", "-c", "touch /etc/boxedai/stop")
	select {
	case <-time.After(stopGrace):
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := vm.run(ctx, os.Stdout, os.Stderr, "stop", "-f", vm.Cfg.SessionID); err != nil {
		return fmt.Errorf("vm: limactl stop: %w", err)
	}
	return nil
}

// Delete destroys the instance. Callers must only invoke this after evidence
// has been sealed: DESIGN.md's kill switch order is revoke -> freeze -> seal
// -> destroy.
func (vm *VM) Delete(ctx context.Context) error {
	if err := vm.run(ctx, os.Stdout, os.Stderr, "delete", vm.Cfg.SessionID); err != nil {
		return fmt.Errorf("vm: limactl delete: %w", err)
	}
	return nil
}

// BakeVM drives the one-off, throwaway Lima instance used to build the
// golden image (see internal/image): create/start it from a bake lima.yaml,
// then stop and delete it once its disk has been copied out. It deliberately
// exposes none of VM's health-gating or harness-launch surface — the bake
// boot installs software as root during provisioning and is torn down before
// any workload could ever run, so there is nothing to wait healthy or launch.
type BakeVM struct {
	// Name is the Lima instance name internal/image chose for the bake boot.
	Name string
	// LimaYAMLPath is the rendered bake lima.yaml path (see
	// WriteBakeLimaYAML).
	LimaYAMLPath string
	// Binary is the path to the limactl executable; defaults to
	// "./bin/limactl" when empty.
	Binary string
}

func (b *BakeVM) binary() string {
	if b.Binary == "" {
		return defaultLimactl
	}
	return b.Binary
}

func (b *BakeVM) run(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	return runLimactl(ctx, b.binary(), stdout, stderr, args...)
}

// Start creates and boots the bake instance, streaming limactl's own
// progress straight to the caller, then independently checking Lima's
// boot-complete marker.
func (b *BakeVM) Start(ctx context.Context) error {
	if err := b.run(ctx, os.Stdout, os.Stderr, limaCreateArgs(b.Name, b.LimaYAMLPath)...); err != nil {
		return fmt.Errorf("vm: limactl create: %w", err)
	}
	if err := startAndWaitForBoot(ctx, b.Name, bakeBootTimeout, b.run); err != nil {
		return fmt.Errorf("vm: start bake instance %s: %w", b.Name, err)
	}
	return nil
}

// Stop force-stops the bake instance. Unlike VM.Stop, there is no guest agent
// to signal and drain: the bake boot never runs one, so there is no sentinel
// file to write or grace window to wait out.
func (b *BakeVM) Stop(ctx context.Context) error {
	if err := runLimactl(ctx, b.binary(), os.Stdout, os.Stderr, "stop", "-f", b.Name); err != nil {
		return fmt.Errorf("vm: limactl stop: %w", err)
	}
	return nil
}

// Delete destroys the bake instance. Callers must copy the golden disk out of
// ~/.lima/<Name>/disk (see internal/image) before calling this.
func (b *BakeVM) Delete(ctx context.Context) error {
	if err := runLimactl(ctx, b.binary(), os.Stdout, os.Stderr, "delete", b.Name); err != nil {
		return fmt.Errorf("vm: limactl delete: %w", err)
	}
	return nil
}

// Verify checks that Claude Code's canonical native executable was installed
// successfully, resets cloud-init for the exported disk's next boot, then
// flushes the guest filesystem before the image is force-stopped and
// snapshotted.
// Lima's provision.system mode does not fail limactl start when an
// individual provisioning script errors — it logs a WARNING and moves on to
// the next script (confirmed empirically: an npm install failure during bake
// left `limactl start` exiting 0) — so Start returning nil is not proof
// provisioning actually succeeded. This is the actual gate.
func (b *BakeVM) Verify(ctx context.Context) error {
	return verifyBake(ctx, b.Name, b.run)
}

func verifyBake(ctx context.Context, name string, run limactlRunFunc) error {
	var verificationStdout strings.Builder
	var verificationStderr strings.Builder
	if err := run(ctx, &verificationStdout, &verificationStderr,
		"shell", name, "--",
		"sudo", "systemd-run",
		"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
		"--uid=agent",
		guestClaudeExecutable, "--version",
	); err != nil {
		var provisioningStdout strings.Builder
		var provisioningStderr strings.Builder
		logErr := run(ctx, &provisioningStdout, &provisioningStderr,
			"shell", name, "--",
			"sudo", "tail", "-n", "500", "/var/log/cloud-init-output.log",
		)

		diagnostics := make([]string, 0, 4)
		if output := strings.TrimSpace(verificationStdout.String()); output != "" {
			diagnostics = append(diagnostics, "verification stdout:\n"+output)
		}
		if output := strings.TrimSpace(verificationStderr.String()); output != "" {
			diagnostics = append(diagnostics, "verification stderr:\n"+output)
		}
		if output := strings.TrimSpace(provisioningStdout.String()); output != "" {
			diagnostics = append(diagnostics, "cloud-init provisioning log:\n"+output)
		}
		if output := strings.TrimSpace(provisioningStderr.String()); output != "" {
			diagnostics = append(diagnostics, "provisioning log retrieval stderr:\n"+output)
		}
		if logErr != nil {
			diagnostics = append(diagnostics, "could not retrieve cloud-init provisioning log: "+logErr.Error())
		}

		detail := ""
		if len(diagnostics) != 0 {
			detail = "\n" + strings.Join(diagnostics, "\n")
		}
		return fmt.Errorf("vm: bake VM %s: Claude Code executable verification failed%s: %w", name, detail, err)
	}
	// Cleaning cloud-init before verification would delete its provisioning
	// log, which is the decisive diagnostic when a CLI install fails. It also
	// must happen only for a disk that is otherwise ready to export. Without
	// this reset, a session boot from the exported disk can hang at Lima's user
	// session readiness gate because cloud-init does not repeat its user setup.
	if err := run(ctx, io.Discard, io.Discard,
		"shell", name, "--",
		"sudo", "cloud-init", "clean", "--logs", "--seed",
	); err != nil {
		return fmt.Errorf("vm: bake VM %s: cloud-init cleanup failed: %w", name, err)
	}
	if err := run(ctx, io.Discard, io.Discard, "shell", name, "--", "sudo", "sync"); err != nil {
		return fmt.Errorf("vm: bake VM %s: guest filesystem sync failed: %w", name, err)
	}
	return nil
}
