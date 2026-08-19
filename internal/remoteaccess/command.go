package remoteaccess

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"boxedai/internal/evidence"
)

// HostCommand is a controller-local adapter command. It carries no broker or
// workload credentials; session and grant authorization remains in Controller.
type HostCommand struct {
	Program string
	Args    []string
}

// CommandTransport starts an explicitly configured host-local adapter after
// reauthorizing the request. It intentionally has no default commands: this
// repository does not provision a browser PTY service or an OpenSSH endpoint.
// Callers must configure an adapter for each surface they intend to offer.
type CommandTransport struct {
	commands map[evidence.AccessSurface]HostCommand
	lookPath func(string) (string, error)
	run      func(context.Context, string, ...string) error
}

// NewCommandTransport creates a transport from the controller-owned adapter
// map. The commands are copied so later caller mutation cannot change routing.
func NewCommandTransport(commands map[evidence.AccessSurface]HostCommand) *CommandTransport {
	copied := make(map[evidence.AccessSurface]HostCommand, len(commands))
	for surface, command := range commands {
		copied[surface] = HostCommand{Program: command.Program, Args: append([]string(nil), command.Args...)}
	}
	return &CommandTransport{
		commands: copied,
		lookPath: exec.LookPath,
		run: func(ctx context.Context, program string, args ...string) error {
			return exec.CommandContext(ctx, program, args...).Run()
		},
	}
}

// SSHConfig is the secret-free OpenSSH handoff fragment for an IDE surface.
// It deliberately supplies no identity, port, or endpoint: those are owned by
// a controller-managed SSH adapter and must be present before a client launch
// is admitted. The proxy runs the restricted limactl path itself; the client
// never receives a Lima management identity. The ProxyCommand is fixed
// controller data, never CLI input.
func SSHConfig(plan LaunchPlan, proxy string) (string, error) {
	return SSHConfigWithIdentity(plan, proxy, "")
}

// SSHConfigWithIdentity returns the secret-free OpenSSH handoff fragment for
// an IDE surface. The identity path is a local filesystem path; private key
// bytes are never placed in the config or launch plan.
func SSHConfigWithIdentity(plan LaunchPlan, proxy, identityPath string) (string, error) {
	if plan.Descriptor.Surface != evidence.AccessSurfaceVSCodeRemoteSSH && plan.Descriptor.Surface != evidence.AccessSurfaceIntelliJRemoteDev {
		return "", fmt.Errorf("%w: %s does not use OpenSSH", ErrHostConfigurationUnavailable, plan.Descriptor.Surface)
	}
	if err := validatePlan(plan); err != nil {
		return "", err
	}
	if !safeSSHConfigToken(proxy) || !safeSSHConfigToken(plan.Descriptor.SessionID) || (identityPath != "" && !safeSSHConfigToken(identityPath)) {
		return "", fmt.Errorf("%w: controller SSH proxy is required", ErrHostConfigurationUnavailable)
	}
	alias := sshAlias(plan.Descriptor.SessionID)
	config := "Host " + alias + "\n" +
		"  HostName " + alias + "\n" +
		"  User human\n" +
		"  IdentitiesOnly yes\n" +
		"  ProxyCommand " + proxy + " --session " + plan.Descriptor.SessionID + " --grant " + plan.Descriptor.GrantID + " --surface " + string(plan.Descriptor.Surface) + " --uid 5000 --workspace /workspace\n"
	if identityPath != "" {
		config += "  IdentityFile " + identityPath + "\n"
	}
	return config, nil
}

// SSHCommand returns a copyable local-terminal handoff. It uses the same
// controller proxy and grant admission as IDE clients and contains no key
// material.
func SSHCommand(plan LaunchPlan, proxy, identityPath string) (string, error) {
	if plan.Descriptor.Surface != evidence.AccessSurfaceBrowserTerminal {
		return "", fmt.Errorf("%w: %s does not use terminal SSH", ErrHostConfigurationUnavailable, plan.Descriptor.Surface)
	}
	if err := validatePlan(plan); err != nil {
		return "", err
	}
	if !safeSSHConfigToken(proxy) || !safeSSHConfigToken(plan.Descriptor.SessionID) || (identityPath != "" && !safeSSHConfigToken(identityPath)) {
		return "", fmt.Errorf("%w: controller SSH proxy is required", ErrHostConfigurationUnavailable)
	}
	command := "ssh"
	if identityPath != "" {
		command += " -i " + shellQuote(identityPath)
	}
	command += " -o User=human -o IdentitiesOnly=yes -o ProxyCommand=" + shellQuote(proxy+" --session "+plan.Descriptor.SessionID+" --grant "+plan.Descriptor.GrantID+" --surface "+string(plan.Descriptor.Surface)+" --uid 5000 --workspace /workspace") + " " + shellQuote(sshAlias(plan.Descriptor.SessionID))
	return command, nil
}

func sshAlias(sessionID string) string {
	return "boxedai-" + sessionID
}

func safeSSHConfigToken(value string) bool {
	return value != "" && !strings.ContainsAny(value, " \t\r\n\\\"'")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\\"'\\\"'") + "'"
}

// Launch verifies adapter availability before it executes it, and asks the
// controller to reauthorize immediately before process admission. The command
// is deliberately not serialized into LaunchPlan, which remains a secret-free
// and client-agnostic session artifact.
func (t *CommandTransport) Launch(ctx context.Context, plan LaunchPlan, authorize func() error) error {
	if t == nil {
		return ErrTransportUnsupported
	}
	if err := validatePlan(plan); err != nil {
		return err
	}
	command, ok := t.commands[plan.Descriptor.Surface]
	if !ok || command.Program == "" {
		return fmt.Errorf("%w: %s has no configured controller-local adapter", ErrTransportUnavailable, plan.Descriptor.Surface)
	}
	program, err := t.lookPath(command.Program)
	if err != nil {
		return fmt.Errorf("%w: %s requires %q", ErrHostCommandUnavailable, plan.Descriptor.Surface, command.Program)
	}
	if err := authorize(); err != nil {
		return err
	}
	if err := t.run(ctx, program, command.Args...); err != nil {
		return fmt.Errorf("remote access: run %s adapter: %w", plan.Descriptor.Surface, err)
	}
	return nil
}
