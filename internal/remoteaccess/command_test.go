package remoteaccess

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func TestCommandTransportReauthorizesBeforeFixedHostCommand(t *testing.T) {
	command := HostCommand{Program: "boxedai-browser-terminal", Args: []string{"--listen", "127.0.0.1"}}
	transport := NewCommandTransport(map[evidence.AccessSurface]HostCommand{
		evidence.AccessSurfaceBrowserTerminal: command,
	})
	transport.lookPath = func(program string) (string, error) {
		if program != command.Program {
			t.Fatalf("program = %q, want %q", program, command.Program)
		}
		return "/host/bin/boxedai-browser-terminal", nil
	}
	var gotProgram string
	var gotArgs []string
	transport.run = func(_ context.Context, program string, args ...string) error {
		gotProgram = program
		gotArgs = append([]string(nil), args...)
		return nil
	}
	plan, err := NewController(testBroker(time.Now().Add(time.Hour), true), transport).Prepare(testRequest(evidence.AccessSurfaceBrowserTerminal))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	plan.WorkingDirectory = "/workspace"
	authorized := 0
	if err := transport.Launch(context.Background(), plan, func() error {
		authorized++
		return nil
	}); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if authorized != 1 {
		t.Fatalf("authorize calls = %d, want 1", authorized)
	}
	if gotProgram != "/host/bin/boxedai-browser-terminal" || !reflect.DeepEqual(gotArgs, command.Args) {
		t.Fatalf("command = %q %q, want fixed adapter command", gotProgram, gotArgs)
	}
	for _, value := range append(gotArgs, gotProgram) {
		if strings.Contains(value, "/workspace") || strings.Contains(value, "credential") {
			t.Fatalf("adapter command leaked plan routing or a credential: %q", value)
		}
	}
}

func TestCommandTransportFailsClosedBeforeExecution(t *testing.T) {
	plan, err := NewController(testBroker(time.Now().Add(time.Hour), true), nil).Prepare(testRequest(evidence.AccessSurfaceBrowserTerminal))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for _, tc := range []struct {
		name      string
		transport *CommandTransport
		want      error
	}{
		{
			name:      "adapter missing",
			transport: NewCommandTransport(nil),
			want:      ErrTransportUnavailable,
		},
		{
			name: "binary missing",
			transport: func() *CommandTransport {
				transport := NewCommandTransport(map[evidence.AccessSurface]HostCommand{evidence.AccessSurfaceBrowserTerminal: HostCommand{Program: "missing-adapter"}})
				transport.lookPath = func(string) (string, error) { return "", errors.New("missing") }
				return transport
			}(),
			want: ErrHostCommandUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.transport.Launch(context.Background(), plan, func() error { return nil }); !errors.Is(err, tc.want) {
				t.Fatalf("Launch() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSSHConfigBindsOnlyTheMediatedWorkspace(t *testing.T) {
	controller := NewController(testBroker(time.Now().Add(time.Hour), true), nil)
	plan, err := controller.Prepare(testRequest(evidence.AccessSurfaceVSCodeRemoteSSH))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	config, err := SSHConfig(plan, "boxedai-ssh-proxy")
	if err != nil {
		t.Fatalf("SSHConfig: %v", err)
	}
	for _, want := range []string{
		"Host boxedai-session-1",
		"User human",
		"ProxyCommand boxedai-ssh-proxy --session session-1 --grant grant-1 --surface vscode_remote_ssh --uid 5000 --workspace /workspace",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("config missing %q: %s", want, config)
		}
	}
	for _, forbidden := range []string{"workspace-lower", "credential-digest", "limactl shell", "token"} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("config contains %q: %s", forbidden, config)
		}
	}
	plan.WorkingDirectory = "/other"
	if _, err := SSHConfig(plan, "boxedai-ssh-proxy"); !errors.Is(err, ErrWorkspaceTarget) {
		t.Fatalf("SSHConfig redirected workspace error = %v, want %v", err, ErrWorkspaceTarget)
	}
	plan.WorkingDirectory = WorkspaceTarget
	plan.Descriptor.SessionID = "session-1; injected"
	if _, err := SSHConfig(plan, "boxedai-ssh-proxy"); !errors.Is(err, ErrHostConfigurationUnavailable) {
		t.Fatalf("SSHConfig injected session error = %v, want unavailable configuration", err)
	}
}

func TestSSHCommandUsesLocalIdentityPathWithoutSecrets(t *testing.T) {
	plan, err := NewController(testBroker(time.Now().Add(time.Hour), true), nil).Prepare(testRequest(evidence.AccessSurfaceBrowserTerminal))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	command, err := SSHCommand(plan, "boxedai-ssh-proxy", "/Users/operator/.config/boxedai/human-ssh/id_ed25519")
	if err != nil {
		t.Fatalf("SSHCommand: %v", err)
	}
	for _, want := range []string{
		"ssh -i '/Users/operator/.config/boxedai/human-ssh/id_ed25519'",
		"-o User=human",
		"--session session-1 --grant grant-1 --surface browser_terminal --uid 5000 --workspace /workspace",
		"'boxedai-session-1'",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("command missing %q: %s", want, command)
		}
	}
	for _, forbidden := range []string{"credential-digest", "private_key", "limactl shell"} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("command contains %q: %s", forbidden, command)
		}
	}
}

func TestSSHCommandRejectsIDEAndUnsafeIdentityPath(t *testing.T) {
	controller := NewController(testBroker(time.Now().Add(time.Hour), true), nil)
	plan, err := controller.Prepare(testRequest(evidence.AccessSurfaceVSCodeRemoteSSH))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := SSHCommand(plan, "boxedai-ssh-proxy", "identity"); !errors.Is(err, ErrHostConfigurationUnavailable) {
		t.Fatalf("IDE surface error = %v, want unavailable configuration", err)
	}
	plan, err = controller.Prepare(testRequest(evidence.AccessSurfaceBrowserTerminal))
	if err != nil {
		t.Fatalf("Prepare browser: %v", err)
	}
	if _, err := SSHCommand(plan, "boxedai-ssh-proxy", "/bad path"); !errors.Is(err, ErrHostConfigurationUnavailable) {
		t.Fatalf("unsafe identity path error = %v, want unavailable configuration", err)
	}
}
