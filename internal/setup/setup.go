// Package setup contains the host preflight used by BoxedAi. VM dependencies
// are installed into each disposable VM from public sources, so setup has no
// company certificate, VPN, registry, or image-build state.
package setup

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"boxedai/internal/session"
)

const Schema = "boxedai.setup/v1"

type Check struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type Action struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Instructions string `json:"instructions"`
}
type Problem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Result struct {
	Schema  string   `json:"schema"`
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Status  string   `json:"status"`
	Ready   bool     `json:"ready"`
	Arch    string   `json:"arch"`
	Home    string   `json:"home"`
	Checks  []Check  `json:"checks"`
	Actions []Action `json:"actions,omitempty"`
	Error   *Problem `json:"error,omitempty"`
}
type StageEvent struct {
	Schema  string `json:"schema"`
	Type    string `json:"type"`
	Command string `json:"command"`
	Stage   string `json:"stage"`
	Status  string `json:"status"`
}
type Options struct {
	Arch        string
	ProgressOut io.Writer
	ProgressErr io.Writer
	Emit        func(StageEvent)
}

var (
	currentGOOS   = runtime.GOOS
	currentGOARCH = runtime.GOARCH
	lookPath      = exec.LookPath
	runOutput     = commandOutput
	checkNetwork  = tlsReachable
)

func Doctor(ctx context.Context, arch string) Result { return inspect(ctx, arch, "doctor") }
func Run(ctx context.Context, opts Options) Result {
	if opts.Emit != nil {
		opts.Emit(StageEvent{Schema: Schema, Type: "stage", Command: "setup", Stage: "preflight", Status: "running"})
	}
	r := inspect(ctx, opts.Arch, "setup")
	if opts.Emit != nil {
		opts.Emit(StageEvent{Schema: Schema, Type: "stage", Command: "setup", Stage: "preflight", Status: "complete"})
	}
	return r
}

func inspect(ctx context.Context, arch, command string) Result {
	r := Result{Schema: Schema, Type: "result", Command: command, Arch: arch, Home: session.Home()}
	blocked := false
	add := func(id, status, message string, action *Action) {
		r.Checks = append(r.Checks, Check{ID: id, Status: status, Message: message})
		if status == "fail" && action != nil {
			r.Actions = append(r.Actions, *action)
		}
	}
	if currentGOOS != "darwin" {
		blocked = true
		add("host_os", "fail", "BoxedAi requires macOS.", &Action{"use_macos", "Use a supported Mac", "Run BoxedAi on macOS with Virtualization.framework support."})
	} else {
		add("host_os", "pass", "Host is macOS.", nil)
	}
	if arch != currentGOARCH || (arch != "arm64" && arch != "amd64") {
		blocked = true
		add("host_arch", "fail", "The requested architecture must match this Mac.", &Action{"use_host_arch", "Use the host architecture", fmt.Sprintf("Retry with --arch %s.", currentGOARCH)})
	} else {
		add("host_arch", "pass", fmt.Sprintf("Host architecture %s is supported.", arch), nil)
	}
	if out, err := runOutput(ctx, "sysctl", "-n", "kern.hv_support"); err != nil || strings.TrimSpace(out) != "1" {
		blocked = true
		add("virtualization", "fail", "Apple virtualization support is unavailable.", &Action{"enable_virtualization", "Enable virtualization", "Use a Mac that supports Virtualization.framework."})
	} else {
		add("virtualization", "pass", "Apple virtualization support is available.", nil)
	}
	for _, command := range []string{"limactl", "git", "gh", "ssh"} {
		name := filepath.Base(command)
		if _, err := lookPath(command); err != nil {
			blocked = true
			add("command_"+name, "fail", fmt.Sprintf("Required command %s is unavailable.", command), &Action{"install_" + name, "Install " + name, "Install or restore " + name + " and retry."})
		} else {
			add("command_"+name, "pass", fmt.Sprintf("Required command %s is available.", command), nil)
		}
	}
	for _, endpoint := range []string{"cloud-images.ubuntu.com:443", "registry.npmjs.org:443", "github.com:443"} {
		id := "network_" + strings.ReplaceAll(strings.Split(endpoint, ":")[0], ".", "_")
		if err := checkNetwork(ctx, endpoint); err != nil {
			blocked = true
			add(id, "fail", "Cannot establish trusted TLS to "+endpoint+".", &Action{"check_network", "Check internet access", "Connect to an internet connection and retry."})
		} else {
			add(id, "pass", "Trusted TLS is available to "+endpoint+".", nil)
		}
	}
	if blocked {
		r.Status = "action_required"
	} else {
		r.Status, r.Ready = "ready", true
	}
	return r
}

func commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	b, err := exec.CommandContext(ctx, name, args...).Output()
	return string(b), err
}
func tlsReachable(ctx context.Context, endpoint string) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return err
	}
	return conn.Close()
}
