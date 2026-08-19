// Package setup owns host readiness checks and the idempotent first-run setup
// used by UI integrations such as Blockwatch.
package setup

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"boxedai/internal/image"
	"boxedai/internal/session"
)

const (
	Schema           = "boxedai.setup/v1"
	CorporateCAName  = "Cloudflare Gateway CA"
	BlockNPMRegistry = "https://global.block-artifacts.com/artifactory/api/npm/square-npm/"
	minimumFreeDisk  = 10 * 1024 * 1024 * 1024
	networkTimeout   = 5 * time.Second
)

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

type ImageStatus struct {
	Status  string    `json:"status"`
	Tag     string    `json:"tag,omitempty"`
	Digest  string    `json:"digest,omitempty"`
	BuiltAt time.Time `json:"built_at,omitempty"`
}

type Problem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Result struct {
	Schema  string       `json:"schema"`
	Type    string       `json:"type"`
	Command string       `json:"command"`
	Status  string       `json:"status"`
	Ready   bool         `json:"ready"`
	Arch    string       `json:"arch"`
	Home    string       `json:"home"`
	Checks  []Check      `json:"checks"`
	Actions []Action     `json:"actions,omitempty"`
	Image   *ImageStatus `json:"image,omitempty"`
	Error   *Problem     `json:"error,omitempty"`
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

type inspection struct {
	checks  []Check
	actions []Action
	caPEM   string
	image   *ImageStatus
	blocked bool
}

var (
	currentGOOS     = runtime.GOOS
	currentGOARCH   = runtime.GOARCH
	lookPath        = exec.LookPath
	runOutput       = commandOutput
	freeDisk        = availableDisk
	checkNetwork    = tlsReachable
	loadCorporateCA = findCorporateCA
	resolveImage    = image.Resolve
	buildImage      = image.BuildWithOutput
)

func Doctor(ctx context.Context, arch string) Result {
	inspected := inspectHost(ctx, arch, true)
	result := baseResult("doctor", arch, inspected)
	if inspected.blocked {
		result.Status = "action_required"
		return result
	}
	result.Status = "ready"
	result.Ready = true
	return result
}

func Run(ctx context.Context, opts Options) Result {
	emit(opts.Emit, "preflight", "running")
	inspected := inspectHost(ctx, opts.Arch, false)
	emit(opts.Emit, "preflight", "complete")
	if inspected.blocked {
		result := baseResult("setup", opts.Arch, inspected)
		result.Status = "action_required"
		return result
	}

	emit(opts.Emit, "configure", "running")
	if err := writeCorporateConfig(inspected.caPEM); err != nil {
		return failedResult("setup", opts.Arch, inspected.checks, "config_write_failed", "Could not write the BoxedAi host configuration: "+safeCause(err))
	}
	publicKey, publicPath, err := session.EnsureHumanSSHKeypair()
	if err != nil {
		return failedResult("setup", opts.Arch, inspected.checks, "human_ssh_key_failed", "Could not prepare the controller-owned human SSH keypair: "+safeCause(err))
	}
	fingerprint := session.HumanSSHPublicKeyFingerprint(publicKey)
	emit(opts.Emit, "configure", "complete")

	emit(opts.Emit, "image", "running")
	m, err := resolveImage(opts.Arch)
	if err != nil || !imageMatchesConfig(m, inspected.caPEM) {
		m, err = buildImage(ctx, opts.Arch, inspected.caPEM, BlockNPMRegistry, opts.ProgressOut, opts.ProgressErr)
		if err != nil {
			return failedResult("setup", opts.Arch, inspected.checks, "image_build_failed", "The golden sandbox image could not be built or verified: "+safeCause(err))
		}
	}
	emit(opts.Emit, "image", "complete")

	checks := append(inspected.checks,
		Check{ID: "host_config", Status: "pass", Message: "Corporate CA and Block npm registry are configured."},
		Check{ID: "human_ssh_key", Status: "pass", Message: fmt.Sprintf("Human SSH key fingerprint %s at %s.", fingerprint, publicPath)},
		Check{ID: "golden_image", Status: "pass", Message: "Golden sandbox image is built and verified."},
	)
	return Result{
		Schema:  Schema,
		Type:    "result",
		Command: "setup",
		Status:  "ready",
		Ready:   true,
		Arch:    opts.Arch,
		Home:    session.Home(),
		Checks:  checks,
		Image:   manifestStatus(m, "ready"),
	}
}

func inspectHost(ctx context.Context, arch string, includeConfiguredState bool) inspection {
	result := inspection{}
	add := func(check Check, action *Action) {
		result.checks = append(result.checks, check)
		if check.Status == "fail" {
			result.blocked = true
			if action != nil {
				appendAction(&result.actions, *action)
			}
		}
	}

	if currentGOOS != "darwin" {
		add(Check{ID: "host_os", Status: "fail", Message: "BoxedAi requires macOS."}, &Action{ID: "use_macos", Title: "Use a supported Mac", Instructions: "Run BoxedAi on macOS with Virtualization.framework support."})
	} else {
		add(Check{ID: "host_os", Status: "pass", Message: "Host is macOS."}, nil)
	}
	if arch != currentGOARCH || (arch != "arm64" && arch != "amd64") {
		add(Check{ID: "host_arch", Status: "fail", Message: "The requested image architecture must match this Mac."}, &Action{ID: "use_host_arch", Title: "Use the host architecture", Instructions: fmt.Sprintf("Retry setup with --arch %s.", currentGOARCH)})
	} else {
		add(Check{ID: "host_arch", Status: "pass", Message: fmt.Sprintf("Host architecture %s is supported.", arch)}, nil)
	}

	if output, err := runOutput(ctx, "sysctl", "-n", "kern.hv_support"); err != nil || strings.TrimSpace(output) != "1" {
		add(Check{ID: "virtualization", Status: "fail", Message: "Apple virtualization support is unavailable."}, &Action{ID: "enable_virtualization", Title: "Enable virtualization", Instructions: "Use a Mac that supports Virtualization.framework and ensure virtualization is enabled."})
	} else {
		add(Check{ID: "virtualization", Status: "pass", Message: "Apple virtualization support is available."}, nil)
	}

	for _, command := range []string{"./bin/limactl", "git", "gh", "ssh", "security"} {
		id := strings.TrimPrefix(filepath.Base(command), ".")
		if _, err := lookPath(command); err != nil {
			add(Check{ID: "command_" + id, Status: "fail", Message: fmt.Sprintf("Required command %s is unavailable.", command)}, &Action{ID: "install_" + id, Title: fmt.Sprintf("Install %s", id), Instructions: fmt.Sprintf("Install or restore %s, then retry setup.", command)})
		} else {
			add(Check{ID: "command_" + id, Status: "pass", Message: fmt.Sprintf("Required command %s is available.", command)}, nil)
		}
	}

	if bytes, err := freeDisk(session.Home()); err != nil {
		add(Check{ID: "disk", Status: "fail", Message: "Available disk space could not be determined."}, &Action{ID: "check_disk", Title: "Check disk space", Instructions: "Ensure the BoxedAi home is on a writable volume with at least 10 GiB free."})
	} else if bytes < minimumFreeDisk {
		add(Check{ID: "disk", Status: "fail", Message: "Less than 10 GiB is available for the sandbox image."}, &Action{ID: "free_disk", Title: "Free disk space", Instructions: "Free at least 10 GiB on the volume containing BOXEDAI_HOME, then retry setup."})
	} else {
		add(Check{ID: "disk", Status: "pass", Message: "Sufficient disk space is available."}, nil)
	}

	for _, endpoint := range []string{"cloud-images.ubuntu.com:443", "global.block-artifacts.com:443"} {
		id := "network_" + strings.ReplaceAll(strings.Split(endpoint, ":")[0], ".", "_")
		if err := checkNetwork(ctx, endpoint); err != nil {
			add(Check{ID: id, Status: "fail", Message: fmt.Sprintf("Cannot establish trusted TLS to %s.", endpoint)}, &Action{ID: "connect_corporate_network", Title: "Connect to the corporate network", Instructions: "Connect Cloudflare WARP and confirm the corporate network is available, then retry setup."})
		} else {
			add(Check{ID: id, Status: "pass", Message: fmt.Sprintf("Trusted TLS is available to %s.", endpoint)}, nil)
		}
	}

	caPEM, err := loadCorporateCA(ctx)
	if err != nil {
		warpPresent := warpInstalled()
		title := "Install and connect Cloudflare WARP"
		if warpPresent {
			title = "Connect Cloudflare WARP"
		}
		add(Check{ID: "corporate_ca", Status: "fail", Message: "A valid Cloudflare Gateway CA was not found in the macOS keychains."}, &Action{ID: "install_corporate_ca", Title: title, Instructions: "Enable Cloudflare WARP until the Cloudflare Gateway CA appears in a macOS keychain, then retry setup."})
	} else {
		result.caPEM = caPEM
		add(Check{ID: "corporate_ca", Status: "pass", Message: "A valid Cloudflare Gateway CA is installed."}, nil)
	}

	if includeConfiguredState && caPEM != "" {
		inspectConfiguredState(&result, arch, caPEM)
	}
	return result
}

func inspectConfiguredState(result *inspection, arch, caPEM string) {
	hc, err := session.LoadHostConfig()
	configPath := filepath.Join(session.Home(), "config.json")
	configReady := err == nil && digest(hc.ExtraCAPEM) == digest(caPEM) && hc.NPMRegistry == BlockNPMRegistry
	if info, statErr := os.Stat(configPath); statErr != nil || info.Mode().Perm() != 0o600 {
		configReady = false
	}
	if !configReady {
		result.blocked = true
		result.checks = append(result.checks, Check{ID: "host_config", Status: "fail", Message: "BoxedAi corporate configuration is missing, stale, or has unsafe permissions."})
		appendAction(&result.actions, Action{ID: "run_setup", Title: "Run BoxedAi setup", Instructions: "Run boxedai setup to configure the corporate CA, npm registry, and image."})
	} else {
		result.checks = append(result.checks, Check{ID: "host_config", Status: "pass", Message: "Corporate CA and Block npm registry are configured."})
	}

	m, imageErr := resolveImage(arch)
	if imageErr != nil || !imageMatchesConfig(m, caPEM) {
		result.blocked = true
		result.checks = append(result.checks, Check{ID: "golden_image", Status: "fail", Message: "The golden sandbox image is missing, invalid, or stale."})
		appendAction(&result.actions, Action{ID: "run_setup", Title: "Build the sandbox image", Instructions: "Run boxedai setup to build and verify the golden image."})
	} else {
		result.checks = append(result.checks, Check{ID: "golden_image", Status: "pass", Message: "Golden sandbox image is built and verified."})
		result.image = manifestStatus(m, "ready")
	}
}

func baseResult(command, arch string, inspected inspection) Result {
	return Result{Schema: Schema, Type: "result", Command: command, Arch: arch, Home: session.Home(), Checks: inspected.checks, Actions: inspected.actions, Image: inspected.image}
}

func failedResult(command, arch string, checks []Check, code, message string) Result {
	return Result{Schema: Schema, Type: "result", Command: command, Status: "failed", Arch: arch, Home: session.Home(), Checks: checks, Error: &Problem{Code: code, Message: message}}
}

func emit(fn func(StageEvent), stage, status string) {
	if fn != nil {
		fn(StageEvent{Schema: Schema, Type: "stage", Command: "setup", Stage: stage, Status: status})
	}
}

func appendAction(actions *[]Action, action Action) {
	for _, existing := range *actions {
		if existing.ID == action.ID {
			return
		}
	}
	*actions = append(*actions, action)
}

func safeCause(err error) string {
	message := err.Error()
	for {
		start := strings.Index(message, "-----BEGIN CERTIFICATE-----")
		if start == -1 {
			break
		}
		end := strings.Index(message[start:], "-----END CERTIFICATE-----")
		if end == -1 {
			message = message[:start] + "[certificate omitted]"
			break
		}
		end += start + len("-----END CERTIFICATE-----")
		message = message[:start] + "[certificate omitted]" + message[end:]
	}
	message = strings.TrimSpace(message)
	runes := []rune(message)
	if len(runes) > 4000 {
		message = string(runes[:4000]) + "…"
	}
	return message
}

func manifestStatus(m image.Manifest, status string) *ImageStatus {
	return &ImageStatus{Status: status, Tag: m.Tag, Digest: m.DiskDigest, BuiltAt: m.BuiltAt}
}

func imageMatchesConfig(m image.Manifest, caPEM string) bool {
	return m.HWEKernel && m.ExtraCADigest == digest(caPEM) && m.NPMRegistry == BlockNPMRegistry
}

func digest(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func findCorporateCA(ctx context.Context) (string, error) {
	output, err := runOutput(ctx, "security", "find-certificate", "-a", "-c", CorporateCAName, "-p")
	if err != nil {
		return "", err
	}
	rest := []byte(output)
	for len(rest) != 0 {
		block, remaining := pem.Decode(rest)
		rest = remaining
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !cert.IsCA || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			continue
		}
		return string(pem.EncodeToMemory(block)), nil
	}
	return "", fmt.Errorf("no valid certificate named %s", CorporateCAName)
}

func writeCorporateConfig(caPEM string) error {
	home := session.Home()
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	path := filepath.Join(home, "config.json")
	config := map[string]json.RawMessage{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &config); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	caJSON, _ := json.Marshal(caPEM)
	registryJSON, _ := json.Marshal(BlockNPMRegistry)
	config["extra_ca_pem"] = caJSON
	config["npm_registry"] = registryJSON
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	b, err := exec.CommandContext(ctx, name, args...).Output()
	return string(b), err
}

func availableDisk(path string) (uint64, error) {
	probe := path
	for {
		if _, err := os.Stat(probe); err == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(probe, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

func tlsReachable(ctx context.Context, endpoint string) error {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: networkTimeout},
		Config:    &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
	}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return err
	}
	return conn.Close()
}

func warpInstalled() bool {
	if _, err := lookPath("warp-cli"); err == nil {
		return true
	}
	_, err := os.Stat("/Applications/Cloudflare WARP.app")
	return err == nil
}
