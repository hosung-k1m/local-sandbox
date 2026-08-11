package vm

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// guestWorkspaceMount is the fixed mount point inside the guest; DESIGN.md
// mounts sessions/<id>/workspace here as the workload's repository.
const guestWorkspaceMount = "/workspace"

// Claude Code writes its native debug log, transcripts, and other session
// state below this directory. Claude sessions mount a fresh, session-local
// host directory here so those diagnostics survive VM deletion without
// exposing the host's real ~/.claude directory to the guest.
const (
	claudeArtifactsDirName  = "claude-code"
	codexArtifactsDirName   = "codex"
	guestClaudeExecutable   = "/usr/local/bin/claude"
	guestClaudeConfigDir    = "/home/agent/.claude"
	guestClaudeDebugFile    = guestClaudeConfigDir + "/debug/claude-code.log"
	guestClaudeRawBodiesDir = guestClaudeConfigDir + "/raw-api-bodies"
	guestCodexConfigDir     = "/home/agent/.codex"
)

// agentUID is the unprivileged workload user's uid, fixed by DESIGN.md step 1.
const agentUID = 4242

// bakeDiskSize is the logical disk size for the one-off bake boot (see
// GenerateBakeLimaYAML), a plain Lima `disk:` size string. Lima's own vz
// default is much larger (100GiB observed); the bake boot only needs enough
// for Ubuntu + Node + two npm-global CLIs + Tetragon with headroom, and a
// smaller logical size keeps the exported golden image quicker to hash and
// copy.
const bakeDiskSize = "20GiB"

// limaTemplate is the subset of Lima's instance config schema BoxedAi needs.
// Field names match Lima's own YAML keys exactly.
type limaTemplate struct {
	VMType                string          `yaml:"vmType"`
	Arch                  string          `yaml:"arch"`
	Images                []limaImage     `yaml:"images"`
	Mounts                []limaMount     `yaml:"mounts"`
	MountTypesUnsupported []string        `yaml:"mountTypesUnsupported"`
	Containerd            limaContainerd  `yaml:"containerd"`
	Provision             []limaProvision `yaml:"provision"`
	// Disk is Lima's `disk:` logical-size override, e.g. "20GiB". Empty
	// (omitted) for real sessions, which use Lima's own vz default; set only
	// for the bake boot (see GenerateBakeLimaYAML / bakeDiskSize).
	Disk string `yaml:"disk,omitempty"`
}

type limaImage struct {
	Location string `yaml:"location"`
	Arch     string `yaml:"arch"`
}

type limaMount struct {
	Location   string `yaml:"location"`
	MountPoint string `yaml:"mountPoint"`
	Writable   bool   `yaml:"writable"`
}

type limaContainerd struct {
	System bool `yaml:"system"`
	User   bool `yaml:"user"`
}

type limaProvision struct {
	Mode   string `yaml:"mode"`
	Script string `yaml:"script"`
}

// GenerateLimaYAML renders the Lima instance configuration for a session:
// vmType vz on the host's own arch, the pre-baked golden image at
// cfg.ImagePath (see internal/image) instead of a freshly downloaded Ubuntu
// image, a writable (or read-only, for the review profile) workspace mount,
// and, for Claude only, a fresh session-local diagnostics mount. It exposes no
// other host directory, configures no port forwards, and ends its fast
// session-only provisioning with the nftables lockdown. It does not touch
// disk; see WriteLimaYAML.
func GenerateLimaYAML(cfg Config) (string, error) {
	if cfg.ImagePath == "" {
		return "", fmt.Errorf("vm: ImagePath is required")
	}
	arch, err := limaArch(cfg.Arch)
	if err != nil {
		return "", err
	}
	provision, err := provisionScripts(cfg)
	if err != nil {
		return "", err
	}
	mounts := []limaMount{{
		Location:   cfg.WorkspacePath,
		MountPoint: guestWorkspaceMount,
		Writable:   cfg.Writable,
	}}
	if cfg.Harness == "claude" || cfg.Harness == "codex" {
		mountPoint := guestClaudeConfigDir
		if cfg.Harness == "codex" {
			mountPoint = guestCodexConfigDir
		}
		mounts = append(mounts, limaMount{
			Location:   harnessHomePath(cfg),
			MountPoint: mountPoint,
			Writable:   true,
		})
	}
	tmpl := limaTemplate{
		VMType: "vz",
		Arch:   arch,
		Images: []limaImage{{Location: cfg.ImagePath, Arch: arch}},
		Mounts: mounts,
		// No other host directory is mounted, and reverse-sshfs (which
		// would otherwise let the guest reach back into the host FS) is
		// explicitly disallowed. portForwards is omitted entirely: DESIGN.md
		// requires none, and Lima treats an absent list the same as an empty
		// one, so there is nothing to marshal.
		MountTypesUnsupported: []string{"reverse-sshfs"},
		Containerd:            limaContainerd{System: false, User: false},
		Provision:             provision,
	}
	b, err := yaml.Marshal(tmpl)
	if err != nil {
		return "", fmt.Errorf("vm: marshal lima config: %w", err)
	}
	return string(b), nil
}

// WriteLimaYAML renders cfg's lima.yaml and writes it to
// <SessionDir>/vm/lima.yaml per DESIGN.md's host filesystem layout, returning
// the path so the caller can hand it to `limactl create`.
func WriteLimaYAML(cfg Config) (string, error) {
	content, err := GenerateLimaYAML(cfg)
	if err != nil {
		return "", err
	}
	if cfg.Harness == "claude" {
		if err := os.MkdirAll(filepath.Join(harnessHomePath(cfg), "debug"), 0o700); err != nil {
			return "", fmt.Errorf("vm: create Claude diagnostics dir: %w", err)
		}
		if err := os.MkdirAll(filepath.Join(harnessHomePath(cfg), "raw-api-bodies"), 0o700); err != nil {
			return "", fmt.Errorf("vm: create Claude raw API body dir: %w", err)
		}
	}
	dir := filepath.Join(cfg.SessionDir, "vm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("vm: create vm dir: %w", err)
	}
	path := filepath.Join(dir, "lima.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("vm: write lima.yaml: %w", err)
	}
	return path, nil
}

func harnessHomePath(cfg Config) string {
	if cfg.HarnessHomePath != "" {
		return cfg.HarnessHomePath
	}
	dir := claudeArtifactsDirName
	if cfg.Harness == "codex" {
		dir = codexArtifactsDirName
	}
	return filepath.Join(cfg.SessionDir, dir)
}

// GenerateBakeLimaYAML renders the Lima instance configuration for the
// one-off, throwaway VM used to build the golden image (see internal/image):
// vmType vz on the host's own arch, the stock downloaded Ubuntu 24.04 image
// (the ONE place that still downloads it — every real session instead boots
// cfg.ImagePath via GenerateLimaYAML), no mounts at all (the bake boot needs
// no host directory — it only installs software), a smaller bakeDiskSize
// logical disk than Lima's vz default, and the slow bake-only provisioning
// steps. It does not touch disk; see WriteBakeLimaYAML.
func GenerateBakeLimaYAML(cfg BakeConfig) (string, error) {
	arch, err := limaArch(cfg.Arch)
	if err != nil {
		return "", err
	}
	provision, err := bakeProvisionScripts(cfg)
	if err != nil {
		return "", err
	}
	tmpl := limaTemplate{
		VMType: "vz",
		Arch:   arch,
		Images: []limaImage{{Location: ubuntuImageURL(cfg.Arch), Arch: arch}},
		// No mounts: unlike a session, the bake boot never touches a
		// workspace, and reverse-sshfs is disallowed for the same reason it
		// is on real sessions — the guest must never reach back into the
		// host FS.
		MountTypesUnsupported: []string{"reverse-sshfs"},
		Containerd:            limaContainerd{System: false, User: false},
		Provision:             provision,
		Disk:                  bakeDiskSize,
	}
	b, err := yaml.Marshal(tmpl)
	if err != nil {
		return "", fmt.Errorf("vm: marshal bake lima config: %w", err)
	}
	return string(b), nil
}

// WriteBakeLimaYAML renders cfg's bake lima.yaml and writes it to
// <SessionDir>/vm/lima.yaml, mirroring WriteLimaYAML's layout. cfg.SessionDir
// is the scratch directory internal/image manages for the bake boot, not a
// real session directory. Returns the path so the caller can hand it to
// `limactl create` (see BakeVM in vm.go).
func WriteBakeLimaYAML(cfg BakeConfig) (string, error) {
	content, err := GenerateBakeLimaYAML(cfg)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfg.SessionDir, "vm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("vm: create vm dir: %w", err)
	}
	path := filepath.Join(dir, "lima.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("vm: write bake lima.yaml: %w", err)
	}
	return path, nil
}

// limaArch maps a Go GOARCH value to the arch string Lima's config expects.
func limaArch(goArch string) (string, error) {
	switch goArch {
	case "arm64":
		return "aarch64", nil
	case "amd64":
		return "x86_64", nil
	default:
		return "", fmt.Errorf("vm: unsupported arch %q", goArch)
	}
}

// ubuntuImageURL returns the official Ubuntu 24.04 cloud image location for
// goArch (Ubuntu's own image naming already matches Go's GOARCH values).
func ubuntuImageURL(goArch string) string {
	return fmt.Sprintf("https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-%s.img", goArch)
}
