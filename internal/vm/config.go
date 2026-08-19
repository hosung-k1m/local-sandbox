// Package vm generates per-session Lima instance configuration, drives the VM
// lifecycle (create/start/stop/delete), gates on guest-agent health, and
// launches the interactive harness inside a hardened systemd-run unit. See
// DESIGN.md "VM (internal/vm) and guest supervisor" and "Harness launch".
package vm

import (
	"boxedai/internal/evidence"
	"boxedai/internal/policy"
	"boxedai/internal/remoteaccess"
)

// Config is everything GenerateLimaYAML and LaunchHarness need to stand up
// one session's VM and drive its interactive harness. The session package
// builds one per run; nothing in this package mutates it.
type Config struct {
	// SessionID is also the Lima instance name.
	SessionID string
	// AgentID is the controller-minted Primary Agent id, exposed to the Claude
	// hook (as BOXEDAI_AGENT_ID) so registered subagents can name it as parent.
	AgentID string
	// SessionDir is the host session directory, e.g. ~/.boxedai/sessions/<id>.
	SessionDir string
	// WorkspacePath is the host path mounted into the guest at /workspace.
	WorkspacePath string
	// HarnessHomePath is a fresh session-scoped home for harness instructions
	// and diagnostics. Empty disables the harness home mount.
	HarnessHomePath string
	// Writable is false for the review profile (read-only mount).
	Writable bool
	// MediatedWorkspace routes a writable workspace through the guest FUSE
	// boundary. The controller enables it only after the sealed runtime contract
	// has established that attributable writes are supported.
	MediatedWorkspace bool
	// SubjectMap and HumanAccessGrant are sealed controller bindings consumed by
	// the guest mediator. They are required when MediatedWorkspace is enabled.
	SubjectMap       *evidence.SessionSubjectMap
	HumanAccessGrant *evidence.HumanAccessGrant
	// RemoteAccessEndpoint describes the private guest socket the controller
	// may use for human access. Nil keeps the production endpoint disabled.
	RemoteAccessEndpoint *remoteaccess.GuestEndpoint
	// HumanAccessPublicKey is the controller-issued ephemeral SSH public key.
	// The corresponding private key never enters the guest or launch plan.
	HumanAccessPublicKey string
	// BrokerHost is the guest-reachable broker hostname, "host.lima.internal".
	BrokerHost string
	// BrokerPort is the broker's listen port.
	BrokerPort int
	// WorkloadToken (W) is injected into the harness environment.
	WorkloadToken string
	// GitHubRepository is the single owner/name repository the host broker
	// exposes through its Git SSH bridge. Empty disables guest GitHub access.
	GitHubRepository string
	// GitHubSSHURL is the exact host-gh-resolved SSH URL for that repository.
	GitHubSSHURL string
	// GitHubRemote is the original snapshot remote rewritten to that broker
	// endpoint inside the harness process.
	GitHubRemote string
	// SupervisorToken (S) is written to the guest-only agent config, never
	// exposed to the workload.
	SupervisorToken string
	// Harness selects the workload: "claude", "codex", or "exec".
	Harness string
	// Cmd is the shell command run for the "exec" harness.
	Cmd string
	// HarnessArgs are extra argv appended after "claude"/"codex" in the guest
	// launch command, e.g. ["-p", "prompt"] for scripted/non-interactive runs.
	// Never applied to the "exec" harness, which uses Cmd instead.
	HarnessArgs []string
	// Limits are the systemd-run resource properties for the harness unit.
	Limits policy.Limits
	// ImagePath is the host filesystem path to the pre-baked golden Lima disk
	// image (see internal/image), used as the Lima `images:` location instead
	// of downloading the stock Ubuntu cloud image on every session boot.
	ImagePath string
	// Arch is the host's GOARCH ("arm64" or "amd64"); it selects the Lima
	// arch string and the guest-agent binary the broker serves during
	// provisioning.
	Arch string
}

// BakeConfig is everything GenerateBakeLimaYAML and bakeProvisionScripts need
// to boot the one-off, throwaway VM used to build the golden image (see
// internal/image): the stock Ubuntu cloud image, both harness CLIs, Tetragon,
// and the nftables/rsyslog packages (package install only — no ruleset, since
// bake time has no broker or session to pin one to). Unlike Config, there is
// no session id, broker, harness, token, or workspace: the bake boot exists
// only to install software, never to run a workload.
type BakeConfig struct {
	// Arch is the host's GOARCH ("arm64" or "amd64"); it selects the Ubuntu
	// image, the Lima arch string, and the Tetragon release tarball.
	Arch string
	// ExtraCAPEM, if non-empty, is trusted inside the guest before npm runs.
	ExtraCAPEM string
	// NPMRegistry, if non-empty, overrides npm's default registry inside the
	// guest before npm runs.
	NPMRegistry string
	// SessionDir is the host directory WriteBakeLimaYAML writes lima.yaml
	// under. Despite the name (shared with Config for WriteLimaYAML's sake),
	// this is a scratch directory internal/image manages for the bake boot,
	// not a real session directory.
	SessionDir string
}
