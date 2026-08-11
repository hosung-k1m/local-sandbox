package vm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"text/template"
)

// guestAgentConfig is written to /etc/boxedai/agent.json (0600, root) during
// session provisioning's guest-agent step. Field names are this package's own
// choice: DESIGN.md specifies the contents in prose ("session id, broker URL,
// supervisor token, workload uid, workspace path") but not a JSON schema,
// since guest/agent (a separate binary) owns parsing it.
type guestAgentConfig struct {
	SessionID       string `json:"session_id"`
	BrokerURL       string `json:"broker_url"`
	SupervisorToken string `json:"supervisor_token"`
	WorkloadUID     int    `json:"workload_uid"`
	WorkspacePath   string `json:"workspace_path"`
	TetragonLog     string `json:"tetragon_log"`
	NFTLogSource    string `json:"nft_log_source"`
}

// guestTetragonLog is where bake provisioning tells tetragon to export events
// and where the guest agent looks for them (its own default matches, but
// wiring it explicitly keeps the two in lockstep if either changes).
const guestTetragonLog = "/var/log/tetragon/tetragon.log"

// guestNFTLogSource is the file the guest agent tails for boxedai-denied
// egress records. nftables `log` emits to the kernel ring buffer; the golden
// image's rsyslog install (bake time) funnels kern.* into this file, giving
// the agent a regular growing file to tail (unlike /dev/kmsg, a char device
// that defeats size-based rotation detection).
const guestNFTLogSource = "/var/log/kern.log"

// Bake provisioning (see bakeProvisionScripts) builds the golden image ONCE
// (internal/image), never for a real session: create the agent user, install
// runtime deps + BOTH harness CLIs (the image is harness-agnostic — a real
// session just picks one at launch, see harness.go), install Tetragon, and
// install (but do not yet configure) the nftables/rsyslog packages. After
// provisioning is verified, BakeVM.Verify resets cloud-init's instance state
// so the exported disk's next boot looks like a genuine first boot. There is
// no broker or session yet, so no nftables ruleset is written, resolv.conf is
// left alone, and no guest agent is fetched — those all need a real session's
// broker IP and tokens, which only exist at session-boot time.

// Session provisioning (see provisionScripts) runs against that pre-baked
// image on every `boxedai run`, root, network still open: the nftables
// lockdown is deliberately second-to-last so every earlier step can still
// reach the internet, and the guest agent starts only after the lockdown so
// its first packet is already governed by it. No apt-get, npm, or downloads
// beyond the guest agent binary itself — avoiding exactly that per-session
// cost is why the golden image exists.

// stepCreateUserTmpl creates the unprivileged workload user. No sudo — the
// harness runs as this uid via systemd-run --uid=agent, and it must not be
// able to escalate in-guest. Shared by bake (so the golden image already has
// the user) and session provisioning (an idempotent no-op guard against that
// same image, via the "if ! id -u agent" check).
var stepCreateUserTmpl = template.Must(template.New("step-user").Parse(`#!/bin/sh
set -eu
if ! id -u agent >/dev/null 2>&1; then
  useradd --create-home --home-dir /home/agent --uid {{.WorkloadUID}} --user-group --shell /bin/bash agent
fi
`))

// stepBakeRuntimeDepsTmpl installs runtime deps + both harness CLIs into the
// golden image. The corporate CA (if configured) is trusted before npm talks
// to any registry, in case it is proxied. Both CLIs install unconditionally —
// the image is harness-agnostic, so no real session ever has to install
// anything at boot regardless of which harness it requests.
var stepBakeRuntimeDepsTmpl = template.Must(template.New("bake-step-runtime").Parse(`#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl gnupg git
{{if .HasExtraCA}}
cat > /usr/local/share/ca-certificates/boxedai-extra-ca.crt <<'BOXEDAI_CA_EOF'
{{.ExtraCAPEM}}
BOXEDAI_CA_EOF
update-ca-certificates
{{end}}
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y --no-install-recommends nodejs
{{if .HasExtraCA}}
# Node bundles its own Mozilla CA set and ignores the system store update-ca-certificates
# just updated, so on networks with TLS interception (e.g. Cloudflare Gateway) npm's
# registry TLS verification fails even though curl/apt (which do use the system store)
# succeeded above. NODE_EXTRA_CA_CERTS is additive to node's bundled CAs, not a
# replacement, so this only helps and cannot weaken verification for the well-known case.
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/boxedai-extra-ca.crt
{{end}}
{{if .HasNPMRegistry}}
# npm's default registry (registry.npmjs.org) is blocked by some corporate
# gateways as a dependency-confusion policy; point it at an internal mirror
# instead, same rationale as the CA injection above.
npm config set registry {{.NPMRegistry}}
{{end}}
npm install -g @anthropic-ai/claude-code @openai/codex
# Some npm mirrors leave Claude Code's generated wrapper unusable even though
# the package's official native executable was installed successfully. Copy
# that executable to the stable path BoxedAi launches and verifies directly.
install -m 0755 \
  /usr/lib/node_modules/@anthropic-ai/claude-code/node_modules/@anthropic-ai/claude-code-linux-{{.ClaudeNativeArch}}/claude \
  /usr/local/bin/claude
/usr/local/bin/claude --version
`))

// stepBakeTetragonTmpl gives the golden image kernel_observed process/network
// evidence. Best-effort: if the release tarball is unavailable for this arch,
// the guest agent falls back to procfs polling and reports that honestly
// (sensor.mechanism=procfs), so a failure here must not abort bake
// provisioning. `systemctl enable --now` here means every future session
// boots with tetragon already running — no per-session systemctl call needed.
var stepBakeTetragonTmpl = template.Must(template.New("bake-step-tetragon").Parse(`#!/bin/sh
set -eu
mkdir -p /var/log/tetragon
(
  set -e
  TETRAGON_VERSION="v1.2.0"
  TMPDIR=$(mktemp -d)
  cd "$TMPDIR"
  curl -fsSL -o tetragon.tar.gz \
    "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-{{.Arch}}.tar.gz"
  tar -xzf tetragon.tar.gz
  install -m 0755 tetragon-*/usr/local/bin/tetragon /usr/local/bin/tetragon
  cd /
  rm -rf "$TMPDIR"
  cat > /etc/systemd/system/tetragon.service <<'UNIT_EOF'
[Unit]
Description=Tetragon eBPF sensor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tetragon --export-filename=/var/log/tetragon/tetragon.log
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT_EOF
  systemctl daemon-reload
  systemctl enable --now tetragon
) || echo "boxedai: tetragon install failed, guest agent will fall back to procfs" >&2
`))

// stepBakePackagesTmpl installs (but does not configure) the nftables and
// rsyslog packages into the golden image. Only the package install + enable
// happen here: the nftables ruleset itself needs a real session's broker IP,
// which does not exist yet at bake time (see stepNftablesRulesetTmpl).
// Enabling rsyslog now means its systemd enable-state is baked into the
// image, so every session boots with it already running, ready to receive
// the kern.* records the session's nftables ruleset will start logging.
var stepBakePackagesTmpl = template.Must(template.New("bake-step-packages").Parse(`#!/bin/sh
set -eu
apt-get install -y --no-install-recommends nftables rsyslog
systemctl enable rsyslog
`))

// stepGuestAgentTmpl fetches the guest supervisor binary from the broker
// (which cross-compiled it) and drops its config. Not started yet — see
// stepEnableAgentTmpl.
var stepGuestAgentTmpl = template.Must(template.New("session-step-guest-agent").Parse(`#!/bin/sh
set -eu
mkdir -p /etc/boxedai
curl -fsSL -H "Authorization: Bearer {{.SupervisorToken}}" \
  "http://{{.BrokerHost}}:{{.BrokerPort}}/v1/guest/agent-binary?arch={{.Arch}}" \
  -o /usr/local/bin/boxedai-guest-agent
chmod 0755 /usr/local/bin/boxedai-guest-agent

echo '{{.AgentConfigB64}}' | base64 -d > /etc/boxedai/agent.json
chmod 0600 /etc/boxedai/agent.json
chown root:root /etc/boxedai/agent.json

cat > /etc/systemd/system/boxedai-guest-agent.service <<'UNIT_EOF'
[Unit]
Description=BoxedAi guest supervisor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/boxedai-guest-agent
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
UNIT_EOF
systemctl daemon-reload
`))

// stepNftablesRulesetTmpl applies the default-deny egress lockdown, LAST
// provisioning step before the workload can run. host.lima.internal is
// resolved to an IP now, while the network is still open, because the
// ruleset that follows drops everything, DNS included, and nftables can only
// match on IP addresses. The nftables and rsyslog packages themselves are
// already installed, and rsyslog's systemd enable-state already baked in
// (stepBakePackagesTmpl) — this step only restarts rsyslog (cheap,
// idempotent) to make sure the log sink is confirmed live for THIS session
// before the ruleset below starts funneling boxedai-denied records into it;
// it never installs anything.
var stepNftablesRulesetTmpl = template.Must(template.New("session-step-nftables-ruleset").Parse(`#!/bin/sh
set -eu
systemctl restart rsyslog
BROKER_IP=$(getent hosts {{.BrokerHost}} | awk '{print $1}' | head -n1)
if [ -z "$BROKER_IP" ]; then
  echo "boxedai: could not resolve broker host {{.BrokerHost}}" >&2
  exit 1
fi
# Pin resolv.conf directly at the upstream nameserver and disable the
# systemd-resolved stub. Otherwise the workload's DNS goes to 127.0.0.53
# (loopback, allowed) and systemd-resolved makes the real upstream query under
# its own uid, so a workload egress attempt never becomes a uid-{{.WorkloadUID}}
# packet and is invisible to the (workload-scoped) deny log. Pointing resolv.conf
# straight at the upstream makes the workload's own DNS queries attributable,
# uid-{{.WorkloadUID}} packets aimed at a single known IP, so the ruleset below can
# silently drop that dead resolver path as noise while still logging DNS to any
# OTHER host as evidence. Captured now, while resolution still works, before the
# ruleset below drops it.
UPSTREAM_DNS=$(awk '/^nameserver/{print $2; exit}' /run/systemd/resolve/resolv.conf 2>/dev/null)
[ -z "$UPSTREAM_DNS" ] && UPSTREAM_DNS=$(resolvectl status 2>/dev/null | awk '/Current DNS Server/{print $NF; exit}')
[ -z "$UPSTREAM_DNS" ] && UPSTREAM_DNS=${BROKER_IP%.*}.2
systemctl stop systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true
rm -f /etc/resolv.conf
printf 'nameserver %s\n' "$UPSTREAM_DNS" > /etc/resolv.conf
cat > /etc/nftables.conf <<NFT_EOF
table inet boxedai {
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
    ip daddr ${BROKER_IP} tcp dport {{.BrokerPort}} accept
    # The workload's own DNS to the configured upstream resolver (${UPSTREAM_DNS})
    # is a dead path — there is no DNS egress by design, so the harness tooling
    # retries it constantly. Drop it silently (like the daemon noise below) so it
    # does not flood the audit log. DNS to any OTHER host still falls through to
    # the log+drop rule, so a real tunneling attempt to an arbitrary resolver
    # stays network.denied evidence.
    meta skuid {{.WorkloadUID}} udp dport 53 ip daddr ${UPSTREAM_DNS} drop
    # Only the workload's (uid {{.WorkloadUID}}) denied egress is evidence.
    # System daemons (systemd-resolved, chrony, ...) are dropped silently so
    # their background DNS/NTP retries do not flood the audit log. The rate
    # limit bounds how fast a workload egress loop can grow the evidence;
    # over-limit and non-workload packets fall through to the silent drop.
    meta skuid {{.WorkloadUID}} limit rate 20/second burst 40 packets log prefix "boxedai-denied: " drop
    drop
  }
}
NFT_EOF
systemctl enable nftables
systemctl restart nftables
`))

// stepEnableAgentTmpl brings the supervisor up now that egress is locked
// down, so its first packet is already governed by the nftables allowlist
// above. It POSTs sensor.started to the broker over the one route that
// survives.
var stepEnableAgentTmpl = template.Must(template.New("session-step-enable-agent").Parse(`#!/bin/sh
set -eu
systemctl enable --now boxedai-guest-agent
`))

// provisionData is the template data for session provisioning (see
// provisionScripts): the fast, per-session steps that run against an
// already-baked golden image. It carries none of bake's node/npm/CA fields —
// session provisioning never touches apt or npm.
type provisionData struct {
	BrokerHost      string
	BrokerPort      int
	SupervisorToken string
	SessionID       string
	Arch            string // GOARCH convention: "arm64" | "amd64"
	AgentConfigB64  string
	WorkloadUID     int
}

// bakeProvisionData is the template data for bake provisioning (see
// bakeProvisionScripts): the slow, one-time steps that build the golden
// image. There is no broker, session id, harness, or token yet — the bake
// boot only installs software.
type bakeProvisionData struct {
	Arch             string // GOARCH convention: "arm64" | "amd64"
	ClaudeNativeArch string
	ExtraCAPEM       string
	HasExtraCA       bool
	NPMRegistry      string
	HasNPMRegistry   bool
	WorkloadUID      int
}

// bakeProvisionScripts renders the bake-only provisioning steps (create the
// agent user, install runtime deps + both harness CLIs, install Tetragon, and
// install the nftables/rsyslog packages) as Lima "system" mode provision
// entries. BakeVM.Verify resets cloud-init only after these steps and CLI
// verification succeed. This is the ONE provisioning path that still runs
// apt-get/npm/curl downloads; internal/image runs it once to build the golden
// image, never per session.
func bakeProvisionScripts(cfg BakeConfig) ([]limaProvision, error) {
	claudeArch, err := claudeNativePackageArch(cfg.Arch)
	if err != nil {
		return nil, err
	}
	data := bakeProvisionData{
		Arch:             cfg.Arch,
		ClaudeNativeArch: claudeArch,
		ExtraCAPEM:       cfg.ExtraCAPEM,
		HasExtraCA:       cfg.ExtraCAPEM != "",
		NPMRegistry:      cfg.NPMRegistry,
		HasNPMRegistry:   cfg.NPMRegistry != "",
		WorkloadUID:      agentUID,
	}
	steps := []*template.Template{
		stepCreateUserTmpl,
		stepBakeRuntimeDepsTmpl,
		stepBakeTetragonTmpl,
		stepBakePackagesTmpl,
	}
	return renderProvisionSteps(steps, data)
}

func claudeNativePackageArch(goArch string) (string, error) {
	switch goArch {
	case "arm64":
		return "arm64", nil
	case "amd64":
		return "x64", nil
	default:
		return "", fmt.Errorf("vm: unsupported Claude Code native package arch %q", goArch)
	}
}

// provisionScripts renders the session-only provisioning steps (idempotent
// user guard, guest agent fetch + config, nftables ruleset, guest agent
// enable) as Lima "system" mode provision entries. It never runs apt-get or
// npm: those packages and CLIs are already present in the golden image
// cfg.ImagePath boots from (see bakeProvisionScripts).
func provisionScripts(cfg Config) ([]limaProvision, error) {
	agentCfg := guestAgentConfig{
		SessionID:       cfg.SessionID,
		BrokerURL:       fmt.Sprintf("http://%s:%d", cfg.BrokerHost, cfg.BrokerPort),
		SupervisorToken: cfg.SupervisorToken,
		WorkloadUID:     agentUID,
		WorkspacePath:   guestWorkspaceMount,
		TetragonLog:     guestTetragonLog,
		NFTLogSource:    guestNFTLogSource,
	}
	agentCfgJSON, err := json.Marshal(agentCfg)
	if err != nil {
		return nil, fmt.Errorf("vm: marshal guest agent config: %w", err)
	}

	data := provisionData{
		BrokerHost:      cfg.BrokerHost,
		BrokerPort:      cfg.BrokerPort,
		SupervisorToken: cfg.SupervisorToken,
		SessionID:       cfg.SessionID,
		Arch:            cfg.Arch,
		AgentConfigB64:  base64.StdEncoding.EncodeToString(agentCfgJSON),
		WorkloadUID:     agentUID,
	}

	steps := []*template.Template{
		stepCreateUserTmpl,
		stepGuestAgentTmpl,
		stepNftablesRulesetTmpl,
		stepEnableAgentTmpl,
	}
	return renderProvisionSteps(steps, data)
}

// renderProvisionSteps executes each template against data, in order, and
// wraps the results as Lima "system" mode provision entries. Shared by both
// bakeProvisionScripts and provisionScripts: the render-and-wrap mechanics
// are identical, only the template set and data type differ.
func renderProvisionSteps(steps []*template.Template, data any) ([]limaProvision, error) {
	provisions := make([]limaProvision, 0, len(steps))
	for _, t := range steps {
		var buf bytes.Buffer
		if err := t.Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("vm: render provisioning script %s: %w", t.Name(), err)
		}
		provisions = append(provisions, limaProvision{Mode: "system", Script: buf.String()})
	}
	return provisions, nil
}
