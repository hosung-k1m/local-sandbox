// Package broker implements the BoxedAi host HTTP broker: one server per session
// on a loopback-reachable random port, mediating the sandboxed workload's access to
// model upstreams, internal read tools, external-effect adapters, approvals, and
// guest event ingest. Every mediated action produces evidence via the shared
// evidence.Emitter; model proxy bodies are recorded as digest + metadata only. Claude's
// explicitly enabled OTLP diagnostic route stores its authenticated JSON batches
// separately from signed evidence. See DESIGN.md "Broker".
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"time"

	"boxedai/internal/evidence"
	"boxedai/internal/policy"
)

// Broker-local evidence attribute keys. The audit.* / vm.* / process.* keys live in
// package evidence; these name broker-mediated request metadata that is safe to store
// (never secrets, never bodies).
const (
	attrProvider    = "model.provider"
	attrModelID     = "model.id"
	attrHTTPStatus  = "http.response.status_code"
	attrToolName    = "tool.name"
	attrToolOp      = "tool.op"
	attrAdapter     = "effect.adapter"
	attrEffectOp    = "effect.op"
	attrDecision    = "authorization.decision"
	attrCommand     = "command.argv"
	attrError       = "error.message"
	attrArch        = "guest.arch"
	attrTruncated   = "output.truncated"
	attrExitCode    = "process.exit_code"
	attrUsageInput  = "llm.usage.input_tokens"
	attrUsageOutput = "llm.usage.output_tokens"
	attrUsageTotal  = "llm.usage.total_tokens"
)

// Body size limits. Model bodies can carry long prompts; tool/effect arg objects are
// small; event batches sit in between. Requests exceeding a limit are rejected 413
// rather than silently truncated (which would corrupt the recorded digest).
const (
	maxModelBody  = 64 << 20 // 64 MiB
	maxArgsBody   = 1 << 20  // 1 MiB
	maxEventsBody = 16 << 20 // 16 MiB
	decisionAllow = "allow"
	decisionDeny  = "deny"
)

// shutdownGrace is how long Stop waits for in-flight requests before force-closing
// what is left. A var so tests can shrink it instead of paying the real grace.
var shutdownGrace = 5 * time.Second

// Upstream is a model provider endpoint plus the real host credential injected into
// proxied requests. Read from host config/env by the caller; never exposed to the guest.
type Upstream struct {
	BaseURL string
	Key     string
	// ChatGPTAccountID, when non-empty, marks an OpenAI upstream backed by a ChatGPT
	// (Codex CLI device login) credential rather than a platform API key: the proxy
	// adds it as the chatgpt-account-id header the ChatGPT Codex backend requires.
	ChatGPTAccountID string
}

// GitHubConfig enables brokered Git-over-SSH access to one repository. SSHURL is
// the exact URL resolved by the host gh CLI; no host credential is copied into
// the broker or guest.
type GitHubConfig struct {
	Repository string
	SSHURL     string
}

// Approver decides whether an exact normalized external effect may dispatch. The
// session controller supplies an immutable preapproval closure; a nil Approver means
// every effect is auto-denied.
type Approver func(action NormalizedAction) bool

// AgentBinaryProvider returns the cross-compiled guest agent binary for the given goarch
// ("arm64" or "amd64"), served to the provisioning script over the broker.
type AgentBinaryProvider func(arch string) ([]byte, error)

// Config carries everything the broker needs for one session. Tools and Effects, when
// nil, default to the DESIGN.md adapter tables (DefaultTools/DefaultEffects).
type Config struct {
	Emitter evidence.Emitter // all events flow through here; never nil
	Policy  policy.Policy    // capability decisions for tools and effects
	Session string           // session id, stamped on events by the recorder

	Anthropic Upstream // Anthropic-compatible model upstream
	OpenAI    Upstream // OpenAI-compatible model upstream
	GitHub    GitHubConfig
	// ClaudeTelemetryDir, when non-empty, receives authenticated OTLP
	// HTTP/JSON logs, metrics, and traces from Claude Code.
	ClaudeTelemetryDir string

	// Tools maps internal read tool -> op -> argv template ({{name}} placeholders).
	Tools map[string]map[string][]string
	// Effects maps external-write adapter -> op -> argv template.
	Effects map[string]map[string][]string

	Approver    Approver            // exact-action approval for effects; nil = auto-deny
	AgentBinary AgentBinaryProvider // guest agent binary source
}

// Broker is a running per-session HTTP mediation server.
type Broker struct {
	cfg             Config
	workloadToken   string // W: in-harness env, gates model/tool/effect routes
	supervisorToken string // S: root-only guest file, gates guest ingest routes
	revoked         atomic.Bool

	anthropicProxy *httputil.ReverseProxy // nil if Anthropic upstream unconfigured
	openaiProxy    *httputil.ReverseProxy // nil if OpenAI upstream unconfigured
	githubTarget   string                 // validated org-N@github.com target; empty if unconfigured
	runGitHubSSH   githubSSHRunner
	telemetryMu    sync.Mutex

	srv *http.Server
	ln  net.Listener
}

// New mints the two bearer tokens, builds the model reverse proxies, and prepares the
// HTTP server. It does not bind a port; call Start for that.
func New(cfg Config) (*Broker, error) {
	if cfg.Emitter == nil {
		return nil, errors.New("broker: Config.Emitter is required")
	}
	if cfg.Tools == nil {
		cfg.Tools = DefaultTools()
	}
	if cfg.Effects == nil {
		cfg.Effects = DefaultEffects()
	}
	w, err := mintToken()
	if err != nil {
		return nil, fmt.Errorf("broker: mint workload token: %w", err)
	}
	s, err := mintToken()
	if err != nil {
		return nil, fmt.Errorf("broker: mint supervisor token: %w", err)
	}
	b := &Broker{cfg: cfg, workloadToken: w, supervisorToken: s}
	if b.anthropicProxy, err = b.newModelProxy(providerAnthropic, cfg.Anthropic); err != nil {
		return nil, err
	}
	if b.openaiProxy, err = b.newModelProxy(providerOpenAI, cfg.OpenAI); err != nil {
		return nil, err
	}
	if b.githubTarget, err = prepareGitHubSSH(cfg.GitHub); err != nil {
		return nil, err
	}
	b.runGitHubSSH = runGitHubSSH
	if err := prepareClaudeTelemetry(cfg.ClaudeTelemetryDir); err != nil {
		return nil, err
	}
	b.srv = &http.Server{Handler: b.routes()}
	return b, nil
}

// DefaultTools is the DESIGN.md internal read adapter table (codesearch via
// `sq agent-tools sourcegraph ...`).
func DefaultTools() map[string]map[string][]string {
	return map[string]map[string][]string{
		"codesearch": {
			"search-code": {"sq", "agent-tools", "sourcegraph", "search-code", "--query", "{{query}}"},
			"show-file":   {"sq", "agent-tools", "sourcegraph", "show-file", "--repo", "{{repo}}", "--path", "{{path}}"},
		},
	}
}

// DefaultEffects is the DESIGN.md external-write adapter table. Git pushes use the
// native SSH bridge instead of executing Git on the host workspace.
func DefaultEffects() map[string]map[string][]string {
	return map[string]map[string][]string{
		"github": {
			"pr-comment": {"gh", "pr", "comment", "{{pr}}", "--body", "{{body}}"},
		},
	}
}

// WorkloadToken returns the bearer token W handed to the harness.
func (b *Broker) WorkloadToken() string { return b.workloadToken }

// SupervisorToken returns the bearer token S handed to the guest supervisor.
func (b *Broker) SupervisorToken() string { return b.supervisorToken }

// Start binds 0.0.0.0 on a random free port and begins serving in the background,
// returning the chosen port. The context governs the bind only; use Stop to shut down.
func (b *Broker) Start(ctx context.Context) (int, error) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		return 0, fmt.Errorf("broker: listen: %w", err)
	}
	b.ln = ln
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		// Serve returns ErrServerClosed on graceful Stop; anything else is unexpected
		// but there is no live caller to surface it to here.
		_ = b.srv.Serve(ln)
	}()
	return port, nil
}

// Stop shuts the server down: in-flight requests get shutdownGrace to drain, and
// whatever is still open afterwards is force-closed. Shutdown alone only waits, so
// one slow ingest handler (a guest final drain, a streaming proxy response) used to
// hold teardown open for the whole grace and then leave that handler still emitting
// into a recorder the caller was about to seal. The returned error says the grace
// expired; the caller logs it and finishes sealing (DESIGN.md "Teardown never
// abandons the seal for a shutdown problem").
func (b *Broker) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := b.srv.Shutdown(ctx); err != nil {
		if closeErr := b.srv.Close(); closeErr != nil {
			return fmt.Errorf("broker: force close after %s shutdown grace (%v): %w", shutdownGrace, err, closeErr)
		}
		return fmt.Errorf("broker: %s shutdown grace expired, connections force-closed: %w", shutdownGrace, err)
	}
	return nil
}

// Revoke invalidates both bearer tokens; every authenticated route then returns 401.
// Idempotent; safe to call from a crash-cleanup path.
func (b *Broker) Revoke() { b.revoked.Store(true) }

// routes wires the HTTP surface. Every route but /v1/healthz requires a valid,
// non-revoked bearer of the correct kind (W-only, S-only, or either).
func (b *Broker) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/healthz", handleHealthz)
	mux.HandleFunc("POST /v1/model/anthropic/{path...}", b.auth(true, false, b.serveModel(providerAnthropic, b.anthropicProxy)))
	mux.HandleFunc("POST /v1/model/openai/{path...}", b.auth(true, false, b.serveModel(providerOpenAI, b.openaiProxy)))
	mux.HandleFunc("POST /v1/tools/{tool}/{op}", b.auth(true, false, b.handleTool))
	mux.HandleFunc("POST /v1/effects/{adapter}/{op}", b.auth(true, false, b.handleEffect))
	mux.HandleFunc("POST /v1/git/{service}", enableGitFullDuplex(b.auth(true, false, b.handleGitBridge)))
	mux.HandleFunc("POST /v1/telemetry/claude/{signal}", b.auth(true, false, b.handleClaudeTelemetry))
	mux.HandleFunc("POST /v1/events", b.auth(true, true, b.handleEvents))
	mux.HandleFunc("GET /v1/guest/agent-binary", b.auth(false, true, b.handleAgentBinary))
	return mux
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// emit stamps the wall-clock time (if unset) and forwards to the recorder. A non-nil
// error means evidence capture is broken; the caller must fail the request closed.
func (b *Broker) emit(ch evidence.Channel, ev evidence.Event) error {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if err := b.cfg.Emitter.Emit(ch, ev); err != nil {
		return fmt.Errorf("broker: emit %s: %w", ev.Name, err)
	}
	return nil
}

// mintToken returns a 256-bit random bearer token as hex.
func mintToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
