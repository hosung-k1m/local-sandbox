// Package session is the BoxedAi orchestration keystone: it wires policy,
// recorder, broker, snapshot and vm into one fail-closed session lifecycle and
// owns the host state layout under ~/.boxedai (DESIGN.md "Session flow" and
// "Host filesystem layout"). It is the only package that composes the others;
// everything below it (recorder, broker, snapshot, vm, verify, view) stays
// independent.
package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// homeEnv overrides the default ~/.boxedai state root when set.
const homeEnv = "BOXEDAI_HOME"

// Default upstream base URLs, used when neither host config nor the provider's
// *_BASE_URL environment variable supplies one (DESIGN.md model routing).
const (
	defaultAnthropicBaseURL = "https://api.anthropic.com"
	defaultOpenAIBaseURL    = "https://api.openai.com"
)

// Home returns the BoxedAi state root: $BOXEDAI_HOME when set, else ~/.boxedai.
func Home() string {
	if h := os.Getenv(homeEnv); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to a relative path rather than panicking; callers that need
		// the dir will surface the mkdir error fail-closed.
		return ".boxedai"
	}
	return filepath.Join(home, ".boxedai")
}

// keysDir is ~/.boxedai/keys, holding the recorder Ed25519 keypair.
func keysDir() string { return filepath.Join(Home(), "keys") }

// configPath is ~/.boxedai/config.json, the host configuration file.
func configPath() string { return filepath.Join(Home(), "config.json") }

func humanSSHKeyDir() string         { return filepath.Join(Home(), "human-ssh") }
func HumanSSHPrivateKeyPath() string { return filepath.Join(humanSSHKeyDir(), "id_ed25519") }
func HumanSSHPublicKeyPath() string  { return filepath.Join(humanSSHKeyDir(), "id_ed25519.pub") }

func HumanSSHPublicKeyFingerprint(publicKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(publicKey)))
	return "SHA256:" + hex.EncodeToString(sum[:])
}

func LoadHumanSSHPublicKey() (string, error) {
	data, err := os.ReadFile(HumanSSHPublicKeyPath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// EnsureHumanSSHKeypair creates the controller-owned human SSH key exactly
// once. Existing material is never replaced; a partial pair fails closed.
func EnsureHumanSSHKeypair() (string, string, error) {
	dir := humanSSHKeyDir()
	privatePath, publicPath := HumanSSHPrivateKeyPath(), HumanSSHPublicKeyPath()
	_, privateErr := os.Stat(privatePath)
	_, publicErr := os.Stat(publicPath)
	if privateErr == nil || publicErr == nil {
		if privateErr != nil || publicErr != nil {
			return "", "", fmt.Errorf("session: human SSH keypair is incomplete")
		}
		public, err := os.ReadFile(publicPath)
		return strings.TrimSpace(string(public)), publicPath, err
	}
	if !os.IsNotExist(privateErr) || !os.IsNotExist(publicErr) {
		return "", "", fmt.Errorf("session: inspect human SSH keypair: %v %v", privateErr, publicErr)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}
	privatePEM, err := ssh.MarshalPrivateKey(ed25519.PrivateKey(priv), "boxedai-human")
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	publicKey, err := ssh.NewPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}
	publicLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))) + " boxedai-human\n"
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(privatePEM), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(publicPath, []byte(publicLine), 0o644); err != nil {
		return "", "", err
	}
	return strings.TrimSpace(publicLine), publicPath, nil
}

// sessionsDir is ~/.boxedai/sessions, the parent of every per-session directory.
func sessionsDir() string { return filepath.Join(Home(), "sessions") }

// SessionDir returns the on-disk directory for a session id,
// ~/.boxedai/sessions/<id>. It does not create the directory.
func SessionDir(id string) string { return filepath.Join(sessionsDir(), id) }

// mkdirAll creates dir (and parents) at 0700, the mode DESIGN.md mandates for the
// state tree.
func mkdirAll(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("session: create %s: %w", dir, err)
	}
	return nil
}

// newSessionID builds a session id "bx-<UTC yyyymmdd-hhmmss>-<8 hex>" from the
// given time plus 4 random bytes (DESIGN.md "Host filesystem layout").
func newSessionID(t time.Time) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session: generate id randomness: %w", err)
	}
	return fmt.Sprintf("bx-%s-%s", t.UTC().Format("20060102-150405"), hex.EncodeToString(b[:])), nil
}

// newTraceID returns 16 random bytes as 32 lowercase hex characters. The
// controller generates all trace ids (DESIGN.md); agent-supplied ids are never
// treated as identity.
func newTraceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session: generate trace id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// HostConfig is ~/.boxedai/config.json: the upstream model endpoints (base URL +
// key reference) and the internal-tool / external-effect adapter allowlists. It is
// host-owned and never exposed to the guest. Absent fields fall back to
// environment variables and the DESIGN.md defaults.
type HostConfig struct {
	// Anthropic configures the Anthropic-compatible model upstream.
	Anthropic ProviderConfig `json:"anthropic"`
	// OpenAI configures the OpenAI-compatible model upstream.
	OpenAI ProviderConfig `json:"openai"`
	// Tools overrides the DESIGN.md internal read adapter table (adapter -> op ->
	// argv template) when non-nil; nil uses broker.DefaultTools.
	Tools map[string]map[string][]string `json:"tools,omitempty"`
	// Effects overrides the DESIGN.md external-write adapter table when non-nil;
	// nil uses broker.DefaultEffects.
	Effects map[string]map[string][]string `json:"effects,omitempty"`
	// ExtraCAPEM, if set, is a PEM bundle trusted inside the guest before npm runs
	// (corporate CA injection, DESIGN.md provisioning).
	ExtraCAPEM string `json:"extra_ca_pem,omitempty"`
	// NPMRegistry, if set, overrides npm's default registry inside the guest
	// before the CLI install (for networks that block the public npm registry,
	// e.g. via corporate policy).
	NPMRegistry string `json:"npm_registry,omitempty"`
}

// ProviderConfig is one model upstream's host configuration. The credential is a
// reference — an inline Key, or KeyEnv naming the environment variable that holds
// it — so config.json need not contain secrets.
type ProviderConfig struct {
	// BaseURL is the upstream base URL; empty falls back to the provider's
	// *_BASE_URL env var, then the DESIGN.md default.
	BaseURL string `json:"base_url,omitempty"`
	// Key is an inline API key (discouraged; prefer KeyEnv).
	Key string `json:"key,omitempty"`
	// KeyEnv names the environment variable holding the API key.
	KeyEnv string `json:"key_env,omitempty"`
}

// LoadHostConfig reads ~/.boxedai/config.json. A missing file yields a zero
// HostConfig (all env/default fallbacks apply); a present but malformed file is a
// fail-closed error.
func LoadHostConfig() (HostConfig, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return HostConfig{}, nil
		}
		return HostConfig{}, fmt.Errorf("session: read host config: %w", err)
	}
	var hc HostConfig
	if err := json.Unmarshal(b, &hc); err != nil {
		return HostConfig{}, fmt.Errorf("session: parse host config: %w", err)
	}
	return hc, nil
}

// resolveKey returns the provider credential: the inline Key, else the value of
// KeyEnv, else the value of the provider's default env var. It may be empty (the
// broker then proxies without injecting a credential).
func (p ProviderConfig) resolveKey(defaultEnv string) string {
	switch {
	case p.Key != "":
		return p.Key
	case p.KeyEnv != "":
		return os.Getenv(p.KeyEnv)
	default:
		return os.Getenv(defaultEnv)
	}
}

// resolveBaseURL returns the provider base URL: the configured BaseURL, else the
// envVar value, else fallback.
func (p ProviderConfig) resolveBaseURL(envVar, fallback string) string {
	if p.BaseURL != "" {
		return p.BaseURL
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return fallback
}
