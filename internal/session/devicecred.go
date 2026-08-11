package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"boxedai/internal/broker"
)

// This file automatically resolves model-upstream credentials from the host's
// existing CLI device logins (Claude Code, Codex CLI) when the host config/env
// path in home.go's resolveKey comes up empty. It never mints or refreshes a
// credential itself — only reads what those CLIs already stored — so host
// credentials still never enter the VM (DESIGN.md security invariant); they flow
// host-side into broker.Upstream exactly like an explicit config Key does.

// claudeOAuthEnv is the env var `claude setup-token` tells users to export: a
// long-lived OAuth token that bypasses the Keychain lookup entirely.
const claudeOAuthEnv = "CLAUDE_CODE_OAUTH_TOKEN"

// claudeKeychainService is the macOS Keychain item name Claude Code stores its
// device-login OAuth credential under; `claude` (interactive) refreshes it in
// place on every run, and `claude setup-token` mints the long-lived token above.
const claudeKeychainService = "Claude Code-credentials"

// claudeCredentialSkew is the clock-skew headroom subtracted from a Keychain
// token's expiry before we call it usable. Without this, a token that is valid
// when resolveUpstreams runs could expire moments later against the real
// Anthropic API, turning a config error into a confusing mid-session 401.
const claudeCredentialSkew = 2 * time.Minute

// defaultChatGPTCodexBaseURL is the Codex CLI's ChatGPT-backend base URL. It
// applies only when a ChatGPT device login (as opposed to a platform API key)
// supplies the OpenAI credential and neither host config nor OPENAI_BASE_URL
// names an explicit upstream — explicit configuration always wins over this
// device-login default.
const defaultChatGPTCodexBaseURL = "https://chatgpt.com/backend-api/codex"

// lookupClaudeKeychain execs the macOS `security` CLI to read Claude Code's stored
// OAuth credential. It is a package-level var, not a direct exec.Command call, so
// tests can substitute a fake reader instead of touching the real Keychain (which
// doesn't exist in CI/Linux anyway) — matching the vmFactory injection seam in
// run.go.
var lookupClaudeKeychain = func() ([]byte, error) {
	return exec.Command("/usr/bin/security", "find-generic-password", "-s", claudeKeychainService, "-w").Output()
}

// codexAuthPath returns the path to the Codex CLI's device-login credential file,
// ~/.codex/auth.json (written by `codex login`). It is a package-level var, like
// lookupClaudeKeychain, so tests can point at a fixture file instead of the real
// $HOME.
var codexAuthPath = func() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("session: resolve home dir for codex auth.json: %w", err)
	}
	return filepath.Join(home, ".codex", "auth.json"), nil
}

// errClaudeCredentialExpired is returned when the host's Claude Code Keychain
// credential has expired (or expires within claudeCredentialSkew). We deliberately
// do not attempt an OAuth refresh ourselves: the stored refresh token rotates on
// use, and consuming it here — behind the host's back — would corrupt the host
// `claude` CLI's own login state. Surfacing guidance and stopping is the safe move.
var errClaudeCredentialExpired = errors.New(
	"session: host Claude Code login has expired; run `claude` on this host (which refreshes it), " +
		"or run `claude setup-token` to mint a new long-lived token")

// claudeKeychainCredential is the JSON shape of the "Claude Code-credentials"
// Keychain item's password field, as written by Claude Code.
type claudeKeychainCredential struct {
	ClaudeAiOauth struct {
		AccessToken string `json:"accessToken"`
		ExpiresAt   int64  `json:"expiresAt"` // epoch milliseconds
	} `json:"claudeAiOauth"`
}

// resolveAnthropicDeviceCredential returns the Anthropic credential implied by the
// host's Claude Code device login, tried only when explicit config/env resolution
// (ProviderConfig.resolveKey) came up empty. A nil error with an empty string means
// "no device login here" (never logged in, non-macOS host, etc.) — that is the
// normal case, not a failure.
func resolveAnthropicDeviceCredential() (string, error) {
	if tok := os.Getenv(claudeOAuthEnv); tok != "" {
		return tok, nil
	}
	out, err := lookupClaudeKeychain()
	if err != nil {
		// Missing item, missing `security` binary, non-macOS host: all indicate
		// there is simply no Claude Code login to find, not an error worth
		// reporting.
		return "", nil
	}
	var cred claudeKeychainCredential
	if err := json.Unmarshal(out, &cred); err != nil {
		return "", fmt.Errorf("session: parse Claude Code Keychain credential: %w", err)
	}
	// Valid JSON without the fields we rely on (empty payload, or a future
	// Claude Code schema change) is its own error: falling through to the
	// expiry check would misreport it as an expired login and send the user
	// chasing a refresh that cannot help.
	if cred.ClaudeAiOauth.AccessToken == "" || cred.ClaudeAiOauth.ExpiresAt == 0 {
		return "", errors.New(
			"session: Claude Code Keychain credential is present but not in a recognized shape; " +
				"set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN (`claude setup-token`) instead")
	}
	expiresAt := time.UnixMilli(cred.ClaudeAiOauth.ExpiresAt)
	if !expiresAt.After(time.Now().Add(claudeCredentialSkew)) {
		return "", errClaudeCredentialExpired
	}
	return cred.ClaudeAiOauth.AccessToken, nil
}

// codexAuthFile is the JSON shape of ~/.codex/auth.json, written by `codex login`.
type codexAuthFile struct {
	OpenAIAPIKey string `json:"OPENAI_API_KEY"`
	Tokens       struct {
		AccessToken string `json:"access_token"`
		AccountID   string `json:"account_id"`
	} `json:"tokens"`
}

// codexDeviceCredential is what resolveOpenAIDeviceCredential found: either a
// plain platform API key, or (ChatGPT mode) an access token plus the account id
// the ChatGPT Codex backend requires as the chatgpt-account-id header
// (broker.Upstream.ChatGPTAccountID carries it through to the proxy).
type codexDeviceCredential struct {
	Key              string
	ChatGPTAccountID string // non-empty only in ChatGPT mode
}

// resolveOpenAIDeviceCredential returns the OpenAI/Codex credential implied by the
// host's Codex CLI device login, tried only when explicit config/env resolution
// came up empty. A nil error with a zero-value result means "no device login here"
// (auth.json absent, or present but without a usable key/token pair).
func resolveOpenAIDeviceCredential() (codexDeviceCredential, error) {
	path, err := codexAuthPath()
	if err != nil {
		return codexDeviceCredential{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return codexDeviceCredential{}, nil // never ran `codex login`; normal.
		}
		return codexDeviceCredential{}, fmt.Errorf("session: read codex auth.json: %w", err)
	}
	var auth codexAuthFile
	if err := json.Unmarshal(b, &auth); err != nil {
		return codexDeviceCredential{}, fmt.Errorf("session: parse codex auth.json: %w", err)
	}
	if auth.OpenAIAPIKey != "" {
		return codexDeviceCredential{Key: auth.OpenAIAPIKey}, nil
	}
	if auth.Tokens.AccessToken != "" && auth.Tokens.AccountID != "" {
		// ChatGPT mode: we do not parse the JWT or check expiry here — a stale
		// access token surfaces as an ordinary upstream 401 recorded in evidence,
		// same as any other broker rejection.
		return codexDeviceCredential{Key: auth.Tokens.AccessToken, ChatGPTAccountID: auth.Tokens.AccountID}, nil
	}
	return codexDeviceCredential{}, nil
}

// resolveUpstreams builds the two model upstreams Run hands to the broker:
// explicit host config/env credentials first (ProviderConfig.resolveKey), falling
// back to the host's device logins (Claude Code Keychain / CLAUDE_CODE_OAUTH_TOKEN;
// Codex CLI auth.json) when the provider has no explicit key configured.
//
// Device-credential lookup runs only for the provider the requested harness
// actually drives (claude -> anthropic, codex -> openai, exec -> neither): the
// lookup has host-visible side effects — a macOS Keychain access that can raise
// an authorization dialog — which a session that never uses the provider must
// not trigger. The other provider (and everything under exec) resolves from
// explicit config/env alone, degrading to an empty credential.
//
// For the harness's own provider a lookup error (e.g. an expired Keychain token)
// is fatal, and so is resolving to no credential at all — previously a missing
// key silently produced upstream 401s deep into a running session instead of a
// clear message up front.
func resolveUpstreams(hc HostConfig, harness string) (anthropic, openai broker.Upstream, err error) {
	anthropicKey := hc.Anthropic.resolveKey("ANTHROPIC_API_KEY")
	if anthropicKey == "" && harness == "claude" {
		anthropicKey, err = resolveAnthropicDeviceCredential()
		if err != nil {
			return broker.Upstream{}, broker.Upstream{}, err
		}
		if anthropicKey == "" {
			return broker.Upstream{}, broker.Upstream{}, errors.New(
				"session: no Anthropic credential available; set ANTHROPIC_API_KEY, log into Claude Code on this host, " +
					"or set CLAUDE_CODE_OAUTH_TOKEN (`claude setup-token`)")
		}
	}

	openaiKey := hc.OpenAI.resolveKey("OPENAI_API_KEY")
	var chatGPTAccountID string
	chatGPTMode := false
	if openaiKey == "" && harness == "codex" {
		cred, err := resolveOpenAIDeviceCredential()
		if err != nil {
			return broker.Upstream{}, broker.Upstream{}, err
		}
		openaiKey = cred.Key
		chatGPTAccountID = cred.ChatGPTAccountID
		chatGPTMode = cred.ChatGPTAccountID != ""
		if openaiKey == "" {
			return broker.Upstream{}, broker.Upstream{}, errors.New(
				"session: no OpenAI credential available; set OPENAI_API_KEY or run `codex login` on this host")
		}
	}

	anthropicBaseURL := hc.Anthropic.resolveBaseURL("ANTHROPIC_BASE_URL", defaultAnthropicBaseURL)
	openaiFallback := defaultOpenAIBaseURL
	if chatGPTMode {
		openaiFallback = defaultChatGPTCodexBaseURL
	}
	openaiBaseURL := hc.OpenAI.resolveBaseURL("OPENAI_BASE_URL", openaiFallback)

	anthropic = broker.Upstream{BaseURL: anthropicBaseURL, Key: anthropicKey}
	openai = broker.Upstream{BaseURL: openaiBaseURL, Key: openaiKey, ChatGPTAccountID: chatGPTAccountID}
	return anthropic, openai, nil
}
