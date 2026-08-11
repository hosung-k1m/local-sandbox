package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withClaudeKeychain swaps lookupClaudeKeychain for fn and restores the real
// implementation when the test ends, so no test ever execs the real macOS
// `security` binary.
func withClaudeKeychain(t *testing.T, fn func() ([]byte, error)) {
	t.Helper()
	orig := lookupClaudeKeychain
	lookupClaudeKeychain = fn
	t.Cleanup(func() { lookupClaudeKeychain = orig })
}

// withCodexAuthFile points codexAuthPath at a fixture file under t.TempDir()
// instead of the real $HOME/.codex/auth.json, writing content there unless it is
// empty (which simulates the file never having been created by `codex login`).
func withCodexAuthFile(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.json")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture codex auth.json: %v", err)
		}
	}
	orig := codexAuthPath
	codexAuthPath = func() (string, error) { return path, nil }
	t.Cleanup(func() { codexAuthPath = orig })
}

// claudeKeychainJSON builds a fake "Claude Code-credentials" Keychain payload
// with the given access token and expiry.
func claudeKeychainJSON(accessToken string, expiresAt time.Time) []byte {
	return []byte(fmt.Sprintf(`{"claudeAiOauth":{"accessToken":%q,"refreshToken":"r","expiresAt":%d}}`,
		accessToken, expiresAt.UnixMilli()))
}

func TestResolveAnthropicDeviceCredential(t *testing.T) {
	t.Run("env token wins over keychain", func(t *testing.T) {
		t.Setenv(claudeOAuthEnv, "sk-ant-oat01-from-env")
		withClaudeKeychain(t, func() ([]byte, error) {
			t.Fatal("keychain must not be consulted when CLAUDE_CODE_OAUTH_TOKEN is set")
			return nil, nil
		})
		got, err := resolveAnthropicDeviceCredential()
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if got != "sk-ant-oat01-from-env" {
			t.Errorf("got %q, want env token", got)
		}
	})

	t.Run("missing keychain item is empty with no error", func(t *testing.T) {
		t.Setenv(claudeOAuthEnv, "")
		withClaudeKeychain(t, func() ([]byte, error) {
			return nil, errors.New("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain")
		})
		got, err := resolveAnthropicDeviceCredential()
		if err != nil {
			t.Fatalf("err = %v, want nil (absence is normal)", err)
		}
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("valid keychain credential is used", func(t *testing.T) {
		t.Setenv(claudeOAuthEnv, "")
		withClaudeKeychain(t, func() ([]byte, error) {
			return claudeKeychainJSON("sk-ant-oat01-keychain", time.Now().Add(time.Hour)), nil
		})
		got, err := resolveAnthropicDeviceCredential()
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if got != "sk-ant-oat01-keychain" {
			t.Errorf("got %q, want keychain access token", got)
		}
	})

	t.Run("expired keychain credential errors with refresh guidance", func(t *testing.T) {
		t.Setenv(claudeOAuthEnv, "")
		withClaudeKeychain(t, func() ([]byte, error) {
			return claudeKeychainJSON("sk-ant-oat01-keychain", time.Now().Add(-time.Hour)), nil
		})
		got, err := resolveAnthropicDeviceCredential()
		if got != "" {
			t.Errorf("got %q, want empty on expiry", got)
		}
		if !errors.Is(err, errClaudeCredentialExpired) {
			t.Fatalf("err = %v, want errClaudeCredentialExpired", err)
		}
		if !strings.Contains(err.Error(), "claude setup-token") || !strings.Contains(err.Error(), "run `claude`") {
			t.Errorf("err = %v, want guidance to run `claude` or `claude setup-token`", err)
		}
	})

	t.Run("expiry within clock-skew window counts as expired", func(t *testing.T) {
		t.Setenv(claudeOAuthEnv, "")
		withClaudeKeychain(t, func() ([]byte, error) {
			return claudeKeychainJSON("sk-ant-oat01-keychain", time.Now().Add(30*time.Second)), nil
		})
		_, err := resolveAnthropicDeviceCredential()
		if !errors.Is(err, errClaudeCredentialExpired) {
			t.Fatalf("err = %v, want errClaudeCredentialExpired within skew window", err)
		}
	})

	t.Run("malformed keychain payload is an error, not silent absence", func(t *testing.T) {
		t.Setenv(claudeOAuthEnv, "")
		withClaudeKeychain(t, func() ([]byte, error) { return []byte("not json"), nil })
		_, err := resolveAnthropicDeviceCredential()
		if err == nil {
			t.Fatal("want error for malformed Keychain payload")
		}
		if errors.Is(err, errClaudeCredentialExpired) {
			t.Errorf("malformed payload should not be reported as expiry: %v", err)
		}
	})

	t.Run("valid JSON without claudeAiOauth is unrecognized, not expired", func(t *testing.T) {
		t.Setenv(claudeOAuthEnv, "")
		withClaudeKeychain(t, func() ([]byte, error) { return []byte(`{}`), nil })
		_, err := resolveAnthropicDeviceCredential()
		if err == nil {
			t.Fatal("want error for a payload with no claudeAiOauth credential")
		}
		// Misreporting this as expiry would send the user to `claude` for a
		// refresh that cannot fix an unrecognized schema.
		if errors.Is(err, errClaudeCredentialExpired) {
			t.Errorf("unrecognized payload should not be reported as expiry: %v", err)
		}
		if !strings.Contains(err.Error(), "not in a recognized shape") {
			t.Errorf("err = %v, want unrecognized-shape message", err)
		}
	})
}

func TestResolveOpenAIDeviceCredential(t *testing.T) {
	t.Run("missing auth.json is empty with no error", func(t *testing.T) {
		withCodexAuthFile(t, "")
		got, err := resolveOpenAIDeviceCredential()
		if err != nil {
			t.Fatalf("err = %v, want nil (absence is normal)", err)
		}
		if got != (codexDeviceCredential{}) {
			t.Errorf("got %+v, want zero value", got)
		}
	})

	t.Run("plain OPENAI_API_KEY field is used as-is", func(t *testing.T) {
		withCodexAuthFile(t, `{"auth_mode":"apikey","OPENAI_API_KEY":"sk-plain-key"}`)
		got, err := resolveOpenAIDeviceCredential()
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		want := codexDeviceCredential{Key: "sk-plain-key"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("chatgpt tokens set the account id", func(t *testing.T) {
		withCodexAuthFile(t, `{"auth_mode":"chatgpt","tokens":{"id_token":"idt","access_token":"at-123","refresh_token":"rt","account_id":"acct-456"},"last_refresh":"2026-01-01T00:00:00Z"}`)
		got, err := resolveOpenAIDeviceCredential()
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		want := codexDeviceCredential{Key: "at-123", ChatGPTAccountID: "acct-456"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("access token without account id is nothing usable", func(t *testing.T) {
		withCodexAuthFile(t, `{"tokens":{"access_token":"at-123"}}`)
		got, err := resolveOpenAIDeviceCredential()
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if got != (codexDeviceCredential{}) {
			t.Errorf("got %+v, want zero value", got)
		}
	})

	t.Run("malformed auth.json is an error", func(t *testing.T) {
		withCodexAuthFile(t, "not json")
		_, err := resolveOpenAIDeviceCredential()
		if err == nil {
			t.Fatal("want error for malformed auth.json")
		}
	})
}

func TestResolveUpstreams(t *testing.T) {
	// Every subtest fully isolates env, Keychain, and the codex auth.json path so
	// none of them can touch the real host's logins.
	clearCredentialEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("ANTHROPIC_BASE_URL", "")
		t.Setenv(claudeOAuthEnv, "")
		t.Setenv("OPENAI_API_KEY", "")
		t.Setenv("OPENAI_BASE_URL", "")
	}
	noKeychainItem := func() ([]byte, error) { return nil, errors.New("item not found") }

	t.Run("explicit env wins over device credentials", func(t *testing.T) {
		clearCredentialEnv(t)
		t.Setenv("ANTHROPIC_API_KEY", "explicit-anthropic")
		t.Setenv("OPENAI_API_KEY", "explicit-openai")
		withClaudeKeychain(t, func() ([]byte, error) {
			t.Fatal("keychain must not be consulted when ANTHROPIC_API_KEY is set")
			return nil, nil
		})
		withCodexAuthFile(t, "")

		a, o, err := resolveUpstreams(HostConfig{}, "claude")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if a.Key != "explicit-anthropic" {
			t.Errorf("anthropic key = %q, want explicit-anthropic", a.Key)
		}
		if o.Key != "explicit-openai" {
			t.Errorf("openai key = %q, want explicit-openai", o.Key)
		}
	})

	t.Run("keychain used when env empty", func(t *testing.T) {
		clearCredentialEnv(t)
		withClaudeKeychain(t, func() ([]byte, error) {
			return claudeKeychainJSON("sk-ant-oat01-keychain", time.Now().Add(time.Hour)), nil
		})
		withCodexAuthFile(t, "")

		a, _, err := resolveUpstreams(HostConfig{}, "claude")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if a.Key != "sk-ant-oat01-keychain" {
			t.Errorf("anthropic key = %q, want keychain token", a.Key)
		}
	})

	t.Run("expired keychain is fatal for the claude harness", func(t *testing.T) {
		clearCredentialEnv(t)
		withClaudeKeychain(t, func() ([]byte, error) {
			return claudeKeychainJSON("sk-ant-oat01-keychain", time.Now().Add(-time.Hour)), nil
		})
		withCodexAuthFile(t, "")

		_, _, err := resolveUpstreams(HostConfig{}, "claude")
		if err == nil {
			t.Fatal("want error when the claude harness's own provider credential is expired")
		}
		if !strings.Contains(err.Error(), "claude setup-token") {
			t.Errorf("err = %v, want refresh guidance", err)
		}
	})

	t.Run("exec harness never consults device credentials at all", func(t *testing.T) {
		// Not merely "errors ignored": the Keychain access has host-visible side
		// effects (it can raise an authorization dialog), so a session that never
		// uses the provider must not trigger the lookup in the first place.
		clearCredentialEnv(t)
		withClaudeKeychain(t, func() ([]byte, error) {
			t.Error("exec harness must not consult the Claude Code Keychain")
			return nil, errors.New("unreachable")
		})
		withCodexAuthFile(t, "")

		a, _, err := resolveUpstreams(HostConfig{}, "exec")
		if err != nil {
			t.Fatalf("exec harness must never fail on credentials, got: %v", err)
		}
		if a.Key != "" {
			t.Errorf("anthropic key = %q, want empty (no device lookup for exec)", a.Key)
		}
	})

	t.Run("codex harness never consults the claude keychain", func(t *testing.T) {
		clearCredentialEnv(t)
		withClaudeKeychain(t, func() ([]byte, error) {
			t.Error("codex harness must not consult the Claude Code Keychain")
			return nil, errors.New("unreachable")
		})
		withCodexAuthFile(t, `{"tokens":{"access_token":"at-123","account_id":"acct-456"}}`)

		a, o, err := resolveUpstreams(HostConfig{}, "codex")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if a.Key != "" {
			t.Errorf("anthropic key = %q, want empty (claude device lookup skipped for codex)", a.Key)
		}
		if o.Key != "at-123" {
			t.Errorf("openai key = %q, want at-123", o.Key)
		}
	})

	t.Run("codex chatgpt mode sets account id and the chatgpt default base URL", func(t *testing.T) {
		clearCredentialEnv(t)
		withClaudeKeychain(t, noKeychainItem)
		withCodexAuthFile(t, `{"tokens":{"access_token":"at-123","account_id":"acct-456"}}`)

		_, o, err := resolveUpstreams(HostConfig{}, "codex")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if o.Key != "at-123" {
			t.Errorf("openai key = %q, want at-123", o.Key)
		}
		if o.ChatGPTAccountID != "acct-456" {
			t.Errorf("ChatGPTAccountID = %q, want acct-456", o.ChatGPTAccountID)
		}
		if o.BaseURL != defaultChatGPTCodexBaseURL {
			t.Errorf("BaseURL = %q, want %q", o.BaseURL, defaultChatGPTCodexBaseURL)
		}
	})

	t.Run("explicit config BaseURL wins over the chatgpt default", func(t *testing.T) {
		clearCredentialEnv(t)
		withClaudeKeychain(t, noKeychainItem)
		withCodexAuthFile(t, `{"tokens":{"access_token":"at-123","account_id":"acct-456"}}`)

		hc := HostConfig{OpenAI: ProviderConfig{BaseURL: "https://custom.example/v1"}}
		_, o, err := resolveUpstreams(hc, "codex")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if o.BaseURL != "https://custom.example/v1" {
			t.Errorf("BaseURL = %q, want explicit config value", o.BaseURL)
		}
	})

	t.Run("OPENAI_BASE_URL env wins over the chatgpt default", func(t *testing.T) {
		clearCredentialEnv(t)
		t.Setenv("OPENAI_BASE_URL", "https://env.example/v1")
		withClaudeKeychain(t, noKeychainItem)
		withCodexAuthFile(t, `{"tokens":{"access_token":"at-123","account_id":"acct-456"}}`)

		_, o, err := resolveUpstreams(HostConfig{}, "codex")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if o.BaseURL != "https://env.example/v1" {
			t.Errorf("BaseURL = %q, want env value", o.BaseURL)
		}
	})

	t.Run("no credential anywhere fails fast for claude", func(t *testing.T) {
		clearCredentialEnv(t)
		withClaudeKeychain(t, noKeychainItem)
		withCodexAuthFile(t, "")

		_, _, err := resolveUpstreams(HostConfig{}, "claude")
		if err == nil {
			t.Fatal("want fail-fast error, not a silently empty Anthropic credential")
		}
		if !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
			t.Errorf("err = %v, want mention of ANTHROPIC_API_KEY", err)
		}
	})

	t.Run("no credential anywhere fails fast for codex", func(t *testing.T) {
		clearCredentialEnv(t)
		withClaudeKeychain(t, noKeychainItem)
		withCodexAuthFile(t, "")

		_, _, err := resolveUpstreams(HostConfig{}, "codex")
		if err == nil {
			t.Fatal("want fail-fast error, not a silently empty OpenAI credential")
		}
		if !strings.Contains(err.Error(), "OPENAI_API_KEY") || !strings.Contains(err.Error(), "codex login") {
			t.Errorf("err = %v, want mention of OPENAI_API_KEY and `codex login`", err)
		}
	})

	t.Run("no credential anywhere is fine for exec", func(t *testing.T) {
		clearCredentialEnv(t)
		withClaudeKeychain(t, noKeychainItem)
		withCodexAuthFile(t, "")

		a, o, err := resolveUpstreams(HostConfig{}, "exec")
		if err != nil {
			t.Fatalf("exec harness must never fail on credentials, got: %v", err)
		}
		if a.Key != "" || o.Key != "" {
			t.Errorf("a.Key = %q, o.Key = %q, want both empty", a.Key, o.Key)
		}
	})
}
