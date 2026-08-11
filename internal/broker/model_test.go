package broker

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestModelProxyAnthropicKeyKind covers the anthropic credential-injection branch: a
// platform API key (sk-ant-api...) keeps today's X-Api-Key behavior, while a Claude
// Code OAuth access token (sk-ant-oat...) switches to Bearer auth and requires the
// oauth-2025-04-20 anthropic-beta flag, merged with (never clobbering) whatever betas
// the guest's Claude Code already sent.
func TestModelProxyAnthropicKeyKind(t *testing.T) {
	cases := []struct {
		name          string
		key           string
		inboundBeta   string // set on the client request if non-empty
		wantAuth      string // exact upstream Authorization value; "" = header absent
		wantAPIKey    string // exact upstream X-Api-Key value; "" = header absent
		wantBetaExact string // exact upstream Anthropic-Beta value; "" = header absent
	}{
		{
			name:       "api key uses X-Api-Key, no oauth beta added",
			key:        "sk-ant-api03-real-key",
			wantAPIKey: "sk-ant-api03-real-key",
		},
		{
			name:          "oauth key uses Bearer auth and adds oauth beta",
			key:           "sk-ant-oat01-real-token",
			wantAuth:      "Bearer sk-ant-oat01-real-token",
			wantBetaExact: anthropicOAuthBeta,
		},
		{
			name:          "oauth key preserves guest beta and appends oauth beta",
			key:           "sk-ant-oat01-real-token",
			inboundBeta:   "some-feature-2025-01-01",
			wantAuth:      "Bearer sk-ant-oat01-real-token",
			wantBetaExact: "some-feature-2025-01-01," + anthropicOAuthBeta,
		},
		{
			name:          "oauth key does not duplicate an already-present oauth beta",
			key:           "sk-ant-oat01-real-token",
			inboundBeta:   "some-feature-2025-01-01," + anthropicOAuthBeta,
			wantAuth:      "Bearer sk-ant-oat01-real-token",
			wantBetaExact: "some-feature-2025-01-01," + anthropicOAuthBeta,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
			var got http.Header
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"msg_1"}`))
			}))
			t.Cleanup(backend.Close)

			b := mustBroker(t, Config{Anthropic: Upstream{BaseURL: backend.URL, Key: tc.key}})
			srv := testServer(t, b)

			req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/anthropic/v1/messages",
				bytes.NewReader([]byte(`{"model":"claude-test","messages":[]}`)))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			// The inbound workload bearer and any inbound X-Api-Key must never reach
			// the upstream: the proxy strips both before injecting the real credential.
			req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
			req.Header.Set("X-Api-Key", "inbound-should-be-stripped")
			req.Header.Set("Traceparent", traceparent)
			if tc.inboundBeta != "" {
				req.Header.Set("Anthropic-Beta", tc.inboundBeta)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("model request: %v", err)
			}
			drain(resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("model status = %d, want 200", resp.StatusCode)
			}

			if gotAuth := got.Get("Authorization"); gotAuth != tc.wantAuth {
				t.Fatalf("upstream Authorization = %q, want %q", gotAuth, tc.wantAuth)
			}
			if gotKey := got.Get("X-Api-Key"); gotKey != tc.wantAPIKey {
				t.Fatalf("upstream X-Api-Key = %q, want %q", gotKey, tc.wantAPIKey)
			}
			if gotBeta := got.Get("Anthropic-Beta"); gotBeta != tc.wantBetaExact {
				t.Fatalf("upstream Anthropic-Beta = %q, want %q", gotBeta, tc.wantBetaExact)
			}
			if gotTraceparent := got.Get("Traceparent"); gotTraceparent != traceparent {
				t.Fatalf("upstream Traceparent = %q, want %q", gotTraceparent, traceparent)
			}
		})
	}
}

// TestModelProxyOpenAIChatGPTAccountID covers the chatgpt-account-id header the ChatGPT
// Codex backend requires when the OpenAI upstream is backed by a ChatGPT credential:
// the header is set only when Upstream.ChatGPTAccountID is configured, and any inbound
// value from the guest (whose codex CLI runs in API-key mode) is stripped first.
func TestModelProxyOpenAIChatGPTAccountID(t *testing.T) {
	cases := []struct {
		name          string
		accountID     string
		wantAccountID string // "" = header absent
	}{
		{"ChatGPTAccountID configured sets header", "acct_123", "acct_123"},
		{"ChatGPTAccountID empty leaves header absent", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got http.Header
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"resp_1"}`))
			}))
			t.Cleanup(backend.Close)

			b := mustBroker(t, Config{
				OpenAI: Upstream{BaseURL: backend.URL, Key: "real-key", ChatGPTAccountID: tc.accountID},
			})
			srv := testServer(t, b)

			req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/openai/v1/chat/completions",
				bytes.NewReader([]byte(`{"model":"gpt-test"}`)))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
			req.Header.Set("chatgpt-account-id", "inbound-should-be-stripped")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("model request: %v", err)
			}
			drain(resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("model status = %d, want 200", resp.StatusCode)
			}

			if gotAuth := got.Get("Authorization"); gotAuth != "Bearer real-key" {
				t.Fatalf("upstream Authorization = %q, want %q", gotAuth, "Bearer real-key")
			}
			if gotID := got.Get("chatgpt-account-id"); gotID != tc.wantAccountID {
				t.Fatalf("upstream chatgpt-account-id = %q, want %q", gotID, tc.wantAccountID)
			}
		})
	}
}
