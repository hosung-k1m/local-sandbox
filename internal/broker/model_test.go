package broker

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"boxedai/internal/evidence"
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

// TestModelProxyClaimedAgentHeaders covers the subagent-identity headers Claude Code
// stamps on subagent API requests: the broker records them on model.requested as
// harness.claimed_* provenance (believed by nothing — model attribution is
// session-level) and strips all three before the request reaches the upstream.
func TestModelProxyClaimedAgentHeaders(t *testing.T) {
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1"}`))
	}))
	t.Cleanup(backend.Close)

	fe := &fakeEmitter{}
	b := mustBroker(t, Config{Emitter: fe, Anthropic: Upstream{BaseURL: backend.URL, Key: "real-key"}})
	srv := testServer(t, b)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/anthropic/v1/messages",
		bytes.NewReader([]byte(`{"model":"claude-test","messages":[]}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
	req.Header.Set(claudeAgentIDHeader, "sub-agent-42")
	req.Header.Set(claudeParentAgentIDHeader, "primary-agent")
	req.Header.Set(claudeSessionIDHeader, "cc-session-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("model request: %v", err)
	}
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model status = %d, want 200", resp.StatusCode)
	}

	// Stripped from the upstream request: a workload-chosen label never reaches the provider.
	for _, h := range []string{claudeAgentIDHeader, claudeParentAgentIDHeader, claudeSessionIDHeader} {
		if v := got.Get(h); v != "" {
			t.Errorf("upstream saw %s = %q, want stripped", h, v)
		}
	}

	// Recorded on model.requested as claimed provenance.
	reqEv := fe.byName(evidence.EventModelRequested)
	if len(reqEv) != 1 {
		t.Fatalf("model.requested count = %d, want 1", len(reqEv))
	}
	attrs := reqEv[0].ev.Attrs
	for k, want := range map[string]any{
		attrClaimedAgentID:       "sub-agent-42",
		attrClaimedParentAgentID: "primary-agent",
		attrClaimedSessionID:     "cc-session-1",
	} {
		if got := attrs[k]; got != want {
			t.Errorf("Attrs[%q] = %v, want %v", k, got, want)
		}
	}
}

// TestParseUsageAnthropicSSEStream covers real Claude Code traffic: Anthropic always
// streams SSE, so input_tokens must come from message_start and the recorded
// output_tokens must be the LAST message_delta's cumulative count, not an earlier one.
func TestParseUsageAnthropicSSEStream(t *testing.T) {
	sse := `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":25,"output_tokens":1}}}

event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":5}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":9}}

event: message_stop
data: {"type":"message_stop"}

data: [DONE]

`
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sse))
	}))
	t.Cleanup(backend.Close)

	fe := &fakeEmitter{}
	b := mustBroker(t, Config{Emitter: fe, Anthropic: Upstream{BaseURL: backend.URL, Key: "real-key"}})
	srv := testServer(t, b)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/anthropic/v1/messages",
		bytes.NewReader([]byte(`{"model":"claude-test","messages":[],"stream":true}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("model request: %v", err)
	}
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model status = %d, want 200", resp.StatusCode)
	}

	compEv := fe.byName(evidence.EventModelCompleted)
	if len(compEv) != 1 {
		t.Fatalf("model.completed count = %d, want 1", len(compEv))
	}
	attrs := compEv[0].ev.Attrs
	if attrs[attrUsageInput] != int64(25) {
		t.Fatalf("usage input = %v, want 25 (from message_start)", attrs[attrUsageInput])
	}
	if attrs[attrUsageOutput] != int64(9) {
		t.Fatalf("usage output = %v, want 9 (last message_delta)", attrs[attrUsageOutput])
	}
	if _, ok := attrs[attrUsageTotal]; ok {
		t.Fatalf("usage total = %v, want absent (anthropic never reports it)", attrs[attrUsageTotal])
	}
}

// TestParseUsageOpenAIChatCompletionsSSEStream covers a Chat Completions stream with
// stream_options.include_usage: the usage object arrives whole on the final chunk
// (after the last content delta), not incrementally.
func TestParseUsageOpenAIChatCompletionsSSEStream(t *testing.T) {
	sse := `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hi"}}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":34,"total_tokens":46}}

data: [DONE]

`
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sse))
	}))
	t.Cleanup(backend.Close)

	fe := &fakeEmitter{}
	b := mustBroker(t, Config{Emitter: fe, OpenAI: Upstream{BaseURL: backend.URL, Key: "real-key"}})
	srv := testServer(t, b)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/openai/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"gpt-test","stream":true}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("model request: %v", err)
	}
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model status = %d, want 200", resp.StatusCode)
	}

	compEv := fe.byName(evidence.EventModelCompleted)
	if len(compEv) != 1 {
		t.Fatalf("model.completed count = %d, want 1", len(compEv))
	}
	attrs := compEv[0].ev.Attrs
	if attrs[attrUsageInput] != int64(12) || attrs[attrUsageOutput] != int64(34) || attrs[attrUsageTotal] != int64(46) {
		t.Fatalf("usage attrs = %+v, want input=12 output=34 total=46", attrs)
	}
}

// TestParseUsageOpenAIResponsesAPISSEStream covers the Responses API's streaming shape,
// distinct from Chat Completions: usage arrives nested under "response" on a single
// "response.completed" event rather than as a top-level "usage" field.
func TestParseUsageOpenAIResponsesAPISSEStream(t *testing.T) {
	sse := `data: {"type":"response.output_text.delta","delta":"Hi"}

data: {"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}}}

`
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sse))
	}))
	t.Cleanup(backend.Close)

	fe := &fakeEmitter{}
	b := mustBroker(t, Config{Emitter: fe, OpenAI: Upstream{BaseURL: backend.URL, Key: "real-key"}})
	srv := testServer(t, b)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/openai/v1/responses",
		bytes.NewReader([]byte(`{"model":"gpt-test","stream":true}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("model request: %v", err)
	}
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model status = %d, want 200", resp.StatusCode)
	}

	compEv := fe.byName(evidence.EventModelCompleted)
	if len(compEv) != 1 {
		t.Fatalf("model.completed count = %d, want 1", len(compEv))
	}
	attrs := compEv[0].ev.Attrs
	if attrs[attrUsageInput] != int64(7) || attrs[attrUsageOutput] != int64(3) || attrs[attrUsageTotal] != int64(10) {
		t.Fatalf("usage attrs = %+v, want input=7 output=3 total=10", attrs)
	}
}

// TestModelProxyStripsWorkloadAcceptEncoding covers the compressed-upstream path: the
// proxy must drop the workload's Accept-Encoding (undici asks for br/zstd, which the
// host cannot decode) so Go's transport negotiates its own gzip and transparently
// decodes it. The digest, the parsed usage, and the bytes forwarded to the workload
// must then all cover the identical plain payload.
func TestModelProxyStripsWorkloadAcceptEncoding(t *testing.T) {
	plain := []byte(`{"id":"msg_1","usage":{"input_tokens":11,"output_tokens":22}}`)
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(plain); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	gzBytes := gzBuf.Bytes()

	var backendAcceptEncoding string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gzBytes)
	}))
	t.Cleanup(backend.Close)

	fe := &fakeEmitter{}
	b := mustBroker(t, Config{Emitter: fe, Anthropic: Upstream{BaseURL: backend.URL, Key: "real-key"}})
	srv := testServer(t, b)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/anthropic/v1/messages",
		bytes.NewReader([]byte(`{"model":"claude-test","messages":[]}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
	// What Claude Code's HTTP client really asks for: codings Go cannot decode. The
	// proxy must not let this reach the upstream.
	req.Header.Set("Accept-Encoding", "br, zstd")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("model request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model status = %d, want 200", resp.StatusCode)
	}
	if backendAcceptEncoding != "gzip" {
		t.Fatalf("upstream saw Accept-Encoding %q, want transport-negotiated %q (workload value stripped)",
			backendAcceptEncoding, "gzip")
	}
	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !bytes.Equal(gotBody, plain) {
		t.Fatalf("client-visible body = %q, want the transparently decoded plain payload", gotBody)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty (transport decoded the negotiated gzip)", got)
	}

	compEv := fe.byName(evidence.EventModelCompleted)
	if len(compEv) != 1 {
		t.Fatalf("model.completed count = %d, want 1", len(compEv))
	}
	attrs := compEv[0].ev.Attrs
	if attrs[attrUsageInput] != int64(11) || attrs[attrUsageOutput] != int64(22) {
		t.Fatalf("usage attrs = %+v, want input=11 output=22", attrs)
	}
	wantDigest := evidence.SHA256Hex(plain)
	if got, _ := attrs[evidence.AttrContentDigest].(string); got != wantDigest {
		t.Fatalf("content digest = %q, want %q (digest of the plain payload the workload received)", got, wantDigest)
	}
}

// TestGunzipForUsageParsingDefensePath covers the belt-and-braces decode directly: a
// non-compliant upstream that sends gzip despite the stripped Accept-Encoding (so the
// transport does not decode it) must still yield parsed usage from the decoded copy.
func TestGunzipForUsageParsingDefensePath(t *testing.T) {
	plain := []byte(`{"id":"msg_1","usage":{"input_tokens":7,"output_tokens":9}}`)
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(plain); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	decoded, ok := gunzipForUsageParsing(gzBuf.Bytes())
	if !ok || !bytes.Equal(decoded, plain) {
		t.Fatalf("gunzipForUsageParsing = (%q, %v), want the plain payload and ok", decoded, ok)
	}
	if _, ok := gunzipForUsageParsing(plain); ok {
		t.Fatal("gunzipForUsageParsing accepted non-gzip bytes, want ok=false")
	}
}

// TestParseUsageMixedTypeUsageObject is the regression test for real Anthropic usage
// objects silently producing no token counts: a modern usage object carries strings,
// objects, and arrays (service_tier, server_tool_use, cache_creation, iterations,
// speed) alongside the numeric counts, and decoding the whole object into
// map[string]json.Number failed, dropping the numbers next to them. Fixtures mirror
// the exact shapes captured from a real session's raw-api-bodies.
func TestParseUsageMixedTypeUsageObject(t *testing.T) {
	plain := []byte(`{"model":"claude-opus-5","id":"msg_1","type":"message","role":"assistant",` +
		`"content":[{"type":"text","text":"done"}],"stop_reason":"end_turn",` +
		`"usage":{"input_tokens":734,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,` +
		`"output_tokens":18,"server_tool_use":{"web_search_requests":0,"web_fetch_requests":0},` +
		`"service_tier":"standard","cache_creation":{"ephemeral_1h_input_tokens":0,"ephemeral_5m_input_tokens":0},` +
		`"inference_geo":"global","iterations":[],"speed":"standard"}}`)
	got := parseUsage(providerAnthropic, plain)
	if got[attrUsageInput] != int64(734) || got[attrUsageOutput] != int64(18) {
		t.Fatalf("plain mixed-type usage = %+v, want input=734 output=18", got)
	}

	sse := []byte("event: message_start\n" +
		`data: {"type":"message_start","message":{"model":"claude-opus-5","id":"msg_1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":3,"output_tokens":1,"service_tier":"standard","server_tool_use":{"web_search_requests":0},"cache_creation":{"ephemeral_1h_input_tokens":0},"iterations":[],"speed":"standard"}}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":9,"service_tier":"standard","iterations":[]}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n")
	got = parseUsage(providerAnthropic, sse)
	if got[attrUsageInput] != int64(3) || got[attrUsageOutput] != int64(9) {
		t.Fatalf("SSE mixed-type usage = %+v, want input=3 output=9", got)
	}
}

// TestParseUsageJunkBodyNoUsageAttrs covers a body that is neither valid plain JSON nor
// SSE data: usage must be silently absent, never a zero-value placeholder.
func TestParseUsageJunkBodyNoUsageAttrs(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("not json and not SSE at all"))
	}))
	t.Cleanup(backend.Close)

	fe := &fakeEmitter{}
	b := mustBroker(t, Config{Emitter: fe, Anthropic: Upstream{BaseURL: backend.URL, Key: "real-key"}})
	srv := testServer(t, b)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/anthropic/v1/messages",
		bytes.NewReader([]byte(`{"model":"claude-test","messages":[]}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("model request: %v", err)
	}
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model status = %d, want 200", resp.StatusCode)
	}

	compEv := fe.byName(evidence.EventModelCompleted)
	if len(compEv) != 1 {
		t.Fatalf("model.completed count = %d, want 1", len(compEv))
	}
	attrs := compEv[0].ev.Attrs
	if _, ok := attrs[attrUsageInput]; ok {
		t.Fatalf("usage input = %v, want absent", attrs[attrUsageInput])
	}
	if _, ok := attrs[attrUsageOutput]; ok {
		t.Fatalf("usage output = %v, want absent", attrs[attrUsageOutput])
	}
	if _, ok := attrs[attrUsageTotal]; ok {
		t.Fatalf("usage total = %v, want absent", attrs[attrUsageTotal])
	}
}

// TestParseUsageAnthropicPlainJSONRegression is a regression guard: a non-streaming
// plain-JSON response (the shape parseUsage handled before SSE support was added) must
// still parse via the plain-JSON path, not accidentally fall through to SSE scanning.
func TestParseUsageAnthropicPlainJSONRegression(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","usage":{"input_tokens":11,"output_tokens":22}}`))
	}))
	t.Cleanup(backend.Close)

	fe := &fakeEmitter{}
	b := mustBroker(t, Config{Emitter: fe, Anthropic: Upstream{BaseURL: backend.URL, Key: "real-key"}})
	srv := testServer(t, b)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/anthropic/v1/messages",
		bytes.NewReader([]byte(`{"model":"claude-test","messages":[]}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("model request: %v", err)
	}
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model status = %d, want 200", resp.StatusCode)
	}

	compEv := fe.byName(evidence.EventModelCompleted)
	if len(compEv) != 1 {
		t.Fatalf("model.completed count = %d, want 1", len(compEv))
	}
	attrs := compEv[0].ev.Attrs
	if attrs[attrUsageInput] != int64(11) || attrs[attrUsageOutput] != int64(22) {
		t.Fatalf("usage attrs = %+v, want input=11 output=22", attrs)
	}
}
