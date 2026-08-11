package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"boxedai/internal/evidence"
	"boxedai/internal/policy"
)

// fakeEmitter is a real in-memory Emitter capturing (channel, event) pairs, per the
// evidence.Emitter contract (never silently drops). failOn simulates a recorder failure.
type fakeEmitter struct {
	mu     sync.Mutex
	events []captured
	failOn string
}

type captured struct {
	ch evidence.Channel
	ev evidence.Event
}

func (f *fakeEmitter) Emit(ch evidence.Channel, ev evidence.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn != "" && ev.Name == f.failOn {
		return fmt.Errorf("simulated emit failure for %s", ev.Name)
	}
	f.events = append(f.events, captured{ch: ch, ev: ev})
	return nil
}

func (f *fakeEmitter) byName(name string) []captured {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []captured
	for _, c := range f.events {
		if c.ev.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeEmitter) has(name string) bool { return len(f.byName(name)) > 0 }

func (f *fakeEmitter) last() captured {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.events[len(f.events)-1]
}

// --- helpers -------------------------------------------------------------------------

func mustBroker(t *testing.T, cfg Config) *Broker {
	t.Helper()
	if cfg.Emitter == nil {
		cfg.Emitter = &fakeEmitter{}
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func testServer(t *testing.T, b *Broker) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(b.routes())
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, method, url, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func drain(resp *http.Response) { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }

func decodeMap(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return m
}

// echoTool wires a policy + adapter table around /bin/echo so tool/effect dispatch runs
// deterministically without external binaries.
func echoToolConfig() Config {
	return Config{
		Emitter: &fakeEmitter{},
		Policy: policy.Policy{
			Schema:  "boxedai.policy/v1",
			Profile: policy.ProfileDevelop,
			Tools:   map[string][]string{"echo": {"say"}},
			Effects: map[string][]string{"github": {"pr-comment"}},
		},
		Tools:   map[string]map[string][]string{"echo": {"say": {"/bin/echo", "{{msg}}"}}},
		Effects: map[string]map[string][]string{"github": {"pr-comment": {"/bin/echo", "{{pr}}", "{{body}}"}}},
	}
}

// --- tests ---------------------------------------------------------------------------

func TestHealthzNeedsNoAuth(t *testing.T) {
	srv := testServer(t, mustBroker(t, Config{Emitter: &fakeEmitter{}}))
	resp := do(t, http.MethodGet, srv.URL+"/v1/healthz", "", "")
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
}

func TestTokenAuth(t *testing.T) {
	b := mustBroker(t, echoToolConfig())
	srv := testServer(t, b)
	url := srv.URL + "/v1/tools/echo/say"

	// No token.
	if resp := do(t, http.MethodPost, url, "", `{"msg":"x"}`); resp.StatusCode != http.StatusUnauthorized {
		drain(resp)
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	} else {
		drain(resp)
	}

	// Bad token.
	if resp := do(t, http.MethodPost, url, "not-the-token", `{"msg":"x"}`); resp.StatusCode != http.StatusUnauthorized {
		drain(resp)
		t.Fatalf("bad-token status = %d, want 401", resp.StatusCode)
	} else {
		drain(resp)
	}

	// Supervisor token on a W-only route is rejected.
	if resp := do(t, http.MethodPost, url, b.SupervisorToken(), `{"msg":"x"}`); resp.StatusCode != http.StatusUnauthorized {
		drain(resp)
		t.Fatalf("S-on-W-route status = %d, want 401", resp.StatusCode)
	} else {
		drain(resp)
	}

	// Workload token on the W-only route succeeds.
	if resp := do(t, http.MethodPost, url, b.WorkloadToken(), `{"msg":"hi"}`); resp.StatusCode != http.StatusOK {
		drain(resp)
		t.Fatalf("W-on-W-route status = %d, want 200", resp.StatusCode)
	} else {
		drain(resp)
	}
}

func TestWorkloadTokenRejectedOnSupervisorRoute(t *testing.T) {
	b := mustBroker(t, Config{
		Emitter:     &fakeEmitter{},
		AgentBinary: func(string) ([]byte, error) { return []byte("BINARY"), nil },
	})
	srv := testServer(t, b)
	url := srv.URL + "/v1/guest/agent-binary?arch=arm64"

	if resp := do(t, http.MethodGet, url, b.WorkloadToken(), ""); resp.StatusCode != http.StatusUnauthorized {
		drain(resp)
		t.Fatalf("W-on-S-route status = %d, want 401", resp.StatusCode)
	} else {
		drain(resp)
	}

	resp := do(t, http.MethodGet, url, b.SupervisorToken(), "")
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("S-on-S-route status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "BINARY" {
		t.Fatalf("agent-binary body = %q, want BINARY", body)
	}
}

func TestToolAllowEmitsAuthorizationAndDispatches(t *testing.T) {
	cfg := echoToolConfig()
	fe := cfg.Emitter.(*fakeEmitter)
	b := mustBroker(t, cfg)
	srv := testServer(t, b)

	resp := do(t, http.MethodPost, srv.URL+"/v1/tools/echo/say", b.WorkloadToken(), `{"msg":"hello"}`)
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allow status = %d, want 200", resp.StatusCode)
	}
	out, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(out)) != "hello" {
		t.Fatalf("tool output = %q, want hello", out)
	}

	decided := fe.byName(evidence.EventAuthorizationDecided)
	if len(decided) != 1 {
		t.Fatalf("authorization.decided count = %d, want 1", len(decided))
	}
	if got := decided[0].ev.Attrs[attrDecision]; got != decisionAllow {
		t.Fatalf("decision = %v, want allow", got)
	}
	if decided[0].ch != evidence.ChannelBroker {
		t.Fatalf("authorization.decided channel = %q, want broker", decided[0].ch)
	}
	if !fe.has(evidence.EventInternalToolDispatched) || !fe.has(evidence.EventInternalToolCompleted) {
		t.Fatalf("expected dispatched+completed events, got %v", eventNames(fe))
	}
	// completed carries a result digest, never a body.
	comp := fe.byName(evidence.EventInternalToolCompleted)[0]
	if d, _ := comp.ev.Attrs[evidence.AttrContentDigest].(string); !strings.HasPrefix(d, "sha256:") {
		t.Fatalf("completed content digest = %q, want sha256:...", d)
	}
}

func TestToolDenyEmitsAuthorizationNoDispatch(t *testing.T) {
	cfg := echoToolConfig()
	fe := cfg.Emitter.(*fakeEmitter)
	b := mustBroker(t, cfg)
	srv := testServer(t, b)

	// "nope" is not granted by policy for the echo tool.
	resp := do(t, http.MethodPost, srv.URL+"/v1/tools/echo/nope", b.WorkloadToken(), `{"msg":"x"}`)
	defer drain(resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("deny status = %d, want 403", resp.StatusCode)
	}
	decided := fe.byName(evidence.EventAuthorizationDecided)
	if len(decided) != 1 || decided[0].ev.Attrs[attrDecision] != decisionDeny {
		t.Fatalf("expected one deny decision, got %+v", decided)
	}
	if decided[0].ev.Outcome != evidence.OutcomeDenied {
		t.Fatalf("deny outcome = %q, want denied", decided[0].ev.Outcome)
	}
	if fe.has(evidence.EventInternalToolDispatched) {
		t.Fatalf("denied tool must not dispatch")
	}
}

func TestToolPlaceholderRejectsUnknownAndMissingFields(t *testing.T) {
	b := mustBroker(t, echoToolConfig())
	fe := b.cfg.Emitter.(*fakeEmitter)
	srv := testServer(t, b)

	// Unknown field "extra" not consumed by any placeholder.
	resp := do(t, http.MethodPost, srv.URL+"/v1/tools/echo/say", b.WorkloadToken(), `{"msg":"hi","extra":"x"}`)
	defer drain(resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown-field status = %d, want 400", resp.StatusCode)
	}
	if fe.has(evidence.EventInternalToolDispatched) || fe.has(evidence.EventInternalToolCompleted) {
		t.Fatalf("strict substitution must reject before dispatch")
	}

	// Missing placeholder value.
	resp2 := do(t, http.MethodPost, srv.URL+"/v1/tools/echo/say", b.WorkloadToken(), `{}`)
	defer drain(resp2)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing-field status = %d, want 400", resp2.StatusCode)
	}
}

func TestEffectDeniedApproverNoDispatch(t *testing.T) {
	cfg := echoToolConfig()
	cfg.Approver = func(NormalizedAction) bool { return false }
	fe := cfg.Emitter.(*fakeEmitter)
	b := mustBroker(t, cfg)
	srv := testServer(t, b)

	resp := do(t, http.MethodPost, srv.URL+"/v1/effects/github/pr-comment", b.WorkloadToken(), `{"pr":"1","body":"hi"}`)
	defer drain(resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied-approver status = %d, want 403", resp.StatusCode)
	}
	if !fe.has(evidence.EventEffectRequested) {
		t.Fatalf("expected effect.requested")
	}
	if !fe.has(evidence.EventEffectDenied) {
		t.Fatalf("expected effect.denied")
	}
	if fe.has(evidence.EventEffectApproved) || fe.has(evidence.EventEffectDispatched) {
		t.Fatalf("denied effect must not approve or dispatch")
	}
}

func TestEffectPolicyDeniedDoesNotPromptApprover(t *testing.T) {
	cfg := echoToolConfig()
	// Policy does NOT grant github/push.
	promptCalled := false
	cfg.Approver = func(NormalizedAction) bool { promptCalled = true; return true }
	fe := cfg.Emitter.(*fakeEmitter)
	b := mustBroker(t, cfg)
	srv := testServer(t, b)

	resp := do(t, http.MethodPost, srv.URL+"/v1/effects/github/push", b.WorkloadToken(), `{"remote":"origin","branch":"main"}`)
	defer drain(resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("policy-denied status = %d, want 403", resp.StatusCode)
	}
	if promptCalled {
		t.Fatalf("approver must not be prompted for a policy-denied effect")
	}
	if !fe.has(evidence.EventEffectDenied) || fe.has(evidence.EventEffectDispatched) {
		t.Fatalf("expected effect.denied, no dispatch")
	}
}

func TestEffectApprovedDispatchesWithSameDigest(t *testing.T) {
	cfg := echoToolConfig()
	cfg.Approver = func(NormalizedAction) bool { return true }
	fe := cfg.Emitter.(*fakeEmitter)
	b := mustBroker(t, cfg)
	srv := testServer(t, b)

	resp := do(t, http.MethodPost, srv.URL+"/v1/effects/github/pr-comment", b.WorkloadToken(), `{"pr":"1","body":"looks good"}`)
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approved status = %d, want 200", resp.StatusCode)
	}
	for _, name := range []string{
		evidence.EventEffectRequested, evidence.EventEffectApproved,
		evidence.EventEffectDispatched, evidence.EventEffectCompleted,
	} {
		if !fe.has(name) {
			t.Fatalf("expected %s, got %v", name, eventNames(fe))
		}
	}
	// requested, approved and dispatched must carry the SAME action digest.
	reqDigest := fe.byName(evidence.EventEffectRequested)[0].ev.Attrs[evidence.AttrContentDigest]
	appDigest := fe.byName(evidence.EventEffectApproved)[0].ev.Attrs[evidence.AttrContentDigest]
	dispDigest := fe.byName(evidence.EventEffectDispatched)[0].ev.Attrs[evidence.AttrContentDigest]
	if reqDigest != appDigest || appDigest != dispDigest {
		t.Fatalf("action digest drifted: requested=%v approved=%v dispatched=%v", reqDigest, appDigest, dispDigest)
	}
	// The digest must match a freshly computed NormalizedAction digest.
	want, _ := NormalizedAction{Adapter: "github", Op: "pr-comment", Args: map[string]string{"pr": "1", "body": "looks good"}}.Digest()
	if reqDigest != want {
		t.Fatalf("action digest = %v, want %v", reqDigest, want)
	}
}

func TestEventsIngestChannelFromToken(t *testing.T) {
	cases := []struct {
		name   string
		token  func(*Broker) string
		wantCh evidence.Channel
	}{
		{"workload", (*Broker).WorkloadToken, evidence.ChannelWorkload},
		{"supervisor", (*Broker).SupervisorToken, evidence.ChannelGuestSupervisor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fe := &fakeEmitter{}
			b := mustBroker(t, Config{Emitter: fe})
			srv := testServer(t, b)
			body := `{"events":[{"name":"file.changed","outcome":"success"}]}`
			resp := do(t, http.MethodPost, srv.URL+"/v1/events", tc.token(b), body)
			m := decodeMap(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("events status = %d, want 200", resp.StatusCode)
			}
			if m["accepted"].(float64) != 1 {
				t.Fatalf("accepted = %v, want 1", m["accepted"])
			}
			got := fe.last()
			if got.ch != tc.wantCh {
				t.Fatalf("ingest channel = %q, want %q", got.ch, tc.wantCh)
			}
			if got.ev.Name != "file.changed" {
				t.Fatalf("ingest event name = %q, want file.changed", got.ev.Name)
			}
		})
	}
}

func TestEventsIngestSurfacesEmitFailure(t *testing.T) {
	fe := &fakeEmitter{failOn: "file.changed"}
	b := mustBroker(t, Config{Emitter: fe})
	srv := testServer(t, b)
	resp := do(t, http.MethodPost, srv.URL+"/v1/events", b.SupervisorToken(), `{"events":[{"name":"file.changed"}]}`)
	m := decodeMap(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 on emit failure", resp.StatusCode)
	}
	if m["rejected"].(float64) != 1 {
		t.Fatalf("rejected = %v, want 1", m["rejected"])
	}
}

func TestModelProxyStripsAuthInjectsKeyAndDigests(t *testing.T) {
	var gotAuth, gotKey, gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-Api-Key")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","usage":{"input_tokens":11,"output_tokens":22}}`))
	}))
	t.Cleanup(backend.Close)

	fe := &fakeEmitter{}
	b := mustBroker(t, Config{
		Emitter:   fe,
		Anthropic: Upstream{BaseURL: backend.URL, Key: "real-key"},
	})
	srv := testServer(t, b)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/anthropic/v1/messages",
		bytes.NewReader([]byte(`{"model":"claude-test","messages":[]}`)))
	req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
	req.Header.Set("X-Api-Key", "inbound-should-be-stripped")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("model request: %v", err)
	}
	body := decodeMap(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model status = %d, want 200", resp.StatusCode)
	}
	if body["id"] != "msg_1" {
		t.Fatalf("response not passed through: %v", body)
	}
	if gotAuth != "" {
		t.Fatalf("upstream Authorization = %q, want stripped", gotAuth)
	}
	if gotKey != "real-key" {
		t.Fatalf("upstream X-Api-Key = %q, want real-key", gotKey)
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("upstream path = %q, want /v1/messages", gotPath)
	}

	reqEv := fe.byName(evidence.EventModelRequested)
	if len(reqEv) != 1 || reqEv[0].ev.Attrs[attrModelID] != "claude-test" {
		t.Fatalf("model.requested missing or wrong model id: %+v", reqEv)
	}
	compEv := fe.byName(evidence.EventModelCompleted)
	if len(compEv) != 1 {
		t.Fatalf("model.completed count = %d, want 1", len(compEv))
	}
	if compEv[0].ev.Attrs[attrUsageInput] != int64(11) || compEv[0].ev.Attrs[attrUsageOutput] != int64(22) {
		t.Fatalf("usage attrs = %+v, want input=11 output=22", compEv[0].ev.Attrs)
	}
	if d, _ := compEv[0].ev.Attrs[evidence.AttrContentDigest].(string); !strings.HasPrefix(d, "sha256:") {
		t.Fatalf("model.completed content digest = %q, want sha256:...", d)
	}
}

func TestStartRevokeStopLifecycle(t *testing.T) {
	b := mustBroker(t, echoToolConfig())
	port, err := b.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Stop() })
	if port <= 0 {
		t.Fatalf("Start port = %d, want > 0", port)
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	// healthz is reachable on the bound port.
	resp := do(t, http.MethodGet, base+"/v1/healthz", "", "")
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz over port = %d, want 200", resp.StatusCode)
	}

	// A valid W request works before revocation.
	r1 := do(t, http.MethodPost, base+"/v1/tools/echo/say", b.WorkloadToken(), `{"msg":"hi"}`)
	drain(r1)
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke tool = %d, want 200", r1.StatusCode)
	}

	// After Revoke, the same valid token is rejected 401.
	b.Revoke()
	r2 := do(t, http.MethodPost, base+"/v1/tools/echo/say", b.WorkloadToken(), `{"msg":"hi"}`)
	drain(r2)
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-revoke tool = %d, want 401", r2.StatusCode)
	}
}

func TestDistinctTokens(t *testing.T) {
	b := mustBroker(t, Config{Emitter: &fakeEmitter{}})
	if b.WorkloadToken() == b.SupervisorToken() {
		t.Fatalf("workload and supervisor tokens must differ")
	}
	if len(b.WorkloadToken()) != 64 { // 32 bytes hex
		t.Fatalf("token length = %d, want 64 hex chars", len(b.WorkloadToken()))
	}
}

func eventNames(fe *fakeEmitter) []string {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	var out []string
	for _, c := range fe.events {
		out = append(out, c.ev.Name)
	}
	return out
}
