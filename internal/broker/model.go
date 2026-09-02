package broker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"boxedai/internal/evidence"
)

const (
	providerAnthropic = "anthropic"
	providerOpenAI    = "openai"
)

const (
	// anthropicOAuthKeyPrefix marks an Anthropic key as a Claude Code OAuth access
	// token (minted by `claude setup-token` style device login) rather than a
	// platform API key. OAuth tokens authenticate as a Bearer credential and require
	// the anthropicOAuthBeta feature flag; API keys use X-Api-Key and no beta flag.
	anthropicOAuthKeyPrefix = "sk-ant-oat"
	// anthropicBetaHeader is Anthropic's feature-flag header. The guest's Claude
	// Code sends its own values here (e.g. for prompt-caching or other betas); the
	// proxy must preserve those and only append the OAuth flag when missing.
	anthropicBetaHeader = "Anthropic-Beta"
	// anthropicOAuthBeta is the beta flag value the Anthropic API requires to accept
	// a Bearer(OAuth) credential in place of an X-Api-Key.
	anthropicOAuthBeta = "oauth-2025-04-20"
	// chatgptAccountIDHeader is the header the ChatGPT Codex backend requires when
	// authenticating with a ChatGPT (ChatGPT Plus/Pro device login) credential
	// rather than a platform API key.
	chatgptAccountIDHeader = "chatgpt-account-id"
	// Claude Code stamps the acting subagent's identity on subagent API requests
	// (v2.1.139+). The broker records these as claimed provenance on
	// model.requested and strips them before forwarding, so a workload-chosen
	// label never reaches the provider.
	claudeAgentIDHeader       = "X-Claude-Code-Agent-Id"
	claudeParentAgentIDHeader = "X-Claude-Code-Parent-Agent-Id"
	claudeSessionIDHeader     = "X-Claude-Code-Session-Id"
	// Codex carries equivalent self-reported lifecycle identity in the Responses
	// request metadata. These must remain upstream because Codex's backend may
	// consume them.
	codexTurnMetadataHeader   = "X-Codex-Turn-Metadata"
	codexParentThreadIDHeader = "X-Codex-Parent-Thread-Id"
	codexSubagentHeader       = "X-OpenAI-Subagent"
	// maxClaimedHeaderChars bounds the workload-controlled header values stored.
	maxClaimedHeaderChars = 256
)

// modelCallKey stashes the per-request modelCall in the request context so ModifyResponse
// and ErrorHandler can correlate the completion with its request.
type modelCallKey struct{}

// modelCall carries request-side state from the handler into the proxy callbacks.
type modelCall struct {
	actionID string
	provider string
}

// newModelProxy builds the reverse proxy for one upstream, or returns nil (with no
// error) if the upstream is unconfigured — the handler then responds 502.
func (b *Broker) newModelProxy(provider string, up Upstream) (*httputil.ReverseProxy, error) {
	if up.BaseURL == "" {
		return nil, nil
	}
	target, err := url.Parse(up.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("broker: parse %s base url: %w", provider, err)
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			rest := pr.In.PathValue("path")
			pr.SetURL(target) // sets scheme/host and Out.Host=""
			pr.Out.URL.Path = joinPath(target.Path, rest)
			pr.Out.URL.RawPath = ""
			// Strip any inbound credential (including the workload bearer) and inject the
			// real host key. Headers are never recorded.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("X-Api-Key")
			pr.Out.Header.Del(chatgptAccountIDHeader)
			// The workload's self-reported agent-identity headers are recorded on
			// model.requested as claimed provenance; they must never reach the
			// provider (DESIGN.md "Agent hierarchy and attribution").
			pr.Out.Header.Del(claudeAgentIDHeader)
			pr.Out.Header.Del(claudeParentAgentIDHeader)
			pr.Out.Header.Del(claudeSessionIDHeader)
			// Strip the workload's Accept-Encoding: the guest HTTP client asks for
			// codings the host cannot decode (undici requests br/zstd), which would
			// leave ModifyResponse digesting and parsing opaque compressed bytes.
			// With it gone, Go's transport negotiates its own gzip and transparently
			// decodes it, so the digest, usage parsing, and the bytes forwarded to
			// the workload are always the identical plain payload.
			pr.Out.Header.Del("Accept-Encoding")
			if up.Key != "" {
				switch provider {
				case providerAnthropic:
					if strings.HasPrefix(up.Key, anthropicOAuthKeyPrefix) {
						// Claude Code OAuth access token: Bearer auth, and the API
						// requires the oauth beta flag alongside whatever betas the
						// guest's Claude Code already requested.
						pr.Out.Header.Set("Authorization", "Bearer "+up.Key)
						addAnthropicOAuthBeta(pr.Out.Header)
					} else {
						pr.Out.Header.Set("X-Api-Key", up.Key)
					}
				case providerOpenAI:
					pr.Out.Header.Set("Authorization", "Bearer "+up.Key)
					if up.ChatGPTAccountID != "" {
						pr.Out.Header.Set(chatgptAccountIDHeader, up.ChatGPTAccountID)
					}
				}
			}
		},
		ModifyResponse: b.modelModifyResponse(provider),
		ErrorHandler:   b.modelErrorHandler(provider),
	}, nil
}

// addAnthropicOAuthBeta ensures the outbound anthropic-beta header set (the guest's
// Claude Code sends its own feature betas, and callers may repeat the header or
// comma-join values within one line) includes the OAuth beta flag exactly once,
// appending it to the existing header rather than clobbering the guest's betas.
func addAnthropicOAuthBeta(h http.Header) {
	// Header.Values returns every "Anthropic-Beta" line as sent (there can be more
	// than one per RFC 7230 §3.2.2, each itself possibly a comma-separated list).
	values := h.Values(anthropicBetaHeader)
	for _, line := range values {
		for _, v := range strings.Split(line, ",") {
			if strings.TrimSpace(v) == anthropicOAuthBeta {
				return // already present, nothing to add
			}
		}
	}
	if len(values) == 0 {
		h.Set(anthropicBetaHeader, anthropicOAuthBeta)
		return
	}
	// Collapse to one canonical header line, preserving every guest-requested beta.
	h.Set(anthropicBetaHeader, strings.Join(values, ",")+","+anthropicOAuthBeta)
}

// serveModel returns the handler for a model route. It digests the request body, emits
// model.requested, then hands off to the reverse proxy (which emits model.completed).
func (b *Broker) serveModel(provider string, proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request, authKind) {
	return func(w http.ResponseWriter, r *http.Request, _ authKind) {
		if proxy == nil {
			writeErr(w, http.StatusBadGateway, provider+" upstream not configured")
			return
		}
		body, err := readBody(r, maxModelBody)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		actionID := newActionID()
		attrs := map[string]any{
			attrProvider:                provider,
			evidence.AttrContentDigest:  evidence.SHA256Hex(body),
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
		}
		if model := extractModel(body); model != "" {
			attrs[attrModelID] = model
		}
		addClaimedAgentAttrs(attrs, r.Header)
		if err := b.emit(evidence.ChannelBroker, evidence.Event{
			Name:     evidence.EventModelRequested,
			Class:    evidence.ClassBrokerMediated,
			Outcome:  evidence.OutcomeSuccess,
			ActionID: actionID,
			Body:     "model request to " + provider,
			Attrs:    attrs,
		}); err != nil {
			writeErr(w, http.StatusInternalServerError, "evidence emit failed")
			return
		}

		// Restore the consumed body for the proxy and carry correlation state forward.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		ctx := context.WithValue(r.Context(), modelCallKey{}, &modelCall{actionID: actionID, provider: provider})
		proxy.ServeHTTP(w, r.WithContext(ctx))
	}
}

// modelModifyResponse buffers the upstream response to digest it and parse token usage,
// then restores the body so the client still receives it. Bodies are never stored.
func (b *Broker) modelModifyResponse(provider string) func(*http.Response) error {
	return func(resp *http.Response) error {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("read %s upstream response: %w", provider, err)
		}
		_ = resp.Body.Close()

		// Defense in depth: the proxy strips the workload's Accept-Encoding, so a
		// compressed body should already have been transport-negotiated gzip and
		// transparently decoded before this callback. If a non-compliant upstream
		// compresses anyway, usage is parsed from a decoded COPY; the digest, the
		// client passthrough bytes, the Content-Length, and every header below all
		// stay over the untouched raw body — this decode exists only to parse usage.
		usageBody := body
		if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			if decoded, ok := gunzipForUsageParsing(body); ok {
				usageBody = decoded
			}
		}

		actionID := ""
		if mc, ok := resp.Request.Context().Value(modelCallKey{}).(*modelCall); ok {
			actionID = mc.actionID
		}
		attrs := map[string]any{
			attrProvider:                provider,
			attrHTTPStatus:              int64(resp.StatusCode),
			evidence.AttrContentDigest:  evidence.SHA256Hex(body),
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
		}
		for k, v := range parseUsage(provider, usageBody) {
			attrs[k] = v
		}
		outcome := evidence.OutcomeSuccess
		if resp.StatusCode >= 400 {
			outcome = evidence.OutcomeFailure
		}
		if err := b.emit(evidence.ChannelBroker, evidence.Event{
			Name:     evidence.EventModelCompleted,
			Class:    evidence.ClassBrokerMediated,
			Outcome:  outcome,
			ActionID: actionID,
			Body:     "model response from " + provider,
			Attrs:    attrs,
		}); err != nil {
			return err
		}

		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
}

// modelErrorHandler records a failed completion when the upstream is unreachable or a
// proxy callback errors, and returns 502 to the client.
func (b *Broker) modelErrorHandler(provider string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		actionID := ""
		if mc, ok := r.Context().Value(modelCallKey{}).(*modelCall); ok {
			actionID = mc.actionID
		}
		_ = b.emit(evidence.ChannelBroker, evidence.Event{
			Name:     evidence.EventModelCompleted,
			Class:    evidence.ClassBrokerMediated,
			Outcome:  evidence.OutcomeFailure,
			ActionID: actionID,
			Body:     "model request to " + provider + " failed",
			Attrs:    map[string]any{attrProvider: provider, attrError: err.Error()},
		})
		writeErr(w, http.StatusBadGateway, "upstream request failed")
	}
}

// addClaimedAgentAttrs records the workload's self-reported agent-identity headers
// on a model event as claimed provenance (bounded). They are believed by nothing —
// model attribution is session-level — and are stripped from the upstream request
// in the proxy Rewrite; recording them keeps the claim forensically visible.
func addClaimedAgentAttrs(attrs map[string]any, h http.Header) {
	for header, key := range map[string]string{
		claudeAgentIDHeader:       attrClaimedAgentID,
		claudeParentAgentIDHeader: attrClaimedParentAgentID,
		claudeSessionIDHeader:     attrClaimedSessionID,
	} {
		if v := h.Get(header); v != "" {
			attrs[key] = capRunes(v, maxClaimedHeaderChars)
		}
	}
	var metadata struct {
		SessionID      string `json:"session_id"`
		ThreadID       string `json:"thread_id"`
		ParentThreadID string `json:"parent_thread_id"`
	}
	if raw := h.Get(codexTurnMetadataHeader); raw != "" && json.Unmarshal([]byte(raw), &metadata) == nil {
		if metadata.ThreadID != "" {
			attrs[attrClaimedAgentID] = capRunes(metadata.ThreadID, maxClaimedHeaderChars)
		}
		if metadata.ParentThreadID != "" {
			attrs[attrClaimedParentAgentID] = capRunes(metadata.ParentThreadID, maxClaimedHeaderChars)
		}
		if metadata.SessionID != "" {
			attrs[attrClaimedSessionID] = capRunes(metadata.SessionID, maxClaimedHeaderChars)
		}
	}
	// Some Codex versions carry the parent outside metadata. It is still just a
	// claim and only fills a missing metadata field.
	if _, ok := attrs[attrClaimedParentAgentID]; !ok {
		if v := h.Get(codexParentThreadIDHeader); v != "" {
			attrs[attrClaimedParentAgentID] = capRunes(v, maxClaimedHeaderChars)
		}
	}
}

// capRunes bounds s to max runes without splitting a multi-byte sequence.
func capRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// extractModel pulls the "model" field from a model request body, best-effort.
func extractModel(body []byte) string {
	var parsed struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &parsed)
	return parsed.Model
}

// maxGunzipDecodeBytes caps the size of the gzip-decoded COPY made for usage parsing
// only, guarding against a decompression bomb; the client-visible response bytes are
// completely unaffected by this cap regardless of outcome.
const maxGunzipDecodeBytes = 32 << 20 // 32 MiB

// gunzipForUsageParsing decodes a gzip-compressed response body into a separate copy
// for usage parsing only; body itself is never consumed or mutated. It reports ok=false
// on any error (not actually gzip, corrupt, or larger than maxGunzipDecodeBytes), and
// the caller falls back to parsing the raw body, matching this file's existing
// best-effort parsing style (see extractModel).
func gunzipForUsageParsing(body []byte) (decoded []byte, ok bool) {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	decoded, err = io.ReadAll(io.LimitReader(zr, maxGunzipDecodeBytes+1))
	if err != nil || int64(len(decoded)) > maxGunzipDecodeBytes {
		return nil, false
	}
	return decoded, true
}

// parseUsage extracts token counts from a model response body, mapping provider-
// specific field names to the common llm.usage.* attributes. Claude Code always
// requests SSE streaming, so a real response is almost never a plain JSON object: a
// plain top-level "usage" object (the non-streaming shape) is tried first, and any body
// that isn't one, or carries no usage there, falls back to scanning it as Server-Sent
// Events.
func parseUsage(provider string, body []byte) map[string]any {
	if out := parsePlainUsage(provider, body); out != nil {
		return out
	}
	return parseSSEUsage(provider, body)
}

// parsePlainUsage parses body as a single non-streaming JSON object with a top-level
// "usage" field — the shape the original parseUsage handled before SSE support existed.
func parsePlainUsage(provider string, body []byte) map[string]any {
	var parsed struct {
		Usage map[string]any `json:"usage"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil || parsed.Usage == nil {
		return nil
	}
	return usageAttrs(provider, parsed.Usage)
}

// usageAttrs maps one raw provider usage field map to the common llm.usage.* attributes,
// emitting only the fields the provider actually reported (an absent field stays absent;
// an empty/unrecognized usage map yields nil, never a zero-value attr). Shared by both
// the plain-JSON and SSE parsing paths so the field-name mapping cannot drift between
// them. The map value type is any, not json.Number: a real Anthropic usage object also
// carries strings, objects, and arrays (service_tier, server_tool_use, cache_creation,
// iterations, speed), and decoding those into json.Number would fail the WHOLE usage
// object, silently dropping the token counts next to them. Callers decode with
// UseNumber, so numeric fields arrive here as json.Number.
func usageAttrs(provider string, usage map[string]any) map[string]any {
	get := func(k string) (int64, bool) {
		n, ok := usage[k].(json.Number)
		if !ok {
			return 0, false
		}
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	}
	out := map[string]any{}
	switch provider {
	case providerAnthropic:
		// cache_creation_input_tokens / cache_read_input_tokens are deliberately
		// ignored: only the common input/output counts are recorded.
		if v, ok := get("input_tokens"); ok {
			out[attrUsageInput] = v
		}
		if v, ok := get("output_tokens"); ok {
			out[attrUsageOutput] = v
		}
	case providerOpenAI:
		// Chat Completions (prompt_tokens/completion_tokens) and the Responses API
		// (input_tokens/output_tokens) name the same counts differently; a single usage
		// object only ever carries one of the two namings, so trying both is safe.
		if v, ok := get("prompt_tokens"); ok {
			out[attrUsageInput] = v
		} else if v, ok := get("input_tokens"); ok {
			out[attrUsageInput] = v
		}
		if v, ok := get("completion_tokens"); ok {
			out[attrUsageOutput] = v
		} else if v, ok := get("output_tokens"); ok {
			out[attrUsageOutput] = v
		}
		if v, ok := get("total_tokens"); ok {
			out[attrUsageTotal] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSSEUsage scans body as Server-Sent Events — the shape of every real streaming
// model response. Each "data:" line decodes independently; recognized usage fields fold
// into a last-value-wins map so that Anthropic's cumulative message_delta usage and
// OpenAI's single whole-usage chunk/event both converge on the correct final counts.
func parseSSEUsage(provider string, body []byte) map[string]any {
	out := map[string]any{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r") // tolerate CRLF line endings
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		switch provider {
		case providerAnthropic:
			applyAnthropicSSELine(data, out)
		case providerOpenAI:
			applyOpenAISSELine(data, out)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// applyAnthropicSSELine decodes one Anthropic SSE data line and folds any usage it
// carries into out. message_start's usage lives under "message"; message_delta's usage
// is a top-level field on the event itself (cumulative — a later delta naturally
// overwrites an earlier one as the stream is scanned in order).
func applyAnthropicSSELine(data string, out map[string]any) {
	var evt struct {
		Type    string `json:"type"`
		Message struct {
			Usage map[string]any `json:"usage"`
		} `json:"message"`
		Usage map[string]any `json:"usage"`
	}
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&evt); err != nil {
		return // malformed/non-JSON data line; ignore, best-effort like extractModel
	}
	var usage map[string]any
	switch evt.Type {
	case "message_start":
		usage = evt.Message.Usage
	case "message_delta":
		usage = evt.Usage
	default:
		return
	}
	for k, v := range usageAttrs(providerAnthropic, usage) {
		out[k] = v
	}
}

// applyOpenAISSELine decodes one OpenAI SSE data line, handling both Chat Completions
// chunks (a top-level "usage" object appears only on the final chunk, when
// stream_options.include_usage is set) and Responses-API "response.completed" events
// (usage nested under "response").
func applyOpenAISSELine(data string, out map[string]any) {
	var evt struct {
		Type     string         `json:"type"`
		Usage    map[string]any `json:"usage"`
		Response struct {
			Usage map[string]any `json:"usage"`
		} `json:"response"`
	}
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&evt); err != nil {
		return
	}
	usage := evt.Usage
	if evt.Type == "response.completed" {
		usage = evt.Response.Usage
	}
	for k, v := range usageAttrs(providerOpenAI, usage) {
		out[k] = v
	}
}

// joinPath joins an upstream base path with the captured request tail using a single
// separating slash.
func joinPath(base, rest string) string {
	base = strings.TrimSuffix(base, "/")
	rest = strings.TrimPrefix(rest, "/")
	switch {
	case rest == "":
		if base == "" {
			return "/"
		}
		return base
	case base == "":
		return "/" + rest
	default:
		return base + "/" + rest
	}
}
