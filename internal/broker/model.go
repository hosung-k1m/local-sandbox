package broker

import (
	"bytes"
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
		for k, v := range parseUsage(provider, body) {
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

// extractModel pulls the "model" field from a model request body, best-effort.
func extractModel(body []byte) string {
	var parsed struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &parsed)
	return parsed.Model
}

// parseUsage extracts token counts from a model response body if present, mapping
// provider-specific field names to the common llm.usage.* attributes.
func parseUsage(provider string, body []byte) map[string]any {
	var parsed struct {
		Usage map[string]json.Number `json:"usage"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil || parsed.Usage == nil {
		return nil
	}
	get := func(k string) (int64, bool) {
		n, ok := parsed.Usage[k]
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
		if v, ok := get("input_tokens"); ok {
			out[attrUsageInput] = v
		}
		if v, ok := get("output_tokens"); ok {
			out[attrUsageOutput] = v
		}
	case providerOpenAI:
		if v, ok := get("prompt_tokens"); ok {
			out[attrUsageInput] = v
		}
		if v, ok := get("completion_tokens"); ok {
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
