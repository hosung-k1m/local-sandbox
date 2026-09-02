package broker

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// authKind identifies which bearer token authenticated a request.
type authKind int

const (
	authNone authKind = iota
	authWorkload
	authSupervisor
	authOpenAI
)

// authenticate resolves the presented bearer to a token identity, or authNone if the
// header is missing/malformed, the token matches neither, or the broker is revoked.
func (b *Broker) authenticate(r *http.Request) authKind {
	if b.revoked.Load() {
		return authNone
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return authNone
	}
	switch {
	case tokenMatch(tok, b.workloadToken):
		return authWorkload
	case tokenMatch(tok, b.supervisorToken):
		return authSupervisor
	case b.cfg.OpenAI.ChatGPTAccountID != "" && tokenMatch(tok, b.cfg.OpenAI.Key):
		return authOpenAI
	default:
		return authNone
	}
}

func (b *Broker) modelAuth(provider string, h func(http.ResponseWriter, *http.Request, authKind)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind := b.authenticate(r)
		if kind != authWorkload && !(provider == providerOpenAI && kind == authOpenAI) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r, kind)
	}
}

// auth wraps a handler with bearer authentication scoped to the allowed token kinds.
// A valid token of the wrong kind (W on an S-only route or vice versa) is rejected 401,
// matching DESIGN.md's W/S route separation.
func (b *Broker) auth(allowW, allowS bool, h func(http.ResponseWriter, *http.Request, authKind)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind := b.authenticate(r)
		ok := (kind == authWorkload && allowW) || (kind == authSupervisor && allowS)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r, kind)
	}
}

// tokenMatch compares in constant time. A zero actual (unset token) never matches.
func tokenMatch(provided, actual string) bool {
	if actual == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(actual)) == 1
}
