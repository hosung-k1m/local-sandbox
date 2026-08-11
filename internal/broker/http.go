package broker

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// errBodyTooLarge is returned by readBody when the request exceeds the route limit.
var errBodyTooLarge = errors.New("request body too large")

// writeJSON encodes v as the response body with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr writes a JSON {"error": msg} body with the given status.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readBody reads up to limit bytes from r.Body, rejecting anything larger rather than
// silently truncating (which would corrupt the recorded content digest).
func readBody(r *http.Request, limit int64) ([]byte, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, errBodyTooLarge
	}
	return body, nil
}

// decodeStringArgs reads and decodes a JSON object of string values (the tool/effect
// argument map). Non-string values or non-object bodies are rejected. An empty body
// decodes to an empty map.
func decodeStringArgs(r *http.Request) (map[string]string, error) {
	body, err := readBody(r, maxArgsBody)
	if err != nil {
		return nil, err
	}
	args := map[string]string{}
	if len(bytes.TrimSpace(body)) == 0 {
		return args, nil
	}
	if err := json.Unmarshal(body, &args); err != nil {
		return nil, fmt.Errorf("body must be a JSON object of string values: %w", err)
	}
	return args, nil
}

// newActionID returns a random 128-bit action id (audit.action.id) correlating the
// events of a single mediated action.
func newActionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
