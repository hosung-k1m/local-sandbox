package view

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"boxedai/internal/evidence"
	"boxedai/internal/session"
	"boxedai/internal/verify"
)

//go:embed web.html
var indexHTML []byte

//go:embed dashboard.html
var dashboardHTML []byte

// webEvent is one events row shaped for the web UI's JSON payload.
type webEvent struct {
	Seq            int64          `json:"seq"`
	TS             string         `json:"ts"`
	Name           string         `json:"name"`
	Class          string         `json:"class"`
	Badge          string         `json:"badge"`
	Producer       string         `json:"producer"`
	ActionID       string         `json:"action_id,omitempty"`
	ParentActionID string         `json:"parent_action_id,omitempty"`
	Outcome        string         `json:"outcome,omitempty"`
	Body           string         `json:"body,omitempty"`
	Attrs          map[string]any `json:"attrs"`
}

// webPayload is the full JSON document served at /api/events: overview header,
// verdict banner, process tree and the complete event list. The web page's
// vanilla JS derives the file-changes, network-attempts and internal-tool-call
// views from Events client-side.
type webPayload struct {
	SessionID    string         `json:"session_id"`
	PolicyDigest string         `json:"policy_digest"`
	Verify       *verify.Report `json:"verify,omitempty"`
	VerifyError  string         `json:"verify_error,omitempty"`
	Proof        proofState     `json:"proof"`
	ProcessTree  string         `json:"process_tree"`
	Events       []webEvent     `json:"events"`
}

// dashboardSession is one row in the global dashboard session list.
type dashboardSession struct {
	SessionID    string     `json:"session_id"`
	State        string     `json:"state"`
	Harness      string     `json:"harness,omitempty"`
	Profile      string     `json:"profile,omitempty"`
	CreatedAt    string     `json:"created_at,omitempty"`
	EventCount   int        `json:"event_count"`
	LastEventSeq int64      `json:"last_event_seq"`
	LastEventTS  string     `json:"last_event_ts,omitempty"`
	Proof        proofState `json:"proof"`
	VerifyError  string     `json:"verify_error,omitempty"`
}

// dashboardPayload is the polling-oriented JSON document served at
// /api/sessions.
type dashboardPayload struct {
	Sessions []dashboardSession `json:"sessions"`
}

// proofState exposes cryptographic proof status without implying that live
// open-segment evidence has already been sealed.
type proofState struct {
	Status              string         `json:"status"` // sealed | sealed_unverified | provisional | unavailable
	Provisional         bool           `json:"provisional"`
	UnsealedTail        bool           `json:"unsealed_tail"`
	Message             string         `json:"message"`
	DigestAlgorithm     string         `json:"digest_algorithm"`
	ChainValid          bool           `json:"chain_valid"`
	SignatureFormat     string         `json:"signature_format"`
	SignatureAlgorithm  string         `json:"signature_algorithm"`
	RecorderFingerprint string         `json:"recorder_key_fingerprint,omitempty"`
	Verdict             string         `json:"verdict,omitempty"`
	Checks              []verify.Check `json:"checks,omitempty"`
	Segments            []proofSegment `json:"segments"`
}

// proofSegment is the digest/signature state for one segment file.
type proofSegment struct {
	Number                int    `json:"number"`
	Sealed                bool   `json:"sealed"`
	OTLPDigest            string `json:"otlp_digest,omitempty"`
	DeclaredSegmentDigest string `json:"declared_segment_digest,omitempty"`
	ManifestFileDigest    string `json:"manifest_file_digest,omitempty"`
	PrevSegmentDigest     string `json:"prev_segment_digest,omitempty"`
	COSESign1             bool   `json:"cose_sign1"`
	RecordCount           int    `json:"record_count,omitempty"`
	FirstSequence         int64  `json:"first_sequence,omitempty"`
	LastSequence          int64  `json:"last_sequence,omitempty"`
	SealedAt              string `json:"sealed_at,omitempty"`
}

type webSegmentManifest struct {
	SegmentNumber     int    `json:"segment_number"`
	RecordCount       int    `json:"record_count"`
	FirstSequence     int64  `json:"first_sequence"`
	LastSequence      int64  `json:"last_sequence"`
	PrevSegmentDigest string `json:"prev_segment_digest"`
	SegmentDigest     string `json:"segment_digest"`
	SealedAt          string `json:"sealed_at"`
}

type cachedDashboardSession struct {
	signature string
	session   dashboardSession
}

var (
	dashboardCacheMu sync.Mutex
	dashboardCache   = map[string]cachedDashboardSession{}

	rebuildDashboardProjection = Rebuild
)

// ServeWeb serves the self-contained web viewer for sessionDir on addr,
// blocking until the server stops or errors. It exposes the static page at
// "/" and the event data (rebuilt fresh per request) as JSON at
// "/api/events".
func ServeWeb(sessionDir, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "serving %s viewer on http://%s (Ctrl-C to stop)\n", filepath.Base(sessionDir), ln.Addr().String())
	return ServeWebListener(sessionDir, ln)
}

// ServeWebListener serves a single-session viewer on an already-bound listener.
func ServeWebListener(sessionDir string, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		payload, err := buildWebPayload(sessionDir)
		if err != nil {
			http.Error(w, fmt.Sprintf("view: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			http.Error(w, fmt.Sprintf("view: encode response: %v", err), http.StatusInternalServerError)
		}
	})
	return http.Serve(ln, mux)
}

// ServeDashboard serves the global session dashboard on addr.
func ServeDashboard(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "serving BoxedAi dashboard on http://%s (Ctrl-C to stop)\n", ln.Addr().String())
	return ServeDashboardListener(ln)
}

// ServeDashboardListener serves the global session dashboard on an already-bound
// listener.
func ServeDashboardListener(ln net.Listener) error {
	return http.Serve(ln, newDashboardMux())
}

func newDashboardMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	})
	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		payload, err := buildDashboardPayload()
		if err != nil {
			http.Error(w, fmt.Sprintf("view: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			http.Error(w, fmt.Sprintf("view: encode response: %v", err), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if !isSessionID(id) {
			http.Error(w, "view: missing or invalid session id", http.StatusBadRequest)
			return
		}
		sessionDir := session.SessionDir(id)
		info, err := os.Lstat(sessionDir)
		if os.IsNotExist(err) || err == nil && !info.IsDir() {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("view: inspect session: %v", err), http.StatusInternalServerError)
			return
		}
		payload, err := buildWebPayload(sessionDir)
		if err != nil {
			http.Error(w, fmt.Sprintf("view: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			http.Error(w, fmt.Sprintf("view: encode response: %v", err), http.StatusInternalServerError)
		}
	})
	return mux
}

func isSessionID(id string) bool {
	if !strings.HasPrefix(id, "bx-") || strings.Contains(id, "/") || strings.Contains(id, string(filepath.Separator)) {
		return false
	}
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

// buildDashboardPayload lists all known sessions and attaches enough summary
// data for polling clients to update rows without fetching every timeline.
func buildDashboardPayload() (dashboardPayload, error) {
	infos, err := session.ListSessions()
	if err != nil {
		return dashboardPayload{}, err
	}
	sort.SliceStable(infos, func(i, j int) bool {
		iRunning := infos[i].State == session.StateRunning
		jRunning := infos[j].State == session.StateRunning
		if iRunning != jRunning {
			return iRunning
		}
		return infos[i].SessionID > infos[j].SessionID
	})

	out := dashboardPayload{Sessions: make([]dashboardSession, 0, len(infos))}
	for _, info := range infos {
		out.Sessions = append(out.Sessions, buildDashboardSession(info))
	}
	return out, nil
}

func buildDashboardSession(info session.SessionInfo) dashboardSession {
	if info.State == session.StateSealed {
		if cached, ok := cachedSealedDashboardSession(info); ok {
			return cached
		}
	}
	entry := dashboardSession{
		SessionID: info.SessionID,
		State:     string(info.State),
		Harness:   info.Harness,
		Profile:   info.Profile,
		CreatedAt: info.CreatedAt,
	}
	if info.State == session.StateRunning {
		if db, err := rebuildDashboardProjection(info.Dir); err == nil {
			entry.EventCount, entry.LastEventSeq, entry.LastEventTS = eventSummary(db)
			db.Close()
		}
	} else {
		entry.EventCount, entry.LastEventSeq, entry.LastEventTS = manifestEventSummary(info.Dir)
	}
	entry.Proof = buildDashboardProofState(info.Dir, info.State)
	if info.State == session.StateSealed {
		cacheSealedDashboardSession(info, entry)
	}
	return entry
}

func cachedSealedDashboardSession(info session.SessionInfo) (dashboardSession, bool) {
	signature := dashboardSessionSignature(info.Dir)
	dashboardCacheMu.Lock()
	defer dashboardCacheMu.Unlock()
	cached, ok := dashboardCache[info.Dir]
	if !ok || cached.signature != signature {
		return dashboardSession{}, false
	}
	return cached.session, true
}

func cacheSealedDashboardSession(info session.SessionInfo, entry dashboardSession) {
	signature := dashboardSessionSignature(info.Dir)
	dashboardCacheMu.Lock()
	defer dashboardCacheMu.Unlock()
	dashboardCache[info.Dir] = cachedDashboardSession{signature: signature, session: entry}
}

func dashboardSessionSignature(sessionDir string) string {
	segDir := filepath.Join(sessionDir, "evidence", "segments")
	entries, err := os.ReadDir(segDir)
	if err != nil {
		return "no-segments"
	}
	var parts []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "segment-") || !(strings.HasSuffix(name, ".manifest.json") || strings.HasSuffix(name, ".manifest.cose") || strings.HasSuffix(name, ".otlp")) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%d", name, info.Size(), info.ModTime().UnixNano()))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// buildWebPayload rebuilds the projection and assembles the full web payload,
// including the verdict banner from internal/verify (best-effort: a verify
// failure is surfaced as VerifyError rather than failing the whole page).
func buildWebPayload(sessionDir string) (webPayload, error) {
	db, err := Rebuild(sessionDir)
	if err != nil {
		return webPayload{}, err
	}
	defer db.Close()

	sessionID, policyDigest, err := sessionOverview(db)
	if err != nil {
		return webPayload{}, err
	}

	rows, err := queryEvents(db, Filter{})
	if err != nil {
		return webPayload{}, err
	}
	events := make([]webEvent, 0, len(rows))
	for _, row := range rows {
		var attrs map[string]any
		if err := json.Unmarshal([]byte(row.AttrsJSON), &attrs); err != nil {
			return webPayload{}, fmt.Errorf("view: decode attrs for seq %d: %w", row.Seq, err)
		}
		events = append(events, webEvent{
			Seq:            row.Seq,
			TS:             row.TS,
			Name:           row.Name,
			Class:          row.Class,
			Badge:          classBadge(row.Class),
			Producer:       row.Producer,
			ActionID:       row.ActionID,
			ParentActionID: row.ParentActionID,
			Outcome:        row.Outcome,
			Body:           row.Body,
			Attrs:          attrs,
		})
	}

	tree, err := processTreeFromDB(db)
	if err != nil {
		return webPayload{}, err
	}

	payload := webPayload{
		SessionID:    sessionID,
		PolicyDigest: policyDigest,
		ProcessTree:  tree,
		Events:       events,
	}
	state := loadSessionState(sessionDir)
	if report, err := verify.Verify(sessionDir); err != nil {
		payload.VerifyError = err.Error()
		payload.Proof = buildProofState(sessionDir, state, verify.Report{}, err)
	} else {
		payload.Verify = &report
		payload.Proof = buildProofState(sessionDir, state, report, nil)
	}
	return payload, nil
}

func loadSessionState(sessionDir string) session.State {
	b, err := os.ReadFile(filepath.Join(sessionDir, "session.state"))
	if err != nil {
		return session.StateIncomplete
	}
	return session.State(strings.TrimSpace(string(b)))
}

// sessionOverview recovers the session id and policy digest from the first
// projected event's attrs (they are constant for the whole session), so the
// overview header works even when session.json is missing or unparsable.
func sessionOverview(db *sql.DB) (sessionID, policyDigest string, err error) {
	var attrsJSON string
	err = db.QueryRow(`SELECT attrs_json FROM events ORDER BY seq ASC LIMIT 1`).Scan(&attrsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("view: read session overview: %w", err)
	}
	var attrs map[string]any
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return "", "", fmt.Errorf("view: decode session overview attrs: %w", err)
	}
	return attrString(attrs, evidence.AttrSessionID), attrString(attrs, evidence.AttrPolicyDigest), nil
}

func eventSummary(db *sql.DB) (count int, lastSeq int64, lastTS string) {
	_ = db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(seq), 0) FROM events`).Scan(&count, &lastSeq)
	_ = db.QueryRow(`SELECT ts FROM events ORDER BY seq DESC LIMIT 1`).Scan(&lastTS)
	return count, lastSeq, lastTS
}

func manifestEventSummary(sessionDir string) (count int, lastSeq int64, lastTS string) {
	for _, seg := range collectProofSegments(sessionDir, false) {
		count += seg.RecordCount
		if seg.LastSequence > lastSeq {
			lastSeq = seg.LastSequence
		}
		if seg.SealedAt > lastTS {
			lastTS = seg.SealedAt
		}
	}
	return count, lastSeq, lastTS
}

func buildDashboardProofState(sessionDir string, state session.State) proofState {
	proof := proofState{
		DigestAlgorithm:    "SHA-256",
		SignatureFormat:    "COSE Sign1",
		SignatureAlgorithm: "EdDSA (Ed25519)",
		Segments:           collectProofSegments(sessionDir, false),
	}
	unsealed := hasUnsealedSegment(proof.Segments)
	proof.UnsealedTail = unsealed
	proof.Provisional = state == session.StateRunning || unsealed
	switch {
	case proof.Provisional:
		proof.Status = "provisional"
		proof.Message = "active/open segment evidence is provisional and not represented as signed until its manifest and COSE Sign1 are written"
	case len(proof.Segments) == 0:
		proof.Status = "unavailable"
		proof.Message = "no segment metadata is available; select the session to run full projection and verification"
	default:
		proof.Status = "sealed_unverified"
		proof.Message = "sealed segment manifests and COSE Sign1 sidecars are present but not verified in this summary; select the session to recompute hashes, verify signatures, and check the chain"
	}
	return proof
}

func buildProofState(sessionDir string, state session.State, report verify.Report, verifyErr error) proofState {
	proof := proofState{
		DigestAlgorithm:    "SHA-256",
		SignatureFormat:    "COSE Sign1",
		SignatureAlgorithm: "EdDSA (Ed25519)",
		Segments:           collectProofSegments(sessionDir, true),
	}
	unsealed := hasUnsealedSegment(proof.Segments)
	proof.UnsealedTail = unsealed
	proof.Provisional = state == session.StateRunning || unsealed
	if verifyErr == nil {
		proof.ChainValid = report.Facets.ChainValid
		proof.RecorderFingerprint = report.Facets.RecorderFingerprint
		proof.Verdict = string(report.Verdict)
		proof.Checks = report.Checks
	}
	switch {
	case proof.Provisional:
		proof.Status = "provisional"
		proof.Message = "active/open segment evidence is provisional and not represented as signed until its manifest and COSE Sign1 are written"
	case verifyErr != nil:
		proof.Status = "unavailable"
		proof.Message = verifyErr.Error()
	default:
		proof.Status = "sealed"
		proof.Message = "sealed segments have SHA-256 manifests signed as COSE Sign1 with EdDSA (Ed25519)"
	}
	return proof
}

func collectProofSegments(sessionDir string, hashFiles bool) []proofSegment {
	segDir := filepath.Join(sessionDir, "evidence", "segments")
	entries, err := os.ReadDir(segDir)
	if err != nil {
		return nil
	}
	byNumber := map[int]proofSegment{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, ".manifest.json"), ".manifest.cose"), ".otlp")
		if !strings.HasPrefix(base, "segment-") {
			continue
		}
		number := parseProofSegmentNumber(base)
		seg := byNumber[number]
		seg.Number = number
		path := filepath.Join(segDir, name)
		switch {
		case strings.HasSuffix(name, ".otlp"):
			if hashFiles {
				seg.OTLPDigest = fileDigestOrEmpty(path)
			}
		case strings.HasSuffix(name, ".manifest.json"):
			if b, err := os.ReadFile(path); err == nil {
				var man webSegmentManifest
				if json.Unmarshal(b, &man) == nil {
					seg.DeclaredSegmentDigest = man.SegmentDigest
					seg.RecordCount = man.RecordCount
					seg.FirstSequence = man.FirstSequence
					seg.LastSequence = man.LastSequence
					seg.PrevSegmentDigest = man.PrevSegmentDigest
					seg.SealedAt = man.SealedAt
				}
			}
			if hashFiles {
				seg.ManifestFileDigest = fileDigestOrEmpty(path)
			}
		case strings.HasSuffix(name, ".manifest.cose"):
			seg.COSESign1 = true
		}
		byNumber[number] = seg
	}
	out := make([]proofSegment, 0, len(byNumber))
	for _, seg := range byNumber {
		seg.Sealed = seg.DeclaredSegmentDigest != "" && seg.COSESign1
		out = append(out, seg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out
}

func hasUnsealedSegment(segments []proofSegment) bool {
	for _, seg := range segments {
		if !seg.Sealed {
			return true
		}
	}
	return false
}

func parseProofSegmentNumber(base string) int {
	i := strings.LastIndexByte(base, '-')
	if i < 0 {
		return 0
	}
	n := 0
	for _, c := range base[i+1:] {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func fileDigestOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return evidence.SHA256Hex(b)
}
