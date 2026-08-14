package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// State is the coarse lifecycle marker persisted to sessions/<id>/session.state
// (DESIGN.md "Crash safety"). It lets `boxedai sessions` and crash recovery tell a
// clean seal from an interrupted run without replaying evidence.
type State string

const (
	// StateCreated: session dir made, run not yet underway.
	StateCreated State = "created"
	// StateRunning: workload launched (session.started emitted).
	StateRunning State = "running"
	// StateSealed: clean completion, evidence sealed.
	StateSealed State = "sealed"
	// StateIncomplete: crashed, aborted, or missing seal.
	StateIncomplete State = "incomplete"
)

// stateFileName is the per-session state marker file.
const stateFileName = "session.state"

// writeState writes the state marker for a session dir at 0600.
func writeState(sessionDir string, s State) error {
	path := filepath.Join(sessionDir, stateFileName)
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		return fmt.Errorf("session: write state: %w", err)
	}
	return nil
}

// LoadState reads the persisted lifecycle state for a session id. A session dir
// with no state file (e.g. one that died before writing one) reports
// StateIncomplete rather than erroring.
func LoadState(id string) (State, error) {
	b, err := os.ReadFile(filepath.Join(SessionDir(id), stateFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return StateIncomplete, nil
		}
		return "", fmt.Errorf("session: read state for %s: %w", id, err)
	}
	return State(b), nil
}

// SessionInfo is a listing entry for `boxedai sessions`: the identity and
// disposition of one recorded session, read from its session.json grant and
// session.state marker.
type SessionInfo struct {
	SessionID string `json:"session_id"`
	Dir       string `json:"dir"`
	State     State  `json:"state"`
	Harness   string `json:"harness"`
	Profile   string `json:"profile"`
	CreatedAt string `json:"created_at"`
}

// ListSessions enumerates ~/.boxedai/sessions in id order (which, because ids
// carry a UTC timestamp prefix, is chronological). Directories without a readable
// grant are still listed with whatever identity can be recovered, so an
// interrupted session is never hidden.
func ListSessions() ([]SessionInfo, error) {
	entries, err := os.ReadDir(sessionsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("session: read sessions dir: %w", err)
	}
	var out []SessionInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		info := SessionInfo{SessionID: id, Dir: SessionDir(id)}
		if g, err := readGrant(id); err == nil {
			info.Harness = g.Harness
			info.Profile = g.Profile
			info.CreatedAt = g.CreatedAt
		}
		if st, err := LoadState(id); err == nil {
			info.State = st
		} else {
			info.State = StateIncomplete
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out, nil
}

// readGrant loads and parses a session's session.json grant.
func readGrant(id string) (sessionGrant, error) {
	b, err := os.ReadFile(filepath.Join(SessionDir(id), grantFileName))
	if err != nil {
		return sessionGrant{}, err
	}
	var g sessionGrant
	if err := json.Unmarshal(b, &g); err != nil {
		return sessionGrant{}, err
	}
	return g, nil
}
