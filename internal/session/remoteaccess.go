package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"boxedai/internal/evidence"
)

var (
	ErrRemoteAccessUnavailable = errors.New("session: human remote access is unavailable")
	ErrRemoteAccessNotRunning  = errors.New("session: human remote access requires a running session")
)

const remoteAccessDirName = "remote-access"

// LoadRunningHumanAccessBinding returns the sealed human-access binding only
// while its owning session remains live. The grant is intentionally read from
// session.json rather than reconstructed from CLI input.
func LoadRunningHumanAccessBinding(id string) (evidence.HumanAccessBinding, error) {
	if !validSessionID(id) {
		return evidence.HumanAccessBinding{}, fmt.Errorf("session: invalid session id %q", id)
	}
	state, err := LoadState(id)
	if err != nil {
		return evidence.HumanAccessBinding{}, err
	}
	if state != StateRunning {
		return evidence.HumanAccessBinding{}, fmt.Errorf("%w: %s is %s", ErrRemoteAccessNotRunning, id, state)
	}
	grant, err := readGrant(id)
	if err != nil {
		return evidence.HumanAccessBinding{}, fmt.Errorf("session: read remote access grant for %s: %w", id, err)
	}
	if grant.SessionID != id || grant.HumanAccess == nil {
		return evidence.HumanAccessBinding{}, ErrRemoteAccessUnavailable
	}
	if err := grant.HumanAccess.Validate(); err != nil {
		return evidence.HumanAccessBinding{}, fmt.Errorf("%w: %v", ErrRemoteAccessUnavailable, err)
	}
	return *grant.HumanAccess, nil
}

// StoreRemoteAccessPlan records a secret-free controller launch plan beneath
// the session directory. It never stores a credential and refuses any session
// that has left the running state, so a stale plan cannot be issued after
// teardown has started.
func StoreRemoteAccessPlan(id, descriptorID string, data []byte) (string, error) {
	if !validSessionID(id) || !validRemoteAccessDescriptorID(descriptorID) {
		return "", fmt.Errorf("session: invalid remote access plan path")
	}
	state, err := LoadState(id)
	if err != nil {
		return "", err
	}
	if state != StateRunning {
		return "", fmt.Errorf("%w: %s is %s", ErrRemoteAccessNotRunning, id, state)
	}
	dir := filepath.Join(SessionDir(id), remoteAccessDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("session: create remote access directory: %w", err)
	}
	path := filepath.Join(dir, descriptorID+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("session: write remote access plan: %w", err)
	}
	return path, nil
}

// StoreRemoteAccessSSHConfig records a secret-free, per-session OpenSSH
// handoff fragment. It is intentionally separate from the launch plan so an
// unavailable IDE endpoint cannot be mistaken for an executable connection.
func StoreRemoteAccessSSHConfig(id, descriptorID string, data []byte) (string, error) {
	if !validSessionID(id) || !validRemoteAccessDescriptorID(descriptorID) {
		return "", fmt.Errorf("session: invalid remote access config path")
	}
	state, err := LoadState(id)
	if err != nil {
		return "", err
	}
	if state != StateRunning {
		return "", fmt.Errorf("%w: %s is %s", ErrRemoteAccessNotRunning, id, state)
	}
	dir := filepath.Join(SessionDir(id), remoteAccessDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("session: create remote access directory: %w", err)
	}
	path := filepath.Join(dir, descriptorID+".ssh-config")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("session: write remote access SSH config: %w", err)
	}
	return path, nil
}

func validSessionID(id string) bool {
	return id != "" && !strings.ContainsAny(id, "/\\") && id != "." && id != ".."
}

func validRemoteAccessDescriptorID(id string) bool {
	return strings.HasPrefix(id, "remote-") && len(id) > len("remote-") && !strings.ContainsAny(id, "/\\")
}
