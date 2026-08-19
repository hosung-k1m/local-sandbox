package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func TestLoadRunningHumanAccessBindingAndStorePlan(t *testing.T) {
	home := t.TempDir()
	t.Setenv(homeEnv, home)
	id := "session-1"
	dir := SessionDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	binding := testHumanAccessBinding(id)
	grant := sessionGrant{Schema: grantSchema, SessionID: id, HumanAccess: &binding}
	data, err := json.Marshal(grant)
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, grantFileName), data, 0o600); err != nil {
		t.Fatalf("write grant: %v", err)
	}
	if err := writeState(dir, StateRunning); err != nil {
		t.Fatalf("write state: %v", err)
	}
	got, err := LoadRunningHumanAccessBinding(id)
	if err != nil {
		t.Fatalf("LoadRunningHumanAccessBinding: %v", err)
	}
	if got.Grant.GrantID != binding.Grant.GrantID {
		t.Fatalf("grant id = %q, want %q", got.Grant.GrantID, binding.Grant.GrantID)
	}
	path, err := StoreRemoteAccessPlan(id, "remote-1", []byte(`{"working_directory":"/workspace"}`))
	if err != nil {
		t.Fatalf("StoreRemoteAccessPlan: %v", err)
	}
	if path != filepath.Join(dir, remoteAccessDirName, "remote-1.json") {
		t.Fatalf("path = %q", path)
	}
	sshPath, err := StoreRemoteAccessSSHConfig(id, "remote-1", []byte("Host boxedai-session-1\n"))
	if err != nil {
		t.Fatalf("StoreRemoteAccessSSHConfig: %v", err)
	}
	if sshPath != filepath.Join(dir, remoteAccessDirName, "remote-1.ssh-config") {
		t.Fatalf("SSH config path = %q", sshPath)
	}
}

func TestLoadRunningHumanAccessBindingRejectsInactiveSessions(t *testing.T) {
	home := t.TempDir()
	t.Setenv(homeEnv, home)
	id := "session-1"
	dir := SessionDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	if err := writeState(dir, StateSealed); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if _, err := LoadRunningHumanAccessBinding(id); !errors.Is(err, ErrRemoteAccessNotRunning) {
		t.Fatalf("LoadRunningHumanAccessBinding error = %v, want %v", err, ErrRemoteAccessNotRunning)
	}
}

func testHumanAccessBinding(sessionID string) evidence.HumanAccessBinding {
	return evidence.HumanAccessBinding{
		Runtime: evidence.RuntimeCapabilityState{
			WriteThroughLowerMount: true, PrivateLowerMount: true, SetfsuidProbe: true,
			WritebackCacheDisabled: true, PrivilegedFUSE: true, MediatedWriteOpen: true,
			HostReDerivation: true, UIDSeparation: true,
		},
		SubjectMap: evidence.SessionSubjectMap{SessionID: sessionID, Subjects: []evidence.SessionSubject{
			{UID: evidence.WorkloadUID, ActorClass: evidence.MutationActorAgent},
			{UID: evidence.HumanUID, ActorClass: evidence.MutationActorHuman, SubjectID: "operator-1", GrantID: "grant-1"},
		}},
		Grant: evidence.HumanAccessGrant{
			SessionID: sessionID, GrantID: "grant-1", SubjectID: "operator-1", UID: evidence.HumanUID,
			ExpiresAt: time.Now().Add(time.Hour), CredentialDigest: "sha256:credential-digest",
			AllowedSurfaces: []evidence.AccessSurface{evidence.AccessSurfaceBrowserTerminal},
		},
	}
}
