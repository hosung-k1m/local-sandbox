package cli

import (
	"bytes"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func TestAccessCommandStoresPlanAndReturnsHandoff(t *testing.T) {
	originalLoad := loadRunningHumanAccessBinding
	originalStore := storeRemoteAccessPlan
	originalStoreSSHConfig := storeRemoteAccessSSHConfig
	t.Cleanup(func() {
		loadRunningHumanAccessBinding = originalLoad
		storeRemoteAccessPlan = originalStore
		storeRemoteAccessSSHConfig = originalStoreSSHConfig
	})
	loadRunningHumanAccessBinding = func(string) (evidence.HumanAccessBinding, error) {
		return cliHumanAccessBinding(), nil
	}
	storedID := ""
	storedData := []byte(nil)
	storeRemoteAccessPlan = func(_ string, descriptorID string, data []byte) (string, error) {
		storedID = descriptorID
		storedData = append([]byte(nil), data...)
		return "/session/remote-access/" + descriptorID + ".json", nil
	}
	cmd := newAccessCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"session-1", string(evidence.AccessSurfaceBrowserTerminal)})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if storedID == "" || !bytes.Contains(storedData, []byte(`"working_directory": "/workspace"`)) {
		t.Fatalf("stored plan id=%q data=%s", storedID, storedData)
	}
	for _, want := range []string{
		"SSH command: ssh",
		"-o User=human",
		"--surface browser_terminal",
		"--workspace /workspace",
	} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Fatalf("output missing %q: %q", want, out.String())
		}
	}
	if bytes.Contains(out.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatalf("output = %q", out.String())
	}
}

func TestParseAccessSurfaceRejectsUnknownSurface(t *testing.T) {
	if _, err := parseAccessSurface("shell"); err == nil {
		t.Fatal("parseAccessSurface accepted unknown surface")
	}
}

func TestAccessCommandStoresRestrictedSSHConfigAndReturnsHandoff(t *testing.T) {
	originalLoad := loadRunningHumanAccessBinding
	originalStore := storeRemoteAccessPlan
	originalStoreSSHConfig := storeRemoteAccessSSHConfig
	t.Cleanup(func() {
		loadRunningHumanAccessBinding = originalLoad
		storeRemoteAccessPlan = originalStore
		storeRemoteAccessSSHConfig = originalStoreSSHConfig
	})
	binding := cliHumanAccessBinding()
	binding.Grant.AllowedSurfaces = []evidence.AccessSurface{evidence.AccessSurfaceVSCodeRemoteSSH}
	loadRunningHumanAccessBinding = func(string) (evidence.HumanAccessBinding, error) { return binding, nil }
	storeRemoteAccessPlan = func(_ string, _ string, _ []byte) (string, error) { return "/session/remote-access/remote-1.json", nil }
	config := ""
	storeRemoteAccessSSHConfig = func(_ string, _ string, data []byte) (string, error) {
		config = string(data)
		return "/session/remote-access/remote-1.ssh-config", nil
	}
	cmd := newAccessCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"session-1", string(evidence.AccessSurfaceVSCodeRemoteSSH)})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	for _, want := range []string{"ProxyCommand boxedai-ssh-proxy", "--uid 5000", "--workspace /workspace", "IdentityFile "} {
		if !bytes.Contains([]byte(config), []byte(want)) {
			t.Fatalf("SSH config missing %q: %s", want, config)
		}
	}
	if !bytes.Contains(out.Bytes(), []byte("Host alias: boxedai-session-1")) {
		t.Fatalf("output missing host alias: %q", out.String())
	}
	for _, forbidden := range []string{"credential-digest", "workspace-lower", "limactl shell"} {
		if bytes.Contains([]byte(config), []byte(forbidden)) {
			t.Fatalf("SSH config contains %q: %s", forbidden, config)
		}
	}
}

func cliHumanAccessBinding() evidence.HumanAccessBinding {
	return evidence.HumanAccessBinding{
		Runtime: evidence.RuntimeCapabilityState{
			WriteThroughLowerMount: true, PrivateLowerMount: true, SetfsuidProbe: true,
			WritebackCacheDisabled: true, PrivilegedFUSE: true, MediatedWriteOpen: true,
			HostReDerivation: true, UIDSeparation: true,
		},
		SubjectMap: evidence.SessionSubjectMap{SessionID: "session-1", Subjects: []evidence.SessionSubject{
			{UID: evidence.WorkloadUID, ActorClass: evidence.MutationActorAgent},
			{UID: evidence.HumanUID, ActorClass: evidence.MutationActorHuman, SubjectID: "operator-1", GrantID: "grant-1"},
		}},
		Grant: evidence.HumanAccessGrant{
			SessionID: "session-1", GrantID: "grant-1", SubjectID: "operator-1", UID: evidence.HumanUID,
			ExpiresAt: time.Now().Add(time.Hour), CredentialDigest: "sha256:credential-digest",
			AllowedSurfaces: []evidence.AccessSurface{evidence.AccessSurfaceBrowserTerminal},
		},
	}
}
