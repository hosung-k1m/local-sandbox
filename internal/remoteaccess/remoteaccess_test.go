package remoteaccess

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func TestBrokerIssuesAndAuthorizesSupportedDescriptors(t *testing.T) {
	broker := testBroker(time.Now().Add(time.Hour), true)

	for _, surface := range []evidence.AccessSurface{
		evidence.AccessSurfaceBrowserTerminal,
		evidence.AccessSurfaceVSCodeRemoteSSH,
		evidence.AccessSurfaceIntelliJRemoteDev,
	} {
		descriptor, err := broker.Issue(testRequest(surface))
		if err != nil {
			t.Fatalf("Issue(%q): %v", surface, err)
		}
		if descriptor.Target == "" || descriptor.SessionID != "session-1" || descriptor.SubjectID != "operator-1" {
			t.Fatalf("descriptor = %+v", descriptor)
		}
		if err := broker.Authorize(descriptor); err != nil {
			t.Fatalf("Authorize(%q): %v", surface, err)
		}
		encoded, err := json.Marshal(descriptor)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if strings.Contains(string(encoded), "credential") || strings.Contains(string(encoded), "private") {
			t.Fatalf("descriptor exposes sensitive material: %s", encoded)
		}
	}
}

func TestBrokerDeniesInvalidLaunches(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name    string
		broker  func() *Broker
		request LaunchRequest
		want    error
	}{
		{
			name:    "workspace unavailable",
			broker:  func() *Broker { return testBroker(now.Add(time.Hour), false) },
			request: testRequest(evidence.AccessSurfaceBrowserTerminal),
			want:    ErrWorkspaceUnavailable,
		},
		{
			name: "runtime unavailable",
			broker: func() *Broker {
				broker := testBroker(now.Add(time.Hour), true)
				broker.binding.Runtime.UIDSeparation = false
				return broker
			},
			request: testRequest(evidence.AccessSurfaceBrowserTerminal),
			want:    ErrRuntimeUnavailable,
		},
		{
			name:    "wrong session",
			broker:  func() *Broker { return testBroker(now.Add(time.Hour), true) },
			request: LaunchRequest{SessionID: "session-2", GrantID: "grant-1", Surface: evidence.AccessSurfaceBrowserTerminal, UID: evidence.HumanUID},
			want:    ErrSessionMismatch,
		},
		{
			name:    "wrong grant",
			broker:  func() *Broker { return testBroker(now.Add(time.Hour), true) },
			request: LaunchRequest{SessionID: "session-1", GrantID: "grant-2", Surface: evidence.AccessSurfaceBrowserTerminal, UID: evidence.HumanUID},
			want:    ErrGrantMismatch,
		},
		{
			name:    "agent uid",
			broker:  func() *Broker { return testBroker(now.Add(time.Hour), true) },
			request: LaunchRequest{SessionID: "session-1", GrantID: "grant-1", Surface: evidence.AccessSurfaceBrowserTerminal, UID: evidence.WorkloadUID},
			want:    ErrHumanUIDRequired,
		},
		{
			name: "subject map missing human membership",
			broker: func() *Broker {
				broker := testBroker(now.Add(time.Hour), true)
				broker.binding.SubjectMap.Subjects[1].GrantID = "other-grant"
				return broker
			},
			request: testRequest(evidence.AccessSurfaceBrowserTerminal),
			want:    ErrSubjectNotBound,
		},
		{
			name:    "surface not granted",
			broker:  func() *Broker { return testBroker(now.Add(time.Hour), true) },
			request: testRequest("unknown"),
			want:    ErrSurfaceNotAllowed,
		},
		{
			name:    "expired grant",
			broker:  func() *Broker { return testBroker(now.Add(-time.Second), true) },
			request: testRequest(evidence.AccessSurfaceBrowserTerminal),
			want:    ErrGrantExpired,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.broker().Issue(tc.request)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Issue() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestBrokerRevocationAndDescriptorIntegrity(t *testing.T) {
	broker := testBroker(time.Now().Add(time.Hour), true)
	descriptor, err := broker.Issue(testRequest(evidence.AccessSurfaceBrowserTerminal))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := broker.Revoke("session-1", "grant-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := broker.Authorize(descriptor); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Authorize after revoke error = %v, want %v", err, ErrGrantRevoked)
	}
	descriptor.SubjectID = "other-subject"
	if err := broker.Authorize(descriptor); !errors.Is(err, ErrDescriptorUnknown) {
		t.Fatalf("Authorize altered descriptor error = %v, want %v", err, ErrDescriptorUnknown)
	}
}

func testBroker(expiresAt time.Time, workspaceReady bool) *Broker {
	binding := evidence.HumanAccessBinding{
		Runtime: evidence.RuntimeCapabilityState{
			WriteThroughLowerMount: true,
			PrivateLowerMount:      true,
			SetfsuidProbe:          true,
			WritebackCacheDisabled: true,
			PrivilegedFUSE:         true,
			MediatedWriteOpen:      true,
			HostReDerivation:       true,
			UIDSeparation:          true,
		},
		SubjectMap: evidence.SessionSubjectMap{
			SessionID: "session-1",
			Subjects: []evidence.SessionSubject{
				{UID: evidence.WorkloadUID, ActorClass: evidence.MutationActorAgent},
				{UID: evidence.HumanUID, ActorClass: evidence.MutationActorHuman, SubjectID: "operator-1", GrantID: "grant-1"},
			},
		},
		Grant: evidence.HumanAccessGrant{
			SessionID:        "session-1",
			GrantID:          "grant-1",
			SubjectID:        "operator-1",
			ExpiresAt:        expiresAt,
			AllowedSurfaces:  []evidence.AccessSurface{evidence.AccessSurfaceBrowserTerminal, evidence.AccessSurfaceVSCodeRemoteSSH, evidence.AccessSurfaceIntelliJRemoteDev},
			UID:              evidence.HumanUID,
			CredentialDigest: "sha256:credential-digest",
		},
	}
	return NewBroker(binding, workspaceReady)
}

func testRequest(surface evidence.AccessSurface) LaunchRequest {
	return LaunchRequest{SessionID: "session-1", GrantID: "grant-1", Surface: surface, UID: evidence.HumanUID}
}
