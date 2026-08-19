package remoteaccess

import (
	"context"
	"errors"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func TestControllerLaunchesOnlyAuthorizedMediatedWorkspacePlan(t *testing.T) {
	broker := testBroker(time.Now().Add(time.Hour), true)
	transport := &fakeTransport{}
	controller := NewController(broker, transport)
	plan, err := controller.Prepare(testRequest(evidence.AccessSurfaceVSCodeRemoteSSH))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if plan.WorkingDirectory != WorkspaceTarget || plan.Descriptor.Target != "host-local/vscode-remote-ssh" {
		t.Fatalf("plan = %+v", plan)
	}
	if err := controller.Launch(context.Background(), plan); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if !transport.authorized {
		t.Fatal("transport was not reauthorized at admission")
	}
}

func TestControllerRejectsWrongSessionRevokedExpiredAndLowerWorkspace(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name  string
		edit  func(*LaunchPlan)
		after func(*Broker)
		want  error
	}{
		{
			name: "wrong session",
			edit: func(plan *LaunchPlan) { plan.Descriptor.SessionID = "session-2" },
			want: ErrDescriptorUnknown,
		},
		{
			name: "revoked",
			after: func(broker *Broker) {
				if err := broker.Revoke("session-1", "grant-1"); err != nil {
					t.Fatalf("Revoke: %v", err)
				}
			},
			edit: func(*LaunchPlan) {},
			want: ErrGrantRevoked,
		},
		{
			name:  "expired",
			after: func(broker *Broker) { broker.now = func() time.Time { return now.Add(time.Hour) } },
			edit:  func(*LaunchPlan) {},
			want:  ErrGrantExpired,
		},
		{
			name: "lower workspace rejected",
			edit: func(plan *LaunchPlan) { plan.WorkingDirectory = "/var/lib/boxedai/private/workspace-lower" },
			want: ErrWorkspaceTarget,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broker := testBroker(now.Add(time.Hour), true)
			controller := NewController(broker, &fakeTransport{})
			plan, err := controller.Prepare(testRequest(evidence.AccessSurfaceBrowserTerminal))
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			tc.edit(&plan)
			if tc.after != nil {
				tc.after(broker)
			}
			if err := controller.Launch(context.Background(), plan); !errors.Is(err, tc.want) {
				t.Fatalf("Launch() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestControllerReportsUnsupportedTransportAfterPreparation(t *testing.T) {
	controller := NewController(testBroker(time.Now().Add(time.Hour), true), nil)
	plan, err := controller.Prepare(testRequest(evidence.AccessSurfaceIntelliJRemoteDev))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := controller.Launch(context.Background(), plan); !errors.Is(err, ErrTransportUnsupported) {
		t.Fatalf("Launch() error = %v, want %v", err, ErrTransportUnsupported)
	}
}

func TestControllerRechecksControllerAdmissionAtTransportBoundary(t *testing.T) {
	broker := testBroker(time.Now().Add(time.Hour), true)
	transport := &fakeTransport{}
	controller := NewController(broker, transport)
	plan, err := controller.Prepare(testRequest(evidence.AccessSurfaceBrowserTerminal))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	controller.SetAdmissionGate(func() error { return ErrWorkspaceUnavailable })
	if err := controller.Launch(context.Background(), plan); !errors.Is(err, ErrWorkspaceUnavailable) {
		t.Fatalf("Launch() error = %v, want controller admission failure", err)
	}
	if transport.authorized {
		t.Fatal("transport admitted a request after the controller gate failed")
	}
}

type fakeTransport struct{ authorized bool }

func (t *fakeTransport) Launch(_ context.Context, plan LaunchPlan, authorize func() error) error {
	if plan.WorkingDirectory != WorkspaceTarget {
		return ErrWorkspaceTarget
	}
	if err := authorize(); err != nil {
		return err
	}
	t.authorized = true
	return nil
}
