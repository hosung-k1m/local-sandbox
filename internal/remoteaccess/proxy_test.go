package remoteaccess

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func TestProxyTransportRequiresConfiguredCredentialProvider(t *testing.T) {
	plan, err := NewController(testBroker(time.Now().Add(time.Hour), true), nil).Prepare(testRequest(evidence.AccessSurfaceBrowserTerminal))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := NewProxyTransport(nil, &fakeProxy{}).Launch(context.Background(), plan, func() error { return nil }); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("Launch error = %v, want unavailable credential provider", err)
	}
}

func TestProxyTransportReauthorizesCredentialAndDoesNotExposeItInPlan(t *testing.T) {
	provider := NewMemoryCredentialProvider()
	proxy := &fakeProxy{}
	controller := NewController(testBroker(time.Now().Add(time.Hour), true), NewProxyTransport(provider, proxy))
	plan, err := controller.Prepare(testRequest(evidence.AccessSurfaceBrowserTerminal))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := controller.Launch(context.Background(), plan); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if proxy.authorizeCalls != 1 {
		t.Fatalf("channel authorization calls = %d, want 1", proxy.authorizeCalls)
	}
	if proxy.request.Credential.ID == "" {
		t.Fatal("proxy did not receive ephemeral credential")
	}
	if strings.Contains(plan.Descriptor.ID, proxy.request.Credential.ID) || strings.Contains(plan.WorkingDirectory, proxy.request.Credential.ID) {
		t.Fatalf("launch plan exposes credential %q", proxy.request.Credential.ID)
	}
	if err := provider.Authorize(context.Background(), proxy.request.Credential, plan.Descriptor); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("credential remained valid after endpoint close: %v", err)
	}
}

func TestProxyTransportClosesAdmissionWhenGrantRevoked(t *testing.T) {
	broker := testBroker(time.Now().Add(time.Hour), true)
	provider := NewMemoryCredentialProvider()
	proxy := &fakeProxy{beforeChannel: func() error { return broker.Revoke("session-1", "grant-1") }}
	controller := NewController(broker, NewProxyTransport(provider, proxy))
	plan, err := controller.Prepare(testRequest(evidence.AccessSurfaceBrowserTerminal))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := controller.Launch(context.Background(), plan); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Launch error = %v, want revoked grant", err)
	}
}

func TestGuestEndpointRejectsLowerWorkspace(t *testing.T) {
	endpoint := GuestEndpoint{Port: GuestPort, IP: GuestIP, UID: evidence.HumanUID, WorkingDirectory: WorkspaceTarget}
	if err := endpoint.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	endpoint.WorkingDirectory = "/var/lib/boxedai/private/workspace-lower"
	if err := endpoint.Validate(); !errors.Is(err, ErrWorkspaceTarget) {
		t.Fatalf("Validate error = %v, want workspace target", err)
	}
}

type fakeProxy struct {
	request        ProxyRequest
	authorizeCalls int
	beforeChannel  func() error
}

func (p *fakeProxy) Serve(_ context.Context, request ProxyRequest, authorize func() error) error {
	p.request = request
	if p.beforeChannel != nil {
		if err := p.beforeChannel(); err != nil {
			return err
		}
	}
	p.authorizeCalls++
	return authorize()
}
