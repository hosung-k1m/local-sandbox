package remoteaccess

import (
	"context"
)

// ProxyRequest joins one authorized descriptor with an opaque ephemeral
// credential. Only the controller-owned proxy receives it; it must never be
// marshalled into a client plan or passed to the guest workload.
type ProxyRequest struct {
	Plan       LaunchPlan
	Credential HumanAccessCredential
}

// HostProxy is the protocol endpoint seam. An implementation may terminate
// SSH channels or browser WebSockets and connect them to a guest endpoint, but
// must reauthorize at every connection and channel admission.
type HostProxy interface {
	Serve(context.Context, ProxyRequest, func() error) error
}

// ProxyTransport adds ephemeral human authentication to a concrete host proxy.
// A nil provider or proxy fails closed, so no production endpoint can be
// accidentally enabled by a descriptor alone.
type ProxyTransport struct {
	provider HumanAccessCredentialProvider
	proxy    HostProxy
}

func NewProxyTransport(provider HumanAccessCredentialProvider, proxy HostProxy) *ProxyTransport {
	return &ProxyTransport{provider: provider, proxy: proxy}
}

func (t *ProxyTransport) Launch(ctx context.Context, plan LaunchPlan, authorize func() error) error {
	if t == nil || t.provider == nil || t.proxy == nil {
		return ErrCredentialUnavailable
	}
	if err := authorize(); err != nil {
		return err
	}
	credential, err := t.provider.Issue(ctx, plan.Descriptor)
	if err != nil {
		return err
	}
	if err := t.provider.Authorize(ctx, credential, plan.Descriptor); err != nil {
		_ = t.provider.Revoke(context.Background(), credential)
		return err
	}
	request := ProxyRequest{Plan: plan, Credential: credential}
	err = t.proxy.Serve(ctx, request, func() error {
		if err := authorize(); err != nil {
			return err
		}
		return t.provider.Authorize(ctx, credential, plan.Descriptor)
	})
	_ = t.provider.Revoke(context.Background(), credential)
	return err
}
