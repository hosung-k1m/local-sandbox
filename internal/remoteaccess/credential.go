package remoteaccess

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrCredentialUnavailable = errors.New("remote access: human-access credential provider is unavailable")

// HumanAccessCredential is an opaque, controller-local admission credential.
// It is deliberately absent from LaunchPlan and client handoff files.
type HumanAccessCredential struct {
	ID        string
	SessionID string
	GrantID   string
	ExpiresAt time.Time
}

// HumanAccessCredentialProvider supplies ephemeral credentials for the host
// proxy boundary. Production must install a provider backed by its configured
// human authentication system; the package supplies no default issuer.
type HumanAccessCredentialProvider interface {
	Issue(context.Context, LaunchDescriptor) (HumanAccessCredential, error)
	Authorize(context.Context, HumanAccessCredential, LaunchDescriptor) error
	Revoke(context.Context, HumanAccessCredential) error
}

// MemoryCredentialProvider is a deterministic in-memory implementation for
// tests. It is intentionally unsuitable for production restarts.
type MemoryCredentialProvider struct {
	mu      sync.Mutex
	now     func() time.Time
	nextID  uint64
	issued  map[string]HumanAccessCredential
	revoked map[string]bool
}

func NewMemoryCredentialProvider() *MemoryCredentialProvider {
	return &MemoryCredentialProvider{
		now:     time.Now,
		issued:  make(map[string]HumanAccessCredential),
		revoked: make(map[string]bool),
	}
}

func (p *MemoryCredentialProvider) Issue(_ context.Context, descriptor LaunchDescriptor) (HumanAccessCredential, error) {
	if descriptor.ID == "" || descriptor.SessionID == "" || descriptor.GrantID == "" || descriptor.ExpiresAt.IsZero() {
		return HumanAccessCredential{}, ErrCredentialUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextID++
	credential := HumanAccessCredential{
		ID:        fmt.Sprintf("human-%d", p.nextID),
		SessionID: descriptor.SessionID,
		GrantID:   descriptor.GrantID,
		ExpiresAt: descriptor.ExpiresAt,
	}
	p.issued[credential.ID] = credential
	return credential, nil
}

func (p *MemoryCredentialProvider) Authorize(_ context.Context, credential HumanAccessCredential, descriptor LaunchDescriptor) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	issued, ok := p.issued[credential.ID]
	if !ok || issued != credential || p.revoked[credential.ID] {
		return ErrCredentialUnavailable
	}
	if credential.SessionID != descriptor.SessionID || credential.GrantID != descriptor.GrantID || !credential.ExpiresAt.After(p.now()) {
		return ErrCredentialUnavailable
	}
	return nil
}

func (p *MemoryCredentialProvider) Revoke(_ context.Context, credential HumanAccessCredential) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.issued[credential.ID]; !ok {
		return ErrCredentialUnavailable
	}
	p.revoked[credential.ID] = true
	return nil
}
