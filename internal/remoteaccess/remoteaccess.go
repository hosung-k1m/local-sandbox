// Package remoteaccess owns controller-local launch descriptors for supported
// human remote-access surfaces. It deliberately does not implement a remote
// transport or expose workload credentials.
package remoteaccess

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"boxedai/internal/evidence"
)

var (
	ErrWorkspaceUnavailable         = errors.New("remote access: workspace is unavailable")
	ErrRuntimeUnavailable           = errors.New("remote access: runtime is unavailable")
	ErrSessionMismatch              = errors.New("remote access: session does not match grant")
	ErrGrantMismatch                = errors.New("remote access: grant does not match binding")
	ErrHumanUIDRequired             = errors.New("remote access: human uid is required")
	ErrSurfaceNotAllowed            = errors.New("remote access: surface is not allowed")
	ErrGrantExpired                 = errors.New("remote access: grant has expired")
	ErrGrantRevoked                 = errors.New("remote access: grant has been revoked")
	ErrSubjectNotBound              = errors.New("remote access: human subject is not bound")
	ErrDescriptorUnknown            = errors.New("remote access: descriptor was not issued")
	ErrTransportUnsupported         = errors.New("remote access: host-local transport is unsupported")
	ErrTransportUnavailable         = errors.New("remote access: host-local transport is unavailable")
	ErrHostCommandUnavailable       = errors.New("remote access: required host command is unavailable")
	ErrHostConfigurationUnavailable = errors.New("remote access: required host configuration is unavailable")
	ErrWorkspaceTarget              = errors.New("remote access: target must be the mediated workspace")
)

// WorkspaceTarget is the only guest path a human-facing transport may expose.
// In mediated sessions this is the FUSE boundary; the lower backing mount is
// intentionally never represented in a controller-side launch artifact.
const WorkspaceTarget = "/workspace"

// GuestEndpoint is the guest-side endpoint contract supplied only by the
// controller. It describes a private forwarded socket, never a workload token
// or the lower workspace mount.
type GuestEndpoint struct {
	Port             int    `json:"port"`
	IP               string `json:"ip"`
	UID              int64  `json:"uid"`
	WorkingDirectory string `json:"working_directory"`
}

const (
	GuestPort = 2222
	GuestIP   = "127.0.0.1"
)

func (e GuestEndpoint) Validate() error {
	if e.Port != GuestPort || e.IP != GuestIP || e.UID != evidence.HumanUID || e.WorkingDirectory != WorkspaceTarget {
		return ErrWorkspaceTarget
	}
	return nil
}

// LaunchRequest identifies the controller-authorized human access being
// requested. UID is included so callers cannot silently substitute a workload
// identity for the human session subject.
type LaunchRequest struct {
	SessionID string
	GrantID   string
	Surface   evidence.AccessSurface
	UID       int64
}

// LaunchDescriptor contains only public routing and attribution data. It is
// not a workload credential or a signing key.
type LaunchDescriptor struct {
	ID        string                 `json:"id"`
	Target    string                 `json:"target"`
	SessionID string                 `json:"session_id"`
	SubjectID string                 `json:"subject_id"`
	GrantID   string                 `json:"grant_id"`
	Surface   evidence.AccessSurface `json:"surface"`
	UID       int64                  `json:"uid"`
	ExpiresAt time.Time              `json:"expires_at"`
}

// Broker is controller-owned state for issuing, authorizing, and revoking
// session-scoped remote-access descriptors.
type Broker struct {
	mu             sync.RWMutex
	binding        evidence.HumanAccessBinding
	workspaceReady bool
	now            func() time.Time
	nextID         uint64
	issued         map[string]LaunchDescriptor
	revoked        map[string]bool
}

// NewBroker creates a broker for one sealed human-access binding. Readiness
// stays controller-owned because a booted session can later become unavailable.
func NewBroker(binding evidence.HumanAccessBinding, workspaceReady bool) *Broker {
	return &Broker{
		binding:        binding,
		workspaceReady: workspaceReady,
		now:            time.Now,
		issued:         make(map[string]LaunchDescriptor),
		revoked:        make(map[string]bool),
	}
}

// SetWorkspaceReady updates the controller's workspace availability gate.
func (b *Broker) SetWorkspaceReady(ready bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.workspaceReady = ready
}

// Issue records and returns one authorized descriptor.
func (b *Broker) Issue(request LaunchRequest) (LaunchDescriptor, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.authorizeRequestLocked(request); err != nil {
		return LaunchDescriptor{}, err
	}
	b.nextID++
	descriptor := LaunchDescriptor{
		ID:        fmt.Sprintf("remote-%d", b.nextID),
		Target:    targetFor(request.Surface),
		SessionID: b.binding.Grant.SessionID,
		SubjectID: b.binding.Grant.SubjectID,
		GrantID:   b.binding.Grant.GrantID,
		Surface:   request.Surface,
		UID:       evidence.HumanUID,
		ExpiresAt: b.binding.Grant.ExpiresAt,
	}
	b.issued[descriptor.ID] = descriptor
	return descriptor, nil
}

// Authorize confirms that a descriptor was issued by this controller and that
// its binding remains active.
func (b *Broker) Authorize(descriptor LaunchDescriptor) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	issued, ok := b.issued[descriptor.ID]
	if !ok || issued != descriptor {
		return ErrDescriptorUnknown
	}
	return b.authorizeRequestLocked(LaunchRequest{
		SessionID: descriptor.SessionID,
		GrantID:   descriptor.GrantID,
		Surface:   descriptor.Surface,
		UID:       descriptor.UID,
	})
}

// Revoke disables every descriptor issued for the bound grant.
func (b *Broker) Revoke(sessionID, grantID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if sessionID != b.binding.Grant.SessionID {
		return ErrSessionMismatch
	}
	if grantID != b.binding.Grant.GrantID {
		return ErrGrantMismatch
	}
	b.revoked[grantID] = true
	return nil
}

func (b *Broker) authorizeRequestLocked(request LaunchRequest) error {
	if !b.workspaceReady {
		return ErrWorkspaceUnavailable
	}
	if !b.binding.Runtime.SupportsAttributableWrites() {
		return ErrRuntimeUnavailable
	}
	if err := b.binding.SubjectMap.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrSubjectNotBound, err)
	}
	if err := b.binding.Grant.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrGrantMismatch, err)
	}
	if request.SessionID != b.binding.Grant.SessionID || request.SessionID != b.binding.SubjectMap.SessionID {
		return ErrSessionMismatch
	}
	if request.GrantID != b.binding.Grant.GrantID {
		return ErrGrantMismatch
	}
	if request.UID != evidence.HumanUID || b.binding.Grant.UID != evidence.HumanUID {
		return ErrHumanUIDRequired
	}
	if !allowsSurface(b.binding.Grant.AllowedSurfaces, request.Surface) {
		return ErrSurfaceNotAllowed
	}
	if b.binding.Grant.Revoked || b.revoked[request.GrantID] {
		return ErrGrantRevoked
	}
	if !b.binding.Grant.ActiveAt(b.now()) {
		return ErrGrantExpired
	}
	if !humanSubjectBound(b.binding.SubjectMap, b.binding.Grant) {
		return ErrSubjectNotBound
	}
	return nil
}

func targetFor(surface evidence.AccessSurface) string {
	switch surface {
	case evidence.AccessSurfaceBrowserTerminal:
		return "host-local/browser-terminal"
	case evidence.AccessSurfaceVSCodeRemoteSSH:
		return "host-local/vscode-remote-ssh"
	case evidence.AccessSurfaceIntelliJRemoteDev:
		return "host-local/intellij-remote-development"
	default:
		return ""
	}
}

func allowsSurface(allowed []evidence.AccessSurface, requested evidence.AccessSurface) bool {
	for _, surface := range allowed {
		if surface == requested {
			return true
		}
	}
	return false
}

func humanSubjectBound(subjects evidence.SessionSubjectMap, grant evidence.HumanAccessGrant) bool {
	for _, subject := range subjects.Subjects {
		if subject.UID == evidence.HumanUID && subject.ActorClass == evidence.MutationActorHuman && subject.SubjectID == grant.SubjectID && subject.GrantID == grant.GrantID {
			return true
		}
	}
	return false
}
