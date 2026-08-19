// Package evidence defines the BoxedAi audit event model: event names, evidence
// classes, producer channels, required attributes, and the Emitter interface that
// every evidence producer uses. See DESIGN.md "Evidence model". This package is the
// shared contract between recorder, broker, vm, session and verify — it imports
// nothing else in the repo.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"strings"
	"time"
)

// SchemaVersion is stamped on every record as audit.schema.version.
const SchemaVersion = "boxedai.evidence/v1"

// Class is the evidence class of a record: how trustworthy the observation is and
// who observed it. Classes are assigned by the recorder from the authenticated
// producer channel, never trusted from the payload.
type Class string

const (
	ClassModelSelfReported Class = "model_self_reported"
	ClassHarnessObserved   Class = "harness_observed"
	ClassKernelObserved    Class = "kernel_observed"
	ClassBrokerMediated    Class = "broker_mediated"
	ClassTargetConfirmed   Class = "target_confirmed"
	ClassIntegrity         Class = "integrity"
)

// Channel identifies the authenticated producer channel an event arrived on.
type Channel string

const (
	ChannelController      Channel = "controller"
	ChannelBroker          Channel = "broker"
	ChannelGuestSupervisor Channel = "guest_supervisor"
	ChannelWorkload        Channel = "workload"
	ChannelRecorder        Channel = "recorder"
)

// AllowedClasses maps each channel to the evidence classes it may assert.
// The recorder clamps any out-of-allowance class to the channel's first entry and
// emits an integrity event noting the attempt.
var AllowedClasses = map[Channel][]Class{
	ChannelController:      {ClassIntegrity, ClassBrokerMediated},
	ChannelBroker:          {ClassBrokerMediated, ClassTargetConfirmed},
	ChannelGuestSupervisor: {ClassKernelObserved, ClassIntegrity},
	ChannelWorkload:        {ClassModelSelfReported, ClassHarnessObserved},
	ChannelRecorder:        {ClassIntegrity},
}

// Outcome of the action an event describes.
type Outcome string

const (
	OutcomeSuccess     Outcome = "success"
	OutcomeFailure     Outcome = "failure"
	OutcomeDenied      Outcome = "denied"
	OutcomeCancelled   Outcome = "cancelled"
	OutcomeInterrupted Outcome = "interrupted"
)

// Correlation strength between a harness-reported intent and a kernel observation.
type Correlation string

const (
	CorrelationStrong  Correlation = "strong"
	CorrelationLineage Correlation = "lineage"
	CorrelationNone    Correlation = "none"
)

// Capture level for content attributes.
type Capture string

const (
	CaptureDigestOnly Capture = "digest_only"
	CaptureRedacted   Capture = "redacted"
	CaptureFull       Capture = "full"
)

// AccessSurface identifies the controller-owned path used for authenticated
// human access. It is grant data, never a claim supplied by a workload.
type AccessSurface string

const (
	AccessSurfaceBrowserTerminal   AccessSurface = "browser_terminal"
	AccessSurfaceVSCodeRemoteSSH   AccessSurface = "vscode_remote_ssh"
	AccessSurfaceIntelliJRemoteDev AccessSurface = "intellij_remote_development"
)

// MutationActorClass is the fail-closed classification for a mediated workspace
// operation. Human requires both a kernel UID and a live sealed grant.
type MutationActorClass string

const (
	MutationActorHuman        MutationActorClass = "human"
	MutationActorAgent        MutationActorClass = "agent"
	MutationActorSupervisor   MutationActorClass = "supervisor"
	MutationActorUnattributed MutationActorClass = "unattributed"
)

const (
	WorkloadUID int64 = 4242
	HumanUID    int64 = 5000
)

type MutationOpenMode string

const (
	MutationOpenWriteOnly MutationOpenMode = "write_only"
	MutationOpenReadWrite MutationOpenMode = "read_write"
)

type MutationOperation string

const (
	MutationOperationWrite    MutationOperation = "write"
	MutationOperationTruncate MutationOperation = "truncate"
	MutationOperationReplace  MutationOperation = "replace"
	MutationOperationRename   MutationOperation = "rename"
	MutationOperationDelete   MutationOperation = "delete"
	MutationOperationMetadata MutationOperation = "metadata"
)

type MutationPositionKind string

const (
	MutationPositionPositional    MutationPositionKind = "positional"
	MutationPositionNonPositional MutationPositionKind = "non_positional"
)

// HumanAccessGrant binds one authenticated human to a session-scoped guest UID.
// The controller seals this contract before a human-facing surface is exposed.
type HumanAccessGrant struct {
	SessionID        string          `json:"session_id"`
	GrantID          string          `json:"grant_id"`
	SubjectID        string          `json:"subject_id"`
	ExpiresAt        time.Time       `json:"expires_at"`
	AllowedSurfaces  []AccessSurface `json:"allowed_surfaces"`
	UID              int64           `json:"uid"`
	CredentialDigest string          `json:"credential_digest"`
	Revoked          bool            `json:"revoked"`
}

func (g HumanAccessGrant) ActiveAt(at time.Time) bool {
	return !g.Revoked && at.Before(g.ExpiresAt)
}

func (g HumanAccessGrant) Validate() error {
	if g.SessionID == "" || g.GrantID == "" || g.SubjectID == "" {
		return fmt.Errorf("evidence: human access grant requires session_id, grant_id, and subject_id")
	}
	if g.ExpiresAt.IsZero() {
		return fmt.Errorf("evidence: human access grant %q has no expiry", g.GrantID)
	}
	if g.UID != HumanUID {
		return fmt.Errorf("evidence: human access grant %q uid is %d, want %d", g.GrantID, g.UID, HumanUID)
	}
	if g.CredentialDigest == "" {
		return fmt.Errorf("evidence: human access grant %q has no credential digest", g.GrantID)
	}
	if len(g.AllowedSurfaces) == 0 {
		return fmt.Errorf("evidence: human access grant %q has no allowed surfaces", g.GrantID)
	}
	seen := map[AccessSurface]struct{}{}
	for _, surface := range g.AllowedSurfaces {
		if !validAccessSurface(surface) {
			return fmt.Errorf("evidence: human access grant %q has invalid surface %q", g.GrantID, surface)
		}
		if _, ok := seen[surface]; ok {
			return fmt.Errorf("evidence: human access grant %q repeats surface %q", g.GrantID, surface)
		}
		seen[surface] = struct{}{}
	}
	return nil
}

type SessionSubject struct {
	UID        int64              `json:"uid"`
	ActorClass MutationActorClass `json:"actor_class"`
	SubjectID  string             `json:"subject_id,omitempty"`
	GrantID    string             `json:"grant_id,omitempty"`
}

// SessionSubjectMap is the controller-sealed UID mapping consumed by FUSE and
// the offline verifier. It must describe exactly the workload and human UIDs.
type SessionSubjectMap struct {
	SessionID string           `json:"session_id"`
	Subjects  []SessionSubject `json:"subjects"`
}

func (m SessionSubjectMap) Validate() error {
	if m.SessionID == "" {
		return fmt.Errorf("evidence: session subject map has no session_id")
	}
	if len(m.Subjects) != 2 {
		return fmt.Errorf("evidence: session subject map has %d subjects, want 2", len(m.Subjects))
	}
	var workload, human *SessionSubject
	for i := range m.Subjects {
		subject := &m.Subjects[i]
		switch subject.UID {
		case WorkloadUID:
			if workload != nil {
				return fmt.Errorf("evidence: session subject map repeats uid %d", WorkloadUID)
			}
			workload = subject
		case HumanUID:
			if human != nil {
				return fmt.Errorf("evidence: session subject map repeats uid %d", HumanUID)
			}
			human = subject
		default:
			return fmt.Errorf("evidence: session subject map has unsupported uid %d", subject.UID)
		}
	}
	if workload == nil || workload.ActorClass != MutationActorAgent || workload.SubjectID != "" || workload.GrantID != "" {
		return fmt.Errorf("evidence: session subject map must bind uid %d only to agent", WorkloadUID)
	}
	if human == nil || human.ActorClass != MutationActorHuman || human.SubjectID == "" || human.GrantID == "" {
		return fmt.Errorf("evidence: session subject map must bind uid %d to a granted human subject", HumanUID)
	}
	return nil
}

// MutationActorFor classifies one kernel-observed mutation. It intentionally
// returns unattributed for every incomplete or mismatched human proof.
func MutationActorFor(uid int64, subjects SessionSubjectMap, grant *HumanAccessGrant, at time.Time) MutationActorClass {
	if subjects.Validate() != nil {
		return MutationActorUnattributed
	}
	if uid == 0 {
		return MutationActorSupervisor
	}
	if uid == WorkloadUID {
		return MutationActorAgent
	}
	if uid != HumanUID || grant == nil || grant.Validate() != nil || !grant.ActiveAt(at) {
		return MutationActorUnattributed
	}
	for _, subject := range subjects.Subjects {
		if subject.UID == HumanUID && subject.SubjectID == grant.SubjectID && subject.GrantID == grant.GrantID && subjects.SessionID == grant.SessionID {
			return MutationActorHuman
		}
	}
	return MutationActorUnattributed
}

// AllowsMutation is the sealed subject-map operation gate used before the
// privileged mediator invokes its loopback implementation. Unknown subjects,
// malformed bindings, expired human grants, and unsupported operations fail
// closed. The root supervisor is a distinct trusted actor for its own lifecycle
// work; it is never a substitute for human attribution.
func (m SessionSubjectMap) AllowsMutation(uid int64, grant *HumanAccessGrant, operation MutationOperation, at time.Time) bool {
	if !validMutationOperation(string(operation)) {
		return false
	}
	switch MutationActorFor(uid, m, grant, at) {
	case MutationActorAgent, MutationActorHuman, MutationActorSupervisor:
		return true
	default:
		return false
	}
}

// MutationActorForChannel provides the recorder-safe lower bound for a mutation
// candidate. Only the authenticated guest-supervisor channel can carry a kernel
// UID; human classification remains unavailable until a sealed grant is joined.
func MutationActorForChannel(channel Channel, uid int64) MutationActorClass {
	if channel == ChannelGuestSupervisor && uid == WorkloadUID {
		return MutationActorAgent
	}
	return MutationActorUnattributed
}

// MutationActorForRecord is the host recorder's authoritative twin of the guest's
// MutationActorFor. The recorder owns the sealed human-access binding and
// re-derives the actor class from it rather than trusting the event payload. Only
// a guest-supervisor mutation carrying a sealed binding reaches the full
// grant-aware classifier; every other channel falls back to the channel-only
// classifier, so a workload cannot post a forged human mutation on its own
// channel and have it sealed as human.
func MutationActorForRecord(channel Channel, uid int64, binding *HumanAccessBinding, at time.Time) MutationActorClass {
	if channel == ChannelGuestSupervisor && binding != nil {
		return MutationActorFor(uid, binding.SubjectMap, &binding.Grant, at)
	}
	return MutationActorForChannel(channel, uid)
}

// RuntimeCapabilityState declares whether the supported guest can establish the
// complete mediated workspace boundary before edits are accepted.
type RuntimeCapabilityState struct {
	// WriteThroughLowerMount: the lower backing is a single writable virtiofs
	// mount at the pinned private mountpoint, and the supervisor verified
	// write-through with a real write before publishing /workspace. It does
	// not claim the backing is unwritable by guest root; see PrivateLowerMount
	// and SetfsuidProbe for the non-root unreachability claims.
	WriteThroughLowerMount bool `json:"write_through_lower_mount"`
	PrivateLowerMount      bool `json:"private_lower_mount"`
	SetfsuidProbe          bool `json:"setfsuid_probe"`
	WritebackCacheDisabled bool `json:"writeback_cache_disabled"`
	PrivilegedFUSE         bool `json:"privileged_fuse"`
	MediatedWriteOpen      bool `json:"mediated_write_open"`
	HostReDerivation       bool `json:"host_re_derivation"`
	UIDSeparation          bool `json:"uid_separation"`
}

func (c RuntimeCapabilityState) SupportsAttributableWrites() bool {
	return c.WriteThroughLowerMount && c.PrivateLowerMount && c.SetfsuidProbe && c.WritebackCacheDisabled && c.PrivilegedFUSE && c.MediatedWriteOpen && c.HostReDerivation && c.UIDSeparation
}

// HumanAccessBinding is the immutable session contract joined with every human
// mutation. Future grants may be appended only as separately sealed evidence.
type HumanAccessBinding struct {
	Runtime    RuntimeCapabilityState `json:"runtime"`
	SubjectMap SessionSubjectMap      `json:"subject_map"`
	Grant      HumanAccessGrant       `json:"grant"`
}

func (b HumanAccessBinding) Validate() error {
	if !b.Runtime.SupportsAttributableWrites() {
		return fmt.Errorf("evidence: human access runtime does not support attributable writes")
	}
	if err := b.SubjectMap.Validate(); err != nil {
		return err
	}
	if err := b.Grant.Validate(); err != nil {
		return err
	}
	if b.SubjectMap.SessionID != b.Grant.SessionID {
		return fmt.Errorf("evidence: human access binding session ids do not match")
	}
	for _, subject := range b.SubjectMap.Subjects {
		if subject.UID == HumanUID && subject.SubjectID == b.Grant.SubjectID && subject.GrantID == b.Grant.GrantID {
			return nil
		}
	}
	return fmt.Errorf("evidence: human access binding grant does not match subject map")
}

// AgentRole distinguishes the controller-owned Primary Agent from a
// harness-spawned Child Agent. See DESIGN.md "Agent hierarchy and attribution".
type AgentRole string

const (
	AgentRolePrimary AgentRole = "primary"
	AgentRoleChild   AgentRole = "child"
)

// AttributionMethod records how an agent's identity was established. Only
// controller and native_harness are producible in v0.1; trusted_cgroup,
// process_inheritance, and broker_context are reserved vocabulary for a future
// trusted-executor / agent-scoped-broker phase and are produced by nothing today.
type AttributionMethod string

const (
	MethodController         AttributionMethod = "controller"
	MethodNativeHarness      AttributionMethod = "native_harness"
	MethodTrustedCgroup      AttributionMethod = "trusted_cgroup"      // reserved
	MethodProcessInheritance AttributionMethod = "process_inheritance" // reserved
	MethodBrokerContext      AttributionMethod = "broker_context"      // reserved
	MethodUnattributed       AttributionMethod = "unattributed"
)

// AttributionStrength is how much trust an agent label carries. The recorder
// derives method and strength from the authenticated channel, never the payload,
// so a workload label can never present as strong.
type AttributionStrength string

const (
	StrengthStrong       AttributionStrength = "strong"
	StrengthLineage      AttributionStrength = "lineage"
	StrengthSelfReported AttributionStrength = "self_reported"
	StrengthNone         AttributionStrength = "none"
)

// Agent execution scope. Only "session" is producible; "cgroup" is reserved for
// the deferred trusted-executor phase.
const (
	ScopeSession = "session"
	ScopeCgroup  = "cgroup" // reserved
)

// Event catalog. Only these names may be emitted; the recorder rejects others.
const (
	EventSessionGranted         = "session.granted"
	EventSessionStarted         = "session.started"
	EventSessionStopped         = "session.stopped"
	EventSessionSealed          = "session.sealed"
	EventPolicyLoaded           = "policy.loaded"
	EventAuthorizationDecided   = "authorization.decided"
	EventModelRequested         = "model.requested"
	EventModelCompleted         = "model.completed"
	EventToolRequested          = "tool.requested"
	EventToolCompleted          = "tool.completed"
	EventAgentStarted           = "agent.started"
	EventAgentCompleted         = "agent.completed"
	EventProcessCreated         = "process.created"
	EventProcessExecuted        = "process.executed"
	EventProcessExited          = "process.exited"
	EventFileChanged            = "file.changed"
	EventFileDeleted            = "file.deleted"
	EventWorkspaceMutated       = "workspace.mutated"
	EventWorkspaceManifested    = "workspace.manifested"
	EventNetworkConnected       = "network.connected"
	EventNetworkDenied          = "network.denied"
	EventInternalToolDispatched = "internal_tool.dispatched"
	EventInternalToolCompleted  = "internal_tool.completed"
	EventInternalToolFailed     = "internal_tool.failed"
	EventEffectRequested        = "effect.requested"
	EventEffectApproved         = "effect.approved"
	EventEffectDenied           = "effect.denied"
	EventEffectDispatched       = "effect.dispatched"
	EventEffectCompleted        = "effect.completed"
	EventEffectFailed           = "effect.failed"
	EventCredentialIssued       = "credential.issued"
	EventCredentialRevoked      = "credential.revoked"
	EventSensorStarted          = "sensor.started"
	EventSensorLoss             = "sensor.loss"
	EventSensorRestarted        = "sensor.restarted"
	EventSegmentSealed          = "segment.sealed"
)

// Catalog is the set of valid event names.
var Catalog = map[string]bool{
	EventSessionGranted: true, EventSessionStarted: true, EventSessionStopped: true,
	EventSessionSealed: true, EventPolicyLoaded: true, EventAuthorizationDecided: true,
	EventModelRequested: true, EventModelCompleted: true, EventToolRequested: true,
	EventToolCompleted: true, EventAgentStarted: true, EventAgentCompleted: true,
	EventProcessCreated: true, EventProcessExecuted: true, EventProcessExited: true,
	EventFileChanged: true, EventWorkspaceMutated: true,
	EventFileDeleted: true, EventWorkspaceManifested: true, EventNetworkConnected: true,
	EventNetworkDenied: true, EventInternalToolDispatched: true,
	EventInternalToolCompleted: true, EventInternalToolFailed: true,
	EventEffectRequested: true, EventEffectApproved: true, EventEffectDenied: true,
	EventEffectDispatched: true, EventEffectCompleted: true, EventEffectFailed: true,
	EventCredentialIssued: true, EventCredentialRevoked: true, EventSensorStarted: true,
	EventSensorLoss: true, EventSensorRestarted: true, EventSegmentSealed: true,
}

// Well-known attribute keys (audit.* / vm.* / process.* namespaces per DESIGN.md).
const (
	AttrSchemaVersion       = "audit.schema.version"
	AttrEventID             = "audit.event.id"
	AttrSequence            = "audit.sequence"
	AttrSessionID           = "audit.session.id"
	AttrActionID            = "audit.action.id"
	AttrParentActionID      = "audit.parent_action.id"
	AttrEvidenceClass       = "audit.evidence.class"
	AttrProducer            = "audit.producer"
	AttrMonotonicNS         = "audit.monotonic_ns"
	AttrPolicyDigest        = "audit.policy.digest"
	AttrOutcome             = "audit.outcome"
	AttrContentDigest       = "audit.content.digest"
	AttrContentCapture      = "audit.content.capture"
	AttrCorrelation         = "audit.correlation"
	AttrVMID                = "vm.id"
	AttrVMBootID            = "vm.boot.id"
	AttrProcessExecID       = "process.exec.id"
	AttrProcessParentExecID = "process.parent_exec_id"
	AttrProcessPID          = "process.pid"
	AttrProcessPPID         = "process.parent_pid"
	AttrProcessCgroupID     = "process.cgroup.id"

	AttrHumanAccessGrantID          = "human_access.grant.id"
	AttrHumanAccessSubjectID        = "human_access.subject.id"
	AttrHumanAccessExpiresAt        = "human_access.expires_at"
	AttrHumanAccessSurface          = "human_access.surface"
	AttrHumanAccessUID              = "human_access.uid"
	AttrHumanAccessCredentialDigest = "human_access.credential.digest"

	AttrMutationActorClass   = "mutation.actor.class"
	AttrMutationBasis        = "mutation.attribution.basis"
	AttrMutationOpenerUID    = "mutation.opener.uid"
	AttrMutationOpenMode     = "mutation.open.mode"
	AttrMutationOperation    = "mutation.operation"
	AttrMutationPath         = "mutation.path"
	AttrMutationPosition     = "mutation.position"
	AttrMutationPositionKind = "mutation.position.kind"
	AttrMutationUID          = "mutation.uid"

	// agent.* attribution family. method/strength are recorder-assigned from the
	// producer channel; native_id is an attribute only, never identity.
	AttrAgentID                  = "agent.id"
	AttrAgentNativeID            = "agent.native_id"
	AttrAgentParentID            = "agent.parent.id"
	AttrAgentRole                = "agent.role"
	AttrAgentType                = "agent.type"
	AttrAgentHarness             = "agent.harness"
	AttrAgentOutcome             = "agent.outcome"
	AttrAgentExecutionScope      = "agent.execution_scope"
	AttrAgentAttributionMethod   = "agent.attribution.method"
	AttrAgentAttributionStrength = "agent.attribution.strength"
	// AttrAgentSettingsDigest is the SHA-256 of the exact staged harness hook
	// settings, stamped by the controller on the Primary Agent's agent.started so
	// the hook wiring the workload ran under is attestable (DESIGN.md "Harness
	// hook capture").
	AttrAgentSettingsDigest = "agent.settings.digest"
	// AttrAgentCapabilityPrefix namespaces the controller-attested adapter
	// capability declaration on the Primary Agent's agent.started; the suffix is
	// one of the Category* constants and the value is an AttributionStrength.
	AttrAgentCapabilityPrefix = "agent.capability."

	// Subagent-spawn narration lifted out of the spawn tool's input by the hook
	// (Claude Code names that tool "Task" or "Agent" depending on version) and
	// stamped on the spawning tool event, because the tool_input excerpt is
	// size-capped and the embedded subagent prompt can crowd the description out
	// of it. Self-reported display narration only: the viewer uses it to pair a
	// spawn with the child it likely started; the record claims no such linkage
	// (DESIGN.md "Harness hook capture").
	AttrHarnessTaskDescription  = "harness.task.description"
	AttrHarnessTaskSubagentType = "harness.task.subagent_type"

	// The spawn↔child linkage the harness itself declares: Claude Code's spawn
	// tool returns the id of the agent it created in the PostToolUse
	// tool_response, so the completion event of a spawn call names both sides of
	// the edge — the spawning agent in AttrAgentID and the agent it produced
	// here. It is the only nested-parent signal Claude Code supplies: the
	// SubagentStart hook that registers a child carries no parent field, so a
	// child's own agent.parent.id cannot name its true parent (DESIGN.md
	// ownership invariant 4). Self-reported like every hook narration, and
	// deferred — a spawn completion can arrive either side of the child's
	// registration (a backgrounded spawn returns before its child starts), so any
	// consumer must join set-wise, never by sequence order (invariant 8).
	AttrAgentSpawnedID       = "agent.spawned.id"
	AttrAgentSpawnedNativeID = "agent.spawned.native_id"
)

// Attribution categories declared in the Primary Agent's capability block and
// gated per-category by the verifier (DESIGN.md "Per-category attribution
// capability"). Each maps to the AttrAgentCapabilityPrefix+<category> key.
const (
	CategoryProcess = "process"
	CategoryTool    = "tool"
	CategoryModel   = "model"
	CategoryFile    = "file"
	CategoryNetwork = "network"
)

// Event is one audit record as submitted by a producer. Sequence, producer and
// (clamped) class are assigned by the recorder at ingest; producers may request a
// Class within their channel allowance.
type Event struct {
	Name           string         `json:"name"`
	Time           time.Time      `json:"time"`            // wall clock; recorder fills if zero
	MonotonicNS    int64          `json:"monotonic_ns"`    // producer monotonic clock; recorder fills if zero
	Class          Class          `json:"class,omitempty"` // requested; clamped to channel allowance
	ActionID       string         `json:"action_id,omitempty"`
	ParentActionID string         `json:"parent_action_id,omitempty"`
	Outcome        Outcome        `json:"outcome,omitempty"`
	Body           string         `json:"body,omitempty"`  // short human-readable summary
	Attrs          map[string]any `json:"attrs,omitempty"` // flat; string|int64|float64|bool values only
}

// Emitter ingests events. Implementations must never silently drop an event:
// a non-nil error means the event was not durably recorded and the session must
// treat evidence capture as broken (fail closed).
type Emitter interface {
	Emit(ch Channel, ev Event) error
}

// Validate checks producer-side invariants before submission.
func (e *Event) Validate() error {
	if !Catalog[e.Name] {
		return fmt.Errorf("evidence: unknown event name %q", e.Name)
	}
	for k, v := range e.Attrs {
		switch v.(type) {
		case string, int64, int, float64, bool:
		default:
			return fmt.Errorf("evidence: attr %q has unsupported type %T", k, v)
		}
	}
	if e.Name == EventWorkspaceMutated {
		if err := validateMediatedMutation(e.Attrs); err != nil {
			return err
		}
	}
	return nil
}

func validAccessSurface(surface AccessSurface) bool {
	switch surface {
	case AccessSurfaceBrowserTerminal, AccessSurfaceVSCodeRemoteSSH, AccessSurfaceIntelliJRemoteDev:
		return true
	default:
		return false
	}
}

func validateMediatedMutation(attrs map[string]any) error {
	if _, ok := integerAttr(attrs, AttrMutationUID); !ok {
		return fmt.Errorf("evidence: workspace mutation has no integer %s", AttrMutationUID)
	}
	switch MutationActorClass(stringAttr(attrs, AttrMutationActorClass)) {
	case MutationActorHuman, MutationActorAgent, MutationActorSupervisor, MutationActorUnattributed:
	default:
		return fmt.Errorf("evidence: workspace mutation has invalid %s", AttrMutationActorClass)
	}
	switch stringAttr(attrs, AttrMutationBasis) {
	case "caller", "opener_fallback", "ambiguous":
	default:
		return fmt.Errorf("evidence: workspace mutation has invalid %s", AttrMutationBasis)
	}
	if _, ok := integerAttr(attrs, AttrMutationOpenerUID); !ok {
		return fmt.Errorf("evidence: workspace mutation has no integer %s", AttrMutationOpenerUID)
	}
	if !validMutationOpenMode(stringAttr(attrs, AttrMutationOpenMode)) {
		return fmt.Errorf("evidence: workspace mutation has invalid %s", AttrMutationOpenMode)
	}
	if !validMutationOperation(stringAttr(attrs, AttrMutationOperation)) {
		return fmt.Errorf("evidence: workspace mutation has invalid %s", AttrMutationOperation)
	}
	mutationPath := stringAttr(attrs, AttrMutationPath)
	cleanMutationPath := path.Clean(mutationPath)
	if mutationPath == "" || path.IsAbs(mutationPath) || mutationPath == "." || cleanMutationPath == ".." || strings.HasPrefix(cleanMutationPath, "../") {
		return fmt.Errorf("evidence: workspace mutation has invalid relative %s", AttrMutationPath)
	}
	if stringAttr(attrs, AttrContentDigest) == "" {
		return fmt.Errorf("evidence: workspace mutation has no %s", AttrContentDigest)
	}
	switch MutationPositionKind(stringAttr(attrs, AttrMutationPositionKind)) {
	case MutationPositionPositional:
		if _, ok := integerAttr(attrs, AttrMutationPosition); !ok {
			return fmt.Errorf("evidence: positional workspace mutation has no integer %s", AttrMutationPosition)
		}
	case MutationPositionNonPositional:
		if _, present := attrs[AttrMutationPosition]; present {
			return fmt.Errorf("evidence: non-positional workspace mutation has %s", AttrMutationPosition)
		}
	default:
		return fmt.Errorf("evidence: workspace mutation has invalid %s", AttrMutationPositionKind)
	}
	return nil
}

func integerAttr(attrs map[string]any, key string) (int64, bool) {
	switch value := attrs[key].(type) {
	case int:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		if math.Trunc(value) == value && value >= -float64(1<<53-1) && value <= float64(1<<53-1) {
			return int64(value), true
		}
		return 0, false
	default:
		return 0, false
	}
}

func stringAttr(attrs map[string]any, key string) string {
	value, _ := attrs[key].(string)
	return value
}

func validMutationOpenMode(mode string) bool {
	return mode == string(MutationOpenWriteOnly) || mode == string(MutationOpenReadWrite)
}

func validMutationOperation(operation string) bool {
	switch MutationOperation(operation) {
	case MutationOperationWrite, MutationOperationTruncate, MutationOperationReplace, MutationOperationRename, MutationOperationDelete, MutationOperationMetadata:
		return true
	default:
		return false
	}
}

// SHA256Hex returns the "sha256:<hex>" digest string used everywhere in BoxedAi.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// agentIDDomain separates the deterministic agent-id preimage. primaryAgentScope
// is the Primary Agent's fixed scope token, so its id never collides with a child
// whose native_id happens to equal the session id.
const (
	agentIDDomain     = "boxedai.agent/v1"
	primaryAgentScope = "primary"
	childAgentScope   = "child"
)

// PrimaryAgentID returns the deterministic, session-scoped id of the Primary
// Agent. The controller mints it and the verifier recomputes it independently.
func PrimaryAgentID(sessionID string) string {
	return agentID(sessionID, primaryAgentScope, "")
}

// ChildAgentID returns the deterministic id of a Child Agent from its
// harness-native id. The stateless hook, the controller, and the verifier all
// derive the same value, so a forged id that does not match its native_id is
// mechanically detectable and duplicate registrations collapse to one id.
func ChildAgentID(sessionID, nativeID string) string {
	return agentID(sessionID, childAgentScope, nativeID)
}

func agentID(sessionID, scope, nativeID string) string {
	sum := sha256.Sum256([]byte(agentIDDomain + "|" + sessionID + "|" + scope + "|" + nativeID))
	return "ag-" + hex.EncodeToString(sum[:])[:16]
}

// AgentAttributionFor returns the attribution method and strength the recorder
// stamps on an agent.started/agent.completed event, derived solely from the
// authenticated producer channel. Payload-supplied values are always overwritten
// with these, so a workload event can never present as controller/strong.
func AgentAttributionFor(ch Channel) (AttributionMethod, AttributionStrength) {
	switch ch {
	case ChannelController:
		return MethodController, StrengthStrong
	case ChannelWorkload:
		return MethodNativeHarness, StrengthSelfReported
	default:
		return MethodUnattributed, StrengthNone
	}
}

// CanonicalJSON marshals v deterministically: object keys sorted, no HTML escaping,
// no insignificant whitespace. All digests over JSON in BoxedAi (policy, manifests,
// normalized effect actions) MUST use this encoding.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(tree); err != nil { // json.Marshal sorts map keys
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
