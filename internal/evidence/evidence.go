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
	EventFileChanged: true,
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
	return nil
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
