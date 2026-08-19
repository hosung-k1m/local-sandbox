package recorder

import (
	"fmt"
	"sort"

	"boxedai/internal/evidence"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// buildLogsData assembles a single-record OTLP LogsData for one resolved record: a
// ResourceLogs carrying the session-constant Resource attributes and one ScopeLogs
// with one LogRecord. Recorder-assigned audit.* attributes overwrite any caller value.
func (r *recorder) buildLogsData(seq int64, eventID string, rr resolvedRecord) *logspb.LogsData {
	attrs := make(map[string]any, len(rr.attrs)+12)
	for k, v := range rr.attrs {
		attrs[k] = v
	}
	// Recorder-owned attributes (authoritative; clobber any caller-supplied value).
	attrs[evidence.AttrSchemaVersion] = evidence.SchemaVersion
	attrs[evidence.AttrEventID] = eventID
	attrs[evidence.AttrSequence] = seq
	attrs[evidence.AttrSessionID] = r.meta.SessionID
	attrs[evidence.AttrEvidenceClass] = string(rr.class)
	attrs[evidence.AttrProducer] = string(rr.producer)
	attrs[evidence.AttrMonotonicNS] = rr.mono
	if r.meta.PolicyDigest != "" {
		attrs[evidence.AttrPolicyDigest] = r.meta.PolicyDigest
	}
	if rr.outcome != "" {
		attrs[evidence.AttrOutcome] = string(rr.outcome)
	}
	if rr.actionID != "" {
		attrs[evidence.AttrActionID] = rr.actionID
	}
	if rr.parentActionID != "" {
		attrs[evidence.AttrParentActionID] = rr.parentActionID
	}
	if r.meta.VMID != "" {
		attrs[evidence.AttrVMID] = r.meta.VMID
	}
	if r.meta.VMBootID != "" {
		attrs[evidence.AttrVMBootID] = r.meta.VMBootID
	}
	// agent.* lifecycle: derive attribution method/strength from the authenticated
	// channel and clobber any payload value, so a workload registration can never
	// present as controller/strong (DESIGN "Agent hierarchy and attribution").
	if rr.name == evidence.EventAgentStarted || rr.name == evidence.EventAgentCompleted {
		method, strength := evidence.AgentAttributionFor(rr.producer)
		attrs[evidence.AttrAgentAttributionMethod] = string(method)
		attrs[evidence.AttrAgentAttributionStrength] = string(strength)
	}
	if rr.name == evidence.EventWorkspaceMutated {
		uid := int64(-1)
		switch value := rr.attrs[evidence.AttrMutationUID].(type) {
		case int:
			uid = int64(value)
		case int64:
			uid = value
		case float64:
			uid = int64(value)
		}
		attrs[evidence.AttrMutationActorClass] = string(evidence.MutationActorForRecord(rr.producer, uid, r.meta.HumanAccessBinding, rr.wall))
	}

	rec := &logspb.LogRecord{
		TimeUnixNano:         uint64(rr.wall.UnixNano()),
		ObservedTimeUnixNano: uint64(rr.observed.UnixNano()),
		EventName:            rr.name,
		Body:                 &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: rr.body}},
		Attributes:           toKeyValues(attrs),
	}
	if len(r.traceID) > 0 {
		rec.TraceId = r.traceID
	}

	return &logspb.LogsData{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource:  &resourcepb.Resource{Attributes: toKeyValues(r.resourceAttrs())},
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{rec}}},
		}},
	}
}

// resourceAttrs returns the session-constant attributes carried on every Resource
// ("inherited from Resource where constant", DESIGN "Required attributes").
func (r *recorder) resourceAttrs() map[string]any {
	m := map[string]any{
		evidence.AttrSchemaVersion: evidence.SchemaVersion,
		evidence.AttrSessionID:     r.meta.SessionID,
	}
	if r.meta.PolicyDigest != "" {
		m[evidence.AttrPolicyDigest] = r.meta.PolicyDigest
	}
	if r.meta.VMID != "" {
		m[evidence.AttrVMID] = r.meta.VMID
	}
	if r.meta.VMBootID != "" {
		m[evidence.AttrVMBootID] = r.meta.VMBootID
	}
	return m
}

// toKeyValues converts an attribute map to OTLP KeyValues, key-sorted for stable output.
func toKeyValues(m map[string]any) []*commonpb.KeyValue {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kvs := make([]*commonpb.KeyValue, 0, len(m))
	for _, k := range keys {
		kvs = append(kvs, &commonpb.KeyValue{Key: k, Value: toAnyValue(m[k])})
	}
	return kvs
}

// toAnyValue wraps a scalar attribute value in an OTLP AnyValue. evidence.Event.Validate
// restricts attrs to string|int|int64|float64|bool; the default arm is defensive only.
func toAnyValue(v any) *commonpb.AnyValue {
	switch t := v.(type) {
	case string:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: t}}
	case bool:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: t}}
	case int:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(t)}}
	case int64:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: t}}
	case float64:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: t}}
	default:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: fmt.Sprintf("%v", v)}}
	}
}
