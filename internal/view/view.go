// Package view rebuilds a disposable SQLite projection from a session's raw
// evidence segments and renders it as a CLI timeline, a process tree, or a
// self-contained web UI (DESIGN.md "Viewer").
//
// view reads the length-delimited OTLP segment files directly (protodelim) and
// MUST NOT import internal/recorder: the projection is an independent read of
// the authoritative raw evidence, exactly like internal/verify. The projection
// database is disposable — Rebuild recreates it from the segments every time it
// is called, so it is safe to delete and never migrated.
package view

import (
	"strconv"
	"strings"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"

	"boxedai/internal/evidence"
)

// Filter narrows Timeline (and the web timeline) to a subset of events. Empty
// fields are unconstrained.
type Filter struct {
	Name  string // exact event name, e.g. "process.executed"
	Class string // exact evidence class, e.g. "kernel_observed"
	Since string // RFC3339 timestamp; only events with ts >= Since are included
}

// classBadges maps evidence classes to the short, human-readable badges shown
// in the timeline and web UI.
var classBadges = map[evidence.Class]string{
	evidence.ClassModelSelfReported: "SELF",
	evidence.ClassHarnessObserved:   "HARNESS",
	evidence.ClassKernelObserved:    "KERNEL",
	evidence.ClassBrokerMediated:    "BROKER",
	evidence.ClassTargetConfirmed:   "TARGET",
	evidence.ClassIntegrity:         "INTEG",
}

// classBadge returns the short badge for an evidence class, or the upper-cased
// class itself if unrecognized (forward-compatible with new classes).
func classBadge(class string) string {
	if b, ok := classBadges[evidence.Class(class)]; ok {
		return b
	}
	if class == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(class)
}

// anyValueToGo extracts the concrete Go value from an OTLP AnyValue, matching
// the scalar kinds evidence.Event.Validate accepts (string, int64, float64,
// bool). Other kinds (arrays, kvlists, bytes) are not used for audit attrs and
// decode to nil.
func anyValueToGo(v *commonv1.AnyValue) any {
	if v == nil {
		return nil
	}
	switch v.GetValue().(type) {
	case *commonv1.AnyValue_StringValue:
		return v.GetStringValue()
	case *commonv1.AnyValue_IntValue:
		return v.GetIntValue()
	case *commonv1.AnyValue_DoubleValue:
		return v.GetDoubleValue()
	case *commonv1.AnyValue_BoolValue:
		return v.GetBoolValue()
	default:
		return nil
	}
}

// kvListToMap flattens an OTLP KeyValue list into a plain map.
func kvListToMap(kvs []*commonv1.KeyValue) map[string]any {
	m := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		if kv == nil {
			continue
		}
		if v := anyValueToGo(kv.GetValue()); v != nil {
			m[kv.GetKey()] = v
		}
	}
	return m
}

// mergeAttrs combines resource-level (session-constant) and record-level
// attributes, with record-level winning on key collision. It does not matter
// which layer the recorder chose to place a given constant attribute on.
func mergeAttrs(resourceAttrs, recordAttrs map[string]any) map[string]any {
	out := make(map[string]any, len(resourceAttrs)+len(recordAttrs))
	for k, v := range resourceAttrs {
		out[k] = v
	}
	for k, v := range recordAttrs {
		out[k] = v
	}
	return out
}

// attrString renders an attribute value as a string regardless of its
// underlying scalar type, or "" if absent.
func attrString(attrs map[string]any, key string) string {
	switch v := attrs[key].(type) {
	case string:
		return v
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

// attrInt64 renders an attribute value as an int64 regardless of whether it
// decoded as int64 or float64, or 0 if absent/non-numeric.
func attrInt64(attrs map[string]any, key string) int64 {
	switch v := attrs[key].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	default:
		return 0
	}
}
