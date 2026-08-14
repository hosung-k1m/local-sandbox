package verify

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protodelim"

	"boxedai/internal/evidence"
)

// record is one decoded evidence event, flattened from its OTLP LogRecord. The
// verifier reads segments itself (length-delimited OTLP) rather than reusing the
// recorder — independent decoding is the point. Resource-level and record-level
// attributes are merged (record wins) so it does not matter which layer the
// recorder placed a given constant attribute on.
type record struct {
	seq     int64
	name    string
	ts      time.Time
	traceID string
	seg     int // index of the segment file this record came from
	attrs   map[string]any
}

func (r record) str(key string) string {
	if s, ok := r.attrs[key].(string); ok {
		return s
	}
	return ""
}

func (r record) i64(key string) (int64, bool) {
	switch v := r.attrs[key].(type) {
	case int64:
		return v, true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v {
			return 0, false
		}
		return int64(v), true
	}
	return 0, false
}

// anyValue extracts the concrete Go value from an OTLP AnyValue. Only the scalar
// kinds used by BoxedAi events (string/int/double/bool) are decoded; other kinds
// yield nil.
func anyValue(v *commonv1.AnyValue) any {
	if v == nil {
		return nil
	}
	switch v.Value.(type) {
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

func collectAttrs(dst map[string]any, kvs []*commonv1.KeyValue) {
	for _, kv := range kvs {
		if kv == nil {
			continue
		}
		if val := anyValue(kv.GetValue()); val != nil {
			dst[kv.GetKey()] = val
		}
	}
}

// readSegment decodes every LogRecord in one .otlp file. Each protodelim frame is
// a single-record LogsData (DESIGN "Recorder" step 2); this reader tolerates
// multiple records per frame defensively.
func readSegment(path string, segIndex int) ([]record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	var out []record
	for {
		var ld logsv1.LogsData
		err := protodelim.UnmarshalFrom(br, &ld)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode otlp frame in %s: %w", path, err)
		}
		for _, rl := range ld.GetResourceLogs() {
			resAttrs := map[string]any{}
			collectAttrs(resAttrs, rl.GetResource().GetAttributes())
			for _, sl := range rl.GetScopeLogs() {
				for _, lr := range sl.GetLogRecords() {
					attrs := map[string]any{}
					for k, v := range resAttrs {
						attrs[k] = v
					}
					collectAttrs(attrs, lr.GetAttributes())
					r := record{
						name:    lr.GetEventName(),
						ts:      time.Unix(0, int64(lr.GetTimeUnixNano())).UTC(),
						traceID: hex.EncodeToString(lr.GetTraceId()),
						seg:     segIndex,
						attrs:   attrs,
					}
					sequence, ok := r.i64(evidence.AttrSequence)
					if !ok {
						return nil, fmt.Errorf("decode otlp frame in %s: audit.sequence is not an integer", path)
					}
					r.seq = sequence
					out = append(out, r)
				}
			}
		}
	}
	return out, nil
}
