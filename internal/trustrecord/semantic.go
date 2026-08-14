package trustrecord

import (
	"fmt"
	"time"
)

func ValidateSemantics(record Record) error {
	if record.Policy.Digest != record.Artifacts.PolicyDigest {
		return fmt.Errorf("trust record: policy digest does not match policy artifact digest")
	}
	if record.Evidence.SegmentCount != len(record.Evidence.Segments) {
		return fmt.Errorf("trust record: segment_count %d does not match %d segment descriptors", record.Evidence.SegmentCount, len(record.Evidence.Segments))
	}
	if len(record.Evidence.Segments) == 0 {
		return fmt.Errorf("trust record: no segment descriptors")
	}
	var recordCount int64
	for i, segment := range record.Evidence.Segments {
		wantNumber := i + 1
		if segment.Number != wantNumber {
			return fmt.Errorf("trust record: segment descriptor %d has number %d", wantNumber, segment.Number)
		}
		if segment.LastSequence-segment.FirstSequence+1 != segment.RecordCount {
			return fmt.Errorf("trust record: segment %d sequence range does not match record_count", segment.Number)
		}
		if i > 0 && segment.FirstSequence != record.Evidence.Segments[i-1].LastSequence+1 {
			return fmt.Errorf("trust record: segment %d sequence does not follow segment %d", segment.Number, segment.Number-1)
		}
		var ok bool
		recordCount, ok = addSafeInteger(recordCount, segment.RecordCount)
		if !ok {
			return fmt.Errorf("trust record: segment record total exceeds the RFC 8785 safe-integer range")
		}
	}
	first := record.Evidence.Segments[0]
	last := record.Evidence.Segments[len(record.Evidence.Segments)-1]
	if record.Evidence.FirstSequence != first.FirstSequence || record.Evidence.LastSequence != last.LastSequence {
		return fmt.Errorf("trust record: evidence sequence range does not match segment descriptors")
	}
	if record.Evidence.FirstSequence != 1 {
		return fmt.Errorf("trust record: first sequence is %d, want 1", record.Evidence.FirstSequence)
	}
	if record.Evidence.RecordCount != recordCount {
		return fmt.Errorf("trust record: record_count %d does not match segment total %d", record.Evidence.RecordCount, recordCount)
	}
	if record.Evidence.ChainTip != last.SegmentDigest {
		return fmt.Errorf("trust record: chain_tip does not match final segment digest")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, record.IssuedAt)
	if err != nil {
		return fmt.Errorf("trust record: parse issued_at: %w", err)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, record.Session.CreatedAt)
	if err != nil {
		return fmt.Errorf("trust record: parse session created_at: %w", err)
	}
	if issuedAt.Before(createdAt) {
		return fmt.Errorf("trust record: issued_at precedes session creation")
	}
	for _, segment := range record.Evidence.Segments {
		sealedAt, err := time.Parse(time.RFC3339Nano, segment.SealedAt)
		if err != nil {
			return fmt.Errorf("trust record: parse segment %d sealed_at: %w", segment.Number, err)
		}
		if issuedAt.Before(sealedAt) {
			return fmt.Errorf("trust record: issued_at precedes segment %d seal", segment.Number)
		}
	}
	if !stringsStrictlySorted(record.Evidence.SensorMechanisms) {
		return fmt.Errorf("trust record: sensor_mechanisms must be sorted and unique")
	}
	var modelRequests int64
	for i, model := range record.Activity.Models {
		if i > 0 {
			previous := record.Activity.Models[i-1]
			if previous.Provider > model.Provider || previous.Provider == model.Provider && previous.ModelID >= model.ModelID {
				return fmt.Errorf("trust record: models must be sorted and unique")
			}
		}
		var ok bool
		modelRequests, ok = addSafeInteger(modelRequests, model.RequestCount)
		if !ok {
			return fmt.Errorf("trust record: model request total exceeds the RFC 8785 safe-integer range")
		}
	}
	if modelRequests != record.Activity.ModelRequestCount {
		return fmt.Errorf("trust record: model_request_count %d does not match model totals %d", record.Activity.ModelRequestCount, modelRequests)
	}
	for i, tool := range record.Activity.Tools {
		if i > 0 && record.Activity.Tools[i-1].Name >= tool.Name {
			return fmt.Errorf("trust record: tools must be sorted and unique")
		}
	}
	var dispatchedCalls int64
	for _, tool := range record.Activity.Tools {
		var ok bool
		dispatchedCalls, ok = addSafeInteger(dispatchedCalls, tool.CallCount)
		if !ok {
			return fmt.Errorf("trust record: dispatched call total exceeds the RFC 8785 safe-integer range")
		}
	}
	var ok bool
	dispatchedCalls, ok = addSafeInteger(dispatchedCalls, record.Activity.EffectDispatchCount)
	if !ok {
		return fmt.Errorf("trust record: dispatched call total exceeds the RFC 8785 safe-integer range")
	}
	if record.Activity.ToolTranscript.CallCount != dispatchedCalls {
		return fmt.Errorf("trust record: tool transcript call_count does not match dispatched call totals")
	}
	if record.Activity.ToolTranscript.CallCount > record.Activity.ToolTranscript.EventCount {
		return fmt.Errorf("trust record: tool transcript call_count exceeds event_count")
	}
	return nil
}

func addSafeInteger(total, value int64) (int64, bool) {
	if value < 0 || total < 0 || value > MaxSafeInteger-total {
		return 0, false
	}
	return total + value, true
}

func stringsStrictlySorted(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] >= values[i] {
			return false
		}
	}
	return true
}
