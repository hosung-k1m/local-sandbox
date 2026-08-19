package trustrecord

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"boxedai/internal/evidence"

	"github.com/gowebpki/jcs"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protodelim"
)

const (
	attrModelProvider   = "model.provider"
	attrModelID         = "model.id"
	attrUsageInput      = "llm.usage.input_tokens"
	attrUsageOutput     = "llm.usage.output_tokens"
	attrUsageTotal      = "llm.usage.total_tokens"
	attrToolName        = "tool.name"
	attrToolOperation   = "tool.op"
	attrEffectAdapter   = "effect.adapter"
	attrEffectOperation = "effect.op"
	attrSensorMechanism = "sensor.mechanism"
	attrWorkspacePhase  = "workspace.phase"
)

type buildGrant struct {
	Schema              string                       `json:"schema"`
	SessionID           string                       `json:"session_id"`
	TraceID             string                       `json:"trace_id"`
	Harness             string                       `json:"harness"`
	Profile             string                       `json:"profile"`
	Repository          string                       `json:"repository"`
	Branch              string                       `json:"branch"`
	Commit              string                       `json:"commit"`
	CreatedAt           string                       `json:"created_at"`
	PolicyDigest        string                       `json:"policy_digest"`
	InputManifestDigest string                       `json:"input_manifest_digest"`
	VMImage             string                       `json:"vm_image"`
	VMImageDigest       string                       `json:"vm_image_digest"`
	HumanAccess         *evidence.HumanAccessBinding `json:"human_access,omitempty"`
	TrustRecord         struct {
		Schema   string `json:"schema"`
		Path     string `json:"path"`
		Required bool   `json:"required"`
	} `json:"trust_record"`
}

type buildManifest struct {
	Schema             string `json:"schema"`
	SessionID          string `json:"session_id"`
	SegmentNumber      int    `json:"segment_number"`
	FirstSequence      int64  `json:"first_sequence"`
	LastSequence       int64  `json:"last_sequence"`
	RecordCount        int64  `json:"record_count"`
	PrevSegmentDigest  string `json:"prev_segment_digest"`
	SegmentDigest      string `json:"segment_digest"`
	PolicyDigest       string `json:"policy_digest"`
	SensorLossCount    int64  `json:"sensor_loss_count"`
	SensorRestartCount int64  `json:"sensor_restart_count"`
	CreatedAt          string `json:"created_at"`
	SealedAt           string `json:"sealed_at"`
}

type observedRecord struct {
	sequence int64
	name     string
	traceID  string
	attrs    map[string]any
}

func (r observedRecord) stringValue(key string) string {
	value, _ := r.attrs[key].(string)
	return value
}

func (r observedRecord) int64Value(key string) (int64, bool, error) {
	switch value := r.attrs[key].(type) {
	case int64:
		if value > MaxSafeInteger || value < -MaxSafeInteger {
			return 0, false, fmt.Errorf("trust record: observed %s is outside the RFC 8785 safe-integer range", key)
		}
		return value, true, nil
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value > float64(MaxSafeInteger) || value < -float64(MaxSafeInteger) {
			return 0, false, fmt.Errorf("trust record: observed %s is not a safe integer", key)
		}
		return int64(value), true, nil
	default:
		return 0, false, nil
	}
}

func (r observedRecord) brokerMediated() bool {
	return r.stringValue(evidence.AttrProducer) == string(evidence.ChannelBroker) &&
		r.stringValue(evidence.AttrEvidenceClass) == string(evidence.ClassBrokerMediated)
}

func (r observedRecord) guestKernelObserved() bool {
	return r.stringValue(evidence.AttrProducer) == string(evidence.ChannelGuestSupervisor) &&
		r.stringValue(evidence.AttrEvidenceClass) == string(evidence.ClassKernelObserved)
}

func (r observedRecord) guestIntegrityObserved() bool {
	return r.stringValue(evidence.AttrProducer) == string(evidence.ChannelGuestSupervisor) &&
		r.stringValue(evidence.AttrEvidenceClass) == string(evidence.ClassIntegrity)
}

type normalizedToolEvent struct {
	Sequence        int64  `json:"sequence"`
	Event           string `json:"event"`
	ActionID        string `json:"action_id,omitempty"`
	ParentActionID  string `json:"parent_action_id,omitempty"`
	Outcome         string `json:"outcome,omitempty"`
	ContentDigest   string `json:"content_digest,omitempty"`
	ToolName        string `json:"tool_name,omitempty"`
	ToolOperation   string `json:"tool_operation,omitempty"`
	EffectAdapter   string `json:"effect_adapter,omitempty"`
	EffectOperation string `json:"effect_operation,omitempty"`
}

// Build rereads the sealed session artifacts and OTLP evidence to create the
// unsigned record. Signing is a separate step so the producer never needs to
// place private key material into the portable record.
func Build(sessionDir string, issuedAt time.Time, publicKey ed25519.PublicKey) (Record, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Record{}, fmt.Errorf("trust record: build key has %d bytes, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	grantBytes, grantDigest, err := readArtifact(sessionDir, "session.json")
	if err != nil {
		return Record{}, err
	}
	var grant buildGrant
	if err := json.Unmarshal(grantBytes, &grant); err != nil {
		return Record{}, fmt.Errorf("trust record: parse session grant: %w", err)
	}
	if grant.Schema != "boxedai.session/v2" || grant.TrustRecord.Schema != Profile || grant.TrustRecord.Path != FileName || !grant.TrustRecord.Required {
		return Record{}, fmt.Errorf("trust record: session grant does not require the canonical %s record", Profile)
	}
	_, policyDigest, err := readArtifact(sessionDir, "policy.json")
	if err != nil {
		return Record{}, err
	}
	_, inputDigest, err := readArtifact(sessionDir, "input-manifest.json")
	if err != nil {
		return Record{}, err
	}
	_, outputDigest, err := readArtifact(sessionDir, "output-manifest.json")
	if err != nil {
		return Record{}, err
	}
	if grant.PolicyDigest != policyDigest {
		return Record{}, fmt.Errorf("trust record: policy artifact digest %s does not match grant %s", policyDigest, grant.PolicyDigest)
	}
	if grant.InputManifestDigest != inputDigest {
		return Record{}, fmt.Errorf("trust record: input manifest digest %s does not match grant %s", inputDigest, grant.InputManifestDigest)
	}

	evidenceSummary, records, err := buildEvidence(sessionDir, grant)
	if err != nil {
		return Record{}, err
	}
	if err := validateArtifactEvents(records, grantDigest, policyDigest, inputDigest, outputDigest); err != nil {
		return Record{}, err
	}
	activity, err := buildActivity(records)
	if err != nil {
		return Record{}, err
	}

	record := Record{
		Schema:   Profile,
		IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano),
		Session: Session{
			ID:        grant.SessionID,
			TraceID:   grant.TraceID,
			Harness:   grant.Harness,
			CreatedAt: grant.CreatedAt,
		},
		Runtime: Runtime{
			Platform:  RuntimePlatformSoftware,
			Isolation: RuntimeIsolationLima,
			Image: RuntimeImage{
				Name:   grant.VMImage,
				Digest: grant.VMImageDigest,
			},
		},
		Origin: Origin{
			Kind:     OriginHostControlPlane,
			Producer: OriginProducerRecorder,
		},
		Policy: Policy{
			Profile: grant.Profile,
			Digest:  grant.PolicyDigest,
		},
		Artifacts: Artifacts{
			SessionGrantDigest:   grantDigest,
			PolicyDigest:         policyDigest,
			InputManifestDigest:  inputDigest,
			OutputManifestDigest: outputDigest,
		},
		Evidence: evidenceSummary,
		Activity: activity,
		Assurance: Assurance{
			Level:               0,
			VerdictCeiling:      AssuranceVerdictLocalOnly,
			HardwareAttested:    false,
			ExternallyWitnessed: false,
		},
		Signing: Signing{
			Algorithm:              SignatureAlgorithmEd25519,
			Canonicalization:       CanonicalizationRFC8785,
			RecorderKeyFingerprint: PublicKeyFingerprint(publicKey),
		},
	}
	if grant.HumanAccess != nil {
		if err := grant.HumanAccess.Validate(); err != nil {
			return Record{}, fmt.Errorf("trust record: invalid human access binding: %w", err)
		}
		record.Runtime.HumanAccess = grant.HumanAccess
	}
	if grant.Repository != "" || grant.Branch != "" || grant.Commit != "" {
		record.Source = &Source{Repository: grant.Repository, Branch: grant.Branch, Commit: grant.Commit}
	}
	return record, nil
}

func readArtifact(sessionDir, name string) ([]byte, string, error) {
	data, err := os.ReadFile(filepath.Join(sessionDir, name))
	if err != nil {
		return nil, "", fmt.Errorf("trust record: read %s: %w", name, err)
	}
	return data, evidence.SHA256Hex(data), nil
}

func buildEvidence(sessionDir string, grant buildGrant) (Evidence, []observedRecord, error) {
	dir := filepath.Join(sessionDir, "evidence", "segments")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Evidence{}, nil, fmt.Errorf("trust record: read segment directory: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".otlp") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return Evidence{}, nil, fmt.Errorf("trust record: no sealed evidence segments")
	}

	summary := Evidence{Schema: EvidenceProfile, SegmentCount: len(names)}
	var records []observedRecord
	var previousDigest string
	mechanisms := map[string]struct{}{}
	for i, name := range names {
		number, err := segmentNumber(name)
		if err != nil {
			return Evidence{}, nil, err
		}
		if number != i+1 {
			return Evidence{}, nil, fmt.Errorf("trust record: segment %s has number %d, want %d", name, number, i+1)
		}
		otlpPath := filepath.Join(dir, name)
		segmentDigest, err := fileDigest(otlpPath)
		if err != nil {
			return Evidence{}, nil, err
		}
		base := strings.TrimSuffix(name, ".otlp")
		manifestPath := filepath.Join(dir, base+".manifest.json")
		if _, err := os.Stat(filepath.Join(dir, base+".manifest.cose")); err != nil {
			return Evidence{}, nil, fmt.Errorf("trust record: read %s.manifest.cose: %w", base, err)
		}
		manifestBytes, err := os.ReadFile(manifestPath)
		if err != nil {
			return Evidence{}, nil, fmt.Errorf("trust record: read %s: %w", filepath.Base(manifestPath), err)
		}
		var manifest buildManifest
		decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			return Evidence{}, nil, fmt.Errorf("trust record: parse %s: %w", filepath.Base(manifestPath), err)
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return Evidence{}, nil, err
		}
		if manifest.Schema != "boxedai.segment/v1" || manifest.SessionID != grant.SessionID || manifest.PolicyDigest != grant.PolicyDigest {
			return Evidence{}, nil, fmt.Errorf("trust record: segment %d manifest binding mismatch", number)
		}
		if manifest.SegmentNumber != number || manifest.SegmentDigest != segmentDigest || manifest.PrevSegmentDigest != previousDigest {
			return Evidence{}, nil, fmt.Errorf("trust record: segment %d manifest chain or digest mismatch", number)
		}
		segmentRecords, err := readOTLP(otlpPath)
		if err != nil {
			return Evidence{}, nil, err
		}
		if int64(len(segmentRecords)) != manifest.RecordCount || len(segmentRecords) == 0 {
			return Evidence{}, nil, fmt.Errorf("trust record: segment %d record count does not match manifest", number)
		}
		if segmentRecords[0].sequence != manifest.FirstSequence || segmentRecords[len(segmentRecords)-1].sequence != manifest.LastSequence {
			return Evidence{}, nil, fmt.Errorf("trust record: segment %d sequence range does not match manifest", number)
		}
		for _, observed := range segmentRecords {
			wantSequence := int64(len(records) + 1)
			if observed.sequence != wantSequence {
				return Evidence{}, nil, fmt.Errorf("trust record: audit sequence %d, want %d", observed.sequence, wantSequence)
			}
			if observed.traceID != grant.TraceID || observed.stringValue(evidence.AttrSchemaVersion) != evidence.SchemaVersion || observed.stringValue(evidence.AttrSessionID) != grant.SessionID || observed.stringValue(evidence.AttrPolicyDigest) != grant.PolicyDigest {
				return Evidence{}, nil, fmt.Errorf("trust record: event %d trace, schema, session, or policy binding mismatch", observed.sequence)
			}
			if (observed.name == evidence.EventSensorStarted || observed.name == evidence.EventSensorRestarted) && observed.guestIntegrityObserved() {
				if mechanism := observed.stringValue(attrSensorMechanism); mechanism != "" {
					mechanisms[mechanism] = struct{}{}
				}
			}
			records = append(records, observed)
		}
		summary.RecordCount += manifest.RecordCount
		summary.Segments = append(summary.Segments, Segment{
			Number:         manifest.SegmentNumber,
			SegmentDigest:  manifest.SegmentDigest,
			ManifestDigest: evidence.SHA256Hex(manifestBytes),
			FirstSequence:  manifest.FirstSequence,
			LastSequence:   manifest.LastSequence,
			RecordCount:    manifest.RecordCount,
			SealedAt:       manifest.SealedAt,
		})
		previousDigest = manifest.SegmentDigest
	}
	summary.FirstSequence = records[0].sequence
	summary.LastSequence = records[len(records)-1].sequence
	summary.ChainTip = previousDigest
	for mechanism := range mechanisms {
		summary.SensorMechanisms = append(summary.SensorMechanisms, mechanism)
	}
	sort.Strings(summary.SensorMechanisms)
	var observedLosses, observedRestarts int64
	for _, observed := range records {
		if !observed.guestIntegrityObserved() {
			continue
		}
		switch observed.name {
		case evidence.EventSensorLoss:
			observedLosses++
		case evidence.EventSensorRestarted:
			observedRestarts++
		}
	}
	summary.SensorLossCount = observedLosses
	summary.SensorRestartCount = observedRestarts
	return summary, records, nil
}

func segmentNumber(name string) (int, error) {
	value := strings.TrimSuffix(strings.TrimPrefix(name, "segment-"), ".otlp")
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 {
		return 0, fmt.Errorf("trust record: invalid segment file name %q", name)
	}
	return number, nil
}

func fileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("trust record: read %s: %w", filepath.Base(path), err)
	}
	return evidence.SHA256Hex(data), nil
}

func readOTLP(path string) ([]observedRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("trust record: open %s: %w", filepath.Base(path), err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var records []observedRecord
	for {
		var data logsv1.LogsData
		err := protodelim.UnmarshalFrom(reader, &data)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("trust record: decode OTLP frame in %s: %w", filepath.Base(path), err)
		}
		for _, resourceLogs := range data.GetResourceLogs() {
			resourceAttrs := map[string]any{}
			collectAttributes(resourceAttrs, resourceLogs.GetResource().GetAttributes())
			for _, scopeLogs := range resourceLogs.GetScopeLogs() {
				for _, logRecord := range scopeLogs.GetLogRecords() {
					attrs := map[string]any{}
					for key, value := range resourceAttrs {
						attrs[key] = value
					}
					collectAttributes(attrs, logRecord.GetAttributes())
					sequence, _ := scalarInt64(attrs[evidence.AttrSequence])
					records = append(records, observedRecord{sequence: sequence, name: logRecord.GetEventName(), traceID: hex.EncodeToString(logRecord.GetTraceId()), attrs: attrs})
				}
			}
		}
	}
	return records, nil
}

func collectAttributes(destination map[string]any, values []*commonv1.KeyValue) {
	for _, value := range values {
		if value == nil || value.GetValue() == nil {
			continue
		}
		switch concrete := value.GetValue().Value.(type) {
		case *commonv1.AnyValue_StringValue:
			destination[value.GetKey()] = concrete.StringValue
		case *commonv1.AnyValue_IntValue:
			destination[value.GetKey()] = concrete.IntValue
		case *commonv1.AnyValue_DoubleValue:
			destination[value.GetKey()] = concrete.DoubleValue
		case *commonv1.AnyValue_BoolValue:
			destination[value.GetKey()] = concrete.BoolValue
		}
	}
}

func scalarInt64(value any) (int64, bool) {
	switch concrete := value.(type) {
	case int64:
		return concrete, concrete <= MaxSafeInteger && concrete >= -MaxSafeInteger
	case float64:
		if math.IsNaN(concrete) || math.IsInf(concrete, 0) || math.Trunc(concrete) != concrete || concrete > float64(MaxSafeInteger) || concrete < -float64(MaxSafeInteger) {
			return 0, false
		}
		return int64(concrete), true
	default:
		return 0, false
	}
}

func validateArtifactEvents(records []observedRecord, grantDigest, policyDigest, inputDigest, outputDigest string) error {
	want := map[string]string{
		"grant":  grantDigest,
		"policy": policyDigest,
		"input":  inputDigest,
		"output": outputDigest,
	}
	seen := map[string]bool{}
	for _, record := range records {
		kind := ""
		switch record.name {
		case evidence.EventSessionGranted:
			kind = "grant"
		case evidence.EventPolicyLoaded:
			kind = "policy"
		case evidence.EventWorkspaceManifested:
			kind = record.stringValue(attrWorkspacePhase)
		}
		if kind == "" {
			continue
		}
		if record.stringValue(evidence.AttrProducer) != string(evidence.ChannelController) {
			continue
		}
		if record.stringValue(evidence.AttrContentDigest) != want[kind] {
			return fmt.Errorf("trust record: %s artifact event digest mismatch", kind)
		}
		seen[kind] = true
	}
	for _, kind := range []string{"grant", "policy", "input", "output"} {
		if !seen[kind] {
			return fmt.Errorf("trust record: %s artifact event missing", kind)
		}
	}
	return nil
}

type modelKey struct {
	provider string
	modelID  string
}

type modelAccumulator struct {
	requestCount int64
	input        int64
	inputSeen    bool
	output       int64
	outputSeen   bool
	total        int64
	totalSeen    bool
}

func buildActivity(records []observedRecord) (Activity, error) {
	models := map[modelKey]*modelAccumulator{}
	requests := map[string]modelKey{}
	tools := map[string]int64{}
	transcript := make([]normalizedToolEvent, 0)
	activity := Activity{Models: []ModelActivity{}, Tools: []ToolActivity{}}
	for _, record := range records {
		switch record.name {
		case evidence.EventModelRequested:
			if !record.brokerMediated() {
				continue
			}
			key := modelKey{provider: record.stringValue(attrModelProvider), modelID: record.stringValue(attrModelID)}
			if key.provider == "" {
				continue
			}
			models[key] = modelAccumulatorFor(models, key)
			models[key].requestCount++
			activity.ModelRequestCount++
			if actionID := record.stringValue(evidence.AttrActionID); actionID != "" {
				requests[actionID] = key
			}
		case evidence.EventModelCompleted:
			if !record.brokerMediated() {
				continue
			}
			key := modelKey{provider: record.stringValue(attrModelProvider), modelID: record.stringValue(attrModelID)}
			if requested, ok := requests[record.stringValue(evidence.AttrActionID)]; ok {
				if key.provider != "" && key.provider != requested.provider {
					return Activity{}, fmt.Errorf("trust record: model completion provider differs from request")
				}
				if key.modelID != "" && key.modelID != requested.modelID {
					return Activity{}, fmt.Errorf("trust record: model completion id differs from request")
				}
				key = requested
			}
			if key.provider != "" {
				accumulator := modelAccumulatorFor(models, key)
				models[key] = accumulator
				if err := addObservedUsage(record, accumulator); err != nil {
					return Activity{}, err
				}
			}
		case evidence.EventInternalToolDispatched:
			if !record.brokerMediated() {
				continue
			}
			activity.ToolTranscript.CallCount++
			if name := record.stringValue(attrToolName); name != "" {
				tools[name]++
			}
		case evidence.EventEffectDispatched:
			if !record.brokerMediated() {
				continue
			}
			activity.EffectDispatchCount++
			activity.ToolTranscript.CallCount++
		case evidence.EventNetworkDenied:
			if record.guestKernelObserved() {
				activity.NetworkDenialCount++
			}
		}
		if record.brokerMediated() && isToolTranscriptEvent(record.name) {
			transcript = append(transcript, normalizedToolEvent{
				Sequence:        record.sequence,
				Event:           record.name,
				ActionID:        record.stringValue(evidence.AttrActionID),
				ParentActionID:  record.stringValue(evidence.AttrParentActionID),
				Outcome:         record.stringValue(evidence.AttrOutcome),
				ContentDigest:   record.stringValue(evidence.AttrContentDigest),
				ToolName:        record.stringValue(attrToolName),
				ToolOperation:   record.stringValue(attrToolOperation),
				EffectAdapter:   record.stringValue(attrEffectAdapter),
				EffectOperation: record.stringValue(attrEffectOperation),
			})
		}
	}

	keys := make([]modelKey, 0, len(models))
	for key := range models {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].provider == keys[j].provider {
			return keys[i].modelID < keys[j].modelID
		}
		return keys[i].provider < keys[j].provider
	})
	for _, key := range keys {
		accumulator := models[key]
		model := ModelActivity{Provider: key.provider, ModelID: key.modelID, RequestCount: accumulator.requestCount}
		if accumulator.inputSeen || accumulator.outputSeen || accumulator.totalSeen {
			model.Usage = &TokenUsage{}
			if accumulator.inputSeen {
				value := accumulator.input
				model.Usage.InputTokens = &value
			}
			if accumulator.outputSeen {
				value := accumulator.output
				model.Usage.OutputTokens = &value
			}
			if accumulator.totalSeen {
				value := accumulator.total
				model.Usage.TotalTokens = &value
			}
		}
		activity.Models = append(activity.Models, model)
	}
	toolNames := make([]string, 0, len(tools))
	for name := range tools {
		toolNames = append(toolNames, name)
	}
	sort.Strings(toolNames)
	for _, name := range toolNames {
		activity.Tools = append(activity.Tools, ToolActivity{Name: name, CallCount: tools[name]})
	}
	rawTranscript, err := json.Marshal(transcript)
	if err != nil {
		return Activity{}, fmt.Errorf("trust record: marshal tool transcript: %w", err)
	}
	canonicalTranscript, err := jcs.Transform(rawTranscript)
	if err != nil {
		return Activity{}, fmt.Errorf("trust record: canonicalize tool transcript: %w", err)
	}
	activity.ToolTranscript.Schema = ToolTranscriptEventVersion
	activity.ToolTranscript.Canonicalization = CanonicalizationRFC8785
	activity.ToolTranscript.Digest = evidence.SHA256Hex(canonicalTranscript)
	activity.ToolTranscript.EventCount = int64(len(transcript))
	return activity, nil
}

func modelAccumulatorFor(models map[modelKey]*modelAccumulator, key modelKey) *modelAccumulator {
	if models[key] == nil {
		models[key] = &modelAccumulator{}
	}
	return models[key]
}

func addObservedUsage(record observedRecord, accumulator *modelAccumulator) error {
	values := []struct {
		key  string
		sum  *int64
		seen *bool
	}{
		{attrUsageInput, &accumulator.input, &accumulator.inputSeen},
		{attrUsageOutput, &accumulator.output, &accumulator.outputSeen},
		{attrUsageTotal, &accumulator.total, &accumulator.totalSeen},
	}
	for _, value := range values {
		observed, ok, err := record.int64Value(value.key)
		if err != nil {
			return err
		}
		if ok {
			if observed < 0 {
				return fmt.Errorf("trust record: negative observed token usage %s", value.key)
			}
			if observed > MaxSafeInteger-*value.sum {
				return fmt.Errorf("trust record: observed token usage %s exceeds the RFC 8785 safe-integer range", value.key)
			}
			*value.sum += observed
			*value.seen = true
		}
	}
	return nil
}

func isToolTranscriptEvent(name string) bool {
	switch name {
	case evidence.EventAuthorizationDecided,
		evidence.EventInternalToolDispatched,
		evidence.EventInternalToolCompleted,
		evidence.EventInternalToolFailed,
		evidence.EventEffectRequested,
		evidence.EventEffectApproved,
		evidence.EventEffectDenied,
		evidence.EventEffectDispatched,
		evidence.EventEffectCompleted,
		evidence.EventEffectFailed:
		return true
	default:
		return false
	}
}
