package verify

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"boxedai/internal/evidence"
	"boxedai/internal/trustrecord"

	"github.com/gowebpki/jcs"
)

const (
	sessionGrantV1  = "boxedai.session/v1"
	sessionGrantV2  = "boxedai.session/v2"
	stepGrantRecord = "session-grant-binding"
	stepTrustRecord = "session-trust-record"
)

type trustRecordResult struct {
	status         string
	profile        string
	assurance      string
	signatureValid bool
	crossDerived   bool
	detail         string
	tamper         bool
	incomplete     bool
}

func isBrokerMediatedRecord(observed record) bool {
	return observed.str(evidence.AttrProducer) == string(evidence.ChannelBroker) &&
		observed.str(evidence.AttrEvidenceClass) == string(evidence.ClassBrokerMediated)
}

func isGuestKernelRecord(observed record) bool {
	return observed.str(evidence.AttrProducer) == string(evidence.ChannelGuestSupervisor) &&
		observed.str(evidence.AttrEvidenceClass) == string(evidence.ClassKernelObserved)
}

func isGuestIntegrityRecord(observed record) bool {
	return observed.str(evidence.AttrProducer) == string(evidence.ChannelGuestSupervisor) &&
		observed.str(evidence.AttrEvidenceClass) == string(evidence.ClassIntegrity)
}

func checkSessionGrantBinding(sessionDir string, g grant, records []record) (bool, string) {
	if g.Schema != sessionGrantV1 && g.Schema != sessionGrantV2 {
		return false, fmt.Sprintf("unsupported session grant schema %q", g.Schema)
	}
	digest, err := fileDigest(filepath.Join(sessionDir, "session.json"))
	if err != nil {
		return false, fmt.Sprintf("session grant unreadable: %v", err)
	}
	var recorded string
	for _, observed := range records {
		if observed.name == evidence.EventSessionGranted && observed.str(evidence.AttrProducer) == string(evidence.ChannelController) {
			recorded = observed.str(evidence.AttrContentDigest)
			break
		}
	}
	if recorded == "" {
		if g.Schema == sessionGrantV2 {
			return false, "v2 session.granted event has no grant digest"
		}
		return true, "legacy session.granted event carries no grant digest"
	}
	if recorded != digest {
		return false, fmt.Sprintf("session.json digest %s != recorded %s", digest, recorded)
	}
	return true, "session.json exact-byte digest matches session.granted"
}

func checkTrustRecord(sessionDir string, g grant, publicKey ed25519.PublicKey, segs []segFiles, manifests []segmentManifest, records []record) trustRecordResult {
	if g.Schema != sessionGrantV1 && g.Schema != sessionGrantV2 {
		return trustRecordResult{status: "unsupported_grant_schema", detail: fmt.Sprintf("unsupported session grant schema %q", g.Schema), incomplete: true}
	}
	path := filepath.Join(sessionDir, trustrecord.FileName)
	required := g.Schema == sessionGrantV2
	markerValid := g.TrustRecord.Schema == trustrecord.Profile && g.TrustRecord.Path == trustrecord.FileName && g.TrustRecord.Required
	if !fileExists(path) {
		if required {
			detail := "v2 session requires trust-record.json, but it is missing"
			if !markerValid {
				detail = "v2 session has an invalid required trust-record marker and no trust-record.json"
			}
			return trustRecordResult{status: "missing_required", profile: trustrecord.Profile, detail: detail, incomplete: true}
		}
		return trustRecordResult{status: "absent_legacy", detail: "legacy v1 session has no required trust record"}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return trustRecordResult{status: "invalid", detail: fmt.Sprintf("read trust-record.json: %v", err), tamper: true}
	}
	verified, err := trustrecord.VerifyEnvelope(data, publicKey)
	if err != nil {
		if errors.Is(err, trustrecord.ErrUnsupportedProfile) {
			return trustRecordResult{status: "unsupported_profile", detail: err.Error(), incomplete: true}
		}
		return trustRecordResult{status: "invalid", profile: trustrecord.Profile, detail: err.Error(), tamper: true}
	}
	result := trustRecordResult{
		status:         "verified",
		profile:        verified.Schema,
		assurance:      "Level 0 (software-only)",
		signatureValid: true,
	}
	if required && !markerValid {
		result.status = "invalid_required_marker"
		result.detail = "trust record is valid, but the v2 grant marker is not the required canonical descriptor"
		result.incomplete = true
	}
	problems := rederiveTrustRecord(sessionDir, g, verified, segs, manifests, records)
	if len(problems) > 0 {
		result.status = "claim_mismatch"
		result.detail = joinStrings(problems)
		result.tamper = true
		return result
	}
	result.crossDerived = true
	if result.detail == "" {
		result.detail = "RFC 8785 Ed25519 signature valid; every claim rederived from sealed session evidence"
	}
	return result
}

func rederiveTrustRecord(sessionDir string, g grant, signed trustrecord.Record, segs []segFiles, manifests []segmentManifest, records []record) []string {
	var problems []string
	source := (*trustrecord.Source)(nil)
	if g.Repository != "" || g.Branch != "" || g.Commit != "" {
		source = &trustrecord.Source{Repository: g.Repository, Branch: g.Branch, Commit: g.Commit}
	}
	expectedSession := trustrecord.Session{ID: g.SessionID, TraceID: g.TraceID, Harness: g.Harness, CreatedAt: g.CreatedAt}
	expectedRuntime := trustrecord.Runtime{
		Platform:  trustrecord.RuntimePlatformSoftware,
		Isolation: trustrecord.RuntimeIsolationLima,
		Image:     trustrecord.RuntimeImage{Name: g.VMImage, Digest: g.VMImageDigest},
	}
	// Mirrors trustrecord/build.go's embedding: build.go copies grant.HumanAccess onto
	// the record's runtime verbatim (nil for a non-mediated session), so the expected
	// side must carry the same grant-derived value or every mediated session's runtime
	// claim would mismatch regardless of tampering.
	expectedRuntime.HumanAccess = g.HumanAccess
	expectedPolicy := trustrecord.Policy{Profile: g.Profile, Digest: g.PolicyDigest}
	compareTrustClaim(&problems, "session", signed.Session, expectedSession)
	compareTrustClaim(&problems, "source", signed.Source, source)
	compareTrustClaim(&problems, "runtime", signed.Runtime, expectedRuntime)
	compareTrustClaim(&problems, "origin", signed.Origin, trustrecord.Origin{Kind: trustrecord.OriginHostControlPlane, Producer: trustrecord.OriginProducerRecorder})
	compareTrustClaim(&problems, "policy", signed.Policy, expectedPolicy)
	compareTrustClaim(&problems, "assurance", signed.Assurance, trustrecord.Assurance{Level: 0, VerdictCeiling: trustrecord.AssuranceVerdictLocalOnly})

	artifacts, err := deriveArtifacts(sessionDir)
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		if artifacts.PolicyDigest != g.PolicyDigest {
			problems = append(problems, "policy.json digest does not match session grant")
		}
		if artifacts.InputManifestDigest != g.InputManifestDigest {
			problems = append(problems, "input-manifest.json digest does not match session grant")
		}
		compareTrustClaim(&problems, "artifacts", signed.Artifacts, artifacts)
		if ok, detail := checkArtifactEventBindings(records, artifacts); !ok {
			problems = append(problems, detail)
		}
	}
	evidenceClaim, err := deriveEvidenceClaim(g, segs, manifests, records)
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		compareTrustClaim(&problems, "evidence", signed.Evidence, evidenceClaim)
	}
	activity, err := deriveActivityClaim(records)
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		compareTrustClaim(&problems, "activity", signed.Activity, activity)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, signed.IssuedAt)
	if err != nil {
		problems = append(problems, fmt.Sprintf("issued_at is invalid: %v", err))
	} else {
		for _, manifest := range manifests {
			sealedAt, parseErr := time.Parse(time.RFC3339Nano, manifest.SealedAt)
			if parseErr != nil {
				problems = append(problems, fmt.Sprintf("segment %d sealed_at is invalid", manifest.SegmentNumber))
				continue
			}
			if issuedAt.Before(sealedAt) {
				problems = append(problems, fmt.Sprintf("issued_at precedes segment %d seal", manifest.SegmentNumber))
			}
		}
	}
	return problems
}

func compareTrustClaim(problems *[]string, name string, actual, expected any) {
	if !reflect.DeepEqual(actual, expected) {
		*problems = append(*problems, name+" claim does not match on-disk evidence")
	}
}

func deriveArtifacts(sessionDir string) (trustrecord.Artifacts, error) {
	names := []string{"session.json", "policy.json", "input-manifest.json", "output-manifest.json"}
	digests := make([]string, len(names))
	for i, name := range names {
		digest, err := fileDigest(filepath.Join(sessionDir, name))
		if err != nil {
			return trustrecord.Artifacts{}, fmt.Errorf("trust record: derive %s digest: %w", name, err)
		}
		digests[i] = digest
	}
	return trustrecord.Artifacts{
		SessionGrantDigest:   digests[0],
		PolicyDigest:         digests[1],
		InputManifestDigest:  digests[2],
		OutputManifestDigest: digests[3],
	}, nil
}

func checkArtifactEventBindings(records []record, artifacts trustrecord.Artifacts) (bool, string) {
	want := map[string]string{
		"grant":  artifacts.SessionGrantDigest,
		"policy": artifacts.PolicyDigest,
		"input":  artifacts.InputManifestDigest,
		"output": artifacts.OutputManifestDigest,
	}
	seen := map[string]bool{}
	for _, observed := range records {
		kind := ""
		switch observed.name {
		case evidence.EventSessionGranted:
			kind = "grant"
		case evidence.EventPolicyLoaded:
			kind = "policy"
		case evidence.EventWorkspaceManifested:
			kind = observed.str("workspace.phase")
		}
		if kind == "" {
			continue
		}
		if observed.str(evidence.AttrProducer) != string(evidence.ChannelController) {
			continue
		}
		expected, known := want[kind]
		if !known || observed.str(evidence.AttrContentDigest) != expected {
			return false, fmt.Sprintf("%s artifact event digest does not match exact on-disk bytes", kind)
		}
		seen[kind] = true
	}
	for _, kind := range []string{"grant", "policy", "input", "output"} {
		if !seen[kind] {
			return false, kind + " artifact event is missing"
		}
	}
	return true, "artifact events match exact on-disk bytes"
}

func deriveEvidenceClaim(g grant, segs []segFiles, manifests []segmentManifest, records []record) (trustrecord.Evidence, error) {
	if len(segs) == 0 || len(segs) != len(manifests) {
		return trustrecord.Evidence{}, fmt.Errorf("trust record: sealed segment set is incomplete")
	}
	if len(records) == 0 {
		return trustrecord.Evidence{}, fmt.Errorf("trust record: no evidence records")
	}
	claim := trustrecord.Evidence{
		Schema:        trustrecord.EvidenceProfile,
		SegmentCount:  len(segs),
		FirstSequence: records[0].seq,
		LastSequence:  records[len(records)-1].seq,
	}
	mechanisms := map[string]struct{}{}
	var observedLosses, observedRestarts int64
	for _, observed := range records {
		if (observed.name == evidence.EventSensorStarted || observed.name == evidence.EventSensorRestarted) && isGuestIntegrityRecord(observed) {
			if mechanism := observed.str("sensor.mechanism"); mechanism != "" {
				mechanisms[mechanism] = struct{}{}
			}
		}
		if !isGuestIntegrityRecord(observed) {
			continue
		}
		switch observed.name {
		case evidence.EventSensorLoss:
			observedLosses++
		case evidence.EventSensorRestarted:
			observedRestarts++
		}
	}
	for mechanism := range mechanisms {
		claim.SensorMechanisms = append(claim.SensorMechanisms, mechanism)
	}
	sort.Strings(claim.SensorMechanisms)
	previousDigest := ""
	recordOffset := 0
	for i, manifest := range manifests {
		if segs[i].manifest == "" || manifest.Schema != "boxedai.segment/v1" || manifest.SessionID != g.SessionID || manifest.PolicyDigest != g.PolicyDigest {
			return trustrecord.Evidence{}, fmt.Errorf("trust record: segment %d manifest schema, session, or policy binding mismatch", i+1)
		}
		if manifest.SegmentNumber != i+1 || manifest.SegmentNumber != segs[i].number || manifest.PrevSegmentDigest != previousDigest {
			return trustrecord.Evidence{}, fmt.Errorf("trust record: segment manifest ordering mismatch")
		}
		segmentDigest, err := fileDigest(segs[i].otlp)
		if err != nil {
			return trustrecord.Evidence{}, err
		}
		if manifest.SegmentDigest != segmentDigest {
			return trustrecord.Evidence{}, fmt.Errorf("trust record: segment %d digest does not match exact OTLP bytes", manifest.SegmentNumber)
		}
		if manifest.RecordCount < 1 || recordOffset > len(records) || manifest.RecordCount > len(records)-recordOffset {
			return trustrecord.Evidence{}, fmt.Errorf("trust record: segment %d record count does not match OTLP records", manifest.SegmentNumber)
		}
		segmentRecords := records[recordOffset : recordOffset+manifest.RecordCount]
		if segmentRecords[0].seq != manifest.FirstSequence || segmentRecords[len(segmentRecords)-1].seq != manifest.LastSequence {
			return trustrecord.Evidence{}, fmt.Errorf("trust record: segment %d sequence range does not match OTLP records", manifest.SegmentNumber)
		}
		for j, observed := range segmentRecords {
			wantSequence := int64(recordOffset + j + 1)
			if observed.seg != i || observed.seq != wantSequence {
				return trustrecord.Evidence{}, fmt.Errorf("trust record: event %d is not in exact segment and sequence order", observed.seq)
			}
			if observed.traceID != g.TraceID || observed.str(evidence.AttrSchemaVersion) != evidence.SchemaVersion || observed.str(evidence.AttrSessionID) != g.SessionID || observed.str(evidence.AttrPolicyDigest) != g.PolicyDigest {
				return trustrecord.Evidence{}, fmt.Errorf("trust record: event %d trace, schema, session, or policy binding mismatch", observed.seq)
			}
		}
		manifestDigest, err := fileDigest(segs[i].manifest)
		if err != nil {
			return trustrecord.Evidence{}, err
		}
		claim.RecordCount += int64(manifest.RecordCount)
		claim.Segments = append(claim.Segments, trustrecord.Segment{
			Number:         manifest.SegmentNumber,
			SegmentDigest:  manifest.SegmentDigest,
			ManifestDigest: manifestDigest,
			FirstSequence:  manifest.FirstSequence,
			LastSequence:   manifest.LastSequence,
			RecordCount:    int64(manifest.RecordCount),
			SealedAt:       manifest.SealedAt,
		})
		recordOffset += manifest.RecordCount
		previousDigest = manifest.SegmentDigest
	}
	claim.ChainTip = previousDigest
	if recordOffset != len(records) || claim.RecordCount != int64(len(records)) {
		return trustrecord.Evidence{}, fmt.Errorf("trust record: manifest record total does not match OTLP records")
	}
	claim.SensorLossCount = observedLosses
	claim.SensorRestartCount = observedRestarts
	return claim, nil
}

type verifyModelKey struct {
	provider string
	modelID  string
}

type verifyModelAccumulator struct {
	requestCount int64
	input        int64
	inputSeen    bool
	output       int64
	outputSeen   bool
	total        int64
	totalSeen    bool
}

type verifyTranscriptEvent struct {
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

func deriveActivityClaim(records []record) (trustrecord.Activity, error) {
	models := map[verifyModelKey]*verifyModelAccumulator{}
	requests := map[string]verifyModelKey{}
	tools := map[string]int64{}
	transcript := make([]verifyTranscriptEvent, 0)
	activity := trustrecord.Activity{Models: []trustrecord.ModelActivity{}, Tools: []trustrecord.ToolActivity{}}
	for _, observed := range records {
		switch observed.name {
		case evidence.EventModelRequested:
			if !isBrokerMediatedRecord(observed) {
				continue
			}
			key := verifyModelKey{provider: observed.str("model.provider"), modelID: observed.str("model.id")}
			if key.provider != "" {
				accumulator := verifyModelAccumulatorFor(models, key)
				accumulator.requestCount++
				activity.ModelRequestCount++
				if actionID := observed.str(evidence.AttrActionID); actionID != "" {
					requests[actionID] = key
				}
			}
		case evidence.EventModelCompleted:
			if !isBrokerMediatedRecord(observed) {
				continue
			}
			key := verifyModelKey{provider: observed.str("model.provider"), modelID: observed.str("model.id")}
			if requested, ok := requests[observed.str(evidence.AttrActionID)]; ok {
				if key.provider != "" && key.provider != requested.provider {
					return trustrecord.Activity{}, fmt.Errorf("trust record: model completion provider differs from request")
				}
				if key.modelID != "" && key.modelID != requested.modelID {
					return trustrecord.Activity{}, fmt.Errorf("trust record: model completion id differs from request")
				}
				key = requested
			}
			if key.provider != "" {
				if err := addVerifyUsage(observed, verifyModelAccumulatorFor(models, key)); err != nil {
					return trustrecord.Activity{}, err
				}
			}
		case evidence.EventInternalToolDispatched:
			if !isBrokerMediatedRecord(observed) {
				continue
			}
			activity.ToolTranscript.CallCount++
			if name := observed.str("tool.name"); name != "" {
				tools[name]++
			}
		case evidence.EventEffectDispatched:
			if !isBrokerMediatedRecord(observed) {
				continue
			}
			activity.EffectDispatchCount++
			activity.ToolTranscript.CallCount++
		case evidence.EventNetworkDenied:
			if isGuestKernelRecord(observed) {
				activity.NetworkDenialCount++
			}
		}
		if isBrokerMediatedRecord(observed) && verifyToolTranscriptEvent(observed.name) {
			transcript = append(transcript, verifyTranscriptEvent{
				Sequence:        observed.seq,
				Event:           observed.name,
				ActionID:        observed.str(evidence.AttrActionID),
				ParentActionID:  observed.str(evidence.AttrParentActionID),
				Outcome:         observed.str(evidence.AttrOutcome),
				ContentDigest:   observed.str(evidence.AttrContentDigest),
				ToolName:        observed.str("tool.name"),
				ToolOperation:   observed.str("tool.op"),
				EffectAdapter:   observed.str("effect.adapter"),
				EffectOperation: observed.str("effect.op"),
			})
		}
	}
	keys := make([]verifyModelKey, 0, len(models))
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
		model := trustrecord.ModelActivity{Provider: key.provider, ModelID: key.modelID, RequestCount: accumulator.requestCount}
		if accumulator.inputSeen || accumulator.outputSeen || accumulator.totalSeen {
			model.Usage = &trustrecord.TokenUsage{}
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
		activity.Tools = append(activity.Tools, trustrecord.ToolActivity{Name: name, CallCount: tools[name]})
	}
	raw, err := json.Marshal(transcript)
	if err != nil {
		return trustrecord.Activity{}, err
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return trustrecord.Activity{}, err
	}
	activity.ToolTranscript.Schema = trustrecord.ToolTranscriptEventVersion
	activity.ToolTranscript.Canonicalization = trustrecord.CanonicalizationRFC8785
	activity.ToolTranscript.Digest = evidence.SHA256Hex(canonical)
	activity.ToolTranscript.EventCount = int64(len(transcript))
	return activity, nil
}

func verifyModelAccumulatorFor(models map[verifyModelKey]*verifyModelAccumulator, key verifyModelKey) *verifyModelAccumulator {
	if models[key] == nil {
		models[key] = &verifyModelAccumulator{}
	}
	return models[key]
}

func addVerifyUsage(observed record, accumulator *verifyModelAccumulator) error {
	values := []struct {
		key  string
		sum  *int64
		seen *bool
	}{
		{"llm.usage.input_tokens", &accumulator.input, &accumulator.inputSeen},
		{"llm.usage.output_tokens", &accumulator.output, &accumulator.outputSeen},
		{"llm.usage.total_tokens", &accumulator.total, &accumulator.totalSeen},
	}
	for _, value := range values {
		tokenCount, ok, err := recordInt64(observed, value.key)
		if err != nil {
			return err
		}
		if ok {
			if tokenCount < 0 {
				return fmt.Errorf("trust record: negative observed token usage %s", value.key)
			}
			if tokenCount > trustrecord.MaxSafeInteger-*value.sum {
				return fmt.Errorf("trust record: observed token usage %s exceeds the RFC 8785 safe-integer range", value.key)
			}
			*value.sum += tokenCount
			*value.seen = true
		}
	}
	return nil
}

func recordInt64(observed record, key string) (int64, bool, error) {
	switch value := observed.attrs[key].(type) {
	case int64:
		if value > trustrecord.MaxSafeInteger || value < -trustrecord.MaxSafeInteger {
			return 0, false, fmt.Errorf("trust record: observed %s is outside the RFC 8785 safe-integer range", key)
		}
		return value, true, nil
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value > float64(trustrecord.MaxSafeInteger) || value < -float64(trustrecord.MaxSafeInteger) {
			return 0, false, fmt.Errorf("trust record: observed %s is not a safe integer", key)
		}
		return int64(value), true, nil
	default:
		return 0, false, nil
	}
}

func verifyToolTranscriptEvent(name string) bool {
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
