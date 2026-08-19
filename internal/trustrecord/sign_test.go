package trustrecord

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"boxedai/internal/evidence"
)

func validRecord(publicKey ed25519.PublicKey) Record {
	digest := "sha256:" + strings.Repeat("1", 64)
	return Record{
		Schema:   Profile,
		IssuedAt: "2026-08-13T03:00:02Z",
		Session: Session{
			ID:        "bx-20260813-030000-abcdef01",
			TraceID:   "11111111111111111111111111111111",
			Harness:   "exec",
			CreatedAt: "2026-08-13T03:00:00Z",
		},
		Runtime: Runtime{
			Platform:  RuntimePlatformSoftware,
			Isolation: RuntimeIsolationLima,
			Image:     RuntimeImage{Name: "boxedai-base-test", Digest: digest},
		},
		Origin: Origin{Kind: OriginHostControlPlane, Producer: OriginProducerRecorder},
		Policy: Policy{Profile: "develop", Digest: digest},
		Artifacts: Artifacts{
			SessionGrantDigest:   digest,
			PolicyDigest:         digest,
			InputManifestDigest:  digest,
			OutputManifestDigest: digest,
		},
		Evidence: Evidence{
			Schema:        EvidenceProfile,
			SegmentCount:  1,
			RecordCount:   2,
			FirstSequence: 1,
			LastSequence:  2,
			ChainTip:      digest,
			Segments: []Segment{{
				Number:         1,
				SegmentDigest:  digest,
				ManifestDigest: digest,
				FirstSequence:  1,
				LastSequence:   2,
				RecordCount:    2,
				SealedAt:       "2026-08-13T03:00:01Z",
			}},
		},
		Activity: Activity{
			Models: []ModelActivity{},
			Tools:  []ToolActivity{},
			ToolTranscript: ToolTranscript{
				Schema:           ToolTranscriptEventVersion,
				Canonicalization: CanonicalizationRFC8785,
				Digest:           digest,
			},
		},
		Assurance: Assurance{Level: 0, VerdictCeiling: AssuranceVerdictLocalOnly},
		Signing: Signing{
			Algorithm:              SignatureAlgorithmEd25519,
			Canonicalization:       CanonicalizationRFC8785,
			RecorderKeyFingerprint: PublicKeyFingerprint(publicKey),
		},
	}
}

func TestSignAndVerifyEnvelopeUsesCallerKeyAndJCS(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := validRecord(publicKey)
	if err := Sign(&record, privateKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	indented, err := json.MarshalIndent(record, "", "    ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	verified, err := VerifyEnvelope(indented, publicKey)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if verified.Signature != record.Signature {
		t.Errorf("signature changed after verification")
	}
}

func TestTrustRecordBindsSealedHumanAccessContract(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := validRecord(publicKey)
	record.Runtime.HumanAccess = &evidence.HumanAccessBinding{
		Runtime: evidence.RuntimeCapabilityState{
			WriteThroughLowerMount: true,
			PrivateLowerMount:      true,
			SetfsuidProbe:          true,
			WritebackCacheDisabled: true,
			PrivilegedFUSE:         true,
			MediatedWriteOpen:      true,
			HostReDerivation:       true,
			UIDSeparation:          true,
		},
		SubjectMap: evidence.SessionSubjectMap{
			SessionID: record.Session.ID,
			Subjects: []evidence.SessionSubject{
				{UID: evidence.WorkloadUID, ActorClass: evidence.MutationActorAgent},
				{UID: evidence.HumanUID, ActorClass: evidence.MutationActorHuman, SubjectID: "operator-1", GrantID: "grant-1"},
			},
		},
		Grant: evidence.HumanAccessGrant{
			SessionID:        record.Session.ID,
			GrantID:          "grant-1",
			SubjectID:        "operator-1",
			ExpiresAt:        time.Date(2026, time.August, 18, 12, 30, 0, 0, time.UTC),
			AllowedSurfaces:  []evidence.AccessSurface{evidence.AccessSurfaceBrowserTerminal},
			UID:              evidence.HumanUID,
			CredentialDigest: "sha256:" + strings.Repeat("2", 64),
		},
	}
	if err := Sign(&record, privateKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := VerifyEnvelope(data, publicKey); err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
}

func TestVerifyEnvelopeRejectsDifferentCallerKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := validRecord(publicKey)
	if err := Sign(&record, privateKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	differentKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey different key: %v", err)
	}
	if _, err := VerifyEnvelope(data, differentKey); err == nil || !strings.Contains(err.Error(), "does not match supplied key") {
		t.Fatalf("VerifyEnvelope error = %v, want caller-key mismatch", err)
	}
}

func TestSignRejectsUnsortedObservedClaims(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := validRecord(publicKey)
	record.Evidence.SensorMechanisms = []string{"tetragon", "procfs"}
	if err := Sign(&record, privateKey); err == nil || !strings.Contains(err.Error(), "sensor_mechanisms must be sorted") {
		t.Fatalf("Sign error = %v, want sorted sensor mechanism failure", err)
	}
}

func TestSignRejectsMismatchedPrivateKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, differentPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey different key: %v", err)
	}
	record := validRecord(publicKey)
	if err := Sign(&record, differentPrivateKey); err == nil || !strings.Contains(err.Error(), "does not match recorder key fingerprint") {
		t.Fatalf("Sign error = %v, want signing-key mismatch", err)
	}
}

func TestSignRejectsIntegersOutsideJCSSafeRange(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := validRecord(publicKey)
	record.Evidence.RecordCount = MaxSafeInteger + 1
	if err := Sign(&record, privateKey); err == nil || !strings.Contains(err.Error(), "schema validation") {
		t.Fatalf("Sign error = %v, want safe-integer schema failure", err)
	}
}

func TestValidateSemanticsRejectsAggregateOutsideJCSSafeRange(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := validRecord(publicKey)
	record.Activity.Models = []ModelActivity{
		{Provider: "a", RequestCount: MaxSafeInteger},
		{Provider: "b", RequestCount: MaxSafeInteger},
	}
	record.Activity.ModelRequestCount = MaxSafeInteger
	if err := ValidateSemantics(record); err == nil || !strings.Contains(err.Error(), "model request total exceeds") {
		t.Fatalf("ValidateSemantics error = %v, want aggregate safe-integer failure", err)
	}
}

func TestVerifyEnvelopeRejectsNonCanonicalBase64PadBits(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := validRecord(publicKey)
	if err := Sign(&record, privateKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, record.Signature[len(record.Signature)-1])
	if last < 0 || last%16 != 0 {
		t.Fatalf("unexpected final base64url character %q", record.Signature[len(record.Signature)-1])
	}
	record.Signature = record.Signature[:len(record.Signature)-1] + string(alphabet[last+1])
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := VerifyEnvelope(data, publicKey); err == nil || !strings.Contains(err.Error(), "decode signature") {
		t.Fatalf("VerifyEnvelope error = %v, want strict base64url failure", err)
	}
}

func TestVerifyEnvelopeRejectsDuplicateJSONMembers(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	record := validRecord(publicKey)
	if err := Sign(&record, privateKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	duplicate := append([]byte(`{"schema":"boxedai.trust-record/unsupported",`), data[1:]...)
	if _, err := VerifyEnvelope(duplicate, publicKey); err == nil {
		t.Fatal("VerifyEnvelope accepted duplicate schema members")
	}
}
