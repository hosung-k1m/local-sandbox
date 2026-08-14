package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"boxedai/internal/trustrecord"
)

func writeTrustRecordFixture(t *testing.T) (recordPath, keyPath string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := "sha256:" + strings.Repeat("1", 64)
	record := trustrecord.Record{
		Schema:   trustrecord.Profile,
		IssuedAt: "2026-08-13T03:00:02Z",
		Session: trustrecord.Session{
			ID: "bx-20260813-030000-abcdef01", TraceID: strings.Repeat("1", 32), Harness: "exec", CreatedAt: "2026-08-13T03:00:00Z",
		},
		Runtime: trustrecord.Runtime{
			Platform: trustrecord.RuntimePlatformSoftware, Isolation: trustrecord.RuntimeIsolationLima,
			Image: trustrecord.RuntimeImage{Name: "boxedai-base-test", Digest: digest},
		},
		Origin: trustrecord.Origin{Kind: trustrecord.OriginHostControlPlane, Producer: trustrecord.OriginProducerRecorder},
		Policy: trustrecord.Policy{Profile: "develop", Digest: digest},
		Artifacts: trustrecord.Artifacts{
			SessionGrantDigest: digest, PolicyDigest: digest, InputManifestDigest: digest, OutputManifestDigest: digest,
		},
		Evidence: trustrecord.Evidence{
			Schema: trustrecord.EvidenceProfile, SegmentCount: 1, RecordCount: 2, FirstSequence: 1, LastSequence: 2, ChainTip: digest,
			Segments: []trustrecord.Segment{{Number: 1, SegmentDigest: digest, ManifestDigest: digest, FirstSequence: 1, LastSequence: 2, RecordCount: 2, SealedAt: "2026-08-13T03:00:01Z"}},
		},
		Activity: trustrecord.Activity{
			Models:            []trustrecord.ModelActivity{{Provider: "openai", ModelID: "gpt-test", RequestCount: 2}},
			ModelRequestCount: 2,
			Tools:             []trustrecord.ToolActivity{{Name: "github/repo_view", CallCount: 1}},
			ToolTranscript:    trustrecord.ToolTranscript{Schema: trustrecord.ToolTranscriptEventVersion, Canonicalization: trustrecord.CanonicalizationRFC8785, Digest: digest, EventCount: 1, CallCount: 1},
		},
		Assurance: trustrecord.Assurance{Level: 0, VerdictCeiling: trustrecord.AssuranceVerdictLocalOnly},
		Signing:   trustrecord.Signing{Algorithm: trustrecord.SignatureAlgorithmEd25519, Canonicalization: trustrecord.CanonicalizationRFC8785, RecorderKeyFingerprint: trustrecord.PublicKeyFingerprint(publicKey)},
	}
	if err := trustrecord.Sign(&record, privateKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	dir := t.TempDir()
	recordPath = filepath.Join(dir, trustrecord.FileName)
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal record: %v", err)
	}
	if err := os.WriteFile(recordPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile record: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	keyPath = filepath.Join(dir, "recorder-public-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	return recordPath, keyPath
}

func TestVerifyRecordJSONReportsPortableClaims(t *testing.T) {
	recordPath, keyPath := writeTrustRecordFixture(t)
	root := newRootCmd()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"verify-record", recordPath, "--public-key", keyPath, "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("verify-record: %v", err)
	}
	var report trustRecordReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("JSON output = %q: %v", output.String(), err)
	}
	if report.Profile != trustrecord.Profile || !report.Signature.Valid {
		t.Fatalf("report profile/signature = %+v", report)
	}
	if report.Scope != "envelope-only" || report.SessionID == "" || report.ClaimsRederived {
		t.Fatalf("report scope/session = %+v", report)
	}
	if report.Assurance.Description != "Level 0 (software-only)" || report.Assurance.VerdictCeiling != trustrecord.AssuranceVerdictLocalOnly {
		t.Fatalf("assurance = %+v", report.Assurance)
	}
	if report.SegmentCount != 1 || report.RecordCount != 2 || report.ChainTip == "" {
		t.Fatalf("evidence summary = %+v", report)
	}
	if len(report.Models) != 1 || len(report.Tools) != 1 || report.TranscriptDigest == "" {
		t.Fatalf("activity summary = %+v", report)
	}
}

func TestVerifyRecordTextReportsClaims(t *testing.T) {
	recordPath, keyPath := writeTrustRecordFixture(t)
	root := newRootCmd()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"verify-record", recordPath, "--public-key", keyPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("verify-record: %v", err)
	}
	for _, want := range []string{"Scope:              envelope only; claims not rederived", "Session:            bx-", "Profile:            " + trustrecord.Profile, "Signature:          valid", "Assurance:          Level 0 (software-only)", "1 segments; 2 records", "Chain tip:", "Models:", "Tools:", "Transcript digest:"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("text output missing %q:\n%s", want, output.String())
		}
	}
}

func TestVerifyRecordRequiresPKIXEd25519Key(t *testing.T) {
	recordPath, _ := writeTrustRecordFixture(t)
	root := newRootCmd()
	root.SetArgs([]string{"verify-record", recordPath})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "required --public-key flag is missing") {
		t.Fatalf("verify-record error = %v, want required public-key flag", err)
	}
}

func TestVerifyRecordPinsProfileBeforeLoadingKey(t *testing.T) {
	recordPath, _ := writeTrustRecordFixture(t)
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	data = bytes.Replace(data, []byte(trustrecord.Profile), []byte("boxedai.trust-record/x1"), 1)
	if err := os.WriteFile(recordPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	root := newRootCmd()
	root.SetArgs([]string{"verify-record", recordPath, "--public-key", filepath.Join(t.TempDir(), "missing.pem")})
	err = root.Execute()
	if err == nil || !strings.Contains(err.Error(), "unsupported profile") || strings.Contains(err.Error(), "read public key") {
		t.Fatalf("verify-record error = %v, want profile failure before key loading", err)
	}
}
