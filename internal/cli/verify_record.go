package cli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"boxedai/internal/trustrecord"
)

type trustRecordReport struct {
	Scope            string                      `json:"scope"`
	SessionID        string                      `json:"session_id"`
	ClaimsRederived  bool                        `json:"claims_rederived"`
	Profile          string                      `json:"profile"`
	Signature        trustRecordSignatureReport  `json:"signature"`
	Assurance        trustRecordAssuranceReport  `json:"assurance"`
	SegmentCount     int                         `json:"segment_count"`
	RecordCount      int64                       `json:"record_count"`
	ChainTip         string                      `json:"chain_tip"`
	Models           []trustrecord.ModelActivity `json:"models"`
	Tools            []trustrecord.ToolActivity  `json:"tools"`
	TranscriptDigest string                      `json:"transcript_digest"`
}

type trustRecordSignatureReport struct {
	Valid            bool   `json:"valid"`
	Algorithm        string `json:"algorithm"`
	Canonicalization string `json:"canonicalization"`
	KeyFingerprint   string `json:"recorder_key_fingerprint"`
}

type trustRecordAssuranceReport struct {
	Level               int    `json:"level"`
	Description         string `json:"description"`
	VerdictCeiling      string `json:"verdict_ceiling"`
	HardwareAttested    bool   `json:"hardware_attested"`
	ExternallyWitnessed bool   `json:"externally_witnessed"`
}

func newVerifyRecordCmd() *cobra.Command {
	var (
		publicKeyPath string
		asJSON        bool
	)
	cmd := &cobra.Command{
		Use:   "verify-record <trust-record.json>",
		Short: "Verify a portable trust record with an external Ed25519 public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("verify-record: read trust record: %w", err)
			}
			record, err := trustrecord.Decode(data)
			if err != nil {
				return fmt.Errorf("verify-record: %w", err)
			}
			if publicKeyPath == "" {
				return fmt.Errorf("verify-record: required --public-key flag is missing")
			}
			publicKey, err := readEd25519PublicKey(publicKeyPath)
			if err != nil {
				return err
			}
			record, err = trustrecord.VerifyDecodedEnvelope(record, publicKey)
			if err != nil {
				return fmt.Errorf("verify-record: %w", err)
			}
			report := makeTrustRecordReport(record)
			if asJSON {
				enc := json.NewEncoder(c.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			writeTrustRecordReport(c.OutOrStdout(), report)
			return nil
		},
	}
	cmd.Flags().StringVar(&publicKeyPath, "public-key", "", "PKIX PEM Ed25519 recorder public key")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the verification report as JSON")
	return cmd
}

func readEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("verify-record: read public key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("verify-record: public key is not a single PKIX PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("verify-record: parse PKIX public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("verify-record: public key type is %T, want Ed25519", parsed)
	}
	return publicKey, nil
}

func makeTrustRecordReport(record trustrecord.Record) trustRecordReport {
	return trustRecordReport{
		Scope:           "envelope-only",
		SessionID:       record.Session.ID,
		ClaimsRederived: false,
		Profile:         record.Schema,
		Signature: trustRecordSignatureReport{
			Valid:            true,
			Algorithm:        record.Signing.Algorithm,
			Canonicalization: record.Signing.Canonicalization,
			KeyFingerprint:   record.Signing.RecorderKeyFingerprint,
		},
		Assurance: trustRecordAssuranceReport{
			Level:               record.Assurance.Level,
			Description:         fmt.Sprintf("Level %d (%s)", record.Assurance.Level, record.Runtime.Platform),
			VerdictCeiling:      record.Assurance.VerdictCeiling,
			HardwareAttested:    record.Assurance.HardwareAttested,
			ExternallyWitnessed: record.Assurance.ExternallyWitnessed,
		},
		SegmentCount:     record.Evidence.SegmentCount,
		RecordCount:      record.Evidence.RecordCount,
		ChainTip:         record.Evidence.ChainTip,
		Models:           record.Activity.Models,
		Tools:            record.Activity.Tools,
		TranscriptDigest: record.Activity.ToolTranscript.Digest,
	}
}

func writeTrustRecordReport(w io.Writer, report trustRecordReport) {
	fmt.Fprintf(w, "Scope:              envelope only; claims not rederived from session evidence\n")
	fmt.Fprintf(w, "Session:            %s\n", report.SessionID)
	fmt.Fprintf(w, "Profile:            %s\n", report.Profile)
	fmt.Fprintf(w, "Signature:          valid (%s; %s)\n", report.Signature.Algorithm, report.Signature.Canonicalization)
	fmt.Fprintf(w, "Recorder key:       %s\n", report.Signature.KeyFingerprint)
	fmt.Fprintf(w, "Assurance:          %s; ceiling %s\n", report.Assurance.Description, report.Assurance.VerdictCeiling)
	fmt.Fprintf(w, "Evidence:           %d segments; %d records\n", report.SegmentCount, report.RecordCount)
	fmt.Fprintf(w, "Chain tip:          %s\n", report.ChainTip)
	fmt.Fprintf(w, "Models:             %s\n", trustRecordModelSummary(report.Models))
	fmt.Fprintf(w, "Tools:              %s\n", trustRecordToolSummary(report.Tools))
	fmt.Fprintf(w, "Transcript digest:  %s\n", report.TranscriptDigest)
}

func trustRecordModelSummary(models []trustrecord.ModelActivity) string {
	if len(models) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(models))
	for _, model := range models {
		name := model.Provider
		if model.ModelID != "" {
			name += "/" + model.ModelID
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", name, model.RequestCount))
	}
	return strings.Join(parts, ", ")
}

func trustRecordToolSummary(tools []trustrecord.ToolActivity) string {
	if len(tools) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(tools))
	for _, tool := range tools {
		parts = append(parts, fmt.Sprintf("%s (%d)", tool.Name, tool.CallCount))
	}
	return strings.Join(parts, ", ")
}
