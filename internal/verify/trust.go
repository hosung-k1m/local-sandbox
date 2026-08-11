package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	cose "github.com/veraison/go-cose"

	"boxedai/internal/evidence"
)

// grant is the subset of session.json (the session grant) the verifier needs:
// the trust root (recorder public key) and the expected policy digest. Other
// grant fields are ignored here; the verifier does not trust anything it cannot
// independently re-derive.
type grant struct {
	Schema       string `json:"schema"`
	SessionID    string `json:"session_id"`
	PolicyDigest string `json:"policy_digest"`
	RecorderPub  string `json:"recorder_pub"` // PEM PKIX Ed25519 public key
}

// loadGrant reads and parses session.json from the session directory.
func loadGrant(path string) (grant, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return grant{}, fmt.Errorf("verify: read session grant: %w", err)
	}
	var g grant
	if err := json.Unmarshal(b, &g); err != nil {
		return grant{}, fmt.Errorf("verify: parse session grant: %w", err)
	}
	return g, nil
}

// trustRoot parses the recorder public key PEM from the grant into an Ed25519
// public key and a COSE verifier bound to it.
func (g grant) trustRoot() (ed25519.PublicKey, cose.Verifier, error) {
	block, _ := pem.Decode([]byte(g.RecorderPub))
	if block == nil {
		return nil, nil, fmt.Errorf("verify: recorder_pub is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("verify: parse recorder_pub: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("verify: recorder_pub is %T, want ed25519 public key", pub)
	}
	v, err := cose.NewVerifier(cose.AlgorithmEdDSA, ed)
	if err != nil {
		return nil, nil, fmt.Errorf("verify: build cose verifier: %w", err)
	}
	return ed, v, nil
}

// segmentManifest mirrors the recorder's per-segment manifest (DESIGN "Recorder"
// step 5). Field names and JSON tags match the recorder's canonical output so the
// same bytes verify identically. The verifier re-parses these bytes independently.
type segmentManifest struct {
	Schema             string `json:"schema"`
	SessionID          string `json:"session_id"`
	SegmentNumber      int    `json:"segment_number"`
	FirstSequence      int64  `json:"first_sequence"`
	LastSequence       int64  `json:"last_sequence"`
	RecordCount        int    `json:"record_count"`
	PrevSegmentDigest  string `json:"prev_segment_digest"`
	SegmentDigest      string `json:"segment_digest"`
	PolicyDigest       string `json:"policy_digest"`
	SensorLossCount    int    `json:"sensor_loss_count"`
	SensorRestartCount int    `json:"sensor_restart_count"`
	CreatedAt          string `json:"created_at"`
	SealedAt           string `json:"sealed_at"`
}

// verifyManifestSignature checks the COSE Sign1 in coseBytes against the trust
// root and confirms it signs exactly manifestBytes (the .manifest.json file). It
// accepts either an embedded-payload Sign1 (the recorder's convention: payload =
// manifest bytes) or a detached one (manifest bytes supplied as external data),
// so the verifier stays independent of how the recorder chose to package it.
func verifyManifestSignature(coseBytes, manifestBytes []byte, v cose.Verifier) error {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(coseBytes); err != nil {
		return fmt.Errorf("decode cose Sign1: %w", err)
	}
	if len(msg.Payload) == 0 {
		// Detached payload: the manifest bytes are the externally supplied data.
		if err := msg.Verify(manifestBytes, v); err != nil {
			return fmt.Errorf("cose signature invalid: %w", err)
		}
		return nil
	}
	// Embedded payload: the signed bytes must be exactly the manifest we read.
	if !bytes.Equal(msg.Payload, manifestBytes) {
		return fmt.Errorf("cose payload does not match manifest file bytes")
	}
	if err := msg.Verify(nil, v); err != nil {
		return fmt.Errorf("cose signature invalid: %w", err)
	}
	return nil
}

// fileDigest returns the "sha256:<hex>" digest of a file's exact bytes.
func fileDigest(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return evidence.SHA256Hex(b), nil
}
