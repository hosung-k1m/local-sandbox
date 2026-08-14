package trustrecord

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gowebpki/jcs"
)

func signingInput(record Record) ([]byte, error) {
	record.Signature = ""
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("trust record: marshal signing input: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("trust record: RFC8785 canonicalization: %w", err)
	}
	return canonical, nil
}

func validateUnsigned(record Record) error {
	record.Signature = strings.Repeat("A", 86)
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("trust record: marshal unsigned record: %w", err)
	}
	if err := PinProfile(raw); err != nil {
		return err
	}
	return ValidateJSON(raw)
}

func Sign(record *Record, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("trust record: signing key has %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if record.Signing.RecorderKeyFingerprint != PublicKeyFingerprint(publicKey) {
		return fmt.Errorf("trust record: signing key does not match recorder key fingerprint")
	}
	if err := validateUnsigned(*record); err != nil {
		return err
	}
	if err := ValidateSemantics(*record); err != nil {
		return err
	}
	input, err := signingInput(*record)
	if err != nil {
		return err
	}
	record.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, input))
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("trust record: marshal signed record: %w", err)
	}
	return ValidateJSON(raw)
}

// VerifyEnvelope applies the profile, schema, caller-supplied key, signature,
// and semantic gates in that order. It does not rederive on-disk evidence claims;
// internal/verify performs that final independent gate.
func VerifyEnvelope(data []byte, publicKey ed25519.PublicKey) (Record, error) {
	record, err := Decode(data)
	if err != nil {
		return Record{}, err
	}
	return VerifyDecodedEnvelope(record, publicKey)
}

// VerifyDecodedEnvelope continues verification after Decode has pinned the
// profile and validated the schema. It exists so callers that load external key
// material can preserve the required profile/schema -> key -> signature order.
func VerifyDecodedEnvelope(record Record, publicKey ed25519.PublicKey) (Record, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Record{}, fmt.Errorf("trust record: verification key has %d bytes, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	wantFingerprint := PublicKeyFingerprint(publicKey)
	if record.Signing.RecorderKeyFingerprint != wantFingerprint {
		return Record{}, fmt.Errorf("trust record: recorder key fingerprint %s does not match supplied key %s", record.Signing.RecorderKeyFingerprint, wantFingerprint)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(record.Signature)
	if err != nil {
		return Record{}, fmt.Errorf("trust record: decode signature: %w", err)
	}
	input, err := signingInput(record)
	if err != nil {
		return Record{}, err
	}
	if !ed25519.Verify(publicKey, input, signature) {
		return Record{}, fmt.Errorf("trust record: Ed25519 signature invalid")
	}
	if err := ValidateSemantics(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func PublicKeyFingerprint(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:])
}
