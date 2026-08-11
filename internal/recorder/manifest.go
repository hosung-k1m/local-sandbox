package recorder

import (
	"crypto/rand"
	"fmt"

	cose "github.com/veraison/go-cose"
)

// manifestSchema is the schema identifier stamped on every segment manifest.
const manifestSchema = "boxedai.segment/v1"

// segmentManifest is the per-segment manifest (DESIGN "Recorder" step 5). It is
// serialized with evidence.CanonicalJSON (sorted keys, no insignificant whitespace);
// its sha256 field digests the exact segment .otlp file bytes, and the manifest bytes
// themselves are COSE Sign1 signed.
type segmentManifest struct {
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

// signManifest COSE Sign1 signs the exact manifest bytes with the recorder's Ed25519
// key and returns the tagged COSE_Sign1 CBOR message.
func signManifest(key SigningKey, payload []byte) ([]byte, error) {
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, key.Priv)
	if err != nil {
		return nil, fmt.Errorf("recorder: create cose signer: %w", err)
	}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA},
	}
	sig, err := cose.Sign1(rand.Reader, signer, headers, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("recorder: cose sign1: %w", err)
	}
	return sig, nil
}
