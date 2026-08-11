package broker

import (
	"fmt"

	"boxedai/internal/evidence"
)

// NormalizedAction is the canonical form of a requested external effect. Its digest is
// what the approver sees, what effect.requested/approved/dispatched all carry, and what
// the verifier matches to prove no dispatch preceded approval.
type NormalizedAction struct {
	Adapter string            `json:"adapter"`
	Op      string            `json:"op"`
	Args    map[string]string `json:"args"`
}

// Digest returns the "sha256:<hex>" digest over the action's canonical JSON.
func (a NormalizedAction) Digest() (string, error) {
	b, err := evidence.CanonicalJSON(a)
	if err != nil {
		return "", fmt.Errorf("broker: digest action: %w", err)
	}
	return evidence.SHA256Hex(b), nil
}
