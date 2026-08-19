package recorder

import "boxedai/internal/evidence"

// SessionMeta carries the session-constant values the recorder stamps onto every
// evidence record and into each segment manifest. It is supplied once at
// NewRecorder and never mutated. Fields map to the audit.*/vm.* attribute namespaces
// (DESIGN "Required attributes") and to session.json.
type SessionMeta struct {
	// SessionID is stamped as audit.session.id and into every manifest.
	SessionID string
	// TraceID is the 32-hex-char (16 byte) session trace id set on each OTLP
	// LogRecord's TraceId. May be empty (no trace binding).
	TraceID string
	// PolicyDigest is the canonical-JSON sha256 ("sha256:...") of the resolved
	// policy, stamped as audit.policy.digest and into every manifest.
	PolicyDigest string
	// VMImage is the golden image tag (e.g. "boxedai-base-arm64"), sourced from
	// image.Manifest.Tag (see internal/image).
	VMImage string
	// VMImageDigest is the golden image's disk digest ("sha256:..."), sourced
	// from image.Manifest.DiskDigest (see internal/image).
	VMImageDigest string
	// VMID is the lima instance id (= session id); stamped as vm.id when set.
	VMID string
	// VMBootID identifies a specific VM boot; stamped as vm.boot.id when set.
	VMBootID string
	// RecorderPubPEM is the recorder public key PKIX PEM, carried so the session
	// can embed it in session.json as the verifier trust root.
	RecorderPubPEM string
	// HumanAccessBinding is the sealed human-access contract for a mediated
	// session (nil for non-mediated sessions). The recorder reads it to
	// authoritatively re-derive workspace mutation actor classes from host-owned
	// data. Like the rest of SessionMeta it is supplied once and MUST NOT be
	// mutated after construction: the same pointer is shared with session.json
	// marshaling and guest provisioning, and revocation is tracked in side-state,
	// never by flipping a field on this binding.
	HumanAccessBinding *evidence.HumanAccessBinding
}
