package trustrecord

const (
	MaxSafeInteger             = int64(1<<53 - 1)
	Profile                    = "boxedai.trust-record/v1"
	EvidenceProfile            = "boxedai.evidence/v1"
	CanonicalizationRFC8785    = "RFC8785"
	SignatureAlgorithmEd25519  = "Ed25519"
	RuntimePlatformSoftware    = "software-only"
	RuntimeIsolationLima       = "lima-vm"
	OriginHostControlPlane     = "host-control-plane"
	OriginProducerRecorder     = "boxedai-recorder"
	AssuranceVerdictLocalOnly  = "LOCAL_ONLY"
	ToolTranscriptEventVersion = "boxedai.tool-transcript/v1"
)

type Record struct {
	Schema    string    `json:"schema"`
	IssuedAt  string    `json:"issued_at"`
	Session   Session   `json:"session"`
	Source    *Source   `json:"source,omitempty"`
	Runtime   Runtime   `json:"runtime"`
	Origin    Origin    `json:"origin"`
	Policy    Policy    `json:"policy"`
	Artifacts Artifacts `json:"artifacts"`
	Evidence  Evidence  `json:"evidence"`
	Activity  Activity  `json:"activity"`
	Assurance Assurance `json:"assurance"`
	Signing   Signing   `json:"signing"`
	Signature string    `json:"signature,omitempty"`
}

type Session struct {
	ID        string `json:"id"`
	TraceID   string `json:"trace_id"`
	Harness   string `json:"harness"`
	CreatedAt string `json:"created_at"`
}

type Source struct {
	Repository string `json:"repository,omitempty"`
	Branch     string `json:"branch,omitempty"`
	Commit     string `json:"commit,omitempty"`
}

type Runtime struct {
	Platform  string       `json:"platform"`
	Isolation string       `json:"isolation"`
	Image     RuntimeImage `json:"image"`
}

type RuntimeImage struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type Origin struct {
	Kind     string `json:"kind"`
	Producer string `json:"producer"`
}

type Policy struct {
	Profile string `json:"profile"`
	Digest  string `json:"digest"`
}

type Artifacts struct {
	SessionGrantDigest   string `json:"session_grant_digest"`
	PolicyDigest         string `json:"policy_digest"`
	InputManifestDigest  string `json:"input_manifest_digest"`
	OutputManifestDigest string `json:"output_manifest_digest"`
}

type Evidence struct {
	Schema             string    `json:"schema"`
	SegmentCount       int       `json:"segment_count"`
	RecordCount        int64     `json:"record_count"`
	FirstSequence      int64     `json:"first_sequence"`
	LastSequence       int64     `json:"last_sequence"`
	ChainTip           string    `json:"chain_tip"`
	SensorLossCount    int64     `json:"sensor_loss_count"`
	SensorRestartCount int64     `json:"sensor_restart_count"`
	SensorMechanisms   []string  `json:"sensor_mechanisms,omitempty"`
	Segments           []Segment `json:"segments"`
}

type Segment struct {
	Number         int    `json:"number"`
	SegmentDigest  string `json:"segment_digest"`
	ManifestDigest string `json:"manifest_digest"`
	FirstSequence  int64  `json:"first_sequence"`
	LastSequence   int64  `json:"last_sequence"`
	RecordCount    int64  `json:"record_count"`
	SealedAt       string `json:"sealed_at"`
}

type Activity struct {
	Models              []ModelActivity `json:"models"`
	ModelRequestCount   int64           `json:"model_request_count"`
	Tools               []ToolActivity  `json:"tools"`
	EffectDispatchCount int64           `json:"effect_dispatch_count"`
	NetworkDenialCount  int64           `json:"network_denial_count"`
	ToolTranscript      ToolTranscript  `json:"tool_transcript"`
}

type ModelActivity struct {
	Provider     string      `json:"provider"`
	ModelID      string      `json:"model_id,omitempty"`
	RequestCount int64       `json:"request_count"`
	Usage        *TokenUsage `json:"usage,omitempty"`
}

type TokenUsage struct {
	InputTokens  *int64 `json:"input_tokens,omitempty"`
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	TotalTokens  *int64 `json:"total_tokens,omitempty"`
}

type ToolActivity struct {
	Name      string `json:"name"`
	CallCount int64  `json:"call_count"`
}

type ToolTranscript struct {
	Schema           string `json:"schema"`
	Canonicalization string `json:"canonicalization"`
	Digest           string `json:"digest"`
	EventCount       int64  `json:"event_count"`
	CallCount        int64  `json:"call_count"`
}

type Assurance struct {
	Level               int    `json:"level"`
	VerdictCeiling      string `json:"verdict_ceiling"`
	HardwareAttested    bool   `json:"hardware_attested"`
	ExternallyWitnessed bool   `json:"externally_witnessed"`
}

type Signing struct {
	Algorithm              string `json:"algorithm"`
	Canonicalization       string `json:"canonicalization"`
	RecorderKeyFingerprint string `json:"recorder_key_fingerprint"`
}
