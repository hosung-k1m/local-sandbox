// Package verify is the BoxedAi offline verifier (DESIGN.md "Verifier"). Given a
// session directory it re-derives, from the raw evidence on disk, whether the
// session's audit record is internally consistent and untampered, and renders a
// verdict with supporting facets.
//
// This package is a deliberately INDEPENDENT re-implementation of evidence
// reading: it decodes the length-delimited OTLP segment files itself and
// re-checks every COSE signature, digest, chain link and sequence from scratch.
// It shares only the evidence vocabulary (event names, attribute keys, digest
// rules) via internal/evidence and MUST NOT import internal/recorder — that
// independence is what makes a passing verdict meaningful.
package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"boxedai/internal/evidence"
)

// Verdict is the top-level judgement. Ordered here most-severe first.
type Verdict string

const (
	// VerdictVerified is unreachable in v0.1: it would require an external
	// transparency witness (SCITT receipts, Phase 5). See Facets.VerifiedUnreachable.
	VerdictVerified Verdict = "VERIFIED"
	// VerdictTamperSuspected: a signature, digest, chain or sequence check failed.
	VerdictTamperSuspected Verdict = "TAMPER_SUSPECTED"
	// VerdictBypassDetected: a flow invariant was violated (ungated effect/tool).
	VerdictBypassDetected Verdict = "BYPASS_DETECTED"
	// VerdictIncomplete: missing close/seal, sensor loss, or an unresolved tail.
	VerdictIncomplete Verdict = "INCOMPLETE"
	// VerdictLocalOnly: all checks pass; the local-assurance ceiling in v0.1.
	VerdictLocalOnly Verdict = "LOCAL_ONLY"
)

// verifiedUnreachableReason is the fixed explanation for why VERIFIED cannot be
// produced in v0.1.
const verifiedUnreachableReason = "VERIFIED requires an external transparency witness (SCITT receipts, Phase 5); " +
	"v0.1 has no external witnessing, so LOCAL_ONLY is the assurance ceiling"

// Facets are the individual dimensions behind the verdict (DESIGN "Verifier":
// signature validity, chain validity, sequence continuity, close status,
// sensor-loss count, ungated-activity count), plus the collected check messages
// and the reason VERIFIED is unreachable.
type Facets struct {
	SignatureValid       bool     `json:"signature_valid"`
	ChainValid           bool     `json:"chain_valid"`
	SequenceContinuous   bool     `json:"sequence_continuous"`
	CloseStatus          string   `json:"close_status"` // "sealed" | "no_seal" | "no_segments"
	SensorLossCount      int      `json:"sensor_loss_count"`
	UngatedActivityCount int      `json:"ungated_activity_count"`
	Messages             []string `json:"messages"`
	VerifiedUnreachable  string   `json:"verified_unreachable"`
	DigestAlgorithm      string   `json:"digest_algorithm"`
	SignatureFormat      string   `json:"signature_format"`
	SignatureAlgorithm   string   `json:"signature_algorithm"`
	RecorderFingerprint  string   `json:"recorder_key_fingerprint"`
	SegmentCount         int      `json:"segment_count"`
}

// Check is one named verification step and its outcome (DESIGN "Verifier"
// checks 1..9). Detail carries a short human-readable explanation.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Report is the full verifier output for a session.
type Report struct {
	Session      string  `json:"session"`
	Verdict      Verdict `json:"verdict"`
	PolicyDigest string  `json:"policy_digest"`
	Facets       Facets  `json:"facets"`
	Checks       []Check `json:"checks"`
}

// Check names, in DESIGN.md order.
const (
	stepSignatures = "cose-signatures"
	stepDigests    = "segment-digests"
	stepChain      = "chain-links"
	stepSequence   = "sequence-continuity"
	stepLifecycle  = "session-lifecycle"
	stepPolicy     = "policy-digest-consistency"
	stepSensor     = "sensor-invariants"
	stepFlow       = "flow-invariants"
	stepOutput     = "output-manifest"
)

// segFiles bundles the three files that make up one sealed segment.
type segFiles struct {
	number   int    // parsed from the segment-NNNNNN prefix
	otlp     string // path to the .otlp WAL file
	manifest string // path to the .manifest.json file ("" if absent)
	cose     string // path to the .manifest.cose file ("" if absent)
}

// Verify runs the offline verifier over a session directory and returns its
// Report. It returns a non-nil error only for structural problems that prevent
// verification from running at all (missing/invalid session.json, unreadable
// segment directory, undecodable segment bytes). Evidence-level problems (bad
// signature, missing seal, ungated activity) are reported as a verdict, not an
// error.
func Verify(sessionDir string) (Report, error) {
	g, err := loadGrant(filepath.Join(sessionDir, "session.json"))
	if err != nil {
		return Report{}, err
	}
	publicKey, verifier, err := g.trustRoot()
	if err != nil {
		return Report{}, err
	}

	rep := Report{
		Session:      g.SessionID,
		PolicyDigest: g.PolicyDigest,
		Facets: Facets{
			VerifiedUnreachable: verifiedUnreachableReason,
			DigestAlgorithm:     "SHA-256",
			SignatureFormat:     "COSE Sign1",
			SignatureAlgorithm:  "EdDSA (Ed25519)",
			RecorderFingerprint: evidence.SHA256Hex(publicKey),
		},
	}

	segs, err := enumerateSegments(filepath.Join(sessionDir, "evidence", "segments"))
	if err != nil {
		return Report{}, err
	}
	rep.Facets.SegmentCount = len(segs)

	// Decode manifests and records up front; both check groups read them.
	manifests := make([]segmentManifest, 0, len(segs))
	var records []record
	hasUnsealedTail := false
	sigOK, digestOK := true, true
	var sigDetail, digestDetail []string

	for i, s := range segs {
		recs, err := readSegment(s.otlp, i)
		if err != nil {
			return Report{}, err
		}
		records = append(records, recs...)

		if s.manifest == "" || s.cose == "" {
			hasUnsealedTail = true
			continue
		}
		mBytes, err := os.ReadFile(s.manifest)
		if err != nil {
			return Report{}, err
		}
		var man segmentManifest
		if err := jsonUnmarshalStrict(mBytes, &man); err != nil {
			return Report{}, fmt.Errorf("verify: parse manifest %s: %w", s.manifest, err)
		}
		manifests = append(manifests, man)

		// (1) COSE signature of the manifest against the trust root.
		cBytes, err := os.ReadFile(s.cose)
		if err != nil {
			return Report{}, err
		}
		if err := verifyManifestSignature(cBytes, mBytes, verifier); err != nil {
			sigOK = false
			sigDetail = append(sigDetail, fmt.Sprintf("segment %d: %v", man.SegmentNumber, err))
		}

		// (2) recomputed segment file digest matches the manifest.
		got, err := fileDigest(s.otlp)
		if err != nil {
			return Report{}, err
		}
		if got != man.SegmentDigest {
			digestOK = false
			digestDetail = append(digestDetail, fmt.Sprintf("segment %d: file %s != manifest %s", man.SegmentNumber, got, man.SegmentDigest))
		}
	}

	// (3) prev_segment_digest chain links.
	chainOK, chainDetail := checkChainLinks(manifests)

	// (4) sequence continuity 1..N across segments.
	seqOK, seqDetail := checkSequenceContinuity(records)

	// (5) session lifecycle events present exactly once and ordered.
	lifecycleOK, closeStatus, lifecycleDetail := checkLifecycleEvents(records, len(segs))

	// (6) policy digest consistent across grant, events, manifests.
	policyOK, policyDetail := checkPolicyDigest(g.PolicyDigest, records, manifests)

	// (7) sensor invariants.
	sensorOK, lossCount, sensorDetail := checkSensor(records)

	// (8) flow invariants (effect/tool gating).
	flowOK, ungated, flowDetail := checkFlow(records)

	// (9) output manifest digest matches the recorded workspace.manifested event.
	outputOK, outputDetail := checkOutputManifest(sessionDir, records)

	rep.Checks = []Check{
		{stepSignatures, sigOK, join(sigDetail, fmt.Sprintf("%d COSE Sign1 manifest signature(s) verified with EdDSA (Ed25519); key %s", len(manifests), rep.Facets.RecorderFingerprint))},
		{stepDigests, digestOK, join(digestDetail, "all SHA-256 segment digests match their manifests")},
		{stepChain, chainOK, chainDetail},
		{stepSequence, seqOK, seqDetail},
		{stepLifecycle, lifecycleOK, lifecycleDetail},
		{stepPolicy, policyOK, policyDetail},
		{stepSensor, sensorOK, sensorDetail},
		{stepFlow, flowOK, flowDetail},
		{stepOutput, outputOK, outputDetail},
	}

	rep.Facets.SignatureValid = sigOK
	rep.Facets.ChainValid = chainOK
	rep.Facets.SequenceContinuous = seqOK
	rep.Facets.CloseStatus = closeStatus
	rep.Facets.SensorLossCount = lossCount
	rep.Facets.UngatedActivityCount = ungated
	for _, c := range rep.Checks {
		status := "ok"
		if !c.Passed {
			status = "FAIL"
		}
		rep.Facets.Messages = append(rep.Facets.Messages, fmt.Sprintf("[%s] %s: %s", status, c.Name, c.Detail))
	}
	if hasUnsealedTail {
		rep.Facets.Messages = append(rep.Facets.Messages, "note: an .otlp segment has no sealed manifest (unresolved tail)")
	}

	// Verdict selection (DESIGN "Verifier"), most-severe wins.
	switch {
	case !sigOK || !digestOK || !chainOK || !seqOK || !policyOK || !outputOK:
		rep.Verdict = VerdictTamperSuspected
	case !flowOK:
		rep.Verdict = VerdictBypassDetected
	case !lifecycleOK || closeStatus != "sealed" || !sensorOK || hasUnsealedTail:
		rep.Verdict = VerdictIncomplete
	default:
		rep.Verdict = VerdictLocalOnly
	}
	return rep, nil
}

// enumerateSegments finds segment-*.otlp files in order and pairs each with its
// manifest and cose sidecars (which may be absent for an unsealed tail).
func enumerateSegments(dir string) ([]segFiles, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("verify: read segments dir: %w", err)
	}
	var segs []segFiles
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".otlp") {
			continue
		}
		base := strings.TrimSuffix(name, ".otlp")
		s := segFiles{
			number: parseSegmentNumber(base),
			otlp:   filepath.Join(dir, name),
		}
		manPath := filepath.Join(dir, base+".manifest.json")
		cosePath := filepath.Join(dir, base+".manifest.cose")
		if fileExists(manPath) {
			s.manifest = manPath
		}
		if fileExists(cosePath) {
			s.cose = cosePath
		}
		segs = append(segs, s)
	}
	// Deterministic order: segment file names are zero-padded, so lexical == numeric.
	sort.Slice(segs, func(i, j int) bool { return segs[i].number < segs[j].number })
	return segs, nil
}

// parseSegmentNumber extracts the trailing integer from "segment-000001".
func parseSegmentNumber(base string) int {
	i := strings.LastIndexByte(base, '-')
	if i < 0 {
		return 0
	}
	n := 0
	for _, c := range base[i+1:] {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// join returns the detail string built from any failure details, else the ok text.
func join(details []string, okText string) string {
	if len(details) == 0 {
		return okText
	}
	return strings.Join(details, "; ")
}

// String renders the report for the CLI (DESIGN "CLI": boxedai verify).
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Session:  %s\n", r.Session)
	fmt.Fprintf(&b, "Verdict:  %s\n", r.Verdict)
	fmt.Fprintf(&b, "Policy:   %s\n", r.PolicyDigest)
	fmt.Fprintf(&b, "Crypto:   SHA-256; COSE Sign1; EdDSA (Ed25519)\n")
	fmt.Fprintf(&b, "Key:      %s\n", r.Facets.RecorderFingerprint)
	b.WriteString("\nFacets:\n")
	fmt.Fprintf(&b, "  signature valid:     %v\n", r.Facets.SignatureValid)
	fmt.Fprintf(&b, "  SHA-256 chain valid: %v\n", r.Facets.ChainValid)
	fmt.Fprintf(&b, "  sequence continuous: %v\n", r.Facets.SequenceContinuous)
	fmt.Fprintf(&b, "  close status:        %s\n", r.Facets.CloseStatus)
	fmt.Fprintf(&b, "  sensor loss count:   %d\n", r.Facets.SensorLossCount)
	fmt.Fprintf(&b, "  ungated activity:    %d\n", r.Facets.UngatedActivityCount)
	b.WriteString("\nChecks:\n")
	for _, c := range r.Checks {
		status := "PASS"
		if !c.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "  [%s] %-26s %s\n", status, c.Name, c.Detail)
	}
	if r.Verdict != VerdictVerified {
		fmt.Fprintf(&b, "\nVERIFIED unreachable: %s\n", r.Facets.VerifiedUnreachable)
	}
	return b.String()
}
