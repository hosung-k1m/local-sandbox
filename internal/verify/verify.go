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
	TrustRecordStatus    string   `json:"trust_record_status"`
	TrustRecordProfile   string   `json:"trust_record_profile,omitempty"`
	TrustRecordAssurance string   `json:"trust_record_assurance,omitempty"`
	TrustRecordSignature bool     `json:"trust_record_signature_valid"`
	TrustRecordDerived   bool     `json:"trust_record_cross_derived"`
	// Agent hierarchy (DESIGN "Agent hierarchy and attribution"). AgentTracking is
	// "none" for legacy zero-agent sessions, "tracked" otherwise.
	AgentTracking             string `json:"agent_tracking"`
	AgentCount                int    `json:"agent_count"`
	AgentHierarchyValid       bool   `json:"agent_hierarchy_valid"`
	UnattributedWorkloadCount int    `json:"unattributed_workload_count"`
	// AgentsWithoutWitnessedActivity counts registered children whose id witnessed
	// no non-lifecycle event (the decoy shape); a plausibility facet, never gating.
	AgentsWithoutWitnessedActivity int `json:"agents_without_witnessed_activity"`
	// OpenChildAgents counts registered children with no agent.completed and gates
	// hierarchy verification. UnregisteredAgentActivity counts workload events
	// tagged with an agent.id no agent.started ever registered; that self-reported
	// plausibility facet does not gate.
	OpenChildAgents           int `json:"open_child_agents"`
	UnregisteredAgentActivity int `json:"unregistered_agent_activity"`
	// HookProcessesAnchored / HookProcessesUnanchored reconcile the Narration track
	// against kernel observation: hook-reported pids the guest_supervisor sensor
	// corroborates vs. never witnessed. Plausibility facets, never gating (process
	// attribution is lineage-scoped, not strong).
	HookProcessesAnchored   int `json:"hook_processes_anchored"`
	HookProcessesUnanchored int `json:"hook_processes_unanchored"`
	// File content capture (DESIGN "File content capture"). FileContentCaptured
	// counts file.changed events whose bytes the host says it stored; Withheld and
	// Misses split the rest by whether policy refused the capture or the capture
	// failed — a deliberate withholding is a working store, a miss is a lossy one.
	// FileContentStoreValid is true only when every claimed blob is present and
	// still hashes to its signed digest; it is false for a store that is merely
	// incomplete as well as for one that is wrong, so read it with the check.
	FileContentCaptured   int  `json:"file_content_captured"`
	FileContentWithheld   int  `json:"file_content_withheld"`
	FileContentMisses     int  `json:"file_content_misses"`
	FileContentStoreValid bool `json:"file_content_store_valid"`
}

// Check is one named verification step and its outcome (DESIGN "Verifier"
// checks 1..11). Detail carries a short human-readable explanation.
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
	// stepContentStore re-resolves the unsigned per-session blob store against the
	// signed file.changed digests (DESIGN "File content capture").
	stepContentStore = "file-content-store"
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

	// (7) policy digest consistent across grant, events, manifests.
	policyOK, policyDetail := checkPolicyDigest(g.PolicyDigest, records, manifests)

	// (8) sensor invariants.
	sensorOK, lossCount, sensorDetail := checkSensor(records)

	// (9) flow invariants (effect/tool gating).
	flowOK, ungated, flowDetail := checkFlow(records)

	// (10) output manifest digest matches the recorded workspace.manifested event.
	outputOK, outputDetail := checkOutputManifest(sessionDir, records)

	// Captured file content still resolves in the unsigned per-session blob store.
	// The check passes only when the store is both complete and correct; the two
	// failure classes are read apart below because they carry different verdicts.
	contentStore := checkFileContentStore(records, sessionDir)
	contentStoreOK := !contentStore.tamper && !contentStore.incomplete

	grantOK, grantDetail := checkSessionGrantBinding(sessionDir, g, records)
	trustResult := checkTrustRecord(sessionDir, g, publicKey, segs, manifests, records)
	trustOK := !trustResult.tamper && !trustResult.incomplete

	// (12) agent hierarchy reconstruction and ownership invariants. Anomalies are
	// workload-forgeable, so they drive INCOMPLETE, never TAMPER.
	agentsOK, agFacets, agentDetail := checkAgents(g.SessionID, records)

	rep.Checks = []Check{
		{stepSignatures, sigOK, join(sigDetail, fmt.Sprintf("%d COSE Sign1 manifest signature(s) verified with EdDSA (Ed25519); key %s", len(manifests), rep.Facets.RecorderFingerprint))},
		{stepDigests, digestOK, join(digestDetail, "all SHA-256 segment digests match their manifests")},
		{stepChain, chainOK, chainDetail},
		{stepSequence, seqOK, seqDetail},
		{stepLifecycle, lifecycleOK, lifecycleDetail},
		{stepGrantRecord, grantOK, grantDetail},
		{stepPolicy, policyOK, policyDetail},
		{stepSensor, sensorOK, sensorDetail},
		{stepFlow, flowOK, flowDetail},
		{stepOutput, outputOK, outputDetail},
		{stepContentStore, contentStoreOK, contentStore.detail},
		{stepTrustRecord, trustOK, trustResult.detail},
		{stepAgents, agentsOK, agentDetail},
	}

	rep.Facets.SignatureValid = sigOK
	rep.Facets.ChainValid = chainOK
	rep.Facets.SequenceContinuous = seqOK
	rep.Facets.CloseStatus = closeStatus
	rep.Facets.SensorLossCount = lossCount
	rep.Facets.UngatedActivityCount = ungated
	rep.Facets.TrustRecordStatus = trustResult.status
	rep.Facets.TrustRecordProfile = trustResult.profile
	rep.Facets.TrustRecordAssurance = trustResult.assurance
	rep.Facets.TrustRecordSignature = trustResult.signatureValid
	rep.Facets.TrustRecordDerived = trustResult.crossDerived
	rep.Facets.AgentTracking = agFacets.tracking
	rep.Facets.AgentCount = agFacets.count
	rep.Facets.AgentHierarchyValid = agFacets.hierarchyValid
	rep.Facets.UnattributedWorkloadCount = agFacets.unattributed
	rep.Facets.AgentsWithoutWitnessedActivity = agFacets.noActivity
	rep.Facets.OpenChildAgents = agFacets.openChildren
	rep.Facets.UnregisteredAgentActivity = agFacets.unregisteredActivity
	rep.Facets.HookProcessesAnchored = agFacets.hookAnchored
	rep.Facets.HookProcessesUnanchored = agFacets.hookUnanchored
	rep.Facets.FileContentCaptured = contentStore.captured
	rep.Facets.FileContentWithheld = contentStore.withheld
	rep.Facets.FileContentMisses = contentStore.misses
	rep.Facets.FileContentStoreValid = contentStore.storeValid
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
	// A blob that hashes to something other than its signed digest is an artifact
	// contradicting the signed record, so it joins the tamper class alongside the
	// output-manifest mismatch. A blob that is merely gone takes nothing away from
	// the signed record and only costs inspectability, so it degrades to INCOMPLETE.
	case !sigOK || !digestOK || !chainOK || !seqOK || !grantOK || !policyOK || !outputOK || trustResult.tamper || contentStore.tamper:
		rep.Verdict = VerdictTamperSuspected
	case !flowOK:
		rep.Verdict = VerdictBypassDetected
	case !lifecycleOK || closeStatus != "sealed" || !sensorOK || hasUnsealedTail || trustResult.incomplete || !agentsOK || contentStore.incomplete:
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
	fmt.Fprintf(&b, "  trust record:        %s\n", r.Facets.TrustRecordStatus)
	if r.Facets.TrustRecordProfile != "" {
		fmt.Fprintf(&b, "  trust profile:       %s\n", r.Facets.TrustRecordProfile)
		fmt.Fprintf(&b, "  trust signature:     %v\n", r.Facets.TrustRecordSignature)
		fmt.Fprintf(&b, "  claims rederived:    %v\n", r.Facets.TrustRecordDerived)
		fmt.Fprintf(&b, "  assurance:           %s\n", r.Facets.TrustRecordAssurance)
	}
	fmt.Fprintf(&b, "  agent tracking:      %s\n", r.Facets.AgentTracking)
	if r.Facets.AgentTracking != "none" {
		fmt.Fprintf(&b, "  agent count:         %d\n", r.Facets.AgentCount)
		fmt.Fprintf(&b, "  hierarchy valid:     %v\n", r.Facets.AgentHierarchyValid)
		fmt.Fprintf(&b, "  unattributed work:   %d\n", r.Facets.UnattributedWorkloadCount)
		fmt.Fprintf(&b, "  agents w/o activity: %d\n", r.Facets.AgentsWithoutWitnessedActivity)
		fmt.Fprintf(&b, "  open children:       %d\n", r.Facets.OpenChildAgents)
		fmt.Fprintf(&b, "  unregistered work:   %d\n", r.Facets.UnregisteredAgentActivity)
		fmt.Fprintf(&b, "  hook pids anchored:   %d\n", r.Facets.HookProcessesAnchored)
		fmt.Fprintf(&b, "  hook pids unanchored: %d\n", r.Facets.HookProcessesUnanchored)
	}
	// Content facets are omitted entirely for a session that neither captured nor
	// declined to capture anything (every legacy session), where all four values are
	// zero and would read as a finding rather than as an absence of the feature.
	if r.Facets.FileContentCaptured > 0 || r.Facets.FileContentWithheld > 0 || r.Facets.FileContentMisses > 0 {
		fmt.Fprintf(&b, "  content captured:    %d (withheld %d, misses %d)\n",
			r.Facets.FileContentCaptured, r.Facets.FileContentWithheld, r.Facets.FileContentMisses)
		fmt.Fprintf(&b, "  content store valid: %v\n", r.Facets.FileContentStoreValid)
	}
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
