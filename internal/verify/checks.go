package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"boxedai/internal/evidence"
)

// jsonUnmarshalStrict decodes JSON rejecting unknown fields, so a manifest that
// carries fields the verifier does not know about is surfaced rather than
// silently ignored.
func jsonUnmarshalStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

// checkChainLinks verifies the prev_segment_digest chain (DESIGN check 3): the
// first sealed segment has an empty prev digest and each subsequent segment's
// prev digest equals the previous segment's segment_digest. Manifests are sorted
// by segment number first so ordering does not depend on read order.
func checkChainLinks(manifests []segmentManifest) (bool, string) {
	if len(manifests) == 0 {
		return true, "no sealed segments to SHA-256 chain"
	}
	ms := append([]segmentManifest(nil), manifests...)
	sort.Slice(ms, func(i, j int) bool { return ms[i].SegmentNumber < ms[j].SegmentNumber })
	if ms[0].PrevSegmentDigest != "" {
		return false, fmt.Sprintf("first segment %d prev digest is %q, want empty", ms[0].SegmentNumber, ms[0].PrevSegmentDigest)
	}
	for i := 1; i < len(ms); i++ {
		if ms[i].PrevSegmentDigest != ms[i-1].SegmentDigest {
			return false, fmt.Sprintf("segment %d prev digest %s != segment %d digest %s",
				ms[i].SegmentNumber, ms[i].PrevSegmentDigest, ms[i-1].SegmentNumber, ms[i-1].SegmentDigest)
		}
	}
	return true, fmt.Sprintf("%d segment(s) linked by SHA-256 digest", len(ms))
}

// checkSequenceContinuity verifies audit.sequence forms 1..N in physical record
// order with no gaps, duplicates, or reordering across segments (DESIGN check 4).
func checkSequenceContinuity(records []record) (bool, string) {
	if len(records) == 0 {
		return false, "no records found"
	}
	for i, r := range records {
		want := int64(i + 1)
		if r.seq == want {
			continue
		}
		if r.seq < want {
			return false, fmt.Sprintf("duplicate or reordered sequence: expected %d, found %d", want, r.seq)
		}
		return false, fmt.Sprintf("sequence gap or reordering: expected %d, found %d", want, r.seq)
	}
	return true, fmt.Sprintf("sequences 1..%d continuous and physically ordered", len(records))
}

// lifecycleEvents are the four session-scope events checked in order.
var lifecycleEvents = []string{
	evidence.EventSessionGranted,
	evidence.EventSessionStarted,
	evidence.EventSessionStopped,
	evidence.EventSessionSealed,
}

// checkLifecycleEvents verifies session.granted/started/stopped/sealed each occur
// exactly once and in sequence order (DESIGN check 5). It also derives the close
// status facet: "sealed" when the session is both stopped and sealed, otherwise
// "no_seal" (or "no_segments" when there are no segments at all).
func checkLifecycleEvents(records []record, segCount int) (ok bool, closeStatus, detail string) {
	seqByName := map[string][]int64{}
	for _, r := range records {
		if r.str(evidence.AttrProducer) != string(evidence.ChannelController) {
			continue
		}
		if _, tracked := indexOf(lifecycleEvents, r.name); tracked {
			seqByName[r.name] = append(seqByName[r.name], r.seq)
		}
	}
	var problems []string
	for _, name := range lifecycleEvents {
		switch n := len(seqByName[name]); {
		case n == 0:
			problems = append(problems, fmt.Sprintf("%s missing", name))
		case n > 1:
			problems = append(problems, fmt.Sprintf("%s occurs %d times", name, n))
		}
	}
	// Ordering: granted < started < stopped < sealed, using the first seq of each
	// present event. Only meaningful once each present-once check holds enough.
	var prevSeq int64 = -1
	var prevName string
	for _, name := range lifecycleEvents {
		s, ok := firstSeq(seqByName, name)
		if !ok {
			continue
		}
		if prevSeq >= 0 && s <= prevSeq {
			problems = append(problems, fmt.Sprintf("%s (seq %d) not after %s (seq %d)", name, s, prevName, prevSeq))
		}
		prevSeq, prevName = s, name
	}

	switch {
	case segCount == 0:
		closeStatus = "no_segments"
	case len(seqByName[evidence.EventSessionStopped]) == 1 && len(seqByName[evidence.EventSessionSealed]) == 1 && len(problems) == 0:
		closeStatus = "sealed"
	default:
		closeStatus = "no_seal"
	}

	if len(problems) == 0 {
		return true, closeStatus, "granted/started/stopped/sealed each present once and ordered"
	}
	return false, closeStatus, joinStrings(problems)
}

// checkPolicyDigest verifies the policy digest is identical across the grant,
// every event's audit.policy.digest, and every manifest (DESIGN check 7).
func checkPolicyDigest(grantDigest string, records []record, manifests []segmentManifest) (bool, string) {
	if grantDigest == "" {
		return false, "grant has empty policy_digest"
	}
	for _, r := range records {
		d := r.str(evidence.AttrPolicyDigest)
		if d != grantDigest {
			return false, fmt.Sprintf("event %s (seq %d) policy digest %s != grant %s", r.name, r.seq, d, grantDigest)
		}
	}
	for _, m := range manifests {
		if m.PolicyDigest != grantDigest {
			return false, fmt.Sprintf("manifest %d policy digest %s != grant %s", m.SegmentNumber, m.PolicyDigest, grantDigest)
		}
	}
	return true, "policy digest consistent across grant, events, manifests"
}

// checkSensor verifies sensor.started precedes the first process lifecycle event and
// counts sensor loss (DESIGN check 8). Any sensor loss, or a process observed
// before the sensor came up, fails the check (driving an INCOMPLETE verdict);
// the loss count is returned regardless for the facet.
func checkSensor(records []record) (ok bool, lossCount int, detail string) {
	var firstSensorStart int64 = -1
	var firstProcessEvent int64 = -1
	sessionStarted := false
	processExecuted := false
	processExited := false
	restartCount := 0
	procfsCoverage := false
	for _, r := range records {
		switch r.name {
		case evidence.EventSessionStarted:
			if r.str(evidence.AttrProducer) == string(evidence.ChannelController) {
				sessionStarted = true
			}
		case evidence.EventSensorStarted:
			if !isGuestIntegrityRecord(r) {
				continue
			}
			if r.str("sensor.mechanism") == "procfs" {
				procfsCoverage = true
			}
			if firstSensorStart < 0 || r.seq < firstSensorStart {
				firstSensorStart = r.seq
			}
		case evidence.EventSensorLoss:
			if isGuestIntegrityRecord(r) {
				lossCount++
			}
		case evidence.EventSensorRestarted:
			if isGuestIntegrityRecord(r) {
				restartCount++
				if r.str("sensor.mechanism") == "procfs" {
					procfsCoverage = true
				}
			}
		case evidence.EventProcessCreated, evidence.EventProcessExecuted:
			if !isGuestKernelRecord(r) {
				continue
			}
			if r.str("observer") == "procfs" {
				procfsCoverage = true
			}
			if firstProcessEvent < 0 || r.seq < firstProcessEvent {
				firstProcessEvent = r.seq
			}
			if r.name == evidence.EventProcessExecuted && r.str("observer") == "tetragon" {
				processExecuted = true
			}
		case evidence.EventProcessExited:
			if !isGuestKernelRecord(r) {
				continue
			}
			if r.str("observer") == "procfs" {
				procfsCoverage = true
			}
			if firstProcessEvent < 0 || r.seq < firstProcessEvent {
				firstProcessEvent = r.seq
			}
			if r.str("observer") == "tetragon" {
				processExited = true
			}
		}
	}

	var problems []string
	if sessionStarted && (!processExecuted || !processExited) {
		problems = append(problems, "started session lacks trusted Tetragon process.executed and process.exited coverage")
	}
	if firstProcessEvent >= 0 {
		if firstSensorStart < 0 {
			problems = append(problems, "process lifecycle observed but sensor.started never recorded")
		} else if firstSensorStart >= firstProcessEvent {
			problems = append(problems, fmt.Sprintf("sensor.started (seq %d) not before first process lifecycle event (seq %d)", firstSensorStart, firstProcessEvent))
		}
	}
	if lossCount > 0 {
		problems = append(problems, fmt.Sprintf("sensor.loss recorded %d time(s), %d restart(s)", lossCount, restartCount))
	}
	if procfsCoverage {
		problems = append(problems, "authoritative process coverage used procfs polling")
	}
	if len(problems) == 0 {
		return true, lossCount, "sensor.started before workload; no sensor loss"
	}
	return false, lossCount, joinStrings(problems)
}

// checkFlow verifies the flow invariants (DESIGN check 9): every effect.dispatched
// is preceded by an effect.approved for the same action (matched by
// audit.content.digest, falling back to audit.action.id), and every
// internal_tool.dispatched is preceded by an authorization.decided=allow for the
// same action.id. Records are processed in sequence order so "preceded by" means
// strictly earlier. Returns the count of ungated dispatches for the facet.
func checkFlow(records []record) (ok bool, ungated int, detail string) {
	sorted := append([]record(nil), records...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].seq < sorted[j].seq })

	approvedEffects := map[string]bool{} // keys: content digest and/or action id of effect.approved
	authorizedTools := map[string]bool{} // keys: action id of authorization.decided allow
	var problems []string

	for _, r := range sorted {
		if !isBrokerMediatedRecord(r) {
			continue
		}
		switch r.name {
		case evidence.EventEffectApproved:
			if r.str(evidence.AttrOutcome) != string(evidence.OutcomeSuccess) {
				continue
			}
			if d := r.str(evidence.AttrContentDigest); d != "" {
				approvedEffects["digest:"+d] = true
			}
			if a := r.str(evidence.AttrActionID); a != "" {
				approvedEffects["action:"+a] = true
			}
		case evidence.EventAuthorizationDecided:
			if r.str(evidence.AttrOutcome) == string(evidence.OutcomeSuccess) {
				if a := r.str(evidence.AttrActionID); a != "" {
					authorizedTools["action:"+a] = true
				}
			}
		case evidence.EventEffectDispatched:
			if !effectApproved(r, approvedEffects) {
				ungated++
				problems = append(problems, fmt.Sprintf("effect.dispatched (seq %d) has no prior effect.approved", r.seq))
			}
		case evidence.EventInternalToolDispatched:
			a := r.str(evidence.AttrActionID)
			if a == "" || !authorizedTools["action:"+a] {
				ungated++
				problems = append(problems, fmt.Sprintf("internal_tool.dispatched (seq %d) has no prior authorization.decided=allow", r.seq))
			}
		}
	}
	if len(problems) == 0 {
		return true, 0, "every effect/tool dispatch is preceded by its approval"
	}
	return false, ungated, joinStrings(problems)
}

// effectApproved reports whether a dispatched effect has a matching prior
// approval, keyed by content digest when present, else by action id.
func effectApproved(r record, approved map[string]bool) bool {
	if d := r.str(evidence.AttrContentDigest); d != "" {
		return approved["digest:"+d]
	}
	if a := r.str(evidence.AttrActionID); a != "" {
		return approved["action:"+a]
	}
	return false
}

// checkOutputManifest verifies that, when a workspace.manifested(output) event
// exists, its recorded content digest matches the on-disk output-manifest.json
// (DESIGN check 10). The output event is the last workspace.manifested by sequence
// (the input manifest is emitted at snapshot time, the output at session end).
// The check is skipped (and passes) when there is no output event or no file, to
// avoid over-claiming; a genuine mismatch fails, indicating the artifact was
// altered after recording.
func checkOutputManifest(sessionDir string, records []record) (bool, string) {
	var out *record
	for i := range records {
		if records[i].name == evidence.EventWorkspaceManifested && records[i].str(evidence.AttrProducer) == string(evidence.ChannelController) {
			if out == nil || records[i].seq > out.seq {
				out = &records[i]
			}
		}
	}
	if out == nil {
		return true, "no workspace.manifested event to check"
	}
	recorded := out.str(evidence.AttrContentDigest)
	if recorded == "" {
		return true, "workspace.manifested event carries no content digest to check"
	}
	path := filepath.Join(sessionDir, "output-manifest.json")
	if !fileExists(path) {
		return true, "output-manifest.json not present; skipped"
	}
	got, err := fileDigest(path)
	if err != nil {
		return true, fmt.Sprintf("output-manifest.json unreadable: %v", err)
	}
	if got != recorded {
		return false, fmt.Sprintf("output-manifest.json digest %s != recorded %s", got, recorded)
	}
	return true, "output-manifest.json digest matches the recorded event"
}

// Wire names owned by the session host's content-capture middleware, mirrored here
// as local constants rather than imported. The verifier already does this for
// "observer" and "sensor.mechanism" above, for the same reason: the producer and
// the verifier must agree on the wire, not on a Go symbol. A shared constant would
// let a rename on the producer side silently carry the verifier with it, which is
// exactly the agreement this package exists to refuse.
const (
	// attrFileCaptureReason explains why a file.changed event's bytes were not
	// stored. It is absent on legacy events and on events that were captured.
	attrFileCaptureReason = "file.capture.reason"

	// Policy withholding. The host could have stored the bytes and deliberately did
	// not, so the store is complete with respect to what it was allowed to hold.
	reasonSecretPolicy     = "secret_policy"
	reasonExcludedByPolicy = "excluded_by_policy"
	reasonSizeCap          = "size_cap"

	// Capture misses. The host intended to store the bytes and could not; the file
	// had already moved on, vanished, or the read/store failed. Nothing is wrong with
	// the evidence — the signed digest is still the record — but the side store holds
	// less than the session intended, which is worth counting separately from a
	// deliberate withholding.
	reasonChangedBeforeCapture = "changed_before_capture"
	reasonMissingBeforeCapture = "missing_before_capture"
	reasonReadError            = "read_error"
	reasonStoreError           = "store_error"
)

// Blob store layout, re-derived here instead of importing internal/blobstore. The
// package doc's stance on internal/recorder applies verbatim: a check that resolves
// a blob through the same code that wrote it proves only that the code is
// self-consistent. Re-deriving the path and the hash from the recorded digest is
// what makes a passing content-store check mean anything.
const (
	blobsDirName     = "blobs"
	blobAlgoDirName  = "sha256"
	blobDigestPrefix = "sha256:"
	blobDigestHexLen = 64

	// contentStoreExamples caps how many offending blobs a failure detail names. A
	// session that lost or had its whole store rewritten would otherwise render a
	// wall of digests; the counts carry the magnitude, the examples give a starting
	// point for inspection.
	contentStoreExamples = 3
)

// contentStoreResult is the outcome of the file-content-store check. The two
// failure classes are kept apart deliberately, because they say opposite things
// about the record:
//
//   - missing → INCOMPLETE. The blob store is unsigned and derivable: a pruned,
//     lost, or never-written blob costs a reader the ability to see what a file
//     contained, but it forges nothing. The signed file.changed event still carries
//     the digest, so history is intact and merely less inspectable. That degrades
//     honestly and must not be dressed up as an attack.
//   - mismatched → TAMPER_SUSPECTED. A blob that is present but hashes to something
//     other than the digest a sealed segment signed is an artifact presenting itself
//     as verified content while being something else. That is the same integrity
//     violation class as the output-manifest mismatch, and content addressing makes
//     it provable without any key material: rehash the file, compare to the signed
//     digest.
type contentStoreResult struct {
	captured        int // file.changed records claiming capture="full"
	withheld        int // not captured because policy said no
	misses          int // not captured because capture failed
	missingBlobs    int // claimed capture whose blob is absent or unreadable
	mismatchedBlobs int // blob present, hashes to something other than the signed digest
	storeValid      bool
	incomplete      bool
	tamper          bool
	detail          string
}

// checkFileContentStore verifies the unsigned per-session content store against the
// signed record (DESIGN "File content capture"). For every kernel-observed
// file.changed event stamped audit.content.capture="full", the blob named by the
// event's audit.content.digest must exist under <sessionDir>/blobs/sha256/<hex> and
// must still hash to that digest.
//
// Only records passing isGuestKernelRecord are considered. A file.changed on any
// other channel is workload narration, not an observation of the workspace, and the
// host's capture stamp is not the workload's to make — counting those would let the
// workload inflate or deflate the content facets at will.
//
// A session that captured nothing and has no store passes with an explicit skip
// rather than a silent success, mirroring checkOutputManifest: the verifier says
// what it did not check.
func checkFileContentStore(records []record, sessionDir string) contentStoreResult {
	var res contentStoreResult
	blobsDir := filepath.Join(sessionDir, blobsDirName)
	var missingExamples, mismatchExamples []string
	// note records at most contentStoreExamples offenders per class.
	note := func(dst *[]string, format string, args ...any) {
		if len(*dst) < contentStoreExamples {
			*dst = append(*dst, fmt.Sprintf(format, args...))
		}
	}

	for _, r := range records {
		if r.name != evidence.EventFileChanged || !isGuestKernelRecord(r) {
			continue
		}
		if r.str(evidence.AttrContentCapture) != string(evidence.CaptureFull) {
			// Not captured. The reason attribute is the host's account of why; an
			// absent or unrecognized reason (every legacy digest_only event) lands in
			// neither bucket rather than being guessed into one.
			switch r.str(attrFileCaptureReason) {
			case reasonSecretPolicy, reasonExcludedByPolicy, reasonSizeCap:
				res.withheld++
			case reasonChangedBeforeCapture, reasonMissingBeforeCapture, reasonReadError, reasonStoreError:
				res.misses++
			}
			continue
		}

		res.captured++
		digest := r.str(evidence.AttrContentDigest)
		path, ok := blobPath(blobsDir, digest)
		if !ok {
			// The event claims stored content but gives no address that can name a
			// blob. Nothing can be produced for it, so the store is short by one
			// entry — unresolvable, not falsified.
			res.missingBlobs++
			note(&missingExamples, "seq %d: capture=full with unusable digest %q", r.seq, digest)
			continue
		}
		if !fileExists(path) {
			res.missingBlobs++
			note(&missingExamples, "seq %d: no blob for %s", r.seq, digest)
			continue
		}
		got, err := fileDigest(path)
		if err != nil {
			// Present but unreadable proves nothing about its bytes, so it is counted
			// with the absent ones. The verifier does not accuse on an I/O error.
			res.missingBlobs++
			note(&missingExamples, "seq %d: blob for %s unreadable: %v", r.seq, digest, err)
			continue
		}
		if got != digest {
			res.mismatchedBlobs++
			note(&mismatchExamples, "seq %d: blob hashes to %s, signed digest is %s", r.seq, got, digest)
		}
	}

	res.storeValid = res.missingBlobs == 0 && res.mismatchedBlobs == 0
	res.incomplete = res.missingBlobs > 0
	res.tamper = res.mismatchedBlobs > 0

	// Failures first, most severe named first, so the CLI line leads with the worst
	// thing found.
	var problems []string
	if res.mismatchedBlobs > 0 {
		problems = append(problems, fmt.Sprintf("%d captured blob(s) do not hash to their signed digest: %s",
			res.mismatchedBlobs, joinStrings(mismatchExamples)))
	}
	if res.missingBlobs > 0 {
		problems = append(problems, fmt.Sprintf("%d captured blob(s) absent or unreadable (signed digests still stand): %s",
			res.missingBlobs, joinStrings(missingExamples)))
	}
	if len(problems) > 0 {
		res.detail = joinStrings(problems)
		return res
	}

	if res.captured == 0 {
		// Nothing claims stored content. A store directory that exists anyway holds
		// blobs no signed event points at; unreferenced bytes make no integrity claim,
		// so they are reported, not judged.
		if fileExists(blobsDir) {
			res.detail = "no captured content to check (blob store directory present but unreferenced)"
			return res
		}
		res.detail = "no captured content to check"
		return res
	}
	res.detail = fmt.Sprintf("%d captured blob(s) re-hash to their signed digest", res.captured)
	if res.withheld > 0 {
		res.detail += fmt.Sprintf("; %d withheld by policy", res.withheld)
	}
	if res.misses > 0 {
		res.detail += fmt.Sprintf("; %d capture miss(es)", res.misses)
	}
	return res
}

// blobPath re-derives the on-disk address of a captured blob from the digest a
// sealed segment recorded. The digest must be exactly "sha256:" plus 64 lowercase
// hex characters; anything else returns false rather than being normalized. The
// strictness is what makes the join safe — a validated digest contains no path
// separator, no "..", and no absolute prefix — and it is also honest about the only
// address format the recorded evidence is allowed to use.
func blobPath(blobsDir, digest string) (string, bool) {
	hex, ok := strings.CutPrefix(digest, blobDigestPrefix)
	if !ok || len(hex) != blobDigestHexLen {
		return "", false
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return filepath.Join(blobsDir, blobAlgoDirName, hex), true
}

// firstSeq returns the smallest sequence recorded for an event name.
func firstSeq(seqByName map[string][]int64, name string) (int64, bool) {
	seqs, ok := seqByName[name]
	if !ok || len(seqs) == 0 {
		return 0, false
	}
	min := seqs[0]
	for _, s := range seqs[1:] {
		if s < min {
			min = s
		}
	}
	return min, true
}

func indexOf(names []string, name string) (int, bool) {
	for i, n := range names {
		if n == name {
			return i, true
		}
	}
	return -1, false
}

func joinStrings(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}
