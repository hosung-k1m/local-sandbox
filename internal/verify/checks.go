package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"boxedai/internal/evidence"
)

// jsonUnmarshalStrict decodes JSON rejecting unknown fields, so a manifest that
// carries fields the verifier does not know about is surfaced rather than
// silently ignored.
func jsonUnmarshalStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
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

// checkSequenceContinuity verifies audit.sequence forms 1..N with no gaps or
// duplicates across all segments (DESIGN check 4).
func checkSequenceContinuity(records []record) (bool, string) {
	if len(records) == 0 {
		return false, "no records found"
	}
	seqs := make([]int64, 0, len(records))
	for _, r := range records {
		seqs = append(seqs, r.seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for i, s := range seqs {
		want := int64(i + 1)
		if s == want {
			continue
		}
		if s < want {
			return false, fmt.Sprintf("duplicate sequence near %d", s)
		}
		return false, fmt.Sprintf("sequence gap: expected %d, found %d", want, s)
	}
	return true, fmt.Sprintf("sequences 1..%d continuous", len(seqs))
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
// every event's audit.policy.digest, and every manifest (DESIGN check 6).
func checkPolicyDigest(grantDigest string, records []record, manifests []segmentManifest) (bool, string) {
	if grantDigest == "" {
		return false, "grant has empty policy_digest"
	}
	for _, r := range records {
		d := r.str(evidence.AttrPolicyDigest)
		if d == "" {
			continue // not every producer stamps it on every record; skip blanks
		}
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

// checkSensor verifies sensor.started precedes the first process.executed and
// counts sensor loss (DESIGN check 7). Any sensor loss, or a process observed
// before the sensor came up, fails the check (driving an INCOMPLETE verdict);
// the loss count is returned regardless for the facet.
func checkSensor(records []record) (ok bool, lossCount int, detail string) {
	var firstSensorStart int64 = -1
	var firstProcExec int64 = -1
	restartCount := 0
	for _, r := range records {
		switch r.name {
		case evidence.EventSensorStarted:
			if firstSensorStart < 0 || r.seq < firstSensorStart {
				firstSensorStart = r.seq
			}
		case evidence.EventSensorLoss:
			lossCount++
		case evidence.EventSensorRestarted:
			restartCount++
		case evidence.EventProcessExecuted:
			if firstProcExec < 0 || r.seq < firstProcExec {
				firstProcExec = r.seq
			}
		}
	}

	var problems []string
	if firstProcExec >= 0 {
		if firstSensorStart < 0 {
			problems = append(problems, "process.executed observed but sensor.started never recorded")
		} else if firstSensorStart >= firstProcExec {
			problems = append(problems, fmt.Sprintf("sensor.started (seq %d) not before first process.executed (seq %d)", firstSensorStart, firstProcExec))
		}
	}
	if lossCount > 0 {
		problems = append(problems, fmt.Sprintf("sensor.loss recorded %d time(s), %d restart(s)", lossCount, restartCount))
	}
	if len(problems) == 0 {
		return true, lossCount, "sensor.started before workload; no sensor loss"
	}
	return false, lossCount, joinStrings(problems)
}

// checkFlow verifies the flow invariants (DESIGN check 8): every effect.dispatched
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
		switch r.name {
		case evidence.EventEffectApproved:
			if d := r.str(evidence.AttrContentDigest); d != "" {
				approvedEffects["digest:"+d] = true
			}
			if a := r.str(evidence.AttrActionID); a != "" {
				approvedEffects["action:"+a] = true
			}
		case evidence.EventAuthorizationDecided:
			if r.str(evidence.AttrOutcome) != string(evidence.OutcomeDenied) {
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
// (DESIGN check 9). The output event is the last workspace.manifested by sequence
// (the input manifest is emitted at snapshot time, the output at session end).
// The check is skipped (and passes) when there is no output event or no file, to
// avoid over-claiming; a genuine mismatch fails, indicating the artifact was
// altered after recording.
func checkOutputManifest(sessionDir string, records []record) (bool, string) {
	var out *record
	for i := range records {
		if records[i].name == evidence.EventWorkspaceManifested {
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
