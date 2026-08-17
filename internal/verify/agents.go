package verify

import (
	"fmt"
	"sort"
	"strings"

	"boxedai/internal/evidence"
)

// stepAgents is the twelfth verifier check: reconstruct the agent hierarchy from
// the signed segment events and validate the ownership invariants (DESIGN.md
// "Agent hierarchy and attribution"). Every violation here is a workload-forgeable
// input, so a failure maps to INCOMPLETE, never TAMPER_SUSPECTED.
const stepAgents = "agent-hierarchy"

// agentNode is one agent reconstructed from its agent.started, plus whether a
// matching agent.completed closed it. producer/method/strength are the
// recorder-assigned (channel-derived) values, so they cannot be forged by the
// payload; role/parentID/nativeID are self-reported label attributes.
type agentNode struct {
	id        string
	role      string
	parentID  string
	nativeID  string
	producer  string
	method    string
	completed bool
}

// agentFacets are the reconstruction outputs surfaced on the report.
type agentFacets struct {
	tracking             string // "none" (legacy) | "tracked"
	count                int
	hierarchyValid       bool
	unattributed         int
	noActivity           int // registered children whose id witnessed no non-lifecycle event
	openChildren         int // registered children with no agent.completed; gates hierarchy verification
	unregisteredActivity int // workload events tagged with an agent.id that was never registered
	hookAnchored         int // hook-reported pids with exactly one trusted process incarnation
	hookUnanchored       int // hook-reported pids with zero or multiple trusted incarnations
}

// checkAgents reconstructs and validates the per-agent hierarchy. It returns ok
// (no anomaly and no gated-unattributed), the facets, and a human detail. A
// session with zero agent events is a legacy record: tracking "none", ok, and
// verdict-neutral. sessionID drives the deterministic id derivations the verifier
// recomputes independently.
func checkAgents(sessionID string, records []record) (bool, agentFacets, string) {
	agents := map[string]*agentNode{}
	var anomalies []string
	sawLifecycle := false
	// caps is the controller-attested per-category capability declaration read off
	// the Primary Agent's agent.started; it decides which categories gate.
	var caps map[string]string

	primaryID := evidence.PrimaryAgentID(sessionID)

	for _, r := range records {
		if r.name != evidence.EventAgentStarted {
			continue
		}
		sawLifecycle = true
		id := r.str(evidence.AttrAgentID)
		if id == "" {
			anomalies = append(anomalies, fmt.Sprintf("agent.started (seq %d) carries no agent.id", r.seq))
			continue
		}
		node := &agentNode{
			id:       id,
			role:     r.str(evidence.AttrAgentRole),
			parentID: r.str(evidence.AttrAgentParentID),
			nativeID: r.str(evidence.AttrAgentNativeID),
			producer: r.str(evidence.AttrProducer),
			method:   r.str(evidence.AttrAgentAttributionMethod),
		}
		if existing, dup := agents[id]; dup {
			// Duplicate registrations collapse to one id; only a conflicting
			// re-registration (different provenance or lineage) is an anomaly.
			if existing.role != node.role || existing.parentID != node.parentID ||
				existing.nativeID != node.nativeID || existing.producer != node.producer {
				anomalies = append(anomalies, fmt.Sprintf("agent %s registered again with conflicting attributes", id))
			}
			continue
		}
		agents[id] = node
		if id == primaryID && node.producer == string(evidence.ChannelController) {
			caps = capabilityDeclaration(r)
		}
	}

	// Closures. An agent.completed for an unregistered id is itself an anomaly.
	for _, r := range records {
		if r.name != evidence.EventAgentCompleted {
			continue
		}
		sawLifecycle = true
		id := r.str(evidence.AttrAgentID)
		if node, ok := agents[id]; ok {
			producer := r.str(evidence.AttrProducer)
			if producer != node.producer {
				anomalies = append(anomalies, fmt.Sprintf("agent.completed (seq %d) for agent %s arrived on %q, want registration producer %q", r.seq, id, producer, node.producer))
				continue
			}
			node.completed = true
		} else {
			anomalies = append(anomalies, fmt.Sprintf("agent.completed (seq %d) closes unregistered agent %q", r.seq, id))
		}
	}

	// Legacy: no agent events at all verifies exactly as before.
	if !sawLifecycle {
		return true, agentFacets{tracking: "none", hierarchyValid: true}, "no agent events (legacy session)"
	}

	anomalies = append(anomalies, validateAgentSet(sessionID, primaryID, agents)...)
	openChildren := countOpenChildren(agents, primaryID)
	if openChildren > 0 {
		anomalies = append(anomalies, fmt.Sprintf("%d child agent(s) never closed", openChildren))
	}

	unattributed, perCategory := unattributedWorkload(records)
	hookAnchored, hookUnanchored := reconcileHookProcesses(records)
	facets := agentFacets{
		tracking:             "tracked",
		count:                len(agents),
		hierarchyValid:       len(anomalies) == 0,
		unattributed:         unattributed,
		noActivity:           countAgentsWithoutActivity(records, agents, primaryID),
		openChildren:         openChildren,
		unregisteredActivity: countUnregisteredAgentActivity(records, agents),
		hookAnchored:         hookAnchored,
		hookUnanchored:       hookUnanchored,
	}

	// Capability gating: an unattributed workload event only flips the verdict in
	// a category the adapter declared it attributes at `strong`. Nothing is strong
	// in v0.1, so this never fires today — it is forward-wiring for a trusted
	// executor (DESIGN.md "Per-category attribution capability").
	gating := gatedUnattributed(perCategory, caps)

	ok := len(anomalies) == 0 && len(gating) == 0
	if ok {
		detail := fmt.Sprintf("%d agent(s); hierarchy consistent; %d unattributed workload event(s)", facets.count, facets.unattributed)
		if facets.noActivity > 0 {
			detail += fmt.Sprintf("; %d child agent(s) with no witnessed activity", facets.noActivity)
		}
		if facets.openChildren > 0 {
			detail += fmt.Sprintf("; %d child agent(s) never closed", facets.openChildren)
		}
		if facets.unregisteredActivity > 0 {
			detail += fmt.Sprintf("; %d event(s) tagged with an unregistered agent id", facets.unregisteredActivity)
		}
		if facets.hookUnanchored > 0 {
			detail += fmt.Sprintf("; %d hook process(es) unanchored in kernel observation", facets.hookUnanchored)
		}
		return true, facets, detail
	}
	return false, facets, joinStrings(append(anomalies, gating...))
}

// reconcileHookProcesses joins the Narration track to the Observation track at the
// honest ceiling — anchored lineage. Subagents are in-process and never own a pid,
// so a hook↔kernel join can only anchor the pid of the short-lived guest-agent hook
// process that posted the event (hooks.go stamps its own os.Getpid()), never the
// logical subagent. The guest_supervisor process sensor independently witnesses that
// process exec. It returns (anchored, unanchored): hook-reported pids that map to
// exactly one trusted process incarnation vs. pids with zero or multiple trusted
// candidates — the latter being absent or ambiguous observational backing.
//
// It is a plausibility FACET, never verdict-gating: process attribution is
// lineage-scoped, not strong, so an unanchored count is a signal to inspect, not
// proof of forgery — a dropped sensor batch also leaves a genuine hook pid
// unwitnessed (DESIGN.md "Reconciliation (offline)"). Hook and sensor sequence
// values come from different producer channels and cannot define a shared lifetime
// window, so reconciliation inventories trusted incarnations across the complete
// evidence set instead.
func reconcileHookProcesses(records []record) (anchored, unanchored int) {
	type processIncarnation struct {
		execID string
	}

	var processRecords []record
	for _, r := range records {
		if r.str(evidence.AttrProducer) == string(evidence.ChannelGuestSupervisor) &&
			(r.name == evidence.EventProcessCreated || r.name == evidence.EventProcessExecuted || r.name == evidence.EventProcessExited) {
			processRecords = append(processRecords, r)
		}
	}
	sort.SliceStable(processRecords, func(i, j int) bool { return processRecords[i].seq < processRecords[j].seq })
	active := map[int64]*processIncarnation{}
	incarnations := map[int64]int{}
	for _, r := range processRecords {
		pid, ok := r.i64(evidence.AttrProcessPID)
		if !ok {
			continue
		}
		execID := r.str(evidence.AttrProcessExecID)
		switch r.name {
		case evidence.EventProcessCreated, evidence.EventProcessExecuted:
			current := active[pid]
			if current == nil || execID != "" && current.execID != "" && execID != current.execID {
				incarnations[pid]++
				active[pid] = &processIncarnation{execID: execID}
			} else if current.execID == "" {
				current.execID = execID
			}
		case evidence.EventProcessExited:
			current := active[pid]
			if current != nil && (execID == "" || current.execID == "" || execID == current.execID) {
				delete(active, pid)
			}
		}
	}

	seenHooks := map[int64]bool{}
	for _, r := range records {
		if r.str(evidence.AttrProducer) != string(evidence.ChannelWorkload) {
			continue
		}
		pid, ok := r.i64(evidence.AttrProcessPID)
		if !ok || seenHooks[pid] {
			continue
		}
		seenHooks[pid] = true
		if incarnations[pid] == 1 {
			anchored++
		} else {
			unanchored++
		}
	}
	return anchored, unanchored
}

// countAgentsWithoutActivity counts registered child agents whose agent.id
// appears on no event other than their own lifecycle (agent.started/completed) —
// the "narrated agent, no witnessed activity" decoy shape (DESIGN.md
// "Reconciliation (offline)"). It is a plausibility FACET, never verdict-gating:
// a genuine subagent that only made model calls (broker channel, session-level
// attribution, carrying no per-agent id) would also land here, so a nonzero count
// is a signal to inspect, not proof of a decoy. The Primary is excluded: its own
// direct tool calls carry no agent.id by design (invariant 9), so it would always
// appear activity-less under this metric.
func countAgentsWithoutActivity(records []record, agents map[string]*agentNode, primaryID string) int {
	active := map[string]bool{}
	for _, r := range records {
		if r.name == evidence.EventAgentStarted || r.name == evidence.EventAgentCompleted {
			continue
		}
		if id := r.str(evidence.AttrAgentID); id != "" {
			active[id] = true
		}
	}
	n := 0
	for id, node := range agents {
		if id == primaryID || node.role == string(evidence.AgentRolePrimary) {
			continue
		}
		if !active[id] {
			n++
		}
	}
	return n
}

// validateAgentSet checks the ownership invariants over the reconstructed agents:
// exactly one controller-owned Primary at the derived id and closed; no other
// agent claiming primary/controller; every child id deriving from its native_id
// and registered on the workload channel; parents existing and acyclic.
func validateAgentSet(sessionID, primaryID string, agents map[string]*agentNode) []string {
	var out []string

	// (1) Exactly one Primary: the controller-owned node at the derived id.
	if primary, ok := agents[primaryID]; !ok {
		out = append(out, fmt.Sprintf("no controller-owned Primary Agent (expected id %s)", primaryID))
	} else {
		if primary.producer != string(evidence.ChannelController) {
			out = append(out, fmt.Sprintf("Primary Agent %s registered on %q, not the controller channel", primaryID, primary.producer))
		}
		if primary.role != string(evidence.AgentRolePrimary) {
			out = append(out, fmt.Sprintf("Primary Agent %s has role %q, want primary", primaryID, primary.role))
		}
		if primary.parentID != "" {
			out = append(out, fmt.Sprintf("Primary Agent %s names a parent %q; the Primary is the root", primaryID, primary.parentID))
		}
		if !primary.completed {
			out = append(out, fmt.Sprintf("Primary Agent %s has no agent.completed (missing closure)", primaryID))
		}
	}

	// Children (every non-Primary node), in deterministic id order.
	for _, id := range sortedAgentIDs(agents) {
		n := agents[id]
		if id == primaryID {
			continue
		}
		// Every non-Primary registration is exactly a Child rooted through a
		// nonempty parent; arbitrary roles and extra roots are invalid narration.
		if n.role != string(evidence.AgentRoleChild) {
			out = append(out, fmt.Sprintf("agent %s has role %q, want child", id, n.role))
		}
		if n.parentID == "" {
			out = append(out, fmt.Sprintf("child agent %s has no parent; every child must be rooted at the Primary", id))
		}
		if n.method == string(evidence.MethodController) {
			out = append(out, fmt.Sprintf("agent %s claims method=controller but was not controller-registered", id))
		}
		if n.producer != string(evidence.ChannelWorkload) {
			out = append(out, fmt.Sprintf("child agent %s registered on %q, not the workload channel", id, n.producer))
		}
		// (5) A child id must equal the deterministic derivation of its native_id.
		// The check runs unconditionally — an empty native_id is a well-defined hash
		// input, and no legitimate hook ever omits it (guest/agent/hooks.go skips
		// registration when the harness supplies no agent id), so an empty native_id
		// on a registered child is itself the mismatch it is meant to catch. Guarding
		// on non-empty would be a loophole: a direct /v1/events POST could omit
		// native_id and present an arbitrary agent.id with no derivation ever applied.
		if want := evidence.ChildAgentID(sessionID, n.nativeID); want != id {
			out = append(out, fmt.Sprintf("child agent %s does not match the derivation of native_id %q (want %s)", id, n.nativeID, want))
		}
	}

	// (6) Parents exist and form an acyclic forest.
	for _, id := range sortedAgentIDs(agents) {
		parent := agents[id].parentID
		if parent == "" {
			continue
		}
		if _, ok := agents[parent]; !ok {
			out = append(out, fmt.Sprintf("agent %s names unknown parent %s", id, parent))
		}
	}
	if cyc := findAgentCycle(agents); cyc != "" {
		out = append(out, fmt.Sprintf("agent parent graph has a cycle through %s", cyc))
	}
	return out
}

// capabilityDeclaration extracts the agent.capability.<category> attributes from
// the Primary Agent's agent.started into a category→strength map.
func capabilityDeclaration(r record) map[string]string {
	caps := map[string]string{}
	for k, v := range r.attrs {
		if !strings.HasPrefix(k, evidence.AttrAgentCapabilityPrefix) {
			continue
		}
		if s, ok := v.(string); ok {
			caps[strings.TrimPrefix(k, evidence.AttrAgentCapabilityPrefix)] = s
		}
	}
	return caps
}

// unattributedWorkload scans the workload channel once (DESIGN.md ownership
// invariant 9), returning the total count of events carrying no
// positively-identified agent.id — a facet regardless of gating — and a
// per-attribution-category tally of those same events, which feeds capability
// gating. Agent-lifecycle events are excluded: they carry the id they describe,
// not workload activity.
func unattributedWorkload(records []record) (total int, perCategory map[string]int) {
	perCategory = map[string]int{}
	for _, r := range records {
		if r.str(evidence.AttrProducer) != string(evidence.ChannelWorkload) {
			continue
		}
		if r.name == evidence.EventAgentStarted || r.name == evidence.EventAgentCompleted {
			continue
		}
		if r.str(evidence.AttrAgentID) != "" {
			continue
		}
		total++
		if cat := eventCategory(r.name); cat != "" {
			perCategory[cat]++
		}
	}
	return total, perCategory
}

// gatedUnattributed reports, per attributable category, the unattributed workload
// events (tallied by unattributedWorkload) that the adapter declared it attributes
// at `strong` — the only strength worth flipping the verdict on. Weaker
// declarations (self_reported, lineage, none) surface only as the facet count.
func gatedUnattributed(perCategory map[string]int, caps map[string]string) []string {
	var out []string
	for _, cat := range sortedKeys(perCategory) {
		if caps[cat] == string(evidence.StrengthStrong) {
			out = append(out, fmt.Sprintf("%d unattributed %s event(s) under a strong-attribution declaration", perCategory[cat], cat))
		}
	}
	return out
}

// countOpenChildren counts registered child agents with no agent.completed — a
// subagent that started but never closed (a crash, a killed harness, or a dropped
// SubagentStop hook). v0.1 reports the facet and fails hierarchy verification;
// the Primary's closure is checked separately in validateAgentSet.
func countOpenChildren(agents map[string]*agentNode, primaryID string) int {
	n := 0
	for id, node := range agents {
		if id == primaryID || node.role == string(evidence.AgentRolePrimary) {
			continue
		}
		if !node.completed {
			n++
		}
	}
	return n
}

// countUnregisteredAgentActivity counts workload events whose non-empty agent.id
// matches no registered agent (no agent.started ever carried it) — the verifier's
// mirror of the viewer's "unregistered" badge. It happens benignly (a dropped or
// raced SubagentStart trailing a successful tool hook for the same subagent) or
// adversarially (a direct /v1/events POST tagging activity with a fabricated id it
// never registered). A plausibility FACET, never gating: the id is self_reported
// either way, so an unregistered tag forges no trust.
func countUnregisteredAgentActivity(records []record, agents map[string]*agentNode) int {
	n := 0
	for _, r := range records {
		if r.str(evidence.AttrProducer) != string(evidence.ChannelWorkload) {
			continue
		}
		if r.name == evidence.EventAgentStarted || r.name == evidence.EventAgentCompleted {
			continue
		}
		id := r.str(evidence.AttrAgentID)
		if id == "" {
			continue
		}
		if _, ok := agents[id]; !ok {
			n++
		}
	}
	return n
}

// eventCategory maps an event name to its attribution category, or "" for events
// that carry no per-agent attribution concept (session lifecycle, credentials,
// sensor, segment).
func eventCategory(name string) string {
	switch name {
	case evidence.EventToolRequested, evidence.EventToolCompleted,
		evidence.EventInternalToolDispatched, evidence.EventInternalToolCompleted, evidence.EventInternalToolFailed:
		return evidence.CategoryTool
	case evidence.EventModelRequested, evidence.EventModelCompleted:
		return evidence.CategoryModel
	case evidence.EventProcessCreated, evidence.EventProcessExecuted, evidence.EventProcessExited:
		return evidence.CategoryProcess
	case evidence.EventFileChanged, evidence.EventFileDeleted:
		return evidence.CategoryFile
	case evidence.EventNetworkConnected, evidence.EventNetworkDenied:
		return evidence.CategoryNetwork
	default:
		return ""
	}
}

// findAgentCycle returns the id a back-edge closes on if the parent graph has a
// cycle, else "". Each node has at most one parent, so a three-colour DFS over the
// parent pointers detects a cycle without revisiting shared ancestors.
func findAgentCycle(agents map[string]*agentNode) string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var walk func(id string) string
	walk = func(id string) string {
		switch color[id] {
		case gray:
			return id
		case black:
			return ""
		}
		color[id] = gray
		if n := agents[id]; n != nil && n.parentID != "" {
			if _, ok := agents[n.parentID]; ok {
				if c := walk(n.parentID); c != "" {
					return c
				}
			}
		}
		color[id] = black
		return ""
	}
	for _, id := range sortedAgentIDs(agents) {
		if c := walk(id); c != "" {
			return c
		}
	}
	return ""
}

// sortedAgentIDs returns the agent ids in lexical order, so anomaly reporting and
// cycle detection are deterministic.
func sortedAgentIDs(agents map[string]*agentNode) []string {
	ids := make([]string, 0, len(agents))
	for id := range agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// sortedKeys returns a count map's keys in lexical order for deterministic output.
func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
