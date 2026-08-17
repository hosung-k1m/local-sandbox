package verify

import (
	"strings"
	"testing"

	"boxedai/internal/evidence"
)

const agentsTestSession = "bx-verify-agents"

// agentRec builds a decoded record with the given producer and attributes, as the
// verifier would read it back from a signed segment (attribution already stamped).
func agentRec(seq int64, name string, producer evidence.Channel, attrs map[string]any) record {
	m := map[string]any{evidence.AttrProducer: string(producer)}
	for k, v := range attrs {
		m[k] = v
	}
	return record{seq: seq, name: name, attrs: m}
}

// primaryStartedRec is the controller-owned Primary Agent's agent.started, with an
// optional capability declaration.
func primaryStartedRec(seq int64, caps map[string]string) record {
	attrs := map[string]any{
		evidence.AttrAgentID:                evidence.PrimaryAgentID(agentsTestSession),
		evidence.AttrAgentRole:              string(evidence.AgentRolePrimary),
		evidence.AttrAgentAttributionMethod: string(evidence.MethodController),
	}
	for c, s := range caps {
		attrs[evidence.AttrAgentCapabilityPrefix+c] = s
	}
	return agentRec(seq, evidence.EventAgentStarted, evidence.ChannelController, attrs)
}

func agentCompletedRec(seq int64, producer evidence.Channel, id string) record {
	return agentRec(seq, evidence.EventAgentCompleted, producer, map[string]any{evidence.AttrAgentID: id})
}

// childStartedRec is a hook-registered Child Agent on the workload channel.
func childStartedRec(seq int64, nativeID, parentID string) record {
	return agentRec(seq, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:                evidence.ChildAgentID(agentsTestSession, nativeID),
		evidence.AttrAgentNativeID:          nativeID,
		evidence.AttrAgentParentID:          parentID,
		evidence.AttrAgentRole:              string(evidence.AgentRoleChild),
		evidence.AttrAgentAttributionMethod: string(evidence.MethodNativeHarness),
	})
}

// TestCheckAgentsLegacyZeroAgents asserts a session with no agent events verifies
// exactly as before: tracking "none", valid, verdict-neutral.
func TestCheckAgentsLegacyZeroAgents(t *testing.T) {
	ok, facets, _ := checkAgents(agentsTestSession, []record{
		agentRec(1, evidence.EventSessionStarted, evidence.ChannelController, nil),
	})
	if !ok {
		t.Error("legacy zero-agent session should be ok")
	}
	if facets.tracking != "none" || facets.count != 0 || !facets.hierarchyValid {
		t.Errorf("facets = %+v, want tracking none, count 0, valid", facets)
	}
}

func TestCheckAgentsMalformedOnlyLifecycleIsTrackedAndInvalid(t *testing.T) {
	tests := []struct {
		name   string
		record record
	}{
		{
			name:   "start without id",
			record: agentRec(1, evidence.EventAgentStarted, evidence.ChannelWorkload, nil),
		},
		{
			name:   "completion without registration",
			record: agentCompletedRec(1, evidence.ChannelWorkload, "ag-never-started"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, facets, detail := checkAgents(agentsTestSession, []record{tt.record})
			if ok || facets.hierarchyValid || facets.tracking != "tracked" {
				t.Fatalf("ok/facets = %t/%+v, want tracked invalid lifecycle; detail=%q", ok, facets, detail)
			}
			if strings.Contains(detail, "legacy session") {
				t.Fatalf("malformed lifecycle was classified as legacy: %q", detail)
			}
		})
	}
}

// TestCheckAgentsHappyPath is a well-formed Primary + one child, both closed.
func TestCheckAgentsHappyPath(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	records := []record{
		primaryStartedRec(1, nil),
		childStartedRec(2, "task-1", primaryID),
		agentCompletedRec(3, evidence.ChannelWorkload, evidence.ChildAgentID(agentsTestSession, "task-1")),
		agentCompletedRec(4, evidence.ChannelController, primaryID),
	}
	ok, facets, detail := checkAgents(agentsTestSession, records)
	if !ok {
		t.Errorf("well-formed hierarchy rejected: %s", detail)
	}
	if facets.tracking != "tracked" || facets.count != 2 || !facets.hierarchyValid {
		t.Errorf("facets = %+v, want tracked/2/valid", facets)
	}
}

// TestCheckAgentsNestedChainIsDepthGeneric pins that the ownership invariants are
// stated over the parent graph, not over "child of the Primary": a grandchild
// naming another child as its parent verifies exactly like a flat one, and the
// registration order that arrives — a grandchild ahead of its parent, which a
// backgrounded spawn produces — does not matter, because the checks are set-based
// (ownership invariant 8). Claude Code's SubagentStart hook supplies no parent, so
// the guest cannot emit this shape today (invariant 4); the check is the standing
// guarantee that reconstructing depth from spawn edges would not need verifier
// surgery to be accepted.
func TestCheckAgentsNestedChainIsDepthGeneric(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	orchestratorID := evidence.ChildAgentID(agentsTestSession, "orchestrator-1")
	grandchildID := evidence.ChildAgentID(agentsTestSession, "grandchild-1")
	records := []record{
		primaryStartedRec(1, nil),
		childStartedRec(2, "grandchild-1", orchestratorID),
		childStartedRec(3, "orchestrator-1", primaryID),
		agentCompletedRec(4, evidence.ChannelWorkload, grandchildID),
		agentCompletedRec(5, evidence.ChannelWorkload, orchestratorID),
		agentCompletedRec(6, evidence.ChannelController, primaryID),
	}
	ok, facets, detail := checkAgents(agentsTestSession, records)
	if !ok {
		t.Errorf("depth-2 hierarchy rejected: %s", detail)
	}
	if facets.count != 3 || !facets.hierarchyValid || facets.openChildren != 0 {
		t.Errorf("facets = %+v, want 3 agents, valid, no open children", facets)
	}
}

// TestCheckAgentsNestedChainAnomalies asserts the anomaly paths stay armed at
// depth: a grandchild whose parent was never registered is still caught, and a
// two-child parent cycle that never touches the Primary is still caught. Both are
// INCOMPLETE-shaped, never TAMPER.
func TestCheckAgentsNestedChainAnomalies(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	orchestratorID := evidence.ChildAgentID(agentsTestSession, "orchestrator-1")
	tests := []struct {
		name    string
		records []record
		want    string
	}{
		{
			name: "grandchild names an unregistered parent",
			records: []record{
				primaryStartedRec(1, nil),
				childStartedRec(2, "grandchild-1", orchestratorID),
				agentCompletedRec(3, evidence.ChannelWorkload, evidence.ChildAgentID(agentsTestSession, "grandchild-1")),
				agentCompletedRec(4, evidence.ChannelController, primaryID),
			},
			want: "names unknown parent",
		},
		{
			name: "two children parent each other, never reaching the Primary",
			records: []record{
				primaryStartedRec(1, nil),
				childStartedRec(2, "a", evidence.ChildAgentID(agentsTestSession, "b")),
				childStartedRec(3, "b", evidence.ChildAgentID(agentsTestSession, "a")),
				agentCompletedRec(4, evidence.ChannelWorkload, evidence.ChildAgentID(agentsTestSession, "a")),
				agentCompletedRec(5, evidence.ChannelWorkload, evidence.ChildAgentID(agentsTestSession, "b")),
				agentCompletedRec(6, evidence.ChannelController, primaryID),
			},
			want: "has a cycle through",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, facets, detail := checkAgents(agentsTestSession, tt.records)
			if ok || facets.hierarchyValid {
				t.Fatalf("ok/facets = %t/%+v, want the anomaly reported", ok, facets)
			}
			if !strings.Contains(detail, tt.want) {
				t.Errorf("detail = %q, want it to contain %q", detail, tt.want)
			}
		})
	}
}

func TestCheckAgentsCompletionProducerMustMatchRegistration(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	childID := evidence.ChildAgentID(agentsTestSession, "task-1")
	tests := []struct {
		name            string
		primaryProducer evidence.Channel
		childProducer   evidence.Channel
		wantOK          bool
	}{
		{name: "matching producers", primaryProducer: evidence.ChannelController, childProducer: evidence.ChannelWorkload, wantOK: true},
		{name: "primary closed by workload", primaryProducer: evidence.ChannelWorkload, childProducer: evidence.ChannelWorkload},
		{name: "child closed by controller", primaryProducer: evidence.ChannelController, childProducer: evidence.ChannelController},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := []record{
				primaryStartedRec(1, nil),
				childStartedRec(2, "task-1", primaryID),
				agentCompletedRec(3, tt.childProducer, childID),
				agentCompletedRec(4, tt.primaryProducer, primaryID),
			}
			ok, facets, detail := checkAgents(agentsTestSession, records)
			if ok != tt.wantOK || facets.hierarchyValid != tt.wantOK {
				t.Fatalf("ok/facets = %t/%+v, want valid=%t; detail=%q", ok, facets, tt.wantOK, detail)
			}
			if !tt.wantOK && !strings.Contains(detail, "want registration producer") {
				t.Fatalf("producer mismatch detail = %q", detail)
			}
		})
	}
}

// TestCheckAgentsForgedChildID rejects a child whose id does not derive from its
// claimed native_id — the mechanically-detectable forgery.
func TestCheckAgentsForgedChildID(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	forged := agentRec(2, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:       "ag-deadbeefdeadbeef",
		evidence.AttrAgentNativeID: "task-1",
		evidence.AttrAgentParentID: primaryID,
		evidence.AttrAgentRole:     string(evidence.AgentRoleChild),
	})
	records := []record{primaryStartedRec(1, nil), forged, agentCompletedRec(3, evidence.ChannelController, primaryID)}
	ok, facets, _ := checkAgents(agentsTestSession, records)
	if ok || facets.hierarchyValid {
		t.Error("forged child id should be an anomaly")
	}
}

// TestCheckAgentsWorkloadClaimsPrimary rejects a workload agent.started asserting
// role=primary — the repudiation attack the capability gating is designed against.
func TestCheckAgentsWorkloadClaimsPrimary(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	impostor := agentRec(2, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:                evidence.ChildAgentID(agentsTestSession, "task-1"),
		evidence.AttrAgentNativeID:          "task-1",
		evidence.AttrAgentRole:              string(evidence.AgentRolePrimary),
		evidence.AttrAgentAttributionMethod: string(evidence.MethodNativeHarness),
	})
	records := []record{primaryStartedRec(1, nil), impostor, agentCompletedRec(3, evidence.ChannelController, primaryID)}
	ok, _, detail := checkAgents(agentsTestSession, records)
	if ok {
		t.Errorf("workload claiming role=primary should be rejected; detail=%q", detail)
	}
}

func TestCheckAgentsRequiresChildRoleAndPrimaryRootedParent(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	tests := []struct {
		name       string
		role       string
		parentID   string
		wantDetail string
	}{
		{name: "empty role", parentID: primaryID, wantDetail: "want child"},
		{name: "invalid role", role: "worker", parentID: primaryID, wantDetail: "want child"},
		{name: "empty parent", role: string(evidence.AgentRoleChild), wantDetail: "has no parent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childID := evidence.ChildAgentID(agentsTestSession, "task-1")
			child := agentRec(2, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
				evidence.AttrAgentID:       childID,
				evidence.AttrAgentNativeID: "task-1",
				evidence.AttrAgentRole:     tt.role,
				evidence.AttrAgentParentID: tt.parentID,
			})
			records := []record{
				primaryStartedRec(1, nil),
				child,
				agentCompletedRec(3, evidence.ChannelWorkload, childID),
				agentCompletedRec(4, evidence.ChannelController, primaryID),
			}
			ok, facets, detail := checkAgents(agentsTestSession, records)
			if ok || facets.hierarchyValid {
				t.Fatalf("invalid child registration passed: %+v; detail=%q", facets, detail)
			}
			if !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("detail = %q, want %q", detail, tt.wantDetail)
			}
		})
	}
}

// TestCheckAgentsWorkloadCannotClaimControllerMethod asserts the independent
// verifier re-checks the recorder's channel-clobbering: a workload-channel agent
// carrying method=controller (only reachable via a recorder bug, since the recorder
// derives method from the channel) is flagged rather than trusted.
func TestCheckAgentsWorkloadCannotClaimControllerMethod(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	forged := agentRec(2, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:                evidence.ChildAgentID(agentsTestSession, "task-1"),
		evidence.AttrAgentNativeID:          "task-1",
		evidence.AttrAgentParentID:          primaryID,
		evidence.AttrAgentRole:              string(evidence.AgentRoleChild),
		evidence.AttrAgentAttributionMethod: string(evidence.MethodController),
	})
	records := []record{primaryStartedRec(1, nil), forged, agentCompletedRec(3, evidence.ChannelController, primaryID)}
	if ok, _, detail := checkAgents(agentsTestSession, records); ok {
		t.Errorf("workload agent with method=controller must be flagged; detail=%q", detail)
	}
}

// TestCheckAgentsUnknownParentAndCycle covers the two graph anomalies.
func TestCheckAgentsUnknownParentAndCycle(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)

	unknown := []record{
		primaryStartedRec(1, nil),
		childStartedRec(2, "task-1", "ag-nonexistentpppp"),
		agentCompletedRec(3, evidence.ChannelController, primaryID),
	}
	if ok, _, _ := checkAgents(agentsTestSession, unknown); ok {
		t.Error("child naming an unknown parent should be an anomaly")
	}

	// Two children parenting each other form a cycle.
	aID := evidence.ChildAgentID(agentsTestSession, "task-a")
	bID := evidence.ChildAgentID(agentsTestSession, "task-b")
	cycle := []record{
		primaryStartedRec(1, nil),
		childStartedRec(2, "task-a", bID),
		childStartedRec(3, "task-b", aID),
		agentCompletedRec(4, evidence.ChannelController, primaryID),
	}
	if ok, _, _ := checkAgents(agentsTestSession, cycle); ok {
		t.Error("a parent cycle should be an anomaly")
	}
}

// TestCheckAgentsMissingPrimaryClosure flags a Primary that never closed.
func TestCheckAgentsMissingPrimaryClosure(t *testing.T) {
	records := []record{primaryStartedRec(1, nil)} // no agent.completed
	ok, facets, _ := checkAgents(agentsTestSession, records)
	if ok || facets.hierarchyValid {
		t.Error("missing Primary closure should be an anomaly")
	}
}

// TestCheckAgentsDuplicateRegistration collapses identical re-registration but
// flags a conflicting one.
func TestCheckAgentsDuplicateRegistration(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	base := []record{
		primaryStartedRec(1, nil),
		childStartedRec(2, "task-1", primaryID),
		childStartedRec(3, "task-1", primaryID), // exact duplicate → collapses
		agentCompletedRec(4, evidence.ChannelWorkload, evidence.ChildAgentID(agentsTestSession, "task-1")),
		agentCompletedRec(5, evidence.ChannelController, primaryID),
	}
	ok, facets, detail := checkAgents(agentsTestSession, base)
	if !ok {
		t.Errorf("identical re-registration should collapse, not fail: %s", detail)
	}
	if facets.count != 2 {
		t.Errorf("agent count = %d, want 2 (duplicate collapsed)", facets.count)
	}

	// A conflicting re-registration (different parent) is an anomaly.
	childID := evidence.ChildAgentID(agentsTestSession, "task-1")
	conflict := agentRec(3, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:       childID,
		evidence.AttrAgentNativeID: "task-1",
		evidence.AttrAgentParentID: "ag-someotherparent",
		evidence.AttrAgentRole:     string(evidence.AgentRoleChild),
	})
	records := []record{primaryStartedRec(1, nil), childStartedRec(2, "task-1", primaryID), conflict, agentCompletedRec(4, evidence.ChannelController, primaryID)}
	if ok, _, _ := checkAgents(agentsTestSession, records); ok {
		t.Error("conflicting re-registration should be an anomaly")
	}
}

// TestCheckAgentsUnattributedFacetAndGating asserts an unattributed workload tool
// event is only a facet under the v0.1 self_reported declaration, but flips the
// verdict once a category is declared `strong`.
func TestCheckAgentsUnattributedFacetAndGating(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	unlabeledTool := agentRec(2, evidence.EventToolRequested, evidence.ChannelWorkload, map[string]any{
		evidence.AttrEvidenceClass: string(evidence.ClassHarnessObserved),
	})
	closeP := agentCompletedRec(3, evidence.ChannelController, primaryID)

	// self_reported tool: unattributed is a facet, not a gate.
	selfReported := []record{primaryStartedRec(1, map[string]string{evidence.CategoryTool: string(evidence.StrengthSelfReported)}), unlabeledTool, closeP}
	ok, facets, detail := checkAgents(agentsTestSession, selfReported)
	if !ok {
		t.Errorf("unattributed tool under self_reported must not gate: %s", detail)
	}
	if facets.unattributed != 1 {
		t.Errorf("unattributed count = %d, want 1", facets.unattributed)
	}

	// strong tool: the same unattributed event now flips the verdict.
	strong := []record{primaryStartedRec(1, map[string]string{evidence.CategoryTool: string(evidence.StrengthStrong)}), unlabeledTool, closeP}
	if ok, _, _ := checkAgents(agentsTestSession, strong); ok {
		t.Error("unattributed tool under a strong declaration should gate to INCOMPLETE")
	}
}

// TestCheckAgentsLivenessFacet asserts a registered child that witnesses no
// non-lifecycle event (the "narrated agent, no witnessed activity" decoy shape) is
// counted and surfaced, but never gates the verdict: the sibling that did emit a
// tool event under its own id is not counted, and the Primary is always excluded
// (its own direct tool calls carry no agent.id by invariant 9).
func TestCheckAgentsLivenessFacet(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	activeID := evidence.ChildAgentID(agentsTestSession, "task-active")
	// A tool event witnessed under the active child's id — this is its "activity".
	activeTool := agentRec(4, evidence.EventToolRequested, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:       activeID,
		evidence.AttrEvidenceClass: string(evidence.ClassHarnessObserved),
	})
	records := []record{
		primaryStartedRec(1, nil),
		childStartedRec(2, "task-active", primaryID),
		childStartedRec(3, "task-decoy", primaryID), // registered, but never witnessed acting
		activeTool,
		agentCompletedRec(5, evidence.ChannelWorkload, activeID),
		agentCompletedRec(6, evidence.ChannelWorkload, evidence.ChildAgentID(agentsTestSession, "task-decoy")),
		agentCompletedRec(7, evidence.ChannelController, primaryID),
	}
	ok, facets, detail := checkAgents(agentsTestSession, records)
	if !ok {
		t.Errorf("liveness is a plausibility facet and must not gate: %s", detail)
	}
	if facets.noActivity != 1 {
		t.Errorf("agents-without-activity = %d, want 1 (only the decoy child)", facets.noActivity)
	}
	if !strings.Contains(detail, "1 child agent(s) with no witnessed activity") {
		t.Errorf("detail must surface the liveness facet, got %q", detail)
	}
}

// TestCheckAgentsPrimaryAttributedToolActivity pins the shape the tool hooks now
// emit for the harness main loop: the call carries the controller-minted Primary's
// own agent.id instead of nothing. It must verify clean end to end — invariant 9 is
// satisfied because the id is positively identified (0 unattributed), the id is
// registered because the controller emitted the Primary's own agent.started (0
// unregistered activity), and the hierarchy stays valid alongside a normal child.
func TestCheckAgentsPrimaryAttributedToolActivity(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	childID := evidence.ChildAgentID(agentsTestSession, "task-1")
	workloadTool := func(seq int64, name, agentID string) record {
		return agentRec(seq, name, evidence.ChannelWorkload, map[string]any{
			evidence.AttrAgentID:       agentID,
			evidence.AttrEvidenceClass: string(evidence.ClassHarnessObserved),
		})
	}
	records := []record{
		primaryStartedRec(1, map[string]string{evidence.CategoryTool: string(evidence.StrengthSelfReported)}),
		workloadTool(2, evidence.EventToolRequested, primaryID),
		workloadTool(3, evidence.EventToolCompleted, primaryID),
		childStartedRec(4, "task-1", primaryID),
		workloadTool(5, evidence.EventToolRequested, childID),
		agentCompletedRec(6, evidence.ChannelWorkload, childID),
		agentCompletedRec(7, evidence.ChannelController, primaryID),
	}
	ok, facets, detail := checkAgents(agentsTestSession, records)
	if !ok || !facets.hierarchyValid {
		t.Fatalf("primary-attributed tool activity rejected: %+v; detail=%q", facets, detail)
	}
	if facets.unattributed != 0 {
		t.Errorf("unattributed = %d, want 0 (the Primary's own calls now carry its id)", facets.unattributed)
	}
	if facets.unregisteredActivity != 0 {
		t.Errorf("unregistered activity = %d, want 0 (the controller registers the Primary)", facets.unregisteredActivity)
	}
	if facets.noActivity != 0 {
		t.Errorf("agents-without-activity = %d, want 0", facets.noActivity)
	}
}

// TestCheckAgentsHookLineageReconciliation asserts the Narration↔Observation join:
// a hook-reported pid the kernel witnessed is anchored, one it never saw is
// unanchored, and — because process attribution is lineage-scoped, not strong — an
// unanchored pid is a surfaced facet, never a gate.
func TestCheckAgentsHookLineageReconciliation(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	// The kernel (guest_supervisor) independently witnesses the hook process at pid
	// 1938 — the Observation track the workload cannot forge.
	kernelExec := agentRec(2, evidence.EventProcessExecuted, evidence.ChannelGuestSupervisor, map[string]any{
		evidence.AttrProcessPID: int64(1938),
	})
	// An anchored child: its hook self-reports the witnessed pid 1938.
	anchored := agentRec(3, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:       evidence.ChildAgentID(agentsTestSession, "task-anchored"),
		evidence.AttrAgentNativeID: "task-anchored",
		evidence.AttrAgentParentID: primaryID,
		evidence.AttrAgentRole:     string(evidence.AgentRoleChild),
		evidence.AttrProcessPID:    int64(1938),
	})
	// An unanchored child: its hook self-reports pid 9999, which the kernel never
	// witnessed — self-reported process identity with no observational backing.
	unanchored := agentRec(4, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:       evidence.ChildAgentID(agentsTestSession, "task-orphan"),
		evidence.AttrAgentNativeID: "task-orphan",
		evidence.AttrAgentParentID: primaryID,
		evidence.AttrAgentRole:     string(evidence.AgentRoleChild),
		evidence.AttrProcessPID:    int64(9999),
	})
	records := []record{
		primaryStartedRec(1, nil),
		kernelExec,
		anchored,
		unanchored,
		agentCompletedRec(5, evidence.ChannelWorkload, evidence.ChildAgentID(agentsTestSession, "task-anchored")),
		agentCompletedRec(6, evidence.ChannelWorkload, evidence.ChildAgentID(agentsTestSession, "task-orphan")),
		agentCompletedRec(7, evidence.ChannelController, primaryID),
	}
	ok, facets, detail := checkAgents(agentsTestSession, records)
	if !ok {
		t.Errorf("lineage reconciliation must not gate the verdict: %s", detail)
	}
	if facets.hookAnchored != 1 {
		t.Errorf("anchored = %d, want 1 (pid 1938 was kernel-witnessed)", facets.hookAnchored)
	}
	if facets.hookUnanchored != 1 {
		t.Errorf("unanchored = %d, want 1 (pid 9999 was never witnessed)", facets.hookUnanchored)
	}
	if !strings.Contains(detail, "1 hook process(es) unanchored") {
		t.Errorf("detail must surface the unanchored hook process, got %q", detail)
	}
}

func TestReconcileHookProcessesAnchorsOutOfRangeUnambiguousEvidence(t *testing.T) {
	records := []record{
		agentRec(2, evidence.EventProcessExecuted, evidence.ChannelGuestSupervisor, map[string]any{
			evidence.AttrProcessPID: int64(1938),
		}),
		agentRec(1, evidence.EventToolRequested, evidence.ChannelWorkload, map[string]any{
			evidence.AttrProcessPID: int64(1938),
		}),
	}

	anchored, unanchored := reconcileHookProcesses(records)
	if anchored != 1 || unanchored != 0 {
		t.Fatalf("anchored/unanchored = %d/%d, want 1/0", anchored, unanchored)
	}
}

func TestReconcileHookProcessesDoesNotAnchorWithoutCandidate(t *testing.T) {
	records := []record{
		agentRec(3, evidence.EventToolRequested, evidence.ChannelWorkload, map[string]any{
			evidence.AttrProcessPID: int64(1938),
		}),
	}

	anchored, unanchored := reconcileHookProcesses(records)
	if anchored != 0 || unanchored != 1 {
		t.Fatalf("anchored/unanchored = %d/%d, want 0/1", anchored, unanchored)
	}
}

func TestReconcileHookProcessesTreatsReusedPIDAsAmbiguous(t *testing.T) {
	records := []record{
		agentRec(1, evidence.EventProcessExecuted, evidence.ChannelGuestSupervisor, map[string]any{
			evidence.AttrProcessPID: int64(1938), evidence.AttrProcessExecID: "first",
		}),
		agentRec(2, evidence.EventToolRequested, evidence.ChannelWorkload, map[string]any{
			evidence.AttrProcessPID: int64(1938),
		}),
		agentRec(3, evidence.EventProcessExited, evidence.ChannelGuestSupervisor, map[string]any{
			evidence.AttrProcessPID: int64(1938), evidence.AttrProcessExecID: "first",
		}),
		agentRec(4, evidence.EventProcessExecuted, evidence.ChannelGuestSupervisor, map[string]any{
			evidence.AttrProcessPID: int64(1938), evidence.AttrProcessExecID: "second",
		}),
		agentRec(5, evidence.EventToolRequested, evidence.ChannelWorkload, map[string]any{
			evidence.AttrProcessPID: int64(1938),
		}),
	}

	anchored, unanchored := reconcileHookProcesses(records)
	if anchored != 0 || unanchored != 1 {
		t.Fatalf("anchored/unanchored = %d/%d, want 0/1", anchored, unanchored)
	}
}

func TestReconcileHookProcessesDeduplicatesOneIncarnation(t *testing.T) {
	records := []record{
		agentRec(1, evidence.EventProcessCreated, evidence.ChannelGuestSupervisor, map[string]any{
			evidence.AttrProcessPID: int64(1938), evidence.AttrProcessExecID: "hook",
		}),
		agentRec(2, evidence.EventProcessExecuted, evidence.ChannelGuestSupervisor, map[string]any{
			evidence.AttrProcessPID: int64(1938), evidence.AttrProcessExecID: "hook",
		}),
		agentRec(3, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
			evidence.AttrProcessPID: int64(1938),
		}),
		agentRec(4, evidence.EventToolRequested, evidence.ChannelWorkload, map[string]any{
			evidence.AttrProcessPID: int64(1938),
		}),
	}

	anchored, unanchored := reconcileHookProcesses(records)
	if anchored != 1 || unanchored != 0 {
		t.Fatalf("anchored/unanchored = %d/%d, want 1/0", anchored, unanchored)
	}
}

// TestCheckAgentsEmptyNativeIDForged asserts the child id-derivation check runs even
// when native_id is empty. The previous native_id-guarded form let a direct
// /v1/events POST omit native_id and present an arbitrary agent.id that no
// derivation ever constrained; the unconditional check closes that loophole.
func TestCheckAgentsEmptyNativeIDForged(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	// A workload child with no native_id and an id that derives from nothing.
	forged := agentRec(2, evidence.EventAgentStarted, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:       "ag-deadbeefdeadbeef",
		evidence.AttrAgentParentID: primaryID,
		evidence.AttrAgentRole:     string(evidence.AgentRoleChild),
		// native_id deliberately omitted
	})
	records := []record{primaryStartedRec(1, nil), forged, agentCompletedRec(3, evidence.ChannelController, primaryID)}
	ok, facets, detail := checkAgents(agentsTestSession, records)
	if ok || facets.hierarchyValid {
		t.Errorf("child with empty native_id and arbitrary id must be an anomaly; detail=%q", detail)
	}
	if !strings.Contains(detail, "does not match the derivation") {
		t.Errorf("empty native_id must trip the derivation check specifically, got %q", detail)
	}
}

// TestCheckAgentsOpenChildGates asserts a registered child with no
// agent.completed is counted, surfaced, and fails hierarchy verification.
func TestCheckAgentsOpenChildGates(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	records := []record{
		primaryStartedRec(1, nil),
		childStartedRec(2, "task-open", primaryID), // started, never closed
		agentCompletedRec(3, evidence.ChannelController, primaryID),
	}
	ok, facets, detail := checkAgents(agentsTestSession, records)
	if ok || facets.hierarchyValid {
		t.Errorf("an unclosed child must fail hierarchy verification: %s", detail)
	}
	if facets.openChildren != 1 {
		t.Errorf("open children = %d, want 1", facets.openChildren)
	}
	if !strings.Contains(detail, "1 child agent(s) never closed") {
		t.Errorf("detail must surface the open-child facet, got %q", detail)
	}
}

// TestCheckAgentsUnregisteredActivityFacet asserts a workload event tagged with an
// agent.id that no agent.started ever registered is counted and surfaced, but never
// gates: the id is self_reported either way, so an unregistered tag forges no trust.
func TestCheckAgentsUnregisteredActivityFacet(t *testing.T) {
	primaryID := evidence.PrimaryAgentID(agentsTestSession)
	orphanTool := agentRec(2, evidence.EventToolRequested, evidence.ChannelWorkload, map[string]any{
		evidence.AttrAgentID:       "ag-neverregistered0",
		evidence.AttrEvidenceClass: string(evidence.ClassHarnessObserved),
	})
	records := []record{primaryStartedRec(1, nil), orphanTool, agentCompletedRec(3, evidence.ChannelController, primaryID)}
	ok, facets, detail := checkAgents(agentsTestSession, records)
	if !ok {
		t.Errorf("unregistered-id activity is a facet and must not gate: %s", detail)
	}
	if facets.unregisteredActivity != 1 {
		t.Errorf("unregistered activity = %d, want 1", facets.unregisteredActivity)
	}
	if !strings.Contains(detail, "1 event(s) tagged with an unregistered agent id") {
		t.Errorf("detail must surface the unregistered-activity facet, got %q", detail)
	}
}
