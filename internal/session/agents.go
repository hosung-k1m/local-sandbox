package session

import "boxedai/internal/evidence"

// primaryAgentStartedEvent builds the controller-owned Primary Agent's
// agent.started: its deterministic session-scoped id, role, harness, execution
// scope, the staged hook-settings digest (empty for harnesses with no hooks), and
// the controller-attested per-category attribution capability declaration. The
// recorder stamps method=controller/strength=strong from the authenticated
// channel; nothing here is trusted from a payload (DESIGN.md "Agent hierarchy and
// attribution").
func primaryAgentStartedEvent(agentID, harness, settingsDigest string) evidence.Event {
	attrs := map[string]any{
		evidence.AttrAgentID:             agentID,
		evidence.AttrAgentRole:           string(evidence.AgentRolePrimary),
		evidence.AttrAgentHarness:        harness,
		evidence.AttrAgentExecutionScope: evidence.ScopeSession,
	}
	if settingsDigest != "" {
		attrs[evidence.AttrAgentSettingsDigest] = settingsDigest
	}
	// Declare the adapter's per-category ceiling. Key order does not matter: the
	// recorder sorts attributes for stable output.
	for category, strength := range primaryAgentCapabilities(harness) {
		attrs[evidence.AttrAgentCapabilityPrefix+category] = string(strength)
	}
	return evidence.Event{
		Name: evidence.EventAgentStarted,
		// The Primary is the root of the agent action chain: its ActionID is its own
		// agent id, so hook-registered children (ParentActionID = primaryID) and their
		// tools nest under it in the viewer's action-chain view. No ParentActionID —
		// the Primary is the root (DESIGN.md "Agent hierarchy and attribution").
		ActionID: agentID,
		Outcome:  evidence.OutcomeSuccess,
		Body:     "primary agent started",
		Attrs:    attrs,
	}
}

// agentCompletedEvent builds an agent.completed for the given agent and outcome.
// The controller emits it for the Primary Agent in teardown before session.stopped.
func agentCompletedEvent(agentID string, outcome evidence.Outcome) evidence.Event {
	return evidence.Event{
		Name: evidence.EventAgentCompleted,
		// Closure carries the same ActionID as the start, so it links to the agent's
		// action chain rather than dangling (mirrors the child SubagentStop event).
		ActionID: agentID,
		Outcome:  outcome,
		Body:     "primary agent completed",
		Attrs: map[string]any{
			evidence.AttrAgentID:      agentID,
			evidence.AttrAgentOutcome: string(outcome),
		},
	}
}

// primaryAgentCapabilities declares the strongest per-category attribution the
// harness adapter can carry in v0.1 (DESIGN.md "Per-category attribution
// capability"). The verifier gates the verdict only on categories declared
// `strong` — none today — and reports the rest as facets, so no session is
// spuriously INCOMPLETE while the honest ceiling is self_reported. Declaring the
// weaker ceilings anyway is forward-wiring: a future trusted executor raises a
// category here and the same verifier gates it automatically.
func primaryAgentCapabilities(harness string) map[string]evidence.AttributionStrength {
	caps := map[string]evidence.AttributionStrength{
		// Kernel process truth is uid/session-scoped; in-process subagents have no
		// pid, so process attribution is lineage-to-session, never per-agent.
		evidence.CategoryProcess: evidence.StrengthLineage,
		evidence.CategoryTool:    evidence.StrengthNone,
		evidence.CategoryModel:   evidence.StrengthNone,
		// Scans and nftables log lines carry no per-agent actor.
		evidence.CategoryFile:    evidence.StrengthNone,
		evidence.CategoryNetwork: evidence.StrengthNone,
	}
	// Only the Claude adapter wires per-tool hooks (agent_id) and records model
	// agent-label headers in v0.1; both are self_reported. Codex and exec have
	// neither, so their tool/model stay unattributed.
	if harness == "claude" {
		caps[evidence.CategoryTool] = evidence.StrengthSelfReported
		caps[evidence.CategoryModel] = evidence.StrengthSelfReported
	}
	return caps
}
