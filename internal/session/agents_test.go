package session

import (
	"testing"

	"boxedai/internal/evidence"
)

// TestPrimaryAgentStartedEventClaude asserts the Claude Primary Agent's
// agent.started carries the deterministic id, primary role, session scope, the
// staged-hook settings digest, and the self_reported tool/model capability the
// adapter actually wires — and that it passes producer-side Validate.
func TestPrimaryAgentStartedEventClaude(t *testing.T) {
	id := evidence.PrimaryAgentID("bx-primary-test")
	ev := primaryAgentStartedEvent(id, "claude", harnessSettingsDigest("claude"))

	if ev.Name != evidence.EventAgentStarted {
		t.Errorf("name = %q, want %q", ev.Name, evidence.EventAgentStarted)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// The Primary is the root of the agent action chain: ActionID = its agent id,
	// no parent. Children (ParentActionID = primaryID) nest under it in the viewer.
	if ev.ActionID != id {
		t.Errorf("ActionID = %q, want %q (the Primary is the action-chain root)", ev.ActionID, id)
	}
	if ev.ParentActionID != "" {
		t.Errorf("ParentActionID = %q, want empty (the Primary is the root)", ev.ParentActionID)
	}
	want := map[string]string{
		evidence.AttrAgentID:                                          id,
		evidence.AttrAgentRole:                                        string(evidence.AgentRolePrimary),
		evidence.AttrAgentHarness:                                     "claude",
		evidence.AttrAgentExecutionScope:                              evidence.ScopeSession,
		evidence.AttrAgentSettingsDigest:                              harnessSettingsDigest("claude"),
		evidence.AttrAgentCapabilityPrefix + evidence.CategoryProcess: string(evidence.StrengthLineage),
		evidence.AttrAgentCapabilityPrefix + evidence.CategoryTool:    string(evidence.StrengthSelfReported),
		evidence.AttrAgentCapabilityPrefix + evidence.CategoryModel:   string(evidence.StrengthSelfReported),
		evidence.AttrAgentCapabilityPrefix + evidence.CategoryFile:    string(evidence.StrengthNone),
		evidence.AttrAgentCapabilityPrefix + evidence.CategoryNetwork: string(evidence.StrengthNone),
	}
	for k, v := range want {
		if got, _ := ev.Attrs[k].(string); got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
	// The controller never self-asserts attribution — the recorder derives it.
	if _, ok := ev.Attrs[evidence.AttrAgentAttributionMethod]; ok {
		t.Error("agent.started must not carry a payload attribution method")
	}
}

// TestPrimaryAgentStartedEventExec asserts the exec harness (no hooks, no model
// broker) declares tool and model as unattributed and stamps no settings digest.
func TestPrimaryAgentStartedEventExec(t *testing.T) {
	ev := primaryAgentStartedEvent(evidence.PrimaryAgentID("bx-exec-test"), "exec", harnessSettingsDigest("exec"))
	if _, ok := ev.Attrs[evidence.AttrAgentSettingsDigest]; ok {
		t.Error("exec harness stages no hooks, so agent.started must carry no settings digest")
	}
	for _, cat := range []string{evidence.CategoryTool, evidence.CategoryModel} {
		key := evidence.AttrAgentCapabilityPrefix + cat
		if got, _ := ev.Attrs[key].(string); got != string(evidence.StrengthNone) {
			t.Errorf("exec %q = %q, want none", key, got)
		}
	}
}

// TestAgentCompletedEvent asserts the closure event carries the id and outcome.
func TestAgentCompletedEvent(t *testing.T) {
	ev := agentCompletedEvent("ag-xyz", evidence.OutcomeInterrupted)
	if ev.Name != evidence.EventAgentCompleted {
		t.Errorf("name = %q, want %q", ev.Name, evidence.EventAgentCompleted)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got, _ := ev.Attrs[evidence.AttrAgentID].(string); got != "ag-xyz" {
		t.Errorf("agent.id = %q, want ag-xyz", got)
	}
	if got, _ := ev.Attrs[evidence.AttrAgentOutcome].(string); got != string(evidence.OutcomeInterrupted) {
		t.Errorf("agent.outcome = %q, want interrupted", got)
	}
	// Closure links to the agent's action chain (same ActionID as the start).
	if ev.ActionID != "ag-xyz" {
		t.Errorf("ActionID = %q, want ag-xyz (links to the agent action chain)", ev.ActionID)
	}
}

// TestHarnessSettingsDigest asserts hook-wiring harnesses yield the digest of
// their exact staged config bytes.
func TestHarnessSettingsDigest(t *testing.T) {
	if got, want := harnessSettingsDigest("claude"), evidence.SHA256Hex([]byte(claudeHooksSettingsJSON)); got != want {
		t.Errorf("claude settings digest = %q, want %q", got, want)
	}
	if got, want := harnessSettingsDigest("codex"), evidence.SHA256Hex([]byte(codexHooksJSON)); got != want {
		t.Errorf("codex settings digest = %q, want %q", got, want)
	}
	for _, h := range []string{"exec", "unknown"} {
		if got := harnessSettingsDigest(h); got != "" {
			t.Errorf("%s settings digest = %q, want empty", h, got)
		}
	}
}

// TestPrimaryAgentCapabilities locks the per-harness attribution ceiling: process
// is always lineage-to-session; Claude and Codex self-report tool attribution,
// and model identity; file and
// network never carry a per-agent actor.
func TestPrimaryAgentCapabilities(t *testing.T) {
	claude := primaryAgentCapabilities("claude")
	if claude[evidence.CategoryTool] != evidence.StrengthSelfReported || claude[evidence.CategoryModel] != evidence.StrengthSelfReported {
		t.Errorf("claude tool/model = %q/%q, want self_reported", claude[evidence.CategoryTool], claude[evidence.CategoryModel])
	}
	if caps := primaryAgentCapabilities("codex"); caps[evidence.CategoryTool] != evidence.StrengthSelfReported || caps[evidence.CategoryModel] != evidence.StrengthSelfReported {
		t.Errorf("codex tool/model = %q/%q, want self_reported/self_reported", caps[evidence.CategoryTool], caps[evidence.CategoryModel])
	}
	for _, h := range []string{"exec"} {
		caps := primaryAgentCapabilities(h)
		if caps[evidence.CategoryTool] != evidence.StrengthNone || caps[evidence.CategoryModel] != evidence.StrengthNone {
			t.Errorf("%s tool/model = %q/%q, want none", h, caps[evidence.CategoryTool], caps[evidence.CategoryModel])
		}
	}
	for _, h := range []string{"claude", "codex", "exec"} {
		caps := primaryAgentCapabilities(h)
		if caps[evidence.CategoryProcess] != evidence.StrengthLineage {
			t.Errorf("%s process = %q, want lineage", h, caps[evidence.CategoryProcess])
		}
		if caps[evidence.CategoryFile] != evidence.StrengthNone || caps[evidence.CategoryNetwork] != evidence.StrengthNone {
			t.Errorf("%s file/network = %q/%q, want none", h, caps[evidence.CategoryFile], caps[evidence.CategoryNetwork])
		}
	}
}
