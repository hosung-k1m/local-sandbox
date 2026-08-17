package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"boxedai/internal/evidence"
)

// Limits for the hook JSON a harness feeds on stdin: the workload is
// distrusted, so stdin can never be assumed small, and the stored excerpt/
// command text stay bounded even though the content digest still covers the
// full bytes (DESIGN.md "Harness hook capture — lefthook / righthook").
const (
	maxHookStdin        = 8 << 20 // 8 MiB
	maxHookInputExcerpt = 4096    // bytes
	maxBashCommandChars = 300     // runes
	maxHookFieldChars   = 1024    // runes; bound for harness.* context strings
)

// Custom attribute keys for hook-capture evidence, following the existing
// "namespace.field" convention (see events.go).
const (
	attrToolName              = "tool.name"
	attrHarnessToolUseID      = "harness.tool_use_id"
	attrHarnessPermissionMode = "harness.permission_mode"
	attrHarnessToolInput      = "harness.tool.input"
	attrHarnessResponseBytes  = "harness.tool.response_bytes"
	attrHarnessSessionID      = "harness.session_id"
	attrHarnessTranscriptPath = "harness.transcript_path"
	attrHarnessCwd            = "harness.cwd"
	attrHarnessHookEvent      = "harness.hook_event_name"
)

// Claude Code hook_event_name values the agenthook dispatches on.
const (
	hookSubagentStart = "SubagentStart"
	hookSubagentStop  = "SubagentStop"
)

// hookInput is the JSON Claude Code writes to a hook's stdin. Only the fields
// BoxedAi records are declared here; encoding/json ignores the rest, and every
// field is itself optional so a harness version skew never breaks capture.
// ToolResponse is only ever populated on PostToolUse (righthook); AgentID/
// AgentType are present when the hook fires inside a subagent (Claude Code
// v2.1.69+) or on the SubagentStart/SubagentStop lifecycle hooks.
type hookInput struct {
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	ToolUseID      string          `json:"tool_use_id"`
	PermissionMode string          `json:"permission_mode"`
	// Harness-supplied context, recorded as bounded harness.* provenance.
	SessionID      string `json:"session_id"`
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	HookEventName  string `json:"hook_event_name"`
	// Acting-agent identity (self-reported; the BoxedAi id is derived from it).
	AgentID   string `json:"agent_id"`
	AgentType string `json:"agent_type"`
}

// runHook is the guest-side half of Claude Code's PreToolUse ("lefthook")
// and PostToolUse ("righthook") hooks: read the hook JSON from stdin, build
// one workload-channel evidence event, and submit it to the broker with the
// workload token. It ALWAYS returns 0 — a hook that fails closed would break
// every tool call in the session, so missing env, malformed stdin, and
// broker failures are all written to stderr (Claude Code folds this into its
// own debug log) and otherwise swallowed, per DESIGN.md "Hooks fail open".
func runHook(mode string, stdin io.Reader) int {
	brokerURL := os.Getenv(brokerURLEnv)
	token := os.Getenv(workloadTokenEnv)
	if brokerURL == "" || token == "" {
		fmt.Fprintf(os.Stderr, "agent: %s: missing %s or %s\n", mode, brokerURLEnv, workloadTokenEnv)
		return 0
	}

	body, err := io.ReadAll(io.LimitReader(stdin, maxHookStdin))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: %s: read hook stdin: %v\n", mode, err)
		return 0
	}

	var in hookInput
	if err := json.Unmarshal(body, &in); err != nil {
		fmt.Fprintf(os.Stderr, "agent: %s: parse hook input: %v\n", mode, err)
		return 0
	}

	ev := newHookEvent(mode == "righthook", in, os.Getenv(sessionIDEnv), os.Getenv(agentIDEnv))
	if err := NewEventClient(brokerURL, token).Submit([]evidence.Event{ev}); err != nil {
		fmt.Fprintf(os.Stderr, "agent: %s: submit event: %v\n", mode, err)
		return 0
	}
	return 0
}

// runAgentHook is the guest-side half of Claude Code's SubagentStart/SubagentStop
// hooks (wired to `boxedai-guest-agent agenthook`). It registers a Child Agent on
// SubagentStart and closes it on SubagentStop, deriving the BoxedAi child id from
// the harness-native agent_id and naming the controller-minted Primary as parent
// (DESIGN.md "Agent hierarchy and attribution"). Like the tool hooks it ALWAYS
// returns 0 — child-registration failure must never break a subagent — so missing
// env, malformed stdin, and broker failures are logged to stderr and swallowed.
func runAgentHook(stdin io.Reader) int {
	brokerURL := os.Getenv(brokerURLEnv)
	token := os.Getenv(workloadTokenEnv)
	if brokerURL == "" || token == "" {
		fmt.Fprintf(os.Stderr, "agent: agenthook: missing %s or %s\n", brokerURLEnv, workloadTokenEnv)
		return 0
	}
	body, err := io.ReadAll(io.LimitReader(stdin, maxHookStdin))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: agenthook: read hook stdin: %v\n", err)
		return 0
	}
	var in hookInput
	if err := json.Unmarshal(body, &in); err != nil {
		fmt.Fprintf(os.Stderr, "agent: agenthook: parse hook input: %v\n", err)
		return 0
	}
	if in.AgentID == "" {
		fmt.Fprintf(os.Stderr, "agent: agenthook: hook input carries no agent_id; skipping\n")
		return 0
	}

	ev, ok := newAgentEvent(in, os.Getenv(sessionIDEnv), os.Getenv(agentIDEnv))
	if !ok {
		fmt.Fprintf(os.Stderr, "agent: agenthook: unhandled hook_event_name %q; skipping\n", in.HookEventName)
		return 0
	}
	if err := NewEventClient(brokerURL, token).Submit([]evidence.Event{ev}); err != nil {
		fmt.Fprintf(os.Stderr, "agent: agenthook: submit event: %v\n", err)
		return 0
	}
	return 0
}

// newHookEvent builds the tool.requested (lefthook) / tool.completed
// (righthook) event per DESIGN.md "Harness hook capture". Hook events are
// class harness_observed: honest but self-reported, since they originate
// inside the distrusted workload, never authenticated identity. bxSessionID is
// the BoxedAi session id (BOXEDAI_SESSION_ID) used to derive the acting agent's
// BoxedAi id from its harness-native agent_id; primaryID is the
// controller-minted Primary Agent id (BOXEDAI_AGENT_ID) that owns the harness
// main loop.
func newHookEvent(completed bool, in hookInput, bxSessionID, primaryID string) evidence.Event {
	name := evidence.EventToolRequested
	if completed {
		name = evidence.EventToolCompleted
	}

	outcome := evidence.OutcomeSuccess
	if completed && toolResponseFailed(in.ToolResponse) {
		outcome = evidence.OutcomeFailure
	}

	attrs := map[string]any{
		attrToolName:                in.ToolName,
		attrHarnessToolInput:        compactCapped(in.ToolInput, maxHookInputExcerpt),
		evidence.AttrContentCapture: string(evidence.CaptureRedacted),
		evidence.AttrCorrelation:    string(evidence.CorrelationNone),
	}
	if in.ToolUseID != "" {
		// Best-effort correlation of requested/completed pairs: self-reported
		// by the harness, never authenticated identity (DESIGN.md).
		attrs[attrHarnessToolUseID] = in.ToolUseID
	}
	if !completed && in.PermissionMode != "" {
		attrs[attrHarnessPermissionMode] = in.PermissionMode
	}
	if completed {
		attrs[evidence.AttrContentDigest] = evidence.SHA256Hex(in.ToolResponse)
		attrs[attrHarnessResponseBytes] = int64(len(in.ToolResponse))
	} else {
		attrs[evidence.AttrContentDigest] = evidence.SHA256Hex(in.ToolInput)
	}
	addCommonHookAttrs(attrs, in)
	// Task spawn narration is lifted into dedicated attrs rather than left inside
	// the harness.tool.input excerpt: Task embeds the full subagent prompt there,
	// which can push the description past the excerpt cap. Display-only — the
	// viewer pairs a spawn with the child it likely started; nothing here claims
	// that linkage on the wire.
	taskDesc, taskSubagentType := taskSpawn(in.ToolName, in.ToolInput)
	if taskDesc != "" {
		attrs[evidence.AttrHarnessTaskDescription] = truncateRunes(taskDesc, maxHookFieldChars)
	}
	if taskSubagentType != "" {
		attrs[evidence.AttrHarnessTaskSubagentType] = truncateRunes(taskSubagentType, maxHookFieldChars)
	}
	// A completed spawn call names the agent it produced. Stamped beside the
	// acting agent below, this is the one harness-declared parent→child edge in
	// the record; the child's own registration cannot carry it.
	if completed {
		if spawned := spawnedAgentID(in.ToolName, in.ToolResponse); spawned != "" {
			attrs[evidence.AttrAgentSpawnedNativeID] = spawned
			attrs[evidence.AttrAgentSpawnedID] = evidence.ChildAgentID(bxSessionID, spawned)
		}
	}

	ev := evidence.Event{
		Name:     name,
		Class:    evidence.ClassHarnessObserved,
		ActionID: in.ToolUseID,
		Outcome:  outcome,
		Body:     hookBody(completed, in.ToolName, in.ToolInput),
		Attrs:    attrs,
	}
	// Attribute the tool to the acting agent. Claude Code tags every hook fired
	// inside a subagent with its agent_id, so a tool event carrying none is the
	// harness main loop's own call and belongs to the Primary — self_reported like
	// every other hook narration (DESIGN.md ownership invariant 9). With no
	// Primary id in the hook environment there is nothing honest to stamp, so the
	// event stays Unattributed Workload. Parenting the action to the agent id lets
	// the viewer nest the tool under its agent.
	switch {
	case in.AgentID != "":
		childID := evidence.ChildAgentID(bxSessionID, in.AgentID)
		attrs[evidence.AttrAgentID] = childID
		attrs[evidence.AttrAgentNativeID] = in.AgentID
		if in.AgentType != "" {
			attrs[evidence.AttrAgentType] = in.AgentType
		}
		ev.ParentActionID = childID
	case primaryID != "":
		// The Primary is controller-minted: it has no harness-native id and no
		// harness-declared type, so only its BoxedAi id is stamped.
		attrs[evidence.AttrAgentID] = primaryID
		ev.ParentActionID = primaryID
	}
	return ev
}

// newAgentEvent builds the agent.started (SubagentStart) or agent.completed
// (SubagentStop) child-registration event, or ok=false for any other hook. The
// BoxedAi child id derives from the harness-native agent_id under bxSessionID; the
// child names the controller-minted Primary (primaryID) as its parent, since the
// hook stdin carries no parent agent id in v0.1 (nested spawns flatten under the
// Primary — a documented self_reported limitation). The event is class
// harness_observed on the workload channel, so the recorder stamps
// native_harness/self_reported; nothing here can present as controller/strong.
func newAgentEvent(in hookInput, bxSessionID, primaryID string) (evidence.Event, bool) {
	childID := evidence.ChildAgentID(bxSessionID, in.AgentID)
	switch in.HookEventName {
	case hookSubagentStart:
		attrs := map[string]any{
			evidence.AttrAgentID:       childID,
			evidence.AttrAgentNativeID: in.AgentID,
			evidence.AttrAgentParentID: primaryID,
			evidence.AttrAgentRole:     string(evidence.AgentRoleChild),
			evidence.AttrAgentHarness:  "claude",
		}
		if in.AgentType != "" {
			attrs[evidence.AttrAgentType] = in.AgentType
		}
		addCommonHookAttrs(attrs, in)
		return evidence.Event{
			Name:           evidence.EventAgentStarted,
			Class:          evidence.ClassHarnessObserved,
			ActionID:       childID,
			ParentActionID: primaryID,
			Outcome:        evidence.OutcomeSuccess,
			Body:           "subagent started: " + in.AgentType,
			Attrs:          attrs,
		}, true
	case hookSubagentStop:
		attrs := map[string]any{
			evidence.AttrAgentID:      childID,
			evidence.AttrAgentOutcome: string(evidence.OutcomeSuccess),
		}
		if in.AgentType != "" {
			attrs[evidence.AttrAgentType] = in.AgentType
		}
		addCommonHookAttrs(attrs, in)
		return evidence.Event{
			Name:     evidence.EventAgentCompleted,
			Class:    evidence.ClassHarnessObserved,
			ActionID: childID,
			Outcome:  evidence.OutcomeSuccess,
			Body:     "subagent completed: " + in.AgentType,
			Attrs:    attrs,
		}, true
	default:
		return evidence.Event{}, false
	}
}

// addCommonHookAttrs stamps the context every hook invocation records: the
// harness-supplied session_id/transcript_path/cwd/hook_event_name (bounded), and
// the hook process's own pid/ppid. Tetragon independently observes the hook binary
// exec at the same pid, so pid/ppid are an offline anchor joining a self-reported
// hook event to a kernel-observed process; audit.correlation stays none because the
// join is derived in verify/view, never claimed on the wire (DESIGN.md).
func addCommonHookAttrs(attrs map[string]any, in hookInput) {
	if in.SessionID != "" {
		attrs[attrHarnessSessionID] = truncateRunes(in.SessionID, maxHookFieldChars)
	}
	if in.TranscriptPath != "" {
		attrs[attrHarnessTranscriptPath] = truncateRunes(in.TranscriptPath, maxHookFieldChars)
	}
	if in.Cwd != "" {
		attrs[attrHarnessCwd] = truncateRunes(in.Cwd, maxHookFieldChars)
	}
	if in.HookEventName != "" {
		attrs[attrHarnessHookEvent] = truncateRunes(in.HookEventName, maxHookFieldChars)
	}
	attrs[evidence.AttrProcessPID] = int64(os.Getpid())
	attrs[evidence.AttrProcessPPID] = int64(os.Getppid())
}

// hookBody renders the short human-readable summary. Bash commands are shown
// verbatim (workspace command lines are not secrets by policy, per
// DESIGN.md), a Task spawn shows the description the harness wrote for it;
// every other tool gets a generic summary naming the tool.
func hookBody(completed bool, toolName string, toolInput json.RawMessage) string {
	if toolName == "Bash" {
		if cmd, ok := bashCommand(toolInput); ok {
			return "bash: " + truncateRunes(cmd, maxBashCommandChars)
		}
	}
	if desc, _ := taskSpawn(toolName, toolInput); desc != "" {
		return "task: " + truncateRunes(desc, maxBashCommandChars)
	}
	body := "harness tool " + toolName
	if completed {
		body += " completed"
	}
	return body
}

// bashCommand extracts tool_input.command when it is present and a JSON
// string. A pointer field distinguishes "absent" from "present but empty" so
// an empty command string still counts as present.
func bashCommand(toolInput json.RawMessage) (string, bool) {
	if len(toolInput) == 0 {
		return "", false
	}
	var decoded struct {
		Command *string `json:"command"`
	}
	if err := json.Unmarshal(toolInput, &decoded); err != nil || decoded.Command == nil {
		return "", false
	}
	return *decoded.Command, true
}

// taskSpawn extracts the spawn tool's narration — the short description the
// harness wrote for the subagent and the subagent type it asked for. Claude Code
// names that tool "Task" in some versions and "Agent" in others, and both are in
// the wild, so both are accepted. Any other tool, malformed tool_input, or absent
// fields yields empty strings, which callers skip silently (hooks fail open, so
// a harness shape change drops the attribute rather than the event).
func taskSpawn(toolName string, toolInput json.RawMessage) (description, subagentType string) {
	if !isSpawnTool(toolName) || len(toolInput) == 0 {
		return "", ""
	}
	var decoded struct {
		Description  string `json:"description"`
		SubagentType string `json:"subagent_type"`
	}
	if err := json.Unmarshal(toolInput, &decoded); err != nil {
		return "", ""
	}
	return decoded.Description, decoded.SubagentType
}

// spawnedAgentID extracts the harness-native id of the agent a completed spawn
// call created, from the PostToolUse tool_response Claude Code returns for the
// Task/Agent tool ("agentId"). It is present on both synchronous completions and
// backgrounded launches (tool_response.status "completed" and "async_launched"
// respectively). The id is capped like every other harness string; any other
// tool, a malformed tool_response, or an absent field yields "", which the caller
// skips silently (hooks fail open, so a harness shape change drops the attribute
// rather than the event).
func spawnedAgentID(toolName string, toolResponse json.RawMessage) string {
	if !isSpawnTool(toolName) || len(toolResponse) == 0 {
		return ""
	}
	var decoded struct {
		AgentID string `json:"agentId"`
	}
	if err := json.Unmarshal(toolResponse, &decoded); err != nil {
		return ""
	}
	return truncateRunes(decoded.AgentID, maxHookFieldChars)
}

// isSpawnTool reports whether toolName is Claude Code's subagent-spawning tool.
// The CLI has shipped it under both names, so a recording can carry either.
func isSpawnTool(toolName string) bool {
	return toolName == "Task" || toolName == "Agent"
}

// truncateRunes caps s at max runes (not bytes) so a multi-byte UTF-8
// sequence is never split.
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// compactCapped renders raw as compact JSON (no insignificant whitespace),
// capped at max bytes. It is a best-effort excerpt for the audit timeline,
// never reparsed, so defensively falling back to the raw bytes on a Compact
// error still produces a bounded string instead of dropping the attribute.
func compactCapped(raw json.RawMessage, max int) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		buf.Reset()
		buf.Write(raw)
	}
	b := buf.Bytes()
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}

// toolResponseFailed reports whether a PostToolUse tool_response marks the
// call as errored or interrupted. Best-effort: a tool_response that is not a
// JSON object (or is absent) is treated as non-failing.
func toolResponseFailed(toolResponse json.RawMessage) bool {
	if len(toolResponse) == 0 {
		return false
	}
	var decoded struct {
		IsError     bool `json:"is_error"`
		Interrupted bool `json:"interrupted"`
	}
	if err := json.Unmarshal(toolResponse, &decoded); err != nil {
		return false
	}
	return decoded.IsError || decoded.Interrupted
}
