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
)

// Custom attribute keys for hook-capture evidence, following the existing
// "namespace.field" convention (see events.go).
const (
	attrToolName              = "tool.name"
	attrHarnessToolUseID      = "harness.tool_use_id"
	attrHarnessPermissionMode = "harness.permission_mode"
	attrHarnessToolInput      = "harness.tool.input"
	attrHarnessResponseBytes  = "harness.tool.response_bytes"
)

// hookInput is the JSON Claude Code writes to a PreToolUse/PostToolUse hook's
// stdin. Only the fields BoxedAi records are declared here; encoding/json
// ignores the rest, and every field is itself optional so a harness version
// skew never breaks capture. ToolResponse is only ever populated on
// PostToolUse (righthook).
type hookInput struct {
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	ToolUseID      string          `json:"tool_use_id"`
	PermissionMode string          `json:"permission_mode"`
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

	ev := newHookEvent(mode == "righthook", in)
	if err := NewEventClient(brokerURL, token).Submit([]evidence.Event{ev}); err != nil {
		fmt.Fprintf(os.Stderr, "agent: %s: submit event: %v\n", mode, err)
		return 0
	}
	return 0
}

// newHookEvent builds the tool.requested (lefthook) / tool.completed
// (righthook) event per DESIGN.md "Harness hook capture". Hook events are
// class harness_observed: honest but self-reported, since they originate
// inside the distrusted workload, never authenticated identity.
func newHookEvent(completed bool, in hookInput) evidence.Event {
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

	return evidence.Event{
		Name:     name,
		Class:    evidence.ClassHarnessObserved,
		ActionID: in.ToolUseID,
		Outcome:  outcome,
		Body:     hookBody(completed, in.ToolName, in.ToolInput),
		Attrs:    attrs,
	}
}

// hookBody renders the short human-readable summary. Bash commands are shown
// verbatim (workspace command lines are not secrets by policy, per
// DESIGN.md); every other tool gets a generic summary naming the tool.
func hookBody(completed bool, toolName string, toolInput json.RawMessage) string {
	if toolName == "Bash" {
		if cmd, ok := bashCommand(toolInput); ok {
			return "bash: " + truncateRunes(cmd, maxBashCommandChars)
		}
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
