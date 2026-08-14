package view

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"boxedai/internal/evidence"
)

// hiddenTimelineAttrs are attrs already shown as their own column (or pure
// bookkeeping) and so are omitted from the "key-attrs" tail of a timeline line.
var hiddenTimelineAttrs = map[string]bool{
	evidence.AttrSchemaVersion:  true,
	evidence.AttrEventID:        true,
	evidence.AttrSequence:       true,
	evidence.AttrSessionID:      true,
	evidence.AttrEvidenceClass:  true,
	evidence.AttrProducer:       true,
	evidence.AttrMonotonicNS:    true,
	evidence.AttrPolicyDigest:   true,
	evidence.AttrOutcome:        true,
	evidence.AttrActionID:       true,
	evidence.AttrParentActionID: true,
	evidence.AttrVMID:           true, // constant per VM; no signal in a session-scoped timeline
	"process.parent_exec_id":    true, // ~90 chars of base64/line; guest/agent-owned key, no exported evidence.Attr* constant
}

// maxToolInputDisplay caps how much of harness.tool.input is shown per
// timeline line. It is captured up to 4096 bytes (guest/agent/hooks.go
// maxHookInputExcerpt), which is unreadable inline for something like a
// Write tool call that renders a whole file into one attr.
const maxToolInputDisplay = 200

// guestAgentBinaryPath is the guest supervisor's own binary path (installed
// by internal/vm/provision.go). --agent-activity drops process.executed rows
// for this binary: they are hook subprocesses observing the audit pipeline
// itself, and the paired tool.* events already carry that information.
const guestAgentBinaryPath = "/usr/local/bin/boxedai-guest-agent"

// Timeline rebuilds the projection and writes one line per matching event to
// w, in ascending sequence order:
//
//	<seq> <ts> [<CLASS-BADGE>] <name> <outcome> <key-attrs>
func Timeline(sessionDir string, filter Filter, w io.Writer) error {
	db, err := Rebuild(sessionDir)
	if err != nil {
		return err
	}
	defer db.Close()

	// baseFilter is the unfiltered baseline used only to size the "showing N
	// of M events" trailer: same Name/Class/Since constraints as filter, but
	// without the noise exclusion or --agent-activity preset.
	baseFilter := filter
	baseFilter.ExcludeNames = nil
	baseFilter.AgentActivity = false
	allRows, err := queryEvents(db, baseFilter)
	if err != nil {
		return err
	}

	rows, err := queryEvents(db, filter)
	if err != nil {
		return err
	}
	if filter.AgentActivity {
		var filtered []eventRow
		for _, row := range rows {
			if !isGuestAgentBinaryExec(row) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}

	for _, row := range rows {
		if _, err := fmt.Fprintln(w, formatTimelineLine(row)); err != nil {
			return fmt.Errorf("view: write timeline: %w", err)
		}
	}

	if trailer := timelineTrailer(rows, allRows); trailer != "" {
		if _, err := fmt.Fprintln(w, trailer); err != nil {
			return fmt.Errorf("view: write timeline trailer: %w", err)
		}
	}
	return nil
}

// isGuestAgentBinaryExec reports whether row is a process.executed event for
// the guest agent's own binary — either a direct exec (process.binary is the
// guest agent path) or Claude Code's hook shell wrapper (process.binary is
// /bin/sh with process.argv containing "-c '/usr/local/bin/boxedai-guest-agent
// lefthook|righthook'"). Matching on the full path in argv, not just the
// program name, avoids false positives on unrelated commands that merely
// mention "boxedai-guest-agent".
func isGuestAgentBinaryExec(row eventRow) bool {
	if row.Name != evidence.EventProcessExecuted {
		return false
	}
	var attrs map[string]any
	if err := json.Unmarshal([]byte(row.AttrsJSON), &attrs); err != nil {
		return false
	}
	if bin, _ := attrs["process.binary"].(string); bin == guestAgentBinaryPath {
		return true
	}
	argv, _ := attrs["process.argv"].(string)
	return strings.Contains(argv, guestAgentBinaryPath)
}

// timelineTrailer summarizes how many events were hidden relative to the
// unfiltered baseline (same Name/Class/Since constraints, no noise exclusion
// or --agent-activity preset), or "" if nothing was hidden. When exactly one
// event name accounts for every hidden row (the common default-hiding case),
// it is named; otherwise the count is reported generically.
func timelineTrailer(shown, all []eventRow) string {
	if len(shown) >= len(all) {
		return ""
	}
	shownSeqs := make(map[int64]bool, len(shown))
	for _, r := range shown {
		shownSeqs[r.Seq] = true
	}
	counts := map[string]int{}
	hidden := 0
	for _, r := range all {
		if !shownSeqs[r.Seq] {
			counts[r.Name]++
			hidden++
		}
	}
	if len(counts) == 1 {
		for name, n := range counts {
			return fmt.Sprintf("showing %d of %d events (%d %s hidden; --all to show)", len(shown), len(all), n, name)
		}
	}
	return fmt.Sprintf("showing %d of %d events (%d hidden; --all to show)", len(shown), len(all), hidden)
}

// formatTimelineLine renders one events row as a single timeline line.
func formatTimelineLine(row eventRow) string {
	outcome := row.Outcome
	if outcome == "" {
		outcome = "-"
	}
	line := fmt.Sprintf("%d %s [%s] %s %s", row.Seq, row.TS, classBadge(row.Class), row.Name, outcome)
	if row.Body != "" {
		line += " — " + row.Body
	}
	if attrs := keyAttrsSummary(row.AttrsJSON); attrs != "" {
		line += " | " + attrs
	}
	return line
}

// keyAttrsSummary renders the non-bookkeeping attrs of a projected row as a
// sorted "key=value key2=value2" string for compact display.
func keyAttrsSummary(attrsJSON string) string {
	var attrs map[string]any
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
		return ""
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		if hiddenTimelineAttrs[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, displayAttrValue(k, attrs[k])))
	}
	return strings.Join(parts, " ")
}

// displayAttrValue returns v as-is, except harness.tool.input is truncated to
// maxToolInputDisplay chars with an ellipsis marker so one tool call (e.g. a
// Write with a whole file as input) can't dominate a timeline line.
func displayAttrValue(key string, v any) any {
	if key != "harness.tool.input" {
		return v
	}
	s, ok := v.(string)
	if !ok {
		return v
	}
	r := []rune(s)
	if len(r) <= maxToolInputDisplay {
		return v
	}
	return string(r[:maxToolInputDisplay]) + "..."
}
