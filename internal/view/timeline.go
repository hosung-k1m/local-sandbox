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
}

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

	rows, err := queryEvents(db, filter)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(w, formatTimelineLine(row)); err != nil {
			return fmt.Errorf("view: write timeline: %w", err)
		}
	}
	return nil
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
		parts = append(parts, fmt.Sprintf("%s=%v", k, attrs[k]))
	}
	return strings.Join(parts, " ")
}
