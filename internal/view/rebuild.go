package view

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protodelim"

	"boxedai/internal/evidence"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// eventRow is one projected row from the events table.
type eventRow struct {
	Seq            int64
	TS             string
	Name           string
	Class          string
	Producer       string
	ActionID       string
	ParentActionID string
	Outcome        string
	Body           string
	AttrsJSON      string
}

const schemaDDL = `
CREATE TABLE events (
	seq              INTEGER PRIMARY KEY,
	ts               TEXT NOT NULL,
	name             TEXT NOT NULL,
	class            TEXT NOT NULL,
	producer         TEXT NOT NULL,
	action_id        TEXT,
	parent_action_id TEXT,
	outcome          TEXT,
	body             TEXT,
	attrs_json       TEXT NOT NULL
);
CREATE INDEX events_name_idx ON events(name);
CREATE INDEX events_class_idx ON events(class);
`

// Rebuild parses every raw OTLP segment under sessionDir/evidence/segments
// (independent of internal/recorder — protodelim decoding straight off the
// authoritative WAL files) and projects the resulting log records into a fresh
// SQLite database at sessionDir/projection/timeline.sqlite. The projection is
// disposable: it is dropped and rebuilt from the raw segments on every call, so
// the raw segments remain the sole source of truth.
func Rebuild(sessionDir string) (*sql.DB, error) {
	dbPath := filepath.Join(sessionDir, "projection", "timeline.sqlite")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("view: create projection dir: %w", err)
	}
	if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("view: remove stale projection: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("view: open projection db: %w", err)
	}
	if _, err := db.Exec(schemaDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("view: create schema: %w", err)
	}
	if err := projectSegments(db, sessionDir); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// projectSegments decodes every segment-*.otlp file under sessionDir in
// sequence order and inserts one events row per LogRecord, inside a single
// transaction.
func projectSegments(db *sql.DB, sessionDir string) error {
	pattern := filepath.Join(sessionDir, "evidence", "segments", "*.otlp")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("view: glob segments: %w", err)
	}
	// Segment file names are zero-padded (segment-000001.otlp, ...), so lexical
	// order is also sequence order.
	sort.Strings(paths)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("view: begin projection tx: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO events
		(seq, ts, name, class, producer, action_id, parent_action_id, outcome, body, attrs_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("view: prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, path := range paths {
		if err := projectFile(stmt, path); err != nil {
			tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("view: commit projection: %w", err)
	}
	return nil
}

// projectFile decodes one length-delimited OTLP segment file and inserts a row
// per LogRecord via stmt. Each recorder-written frame is a single-record
// LogsData (DESIGN "Recorder" step 2), but this reader tolerates multiple
// ResourceLogs/ScopeLogs/LogRecords per frame defensively.
func projectFile(stmt *sql.Stmt, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("view: open segment %s: %w", path, err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		var data logsv1.LogsData
		err := protodelim.UnmarshalFrom(r, &data)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("view: decode otlp frame in %s: %w", path, err)
		}
		for _, rl := range data.GetResourceLogs() {
			resourceAttrs := kvListToMap(rl.GetResource().GetAttributes())
			for _, sl := range rl.GetScopeLogs() {
				for _, lr := range sl.GetLogRecords() {
					row := recordToRow(resourceAttrs, lr)
					if _, err := stmt.Exec(row.Seq, row.TS, row.Name, row.Class, row.Producer,
						row.ActionID, row.ParentActionID, row.Outcome, row.Body, row.AttrsJSON); err != nil {
						return fmt.Errorf("view: insert event seq %d from %s: %w", row.Seq, path, err)
					}
				}
			}
		}
	}
	return nil
}

// recordToRow flattens one OTLP LogRecord plus its resource-level attributes
// into an eventRow, extracting the audit.* attrs back out of the KeyValue list.
func recordToRow(resourceAttrs map[string]any, lr *logsv1.LogRecord) eventRow {
	attrs := mergeAttrs(resourceAttrs, kvListToMap(lr.GetAttributes()))

	ts := lr.GetTimeUnixNano()
	if ts == 0 {
		ts = lr.GetObservedTimeUnixNano()
	}

	attrsJSON, err := evidence.CanonicalJSON(attrs)
	if err != nil {
		// attrs only ever holds JSON-marshalable scalars (see anyValueToGo), so
		// this cannot fail in practice; fall back to an empty object rather than
		// dropping the row.
		attrsJSON = []byte("{}")
	}

	return eventRow{
		Seq:            attrInt64(attrs, evidence.AttrSequence),
		TS:             time.Unix(0, int64(ts)).UTC().Format(time.RFC3339Nano),
		Name:           lr.GetEventName(),
		Class:          attrString(attrs, evidence.AttrEvidenceClass),
		Producer:       attrString(attrs, evidence.AttrProducer),
		ActionID:       attrString(attrs, evidence.AttrActionID),
		ParentActionID: attrString(attrs, evidence.AttrParentActionID),
		Outcome:        attrString(attrs, evidence.AttrOutcome),
		Body:           lr.GetBody().GetStringValue(),
		AttrsJSON:      string(attrsJSON),
	}
}

// queryEvents runs filter against the events table, returning rows in
// ascending sequence order.
func queryEvents(db *sql.DB, filter Filter) ([]eventRow, error) {
	query := `SELECT seq, ts, name, class, producer, action_id, parent_action_id, outcome, body, attrs_json
		FROM events WHERE 1=1`
	var args []any
	if filter.Name != "" {
		query += " AND name = ?"
		args = append(args, filter.Name)
	}
	if filter.Class != "" {
		query += " AND class = ?"
		args = append(args, filter.Class)
	}
	if filter.Since != "" {
		query += " AND ts >= ?"
		args = append(args, filter.Since)
	}
	excludeNames := filter.ExcludeNames
	if filter.AgentActivity {
		excludeNames = append(append([]string(nil), excludeNames...), excludeNamesForAgentActivity()...)
	}
	if len(excludeNames) > 0 {
		placeholders := make([]string, len(excludeNames))
		for i, name := range excludeNames {
			placeholders[i] = "?"
			args = append(args, name)
		}
		query += " AND name NOT IN (" + strings.Join(placeholders, ",") + ")"
	}
	query += " ORDER BY seq ASC"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("view: query events: %w", err)
	}
	defer rows.Close()

	var out []eventRow
	for rows.Next() {
		var row eventRow
		var actionID, parentActionID, outcome, body sql.NullString
		if err := rows.Scan(&row.Seq, &row.TS, &row.Name, &row.Class, &row.Producer,
			&actionID, &parentActionID, &outcome, &body, &row.AttrsJSON); err != nil {
			return nil, fmt.Errorf("view: scan event row: %w", err)
		}
		row.ActionID = actionID.String
		row.ParentActionID = parentActionID.String
		row.Outcome = outcome.String
		row.Body = body.String
		out = append(out, row)
	}
	return out, rows.Err()
}
