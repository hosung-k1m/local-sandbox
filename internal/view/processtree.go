package view

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"boxedai/internal/evidence"
)

// processNode is one process.executed observation, linked to its children by
// process.pid/process.parent_pid.
type processNode struct {
	PID      string
	Label    string
	Children []*processNode
}

// ProcessTree rebuilds the projection and renders the process tree derived
// from process.executed events (process.pid/process.parent_pid) as an indented
// string, one process per line.
func ProcessTree(sessionDir string) (string, error) {
	db, err := Rebuild(sessionDir)
	if err != nil {
		return "", err
	}
	defer db.Close()
	return processTreeFromDB(db)
}

// processTreeFromDB builds the tree from an already-rebuilt projection.
func processTreeFromDB(db *sql.DB) (string, error) {
	rows, err := queryEvents(db, Filter{Name: evidence.EventProcessExecuted})
	if err != nil {
		return "", err
	}

	nodes := make(map[string]*processNode, len(rows))
	parents := make(map[string]string, len(rows))
	var order []string // first-seen pid order, for deterministic root iteration

	for _, row := range rows {
		var attrs map[string]any
		if err := json.Unmarshal([]byte(row.AttrsJSON), &attrs); err != nil {
			return "", fmt.Errorf("view: decode process attrs for seq %d: %w", row.Seq, err)
		}
		pid := attrString(attrs, evidence.AttrProcessPID)
		if pid == "" {
			continue // no pid to place in the tree
		}
		if _, exists := nodes[pid]; !exists {
			order = append(order, pid)
		}
		nodes[pid] = &processNode{PID: pid, Label: row.Body}
		parents[pid] = attrString(attrs, evidence.AttrProcessPPID)
	}

	var roots []*processNode
	for _, pid := range order {
		n := nodes[pid]
		if parent, ok := nodes[parents[pid]]; ok && parents[pid] != "" {
			parent.Children = append(parent.Children, n)
		} else {
			roots = append(roots, n)
		}
	}
	sortProcessTree(roots)

	var buf strings.Builder
	for _, root := range roots {
		writeProcessNode(&buf, root, 0)
	}
	return buf.String(), nil
}

// sortProcessTree orders siblings numerically by pid, recursively, for
// deterministic output.
func sortProcessTree(nodes []*processNode) {
	sort.Slice(nodes, func(i, j int) bool {
		pi, _ := strconv.Atoi(nodes[i].PID)
		pj, _ := strconv.Atoi(nodes[j].PID)
		return pi < pj
	})
	for _, n := range nodes {
		sortProcessTree(n.Children)
	}
}

// writeProcessNode writes one node and its subtree as indented lines.
func writeProcessNode(buf *strings.Builder, n *processNode, depth int) {
	label := "pid " + n.PID
	if n.Label != "" {
		label += ": " + n.Label
	}
	fmt.Fprintf(buf, "%s%s\n", strings.Repeat("  ", depth), label)
	for _, c := range n.Children {
		writeProcessNode(buf, c, depth+1)
	}
}
