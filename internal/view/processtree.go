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

// processNode is one process incarnation observed by process.executed. Kernel
// exec ids identify incarnations when available; otherwise Seq distinguishes
// reused pids.
type processNode struct {
	PID          string
	Label        string
	Producer     string // audit.producer of the process evidence
	Forged       bool   // observed on a channel other than the trusted guest_supervisor sensor
	Seq          int64
	ExecID       string
	ParentExecID string
	ParentPID    string
	Children     []*processNode
}

// ProcessTree rebuilds the projection and renders the process tree derived
// from process.executed events as an indented string, one process incarnation
// per line.
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

	var nodes []*processNode
	byIdentity := make(map[string]*processNode, len(rows))
	byExecID := make(map[string]*processNode, len(rows))
	byPID := make(map[string][]*processNode)

	for _, row := range rows {
		var attrs map[string]any
		if err := json.Unmarshal([]byte(row.AttrsJSON), &attrs); err != nil {
			return "", fmt.Errorf("view: decode process attrs for seq %d: %w", row.Seq, err)
		}
		pid := attrString(attrs, evidence.AttrProcessPID)
		if pid == "" {
			continue // no pid to place in the tree
		}
		execID := attrString(attrs, evidence.AttrProcessExecID)
		identity := fmt.Sprintf("pid:%s:seq:%d", pid, row.Seq)
		if execID != "" {
			identity = "exec:" + execID
		}
		if existing := byIdentity[identity]; existing != nil {
			if row.Producer != string(evidence.ChannelGuestSupervisor) {
				existing.Producer = row.Producer
				existing.Forged = true
			}
			continue
		}
		// A process.executed on any channel but the trusted guest_supervisor kernel
		// sensor is workload-forgeable; flag it so the tree never presents a forged
		// process as a real one (DESIGN.md channel-derived producer).
		node := &processNode{
			PID:          pid,
			Label:        row.Body,
			Producer:     row.Producer,
			Forged:       row.Producer != string(evidence.ChannelGuestSupervisor),
			Seq:          row.Seq,
			ExecID:       execID,
			ParentExecID: attrString(attrs, evidence.AttrProcessParentExecID),
			ParentPID:    attrString(attrs, evidence.AttrProcessPPID),
		}
		nodes = append(nodes, node)
		byIdentity[identity] = node
		if execID != "" {
			byExecID[execID] = node
		}
		byPID[pid] = append(byPID[pid], node)
	}

	var roots []*processNode
	for _, n := range nodes {
		parent := byExecID[n.ParentExecID]
		if parent == nil && n.ParentPID != "" {
			parent = latestPriorProcess(byPID[n.ParentPID], n.Seq)
		}
		if parent != nil && parent != n {
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

func latestPriorProcess(candidates []*processNode, seq int64) *processNode {
	var latest *processNode
	for _, candidate := range candidates {
		if candidate.Seq < seq && (latest == nil || candidate.Seq > latest.Seq) {
			latest = candidate
		}
	}
	return latest
}

// sortProcessTree orders siblings numerically by pid, recursively, for
// deterministic output.
func sortProcessTree(nodes []*processNode) {
	sort.Slice(nodes, func(i, j int) bool {
		pi, errI := strconv.Atoi(nodes[i].PID)
		pj, errJ := strconv.Atoi(nodes[j].PID)
		if errI == nil && errJ == nil && pi != pj {
			return pi < pj
		}
		if nodes[i].PID != nodes[j].PID {
			return nodes[i].PID < nodes[j].PID
		}
		return nodes[i].Seq < nodes[j].Seq
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
	if n.Forged {
		// Not kernel-verified: surface the untrusted channel inline so a forged
		// process is never rendered indistinguishably from a real one.
		label += fmt.Sprintf(" [unverified producer: %s]", n.Producer)
	}
	fmt.Fprintf(buf, "%s%s\n", strings.Repeat("  ", depth), label)
	for _, c := range n.Children {
		writeProcessNode(buf, c, depth+1)
	}
}
