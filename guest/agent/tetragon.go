package main

import (
	"context"
	"encoding/json"
	"fmt"
)

// tetragonProcess is the subset of Tetragon's process JSON export fields
// the guest agent uses to build process.executed/process.exited evidence.
// Unknown fields in the real export are ignored by json.Unmarshal.
type tetragonProcess struct {
	ExecID       string `json:"exec_id"`
	Pid          uint32 `json:"pid"`
	Uid          uint32 `json:"uid"`
	Binary       string `json:"binary"`
	Arguments    string `json:"arguments"`
	ParentExecID string `json:"parent_exec_id"`
	Docker       string `json:"docker"` // cgroup/container id, used as process.cgroup.id
}

type tetragonExecEvent struct {
	Process tetragonProcess `json:"process"`
	Parent  tetragonProcess `json:"parent"`
}

type tetragonExitEvent struct {
	Process tetragonProcess `json:"process"`
	Parent  tetragonProcess `json:"parent"`
	Status  int             `json:"status"`
}

// tetragonLine is one line of Tetragon's JSON export
// (tetragon_log, default /var/log/tetragon/tetragon.log). Exactly one of
// ProcessExec/ProcessExit is populated for the events this agent cares
// about; other Tetragon event kinds (process_kprobe, health checks, ...)
// parse successfully with both left nil, and callers skip those.
type tetragonLine struct {
	ProcessExec *tetragonExecEvent `json:"process_exec,omitempty"`
	ProcessExit *tetragonExitEvent `json:"process_exit,omitempty"`
}

// parseTetragonLine parses one line of the Tetragon JSON export. It
// returns an error only for malformed JSON; structurally valid lines that
// carry neither payload are returned with both fields nil so the caller
// can skip them defensively, per DESIGN.md ("parse defensively, unknown
// lines skipped").
func parseTetragonLine(line []byte) (*tetragonLine, error) {
	var tl tetragonLine
	if err := json.Unmarshal(line, &tl); err != nil {
		return nil, fmt.Errorf("agent: parse tetragon line: %w", err)
	}
	return &tl, nil
}

// belongsToWorkload reports whether a Tetragon/procfs-observed uid belongs
// to the workload (DESIGN.md: "Filter to the workload cgroup subtree /
// workload_uid").
func belongsToWorkload(uid uint32, workloadUID int64) bool {
	return int64(uid) == workloadUID
}

// runTetragonWatcher tails cfg.TetragonLog and forwards process.executed/
// process.exited events for the workload to batch. It returns when ctx is
// cancelled or the log becomes unreadable.
func runTetragonWatcher(ctx context.Context, cfg Config, batch *Batcher) error {
	return tailFollow(ctx, cfg.TetragonLog, func(line string) {
		tl, err := parseTetragonLine([]byte(line))
		if err != nil {
			return // malformed line: skip defensively
		}
		switch {
		case tl.ProcessExec != nil:
			p := tl.ProcessExec.Process
			if !belongsToWorkload(p.Uid, cfg.WorkloadUID) {
				return
			}
			batch.Add(newProcessExecutedEvent(ProcInfo{
				Pid: int64(p.Pid), Ppid: int64(tl.ProcessExec.Parent.Pid), Uid: int64(p.Uid),
				Binary: p.Binary, Argv: p.Arguments, ExecID: p.ExecID, CgroupID: p.Docker,
				Observer: "tetragon",
			}))
		case tl.ProcessExit != nil:
			p := tl.ProcessExit.Process
			if !belongsToWorkload(p.Uid, cfg.WorkloadUID) {
				return
			}
			batch.Add(newProcessExitedEvent(ProcInfo{
				Pid: int64(p.Pid), Ppid: int64(tl.ProcessExit.Parent.Pid), Uid: int64(p.Uid),
				Binary: p.Binary, Argv: p.Arguments, ExecID: p.ExecID, CgroupID: p.Docker,
				Observer: "tetragon",
			}, int64(tl.ProcessExit.Status)))
		}
	})
}
