package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"boxedai/internal/evidence"
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
	Status  *int64          `json:"status"`
	Signal  string          `json:"signal"`
}

type tetragonTracepointArg struct {
	UintArg *uint32 `json:"uint_arg"`
}

type tetragonTracepointEvent struct {
	Process    tetragonProcess         `json:"process"`
	Subsys     string                  `json:"subsys"`
	Event      string                  `json:"event"`
	Args       []tetragonTracepointArg `json:"args"`
	PolicyName string                  `json:"policy_name"`
}

// tetragonLine is one line of Tetragon's JSON export
// (tetragon_log, default /var/log/tetragon/tetragon.log). Exactly one of
// ProcessExec/ProcessExit is populated for the events this agent cares
// about; other Tetragon event kinds (process_kprobe, health checks, ...)
// parse successfully with both left nil, and callers skip those.
type tetragonLine struct {
	ProcessExec       *tetragonExecEvent       `json:"process_exec,omitempty"`
	ProcessExit       *tetragonExitEvent       `json:"process_exit,omitempty"`
	ProcessTracepoint *tetragonTracepointEvent `json:"process_tracepoint,omitempty"`
	RateLimitInfo     json.RawMessage          `json:"rate_limit_info,omitempty"`
	Time              time.Time                `json:"time,omitempty"`
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

func rateLimitDropped(raw json.RawMessage) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	var info struct {
		Dropped json.RawMessage `json:"number_of_dropped_process_events"`
	}
	if err := json.Unmarshal(raw, &info); err != nil || len(info.Dropped) == 0 {
		return false, fmt.Errorf("agent: malformed Tetragon rate_limit_info")
	}
	var number uint64
	if err := json.Unmarshal(info.Dropped, &number); err != nil {
		var text string
		if err := json.Unmarshal(info.Dropped, &text); err != nil {
			return false, fmt.Errorf("agent: malformed Tetragon rate-limit drop count")
		}
		parsed, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return false, fmt.Errorf("agent: malformed Tetragon rate-limit drop count")
		}
		number = parsed
	}
	return number > 0, nil
}

func parseForkTracepoint(event *tetragonTracepointEvent) (ProcInfo, bool, error) {
	if event == nil || event.PolicyName != "boxedai-process-fork" {
		return ProcInfo{}, false, nil
	}
	if event.Subsys != "sched" || event.Event != "sched_process_fork" || len(event.Args) != 2 || event.Args[0].UintArg == nil || event.Args[1].UintArg == nil {
		return ProcInfo{}, true, fmt.Errorf("agent: malformed boxedai-process-fork tracepoint")
	}
	parentPID := int64(*event.Args[0].UintArg)
	childPID := int64(*event.Args[1].UintArg)
	if parentPID == 0 || childPID == 0 || event.Process.ExecID == "" {
		return ProcInfo{}, true, fmt.Errorf("agent: malformed boxedai-process-fork parent identity")
	}
	// Tetragon only attaches the forking parent as `process` once it has
	// observed that parent's execve. Processes discovered via its startup procfs
	// scan (early-boot system daemons that predate Tetragon) surface with the
	// kernel placeholder instead (pid 0, exec_id of the boot pseudo-process), so
	// process.ExecID is not the parent's and the fork is not attributable to a
	// real parent. Those are never the workload (which starts after Tetragon)
	// and are uid-filtered downstream regardless, so skip rather than treat the
	// unresolved context as corruption and kill the watcher.
	if parentPID != int64(event.Process.Pid) {
		return ProcInfo{}, false, nil
	}
	return ProcInfo{
		Pid:          childPID,
		Ppid:         parentPID,
		Uid:          int64(event.Process.Uid),
		ParentExecID: event.Process.ExecID,
		Observer:     "tetragon",
	}, true, nil
}

// validateBuiltinLifecycle classifies a process_exec/process_exit identity.
// A workload event missing pid/exec_id is fatal: workload evidence integrity
// requires a resolved identity. A non-workload event missing them is merely
// unresolved — Tetragon has not backfilled exec info for that process (e.g.
// procfs-discovered system daemons that predate it), so it cannot serve as a
// lifecycle witness and is skipped rather than treated as corruption that would
// kill the sensor and SIGKILL the workload. resolved is false only for that
// skip case (err nil); a resolved identity returns true.
func validateBuiltinLifecycle(process tetragonProcess, workloadUID int64) (resolved bool, err error) {
	if process.Pid == 0 || process.ExecID == "" {
		if belongsToWorkload(process.Uid, workloadUID) {
			return false, fmt.Errorf("agent: malformed workload Tetragon lifecycle identity")
		}
		return false, nil
	}
	return true, nil
}

// belongsToWorkload reports whether a Tetragon/procfs-observed uid is the
// dedicated VM's workload uid. The sandbox's empty capability set and
// NoNewPrivileges keep descendants on this uid; no cgroup scope is claimed.
func belongsToWorkload(uid uint32, workloadUID int64) bool {
	return int64(uid) == workloadUID
}

func tetragonParentExecID(process, parent tetragonProcess) string {
	if process.ParentExecID != "" {
		return process.ParentExecID
	}
	return parent.ExecID
}

func tetragonExitStatus(event tetragonExitEvent) ProcessExitStatus {
	if event.Signal != "" {
		return ProcessExitStatus{Signal: event.Signal}
	}
	if event.Status != nil {
		return ProcessExitStatus{Code: event.Status}
	}
	// Tetragon v1.2 encodes this proto3 scalar with protojson. A known zero
	// status is omitted by default, so absence without a signal means exit 0.
	code := int64(0)
	return ProcessExitStatus{Code: &code}
}

func tetragonEventTime(source time.Time) time.Time {
	if source.IsZero() {
		return time.Now()
	}
	return source
}

// runTetragonWatcher tails cfg.TetragonLog and forwards process.executed/
// process.exited events for the workload to batch. Each accepted source line
// is flushed before the watcher advances, preserving Tetragon's exec/exit
// source order without inferring cross-channel causality. Filesystem delivery
// and broker scheduling remain independent of PostToolUse, so this does not
// establish a cross-channel causal guarantee. It returns when ctx is cancelled
// or the log becomes unreadable. ready is called only after fresh built-in
// lifecycle and boxedai-process-fork policy observations have both been parsed.
func runTetragonWatcher(ctx context.Context, cfg Config, batch *Batcher, ready func(), lossBaseline float64) error {
	return runTetragonWatcherWithMetrics(ctx, cfg, batch, ready, func(ctx context.Context) (bool, error) {
		return tetragonMetricsLost(ctx, tetragonMetricsURL, lossBaseline)
	})
}

func runTetragonWatcherWithMetrics(ctx context.Context, cfg Config, batch *Batcher, ready func(), metricsLost func(context.Context) (bool, error)) error {
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var readyOnce sync.Once
	seenExec, seenExit, seenFork := false, false, false
	var watcherErr error
	var errOnce sync.Once
	fail := func(err error) {
		errOnce.Do(func() {
			watcherErr = err
			cancel()
		})
	}
	markReady := func() {
		if !seenExec || !seenExit || !seenFork {
			return
		}
		readyOnce.Do(func() {
			lost, err := metricsLost(watchCtx)
			if err != nil {
				fail(fmt.Errorf("agent: Tetragon metrics unavailable at readiness: %w", err))
				return
			}
			if lost {
				fail(fmt.Errorf("agent: Tetragon loss metric is nonzero at readiness"))
				return
			}
			ready()
		})
	}
	err := tailFollowReadyStrict(watchCtx, cfg.TetragonLog, nil, func(line string) {
		tl, err := parseTetragonLine([]byte(line))
		if err != nil {
			fail(fmt.Errorf("agent: malformed complete Tetragon JSON line: %w", err))
			return
		}
		if dropped, err := rateLimitDropped(tl.RateLimitInfo); err != nil {
			fail(err)
			return
		} else if dropped {
			fail(fmt.Errorf("agent: Tetragon rate-limit dropped process events"))
			return
		}
		switch {
		case tl.ProcessExec != nil:
			resolved, err := validateBuiltinLifecycle(tl.ProcessExec.Process, cfg.WorkloadUID)
			if err != nil {
				fail(err)
				return
			}
			if !resolved {
				return
			}
			seenExec = true
			markReady()
			p := tl.ProcessExec.Process
			if !belongsToWorkload(p.Uid, cfg.WorkloadUID) {
				return
			}
			event := newProcessExecutedEvent(ProcInfo{
				Pid: int64(p.Pid), Ppid: int64(tl.ProcessExec.Parent.Pid), Uid: int64(p.Uid),
				Binary: p.Binary, Argv: p.Arguments, ExecID: p.ExecID, ParentExecID: tetragonParentExecID(p, tl.ProcessExec.Parent), CgroupID: p.Docker,
				Observer: "tetragon",
			})
			event.Time = tetragonEventTime(tl.Time)
			if err := addLifecycleEvent(watchCtx, batch, event); err != nil {
				fail(err)
			}
		case tl.ProcessExit != nil:
			resolved, err := validateBuiltinLifecycle(tl.ProcessExit.Process, cfg.WorkloadUID)
			if err != nil {
				fail(err)
				return
			}
			if !resolved {
				return
			}
			seenExit = true
			markReady()
			p := tl.ProcessExit.Process
			if !belongsToWorkload(p.Uid, cfg.WorkloadUID) {
				return
			}
			event := newProcessExitedEvent(ProcInfo{
				Pid: int64(p.Pid), Ppid: int64(tl.ProcessExit.Parent.Pid), Uid: int64(p.Uid),
				Binary: p.Binary, Argv: p.Arguments, ExecID: p.ExecID, ParentExecID: tetragonParentExecID(p, tl.ProcessExit.Parent), CgroupID: p.Docker,
				Observer: "tetragon",
			}, tetragonExitStatus(*tl.ProcessExit))
			event.Time = tetragonEventTime(tl.Time)
			if err := addLifecycleEvent(watchCtx, batch, event); err != nil {
				fail(err)
			}
		case tl.ProcessTracepoint != nil:
			pi, relevant, err := parseForkTracepoint(tl.ProcessTracepoint)
			if err != nil {
				fail(err)
				return
			}
			if !relevant {
				return
			}
			seenFork = true
			markReady()
			if !belongsToWorkload(uint32(pi.Uid), cfg.WorkloadUID) {
				return
			}
			event := newProcessCreatedEvent(pi)
			event.Time = tetragonEventTime(tl.Time)
			if err := addLifecycleEvent(watchCtx, batch, event); err != nil {
				fail(err)
			}
		}
	})
	if watcherErr != nil {
		return watcherErr
	}
	return err
}

var lifecycleDeliveryTimeout = 2 * time.Second

func addLifecycleEvent(ctx context.Context, batch *Batcher, event evidence.Event) error {
	flushCtx, cancel := context.WithTimeout(ctx, lifecycleDeliveryTimeout)
	defer cancel()
	return batch.AddAndFlush(flushCtx, event)
}
