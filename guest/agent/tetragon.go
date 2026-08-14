package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

// readinessMetricsRetryInterval throttles the Tetragon loss-metrics scrape the
// readiness gate performs, so an endpoint that is refusing connections (or
// hanging) cannot be re-probed on every accepted source line.
var readinessMetricsRetryInterval = 1 * time.Second

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
	// Tetragon only attaches the forking parent as `process` once it has
	// observed that parent's execve. Processes discovered via its startup procfs
	// scan (early-boot system daemons that predate Tetragon) surface with the
	// kernel placeholder instead (pid 0, exec_id of the boot pseudo-process), so
	// process.ExecID is not the parent's and the fork is not attributable to a
	// real parent. Those are never the workload (which starts after Tetragon)
	// and are uid-filtered downstream regardless, so skip rather than treat the
	// unresolved context as corruption and kill the watcher. Rapid nested forks
	// hit the same enrichment gap from the other direction and must be skipped
	// for the same reason: a workload subprocess (git spawning children that fork
	// grandchildren) can fork before Tetragon has cached the intermediate
	// execve, and the tracepoint then arrives structurally valid with an
	// unenriched context — empty exec_id, or zero pids where the identity should
	// be. That shape IS the workload, but the fork observation is only
	// supplementary lineage: the child's own process_exec still arrives with a
	// full identity, so exec/exit coverage is unaffected and the honest cost is
	// one unattributable fork rather than a degraded sensor. A malformed *shape*
	// (above) stays fatal, because that is corruption rather than a known gap.
	if parentPID == 0 || childPID == 0 || event.Process.ExecID == "" || parentPID != int64(event.Process.Pid) {
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
// process.exited events for the workload to batch. Accepted source lines are
// queued in read order and the batcher POSTs them in that order, preserving
// Tetragon's exec/exit source order without inferring cross-channel causality.
// Filesystem delivery and broker scheduling remain independent of PostToolUse, so
// this does not establish a cross-channel causal guarantee. It returns when ctx is
// cancelled or the log becomes unreadable. ready is called only after fresh built-in
// lifecycle and boxedai-process-fork policy observations have both been parsed, and two
// loss-metric scrapes agree the readiness-blocking counters have stopped moving.
func runTetragonWatcher(ctx context.Context, cfg Config, batch *Batcher, ready func()) error {
	return runTetragonWatcherWithMetrics(ctx, cfg, batch, ready, func(ctx context.Context) (float64, error) {
		return tetragonLossTotal(ctx, tetragonMetricsURL, tetragonReadinessLossMetrics)
	})
}

func runTetragonWatcherWithMetrics(ctx context.Context, cfg Config, batch *Batcher, ready func(), lossTotal func(context.Context) (float64, error)) error {
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	readyPublished := false
	var lastReadinessProbe time.Time
	// The readiness loss gate is self-anchoring: the first scrape only records where
	// the counters are, and readiness needs a later scrape showing they have not moved
	// since. A fresh VM keeps accruing benign loss counts while it boots, so a delta
	// means "the counters have not settled yet", not "the sensor is broken" — re-anchor
	// and look again. Failing the watcher on that delta (and on every retry after it)
	// is what degraded healthy fresh boots to procfs before the workload launched, at a
	// cost of ~40s and an INCOMPLETE verdict. A counter that never settles is genuine
	// ongoing loss, and runProcessSensor's bounded fallback then degrades honestly.
	readinessLossBaseline := -1.0
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
		if readyPublished || !seenExec || !seenExit || !seenFork {
			return
		}
		// A metrics endpoint that is not answering yet means Tetragon is still
		// coming up, not that the authoritative sensor is broken: retry on a
		// later lifecycle observation instead of ending the watch. The throttle
		// keeps a hung endpoint from stalling every accepted source line, and
		// runProcessSensor's bounded readiness fallback keeps a metrics endpoint
		// that never answers from stalling the session forever.
		if time.Since(lastReadinessProbe) < readinessMetricsRetryInterval {
			return
		}
		lastReadinessProbe = time.Now()
		total, err := lossTotal(watchCtx)
		if err != nil {
			log.Printf("agent: Tetragon metrics unavailable at readiness, retrying: %v", err)
			return
		}
		// Any movement re-anchors, in either direction: growth is a VM still settling,
		// and a drop is Tetragon having restarted its counters.
		if total != readinessLossBaseline {
			if readinessLossBaseline >= 0 {
				log.Printf("agent: Tetragon loss counters still moving at readiness (%v, was %v), re-baselining", total, readinessLossBaseline)
			}
			readinessLossBaseline = total
			return
		}
		readyPublished = true
		ready()
	}
	handleLine := func(line string) {
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
			batch.Add(event)
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
			batch.Add(event)
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
			batch.Add(event)
		}
	}
	// consumed follows the tailer's line-boundary position so the teardown drain
	// below knows where reading stopped. -1 means it never attached at all.
	consumed := int64(-1)
	// Rotation/truncation is recoverable: the tailer reattaches at the start of
	// the replacement file, so coverage resumes, but lines appended to the old
	// file after the last read are unrecoverable. Record that as loss +
	// restarted rather than ending the watch (which used to SIGKILL the
	// workload) — Tetragon's own rotation defaults hit a busy session within
	// minutes even though the session-time unit now pins them far out. Both
	// events go through the same queue as the lines before them, so they land in
	// the timeline exactly where the gap happened.
	err := tailFollowReadyReattach(watchCtx, cfg.TetragonLog, nil, handleLine, func() {
		batch.Add(newSensorLossEvent("process", fmt.Sprintf("Tetragon export %s changed generation (rotated or truncated); reattached at the start of the replacement", cfg.TetragonLog)))
		batch.Add(newSensorRestartedEvent("process", "tetragon"))
	}, func(offset int64) { consumed = offset })
	if watcherErr != nil {
		return watcherErr
	}
	if ctx.Err() != nil {
		drainTetragonExport(cfg.TetragonLog, consumed, batch, handleLine)
	}
	return err
}

// tetragonDrainWindow bounds the teardown catch-up read. It has to stay well
// inside the host's 5s kill-switch grace (vm.stopGrace), after which the instance
// is force-stopped and anything still unposted is gone anyway.
var tetragonDrainWindow = 2 * time.Second

// tetragonBacklogTolerance is how many unread export bytes at teardown are
// treated as the export's own tail rather than a backlog. Teardown itself makes
// Tetragon write: the `limactl shell` that touches the stop sentinel, the
// liveness probe, a partial line mid-write. Reporting those as loss would make
// every single session INCOMPLETE, so the threshold sits above that handful of
// records and far below the tens of megabytes a real fork storm leaves behind.
var tetragonBacklogTolerance int64 = 64 << 10

// drainTetragonExport finishes reading the export once the watch has stopped for
// teardown. The tailer stops wherever the stop sentinel found it, so without this
// every line Tetragon had already written but nobody had read would be dropped —
// silently, which is the worse half: a fork storm outran the guest, ~9% of its
// process events became evidence, and verification still passed its sensor
// invariants. Whatever remains unread after the bounded window is reported as
// sensor.loss, so an undrained backlog surfaces as an INCOMPLETE verdict.
func drainTetragonExport(path string, from int64, batch *Batcher, handleLine func(line string)) {
	if from < 0 {
		// Never attached, so nothing was ever in this watcher's reach; the
		// readiness path already recorded that as its own loss.
		return
	}
	offset, err := readLinesFrom(path, from, time.Now().Add(tetragonDrainWindow), handleLine)
	if err != nil {
		log.Printf("agent: drain Tetragon export at teardown: %v", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return
	}
	unread := info.Size() - offset
	if unread <= tetragonBacklogTolerance {
		return
	}
	batch.Add(newSensorLossEvent("process", fmt.Sprintf(
		"Tetragon export backlog not drained at teardown: %d unread byte(s) in %s after %s",
		unread, path, tetragonDrainWindow)))
}
