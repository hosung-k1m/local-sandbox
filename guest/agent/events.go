package main

import (
	"fmt"
	"time"

	"boxedai/internal/evidence"
)

// Custom attribute keys for guest-supervisor evidence that fall outside the
// shared evidence package's well-known set. DESIGN.md names these fields
// (binary, argv, uid, exit code, dest ip/port/proto, observer, sensor name/
// mechanism) without assigning wire keys, so producers own the naming;
// these follow the existing "namespace.field" convention.
const (
	attrProcessBinary         = "process.binary"
	attrProcessArgv           = "process.argv"
	attrProcessUID            = "process.uid"
	attrProcessExitCode       = "process.exit_code"
	attrProcessExitSignal     = "process.exit_signal"
	attrProcessExitStatus     = "process.exit_status"
	attrProcessParentExecID   = "process.parent_exec_id"
	attrProcessClassification = "process.classification"
	attrObserver              = "observer" // "tetragon" | "procfs" | "scan" | "nftables"
	attrFilePath              = "file.path"
	attrNetworkDestIP         = "network.dest.ip"
	attrNetworkDestPort       = "network.dest.port"
	attrNetworkProto          = "network.proto"
	attrSensorName            = "sensor.name"
	attrSensorMechanism       = "sensor.mechanism"
	attrSensorReason          = "sensor.reason"
	attrSensorCoverage        = "sensor.coverage"
)

// procStart anchors monotonicNS: time.Time carries a monotonic reading
// internally, but only time.Since exposes it as a duration, so agent
// startup is used as the zero point for audit.monotonic_ns.
var procStart = time.Now()

func monotonicNS() int64 {
	return time.Since(procStart).Nanoseconds()
}

// ProcInfo is the mechanism-agnotic process observation shared by the
// Tetragon and procfs watchers. ExecID and CgroupID are empty under the
// procfs fallback, which has no exec-id/cgroup lineage.
type ProcInfo struct {
	Pid          int64
	Ppid         int64
	Uid          int64
	Binary       string
	Argv         string
	ExecID       string
	ParentExecID string
	CgroupID     string
	Observer     string // "tetragon" | "procfs"
}

func newProcessExecutedEvent(pi ProcInfo) evidence.Event {
	attrs := map[string]any{
		evidence.AttrProcessPID:  pi.Pid,
		evidence.AttrProcessPPID: pi.Ppid,
		attrProcessUID:           pi.Uid,
		attrProcessBinary:        pi.Binary,
		attrProcessArgv:          pi.Argv,
		attrObserver:             pi.Observer,
	}
	attrs[evidence.AttrCorrelation] = string(procCorrelation(pi, attrs))
	return evidence.Event{
		Name:        evidence.EventProcessExecuted,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassKernelObserved,
		Outcome:     evidence.OutcomeSuccess,
		Body:        "exec " + pi.Binary,
		Attrs:       attrs,
	}
}

func newProcessCreatedEvent(pi ProcInfo) evidence.Event {
	attrs := map[string]any{
		evidence.AttrProcessPID:   pi.Pid,
		evidence.AttrProcessPPID:  pi.Ppid,
		attrProcessUID:            pi.Uid,
		attrObserver:              pi.Observer,
		attrSensorMechanism:       "tetragon_tracepoint",
		attrProcessClassification: "provisional_unknown_process_or_thread",
	}
	attrs[evidence.AttrCorrelation] = string(procCorrelation(pi, attrs))
	return evidence.Event{
		Name:        evidence.EventProcessCreated,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassKernelObserved,
		Outcome:     evidence.OutcomeSuccess,
		Body:        fmt.Sprintf("created task pid=%d parent=%d", pi.Pid, pi.Ppid),
		Attrs:       attrs,
	}
}

type ProcessExitStatus struct {
	Code   *int64
	Signal string
}

func newProcessExitedEvent(pi ProcInfo, status ProcessExitStatus) evidence.Event {
	var outcome evidence.Outcome
	if status.Signal != "" {
		outcome = evidence.OutcomeInterrupted
	} else if status.Code != nil && *status.Code == 0 {
		outcome = evidence.OutcomeSuccess
	} else if status.Code != nil {
		outcome = evidence.OutcomeFailure
	}
	attrs := map[string]any{
		evidence.AttrProcessPID: pi.Pid,
		attrObserver:            pi.Observer,
	}
	body := fmt.Sprintf("exit pid=%d status=unknown", pi.Pid)
	attrs[attrProcessExitStatus] = "unknown"
	if status.Signal != "" {
		attrs[attrProcessExitSignal] = status.Signal
		attrs[attrProcessExitStatus] = "signal"
		body = fmt.Sprintf("exit pid=%d signal=%s", pi.Pid, status.Signal)
	} else if status.Code != nil {
		attrs[attrProcessExitCode] = *status.Code
		attrs[attrProcessExitStatus] = "code"
		body = fmt.Sprintf("exit pid=%d code=%d", pi.Pid, *status.Code)
	}
	attrs[evidence.AttrCorrelation] = string(procCorrelation(pi, attrs))
	return evidence.Event{
		Name:        evidence.EventProcessExited,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassKernelObserved,
		Outcome:     outcome,
		Body:        body,
		Attrs:       attrs,
	}
}

// procCorrelation fills in exec-id/cgroup attrs when present and reports
// the resulting correlation strength: Tetragon's exec id ties an
// executed/exited pair together (lineage), procfs offers only a uid+pid
// snapshot (none) per DESIGN.md ("procfs fallback ... correlation weaker").
func procCorrelation(pi ProcInfo, attrs map[string]any) evidence.Correlation {
	correlation := evidence.CorrelationNone
	if pi.ExecID != "" {
		attrs[evidence.AttrProcessExecID] = pi.ExecID
		correlation = evidence.CorrelationLineage
	}
	if pi.ParentExecID != "" {
		attrs[attrProcessParentExecID] = pi.ParentExecID
	}
	if pi.CgroupID != "" {
		attrs[evidence.AttrProcessCgroupID] = pi.CgroupID
	}
	return correlation
}

func newFileChangedEvent(relPath, digest string) evidence.Event {
	return evidence.Event{
		Name:        evidence.EventFileChanged,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassKernelObserved,
		Outcome:     evidence.OutcomeSuccess,
		Body:        "file changed " + relPath,
		Attrs: map[string]any{
			attrFilePath:                relPath,
			evidence.AttrContentDigest:  digest,
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
			attrObserver:                "scan",
		},
	}
}

func newFileDeletedEvent(relPath string) evidence.Event {
	return evidence.Event{
		Name:        evidence.EventFileDeleted,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassKernelObserved,
		Outcome:     evidence.OutcomeSuccess,
		Body:        "file deleted " + relPath,
		Attrs: map[string]any{
			attrFilePath: relPath,
			attrObserver: "scan",
		},
	}
}

func newNetworkDeniedEvent(destIP string, destPort int64, proto string) evidence.Event {
	return evidence.Event{
		Name:        evidence.EventNetworkDenied,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassKernelObserved,
		Outcome:     evidence.OutcomeDenied,
		Body:        fmt.Sprintf("denied %s to %s:%d", proto, destIP, destPort),
		Attrs: map[string]any{
			attrNetworkDestIP:   destIP,
			attrNetworkDestPort: destPort,
			attrNetworkProto:    proto,
			attrObserver:        "nftables",
		},
	}
}

// newSensorStartedEvent, newSensorLossEvent and newSensorRestartedEvent use
// evidence.ClassIntegrity rather than ClassKernelObserved: these events
// describe the trustworthiness/completeness of the sensing pipeline itself
// (evidence about evidence), not a direct kernel observation of the
// workload, and ClassIntegrity is in the guest_supervisor channel's
// allowance for exactly that purpose.

func newSensorStartedEvent(mechanism string) evidence.Event {
	attrs := map[string]any{attrSensorMechanism: mechanism}
	if mechanism == "procfs" {
		attrs[attrSensorCoverage] = "incomplete: polling can miss short-lived processes"
	}
	return evidence.Event{
		Name:        evidence.EventSensorStarted,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassIntegrity,
		Outcome:     evidence.OutcomeSuccess,
		Body:        "sensor started: " + mechanism,
		Attrs:       attrs,
	}
}

func newSensorLossEvent(sensorName, reason string) evidence.Event {
	return evidence.Event{
		Name:        evidence.EventSensorLoss,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassIntegrity,
		Outcome:     evidence.OutcomeFailure,
		Body:        "sensor loss: " + sensorName,
		Attrs:       map[string]any{attrSensorName: sensorName, attrSensorReason: reason},
	}
}

func newSensorRestartedEvent(sensorName, mechanism string) evidence.Event {
	attrs := map[string]any{attrSensorName: sensorName, attrSensorMechanism: mechanism}
	if mechanism == "procfs" {
		attrs[attrSensorCoverage] = "incomplete: polling can miss short-lived processes"
	}
	return evidence.Event{
		Name:        evidence.EventSensorRestarted,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassIntegrity,
		Outcome:     evidence.OutcomeSuccess,
		Body:        "sensor restarted: " + sensorName,
		Attrs:       attrs,
	}
}
