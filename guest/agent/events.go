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
	attrProcessBinary   = "process.binary"
	attrProcessArgv     = "process.argv"
	attrProcessUID      = "process.uid"
	attrProcessExitCode = "process.exit_code"
	attrObserver        = "observer" // "tetragon" | "procfs" | "scan" | "nftables"
	attrFilePath        = "file.path"
	attrNetworkDestIP   = "network.dest.ip"
	attrNetworkDestPort = "network.dest.port"
	attrNetworkProto    = "network.proto"
	attrSensorName      = "sensor.name"
	attrSensorMechanism = "sensor.mechanism"
	attrSensorReason    = "sensor.reason"
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
	Pid      int64
	Ppid     int64
	Uid      int64
	Binary   string
	Argv     string
	ExecID   string
	CgroupID string
	Observer string // "tetragon" | "procfs"
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

func newProcessExitedEvent(pi ProcInfo, exitCode int64) evidence.Event {
	outcome := evidence.OutcomeSuccess
	if exitCode != 0 {
		outcome = evidence.OutcomeFailure
	}
	attrs := map[string]any{
		evidence.AttrProcessPID: pi.Pid,
		attrProcessExitCode:     exitCode,
		attrObserver:            pi.Observer,
	}
	attrs[evidence.AttrCorrelation] = string(procCorrelation(pi, attrs))
	return evidence.Event{
		Name:        evidence.EventProcessExited,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassKernelObserved,
		Outcome:     outcome,
		Body:        fmt.Sprintf("exit pid=%d code=%d", pi.Pid, exitCode),
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
	return evidence.Event{
		Name:        evidence.EventSensorStarted,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassIntegrity,
		Outcome:     evidence.OutcomeSuccess,
		Body:        "sensor started: " + mechanism,
		Attrs:       map[string]any{attrSensorMechanism: mechanism},
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
	return evidence.Event{
		Name:        evidence.EventSensorRestarted,
		Time:        time.Now(),
		MonotonicNS: monotonicNS(),
		Class:       evidence.ClassIntegrity,
		Outcome:     evidence.OutcomeSuccess,
		Body:        "sensor restarted: " + sensorName,
		Attrs:       map[string]any{attrSensorName: sensorName, attrSensorMechanism: mechanism},
	}
}
