package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// procfsPollInterval controls how often the fallback process sensor
// re-scans /proc.
const procfsPollInterval = 500 * time.Millisecond

// runProcfsWatcher polls /proc for processes owned by cfg.WorkloadUID,
// emitting process.executed when a new pid appears and process.exited when
// a previously seen pid disappears. It is the fallback process sensor when
// Tetragon is unavailable; correlation is weaker than the Tetragon path
// because /proc offers no exec id or cgroup lineage, only a uid+pid+ppid
// snapshot (DESIGN.md: "procfs fallback emits the same with correlation
// weaker (note in attrs)" — see ProcInfo.Observer).
func runProcfsWatcher(ctx context.Context, cfg Config, batch *Batcher, ready func()) error {
	seen := map[int64]ProcInfo{}
	ticker := time.NewTicker(procfsPollInterval)
	defer ticker.Stop()
	initialized := false
	for {
		current := scanProcfs(cfg.WorkloadUID)
		for pid, pi := range current {
			if _, ok := seen[pid]; !ok {
				batch.Add(newProcessExecutedEvent(pi))
			}
		}
		for pid, pi := range seen {
			if _, ok := current[pid]; !ok {
				// procfs offers no exit code on its own; recorded as unknown.
				batch.Add(newProcessExitedEvent(pi, ProcessExitStatus{}))
			}
		}
		seen = current
		if !initialized {
			initialized = true
			ready()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// scanProcfs returns the processes currently owned by workloadUID.
func scanProcfs(workloadUID int64) map[int64]ProcInfo {
	result := map[int64]ProcInfo{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}
	for _, e := range entries {
		pid, err := strconv.ParseInt(e.Name(), 10, 64)
		if err != nil {
			continue // not a pid directory
		}
		statusData, err := os.ReadFile(filepath.Join("/proc", e.Name(), "status"))
		if err != nil {
			continue // process gone or unreadable
		}
		uid, err := parseProcStatusUID(statusData)
		if err != nil || uid != workloadUID {
			continue
		}
		statData, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		ppid, _ := parseProcStatPPID(statData)
		cmdlineData, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		argv := parseProcCmdline(cmdlineData)
		binary := argv
		if fields := strings.Fields(argv); len(fields) > 0 {
			binary = fields[0]
		}
		result[pid] = ProcInfo{
			Pid: pid, Ppid: ppid, Uid: uid,
			Binary: binary, Argv: argv, Observer: "procfs",
		}
	}
	return result
}

// parseProcStatusUID extracts the real uid from a /proc/[pid]/status
// file's "Uid:" line (format: "Uid:\t<real>\t<effective>\t<saved>\t<fs>").
func parseProcStatusUID(data []byte) (int64, error) {
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("agent: malformed Uid line %q", line)
		}
		return strconv.ParseInt(fields[1], 10, 64)
	}
	return 0, fmt.Errorf("agent: no Uid line in status")
}

// parseProcStatPPID extracts the parent pid from a /proc/[pid]/stat file.
// The comm field (2nd, parenthesized) may itself contain spaces or
// parentheses, so parsing anchors on the last ')' before splitting the
// remaining whitespace-separated fields (state, ppid, ...).
func parseProcStatPPID(data []byte) (int64, error) {
	s := string(data)
	end := strings.LastIndex(s, ")")
	if end == -1 || end+1 >= len(s) {
		return 0, fmt.Errorf("agent: malformed stat line")
	}
	fields := strings.Fields(s[end+1:])
	if len(fields) < 2 {
		return 0, fmt.Errorf("agent: malformed stat line")
	}
	return strconv.ParseInt(fields[1], 10, 64)
}

// parseProcCmdline decodes a /proc/[pid]/cmdline file (NUL-separated argv)
// into a single space-joined string.
func parseProcCmdline(data []byte) string {
	parts := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	return strings.Join(parts, " ")
}
