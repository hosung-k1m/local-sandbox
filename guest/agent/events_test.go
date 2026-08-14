package main

import (
	"testing"

	"boxedai/internal/evidence"
)

func TestProcessExecutedIncludesParentExecIdentity(t *testing.T) {
	event := newProcessExecutedEvent(ProcInfo{
		Pid: 10, Ppid: 1, Uid: 4242, ExecID: "child", ParentExecID: "parent", Observer: "tetragon",
	})

	if event.Attrs[attrProcessParentExecID] != "parent" {
		t.Fatalf("parent exec id = %v, want parent", event.Attrs[attrProcessParentExecID])
	}
}

func TestProcessExitDistinguishesCodeSignalAndUnknown(t *testing.T) {
	code := int64(0)
	tests := []struct {
		name        string
		status      ProcessExitStatus
		wantStatus  string
		wantOutcome evidence.Outcome
	}{
		{name: "code", status: ProcessExitStatus{Code: &code}, wantStatus: "code", wantOutcome: evidence.OutcomeSuccess},
		{name: "signal", status: ProcessExitStatus{Signal: "SIGKILL"}, wantStatus: "signal", wantOutcome: evidence.OutcomeInterrupted},
		{name: "signal overrides status field", status: ProcessExitStatus{Code: &code, Signal: "SIGKILL"}, wantStatus: "signal", wantOutcome: evidence.OutcomeInterrupted},
		{name: "unknown", status: ProcessExitStatus{}, wantStatus: "unknown", wantOutcome: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := newProcessExitedEvent(ProcInfo{Pid: 10, Observer: "tetragon"}, tt.status)
			if event.Attrs[attrProcessExitStatus] != tt.wantStatus || event.Outcome != tt.wantOutcome {
				t.Fatalf("status/outcome = %v/%s, want %s/%s", event.Attrs[attrProcessExitStatus], event.Outcome, tt.wantStatus, tt.wantOutcome)
			}
		})
	}
}
