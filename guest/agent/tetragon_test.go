package main

import "testing"

func TestParseTetragonLine_Exec(t *testing.T) {
	line := []byte(`{"process_exec":{"process":{"exec_id":"abc","pid":100,"uid":4242,"binary":"/usr/bin/node","arguments":"index.js","docker":"cg-1"},"parent":{"pid":1,"exec_id":"root"}}}`)

	tl, err := parseTetragonLine(line)
	if err != nil {
		t.Fatalf("parseTetragonLine: %v", err)
	}
	if tl.ProcessExec == nil {
		t.Fatal("ProcessExec is nil")
	}
	if tl.ProcessExit != nil {
		t.Fatal("ProcessExit should be nil for an exec line")
	}
	p := tl.ProcessExec.Process
	if p.Pid != 100 || p.Uid != 4242 || p.Binary != "/usr/bin/node" || p.Arguments != "index.js" || p.ExecID != "abc" || p.Docker != "cg-1" {
		t.Errorf("unexpected process fields: %+v", p)
	}
	if tl.ProcessExec.Parent.Pid != 1 {
		t.Errorf("Parent.Pid = %d, want 1", tl.ProcessExec.Parent.Pid)
	}
}

func TestParseTetragonLine_Exit(t *testing.T) {
	line := []byte(`{"process_exit":{"process":{"exec_id":"abc","pid":100,"uid":4242,"binary":"/usr/bin/node"},"parent":{"pid":1},"status":1}}`)

	tl, err := parseTetragonLine(line)
	if err != nil {
		t.Fatalf("parseTetragonLine: %v", err)
	}
	if tl.ProcessExit == nil {
		t.Fatal("ProcessExit is nil")
	}
	if tl.ProcessExit.Status != 1 {
		t.Errorf("Status = %d, want 1", tl.ProcessExit.Status)
	}
}

func TestParseTetragonLine_UnknownEventType(t *testing.T) {
	line := []byte(`{"process_kprobe":{"process":{"pid":5}}}`)

	tl, err := parseTetragonLine(line)
	if err != nil {
		t.Fatalf("parseTetragonLine: %v", err)
	}
	if tl.ProcessExec != nil || tl.ProcessExit != nil {
		t.Fatal("want both nil for an unrecognized event type")
	}
}

func TestParseTetragonLine_MalformedJSON(t *testing.T) {
	if _, err := parseTetragonLine([]byte(`{not json`)); err == nil {
		t.Fatal("parseTetragonLine: want error for malformed JSON, got nil")
	}
}

func TestBelongsToWorkload(t *testing.T) {
	if !belongsToWorkload(4242, 4242) {
		t.Error("want uid 4242 to belong to workload 4242")
	}
	if belongsToWorkload(0, 4242) {
		t.Error("want uid 0 to not belong to workload 4242")
	}
}
