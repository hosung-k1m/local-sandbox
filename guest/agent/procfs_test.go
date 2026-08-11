package main

import "testing"

func TestParseProcStatusUID(t *testing.T) {
	data := []byte("Name:\tnode\nState:\tS (sleeping)\nUid:\t4242\t4242\t4242\t4242\nGid:\t4242\t4242\t4242\t4242\n")

	uid, err := parseProcStatusUID(data)
	if err != nil {
		t.Fatalf("parseProcStatusUID: %v", err)
	}
	if uid != 4242 {
		t.Errorf("uid = %d, want 4242", uid)
	}
}

func TestParseProcStatusUID_Missing(t *testing.T) {
	if _, err := parseProcStatusUID([]byte("Name:\tnode\n")); err == nil {
		t.Fatal("parseProcStatusUID: want error when Uid line is absent")
	}
}

func TestParseProcStatPPID(t *testing.T) {
	// comm field can itself contain spaces/parens; the real /proc format is
	// "pid (comm) state ppid ...".
	data := []byte("100 (my (weird) proc) S 42 100 100 0 -1 4194304 100 0 0 0")

	ppid, err := parseProcStatPPID(data)
	if err != nil {
		t.Fatalf("parseProcStatPPID: %v", err)
	}
	if ppid != 42 {
		t.Errorf("ppid = %d, want 42", ppid)
	}
}

func TestParseProcStatPPID_Malformed(t *testing.T) {
	if _, err := parseProcStatPPID([]byte("no parens here")); err == nil {
		t.Fatal("parseProcStatPPID: want error for missing parens")
	}
}

func TestParseProcCmdline(t *testing.T) {
	data := []byte("/usr/bin/node\x00index.js\x00--flag\x00")
	got := parseProcCmdline(data)
	want := "/usr/bin/node index.js --flag"
	if got != want {
		t.Errorf("parseProcCmdline = %q, want %q", got, want)
	}
}
