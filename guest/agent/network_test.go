package main

import "testing"

func TestParseDeniedLine_Valid(t *testing.T) {
	line := `kernel: [12345.678] boxedai-denied: IN=eth0 OUT= SRC=10.0.2.15 DST=93.184.216.34 LEN=60 PROTO=TCP SPT=54321 DPT=443 WINDOW=0 SYN`

	conn, err := parseDeniedLine(line)
	if err != nil {
		t.Fatalf("parseDeniedLine: %v", err)
	}
	if conn.DestIP != "93.184.216.34" {
		t.Errorf("DestIP = %q, want 93.184.216.34", conn.DestIP)
	}
	if conn.DestPort != 443 {
		t.Errorf("DestPort = %d, want 443", conn.DestPort)
	}
	if conn.Proto != "TCP" {
		t.Errorf("Proto = %q, want TCP", conn.Proto)
	}
}

func TestParseDeniedLine_MissingPrefix(t *testing.T) {
	line := `kernel: [12345.678] SRC=10.0.2.15 DST=93.184.216.34 PROTO=TCP DPT=443`
	if _, err := parseDeniedLine(line); err == nil {
		t.Fatal("parseDeniedLine: want error for line missing boxedai-denied prefix")
	}
}

func TestParseDeniedLine_MissingDST(t *testing.T) {
	line := `kernel: boxedai-denied: SRC=10.0.2.15 PROTO=TCP DPT=443`
	if _, err := parseDeniedLine(line); err == nil {
		t.Fatal("parseDeniedLine: want error for line missing DST")
	}
}

func TestParseDeniedLine_MalformedPort(t *testing.T) {
	line := `kernel: boxedai-denied: DST=93.184.216.34 PROTO=TCP DPT=notaport`
	if _, err := parseDeniedLine(line); err == nil {
		t.Fatal("parseDeniedLine: want error for malformed DPT")
	}
}
