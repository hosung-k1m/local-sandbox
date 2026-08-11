package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	return path
}

func TestLoadConfig_Valid(t *testing.T) {
	path := writeConfig(t, `{
		"session_id": "bx-20260810-193004-a1b2c3d4",
		"broker_url": "http://host.lima.internal:5555",
		"supervisor_token": "supervisor-token",
		"workload_uid": 4242,
		"workspace_path": "/workspace",
		"tetragon_log": "/var/log/tetragon/tetragon.log",
		"nft_log_source": "/dev/kmsg"
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SessionID != "bx-20260810-193004-a1b2c3d4" {
		t.Errorf("SessionID = %q", cfg.SessionID)
	}
	if cfg.WorkloadUID != 4242 {
		t.Errorf("WorkloadUID = %d, want 4242", cfg.WorkloadUID)
	}
	if cfg.NFTLogSource != "/dev/kmsg" {
		t.Errorf("NFTLogSource = %q", cfg.NFTLogSource)
	}
}

func TestLoadConfig_DefaultsTetragonLog(t *testing.T) {
	path := writeConfig(t, `{
		"session_id": "bx-1",
		"broker_url": "http://host.lima.internal:5555",
		"supervisor_token": "tok",
		"workspace_path": "/workspace"
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.TetragonLog != defaultTetragonLog {
		t.Errorf("TetragonLog = %q, want default %q", cfg.TetragonLog, defaultTetragonLog)
	}
}

func TestLoadConfig_MissingRequiredField(t *testing.T) {
	path := writeConfig(t, `{"broker_url": "http://host.lima.internal:5555"}`)

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig: want error for missing session_id, got nil")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("LoadConfig: want error for missing file, got nil")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	path := writeConfig(t, `{not json`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig: want error for invalid JSON, got nil")
	}
}
