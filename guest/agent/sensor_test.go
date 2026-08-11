package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTetragonHealthy_MissingFile(t *testing.T) {
	healthy, size := tetragonHealthy(filepath.Join(t.TempDir(), "nope.log"), -1, time.Now())
	if healthy {
		t.Error("want unhealthy for a missing file")
	}
	if size != -1 {
		t.Errorf("size = %d, want -1", size)
	}
}

func TestTetragonHealthy_FirstObservationExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	healthy, size := tetragonHealthy(path, -1, time.Now())
	if !healthy {
		t.Error("want healthy on first observation of an existing file")
	}
	if size != 3 {
		t.Errorf("size = %d, want 3", size)
	}
}

func TestTetragonHealthy_Growth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	healthy, _ := tetragonHealthy(path, 3, time.Now())
	if !healthy {
		t.Error("want healthy when the file has grown since the last poll")
	}
}

func TestTetragonHealthy_StaleNoGrowth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// No growth, and the last check was well past the stale window.
	healthy, _ := tetragonHealthy(path, 3, time.Now().Add(-2*tetragonStaleAfter))
	if healthy {
		t.Error("want unhealthy when stale with no growth")
	}
}

func TestTetragonHealthy_QuietButRecent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tetragon.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// No growth, but still within the grace window: a quiet workload is
	// not the same as a dead sensor.
	healthy, _ := tetragonHealthy(path, 3, time.Now())
	if !healthy {
		t.Error("want healthy within the grace window even without growth")
	}
}
