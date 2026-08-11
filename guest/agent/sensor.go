package main

import (
	"context"
	"log"
	"os"
	"time"
)

const (
	// tetragonStaleAfter is how long the Tetragon export can go without
	// growing before it's considered stale (DESIGN.md: "if tetragon_log
	// exists and grows"); a quiet workload can legitimately produce no
	// exec events briefly, so this is a grace window, not an instant
	// failure.
	tetragonStaleAfter = 5 * time.Second
	// tetragonPollInterval controls how often health is re-checked while
	// a mechanism is active.
	tetragonPollInterval = 2 * time.Second
)

// tetragonHealthy reports whether the Tetragon JSON export at path exists
// and is growing. prevSize/prevCheckedAt carry state across polls; pass
// prevSize < 0 on the first call, in which case mere existence is treated
// as healthy (growth is confirmed on the next poll).
func tetragonHealthy(path string, prevSize int64, prevCheckedAt time.Time) (healthy bool, size int64) {
	info, err := os.Stat(path)
	if err != nil {
		return false, -1
	}
	size = info.Size()
	if prevSize < 0 || size > prevSize {
		return true, size
	}
	// No growth: only unhealthy once stale, not on every quiet poll.
	return time.Since(prevCheckedAt) < tetragonStaleAfter, size
}

// runProcessSensor supervises the process watcher, switching between
// Tetragon and procfs as Tetragon's health changes, and reporting
// sensor.started once plus sensor.loss/sensor.restarted transitions
// (DESIGN.md: "if tetragon was expected but the file is missing/stale,
// sensor.loss then continue with procfs and sensor.restarted when back").
func runProcessSensor(ctx context.Context, cfg Config, batch *Batcher) {
	mechanism := "procfs"
	if _, err := os.Stat(cfg.TetragonLog); err == nil {
		mechanism = "tetragon"
	}
	batch.Add(newSensorStartedEvent(mechanism))

	for {
		watchCtx, cancelWatch := context.WithCancel(ctx)
		done := make(chan struct{})
		go func(mech string) {
			defer close(done)
			var err error
			if mech == "tetragon" {
				err = runTetragonWatcher(watchCtx, cfg, batch)
			} else {
				err = runProcfsWatcher(watchCtx, cfg, batch)
			}
			if err != nil {
				log.Printf("agent: %s process watcher stopped: %v", mech, err)
			}
		}(mechanism)

		next := monitorTetragonHealth(ctx, cfg.TetragonLog, mechanism)
		cancelWatch()
		<-done

		if ctx.Err() != nil {
			return // shutting down
		}
		if next == "procfs" {
			batch.Add(newSensorLossEvent("process", "tetragon export stale or missing"))
		} else {
			batch.Add(newSensorRestartedEvent("process", "tetragon"))
		}
		mechanism = next
	}
}

// monitorTetragonHealth polls tetragonLog until ctx is cancelled (returns
// current, a no-op signal to stop) or the health state flips relative to
// current, returning the mechanism that should run next.
func monitorTetragonHealth(ctx context.Context, tetragonLog, current string) string {
	prevSize := int64(-1)
	prevChecked := time.Now()
	ticker := time.NewTicker(tetragonPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return current
		case <-ticker.C:
		}
		healthy, size := tetragonHealthy(tetragonLog, prevSize, prevChecked)
		prevSize, prevChecked = size, time.Now()
		if current == "tetragon" && !healthy {
			return "procfs"
		}
		if current == "procfs" && healthy {
			return "tetragon"
		}
	}
}
