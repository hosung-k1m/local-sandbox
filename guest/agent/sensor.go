package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/prometheus/common/expfmt"
)

const (
	// tetragonStaleAfter is how long the Tetragon export can go without
	// growing after a liveness probe before it's considered stale
	// (DESIGN.md: "if tetragon_log exists and grows").
	tetragonStaleAfter = 5 * time.Second
	// tetragonPollInterval controls how often health is re-checked while
	// a mechanism is active.
	tetragonPollInterval = 2 * time.Second
)

var sensorLossFlushTimeout = 2 * time.Second

const tetragonMetricsURL = "http://127.0.0.1:2112/metrics"

var tetragonLossMetrics = map[string]bool{
	"tetragon_observer_ringbuf_events_lost_total":       true,
	"tetragon_observer_ringbuf_errors_total":            true,
	"tetragon_observer_ringbuf_queue_events_lost_total": true,
	"tetragon_bpf_missed_events_total":                  true,
	"tetragon_notify_overflowed_events_total":           true,
	"tetragon_events_missing_process_info_total":        true,
	"tetragon_ratelimit_dropped_total":                  true,
}

// tetragonHealthy reports whether the Tetragon JSON export at path exists
// and is growing. prevSize/lastGrowthAt carry state across polls; pass
// prevSize < 0 on the first call, in which case the file must also have been
// modified within the stale window. This prevents a baked stale export from
// establishing Tetragon readiness merely because the path exists.
func tetragonHealthy(path string, prevSize int64, lastGrowthAt time.Time) (healthy bool, size int64) {
	return tetragonHealthyWithStaleAfter(path, prevSize, lastGrowthAt, tetragonStaleAfter)
}

func tetragonHealthyWithStaleAfter(path string, prevSize int64, lastGrowthAt time.Time, staleAfter time.Duration) (healthy bool, size int64) {
	info, err := os.Stat(path)
	if err != nil {
		return false, -1
	}
	size = info.Size()
	if prevSize < 0 {
		return time.Since(info.ModTime()) < staleAfter, size
	}
	if size > prevSize {
		return true, size
	}
	// No growth: only unhealthy once stale, not on every quiet poll.
	return time.Since(lastGrowthAt) < staleAfter, size
}

// runProcessSensor supervises the process watcher, starting with authoritative
// Tetragon and switching to diagnostic-only procfs after a loss, and reporting
// sensor.started once plus sensor.loss/sensor.restarted transitions
// (DESIGN.md: "if tetragon was expected but the file is missing/stale,
// sensor.loss then continue with procfs and sensor.restarted when back").
func runProcessSensor(ctx context.Context, cfg Config, batch *Batcher, ready func()) error {
	mechanism := "tetragon"
	batch.Add(newSensorStartedEvent(mechanism))
	markReady := ready

	for {
		// Snapshot Tetragon's loss counters now, after its session-time restart,
		// so pre-workload boot noise is the baseline and only post-start loss
		// trips readiness or the ongoing health gate. A failed scrape falls back
		// to 0 (conservative: any tracked loss then blocks), and the per-poll
		// scrape surfaces the same endpoint error.
		lossBaseline, err := tetragonLossTotal(ctx, tetragonMetricsURL)
		if err != nil {
			log.Printf("agent: Tetragon loss-metric baseline scrape failed, using 0: %v", err)
			lossBaseline = 0
		}
		watchCtx, cancelWatch := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func(mech string) {
			var err error
			if mech == "tetragon" {
				err = runTetragonWatcher(watchCtx, cfg, batch, markReady, lossBaseline)
			} else {
				err = runProcfsWatcher(watchCtx, cfg, batch, func() {})
			}
			done <- err
		}(mechanism)

		health := make(chan string, 1)
		go func() { health <- monitorTetragonHealth(watchCtx, cfg.TetragonLog, mechanism, lossBaseline) }()
		next := mechanism
		reason := "tetragon export stale, missing, or loss metrics nonzero"
		watcherFinished := false
		select {
		case next = <-health:
		case err := <-done:
			watcherFinished = true
			if err != nil {
				log.Printf("agent: %s process watcher stopped: %v", mechanism, err)
				reason = err.Error()
			}
			if mechanism == "tetragon" {
				next = "procfs"
			}
		}
		cancelWatch()
		if !watcherFinished {
			<-done
		}

		if ctx.Err() != nil {
			return nil // shutting down
		}
		if next == "procfs" {
			if err := handleTetragonLoss(ctx, batch, processSensorReadyPath, reason, stopWorkload); err != nil {
				return err
			}
		} else {
			batch.Add(newSensorRestartedEvent("process", "tetragon"))
		}
		mechanism = next
	}
}

func handleTetragonLoss(ctx context.Context, batch *Batcher, readyPath, reason string, stop func(context.Context) error) error {
	if err := os.Remove(readyPath); err != nil && !os.IsNotExist(err) {
		log.Printf("agent: remove process sensor readiness after loss: %v", err)
	}
	if err := stop(ctx); err != nil && ctx.Err() == nil {
		return fmt.Errorf("agent: stop workload after Tetragon loss: %w", err)
	}
	flushCtx, cancelFlush := context.WithTimeout(ctx, sensorLossFlushTimeout)
	if err := batch.AddAndFlush(flushCtx, newSensorLossEvent("process", reason)); err != nil && ctx.Err() == nil {
		// The event remains queued for the batcher's retry/final-drain path.
		log.Printf("agent: sensor.loss delivery pending after workload stop: %v", err)
	}
	cancelFlush()
	return nil
}

func stopWorkload(ctx context.Context) error {
	return stopWorkloadWithRun(ctx, func(ctx context.Context, args ...string) error {
		return exec.CommandContext(ctx, "systemctl", args...).Run()
	})
}

func stopWorkloadWithRun(ctx context.Context, run func(context.Context, ...string) error) error {
	killErr := run(ctx, "kill", "--kill-whom=all", "--signal=SIGKILL", "boxedai-session.service")
	stopErr := run(ctx, "stop", "boxedai-session.service")
	if killErr != nil {
		return fmt.Errorf("SIGKILL workload unit: %w", killErr)
	}
	if stopErr != nil {
		return fmt.Errorf("stop workload unit: %w", stopErr)
	}
	return nil
}

// monitorTetragonHealth polls tetragonLog until ctx is cancelled (returns
// current, a no-op signal to stop) or the health state flips relative to
// current, returning the mechanism that should run next.
func monitorTetragonHealth(ctx context.Context, tetragonLog, current string, lossBaseline float64) string {
	return monitorTetragonHealthWithIntervalsAndProbe(ctx, tetragonLog, current, tetragonPollInterval, tetragonStaleAfter, func(ctx context.Context) error {
		if err := runTetragonProbe(ctx); err != nil {
			return err
		}
		lost, err := tetragonMetricsLost(ctx, tetragonMetricsURL, lossBaseline)
		if err != nil {
			return err
		}
		if lost {
			return fmt.Errorf("Tetragon loss metric increased beyond baseline")
		}
		return nil
	})
}

// tetragonMetricsLost reports whether Tetragon's tracked loss counters have
// grown past baseline — the total captured when this Tetragon watch began,
// after the session-time restart. The gate is baseline-relative, not absolute:
// a booting VM always accrues some loss counts before the workload exists
// (e.g. tetragon_bpf_missed_events_total{error="ENOENT"} for processes that
// predate Tetragon's BPF maps, so their later exec/exit/fork miss the map),
// and those counters freeze once the boot storm settles. Absorbing that boot
// noise into the baseline lets only genuine post-start loss trip the gate,
// matching DESIGN.md's baseline/freshness philosophy ("an existing export
// establishes only a size baseline").
func tetragonMetricsLost(ctx context.Context, url string, baseline float64) (bool, error) {
	total, err := tetragonLossTotal(ctx, url)
	if err != nil {
		return false, err
	}
	return total > baseline, nil
}

// tetragonLossTotal scrapes the metrics endpoint and sums every tracked loss
// counter into a single monotonic total, used both to capture the baseline and
// to compare against it.
func tetragonLossTotal(ctx context.Context, url string) (float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("Tetragon metrics status %d", resp.StatusCode)
	}
	families, err := new(expfmt.TextParser).TextToMetricFamilies(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("parse Tetragon metrics: %w", err)
	}
	total := 0.0
	for name, family := range families {
		if !tetragonLossMetrics[name] {
			continue
		}
		for _, metric := range family.Metric {
			total += metric.GetCounter().GetValue() + metric.GetGauge().GetValue() + metric.GetUntyped().GetValue()
		}
	}
	return total, nil
}

// runTetragonProbe starts a root-owned process whose lifecycle should make a
// working Tetragon exporter grow. Root events prove sensor liveness but remain
// outside workload evidence because the watcher filters by the workload UID.
func runTetragonProbe(ctx context.Context) error {
	return exec.CommandContext(ctx, "/bin/true").Run()
}

func monitorTetragonHealthWithIntervalsAndProbe(ctx context.Context, tetragonLog, current string, pollInterval, staleAfter time.Duration, probe func(context.Context) error) string {
	prevSize := int64(-1)
	lastGrowthAt := time.Now()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return current
		case <-ticker.C:
		}
		probeErr := probe(ctx)
		if probeErr != nil && ctx.Err() == nil {
			log.Printf("agent: Tetragon liveness probe failed: %v", probeErr)
		}
		healthy, size := tetragonHealthyWithStaleAfter(tetragonLog, prevSize, lastGrowthAt, staleAfter)
		grew := prevSize >= 0 && size > prevSize
		if prevSize < 0 || size > prevSize {
			lastGrowthAt = time.Now()
		}
		prevSize = size
		if current == "tetragon" && (!healthy || probeErr != nil) {
			return "procfs"
		}
		if current == "procfs" && healthy && grew && probeErr == nil {
			return "tetragon"
		}
	}
}
