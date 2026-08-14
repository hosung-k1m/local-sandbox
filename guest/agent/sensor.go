package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync/atomic"
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
	// tetragonUnhealthyPollsBeforeLoss is how many consecutive bad polls must
	// agree before Tetragon is declared lost. A single bad poll is a hiccup — a
	// slow liveness probe, a metrics endpoint that has not come up yet, a quiet
	// moment straddling the stale window — and degrading a healthy session's
	// coverage on one of those is worse than waiting a few more seconds
	// (DESIGN.md: "Loss is declared conservatively, not on a single bad
	// observation").
	tetragonUnhealthyPollsBeforeLoss = 3
	// tetragonMetricsTimeout bounds a single Tetragon metrics scrape. The
	// endpoint is guest-local, but it shares a CPU with an event storm, so a
	// 1s ceiling turned ordinary scheduling delay into declared sensor loss.
	tetragonMetricsTimeout = 5 * time.Second
	// workloadUnit is the transient systemd unit internal/vm launches the
	// harness under (vm.harnessUnit).
	workloadUnit = "boxedai-session.service"
)

var sensorLossFlushTimeout = 2 * time.Second

// readinessFallbackAfter bounds how long the process sensor waits for Tetragon to
// satisfy the readiness gate before degrading to procfs so the marker gets
// published at all (DESIGN.md session-time provisioning step 4). Without it a
// Tetragon that never loads its fork policy leaves readiness unpublished, the
// host's 120s health gate times out, and the session aborts having recorded
// nothing. Procfs coverage is honest (loss + incomplete-coverage evidence, INCOMPLETE
// verdict), so there is no reason to stall a session longer than this.
var readinessFallbackAfter = 30 * time.Second

// tetragonMetricsURL is Tetragon's guest-local metrics endpoint, in a var so tests can
// point the readiness gate at a fixture server.
var tetragonMetricsURL = "http://127.0.0.1:2112/metrics"

// tetragonLossMetrics is every counter tracked for ongoing (post-readiness) loss
// detection.
var tetragonLossMetrics = map[string]bool{
	"tetragon_observer_ringbuf_events_lost_total":       true,
	"tetragon_observer_ringbuf_errors_total":            true,
	"tetragon_observer_ringbuf_queue_events_lost_total": true,
	"tetragon_bpf_missed_events_total":                  true,
	"tetragon_notify_overflowed_events_total":           true,
	"tetragon_events_missing_process_info_total":        true,
	"tetragon_ratelimit_dropped_total":                  true,
}

// tetragonReadinessLossMetrics is the subset of tetragonLossMetrics allowed to block
// launch readiness: counters that move only when the kernel side actually dropped
// events. The two left out — tetragon_bpf_missed_events_total and
// tetragon_events_missing_process_info_total — are boot noise on a fresh VM. Every
// fork/exec/exit of a process that predates Tetragon's BPF maps misses that lookup
// (error="ENOENT") and bumps them, so they climb for as long as the VM is still
// booting, and a readiness gate that blocks on them degraded healthy fresh boots to
// procfs before the workload ever launched. They stay in the ongoing set, where a
// baseline anchored at readiness makes them mean what they say.
var tetragonReadinessLossMetrics = map[string]bool{
	"tetragon_observer_ringbuf_events_lost_total":       true,
	"tetragon_observer_ringbuf_errors_total":            true,
	"tetragon_observer_ringbuf_queue_events_lost_total": true,
	"tetragon_notify_overflowed_events_total":           true,
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
// Tetragon and switching to procfs after a loss, and reporting
// sensor.started once plus sensor.loss/sensor.restarted transitions
// (DESIGN.md: "if tetragon was expected but the file is missing/stale,
// sensor.loss then continue with procfs and sensor.restarted when back").
// Degradation never touches the workload; only losing every mechanism does.
func runProcessSensor(ctx context.Context, cfg Config, batch *Batcher, ready func()) error {
	mechanism := "tetragon"
	batch.Add(newSensorStartedEvent(mechanism))
	// The watcher goroutine publishes readiness while this loop reads it to decide
	// whether the fallback deadline still applies, hence atomic.
	var readyPublished atomic.Bool
	markReady := func() {
		readyPublished.Store(true)
		ready()
	}
	readinessDeadline := time.Now().Add(readinessFallbackAfter)

	for {
		watchCtx, cancelWatch := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func(mech string) {
			var err error
			if mech == "tetragon" {
				// Each watcher anchors its own loss baseline from its own first
				// scrape, so a restart after a degradation never inherits a stale
				// one (DESIGN.md step 4).
				err = runTetragonWatcher(watchCtx, cfg, batch, markReady)
			} else {
				// Procfs publishes readiness too: its sensor.started/
				// sensor.restarted evidence carries the incomplete-coverage
				// attribute, and the verifier turns that into INCOMPLETE, so the
				// honest thing is a launched-and-flagged session rather than a
				// session that never launches (DESIGN.md step 4).
				err = runProcfsWatcher(watchCtx, cfg, batch, markReady)
			}
			done <- err
		}(mechanism)

		health := make(chan string, 1)
		// mech is passed, not captured: the loop advances `mechanism` without
		// waiting for this goroutine to finish reading it.
		go func(mech string) {
			health <- monitorTetragonHealth(watchCtx, cfg.TetragonLog, mech, &readyPublished)
		}(mechanism)
		next := mechanism
		reason := "tetragon export stale, missing, or loss metrics nonzero"
		watcherFinished := false
		var procfsErr error
		// The readiness fallback is armed only while Tetragon still owes a
		// readiness gate it has not satisfied; procfs publishes on its first scan.
		var readinessFallback <-chan time.Time
		if mechanism == "tetragon" && !readyPublished.Load() {
			readinessFallback = time.After(time.Until(readinessDeadline))
		}
		// Readiness usually lands inside the window (about two seconds), while this
		// wait is still blocked on the timer it armed beforehand. Such a timer is
		// retired when it fires rather than acted on, so the wait re-enters instead
		// of transitioning.
		waiting := true
		for waiting {
			waiting = false
			select {
			case next = <-health:
			case <-readinessFallback:
				// Readiness is a once-per-session gate: the marker file is written and
				// the workload has launched, so this deadline no longer means anything.
				// An armed timer that stayed live is what recorded a spurious
				// sensor.loss at exactly the deadline in every session that outlived
				// it, flipping a Tetragon sensor that had been publishing kernel
				// evidence all along to procfs for an INCOMPLETE verdict. Coverage
				// after readiness is the health monitor's job, not the fallback's.
				if readyPublished.Load() {
					readinessFallback = nil
					waiting = true
					continue
				}
				next = "procfs"
				reason = fmt.Sprintf("tetragon did not establish process-sensor readiness within %s", readinessFallbackAfter)
			case err := <-done:
				watcherFinished = true
				if err != nil {
					log.Printf("agent: %s process watcher stopped: %v", mechanism, err)
					reason = err.Error()
				}
				if mechanism == "tetragon" {
					next = "procfs"
				} else {
					procfsErr = err
				}
			}
		}
		cancelWatch()
		if !watcherFinished {
			<-done
		}

		if ctx.Err() != nil {
			return nil // shutting down
		}
		switch {
		case procfsErr != nil:
			// The fail-closed floor: Tetragon already degraded and the procfs
			// fallback cannot observe processes either, so nothing is watching
			// the workload. This is the only sensor path that stops it
			// (DESIGN.md "No process sensor at all").
			if err := stopWorkloadFunc(ctx); err != nil && ctx.Err() == nil {
				log.Printf("agent: stop workload after total process-sensor loss: %v", err)
			}
			recordSensorLoss(ctx, batch, reason)
			return fmt.Errorf("agent: process sensor lost every mechanism: %w", procfsErr)
		case next == "procfs":
			recordSensorLoss(ctx, batch, reason)
			// Name the mechanism now in force. newSensorRestartedEvent carries the
			// incomplete-coverage attribute for procfs, so the switch is legible in
			// the timeline and the trust record's observed mechanisms even in a
			// session where no procfs-observed process happens to show up.
			batch.Add(newSensorRestartedEvent("process", "procfs"))
		default:
			batch.Add(newSensorRestartedEvent("process", "tetragon"))
		}
		mechanism = next
	}
}

// recordSensorLoss reports a process-sensor loss so the caller can degrade to the
// procfs watcher. It deliberately does NOT stop the workload and does NOT withdraw
// the readiness marker: SIGKILLing a running session (or blocking one from
// launching) because the authoritative sensor hiccuped destroys far more evidence
// than the degraded coverage costs, and procfs keeps recording fork/exec/exit with
// explicit incomplete-coverage marking. Offline verification still returns
// INCOMPLETE for the loss and for any procfs coverage, so the gap stays visible
// where it belongs — in the verdict, not in a dead workload.
func recordSensorLoss(ctx context.Context, batch *Batcher, reason string) {
	flushCtx, cancelFlush := context.WithTimeout(ctx, sensorLossFlushTimeout)
	defer cancelFlush()
	if err := batch.AddAndFlush(flushCtx, newSensorLossEvent("process", reason)); err != nil && ctx.Err() == nil {
		// The event remains queued for the batcher's retry/final-drain path.
		log.Printf("agent: sensor.loss delivery pending: %v", err)
	}
}

// stopWorkloadFunc is the guest-side hard stop of the workload unit, held in a var
// so tests can prove the ordinary degradation path never reaches it.
var stopWorkloadFunc = stopWorkload

func stopWorkload(ctx context.Context) error {
	return stopWorkloadWithRun(ctx, func(ctx context.Context, args ...string) error {
		return exec.CommandContext(ctx, "systemctl", args...).Run()
	})
}

func stopWorkloadWithRun(ctx context.Context, run func(context.Context, ...string) error) error {
	killErr := run(ctx, "kill", "--kill-whom=all", "--signal=SIGKILL", workloadUnit)
	stopErr := run(ctx, "stop", workloadUnit)
	if killErr == nil && stopErr == nil {
		return nil
	}
	// A unit that is not loaded at all — the harness has not launched yet, or has
	// already exited and been --collect'ed away — makes both calls exit nonzero,
	// and that is not a failure to stop anything. `systemctl is-active --quiet`
	// exits nonzero for inactive, failed, and not-found alike, so a nonzero probe
	// here means there is nothing left running. Treating "no such unit" as fatal
	// is what turned a pre-launch sensor hiccup into a supervisor crash-loop that
	// could never publish readiness.
	if err := run(ctx, "is-active", "--quiet", workloadUnit); err != nil {
		return nil
	}
	if killErr != nil {
		return fmt.Errorf("SIGKILL workload unit: %w", killErr)
	}
	return fmt.Errorf("stop workload unit: %w", stopErr)
}

// monitorTetragonHealth polls tetragonLog until ctx is cancelled (returns
// current, a no-op signal to stop) or the health state flips relative to
// current, returning the mechanism that should run next.
//
// The loss half of the probe is baseline-relative, not absolute: a booting VM always
// accrues some loss counts before the workload exists (e.g.
// tetragon_bpf_missed_events_total{error="ENOENT"} for processes that predate
// Tetragon's BPF maps, so their later exec/exit/fork miss the map), and those counters
// freeze once the boot storm settles. Absorbing that boot noise into the baseline lets
// only genuine loss trip the gate, matching DESIGN.md's baseline/freshness philosophy
// ("an existing export establishes only a size baseline"). The baseline is taken on the
// first poll after readiness rather than at watcher start: these counters are
// monotonic, so one captured mid-boot would keep reading as loss for the rest of the
// session, and loss before readiness cannot be workload evidence loss because readiness
// is what gates the launch.
func monitorTetragonHealth(ctx context.Context, tetragonLog, current string, readyPublished *atomic.Bool) string {
	baseline := -1.0
	return monitorTetragonHealthWithIntervalsAndProbe(ctx, tetragonLog, current, tetragonPollInterval, tetragonStaleAfter, func(ctx context.Context) error {
		if err := runTetragonProbe(ctx); err != nil {
			return err
		}
		if !readyPublished.Load() {
			return nil
		}
		total, err := tetragonLossTotal(ctx, tetragonMetricsURL, tetragonLossMetrics)
		if err != nil {
			return err
		}
		if baseline < 0 {
			baseline = total
			return nil
		}
		if total > baseline {
			return fmt.Errorf("Tetragon loss metric increased beyond baseline")
		}
		return nil
	})
}

// tetragonLossTotal scrapes the metrics endpoint and sums the given loss
// counters into a single monotonic total, used both to capture a baseline and
// to compare against it. Callers pass tetragonReadinessLossMetrics to gate readiness
// and tetragonLossMetrics to watch a running session.
func tetragonLossTotal(ctx context.Context, url string, metrics map[string]bool) (float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: tetragonMetricsTimeout}
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
		if !metrics[name] {
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
	return monitorTetragonHealthWithPollsBeforeLoss(ctx, tetragonLog, current, pollInterval, staleAfter, tetragonUnhealthyPollsBeforeLoss, probe)
}

func monitorTetragonHealthWithPollsBeforeLoss(ctx context.Context, tetragonLog, current string, pollInterval, staleAfter time.Duration, pollsBeforeLoss int, probe func(context.Context) error) string {
	prevSize := int64(-1)
	lastGrowthAt := time.Now()
	unhealthyPolls := 0
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
		if healthy && probeErr == nil {
			unhealthyPolls = 0
		} else {
			unhealthyPolls++
		}
		// Only a run of consecutive bad polls is loss; one is a hiccup.
		if current == "tetragon" && unhealthyPolls >= pollsBeforeLoss {
			return "procfs"
		}
		if current == "procfs" && healthy && grew && probeErr == nil {
			return "tetragon"
		}
	}
}
