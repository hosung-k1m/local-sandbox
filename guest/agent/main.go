package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// configPath is the fixed location provisioning writes the guest agent's
// config to, per DESIGN.md guest supervisor duties (root-owned, 0600).
const configPath = "/etc/boxedai/agent.json"

// stopSentinel appearing on disk is the guest-side half of the kill switch
// (DESIGN.md: "On /etc/boxedai/stop sentinel or broker signal: freeze the
// session cgroup, drain, final flush").
const stopSentinel = "/etc/boxedai/stop"

// processSensorReadyPath is created once the process sensor can actually observe
// processes: after a fresh Tetragon lifecycle event, or — as the bounded fallback
// when Tetragon cannot satisfy that gate in time — on the procfs watcher's first
// scan, whose sensor.started/sensor.restarted evidence marks the coverage
// incomplete and drives an INCOMPLETE verdict.
// VM.WaitHealthy requires it before launching the harness.
const processSensorReadyPath = "/run/boxedai/process-sensor-ready"

const sentinelPollInterval = 1 * time.Second

func main() {
	if len(os.Args) > 1 && os.Args[1] == "git-bridge" {
		if err := runGitBridge(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			log.Printf("agent: git bridge: %v", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "lefthook" || os.Args[1] == "righthook") {
		// Hook mode always exits 0 (fail open): a hook that breaks the
		// workload defeats the point of capturing its evidence.
		os.Exit(runHook(os.Args[1], os.Stdin))
	}
	if len(os.Args) > 1 && os.Args[1] == "agenthook" {
		// SubagentStart/SubagentStop child registration; also fail-open.
		os.Exit(runAgentHook(os.Stdin))
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}

	client := NewEventClient(cfg.BrokerURL, cfg.SupervisorToken)
	batch := NewBatcher(client.Submit)
	if err := os.Remove(processSensorReadyPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("agent: remove stale process sensor readiness: %v", err)
	}

	// The batcher runs on its own context so it can outlive the watchers
	// long enough to flush events they emit while shutting down.
	batchCtx, cancelBatch := context.WithCancel(context.Background())
	batchDone := make(chan struct{})
	go func() { defer close(batchDone); batch.Run(batchCtx) }()

	watchCtx, cancelWatchers := context.WithCancel(context.Background())
	fatalWatcher := make(chan error, 1)
	var wg sync.WaitGroup
	startWatcher := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(watchCtx); err != nil {
				log.Printf("agent: %s watcher stopped: %v", name, err)
			}
		}()
	}
	startWatcher("process", func(ctx context.Context) error {
		err := runProcessSensor(ctx, cfg, batch, func() {
			if err := os.WriteFile(processSensorReadyPath, []byte("ready\n"), 0o644); err != nil {
				log.Fatalf("agent: mark process sensor ready: %v", err)
			}
		})
		if err != nil {
			fatalWatcher <- err
		}
		return err
	})
	startWatcher("file", func(ctx context.Context) error { return runFileWatcher(ctx, cfg.WorkspacePath, batch) })
	startWatcher("network", func(ctx context.Context) error { return runNetworkWatcher(ctx, cfg.NFTLogSource, batch) })

	fatalErr := waitForStop(watchCtx, cancelWatchers, fatalWatcher)
	if fatalErr != nil {
		// Exit immediately: boxedai-session BindsTo this service and uses
		// control-group SIGKILL, which is the final fail-closed stop path when
		// the supervisor could not stop the workload directly.
		log.Printf("agent: fatal process sensor failure: %v", fatalErr)
		os.Exit(1)
	}
	wg.Wait()

	// Watchers Add synchronously and have all returned by now (wg.Wait
	// above), so their events are already queued; a short grace lets any
	// final batch flush settle before the drain.
	time.Sleep(100 * time.Millisecond)
	cancelBatch()
	<-batchDone

	os.Exit(0)
}

// waitForStop blocks until SIGTERM or the stop sentinel file appears, then
// cancels cancel so all watchers unwind.
func waitForStop(ctx context.Context, cancel context.CancelFunc, fatal <-chan error) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	ticker := time.NewTicker(sentinelPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-sigCh:
			cancel()
			return nil
		case err := <-fatal:
			cancel()
			return err
		case <-ticker.C:
			if _, err := os.Stat(stopSentinel); err == nil {
				cancel()
				return nil
			}
		case <-ctx.Done():
			return nil
		}
	}
}
