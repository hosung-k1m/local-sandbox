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

const sentinelPollInterval = 1 * time.Second

func main() {
	if len(os.Args) > 1 && os.Args[1] == "git-bridge" {
		if err := runGitBridge(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			log.Printf("agent: git bridge: %v", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}

	client := NewEventClient(cfg.BrokerURL, cfg.SupervisorToken)
	batch := NewBatcher(client.Submit)

	// The batcher runs on its own context so it can outlive the watchers
	// long enough to flush events they emit while shutting down.
	batchCtx, cancelBatch := context.WithCancel(context.Background())
	batchDone := make(chan struct{})
	go func() { defer close(batchDone); batch.Run(batchCtx) }()

	watchCtx, cancelWatchers := context.WithCancel(context.Background())
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
	startWatcher("process", func(ctx context.Context) error { runProcessSensor(ctx, cfg, batch); return nil })
	startWatcher("file", func(ctx context.Context) error { return runFileWatcher(ctx, cfg.WorkspacePath, batch) })
	startWatcher("network", func(ctx context.Context) error { return runNetworkWatcher(ctx, cfg.NFTLogSource, batch) })

	waitForStop(watchCtx, cancelWatchers)
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
func waitForStop(ctx context.Context, cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	ticker := time.NewTicker(sentinelPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-sigCh:
			cancel()
			return
		case <-ticker.C:
			if _, err := os.Stat(stopSentinel); err == nil {
				cancel()
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
