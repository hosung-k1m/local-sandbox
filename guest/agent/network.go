package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// deniedPrefix is the nftables log prefix DESIGN.md wires into the deny
// rule: "deny+log everything else with prefix boxedai-denied".
const deniedPrefix = "boxedai-denied"

// deniedConn is a parsed nftables denial log line.
type deniedConn struct {
	DestIP   string
	DestPort int64
	Proto    string
}

// parseDeniedLine extracts dest ip/port/proto from an nftables log line
// carrying the boxedai-denied prefix (netfilter LOG format: space-separated
// KEY=VALUE fields, e.g. "...SRC=10.0.2.15 DST=93.184.216.34 PROTO=TCP
// SPT=54321 DPT=443..."). Lines without the prefix, or missing DST, are not
// denial events and return an error so the caller can skip them.
func parseDeniedLine(line string) (*deniedConn, error) {
	if !strings.Contains(line, deniedPrefix) {
		return nil, fmt.Errorf("agent: not a %s line", deniedPrefix)
	}
	var conn deniedConn
	for _, f := range strings.Fields(line) {
		switch {
		case strings.HasPrefix(f, "DST="):
			conn.DestIP = strings.TrimPrefix(f, "DST=")
		case strings.HasPrefix(f, "DPT="):
			port, err := strconv.ParseInt(strings.TrimPrefix(f, "DPT="), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("agent: parse DPT in denied line: %w", err)
			}
			conn.DestPort = port
		case strings.HasPrefix(f, "PROTO="):
			conn.Proto = strings.TrimPrefix(f, "PROTO=")
		}
	}
	if conn.DestIP == "" {
		return nil, fmt.Errorf("agent: denied line missing DST")
	}
	return &conn, nil
}

// runNetworkWatcher tails source for boxedai-denied lines and forwards
// network.denied events. If source is unconfigured or unreadable, it
// reports sensor.loss for the network sensor once and returns (best
// effort: DESIGN.md does not require the daemon to exit when network
// evidence is unavailable).
func runNetworkWatcher(ctx context.Context, source string, batch *Batcher) error {
	if source == "" {
		batch.Add(newSensorLossEvent("network", "nft_log_source not configured"))
		return nil
	}
	if _, err := os.Stat(source); err != nil {
		batch.Add(newSensorLossEvent("network", fmt.Sprintf("log source unavailable: %v", err)))
		return nil
	}
	return tailFollow(ctx, source, func(line string) {
		conn, err := parseDeniedLine(line)
		if err != nil {
			return
		}
		batch.Add(newNetworkDeniedEvent(conn.DestIP, conn.DestPort, conn.Proto))
	})
}
