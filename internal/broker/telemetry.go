package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

const maxTelemetryBody = 64 << 20 // 64 MiB

// prepareClaudeTelemetry creates the host-only collector directory before the
// guest starts. It must remain outside the guest-writable Claude config mount.
func prepareClaudeTelemetry(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("broker: create Claude telemetry directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("broker: protect Claude telemetry directory: %w", err)
	}
	return nil
}

// handleClaudeTelemetry stores each authenticated OTLP HTTP/JSON export batch
// as one compact JSONL record. The payload is intentionally opaque: BoxedAi
// validates JSON framing but does not reimplement the OTLP schema.
func (b *Broker) handleClaudeTelemetry(w http.ResponseWriter, r *http.Request, _ authKind) {
	fileName, ok := claudeTelemetryFileName(r.PathValue("signal"))
	if !ok || b.cfg.ClaudeTelemetryDir == "" {
		writeErr(w, http.StatusNotFound, "unknown Claude telemetry signal")
		return
	}
	body, err := readBody(r, maxTelemetryBody)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		writeErr(w, http.StatusBadRequest, "body must be valid JSON")
		return
	}
	compact.WriteByte('\n')

	b.telemetryMu.Lock()
	err = appendTelemetry(filepath.Join(b.cfg.ClaudeTelemetryDir, fileName), compact.Bytes())
	b.telemetryMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "persist Claude telemetry failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func claudeTelemetryFileName(signal string) (string, bool) {
	switch signal {
	case "logs":
		return "logs.jsonl", true
	case "metrics":
		return "metrics.jsonl", true
	case "traces":
		return "traces.jsonl", true
	default:
		return "", false
	}
}

func appendTelemetry(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("broker: open Claude telemetry file: %w", err)
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("broker: protect Claude telemetry file: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		return fmt.Errorf("broker: append Claude telemetry: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("broker: sync Claude telemetry: %w", err)
	}
	return nil
}
