package broker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeTelemetryPersistsOpaqueJSONWithProtectedFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claude-telemetry")
	b := mustBroker(t, Config{
		Emitter:            &fakeEmitter{},
		ClaudeTelemetryDir: dir,
	})
	srv := testServer(t, b)

	payloads := map[string]string{
		"logs":    `{ "resourceLogs": [{"scopeLogs": []}] }`,
		"metrics": `{"resourceMetrics":[]}`,
		"traces":  `{"resourceSpans":[]}`,
	}
	for signal, payload := range payloads {
		resp := do(t, "POST", srv.URL+"/v1/telemetry/claude/"+signal, b.WorkloadToken(), payload)
		drain(resp)
		if resp.StatusCode != 200 {
			t.Fatalf("%s status = %d, want 200", signal, resp.StatusCode)
		}

		path := filepath.Join(dir, signal+".jsonl")
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s telemetry: %v", signal, err)
		}
		if !strings.HasSuffix(string(got), "\n") || len(strings.Split(strings.TrimSpace(string(got)), "\n")) != 1 {
			t.Errorf("%s telemetry is not one JSONL record: %q", signal, got)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s telemetry: %v", signal, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s telemetry mode = %o, want 600", signal, info.Mode().Perm())
		}
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat telemetry directory: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("telemetry directory mode = %o, want 700", info.Mode().Perm())
	}
}

func TestClaudeTelemetryAppendsBatches(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claude-telemetry")
	b := mustBroker(t, Config{
		Emitter:            &fakeEmitter{},
		ClaudeTelemetryDir: dir,
	})
	srv := testServer(t, b)

	for _, payload := range []string{`{"resourceLogs":[{"batch":1}]}`, `{"resourceLogs":[{"batch":2}]}`} {
		resp := do(t, "POST", srv.URL+"/v1/telemetry/claude/logs", b.WorkloadToken(), payload)
		drain(resp)
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	}

	got, err := os.ReadFile(filepath.Join(dir, "logs.jsonl"))
	if err != nil {
		t.Fatalf("read telemetry: %v", err)
	}
	want := "{\"resourceLogs\":[{\"batch\":1}]}\n{\"resourceLogs\":[{\"batch\":2}]}\n"
	if string(got) != want {
		t.Errorf("telemetry = %q, want %q", got, want)
	}
}

func TestCodexTelemetryPersistsToSeparateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "codex-telemetry")
	b := mustBroker(t, Config{Emitter: &fakeEmitter{}, CodexTelemetryDir: dir})
	srv := testServer(t, b)
	resp := do(t, "POST", srv.URL+"/v1/telemetry/codex/logs", b.WorkloadToken(), `{"resourceLogs":[]}`)
	drain(resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "logs.jsonl")); err != nil || string(got) != "{\"resourceLogs\":[]}\n" {
		t.Errorf("Codex telemetry = %q, err = %v", got, err)
	}
}

func TestClaudeTelemetryRejectsUnauthenticatedAndInvalidPayloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claude-telemetry")
	b := mustBroker(t, Config{
		Emitter:            &fakeEmitter{},
		ClaudeTelemetryDir: dir,
	})
	srv := testServer(t, b)
	url := srv.URL + "/v1/telemetry/claude/logs"

	resp := do(t, "POST", url, "", `{}`)
	drain(resp)
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated status = %d, want 401", resp.StatusCode)
	}
	resp = do(t, "POST", url, b.SupervisorToken(), `{}`)
	drain(resp)
	if resp.StatusCode != 401 {
		t.Fatalf("supervisor-token status = %d, want 401", resp.StatusCode)
	}
	resp = do(t, "POST", url, b.WorkloadToken(), `not-json`)
	drain(resp)
	if resp.StatusCode != 400 {
		t.Fatalf("invalid JSON status = %d, want 400", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(dir, "logs.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("invalid telemetry created a file: %v", err)
	}
}
