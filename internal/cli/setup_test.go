package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	boxedsetup "boxedai/internal/setup"
)

func TestDoctorJSONWritesActionRequiredResultBeforeExitTwo(t *testing.T) {
	original := doctorHost
	doctorHost = func(context.Context, string) boxedsetup.Result {
		return boxedsetup.Result{
			Schema:  boxedsetup.Schema,
			Type:    "result",
			Command: "doctor",
			Status:  "action_required",
			Arch:    "arm64",
			Home:    "/fixture/home",
			Checks:  []boxedsetup.Check{},
			Actions: []boxedsetup.Action{{ID: "install_corporate_ca", Title: "Connect WARP", Instructions: "Connect WARP and retry."}},
		}
	}
	t.Cleanup(func() { doctorHost = original })

	root := newRootCmd()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"doctor", "--json", "--arch", "arm64"})
	err := root.Execute()
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != 2 {
		t.Fatalf("doctor error = %v, want exit code 2", err)
	}
	var result boxedsetup.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("doctor JSON = %q: %v", output.String(), err)
	}
	if result.Schema != boxedsetup.Schema || result.Command != "doctor" || result.Status != "action_required" {
		t.Fatalf("doctor result = %+v", result)
	}
}

func TestSetupJSONWritesNDJSONStagesThenResult(t *testing.T) {
	original := setupHost
	setupHost = func(_ context.Context, opts boxedsetup.Options) boxedsetup.Result {
		opts.Emit(boxedsetup.StageEvent{Schema: boxedsetup.Schema, Type: "stage", Command: "setup", Stage: "preflight", Status: "running"})
		return boxedsetup.Result{Schema: boxedsetup.Schema, Type: "result", Command: "setup", Status: "ready", Ready: true, Arch: opts.Arch, Home: "/fixture/home", Checks: []boxedsetup.Check{}}
	}
	t.Cleanup(func() { setupHost = original })

	root := newRootCmd()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"setup", "--json", "--arch", "arm64"})
	if err := root.Execute(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("setup stdout lines = %q, want stage and result", lines)
	}
	for i, line := range lines {
		var value map[string]any
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			t.Fatalf("line %d is not JSON: %q: %v", i, line, err)
		}
		if value["schema"] != boxedsetup.Schema {
			t.Fatalf("line %d schema = %v", i, value["schema"])
		}
	}
}
