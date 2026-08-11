package setup

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"boxedai/internal/image"
)

func TestRunConfiguresHostBuildsOnceAndDoctorReportsReady(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())
	configPath := filepath.Join(os.Getenv("BOXEDAI_HOME"), "config.json")
	if err := os.WriteFile(configPath, []byte("{\"custom\":{\"keep\":true}}\n"), 0o644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	originalGOOS := currentGOOS
	originalGOARCH := currentGOARCH
	originalLookPath := lookPath
	originalRunOutput := runOutput
	originalFreeDisk := freeDisk
	originalCheckNetwork := checkNetwork
	originalLoadCorporateCA := loadCorporateCA
	originalResolveImage := resolveImage
	originalBuildImage := buildImage
	t.Cleanup(func() {
		currentGOOS = originalGOOS
		currentGOARCH = originalGOARCH
		lookPath = originalLookPath
		runOutput = originalRunOutput
		freeDisk = originalFreeDisk
		checkNetwork = originalCheckNetwork
		loadCorporateCA = originalLoadCorporateCA
		resolveImage = originalResolveImage
		buildImage = originalBuildImage
	})

	currentGOOS = "darwin"
	currentGOARCH = "arm64"
	lookPath = func(string) (string, error) { return "/fixture/command", nil }
	runOutput = func(context.Context, string, ...string) (string, error) { return "1\n", nil }
	freeDisk = func(string) (uint64, error) { return minimumFreeDisk, nil }
	checkNetwork = func(context.Context, string) error { return nil }
	loadCorporateCA = func(context.Context) (string, error) { return "fixture-ca-pem\n", nil }

	built := false
	buildCalls := 0
	manifest := image.Manifest{
		Tag:           "boxedai-base-arm64",
		Arch:          "arm64",
		DiskDigest:    "sha256:fixture",
		ExtraCADigest: digest("fixture-ca-pem\n"),
		NPMRegistry:   BlockNPMRegistry,
	}
	resolveImage = func(string) (image.Manifest, error) {
		if !built {
			return image.Manifest{}, errors.New("missing")
		}
		return manifest, nil
	}
	buildImage = func(context.Context, string, string, string, io.Writer, io.Writer) (image.Manifest, error) {
		buildCalls++
		built = true
		return manifest, nil
	}

	var events []StageEvent
	result := Run(context.Background(), Options{
		Arch:        "arm64",
		ProgressOut: io.Discard,
		ProgressErr: io.Discard,
		Emit:        func(event StageEvent) { events = append(events, event) },
	})
	if !result.Ready || result.Status != "ready" {
		t.Fatalf("Run result = %+v, want ready", result)
	}
	if buildCalls != 1 {
		t.Fatalf("build calls = %d, want 1", buildCalls)
	}
	if len(events) != 6 || events[0].Stage != "preflight" || events[5].Stage != "image" {
		t.Fatalf("stage events = %+v, want three running/complete stage pairs", events)
	}

	if second := Run(context.Background(), Options{Arch: "arm64", ProgressOut: io.Discard, ProgressErr: io.Discard}); !second.Ready {
		t.Fatalf("second Run result = %+v, want ready", second)
	}
	if buildCalls != 1 {
		t.Fatalf("build calls after idempotent rerun = %d, want 1", buildCalls)
	}

	b, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(b, &config); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if _, ok := config["custom"]; !ok {
		t.Fatal("setup removed an unrelated config field")
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}

	if doctor := Doctor(context.Background(), "arm64"); !doctor.Ready || doctor.Status != "ready" || doctor.Image == nil {
		t.Fatalf("Doctor result = %+v, want ready image", doctor)
	}
}

func TestSafeCausePreservesDiagnosticAndOmitsCertificate(t *testing.T) {
	cause := errors.New("Lima failed\n-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\nretry")
	message := safeCause(cause)
	if !strings.Contains(message, "Lima failed") || !strings.Contains(message, "retry") {
		t.Fatalf("safe cause = %q, want diagnostic context", message)
	}
	if strings.Contains(message, "fixture") || !strings.Contains(message, "[certificate omitted]") {
		t.Fatalf("safe cause = %q, want certificate redaction", message)
	}
}
