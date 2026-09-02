package setup

import (
	"context"
	"testing"
)

func TestDoctorUsesPublicDependenciesOnly(t *testing.T) {
	origOS, origArch, origLook, origOutput, origNetwork := currentGOOS, currentGOARCH, lookPath, runOutput, checkNetwork
	t.Cleanup(func() {
		currentGOOS, currentGOARCH, lookPath, runOutput, checkNetwork = origOS, origArch, origLook, origOutput, origNetwork
	})
	currentGOOS, currentGOARCH = "darwin", "arm64"
	lookPath = func(string) (string, error) { return "/bin/tool", nil }
	runOutput = func(context.Context, string, ...string) (string, error) { return "1", nil }
	checkNetwork = func(context.Context, string) error { return nil }
	result := Doctor(context.Background(), "arm64")
	if !result.Ready || result.Status != "ready" {
		t.Fatalf("Doctor = %+v, want ready", result)
	}
	for _, check := range result.Checks {
		if check.ID == "corporate_ca" || check.ID == "network_global_block_artifacts_com:443" {
			t.Fatalf("unexpected company check: %+v", check)
		}
	}
}
