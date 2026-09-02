package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageHarnessInstructionsCopiesOnlyConventionalFiles(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, ".claude", "CLAUDE.md"), "global instructions\n")
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), `{"secret":"must not copy"}`)
	original := hostUserHomeDir
	hostUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { hostUserHomeDir = original })

	destination, err := stageHarnessInstructions(t.TempDir(), "claude")
	if err != nil {
		t.Fatalf("stageHarnessInstructions: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "CLAUDE.md"))
	if err != nil {
		t.Fatalf("read staged instructions: %v", err)
	}
	if string(content) != "global instructions\n" {
		t.Errorf("staged content = %q", content)
	}
	// The host's settings.json must never leak through: the staged file is
	// always the BoxedAi-authored hook config, byte for byte.
	settingsContent, err := os.ReadFile(filepath.Join(destination, "settings.json"))
	if err != nil {
		t.Fatalf("read staged settings.json: %v", err)
	}
	if strings.Contains(string(settingsContent), "must not copy") {
		t.Errorf("staged settings.json leaked host content: %s", settingsContent)
	}
	if string(settingsContent) != claudeHooksSettingsJSON {
		t.Errorf("staged settings.json = %s, want BoxedAi-authored hook config %s", settingsContent, claudeHooksSettingsJSON)
	}
	settingsInfo, err := os.Stat(filepath.Join(destination, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if settingsInfo.Mode().Perm() != 0o600 {
		t.Errorf("settings.json mode = %o, want 600", settingsInfo.Mode().Perm())
	}
	info, err := os.Stat(filepath.Join(destination, "CLAUDE.md"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("instruction mode = %o, want 600", info.Mode().Perm())
	}
}

func TestStageHarnessInstructionsRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "real-instructions")
	writeFile(t, target, "instructions\n")
	if err := os.Symlink(target, filepath.Join(home, ".codex", "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	original := hostUserHomeDir
	hostUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { hostUserHomeDir = original })

	if _, err := stageHarnessInstructions(t.TempDir(), "codex"); err == nil {
		t.Fatal("expected symlink instruction file to be rejected")
	}
}

func TestStageHarnessInstructionsCodexStagesHooksJSON(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, ".codex", "AGENTS.md"), "codex instructions\n")
	original := hostUserHomeDir
	hostUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { hostUserHomeDir = original })

	destination, err := stageHarnessInstructions(t.TempDir(), "codex")
	if err != nil {
		t.Fatalf("stageHarnessInstructions: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, "settings.json")); !os.IsNotExist(err) {
		t.Errorf("codex staging must not produce Claude settings.json, stat error = %v", err)
	}
	hooks, err := os.ReadFile(filepath.Join(destination, codexHooksFileName))
	if err != nil {
		t.Fatalf("read staged hooks.json: %v", err)
	}
	if string(hooks) != codexHooksJSON {
		t.Errorf("hooks.json = %s, want BoxedAi-authored Codex hook config", hooks)
	}
	if info, err := os.Stat(filepath.Join(destination, codexHooksFileName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("hooks.json mode/stat = %v/%v, want 600", info, err)
	}
}
