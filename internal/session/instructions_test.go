package session

import (
	"os"
	"path/filepath"
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
	if _, err := os.Stat(filepath.Join(destination, "settings.json")); !os.IsNotExist(err) {
		t.Errorf("settings.json must not be copied, stat error = %v", err)
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
