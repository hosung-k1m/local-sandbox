package session

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"boxedai/internal/evidence"
)

const (
	harnessHomeDirName     = "harness-home"
	maxInstructionFileSize = 1 << 20
	claudeSettingsFileName = "settings.json"
	codexHooksFileName     = "hooks.json"
)

// claudeHooksSettingsJSON is the BoxedAi-authored Claude Code settings.json
// staged into the session harness home, never the host's own settings (see
// the exclusion in stageHarnessInstructions below). It wires PreToolUse/
// PostToolUse to the guest agent's lefthook/righthook subcommands so every
// tool invocation is recorded as tool.requested/tool.completed evidence, and
// SubagentStart/SubagentStop (no matcher — they match on agent type) to the
// agenthook subcommand so every subagent is registered as agent.started/
// agent.completed (DESIGN.md "Harness hook capture", "Agent hierarchy").
const claudeHooksSettingsJSON = `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/local/bin/boxedai-guest-agent lefthook", "timeout": 15}]}
    ],
    "PostToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/local/bin/boxedai-guest-agent righthook", "timeout": 15}]}
    ],
    "SubagentStart": [
      {"hooks": [{"type": "command", "command": "/usr/local/bin/boxedai-guest-agent agenthook", "timeout": 15}]}
    ],
    "SubagentStop": [
      {"hooks": [{"type": "command", "command": "/usr/local/bin/boxedai-guest-agent agenthook", "timeout": 15}]}
    ]
  }
}
`

// codexHooksJSON is the BoxedAi-authored Codex hook configuration. Codex reads
// it from CODEX_HOME alongside AGENTS.md; it deliberately contains only the
// capture wiring, never host authentication or user configuration.
const codexHooksJSON = `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/local/bin/boxedai-guest-agent lefthook", "timeout": 15}]}
    ],
    "PostToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/local/bin/boxedai-guest-agent righthook", "timeout": 15}]}
    ],
    "SubagentStart": [
      {"hooks": [{"type": "command", "command": "/usr/local/bin/boxedai-guest-agent agenthook", "timeout": 15}]}
    ],
    "SubagentStop": [
      {"hooks": [{"type": "command", "command": "/usr/local/bin/boxedai-guest-agent agenthook", "timeout": 15}]}
    ]
  }
}
`

// harnessSettingsDigest is the SHA-256 of the exact staged hook configuration.
func harnessSettingsDigest(harness string) string {
	switch harness {
	case "claude":
		return evidence.SHA256Hex([]byte(claudeHooksSettingsJSON))
	case "codex":
		return evidence.SHA256Hex([]byte(codexHooksJSON))
	default:
		return ""
	}
}

var hostUserHomeDir = os.UserHomeDir

type instructionFile struct {
	Source []string
	Name   string
}

var harnessInstructionFiles = map[string][]instructionFile{
	"claude": {
		{Source: []string{".claude", "CLAUDE.md"}, Name: "CLAUDE.md"},
		{Source: []string{".claude", "CLAUDE.local.md"}, Name: "CLAUDE.local.md"},
		{Source: []string{"CLAUDE.md"}, Name: "CLAUDE.md"},
	},
	"codex": {
		{Source: []string{".codex", "AGENTS.md"}, Name: "AGENTS.md"},
		{Source: []string{".codex", "AGENTS.override.md"}, Name: "AGENTS.override.md"},
		{Source: []string{"AGENTS.md"}, Name: "AGENTS.md"},
	},
}

// stageHarnessInstructions copies only conventional host-global instruction
// files into a fresh session-scoped harness home. It never mounts or copies the
// host's complete Claude/Codex configuration directories, and it rejects
// symlinks and unexpectedly large files. Repository-local instruction files
// already travel with the workspace snapshot/clone.
func stageHarnessInstructions(sessionDir, harness string) (string, error) {
	files, ok := harnessInstructionFiles[harness]
	if !ok {
		return "", nil
	}
	hostHome, err := hostUserHomeDir()
	if err != nil {
		return "", fmt.Errorf("session: resolve host home for instructions: %w", err)
	}
	destination := filepath.Join(sessionDir, harnessHomeDirName)
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return "", fmt.Errorf("session: create harness home: %w", err)
	}
	for _, candidate := range files {
		source := filepath.Join(append([]string{hostHome}, candidate.Source...)...)
		info, err := os.Lstat(source)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("session: inspect instruction file %s: %w", source, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("session: instruction file %s is not a regular file", source)
		}
		if info.Size() > maxInstructionFileSize {
			return "", fmt.Errorf("session: instruction file %s exceeds %d bytes", source, maxInstructionFileSize)
		}
		target := filepath.Join(destination, candidate.Name)
		if _, err := os.Stat(target); err == nil {
			continue
		}
		if err := copyInstructionFile(source, target); err != nil {
			return "", err
		}
	}
	// Stage only BoxedAi-authored hook wiring; no host settings/configuration
	// is copied into the isolated harness home.
	if harness == "claude" {
		settingsTarget := filepath.Join(destination, claudeSettingsFileName)
		if err := os.WriteFile(settingsTarget, []byte(claudeHooksSettingsJSON), 0o600); err != nil {
			return "", fmt.Errorf("session: write claude hooks settings: %w", err)
		}
	} else if harness == "codex" {
		hooksTarget := filepath.Join(destination, codexHooksFileName)
		if err := os.WriteFile(hooksTarget, []byte(codexHooksJSON), 0o600); err != nil {
			return "", fmt.Errorf("session: write codex hooks: %w", err)
		}
	}
	return destination, nil
}

func copyInstructionFile(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("session: open instruction file %s: %w", source, err)
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("session: create staged instruction file: %w", err)
	}
	if _, err := io.Copy(out, io.LimitReader(in, maxInstructionFileSize+1)); err != nil {
		out.Close()
		return fmt.Errorf("session: copy instruction file: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("session: close staged instruction file: %w", err)
	}
	return nil
}
