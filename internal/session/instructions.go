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
)

// claudeSettingsJSON is the BoxedAi-authored Claude Code settings.json staged
// into the session harness home, never the host's own settings (see the
// exclusion in stageHarnessInstructions below).
//
// permissions.defaultMode is acceptEdits so the agent can write/edit inside the
// workspace without an interactive approval prompt. This is sound only because
// the VM is the security boundary: writes land solely in the mediated FUSE
// workspace (per-mutation attributed and signed), egress is broker-gated, and
// the systemd unit blocks escalation — Claude's in-app prompt is redundant with
// those controls and, in a headless `-p` run, fails closed with no principal to
// answer it (Read/Bash dispatch but Write/Edit silently deny, so the run does
// nothing). acceptEdits, not bypassPermissions: it fixes exactly that failure
// while leaving non-edit tools to prompt when a human is present. The staged
// file sits at Claude's lowest settings precedence, so a user flag
// (`-- --permission-mode default`, `-- --dangerously-skip-permissions`) or a
// workspace's own .claude/settings.json overrides it with no BoxedAi code. Do
// not copy this default anywhere lacking the VM/FUSE/broker boundary.
//
// hooks wires PreToolUse/PostToolUse to the guest agent's lefthook/righthook
// subcommands so every tool invocation is recorded as tool.requested/
// tool.completed evidence, and SubagentStart/SubagentStop (no matcher — they
// match on agent type) to the agenthook subcommand so every subagent is
// registered as agent.started/agent.completed. Hooks fire in every permission
// mode (mode governs interactive approval, not hook execution), so capture is
// unaffected by defaultMode (DESIGN.md "Harness hook capture", "Agent
// hierarchy").
const claudeSettingsJSON = `{
  "permissions": {
    "defaultMode": "acceptEdits"
  },
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

// harnessSettingsDigest is the SHA-256 of the exact staged settings.json bytes,
// or "" for harnesses that stage no settings. stageHarnessInstructions writes
// []byte(claudeSettingsJSON) verbatim, so digesting the constant matches the
// on-disk file; the controller stamps this on the Primary Agent's agent.started
// as attestable settings provenance (permission posture and hook wiring).
func harnessSettingsDigest(harness string) string {
	if harness != "claude" {
		return ""
	}
	return evidence.SHA256Hex([]byte(claudeSettingsJSON))
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
	// Claude-only: stage the BoxedAi-authored settings — permission default plus
	// hook wiring (never the host's own settings.json — codex/exec get no hook
	// mechanism in v0.1).
	if harness == "claude" {
		settingsTarget := filepath.Join(destination, claudeSettingsFileName)
		if err := os.WriteFile(settingsTarget, []byte(claudeSettingsJSON), 0o600); err != nil {
			return "", fmt.Errorf("session: write claude settings: %w", err)
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
