package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"boxedai/internal/session"
	"boxedai/internal/snapshot"
)

// grantFile is the per-session grant file (DESIGN.md host layout).
const grantFile = "session.json"

// newApplyCmd builds `boxedai apply <session>`, which applies a session's recorded
// workspace diff back onto the original repository after TTY confirmation.
func newApplyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "apply <session>",
		Short: "Apply a session's workspace diff onto the original repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id := args[0]
			dir := session.SessionDir(id)
			repoPath, err := repoPathFromGrant(dir)
			if err != nil {
				return err
			}
			prompt := fmt.Sprintf("Apply workspace diff from %s onto %s?", id, repoPath)
			if !confirm(os.Stdin, c.OutOrStdout(), prompt) {
				fmt.Fprintln(c.OutOrStdout(), "aborted")
				return nil
			}
			if err := snapshot.Apply(dir, repoPath); err != nil {
				return fmt.Errorf("cli: apply %s: %w", id, err)
			}
			fmt.Fprintf(c.OutOrStdout(), "applied %s onto %s\n", id, repoPath)
			return nil
		},
	}
}

// repoPathFromGrant reads the original repository path from a session's
// session.json grant (DESIGN.md: apply reads the repo path from the grant).
func repoPathFromGrant(sessionDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(sessionDir, grantFile))
	if err != nil {
		return "", fmt.Errorf("cli: read session grant: %w", err)
	}
	var g struct {
		RepoPath string `json:"repo_path"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		return "", fmt.Errorf("cli: parse session grant: %w", err)
	}
	if g.RepoPath == "" {
		return "", fmt.Errorf("cli: session %s has no recorded repo_path", filepath.Base(sessionDir))
	}
	return g.RepoPath, nil
}

// confirm renders prompt and reads a y/N answer. Mirroring the session approver,
// it fails closed when stdin is not a TTY (scripted / non-interactive): no prompt,
// treated as "no".
func confirm(in *os.File, out io.Writer, prompt string) bool {
	if !isatty.IsTerminal(in.Fd()) {
		return false
	}
	fmt.Fprintf(out, "%s [y/N] ", prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
