package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"boxedai/internal/session"
)

// workspaceDiffFile is the per-session unified diff file (DESIGN.md host layout).
const workspaceDiffFile = "workspace.diff"

// newDiffCmd builds `boxedai diff <session>`, printing the recorded workspace diff.
func newDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <session>",
		Short: "Print the workspace diff (input to output) for a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			path := filepath.Join(session.SessionDir(args[0]), workspaceDiffFile)
			b, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("cli: read workspace diff for %s: %w", args[0], err)
			}
			_, err = c.OutOrStdout().Write(b)
			return err
		},
	}
}
