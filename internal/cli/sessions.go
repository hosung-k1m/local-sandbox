package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"boxedai/internal/session"
)

// newSessionsCmd builds `boxedai sessions`, a table of recorded sessions.
func newSessionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sessions",
		Short: "List recorded sessions and their state",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			infos, err := session.ListSessions()
			if err != nil {
				return err
			}
			if len(infos) == 0 {
				fmt.Fprintln(c.OutOrStdout(), "no sessions recorded")
				return nil
			}
			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATE\tHARNESS\tPROFILE\tCREATED")
			for _, s := range infos {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.SessionID, s.State, s.Harness, s.Profile, s.CreatedAt)
			}
			return tw.Flush()
		},
	}
}
