package cli

import (
	"github.com/spf13/cobra"

	"boxedai/internal/session"
	"boxedai/internal/view"
)

// newViewCmd builds `boxedai view <session> [--web] [--addr]`.
func newViewCmd() *cobra.Command {
	var (
		web  bool
		addr string
	)
	cmd := &cobra.Command{
		Use:   "view <session>",
		Short: "Show a session's evidence timeline, or serve the web viewer",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			dir := session.SessionDir(args[0])
			if web {
				return view.ServeWeb(dir, addr)
			}
			return view.Timeline(dir, view.Filter{}, c.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&web, "web", false, "serve the embedded web viewer instead of printing the timeline")
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:0", "web viewer listen address (with --web)")
	return cmd
}
