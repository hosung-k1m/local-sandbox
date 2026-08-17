package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"boxedai/internal/evidence"
	"boxedai/internal/session"
	"boxedai/internal/view"
)

// viewTimeline is the timeline renderer the view command drives. It is a
// package variable so tests can substitute a fake that never touches a
// session directory while asserting the Filter the CLI built.
var viewTimeline = view.Timeline

// newViewCmd builds `boxedai view <session> [--web] [--addr] [--name] [--class]
// [--since] [--all] [--agent-activity]`.
func newViewCmd() *cobra.Command {
	var (
		web           bool
		addr          string
		name          string
		class         string
		since         string
		all           bool
		agentActivity bool
	)
	cmd := &cobra.Command{
		Use:   "view <session>",
		Short: "Show a session's evidence timeline, or serve the web viewer",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			dir := session.SessionDir(args[0])
			if web {
				for _, name := range []string{"name", "class", "since", "all", "agent-activity"} {
					if c.Flags().Changed(name) {
						return fmt.Errorf("cli: --%s cannot be used with --web", name)
					}
				}
				return view.ServeWeb(dir, addr)
			}
			if c.Flags().Changed("addr") {
				return fmt.Errorf("cli: --addr requires --web")
			}
			if all && agentActivity {
				return fmt.Errorf("cli: --all and --agent-activity are mutually exclusive")
			}
			filter := view.Filter{Name: name, Class: class, Since: since}
			switch {
			case agentActivity:
				filter.AgentActivity = true
			case !all:
				filter.ExcludeNames = []string{evidence.EventProcessCreated}
			}
			return viewTimeline(dir, filter, c.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&web, "web", false, "serve the embedded web viewer instead of printing the timeline")
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:0", "web viewer listen address (with --web)")
	cmd.Flags().StringVar(&name, "name", "", "filter timeline to events with this exact name")
	cmd.Flags().StringVar(&class, "class", "", "filter timeline to events with this exact evidence class")
	cmd.Flags().StringVar(&since, "since", "", "filter timeline to events at or after this RFC3339 timestamp")
	cmd.Flags().BoolVar(&all, "all", false, "show every event, including process.created noise hidden by default")
	cmd.Flags().BoolVar(&agentActivity, "agent-activity", false, "restrict the timeline to tool calls, executed processes, file/network/model activity, and rare lifecycle events")
	return cmd
}
