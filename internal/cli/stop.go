package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"boxedai/internal/session"
	"boxedai/internal/vm"
)

// newStopCmd builds `boxedai stop <session>`, the kill switch. It locates the
// session and best-effort stops its Lima VM: vm.Stop writes the guest stop
// sentinel (freeze + drain) and then force-stops the instance, which unblocks the
// owning `run` process so it can revoke credentials and seal evidence
// (DESIGN.md "Kill switch": revoke -> freeze -> seal -> destroy).
func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <session>",
		Short: "Kill switch: freeze and stop a running session's VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id := args[0]
			if _, err := os.Stat(session.SessionDir(id)); err != nil {
				return fmt.Errorf("cli: unknown session %s: %w", id, err)
			}
			ctx, stop := signalContext()
			defer stop()

			fmt.Fprintf(c.OutOrStdout(), "stopping %s ...\n", id)
			if err := vm.New(vm.Config{SessionID: id}).Stop(ctx); err != nil {
				return fmt.Errorf("cli: stop %s: %w", id, err)
			}
			fmt.Fprintf(c.OutOrStdout(), "stopped %s\n", id)
			return nil
		},
	}
}
