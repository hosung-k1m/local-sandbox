// Package cli is the BoxedAi command-line surface (DESIGN.md "CLI"). It wires the
// cobra command tree over the session, view, verify, snapshot and vm packages and
// nothing else: every command is a thin adapter that parses flags, calls into a
// library package, and renders the result. cmd/boxedai is a one-line entrypoint
// that defers to Execute.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// exitError lets a command request a specific process exit code without cobra
// re-printing the message. A command that has already rendered its own output
// (e.g. verify printing a report) sets msg="" so Execute exits silently with the
// chosen code; a non-empty msg is written to stderr before exiting.
type exitError struct {
	code int
	msg  string
}

// Error implements error.
func (e *exitError) Error() string { return e.msg }

// Execute builds the root command, runs it, and translates the outcome to a
// process exit code. It is the single entrypoint cmd/boxedai calls.
func Execute() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(os.Stderr, ee.msg)
			}
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "boxedai:", err)
		os.Exit(1)
	}
}

// newRootCmd assembles the full command tree. It is pure — it neither reads flags
// nor touches the filesystem — so tests can build it and inspect help / flag
// parsing without launching a session.
func newRootCmd() *cobra.Command {
	var (
		web  bool
		addr string
	)
	root := &cobra.Command{
		Use:   "boxedai",
		Short: "Launch AI coding agents in a sandboxed VM with verifiable audit evidence",
		Long: "BoxedAi runs Claude Code or Codex inside a disposable Lima Linux VM and " +
			"produces independently verifiable, human-readable audit evidence.",
		// Runtime errors are rendered by Execute; suppress cobra's own error and
		// usage dump so a failed command does not print usage on every error.
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if !web && c.Flags().Changed("addr") {
				return fmt.Errorf("cli: --addr requires --web")
			}
			if !web {
				return c.Help()
			}
			return serveDashboard(addr)
		},
	}
	root.Flags().BoolVar(&web, "web", false, "serve the global evidence dashboard")
	root.Flags().StringVar(&addr, "addr", "127.0.0.1:0", "web dashboard listen address (with --web)")
	root.AddCommand(
		newSetupCmd(),
		newDoctorCmd(),
		newBuildImageCmd(),
		newRunCmd(),
		newSessionsCmd(),
		newViewCmd(),
		newDiffCmd(),
		newVerifyCmd(),
		newVerifyRecordCmd(),
		newApplyCmd(),
		newStopCmd(),
	)
	return root
}

// signalContext returns a context cancelled on SIGINT/SIGTERM so a running
// session (or a long-lived viewer) tears down cleanly when the user hits Ctrl-C.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
