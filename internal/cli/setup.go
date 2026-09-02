package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"

	boxedsetup "boxedai/internal/setup"
)

func validateArch(arch string) error {
	if arch != "arm64" && arch != "amd64" {
		return fmt.Errorf("cli: unknown arch %q (want arm64|amd64)", arch)
	}
	return nil
}

var (
	doctorHost = boxedsetup.Doctor
	setupHost  = boxedsetup.Run
)

func newDoctorCmd() *cobra.Command {
	var arch string
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check whether this host is ready to run BoxedAi",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := validateArch(arch); err != nil {
				return err
			}
			result := doctorHost(c.Context(), arch)
			if err := printSetupResult(c.OutOrStdout(), result, jsonOutput); err != nil {
				return err
			}
			return resultExit(result)
		},
	}
	cmd.Flags().StringVar(&arch, "arch", runtime.GOARCH, "target architecture: arm64|amd64")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "write one boxedai.setup/v1 JSON result")
	return cmd
}

func newSetupCmd() *cobra.Command {
	var arch string
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Configure this host and build the golden sandbox image",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := validateArch(arch); err != nil {
				return err
			}
			ctx, stop := signalContext()
			defer stop()

			encoder := json.NewEncoder(c.OutOrStdout())
			var outputErr error
			emit := func(event boxedsetup.StageEvent) {
				if outputErr != nil {
					return
				}
				if jsonOutput {
					outputErr = encoder.Encode(event)
					return
				}
				_, outputErr = fmt.Fprintf(c.OutOrStdout(), "%s: %s\n", event.Stage, event.Status)
			}
			progressOut := c.OutOrStdout()
			if jsonOutput {
				progressOut = c.ErrOrStderr()
			}
			result := setupHost(ctx, boxedsetup.Options{
				Arch:        arch,
				ProgressOut: progressOut,
				ProgressErr: c.ErrOrStderr(),
				Emit:        emit,
			})
			if outputErr != nil {
				return outputErr
			}
			if err := printSetupResult(c.OutOrStdout(), result, jsonOutput); err != nil {
				return err
			}
			return resultExit(result)
		},
	}
	cmd.Flags().StringVar(&arch, "arch", runtime.GOARCH, "target architecture: arm64|amd64")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "write boxedai.setup/v1 NDJSON stage events and result")
	return cmd
}

func printSetupResult(w io.Writer, result boxedsetup.Result, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(w).Encode(result)
	}
	fmt.Fprintf(w, "Status: %s\n", result.Status)
	for _, check := range result.Checks {
		fmt.Fprintf(w, "[%s] %s: %s\n", check.Status, check.ID, check.Message)
	}
	for _, action := range result.Actions {
		fmt.Fprintf(w, "Action: %s — %s\n", action.Title, action.Instructions)
	}
	if result.Error != nil {
		fmt.Fprintf(w, "Error: %s\n", result.Error.Message)
	}
	return nil
}

func resultExit(result boxedsetup.Result) error {
	switch result.Status {
	case "ready":
		return nil
	case "action_required":
		return &exitError{code: 2}
	default:
		return &exitError{code: 1}
	}
}
