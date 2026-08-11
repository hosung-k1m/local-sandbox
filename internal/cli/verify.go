package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"boxedai/internal/session"
	"boxedai/internal/verify"
)

// newVerifyCmd builds `boxedai verify <session> [--json]`. It prints the report
// and exits non-zero when the verdict indicates tampering or a bypass.
func newVerifyCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify <session>",
		Short: "Run the offline verifier over a session and print its verdict",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			rep, err := verify.Verify(session.SessionDir(args[0]))
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(c.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			} else {
				fmt.Fprint(c.OutOrStdout(), rep.String())
			}
			// Exit non-zero on the adversarial verdicts; the report above already
			// explains why, so suppress a second error line (empty msg).
			switch rep.Verdict {
			case verify.VerdictTamperSuspected, verify.VerdictBypassDetected:
				return &exitError{code: 2}
			default:
				return nil
			}
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the verifier report as JSON")
	return cmd
}
