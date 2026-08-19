package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"boxedai/internal/evidence"
	"boxedai/internal/remoteaccess"
	"boxedai/internal/session"
)

var (
	loadRunningHumanAccessBinding = session.LoadRunningHumanAccessBinding
	storeRemoteAccessPlan         = session.StoreRemoteAccessPlan
	storeRemoteAccessSSHConfig    = session.StoreRemoteAccessSSHConfig
)

// newAccessCmd prepares a controller-owned local launch plan for one running
// session. A real browser PTY or SSH adapter is intentionally required before
// it can connect a client; the command never converts a descriptor into a
// workload credential or a direct lower-workspace path.
func newAccessCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "access <session> <browser_terminal|vscode_remote_ssh|intellij_remote_development>",
		Short: "Prepare a mediated host-local human access launch",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			surface, err := parseAccessSurface(args[1])
			if err != nil {
				return err
			}
			binding, err := loadRunningHumanAccessBinding(args[0])
			if err != nil {
				return fmt.Errorf("cli: load human access binding: %w", err)
			}
			controller := remoteaccess.NewController(remoteaccess.NewBroker(binding, true), nil)
			controller.SetAdmissionGate(func() error {
				_, err := loadRunningHumanAccessBinding(args[0])
				return err
			})
			plan, err := controller.Prepare(remoteaccess.LaunchRequest{
				SessionID: args[0],
				GrantID:   binding.Grant.GrantID,
				Surface:   surface,
				UID:       evidence.HumanUID,
			})
			if err != nil {
				return fmt.Errorf("cli: prepare human access launch: %w", err)
			}
			data, err := json.MarshalIndent(plan, "", "  ")
			if err != nil {
				return fmt.Errorf("cli: encode human access launch plan: %w", err)
			}
			path, err := storeRemoteAccessPlan(args[0], plan.Descriptor.ID, data)
			if err != nil {
				return fmt.Errorf("cli: store human access launch plan: %w", err)
			}
			if surface == evidence.AccessSurfaceBrowserTerminal {
				command, err := remoteaccess.SSHCommand(plan, "boxedai-ssh-proxy", session.HumanSSHPrivateKeyPath())
				if err != nil {
					return fmt.Errorf("cli: prepare human access terminal command: %w", err)
				}
				fmt.Fprintf(c.OutOrStdout(), "SSH command: %s\n", command)
			}
			if surface == evidence.AccessSurfaceVSCodeRemoteSSH || surface == evidence.AccessSurfaceIntelliJRemoteDev {
				sshConfig, err := remoteaccess.SSHConfigWithIdentity(plan, "boxedai-ssh-proxy", session.HumanSSHPrivateKeyPath())
				if err != nil {
					return fmt.Errorf("cli: prepare human access SSH config: %w", err)
				}
				configPath, err := storeRemoteAccessSSHConfig(args[0], plan.Descriptor.ID, []byte(sshConfig))
				if err != nil {
					return fmt.Errorf("cli: store human access SSH config: %w", err)
				}
				fmt.Fprintf(c.OutOrStdout(), "SSH config: %s\nHost alias: %s\n", configPath, "boxedai-"+args[0])
			}
			fmt.Fprintf(c.OutOrStdout(), "prepared %s SSH handoff at %s\n", surface, path)
			return nil
		},
	}
}

func parseAccessSurface(value string) (evidence.AccessSurface, error) {
	surface := evidence.AccessSurface(value)
	switch surface {
	case evidence.AccessSurfaceBrowserTerminal, evidence.AccessSurfaceVSCodeRemoteSSH, evidence.AccessSurfaceIntelliJRemoteDev:
		return surface, nil
	default:
		return "", fmt.Errorf("cli: unknown human access surface %q", value)
	}
}
