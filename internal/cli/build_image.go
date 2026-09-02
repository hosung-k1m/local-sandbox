package cli

import (
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"

	"boxedai/internal/image"
	"boxedai/internal/session"
)

// buildImage is replaceable in tests so CLI parsing can be verified without
// booting Lima or downloading the Ubuntu image.
var buildImage = image.Build

func newBuildImageCmd() *cobra.Command {
	var arch string
	cmd := &cobra.Command{
		Use:   "build-image",
		Short: "Build the golden VM image sessions boot from",
		Long: "Boot a one-off bake VM that installs Node, the Claude and Codex CLIs, " +
			"and Tetragon, then export its disk as the golden image every session boots from. " +
			"Run this once, and again after upgrading, before `boxedai run` will work.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := validateArch(arch); err != nil {
				return err
			}
			hc, err := session.LoadHostConfig()
			if err != nil {
				return err
			}
			ctx, stop := signalContext()
			defer stop()

			m, err := buildImage(ctx, arch, hc.ExtraCAPEM, hc.NPMRegistry)
			if err != nil {
				return err
			}
			printBuildImageSummary(c.OutOrStdout(), m)
			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", runtime.GOARCH, "target architecture to build for: arm64|amd64 (default: this host's)")
	return cmd
}

func printBuildImageSummary(w io.Writer, m image.Manifest) {
	fmt.Fprintf(w, "\nImage tag:  %s\n", m.Tag)
	fmt.Fprintf(w, "Arch:       %s\n", m.Arch)
	fmt.Fprintf(w, "Digest:     %s\n", m.DiskDigest)
	fmt.Fprintf(w, "Disk path:  %s\n", m.DiskPath)
}
