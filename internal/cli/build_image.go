package cli

import (
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"

	"boxedai/internal/image"
	"boxedai/internal/session"
)

// buildImage is the image-build entrypoint the build-image command drives. It
// is a package variable, like run.go's runSession, so tests can substitute a
// fake that never boots a bake VM while asserting the arch/extraCAPEM/
// npmRegistry buildImage was invoked with.
var buildImage = image.Build

// newBuildImageCmd builds `boxedai build-image`.
func newBuildImageCmd() *cobra.Command {
	var arch string
	cmd := &cobra.Command{
		Use:   "build-image",
		Short: "Build the golden VM image sessions boot from",
		Long: "Boot a one-off bake VM that installs Node, the claude and codex CLIs, and " +
			"Tetragon, then export its disk as the golden image every session boots from. " +
			"Run this once, and again after upgrading, before `boxedai run` will work.",
		RunE: func(c *cobra.Command, args []string) error {
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

// validateArch checks arch is one of the two Go GOARCH values this repo
// supports, mirroring run.go's harness-name flag-validation style.
func validateArch(arch string) error {
	switch arch {
	case "arm64", "amd64":
		return nil
	default:
		return fmt.Errorf("cli: unknown arch %q (want arm64|amd64)", arch)
	}
}

// printBuildImageSummary renders the finished build's summary, matching
// printRunSummary's style/location in run.go.
func printBuildImageSummary(w io.Writer, m image.Manifest) {
	fmt.Fprintf(w, "\nImage tag:  %s\n", m.Tag)
	fmt.Fprintf(w, "Arch:       %s\n", m.Arch)
	fmt.Fprintf(w, "Digest:     %s\n", m.DiskDigest)
	fmt.Fprintf(w, "Disk path:  %s\n", m.DiskPath)
}
