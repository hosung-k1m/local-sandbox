// Package image builds and resolves the golden Lima disk image sessions boot
// from (see DESIGN.md "VM (internal/vm) and guest supervisor" and
// internal/vm's BakeConfig/BakeVM): Build drives a one-off, throwaway bake VM
// through internal/vm to install Node, both harness CLIs, and Tetragon, then
// exports its disk as the image every session's internal/vm.Config.ImagePath
// points at; Resolve reads back the manifest Build wrote so the session
// package (and the `boxedai build-image` / `boxedai run` CLI commands) never
// have to touch Lima directly.
//
// This package intentionally does not import internal/session: session will
// import image (to resolve ImagePath before booting a session VM), and the
// reverse would be an import cycle. The tiny BOXEDAI_HOME lookup below is
// duplicated from internal/session/home.go rather than shared for that
// reason — keep the two in sync by hand if the env var or fallback ever
// changes.
package image

import (
	"os"
	"path/filepath"
)

// homeEnv overrides the default ~/.boxedai state root when set. Must match
// internal/session/home.go's homeEnv exactly — same variable, same fallback.
const homeEnv = "BOXEDAI_HOME"

// home returns the BoxedAi state root: $BOXEDAI_HOME when set, else
// ~/.boxedai. Mirrors internal/session.Home() (see package doc comment).
func home() string {
	if h := os.Getenv(homeEnv); h != "" {
		return h
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		// Fall back to a relative path rather than panicking; callers that
		// need the dir will surface the mkdir/stat error fail-closed.
		return ".boxedai"
	}
	return filepath.Join(dir, ".boxedai")
}

// imagesDir is $BOXEDAI_HOME/images, the parent of every per-arch image
// directory.
func imagesDir() string { return filepath.Join(home(), "images") }

// archDir is imagesDir()/<arch>, holding one arch's manifest.json and
// disk.img.
func archDir(arch string) string { return filepath.Join(imagesDir(), arch) }

// manifestPath is archDir(arch)/manifest.json.
func manifestPath(arch string) string { return filepath.Join(archDir(arch), "manifest.json") }

// diskPath is archDir(arch)/disk.img, the exported golden disk image.
func diskPath(arch string) string { return filepath.Join(archDir(arch), "disk.img") }
