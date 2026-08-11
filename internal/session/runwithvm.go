package session

import (
	"context"

	"boxedai/internal/vm"
)

// VMController is the narrow VM surface a session drives: create/boot the VM,
// gate on guest-agent health, launch the harness, then stop and delete it. It is
// the exported alias of the package-internal vmController interface, published
// solely as an injection seam so the out-of-tree host-pipeline test in
// internal/e2e can substitute a fake VM that never boots Lima while still
// exercising the real broker/recorder/verify/view path. Production runs always
// use the real Lima-backed *vm.VM via Run; nothing outside that test should
// depend on this.
type VMController = vmController

// RunWithVMFactory runs one session exactly like Run, except it builds each
// session's VM controller from newVM instead of the real Lima-backed VM. It is a
// test seam for internal/e2e, which drives a full session against an in-process
// fake guest; ordinary callers use Run.
func RunWithVMFactory(ctx context.Context, opts RunOptions, newVM func(cfg vm.Config) VMController) (Result, error) {
	return (&Runner{newVM: newVM}).Run(ctx, opts)
}
