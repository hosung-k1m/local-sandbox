package session

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"

	"boxedai/internal/broker"
	"boxedai/internal/evidence"
)

// ttyApprover returns a broker.Approver that renders the exact normalized action
// JSON and its digest to stderr and reads a y/N decision from stdin. When stdin is
// not a TTY (scripted / non-interactive), it auto-denies without prompting —
// fail-closed, matching DESIGN.md's "auto-deny if non-interactive" for effects.
func ttyApprover() broker.Approver {
	return newApprover(os.Stdin, os.Stderr, isatty.IsTerminal(os.Stdin.Fd()))
}

// newApprover builds an approver over explicit streams so it is testable. interactive
// gates whether a prompt is shown at all; false always denies.
func newApprover(in io.Reader, out io.Writer, interactive bool) broker.Approver {
	reader := bufio.NewReader(in)
	return func(action broker.NormalizedAction) bool {
		canon, err := evidence.CanonicalJSON(action)
		if err != nil {
			fmt.Fprintf(out, "boxedai: cannot render effect for approval: %v — denying\n", err)
			return false
		}
		digest, err := action.Digest()
		if err != nil {
			fmt.Fprintf(out, "boxedai: cannot digest effect for approval: %v — denying\n", err)
			return false
		}
		fmt.Fprintf(out, "\nExternal effect requested:\n  %s\n  digest: %s\n", canon, digest)
		if action.Adapter == "github" && action.Op == "push" {
			fmt.Fprintln(out, "  Approval is cached for the whole session and permits arbitrary Git ref updates and deletions in the exact repository shown above.")
		}
		if !interactive {
			fmt.Fprintf(out, "  stdin is not a TTY; auto-denying.\n")
			return false
		}
		fmt.Fprintf(out, "  Approve? [y/N] ")
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true
		default:
			return false
		}
	}
}

type githubPushApproval struct {
	repository string
	digest     string
}

// preapproveGitHubPush prompts once before the broker or VM starts, then returns
// an immutable session-scoped approver. The returned closure never reads stdin
// and accepts only the exact github/push action shown to the operator.
func preapproveGitHubPush(repository string, allowed bool, prompt broker.Approver) broker.Approver {
	deny := func(broker.NormalizedAction) bool { return false }
	if repository == "" || !allowed || prompt == nil {
		return deny
	}

	action := broker.NormalizedAction{
		Adapter: "github",
		Op:      "push",
		Args:    map[string]string{"repository": repository},
	}
	digest, err := action.Digest()
	if err != nil || !prompt(action) {
		return deny
	}
	approved := githubPushApproval{repository: repository, digest: digest}

	return func(candidate broker.NormalizedAction) bool {
		if candidate.Adapter != "github" || candidate.Op != "push" || len(candidate.Args) != 1 || candidate.Args["repository"] != approved.repository {
			return false
		}
		candidateDigest, err := candidate.Digest()
		return err == nil && candidateDigest == approved.digest
	}
}
