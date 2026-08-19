package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"boxedai/internal/policy"
	"boxedai/internal/session"
)

// runSession is the session entrypoint the run command drives. It is a package
// variable so tests can substitute a fake that never boots a VM while asserting
// the RunOptions the CLI built.
var runSession = session.Run

// knownProfiles are the profile flag values accepted by `boxedai run`.
var knownProfiles = map[string]policy.Profile{
	string(policy.ProfileReview):     policy.ProfileReview,
	string(policy.ProfileDevelop):    policy.ProfileDevelop,
	string(policy.ProfileRestricted): policy.ProfileRestricted,
}

// newRunCmd builds `boxedai run <claude|codex|exec> [path]`.
func newRunCmd() *cobra.Command {
	var (
		profile           string
		caps              []string
		secrets           []string
		execCmd           string
		keepVM            bool
		repository        string
		branch            string
		humanSSHPublicKey string
	)
	cmd := &cobra.Command{
		Use:   "run <claude|codex|exec> [path] [-- harness-args...]",
		Short: "Run a harness in a sandboxed VM and record verifiable evidence",
		Long: "Launch the named harness (claude, codex, or exec) inside a fresh Lima VM " +
			"over an APFS clone of [path] (default: current directory), record the session, " +
			"then seal and summarize the evidence.\n\n" +
			"Anything after -- is passed through as argv to the claude/codex CLI inside the " +
			"guest, so the harness can be driven non-interactively, e.g.:\n" +
			"  boxedai run claude . -- -p 'summarize this repo'",
		Args: runArgs,
		RunE: func(c *cobra.Command, args []string) error {
			positional, harnessArgs := splitDashArgs(c, args)
			opts, err := buildRunOptions(positional, profile, caps, secrets, execCmd, keepVM, repository, branch, harnessArgs)
			if err != nil {
				return err
			}
			opts.HumanSSHPublicKey = humanSSHPublicKey
			opts.Progress = func(stage, detail string) {
				fmt.Fprintf(c.ErrOrStderr(), "==> %-12s %s\n", stage, detail)
			}
			ctx, stop := signalContext()
			defer stop()

			res, runErr := runSession(ctx, opts)
			// The summary is useful even on error: a failed setup still produces a
			// session dir and (usually) sealed evidence to inspect.
			if res.SessionID != "" {
				printRunSummary(c.OutOrStdout(), res)
			}
			if runErr != nil {
				return runErr
			}
			// Propagate a non-zero harness exit as the process exit code without a
			// second error line (the summary already shows it).
			if res.ExitCode != 0 {
				return &exitError{code: res.ExitCode}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profile, "profile", string(policy.ProfileDevelop), "isolation profile: develop|review|restricted")
	cmd.Flags().StringArrayVar(&caps, "cap", nil, "grant an extra capability, e.g. external-write:github (repeatable)")
	cmd.Flags().StringArrayVar(&secrets, "secret", nil, `glob for workspace files whose content is never captured (digest-only evidence), e.g. "*.secret"; repeatable, adds to the profile's defaults`)
	cmd.Flags().StringVar(&execCmd, "cmd", "", "shell command for the exec harness")
	cmd.Flags().BoolVar(&keepVM, "keep-vm", false, "leave the Lima VM in place after the session (debugging)")
	cmd.Flags().StringVar(&repository, "repo", "", "remote Git repository to clone fresh for this session")
	cmd.Flags().StringVar(&branch, "branch", "", "branch to check out from --repo")
	cmd.Flags().StringVar(&humanSSHPublicKey, "human-ssh-public-key", "", "OpenSSH public key enabling mediated human SSH workspace access")
	return cmd
}

// runArgs replaces cobra.RangeArgs(1, 2): it validates only the positionals
// before a `--`, since anything after it is harness passthrough argv, not a
// positional (harness/path) argument.
func runArgs(c *cobra.Command, args []string) error {
	positional, _ := splitDashArgs(c, args)
	if len(positional) < 1 || len(positional) > 2 {
		return fmt.Errorf("accepts 1 or 2 arg(s) (<claude|codex|exec> [path]) before --, received %d", len(positional))
	}
	return nil
}

// splitDashArgs separates cobra's positional args from the harness passthrough
// argv following a literal `--`, using ArgsLenAtDash (the count of args before
// the dash, or -1 if the command line had no `--`).
func splitDashArgs(c *cobra.Command, args []string) (positional, harnessArgs []string) {
	dash := c.ArgsLenAtDash()
	if dash < 0 {
		return args, nil
	}
	return args[:dash], args[dash:]
}

// buildRunOptions maps parsed flags, positional args, and harness passthrough
// args to a session.RunOptions. It validates the harness name and profile up
// front so the CLI fails fast with a clear message before any session setup
// begins. Factored out so tests can assert the flag→options mapping without
// launching a VM.
func buildRunOptions(args []string, profile string, caps, secrets []string, execCmd string, keepVM bool, repository, branch string, harnessArgs []string) (session.RunOptions, error) {
	harness := args[0]
	switch harness {
	case "claude", "codex", "exec":
	default:
		return session.RunOptions{}, fmt.Errorf("cli: unknown harness %q (want claude|codex|exec)", harness)
	}
	if harness == "exec" && len(harnessArgs) > 0 {
		return session.RunOptions{}, fmt.Errorf("cli: exec harness does not accept passthrough args after -- (use --cmd)")
	}
	prof, ok := knownProfiles[profile]
	if !ok {
		return session.RunOptions{}, fmt.Errorf("cli: unknown profile %q (want develop|review|restricted)", profile)
	}
	repoPath := ""
	if len(args) > 1 {
		repoPath = args[1]
	}
	if repository != "" && repoPath != "" {
		return session.RunOptions{}, fmt.Errorf("cli: [path] and --repo are mutually exclusive")
	}
	if branch != "" && repository == "" {
		return session.RunOptions{}, fmt.Errorf("cli: --branch requires --repo")
	}
	// Secret globs are not validated here: policy.Resolve rejects malformed
	// patterns while resolving, so the CLI keeps one validation site rather than
	// a second, drifting copy of the rule.
	return session.RunOptions{
		Harness:     harness,
		RepoPath:    repoPath,
		Repository:  repository,
		Branch:      branch,
		Profile:     prof,
		ExtraCaps:   caps,
		SecretGlobs: secrets,
		Cmd:         execCmd,
		HarnessArgs: harnessArgs,
		KeepVM:      keepVM,
	}, nil
}

// printRunSummary renders the finished-session summary plus the verify hint
// (DESIGN.md session flow step 8).
func printRunSummary(w io.Writer, r session.Result) {
	fmt.Fprintf(w, "\nSession:         %s\n", r.SessionID)
	fmt.Fprintf(w, "State:           %s\n", r.State)
	fmt.Fprintf(w, "Verdict:         %s\n", r.Verdict)
	fmt.Fprintf(w, "Exit code:       %d\n", r.ExitCode)
	fmt.Fprintf(w, "Files changed:   %d\n", r.FilesChanged)
	fmt.Fprintf(w, "Network denials: %d\n", r.NetDenials)
	if len(r.ToolsUsed) > 0 {
		fmt.Fprintf(w, "Tools used:      %s\n", strings.Join(r.ToolsUsed, ", "))
	}
	fmt.Fprintf(w, "Evidence:        %s\n", r.SessionDir)
	fmt.Fprintf(w, "Evidence digest: SHA-256\n")
	fmt.Fprintf(w, "Evidence seal:   COSE Sign1 with EdDSA (Ed25519)\n")
	if r.RecorderKeyFingerprint != "" {
		fmt.Fprintf(w, "Recorder key:    %s\n", r.RecorderKeyFingerprint)
	}
	fmt.Fprintf(w, "\nVerify with:     boxedai verify %s\n", r.SessionID)
}
