package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"boxedai/internal/broker"
	"boxedai/internal/evidence"
	"boxedai/internal/image"
	"boxedai/internal/policy"
	"boxedai/internal/recorder"
	"boxedai/internal/snapshot"
	"boxedai/internal/trustrecord"
	"boxedai/internal/verify"
	"boxedai/internal/vm"
)

// Per-session artifact file names under sessions/<id>/ (DESIGN.md layout).
const (
	grantFileName          = "session.json"
	policyFileName         = "policy.json"
	inputManifestFileName  = "input-manifest.json"
	outputManifestFileName = "output-manifest.json"
	evidenceDirName        = "evidence"
	workspaceDirName       = "workspace"
	workspaceOrigDirName   = "workspace.orig"
	claudeTelemetryDirName = "claude-telemetry"
)

const (
	// grantSchema is the session.json schema id (DESIGN.md session grant).
	grantSchema = "boxedai.session/v2"
	// assuranceMode is the v0.1 ceiling (DESIGN.md "Security claim").
	assuranceMode = "local"
	// brokerHost is the guest-reachable broker hostname lima provides.
	brokerHost = "host.lima.internal"
	// healthTimeout bounds the wait for guest agent readiness (DESIGN.md step 6).
	healthTimeout = 120 * time.Second
	// vmCleanupTimeout lets teardown finish after the run context is canceled
	// without allowing a stuck Lima cleanup command to block indefinitely.
	vmCleanupTimeout = 30 * time.Second
	// attrWorkspacePhase distinguishes the input vs output workspace.manifested event.
	attrWorkspacePhase = "workspace.phase"
	// attrCredentialKind labels credential.issued/revoked without storing the token.
	attrCredentialKind = "credential.kind"
)

// RunOptions parameterizes one session (DESIGN.md CLI `boxedai run`).
type RunOptions struct {
	// Harness is the workload: "claude", "codex", or "exec".
	Harness string
	// RepoPath is the repository to snapshot into the session workspace.
	RepoPath string
	// Repository is a remote Git repository cloned fresh into the session.
	// It is mutually exclusive with RepoPath.
	Repository string
	// Branch is the remote branch selected by Repository. Empty uses the
	// remote's default branch.
	Branch string
	// Profile is the isolation/capability profile; empty defaults to develop.
	Profile policy.Profile
	// ExtraCaps are additional capability flags, e.g. "external-write:github".
	ExtraCaps []string
	// Cmd is the shell command for the "exec" harness (required for exec).
	Cmd string
	// HarnessArgs are extra argv appended after "claude"/"codex" inside the
	// guest, letting callers drive the harness non-interactively (e.g. `claude
	// -p 'prompt'`). Rejected for the "exec" harness, which already has Cmd.
	HarnessArgs []string
	// KeepVM leaves the Lima instance in place after the session for debugging.
	KeepVM bool
	// Progress receives safe, human-readable lifecycle updates. Messages never
	// include credentials or private key material.
	Progress func(stage, detail string)
}

// Result summarizes a finished (or aborted) session for the CLI.
type Result struct {
	// SessionID is the bx-... session identifier.
	SessionID string
	// SessionDir is the on-disk session directory.
	SessionDir string
	// State is the final persisted lifecycle state.
	State State
	// Verdict is a best-effort offline verifier hint over the sealed evidence.
	Verdict string
	// ExitCode is the harness exit code (0 if it never launched).
	ExitCode int
	// FilesChanged is added+modified+deleted workspace paths from the diff.
	FilesChanged int
	// NetDenials is the count of network.denied events observed.
	NetDenials int
	// ToolsUsed is the sorted set of internal tools dispatched.
	ToolsUsed []string
	// RecorderKeyFingerprint is the SHA-256 fingerprint of the public Ed25519
	// recorder key. The private key is never logged or copied into the guest.
	RecorderKeyFingerprint string
}

// vmController is the narrow slice of *vm.VM the session drives. Isolating it
// behind an interface lets tests inject a fake VM that never boots Lima while the
// production path stays exactly *vm.VM.
type vmController interface {
	Start(ctx context.Context) error
	WaitHealthy(ctx context.Context, timeout time.Duration) error
	LaunchHarness(ctx context.Context) (int, error)
	Stop(ctx context.Context) error
	Delete(ctx context.Context) error
}

// vmFactory builds a vmController from a resolved vm.Config.
type vmFactory func(cfg vm.Config) vmController

// realVMFactory is the production factory: a real Lima-backed *vm.VM.
func realVMFactory(cfg vm.Config) vmController { return vm.New(cfg) }

// resolveImage resolves the golden VM image manifest for an arch. It is a
// package-level var, like devicecred.go's lookupClaudeKeychain/codexAuthPath,
// so tests can substitute a fake instead of touching real $BOXEDAI_HOME/images
// state (and without booting a VM, since a resolution failure must abort Run
// before vmFactory is ever invoked).
var resolveImage = image.Resolve

// Runner executes sessions. The zero Runner drives a real Lima VM; tests set
// newVM to inject a fake. Runner holds no per-session state, so one is reusable.
type Runner struct {
	// newVM builds the per-session VM controller; nil uses realVMFactory.
	newVM vmFactory
	// approvalPrompt is the one-shot host prompt used before startup; nil uses
	// the real controller TTY. Tests replace it without touching process stdin.
	approvalPrompt broker.Approver
}

// factory returns the configured VM factory, defaulting to the real one.
func (r *Runner) factory() vmFactory {
	if r.newVM != nil {
		return r.newVM
	}
	return realVMFactory
}

func (r *Runner) promptApprover() broker.Approver {
	if r.approvalPrompt != nil {
		return r.approvalPrompt
	}
	return ttyApprover()
}

// Run executes one session end to end using the real Lima VM (DESIGN.md
// "Session flow"). It is the entrypoint the CLI calls.
func Run(ctx context.Context, opts RunOptions) (Result, error) {
	return (&Runner{}).Run(ctx, opts)
}

// Run drives the full fail-closed session lifecycle: resolve policy, record the
// grant, snapshot the workspace, stand up the broker and VM, launch the harness,
// then seal evidence and summarize. Every setup error aborts closed; a deferred
// teardown revokes credentials, seals whatever evidence exists, and marks the
// session incomplete on any early exit (DESIGN.md "Crash safety").
func (r *Runner) Run(ctx context.Context, opts RunOptions) (result Result, runErr error) {
	progress := func(stage, detail string) {
		if opts.Progress != nil {
			opts.Progress(stage, detail)
		}
	}
	// --- 1. Validate inputs and resolve the policy. ---
	progress("prepare", "validating harness, source, and isolation policy")
	if err := validateHarness(opts.Harness, opts.Cmd, opts.HarnessArgs); err != nil {
		return Result{}, err
	}
	if opts.Repository != "" && opts.RepoPath != "" {
		return Result{}, fmt.Errorf("session: RepoPath and Repository are mutually exclusive")
	}
	var repoPath string
	if opts.Repository == "" {
		var err error
		repoPath, err = resolveRepo(opts.RepoPath)
		if err != nil {
			return Result{}, err
		}
	}
	prof := opts.Profile
	if prof == "" {
		prof = policy.ProfileDevelop
	}
	pol, err := policy.Resolve(prof, opts.ExtraCaps)
	if err != nil {
		return Result{}, err
	}
	policyDigest, err := pol.Digest()
	if err != nil {
		return Result{}, fmt.Errorf("session: policy digest: %w", err)
	}
	hc, err := LoadHostConfig()
	if err != nil {
		return Result{}, err
	}
	// Resolve the golden VM image before any session directory, recorder, or
	// broker exists: like resolveUpstreams's credential check below, a failure
	// here must abort the session fail-closed, and doing it this early (right
	// after the last cheap, side-effect-free config load) avoids creating any
	// on-disk session state or booting the costlier broker/VM setup for a
	// session that can never boot anyway. Its Tag/DiskDigest also feed the
	// recorder metadata and grant built next, so it must run before those.
	img, err := resolveImage(runtime.GOARCH)
	if err != nil {
		return Result{}, fmt.Errorf("session: resolve golden image: %w", err)
	}

	// --- Create the session directory and record the resolved policy. ---
	now := time.Now()
	sessionID, err := newSessionID(now)
	if err != nil {
		return Result{}, err
	}
	traceID, err := newTraceID()
	if err != nil {
		return Result{}, err
	}
	sessionDir := SessionDir(sessionID)
	if err := mkdirAll(sessionDir); err != nil {
		return Result{}, err
	}
	result.SessionID = sessionID
	result.SessionDir = sessionDir
	_ = writeState(sessionDir, StateCreated)

	if err := writeCanonicalFile(filepath.Join(sessionDir, policyFileName), pol); err != nil {
		return result, err
	}

	// --- 2. Load the signing key and stand up the recorder. ---
	key, err := recorder.LoadOrGenerateKey(keysDir())
	if err != nil {
		return result, err
	}
	result.RecorderKeyFingerprint = evidence.SHA256Hex(key.Pub)
	progress("crypto", "recorder ready: SHA-256 digests; COSE Sign1 with EdDSA (Ed25519); public key "+result.RecorderKeyFingerprint)
	meta := recorder.SessionMeta{
		SessionID:      sessionID,
		TraceID:        traceID,
		PolicyDigest:   policyDigest,
		VMImage:        img.Tag,
		VMImageDigest:  img.DiskDigest,
		VMID:           sessionID,
		RecorderPubPEM: key.PubPEM,
	}
	rec, err := recorder.NewRecorder(filepath.Join(sessionDir, evidenceDirName), key, meta)
	if err != nil {
		return result, err
	}
	counter := newCountingEmitter(rec)
	emit := func(ev evidence.Event) error { return counter.Emit(evidence.ChannelController, ev) }

	workspace := filepath.Join(sessionDir, workspaceDirName)
	origWorkspace := filepath.Join(sessionDir, workspaceOrigDirName)

	// Teardown state, declared before the deferred handler so it can observe how
	// far setup progressed.
	var (
		br             *broker.Broker
		vmc            vmController
		sessionStarted bool
	)

	// Deferred teardown: always runs once the recorder exists. Best-effort and
	// fail-closed — revoke tokens, stop the VM, seal evidence, mark state.
	defer func() {
		progress("teardown", "stopping the VM, revoking session credentials, and finalizing the workspace diff")
		var teardownErr error
		failTeardown := func(e error) {
			if teardownErr == nil {
				teardownErr = e
			}
		}

		// Stop the VM FIRST: vmc.Stop writes the guest stop sentinel and waits a
		// drain grace before force-stopping. This lets the guest supervisor
		// freeze the (already-exited) workload and flush its final
		// kernel-observed events — process exits and any last-moment
		// network.denied — to the broker while the supervisor token is still
		// valid. Revoking or stopping the broker before this drain would 401
		// those final events and silently truncate the evidence tail.
		if vmc != nil {
			stopCtx, cancelStop := context.WithTimeout(context.Background(), vmCleanupTimeout)
			if e := vmc.Stop(stopCtx); e != nil {
				failTeardown(fmt.Errorf("session: stop vm: %w", e))
			}
			cancelStop()
		}
		// Now revoke tokens and stop the broker: the guest has drained and the
		// workload is frozen, so no further authenticated call should succeed.
		if br != nil {
			br.Revoke()
			if e := emit(credentialEvent(evidence.EventCredentialRevoked, "workload")); e != nil {
				failTeardown(e)
			}
			if e := emit(credentialEvent(evidence.EventCredentialRevoked, "supervisor")); e != nil {
				failTeardown(e)
			}
			if e := br.Stop(); e != nil {
				failTeardown(fmt.Errorf("session: stop broker: %w", e))
			}
		}

		// Closing artifacts + lifecycle events only if the workload started.
		if sessionStarted {
			if e := finishWorkspace(sessionDir, origWorkspace, workspace, emit, &result); e != nil {
				failTeardown(e)
			}
			if e := emit(sessionEvent(evidence.EventSessionStopped, "session stopped")); e != nil {
				failTeardown(e)
			}
			// session.sealed is emitted just before Close so it lands in the final
			// segment (DESIGN.md "Recorder" note).
			if e := emit(sessionEvent(evidence.EventSessionSealed, "session sealed")); e != nil {
				failTeardown(e)
			}
		}

		// Seal the recorder regardless: this persists whatever evidence exists.
		if _, e := rec.Close(); e != nil {
			failTeardown(e)
		}
		trustRecordWritten := false
		if runErr == nil && sessionStarted && teardownErr == nil {
			record, e := trustrecord.Build(sessionDir, time.Now(), key.Pub)
			if e == nil {
				e = trustrecord.Sign(&record, key.Priv)
			}
			if e == nil {
				e = trustrecord.Write(sessionDir, record)
			}
			if e != nil {
				failTeardown(e)
			} else {
				trustRecordWritten = true
			}
		}
		if teardownErr == nil {
			detail := "evidence sealed: SHA-256 segment/chain digests and COSE Sign1 manifests"
			if trustRecordWritten {
				detail += "; RFC 8785 Ed25519 trust record written"
			}
			progress("crypto", detail)
		}

		finalState := StateIncomplete
		if runErr == nil && sessionStarted && teardownErr == nil {
			finalState = StateSealed
		}
		if e := writeState(sessionDir, finalState); e != nil {
			failTeardown(fmt.Errorf("session: write final state: %w", e))
			finalState = StateIncomplete
			if stateErr := writeState(sessionDir, finalState); stateErr != nil {
				failTeardown(fmt.Errorf("session: write incomplete state: %w", stateErr))
			}
		}
		result.State = finalState

		if vmc != nil && !opts.KeepVM {
			deleteCtx, cancelDelete := context.WithTimeout(context.Background(), vmCleanupTimeout)
			if e := vmc.Delete(deleteCtx); e != nil {
				failTeardown(fmt.Errorf("session: delete vm: %w", e))
				if finalState != StateIncomplete {
					finalState = StateIncomplete
					if stateErr := writeState(sessionDir, finalState); stateErr != nil {
						failTeardown(fmt.Errorf("session: write incomplete state after VM delete failure: %w", stateErr))
					}
				}
			}
			cancelDelete()
		}
		result.State = finalState

		// Best-effort verdict hint from the offline verifier over the sealed evidence.
		if rep, e := verify.Verify(sessionDir); e == nil {
			result.Verdict = string(rep.Verdict)
		}
		net, tools := counter.snapshot()
		result.NetDenials = net
		result.ToolsUsed = tools

		if runErr == nil && teardownErr != nil {
			runErr = teardownErr
		}
	}()

	// --- 3. Snapshot the repo into the session workspace (+ a pristine copy for
	// diffing) and record the input manifest. ---
	if opts.Repository != "" {
		branch := opts.Branch
		if branch == "" {
			branch = "the remote default"
		}
		progress("checkout", fmt.Sprintf("cloning %s branch into a fresh session workspace", branch))
		if err := cloneRepository(ctx, opts.Repository, opts.Branch, workspace); err != nil {
			return result, err
		}
	} else if err := snapshot.Snapshot(repoPath, workspace); err != nil {
		return result, err
	}
	if opts.Repository == "" {
		progress("checkout", "snapshotted local repository into the isolated session workspace")
	}
	if err := snapshot.Snapshot(workspace, origWorkspace); err != nil {
		return result, err
	}
	provenance, err := gitProvenance(ctx, workspace, opts.Repository, opts.Branch)
	if err != nil {
		return result, err
	}
	inManifest, err := snapshot.ManifestOf(workspace)
	if err != nil {
		return result, err
	}
	inBytes, err := evidence.CanonicalJSON(inManifest)
	if err != nil {
		return result, fmt.Errorf("session: canonicalize input manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, inputManifestFileName), inBytes, 0o600); err != nil {
		return result, fmt.Errorf("session: write input manifest: %w", err)
	}
	inputManifestDigest := evidence.SHA256Hex(inBytes)

	// --- Write the session grant BEFORE VM boot; its digest anchors session.granted.
	// The snapshot precedes the grant so input_manifest_digest is final and the
	// recorded grant digest exactly matches the on-disk session.json bytes. ---
	grant := sessionGrant{
		Schema:              grantSchema,
		SessionID:           sessionID,
		TraceID:             traceID,
		Harness:             opts.Harness,
		Profile:             string(prof),
		RepoPath:            repoPath,
		Repository:          provenance.Repository,
		Branch:              provenance.Branch,
		Commit:              provenance.Commit,
		CreatedAt:           now.UTC().Format(time.RFC3339),
		PolicyDigest:        policyDigest,
		InputManifestDigest: inputManifestDigest,
		VMImage:             img.Tag,
		VMImageDigest:       img.DiskDigest,
		RecorderPub:         key.PubPEM,
		AssuranceMode:       assuranceMode,
		TrustRecord: trustRecordGrant{
			Schema:   trustrecord.Profile,
			Path:     trustrecord.FileName,
			Required: true,
		},
	}
	grantBytes, err := json.MarshalIndent(grant, "", "  ")
	if err != nil {
		return result, fmt.Errorf("session: marshal grant: %w", err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, grantFileName), grantBytes, 0o600); err != nil {
		return result, fmt.Errorf("session: write grant: %w", err)
	}
	grantDigest := evidence.SHA256Hex(grantBytes)

	// session.granted (grant digest) + policy.loaded (policy digest) + input manifest.
	if err := emit(evidence.Event{
		Name:    evidence.EventSessionGranted,
		Outcome: evidence.OutcomeSuccess,
		Body:    "session grant issued",
		Attrs: map[string]any{
			evidence.AttrContentDigest:  grantDigest,
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
		},
	}); err != nil {
		return result, err
	}
	if err := emit(evidence.Event{
		Name:    evidence.EventPolicyLoaded,
		Outcome: evidence.OutcomeSuccess,
		Body:    fmt.Sprintf("policy %s loaded", prof),
		Attrs: map[string]any{
			evidence.AttrContentDigest:  policyDigest,
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
		},
	}); err != nil {
		return result, err
	}
	if err := emit(workspaceManifestedEvent("input", inputManifestDigest)); err != nil {
		return result, err
	}

	// --- 4. Build and start the broker; hand out the two credentials. ---
	anthropicUpstream, openaiUpstream, err := resolveUpstreams(hc, opts.Harness)
	if err != nil {
		return result, err
	}
	var githubConfig broker.GitHubConfig
	var githubRemote string
	if opts.Harness == "claude" || opts.Harness == "codex" {
		accessPath := repoPath
		if opts.Repository != "" {
			accessPath = workspace
		}
		githubConfig, githubRemote, err = resolveGitHubAccess(ctx, accessPath)
		if err != nil {
			return result, err
		}
	}
	harnessHome, err := stageHarnessInstructions(sessionDir, opts.Harness)
	if err != nil {
		return result, err
	}
	approver := preapproveGitHubPush(
		githubConfig.Repository,
		pol.AllowsEffect("github", "push"),
		r.promptApprover(),
	)
	br, err = broker.New(broker.Config{
		Emitter:            counter,
		Policy:             pol,
		Session:            sessionID,
		Anthropic:          anthropicUpstream,
		OpenAI:             openaiUpstream,
		GitHub:             githubConfig,
		ClaudeTelemetryDir: claudeTelemetryDir(sessionDir, opts.Harness),
		Tools:              hc.Tools,
		Effects:            hc.Effects,
		Approver:           approver,
		AgentBinary:        agentBinaryProvider,
	})
	if err != nil {
		return result, err
	}
	progress("broker", "starting credential and network broker with exact-repository GitHub scope")
	port, err := br.Start(ctx)
	if err != nil {
		return result, err
	}
	if err := emit(credentialEvent(evidence.EventCredentialIssued, "workload")); err != nil {
		return result, err
	}
	if err := emit(credentialEvent(evidence.EventCredentialIssued, "supervisor")); err != nil {
		return result, err
	}

	// --- 5/6. Create + boot the VM, then gate on guest-agent health. ---
	vmc = r.factory()(vm.Config{
		SessionID:        sessionID,
		SessionDir:       sessionDir,
		WorkspacePath:    workspace,
		HarnessHomePath:  harnessHome,
		Writable:         pol.WorkspaceWritable,
		BrokerHost:       brokerHost,
		BrokerPort:       port,
		WorkloadToken:    br.WorkloadToken(),
		SupervisorToken:  br.SupervisorToken(),
		GitHubRepository: githubConfig.Repository,
		GitHubSSHURL:     githubConfig.SSHURL,
		GitHubRemote:     githubRemote,
		Harness:          opts.Harness,
		Cmd:              opts.Cmd,
		HarnessArgs:      opts.HarnessArgs,
		Limits:           pol.Limits,
		ImagePath:        img.DiskPath,
		Arch:             runtime.GOARCH,
	})
	progress("sandbox", "starting the fresh VM and waiting for the guest supervisor")
	if err := vmc.Start(ctx); err != nil {
		return result, fmt.Errorf("session: start vm: %w", err)
	}
	if err := vmc.WaitHealthy(ctx, healthTimeout); err != nil {
		// DESIGN.md failure behavior: guest unhealthy before launch -> abort,
		// INCOMPLETE. The deferred teardown seals what exists and marks incomplete.
		return result, fmt.Errorf("session: guest agent unhealthy: %w", err)
	}

	// --- 7. Launch the harness interactively. ---
	progress("harness", "launching "+opts.Harness+" in /workspace")
	if err := emit(sessionEvent(evidence.EventSessionStarted, "session started")); err != nil {
		return result, err
	}
	sessionStarted = true
	if err := writeState(sessionDir, StateRunning); err != nil {
		return result, fmt.Errorf("session: write running state: %w", err)
	}

	exit, err := vmc.LaunchHarness(ctx)
	if err != nil {
		return result, fmt.Errorf("session: launch harness: %w", err)
	}
	result.ExitCode = exit

	// --- 8. Teardown (revoke, stop, output manifest+diff, seal) runs deferred. ---
	return result, nil
}

func claudeTelemetryDir(sessionDir, harness string) string {
	if harness != "claude" {
		return ""
	}
	return filepath.Join(sessionDir, claudeTelemetryDirName)
}

// sessionGrant is the session.json grant written before VM boot (DESIGN.md
// session grant schema). Its digest is recorded on session.granted.
type sessionGrant struct {
	Schema              string           `json:"schema"`
	SessionID           string           `json:"session_id"`
	TraceID             string           `json:"trace_id"`
	Harness             string           `json:"harness"`
	Profile             string           `json:"profile"`
	RepoPath            string           `json:"repo_path"`
	Repository          string           `json:"repository,omitempty"`
	Branch              string           `json:"branch,omitempty"`
	Commit              string           `json:"commit,omitempty"`
	CreatedAt           string           `json:"created_at"`
	PolicyDigest        string           `json:"policy_digest"`
	InputManifestDigest string           `json:"input_manifest_digest"`
	VMImage             string           `json:"vm_image"`
	VMImageDigest       string           `json:"vm_image_digest"`
	RecorderPub         string           `json:"recorder_pub"`
	AssuranceMode       string           `json:"assurance_mode"`
	TrustRecord         trustRecordGrant `json:"trust_record"`
}

type trustRecordGrant struct {
	Schema   string `json:"schema"`
	Path     string `json:"path"`
	Required bool   `json:"required"`
}

type repositoryProvenance struct {
	Repository string
	Branch     string
	Commit     string
}

func cloneRepository(ctx context.Context, repository, branch, destination string) error {
	if strings.TrimSpace(repository) == "" {
		return fmt.Errorf("session: remote repository is empty")
	}
	if err := validateRemoteRepository(repository); err != nil {
		return err
	}
	args := []string{"clone", "--single-branch"}
	if branch != "" {
		check := exec.CommandContext(ctx, "git", "check-ref-format", "--branch", branch)
		if out, err := check.CombinedOutput(); err != nil {
			return fmt.Errorf("session: invalid branch %q: %s", branch, strings.TrimSpace(string(out)))
		}
		args = append(args, "--branch", branch)
	}
	args = append(args, "--", repository, destination)
	cmd := exec.CommandContext(ctx, "git", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("session: clone repository: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if branch != "" {
		check := exec.CommandContext(ctx, "git", "symbolic-ref", "--quiet", "HEAD")
		check.Dir = destination
		if out, err := check.CombinedOutput(); err != nil {
			return fmt.Errorf("session: requested branch %q did not resolve to a branch: %s", branch, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func validateRemoteRepository(repository string) error {
	if _, ok := githubRepositoryFromRemote(repository); ok {
		return nil
	}
	u, err := url.Parse(repository)
	if err != nil {
		return fmt.Errorf("session: parse remote repository: %w", err)
	}
	if (u.Scheme == "http" || u.Scheme == "https") && u.User != nil {
		return fmt.Errorf("session: remote repository URL must not contain credentials")
	}
	if u.Scheme == "ssh" && u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return fmt.Errorf("session: remote repository URL must not contain credentials")
		}
	}
	return nil
}

func gitProvenance(ctx context.Context, workspace, requestedRepository, requestedBranch string) (repositoryProvenance, error) {
	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = workspace
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	commit, err := run("rev-parse", "HEAD")
	if err != nil {
		if requestedRepository == "" {
			return repositoryProvenance{}, nil
		}
		return repositoryProvenance{}, fmt.Errorf("session: resolve cloned commit: %w", err)
	}
	repository := requestedRepository
	if origin, err := run("config", "--get", "remote.origin.url"); err == nil && origin != "" {
		repository = origin
	}
	branch := requestedBranch
	if current, err := run("branch", "--show-current"); err == nil && current != "" {
		branch = current
	}
	return repositoryProvenance{Repository: repository, Branch: branch, Commit: commit}, nil
}

// validateHarness checks the harness name, that exec has a command, and that
// exec (which is already parameterized by --cmd) is not also given passthrough
// harness args intended for claude/codex.
func validateHarness(harness, cmd string, harnessArgs []string) error {
	switch harness {
	case "claude", "codex":
		return nil
	case "exec":
		if cmd == "" {
			return fmt.Errorf("session: exec harness requires a command (--cmd)")
		}
		if len(harnessArgs) > 0 {
			return fmt.Errorf("session: exec harness does not accept passthrough args (use --cmd)")
		}
		return nil
	default:
		return fmt.Errorf("session: unknown harness %q (want claude|codex|exec)", harness)
	}
}

// resolveRepo absolutizes and confirms the repo path is an existing directory.
func resolveRepo(path string) (string, error) {
	if path == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("session: absolute repo path: %w", err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("session: stat repo %s: %w", abs, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("session: repo path %s is not a directory", abs)
	}
	return abs, nil
}

// agentBinaryProvider serves the cross-compiled guest agent for the given goarch
// from the build output tree (DESIGN.md provisioning step 4). It is read lazily,
// only when the guest actually requests it during provisioning.
func agentBinaryProvider(arch string) ([]byte, error) {
	path := filepath.Join("dist", "guest", "boxedai-guest-agent-linux-"+arch)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("session: read guest agent binary %s: %w", path, err)
	}
	return b, nil
}

// finishWorkspace computes the output manifest, writes it, diffs against the
// pristine input copy, and emits the output workspace.manifested event whose
// content digest matches the output-manifest.json file bytes (the verifier's
// check 9).
func finishWorkspace(sessionDir, orig, workspace string, emit func(evidence.Event) error, result *Result) error {
	outManifest, err := snapshot.ManifestOf(workspace)
	if err != nil {
		return fmt.Errorf("session: output manifest: %w", err)
	}
	outBytes, err := evidence.CanonicalJSON(outManifest)
	if err != nil {
		return fmt.Errorf("session: canonicalize output manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, outputManifestFileName), outBytes, 0o600); err != nil {
		return fmt.Errorf("session: write output manifest: %w", err)
	}
	outDigest := evidence.SHA256Hex(outBytes)

	diff, err := snapshot.Diff(orig, workspace)
	if err != nil {
		return fmt.Errorf("session: diff workspace: %w", err)
	}
	if err := snapshot.WriteDiff(sessionDir, diff); err != nil {
		return err
	}
	result.FilesChanged = len(diff.Added) + len(diff.Modified) + len(diff.Deleted)

	return emit(workspaceManifestedEvent("output", outDigest))
}

// workspaceManifestedEvent builds a workspace.manifested event for a phase
// ("input"/"output") carrying the manifest content digest.
func workspaceManifestedEvent(phase, digest string) evidence.Event {
	return evidence.Event{
		Name:    evidence.EventWorkspaceManifested,
		Outcome: evidence.OutcomeSuccess,
		Body:    phase + " workspace manifest",
		Attrs: map[string]any{
			attrWorkspacePhase:          phase,
			evidence.AttrContentDigest:  digest,
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
		},
	}
}

// credentialEvent builds a credential.issued/revoked event labeled by kind. The
// token value itself is never recorded.
func credentialEvent(name, kind string) evidence.Event {
	return evidence.Event{
		Name:    name,
		Outcome: evidence.OutcomeSuccess,
		Body:    kind + " credential " + credentialVerb(name),
		Attrs:   map[string]any{attrCredentialKind: kind},
	}
}

// credentialVerb renders the human verb for a credential event name.
func credentialVerb(name string) string {
	if name == evidence.EventCredentialRevoked {
		return "revoked"
	}
	return "issued"
}

// sessionEvent builds a plain session lifecycle event.
func sessionEvent(name, body string) evidence.Event {
	return evidence.Event{Name: name, Outcome: evidence.OutcomeSuccess, Body: body}
}

// writeCanonicalFile writes v as canonical JSON (sorted keys) at 0600.
func writeCanonicalFile(path string, v any) error {
	b, err := evidence.CanonicalJSON(v)
	if err != nil {
		return fmt.Errorf("session: canonicalize %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("session: write %s: %w", filepath.Base(path), err)
	}
	return nil
}
