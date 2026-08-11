package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"boxedai/internal/evidence"
	"boxedai/internal/policy"
)

const (
	gitExitTrailer     = "X-BoxedAI-Git-Exit"
	gitErrorTrailer    = "X-BoxedAI-Git-Error"
	gitEvidenceTrailer = "X-BoxedAI-Git-Evidence"
	maxGitErrorBytes   = 4096
)

type githubSSHRunner func(context.Context, io.Reader, io.Writer, io.Writer, []string) error

// enableGitFullDuplex runs before authentication and policy checks so a denied
// receive-pack can return immediately. Git waits for the server's initial ref
// advertisement before writing its request body; Go's default HTTP/1 behavior
// would otherwise try to drain that still-open body before sending the denial.
func enableGitFullDuplex(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A bridge request owns the connection for one bidirectional Git
		// session. Closing it with the response prevents net/http from trying
		// to parse a next request while the current streaming body is open.
		w.Header().Set("Connection", "close")
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			writeErr(w, http.StatusInternalServerError, "Git bridge full-duplex unavailable")
			return
		}
		next(w, r)
	}
}

func prepareGitHubSSH(cfg GitHubConfig) (string, error) {
	repository := strings.TrimSpace(cfg.Repository)
	sshURL := strings.TrimSpace(cfg.SSHURL)
	if repository != cfg.Repository || sshURL != cfg.SSHURL {
		return "", errors.New("broker: GitHub repository and SSH URL must not contain surrounding whitespace")
	}
	if repository == "" {
		if sshURL != "" {
			return "", errors.New("broker: GitHub SSH URL configured without a repository")
		}
		return "", nil
	}
	if !validGitHubRepository(repository) {
		return "", fmt.Errorf("broker: invalid GitHub repository %q", repository)
	}
	authority, path, ok := strings.Cut(sshURL, ":")
	if !ok || !validGitHubAuthority(authority) || !strings.EqualFold(path, repository+".git") {
		return "", fmt.Errorf("broker: invalid GitHub SSH URL %q for repository %q", sshURL, repository)
	}
	return authority, nil
}

func validGitHubRepository(repository string) bool {
	owner, name, ok := strings.Cut(repository, "/")
	return ok && !strings.Contains(name, "/") && validGitHubName(owner) && validGitHubName(name)
}

func validGitHubName(value string) bool {
	if value == "" || len(value) > 100 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !asciiLetterOrDigit(r) && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

func asciiLetterOrDigit(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func validGitHubAuthority(authority string) bool {
	user, host, ok := strings.Cut(authority, "@")
	if !ok || host != "github.com" {
		return false
	}
	if user == "git" {
		return true
	}
	digits, ok := strings.CutPrefix(user, "org-")
	if !ok || digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// handleGitBridge streams one Git wire-protocol session between the guest and
// the host's organization-scoped GitHub SSH identity. The repository and SSH
// target come only from validated session configuration, never from request data.
func (b *Broker) handleGitBridge(w http.ResponseWriter, r *http.Request, _ authKind) {
	if b.githubTarget == "" {
		writeErr(w, http.StatusNotFound, "GitHub access is not configured")
		return
	}
	service := r.PathValue("service")
	var actionID, digest string
	switch service {
	case "git-upload-pack":
		if !strings.EqualFold(r.Header.Get("Content-Type"), "application/octet-stream") {
			writeErr(w, http.StatusUnsupportedMediaType, "Git bridge requires application/octet-stream")
			return
		}
		if !slices.Contains(b.cfg.Policy.Capabilities, policy.CapInternalRead) {
			writeErr(w, http.StatusForbidden, "GitHub read not permitted by policy")
			return
		}
	case "git-receive-pack":
		if !strings.EqualFold(r.Header.Get("Content-Type"), "application/octet-stream") {
			writeErr(w, http.StatusUnsupportedMediaType, "Git bridge requires application/octet-stream")
			return
		}
		var ok bool
		actionID, digest, ok = b.authorizeGitHubPush(w)
		if !ok {
			return
		}
	default:
		writeErr(w, http.StatusNotFound, "Git service not permitted")
		return
	}

	controller := http.NewResponseController(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Trailer", strings.Join([]string{gitExitTrailer, gitErrorTrailer, gitEvidenceTrailer}, ", "))
	w.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		if actionID != "" {
			b.emitEffectFailed(actionID, "github", "push", digest, "initial Git bridge response flush failed", err)
		}
		return
	}

	stderr := &limitedBuffer{remaining: maxGitErrorBytes}
	stdout := &flushWriter{writer: w, controller: controller}
	argv := githubSSHArgs(b.githubTarget, service, b.cfg.GitHub.Repository)
	runErr := b.runGitHubSSH(r.Context(), r.Body, stdout, stderr, argv)
	if runErr != nil {
		if actionID != "" {
			b.emitEffectFailed(actionID, "github", "push", digest, runErr.Error(), runErr)
		}
		setGitTrailers(w.Header(), gitExitCode(runErr), "failed", gitErrorMessage(stderr.String(), runErr))
		return
	}

	if actionID != "" {
		if err := b.emit(evidence.ChannelBroker, effectEvent(
			evidence.EventEffectCompleted,
			evidence.OutcomeSuccess,
			actionID,
			"github",
			"push",
			digest,
			nil,
		)); err != nil {
			setGitTrailers(w.Header(), 1, "failed", "push completed upstream but completion evidence could not be recorded")
			return
		}
		setGitTrailers(w.Header(), 0, "completed", "")
		return
	}
	setGitTrailers(w.Header(), 0, "not-required", "")
}

func (b *Broker) authorizeGitHubPush(w http.ResponseWriter) (string, string, bool) {
	action := NormalizedAction{
		Adapter: "github",
		Op:      "push",
		Args:    map[string]string{"repository": b.cfg.GitHub.Repository},
	}
	digest, err := action.Digest()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to normalize GitHub push")
		return "", "", false
	}
	actionID := newActionID()
	if err := b.emit(evidence.ChannelBroker, effectEvent(evidence.EventEffectRequested, evidence.OutcomeSuccess, actionID, action.Adapter, action.Op, digest, nil)); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return "", "", false
	}
	if !b.cfg.Policy.AllowsEffect(action.Adapter, action.Op) {
		b.emitEffectDenied(actionID, action.Adapter, action.Op, digest, "not permitted by policy")
		writeErr(w, http.StatusForbidden, "GitHub push not permitted by policy")
		return "", "", false
	}
	if b.cfg.Approver == nil || !b.cfg.Approver(action) {
		b.emitEffectDenied(actionID, action.Adapter, action.Op, digest, "not approved")
		writeErr(w, http.StatusForbidden, "GitHub push not approved")
		return "", "", false
	}
	if err := b.emit(evidence.ChannelBroker, effectEvent(evidence.EventEffectApproved, evidence.OutcomeSuccess, actionID, action.Adapter, action.Op, digest, nil)); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return "", "", false
	}
	if err := b.emit(evidence.ChannelBroker, effectEvent(evidence.EventEffectDispatched, evidence.OutcomeSuccess, actionID, action.Adapter, action.Op, digest, nil)); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return "", "", false
	}
	return actionID, digest, true
}

func githubSSHArgs(target, service, repository string) []string {
	return []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "ClearAllForwardings=yes",
		"-o", "ConnectTimeout=15",
		"-o", "ForwardAgent=no",
		"-o", "PermitLocalCommand=no",
		"-o", "RequestTTY=no",
		"--",
		target,
		service,
		repository + ".git",
	}
}

func runGitHubSSH(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, argv []string) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", argv...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

type flushWriter struct {
	writer     io.Writer
	controller *http.ResponseController
}

func (w *flushWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err != nil {
		return n, err
	}
	if err := w.controller.Flush(); err != nil {
		return n, err
	}
	return n, nil
}

type limitedBuffer struct {
	bytes.Buffer
	remaining int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	originalLength := len(p)
	if len(p) > w.remaining {
		p = p[:w.remaining]
	}
	_, _ = w.Buffer.Write(p)
	w.remaining -= len(p)
	return originalLength, nil
}

func gitExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
		return exitErr.ExitCode()
	}
	return 1
}

func gitErrorMessage(stderr string, runErr error) string {
	if message := strings.TrimSpace(stderr); message != "" {
		return message
	}
	return runErr.Error()
}

func setGitTrailers(header http.Header, exitCode int, evidenceStatus, message string) {
	header.Set(gitExitTrailer, strconv.Itoa(exitCode))
	header.Set(gitEvidenceTrailer, evidenceStatus)
	header.Set(gitErrorTrailer, base64.RawStdEncoding.EncodeToString([]byte(message)))
}
