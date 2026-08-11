package broker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"boxedai/internal/evidence"
	"boxedai/internal/policy"
)

func githubConfig(t *testing.T, extraCaps []string, approver Approver) Config {
	t.Helper()
	pol, err := policy.Resolve(policy.ProfileDevelop, extraCaps)
	if err != nil {
		t.Fatalf("resolve policy: %v", err)
	}
	return Config{
		Emitter:  &fakeEmitter{},
		Policy:   pol,
		Approver: approver,
		GitHub: GitHubConfig{
			Repository: "acme/widget",
			SSHURL:     "org-12345@github.com:acme/widget.git",
		},
	}
}

func gitRequest(t *testing.T, method, rawURL, token string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Git bridge request: %v", err)
	}
	return resp
}

func TestPrepareGitHubSSHScopesExactRepositoryAndTarget(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  GitHubConfig
		want string
		ok   bool
	}{
		{name: "organization identity", cfg: GitHubConfig{Repository: "squareup/boxedai", SSHURL: "org-49461806@github.com:squareup/boxedai.git"}, want: "org-49461806@github.com", ok: true},
		{name: "standard identity", cfg: GitHubConfig{Repository: "squareup/boxedai", SSHURL: "git@github.com:squareup/boxedai.git"}, want: "git@github.com", ok: true},
		{name: "case insensitive identity", cfg: GitHubConfig{Repository: "squareup/boxedai", SSHURL: "git@github.com:SquareUp/BoxedAi.git"}, want: "git@github.com", ok: true},
		{name: "mismatched path", cfg: GitHubConfig{Repository: "squareup/boxedai", SSHURL: "git@github.com:squareup/other.git"}},
		{name: "wrong host", cfg: GitHubConfig{Repository: "squareup/boxedai", SSHURL: "git@evil.example:squareup/boxedai.git"}},
		{name: "option injection", cfg: GitHubConfig{Repository: "squareup/boxedai", SSHURL: "-oProxyCommand=x@github.com:squareup/boxedai.git"}},
		{name: "path injection", cfg: GitHubConfig{Repository: "squareup/widget;touch-pwned", SSHURL: "git@github.com:squareup/widget;touch-pwned.git"}},
		{name: "repository surrounding whitespace", cfg: GitHubConfig{Repository: "squareup/boxedai\n", SSHURL: "git@github.com:squareup/boxedai.git"}},
		{name: "SSH URL surrounding whitespace", cfg: GitHubConfig{Repository: "squareup/boxedai", SSHURL: " git@github.com:squareup/boxedai.git"}},
		{name: "URL without repository", cfg: GitHubConfig{SSHURL: "git@github.com:squareup/boxedai.git"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := prepareGitHubSSH(tc.cfg)
			if tc.ok && (err != nil || got != tc.want) {
				t.Fatalf("prepareGitHubSSH = %q, %v; want %q, nil", got, err, tc.want)
			}
			if !tc.ok && err == nil {
				t.Fatalf("prepareGitHubSSH accepted %+v", tc.cfg)
			}
		})
	}
}

func TestGitHubReadUsesFixedHostSSHArgvAndStreams(t *testing.T) {
	b := mustBroker(t, githubConfig(t, nil, nil))
	var gotArgv []string
	b.runGitHubSSH = func(_ context.Context, stdin io.Reader, stdout, _ io.Writer, argv []string) error {
		gotArgv = append([]string(nil), argv...)
		body, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		if string(body) != "request" {
			t.Errorf("SSH stdin = %q, want request", body)
		}
		_, err = io.WriteString(stdout, "response")
		return err
	}
	srv := testServer(t, b)

	resp := gitRequest(t, http.MethodPost, srv.URL+"/v1/git/git-upload-pack", b.WorkloadToken(), strings.NewReader("request"))
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "response" {
		t.Fatalf("Git response = %q, %v", body, err)
	}
	if got := resp.Trailer.Get(gitExitTrailer); got != "0" {
		t.Errorf("exit trailer = %q, want 0", got)
	}
	if got := resp.Trailer.Get(gitEvidenceTrailer); got != "not-required" {
		t.Errorf("evidence trailer = %q, want not-required", got)
	}
	wantArgv := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "ClearAllForwardings=yes",
		"-o", "ConnectTimeout=15",
		"-o", "ForwardAgent=no",
		"-o", "PermitLocalCommand=no",
		"-o", "RequestTTY=no",
		"--",
		"org-12345@github.com",
		"git-upload-pack",
		"acme/widget.git",
	}
	if strings.Join(gotArgv, "\x00") != strings.Join(wantArgv, "\x00") {
		t.Fatalf("SSH argv = %v, want %v", gotArgv, wantArgv)
	}
}

func TestGitBridgeIsFullDuplex(t *testing.T) {
	b := mustBroker(t, githubConfig(t, nil, nil))
	received := make(chan string, 1)
	b.runGitHubSSH = func(_ context.Context, stdin io.Reader, stdout, _ io.Writer, _ []string) error {
		if _, err := io.WriteString(stdout, "ready"); err != nil {
			return err
		}
		body, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		received <- string(body)
		_, err = io.WriteString(stdout, "done")
		return err
	}
	srv := testServer(t, b)
	requestReader, requestWriter := io.Pipe()
	response := make(chan *http.Response, 1)
	requestErr := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/git/git-upload-pack", requestReader)
		if err != nil {
			requestErr <- err
			return
		}
		req.Header.Set("Authorization", "Bearer "+b.WorkloadToken())
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			requestErr <- err
			return
		}
		response <- resp
	}()

	if _, err := io.WriteString(requestWriter, "input"); err != nil {
		t.Fatalf("write request prefix: %v", err)
	}
	var resp *http.Response
	select {
	case resp = <-response:
	case err := <-requestErr:
		t.Fatalf("request before body close: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("response headers did not arrive while request body remained open")
	}
	first := make([]byte, len("ready"))
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "ready" {
		t.Fatalf("first response = %q, %v", first, err)
	}
	if err := requestWriter.Close(); err != nil {
		t.Fatalf("close request: %v", err)
	}
	rest, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(rest) != "done" {
		t.Fatalf("remaining response = %q, %v", rest, err)
	}
	if got := <-received; got != "input" {
		t.Fatalf("SSH stdin = %q, want input", got)
	}
}

func TestGitHubPushDeniedBeforeSSH(t *testing.T) {
	approverCalled := false
	cfg := Config{
		Emitter: &fakeEmitter{},
		Policy: policy.Policy{
			Schema:       "boxedai.policy/v1",
			Profile:      policy.ProfileDevelop,
			Capabilities: []policy.Capability{policy.CapModel, policy.CapInternalRead},
			Tools:        map[string][]string{"codesearch": {"search-code", "show-file"}},
			Effects:      map[string][]string{"github": {"pr-comment"}},
		},
		Approver: func(NormalizedAction) bool {
			approverCalled = true
			return true
		},
		GitHub: GitHubConfig{
			Repository: "acme/widget",
			SSHURL:     "org-12345@github.com:acme/widget.git",
		},
	}
	b := mustBroker(t, cfg)
	sshCalled := false
	b.runGitHubSSH = func(context.Context, io.Reader, io.Writer, io.Writer, []string) error {
		sshCalled = true
		return nil
	}
	fe := b.cfg.Emitter.(*fakeEmitter)
	srv := testServer(t, b)
	resp := gitRequest(t, http.MethodPost, srv.URL+"/v1/git/git-receive-pack", b.WorkloadToken(), strings.NewReader("push"))
	drain(resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("push status = %d, want 403", resp.StatusCode)
	}
	if approverCalled || sshCalled {
		t.Fatal("policy-denied push reached approval or SSH")
	}
	if !fe.has(evidence.EventEffectRequested) || !fe.has(evidence.EventEffectDenied) || fe.has(evidence.EventEffectDispatched) {
		t.Fatalf("unexpected push evidence: %v", eventNames(fe))
	}
}

func TestGitBridgeDenialReturnsWhileRequestBodyRemainsOpen(t *testing.T) {
	for _, tc := range []struct {
		name       string
		token      func(*Broker) string
		wantStatus int
	}{
		{
			name:       "authentication denial",
			token:      func(*Broker) string { return "wrong" },
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "push policy denial",
			token:      func(b *Broker) string { return b.WorkloadToken() },
			wantStatus: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := mustBroker(t, githubConfig(t, nil, nil))
			srv := testServer(t, b)
			requestReader, requestWriter := io.Pipe()
			t.Cleanup(func() {
				_ = requestReader.Close()
				_ = requestWriter.Close()
			})

			response := make(chan *http.Response, 1)
			requestErr := make(chan error, 1)
			go func() {
				req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/git/git-receive-pack", requestReader)
				if err != nil {
					requestErr <- err
					return
				}
				req.Header.Set("Authorization", "Bearer "+tc.token(b))
				req.Header.Set("Content-Type", "application/octet-stream")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					requestErr <- err
					return
				}
				response <- resp
			}()

			select {
			case resp := <-response:
				defer resp.Body.Close()
				if resp.StatusCode != tc.wantStatus {
					t.Fatalf("denial status = %d, want %d", resp.StatusCode, tc.wantStatus)
				}
			case err := <-requestErr:
				t.Fatalf("denial request: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("denial did not arrive while request body remained open")
			}
		})
	}
}

func TestGitHubPushRequiresApprovalAndRecordsCompletion(t *testing.T) {
	approved := false
	var action NormalizedAction
	b := mustBroker(t, githubConfig(t, []string{"external-write:github"}, func(got NormalizedAction) bool {
		action = got
		return approved
	}))
	sshCalls := 0
	b.runGitHubSSH = func(_ context.Context, _ io.Reader, stdout, _ io.Writer, argv []string) error {
		sshCalls++
		if argv[len(argv)-2] != "git-receive-pack" {
			t.Errorf("SSH service argv = %v", argv)
		}
		_, err := io.WriteString(stdout, "push result")
		return err
	}
	fe := b.cfg.Emitter.(*fakeEmitter)
	srv := testServer(t, b)
	bridgeURL := srv.URL + "/v1/git/git-receive-pack"

	denied := gitRequest(t, http.MethodPost, bridgeURL, b.WorkloadToken(), strings.NewReader("push"))
	drain(denied)
	if denied.StatusCode != http.StatusForbidden || sshCalls != 0 {
		t.Fatalf("unapproved push = status %d SSH calls %d", denied.StatusCode, sshCalls)
	}
	if action.Adapter != "github" || action.Op != "push" || action.Args["repository"] != "acme/widget" {
		t.Fatalf("approval action = %+v", action)
	}

	approved = true
	allowed := gitRequest(t, http.MethodPost, bridgeURL, b.WorkloadToken(), strings.NewReader("push"))
	body, err := io.ReadAll(allowed.Body)
	allowed.Body.Close()
	if err != nil || allowed.StatusCode != http.StatusOK || string(body) != "push result" {
		t.Fatalf("approved push = status %d body %q err %v", allowed.StatusCode, body, err)
	}
	if allowed.Trailer.Get(gitExitTrailer) != "0" || allowed.Trailer.Get(gitEvidenceTrailer) != "completed" {
		t.Fatalf("approved push trailers = %v", allowed.Trailer)
	}
	for _, name := range []string{evidence.EventEffectApproved, evidence.EventEffectDispatched, evidence.EventEffectCompleted} {
		if !fe.has(name) {
			t.Errorf("approved push missing %s evidence: %v", name, eventNames(fe))
		}
	}
}

func TestGitHubPushSignalsSSHAndEvidenceFailuresInTrailers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		runErr     error
		failEvent  string
		wantOutput string
	}{
		{name: "SSH failure", runErr: errors.New("SSH failed"), wantOutput: "partial"},
		{name: "completion evidence failure", failEvent: evidence.EventEffectCompleted, wantOutput: "partial"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := mustBroker(t, githubConfig(t, []string{"external-write:github"}, func(NormalizedAction) bool { return true }))
			fe := b.cfg.Emitter.(*fakeEmitter)
			fe.failOn = tc.failEvent
			b.runGitHubSSH = func(_ context.Context, _ io.Reader, stdout, stderr io.Writer, _ []string) error {
				_, _ = io.WriteString(stdout, "partial")
				if tc.runErr != nil {
					_, _ = io.WriteString(stderr, "safe SSH error")
				}
				return tc.runErr
			}
			srv := testServer(t, b)
			resp := gitRequest(t, http.MethodPost, srv.URL+"/v1/git/git-receive-pack", b.WorkloadToken(), strings.NewReader("push"))
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != tc.wantOutput {
				t.Fatalf("push response = %q, %v", body, err)
			}
			if resp.Trailer.Get(gitExitTrailer) == "0" || resp.Trailer.Get(gitEvidenceTrailer) != "failed" {
				t.Fatalf("failed push trailers = %v", resp.Trailer)
			}
		})
	}
}

func TestGitBridgeRejectsWrongAuthAndServiceBeforeSSH(t *testing.T) {
	b := mustBroker(t, githubConfig(t, nil, nil))
	sshCalled := false
	b.runGitHubSSH = func(context.Context, io.Reader, io.Writer, io.Writer, []string) error {
		sshCalled = true
		return nil
	}
	srv := testServer(t, b)

	badAuth := gitRequest(t, http.MethodPost, srv.URL+"/v1/git/git-upload-pack", "wrong", strings.NewReader(""))
	drain(badAuth)
	if badAuth.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad auth status = %d, want 401", badAuth.StatusCode)
	}
	badService := gitRequest(t, http.MethodPost, srv.URL+"/v1/git/git-upload-archive", b.WorkloadToken(), strings.NewReader(""))
	drain(badService)
	if badService.StatusCode != http.StatusNotFound {
		t.Errorf("bad service status = %d, want 404", badService.StatusCode)
	}
	if sshCalled {
		t.Fatal("invalid bridge request reached SSH")
	}
}

func TestLegacyHostGitPushAdapterIsDisabled(t *testing.T) {
	pol, err := policy.Resolve(policy.ProfileDevelop, []string{"external-write:github"})
	if err != nil {
		t.Fatalf("resolve policy: %v", err)
	}
	approverCalled := false
	b := mustBroker(t, Config{
		Emitter: &fakeEmitter{},
		Policy:  pol,
		Effects: map[string]map[string][]string{
			"github": {"push": {"git", "push", "{{remote}}", "{{branch}}"}},
		},
		Approver: func(NormalizedAction) bool {
			approverCalled = true
			return true
		},
	})
	srv := testServer(t, b)
	resp := do(t, http.MethodPost, srv.URL+"/v1/effects/github/push", b.WorkloadToken(), `{"remote":"origin","branch":"main"}`)
	drain(resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("legacy host push status = %d, want 400", resp.StatusCode)
	}
	if approverCalled {
		t.Fatal("legacy host push must not reach approval or dispatch")
	}
}
