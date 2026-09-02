package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"boxedai/internal/broker"
)

var lookupGitRemote = func(ctx context.Context, repoPath string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", "config", "--get", "remote.origin.url")
	cmd.Dir = repoPath
	return cmd.Output()
}

var lookupGitHubRepository = func(ctx context.Context, repoPath string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "gh", "repo", "view", "--json", "nameWithOwner,sshUrl")
	cmd.Dir = repoPath
	// Repository discovery must never enter gh's interactive auth flow. Setup
	// and session startup are non-authenticating operations; if gh is not
	// already logged in, return its error and let the caller fail closed.
	cmd.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1")
	return cmd.Output()
}

type githubRepositoryView struct {
	NameWithOwner string `json:"nameWithOwner"`
	SSHURL        string `json:"sshUrl"`
}

// resolveGitHubAccess resolves one exact repository and its organization-scoped
// SSH URL through the host gh CLI. No long-lived GitHub credential is copied into
// broker state or the guest.
func resolveGitHubAccess(ctx context.Context, repoPath string) (broker.GitHubConfig, string, error) {
	originOut, err := lookupGitRemote(ctx, repoPath)
	if err != nil {
		// A plain directory is a valid BoxedAi input and has no GitHub access to
		// configure. Avoid invoking gh at all in that case.
		return broker.GitHubConfig{}, "", nil
	}
	origin := strings.TrimSpace(string(originOut))
	if origin == "" || !strings.Contains(strings.ToLower(origin), "github.com") {
		return broker.GitHubConfig{}, "", nil
	}
	originRepository, ok := githubRepositoryFromRemote(origin)
	if !ok {
		return broker.GitHubConfig{}, "", errors.New("session: GitHub origin must be a credential-free github.com repository URL")
	}

	repoOut, err := lookupGitHubRepository(ctx, repoPath)
	if err != nil {
		return broker.GitHubConfig{}, "", fmt.Errorf("session: resolve GitHub repository with gh: %w", err)
	}
	var view githubRepositoryView
	if err := json.Unmarshal(repoOut, &view); err != nil {
		return broker.GitHubConfig{}, "", fmt.Errorf("session: parse GitHub repository metadata from gh: %w", err)
	}
	view.NameWithOwner = strings.TrimSpace(view.NameWithOwner)
	view.SSHURL = strings.TrimSpace(view.SSHURL)
	if !validGitHubRepository(view.NameWithOwner) {
		return broker.GitHubConfig{}, "", fmt.Errorf("session: gh returned invalid GitHub repository %q", view.NameWithOwner)
	}
	if !strings.EqualFold(originRepository, view.NameWithOwner) {
		return broker.GitHubConfig{}, "", fmt.Errorf("session: GitHub origin repository %q does not match gh repository %q", originRepository, view.NameWithOwner)
	}
	if !validResolvedGitHubSSHURL(view.SSHURL, view.NameWithOwner) {
		return broker.GitHubConfig{}, "", fmt.Errorf("session: gh returned invalid GitHub SSH URL %q", view.SSHURL)
	}
	return broker.GitHubConfig{Repository: view.NameWithOwner, SSHURL: view.SSHURL}, origin, nil
}

func githubRepositoryFromRemote(remote string) (string, bool) {
	if authority, repoPath, ok := strings.Cut(remote, ":"); ok && strings.Contains(authority, "@") && !strings.Contains(authority, "/") {
		if !validGitHubSSHAuthority(authority) {
			return "", false
		}
		return normalizeGitHubRepository(repoPath)
	}

	u, err := url.Parse(remote)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() != "github.com" || u.Port() != "" {
		return "", false
	}
	switch u.Scheme {
	case "http", "https":
		if u.User != nil {
			return "", false
		}
	case "ssh":
		if u.User == nil || !validGitHubSSHUser(u.User.Username()) {
			return "", false
		}
		if _, hasPassword := u.User.Password(); hasPassword {
			return "", false
		}
	default:
		return "", false
	}
	return normalizeGitHubRepository(strings.TrimPrefix(u.EscapedPath(), "/"))
}

func normalizeGitHubRepository(repoPath string) (string, bool) {
	if decoded, err := url.PathUnescape(repoPath); err == nil {
		repoPath = decoded
	} else {
		return "", false
	}
	repository := strings.TrimSuffix(repoPath, ".git")
	if !validGitHubRepository(repository) {
		return "", false
	}
	return repository, true
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

func validResolvedGitHubSSHURL(sshURL, repository string) bool {
	authority, repoPath, ok := strings.Cut(sshURL, ":")
	if !ok || !validGitHubSSHAuthority(authority) {
		return false
	}
	resolved, ok := normalizeGitHubRepository(repoPath)
	return ok && strings.HasSuffix(repoPath, ".git") && strings.EqualFold(resolved, repository)
}

func validGitHubSSHAuthority(authority string) bool {
	user, host, ok := strings.Cut(authority, "@")
	return ok && host == "github.com" && validGitHubSSHUser(user)
}

func validGitHubSSHUser(user string) bool {
	return user == "git" || validOrgGitHubSSHUser(user)
}

func validOrgGitHubSSHUser(user string) bool {
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
