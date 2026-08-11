package session

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func withGitHubLookups(
	t *testing.T,
	remote func(context.Context, string) ([]byte, error),
	repository func(context.Context, string) ([]byte, error),
) {
	t.Helper()
	originalRemote := lookupGitRemote
	originalRepository := lookupGitHubRepository
	lookupGitRemote = remote
	lookupGitHubRepository = repository
	t.Cleanup(func() {
		lookupGitRemote = originalRemote
		lookupGitHubRepository = originalRepository
	})
}

func TestResolveGitHubAccessUsesExactGhSSHURLWithoutToken(t *testing.T) {
	withGitHubLookups(
		t,
		func(context.Context, string) ([]byte, error) {
			return []byte("org-49461806@github.com:squareup/boxedai.git\n"), nil
		},
		func(context.Context, string) ([]byte, error) {
			return []byte(`{"nameWithOwner":"squareup/boxedai","sshUrl":"org-49461806@github.com:squareup/boxedai.git"}`), nil
		},
	)

	cfg, remote, err := resolveGitHubAccess(context.Background(), "/repo")
	if err != nil {
		t.Fatalf("resolveGitHubAccess: %v", err)
	}
	if cfg.Repository != "squareup/boxedai" || cfg.SSHURL != "org-49461806@github.com:squareup/boxedai.git" {
		t.Fatalf("GitHub config = %+v", cfg)
	}
	if remote != "org-49461806@github.com:squareup/boxedai.git" {
		t.Fatalf("GitHub remote = %q", remote)
	}
}

func TestResolveGitHubAccessAcceptsStandardGhSSHURLAndCanonicalCase(t *testing.T) {
	withGitHubLookups(
		t,
		func(context.Context, string) ([]byte, error) {
			return []byte("https://github.com/SquareUp/BoxedAi.git\n"), nil
		},
		func(context.Context, string) ([]byte, error) {
			return []byte(`{"nameWithOwner":"squareup/boxedai","sshUrl":"git@github.com:squareup/boxedai.git"}`), nil
		},
	)

	cfg, _, err := resolveGitHubAccess(context.Background(), "/repo")
	if err != nil {
		t.Fatalf("resolveGitHubAccess: %v", err)
	}
	if cfg.Repository != "squareup/boxedai" || cfg.SSHURL != "git@github.com:squareup/boxedai.git" {
		t.Fatalf("GitHub config = %+v", cfg)
	}
}

func TestResolveGitHubAccessRejectsCredentialInOrigin(t *testing.T) {
	withGitHubLookups(
		t,
		func(context.Context, string) ([]byte, error) {
			return []byte("https://secret@github.com/squareup/boxedai.git"), nil
		},
		func(context.Context, string) ([]byte, error) {
			t.Fatal("gh repo lookup must not run for an unsafe origin")
			return nil, nil
		},
	)

	_, _, err := resolveGitHubAccess(context.Background(), "/repo")
	if err == nil || !strings.Contains(err.Error(), "credential-free") {
		t.Fatalf("resolveGitHubAccess error = %v", err)
	}
}

func TestResolveGitHubAccessRejectsMismatchedOrUnsafeGhMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
	}{
		{name: "different repository", json: `{"nameWithOwner":"squareup/other","sshUrl":"git@github.com:squareup/other.git"}`},
		{name: "different SSH path", json: `{"nameWithOwner":"squareup/boxedai","sshUrl":"git@github.com:squareup/other.git"}`},
		{name: "different host", json: `{"nameWithOwner":"squareup/boxedai","sshUrl":"git@evil.example:squareup/boxedai.git"}`},
		{name: "SSH option injection", json: `{"nameWithOwner":"squareup/boxedai","sshUrl":"-oProxyCommand=x@github.com:squareup/boxedai.git"}`},
		{name: "repository injection", json: `{"nameWithOwner":"squareup/boxedai;touch-pwned","sshUrl":"git@github.com:squareup/boxedai;touch-pwned.git"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGitHubLookups(
				t,
				func(context.Context, string) ([]byte, error) {
					return []byte("git@github.com:squareup/boxedai.git"), nil
				},
				func(context.Context, string) ([]byte, error) { return []byte(tc.json), nil },
			)
			if _, _, err := resolveGitHubAccess(context.Background(), "/repo"); err == nil {
				t.Fatal("resolveGitHubAccess accepted unsafe or mismatched metadata")
			}
		})
	}
}

func TestResolveGitHubAccessSkipsPlainDirectory(t *testing.T) {
	withGitHubLookups(
		t,
		func(context.Context, string) ([]byte, error) {
			return nil, errors.New("not a git repository")
		},
		func(context.Context, string) ([]byte, error) {
			t.Fatal("gh repo lookup must not run for a plain directory")
			return nil, nil
		},
	)

	cfg, remote, err := resolveGitHubAccess(context.Background(), "/repo")
	if err != nil || cfg.Repository != "" || remote != "" {
		t.Fatalf("plain directory resolution = cfg %+v remote %q err %v", cfg, remote, err)
	}
}

func TestGitHubRepositoryFromRemote(t *testing.T) {
	for _, tc := range []struct {
		remote string
		want   string
		ok     bool
	}{
		{remote: "org-49461806@github.com:squareup/boxedai.git", want: "squareup/boxedai", ok: true},
		{remote: "git@github.com:squareup/boxedai.git", want: "squareup/boxedai", ok: true},
		{remote: "https://github.com/squareup/boxedai.git", want: "squareup/boxedai", ok: true},
		{remote: "ssh://git@github.com/squareup/boxedai.git", want: "squareup/boxedai", ok: true},
		{remote: "https://token@github.com/squareup/boxedai.git", ok: false},
		{remote: "ssh://git:secret@github.com/squareup/boxedai.git", ok: false},
		{remote: "https://github.com/squareup/boxedai.git?token=secret", ok: false},
		{remote: "git@github.com:squareup/boxedai.git/other", ok: false},
	} {
		got, ok := githubRepositoryFromRemote(tc.remote)
		if got != tc.want || ok != tc.ok {
			t.Errorf("githubRepositoryFromRemote(%q) = %q, %v; want %q, %v", tc.remote, got, ok, tc.want, tc.ok)
		}
	}
}
