package session

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloneRepositoryRecordsRequestedBranchAndCommit(t *testing.T) {
	source := t.TempDir()
	runGit(t, source, "init")
	runGit(t, source, "config", "user.email", "boxedai@example.invalid")
	runGit(t, source, "config", "user.name", "BoxedAi test")
	writeFile(t, filepath.Join(source, "README.md"), "main\n")
	runGit(t, source, "add", "README.md")
	runGit(t, source, "commit", "-m", "initial")
	runGit(t, source, "checkout", "-b", "feature")
	writeFile(t, filepath.Join(source, "feature.txt"), "feature\n")
	runGit(t, source, "add", "feature.txt")
	runGit(t, source, "commit", "-m", "feature")
	wantCommit := runGit(t, source, "rev-parse", "HEAD")

	destination := filepath.Join(t.TempDir(), "workspace")
	if err := cloneRepository(context.Background(), source, "feature", destination); err != nil {
		t.Fatalf("cloneRepository: %v", err)
	}
	provenance, err := gitProvenance(context.Background(), destination, source, "feature")
	if err != nil {
		t.Fatalf("gitProvenance: %v", err)
	}
	if provenance.Repository != source || provenance.Branch != "feature" || provenance.Commit != wantCommit {
		t.Errorf("provenance = %+v, want repository=%q branch=feature commit=%s", provenance, source, wantCommit)
	}
	if _, err := os.Stat(filepath.Join(destination, "feature.txt")); err != nil {
		t.Errorf("fresh branch checkout missing feature.txt: %v", err)
	}
}

func TestCloneRepositoryRejectsTagAsBranch(t *testing.T) {
	source := t.TempDir()
	runGit(t, source, "init")
	runGit(t, source, "config", "user.email", "boxedai@example.invalid")
	runGit(t, source, "config", "user.name", "BoxedAi test")
	writeFile(t, filepath.Join(source, "README.md"), "tagged\n")
	runGit(t, source, "add", "README.md")
	runGit(t, source, "commit", "-m", "initial")
	runGit(t, source, "tag", "v1")

	destination := filepath.Join(t.TempDir(), "workspace")
	err := cloneRepository(context.Background(), source, "v1", destination)
	if err == nil || !strings.Contains(err.Error(), "did not resolve to a branch") {
		t.Fatalf("cloneRepository error = %v, want detached tag rejection", err)
	}
}

func TestValidateRemoteRepositoryAcceptsGitHubSCPURLs(t *testing.T) {
	for _, repository := range []string{
		"org-49461806@github.com:squareup/blockwatch.git",
		"git@github.com:squareup/blockwatch.git",
	} {
		t.Run(repository, func(t *testing.T) {
			if err := validateRemoteRepository(repository); err != nil {
				t.Errorf("validateRemoteRepository(%q) = %v, want nil", repository, err)
			}
		})
	}
}

func TestValidateRemoteRepositoryRejectsInvalidGitHubSCPURLs(t *testing.T) {
	for _, repository := range []string{
		"org-invalid@github.com:squareup/blockwatch.git",
		"org-49461806@github.com:",
	} {
		t.Run(repository, func(t *testing.T) {
			if err := validateRemoteRepository(repository); err == nil {
				t.Errorf("validateRemoteRepository(%q) = nil, want error", repository)
			}
		})
	}
}

func TestValidateRemoteRepositoryPreservesURLValidation(t *testing.T) {
	for _, repository := range []string{
		"https://user:password@github.com/squareup/blockwatch.git",
		"ssh://user:password@github.com/squareup/blockwatch.git",
		"https://github.com/%zz",
	} {
		t.Run(repository, func(t *testing.T) {
			if err := validateRemoteRepository(repository); err == nil {
				t.Errorf("validateRemoteRepository(%q) = nil, want error", repository)
			}
		})
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
