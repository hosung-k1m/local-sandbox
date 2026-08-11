package session

import (
	"strings"
	"testing"

	"boxedai/internal/broker"
)

func TestPreapproveGitHubPushCachesExactAction(t *testing.T) {
	promptCalls := 0
	approver := preapproveGitHubPush("squareup/boxedai", true, func(action broker.NormalizedAction) bool {
		promptCalls++
		if action.Adapter != "github" || action.Op != "push" || len(action.Args) != 1 || action.Args["repository"] != "squareup/boxedai" {
			t.Fatalf("prompt action = %+v, want exact github/push action", action)
		}
		return true
	})

	exact := broker.NormalizedAction{
		Adapter: "github",
		Op:      "push",
		Args:    map[string]string{"repository": "squareup/boxedai"},
	}
	if !approver(exact) || !approver(exact) {
		t.Fatal("cached approver denied the exact preapproved action")
	}
	if promptCalls != 1 {
		t.Fatalf("prompt calls = %d, want 1", promptCalls)
	}

	for _, action := range []broker.NormalizedAction{
		{Adapter: "github", Op: "push", Args: map[string]string{"repository": "squareup/other"}},
		{Adapter: "github", Op: "pr-comment", Args: map[string]string{"repository": "squareup/boxedai"}},
		{Adapter: "github", Op: "push", Args: map[string]string{"repository": "squareup/boxedai", "branch": "main"}},
		{Adapter: "slack", Op: "post", Args: map[string]string{"repository": "squareup/boxedai"}},
	} {
		if approver(action) {
			t.Errorf("cached approver accepted unapproved action %+v", action)
		}
	}
	if promptCalls != 1 {
		t.Fatalf("prompt calls after broker checks = %d, want 1", promptCalls)
	}
}

func TestPreapproveGitHubPushDoesNotPromptWithoutGrantOrRepository(t *testing.T) {
	prompt := func(action broker.NormalizedAction) bool {
		t.Fatalf("unexpected approval prompt for %+v", action)
		return true
	}
	exact := broker.NormalizedAction{
		Adapter: "github",
		Op:      "push",
		Args:    map[string]string{"repository": "squareup/boxedai"},
	}

	if preapproveGitHubPush("squareup/boxedai", false, prompt)(exact) {
		t.Fatal("push approved without an external-write:github grant")
	}
	if preapproveGitHubPush("", true, prompt)(exact) {
		t.Fatal("push approved without a configured repository")
	}
}

func TestPreapproveGitHubPushNoninteractiveDeniesBeforeSession(t *testing.T) {
	var output strings.Builder
	prompt := newApprover(strings.NewReader("yes\n"), &output, false)
	approver := preapproveGitHubPush("squareup/boxedai", true, prompt)
	exact := broker.NormalizedAction{
		Adapter: "github",
		Op:      "push",
		Args:    map[string]string{"repository": "squareup/boxedai"},
	}

	if approver(exact) {
		t.Fatal("noninteractive approval unexpectedly allowed a push")
	}
	if !strings.Contains(output.String(), `{"adapter":"github","args":{"repository":"squareup/boxedai"},"op":"push"}`) {
		t.Errorf("approval output did not render the exact action: %q", output.String())
	}
	if !strings.Contains(output.String(), "stdin is not a TTY; auto-denying") {
		t.Errorf("approval output did not explain the denial: %q", output.String())
	}
	if strings.Contains(output.String(), "Approve? [y/N]") {
		t.Errorf("noninteractive approval emitted a prompt: %q", output.String())
	}
}

func TestGitHubPushPromptDisclosesSessionWideRefScope(t *testing.T) {
	var output strings.Builder
	prompt := newApprover(strings.NewReader("yes\n"), &output, true)
	action := broker.NormalizedAction{
		Adapter: "github",
		Op:      "push",
		Args:    map[string]string{"repository": "squareup/boxedai"},
	}

	if !prompt(action) {
		t.Fatal("interactive approval unexpectedly denied")
	}
	for _, disclosure := range []string{
		"cached for the whole session",
		"arbitrary Git ref updates and deletions",
		"exact repository shown above",
	} {
		if !strings.Contains(output.String(), disclosure) {
			t.Errorf("approval output missing %q disclosure: %q", disclosure, output.String())
		}
	}
}
