package policy

import "testing"

func TestDevelopAllowsApprovalGatedGitHubPushByDefault(t *testing.T) {
	develop, err := Resolve(ProfileDevelop, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !develop.AllowsEffect("github", "push") {
		t.Error("develop profile must allow repository-scoped GitHub push")
	}
	review, err := Resolve(ProfileReview, nil)
	if err != nil {
		t.Fatal(err)
	}
	if review.AllowsEffect("github", "push") {
		t.Error("review profile must not allow GitHub push by default")
	}
}
