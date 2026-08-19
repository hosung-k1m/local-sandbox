package policy

import (
	"slices"
	"testing"

	"boxedai/internal/evidence"
)

func TestDevelopAllowsApprovalGatedGitHubPushByDefault(t *testing.T) {
	develop, err := Resolve(ProfileDevelop, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !develop.AllowsEffect("github", "push") {
		t.Error("develop profile must allow repository-scoped GitHub push")
	}
	review, err := Resolve(ProfileReview, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if review.AllowsEffect("github", "push") {
		t.Error("review profile must not allow GitHub push by default")
	}
}

// TestResolveAllProfilesCarryFileCaptureDefaults pins the file-capture policy to be
// uniform across profiles: they differ in what the agent may reach, not in what an
// observer may later read back (see defaultFileCapture's doc comment).
func TestResolveAllProfilesCarryFileCaptureDefaults(t *testing.T) {
	wantSecretGlobs := []string{".env*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*"}
	wantExcludeDirs := []string{"node_modules", "vendor", ".venv", "venv", "target", "build", "dist", "__pycache__", ".gradle"}
	for _, profile := range []Profile{ProfileReview, ProfileDevelop, ProfileRestricted} {
		t.Run(string(profile), func(t *testing.T) {
			p, err := Resolve(profile, nil, nil)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if p.FileCapture.MaxBytes != 8<<20 {
				t.Errorf("MaxBytes = %d, want %d", p.FileCapture.MaxBytes, int64(8<<20))
			}
			if !slices.Equal(p.FileCapture.SecretGlobs, wantSecretGlobs) {
				t.Errorf("SecretGlobs = %v, want %v", p.FileCapture.SecretGlobs, wantSecretGlobs)
			}
			if !slices.Equal(p.FileCapture.ExcludeDirs, wantExcludeDirs) {
				t.Errorf("ExcludeDirs = %v, want %v", p.FileCapture.ExcludeDirs, wantExcludeDirs)
			}
		})
	}
}

// TestResolveExtraSecretGlobsAppendWithoutMutatingDefaults guards the clone in
// Resolve: appending a caller's --secret glob must never leak into the
// package-level defaultFileCapture, or one session's extra glob would silently
// apply to every later Resolve call.
func TestResolveExtraSecretGlobsAppendWithoutMutatingDefaults(t *testing.T) {
	base, err := Resolve(ProfileDevelop, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	withExtra, err := Resolve(ProfileDevelop, nil, []string{"*.secret", "config/*.json"})
	if err != nil {
		t.Fatal(err)
	}
	want := append(slices.Clone(base.FileCapture.SecretGlobs), "*.secret", "config/*.json")
	if !slices.Equal(withExtra.FileCapture.SecretGlobs, want) {
		t.Errorf("SecretGlobs = %v, want %v", withExtra.FileCapture.SecretGlobs, want)
	}

	// A later, unrelated Resolve call must still see only the untouched defaults.
	again, err := Resolve(ProfileDevelop, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(again.FileCapture.SecretGlobs, base.FileCapture.SecretGlobs) {
		t.Errorf("later Resolve SecretGlobs = %v, want %v (previous call's extra globs leaked into the defaults)",
			again.FileCapture.SecretGlobs, base.FileCapture.SecretGlobs)
	}
}

// TestResolveRejectsMalformedSecretGlob guards against a malformed --secret value
// being silently accepted and then never matching anything at capture time — a
// secret leak dressed up as a working flag. Resolve must fail loudly instead.
func TestResolveRejectsMalformedSecretGlob(t *testing.T) {
	if _, err := Resolve(ProfileDevelop, nil, []string{"["}); err == nil {
		t.Fatal("Resolve: expected error for malformed secret glob, got nil")
	}
}

// TestFileCaptureSecret pins the matching semantics documented on Secret: a
// slash-free glob matches the base name at any depth, a glob containing "/" is
// matched against the whole relative path, and everything else stays unmatched.
func TestFileCaptureSecret(t *testing.T) {
	cases := []struct {
		name    string
		globs   []string
		relPath string
		want    bool
	}{
		{"slash-free glob matches basename at depth", []string{".env*"}, "sub/dir/.env.local", true},
		{"slash-free glob matches basename at root", []string{"*.pem"}, "certs/x.pem", true},
		{"glob with slash matches full path", []string{"deploy/*.json"}, "deploy/config.json", true},
		{"glob with slash does not match other depths", []string{"deploy/*.json"}, "other/deploy/config.json", false},
		{"non-matching file", []string{".env*", "*.pem"}, "README.md", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fc := FileCapture{SecretGlobs: c.globs}
			if got := fc.Secret(c.relPath); got != c.want {
				t.Errorf("Secret(%q) with globs %v = %v, want %v", c.relPath, c.globs, got, c.want)
			}
		})
	}
}

// TestFileCaptureExcluded pins the matching semantics documented on Excluded: an
// ExcludeDirs entry matches a whole path segment at any depth, never a partial
// segment.
func TestFileCaptureExcluded(t *testing.T) {
	fc := FileCapture{ExcludeDirs: []string{"node_modules", "vendor"}}
	cases := []struct {
		relPath string
		want    bool
	}{
		{"a/node_modules/b/x.js", true},
		{"node_modules/x.js", true},
		{"my_node_modules/x.js", false},
		{"a/node_modules_bak/x", false},
		{"vendor/pkg/main.go", true},
		{"src/main.go", false},
	}
	for _, c := range cases {
		if got := fc.Excluded(c.relPath); got != c.want {
			t.Errorf("Excluded(%q) = %v, want %v", c.relPath, got, c.want)
		}
	}
}

// TestPolicyDigestReflectsFileCapture guards the reason FileCapture rides inside
// Policy rather than a separate config: the capture rules in force must be covered
// by the attested policy digest, so a change to them must change the digest, and
// identical input must always digest identically.
func TestPolicyDigestReflectsFileCapture(t *testing.T) {
	p1, err := Resolve(ProfileDevelop, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := p1.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d1Again, err := p1.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d1Again {
		t.Errorf("Digest not stable for identical input: %s != %s", d1, d1Again)
	}

	p2, err := Resolve(ProfileDevelop, nil, []string{"*.secret"})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := p2.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Error("Digest unchanged after FileCapture.SecretGlobs differed")
	}
}

func TestHumanAccessPolicyRejectsUnsupportedWritableRuntime(t *testing.T) {
	p, err := Resolve(ProfileDevelop, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.HumanAccess.Enabled = true
	if p.HumanAccess.CanStartWritable(p.WorkspaceWritable) {
		t.Fatal("unsupported human access runtime may start writable session")
	}
	p.HumanAccess.Runtime = evidence.RuntimeCapabilityState{
		WriteThroughLowerMount: true,
		PrivateLowerMount:      true,
		SetfsuidProbe:          true,
		WritebackCacheDisabled: true,
		PrivilegedFUSE:         true,
		MediatedWriteOpen:      true,
		HostReDerivation:       true,
		UIDSeparation:          true,
	}
	if !p.HumanAccess.CanStartWritable(p.WorkspaceWritable) {
		t.Fatal("complete human access runtime may not start writable session")
	}
}
