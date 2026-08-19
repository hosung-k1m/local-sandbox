package session

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEnsureHumanSSHKeypair(t *testing.T) {
	t.Setenv("BOXEDAI_HOME", t.TempDir())
	public, path, err := EnsureHumanSSHKeypair()
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if public == "" || path == "" {
		t.Fatal("missing generated key")
	}
	for name, want := range map[string]os.FileMode{"human-ssh": 0o700, "human-ssh/id_ed25519": 0o600, "human-ssh/id_ed25519.pub": 0o644} {
		info, statErr := os.Stat(filepath.Join(os.Getenv("BOXEDAI_HOME"), name))
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %v, want %o", name, info.Mode().Perm(), want)
		}
	}
	publicAgain, pathAgain, err := EnsureHumanSSHKeypair()
	if err != nil || publicAgain != public || pathAgain != path {
		t.Fatalf("not idempotent: %q %q %v", publicAgain, pathAgain, err)
	}
}

func TestNormalizeHumanSSHPublicKey(t *testing.T) {
	key, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	publicKey := ssh.MarshalAuthorizedKey(key)
	got, err := normalizeHumanSSHPublicKey(strings.TrimSpace(string(publicKey)) + " operator\n")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !strings.HasSuffix(got, " operator\n") {
		t.Fatalf("normalized key = %q, want preserved comment", got)
	}
}

func TestNormalizeHumanSSHPublicKeyRejectsOptionsAndTrailingData(t *testing.T) {
	for _, value := range []string{
		"command=bad ssh-ed25519 AAAA",
		"ssh-ed25519 AAAA trailing-invalid",
		"not-a-key",
	} {
		if _, err := normalizeHumanSSHPublicKey(value); err == nil {
			t.Errorf("normalize(%q) succeeded, want error", value)
		}
	}
}
