package session

import (
	"strings"
	"testing"
)

func TestHumanCredentialDigestIsSinglePrefixedDigest(t *testing.T) {
	digest := humanCredentialDigest("ssh-ed25519 AAAA\n")
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest = %q, want sha256 prefix", digest)
	}
	if strings.Count(digest, "sha256:") != 1 {
		t.Fatalf("digest = %q, want exactly one sha256 prefix", digest)
	}
}
