package recorder

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SigningKey is the recorder's Ed25519 identity: the private key used to COSE-sign
// segment manifests, plus the derived public key and its PKIX PEM encoding (recorded
// in session.json and used by the verifier as the trust root).
type SigningKey struct {
	Priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey
	PubPEM string
}

// key/public-key file names under the key directory (DESIGN "Host filesystem layout").
const (
	privKeyFile = "recorder.key"
	pubKeyFile  = "recorder.pub"
)

// LoadOrGenerateKey loads the Ed25519 recorder keypair from dir, or generates and
// persists a new one if recorder.key is absent. The private key is written PKCS8 at
// 0600 and the public key PKIX at 0644. An existing key is reused as-is.
func LoadOrGenerateKey(dir string) (SigningKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return SigningKey{}, fmt.Errorf("recorder: create key dir: %w", err)
	}
	keyPath := filepath.Join(dir, privKeyFile)
	pubPath := filepath.Join(dir, pubKeyFile)

	if pemBytes, err := os.ReadFile(keyPath); err == nil {
		sk, err := parsePrivateKeyPEM(pemBytes)
		if err != nil {
			return SigningKey{}, err
		}
		// Ensure the public PEM is present alongside the private key for consumers
		// (verifier, session.json) even if a prior run left it missing.
		if _, statErr := os.Stat(pubPath); errors.Is(statErr, os.ErrNotExist) {
			if err := os.WriteFile(pubPath, []byte(sk.PubPEM), 0o644); err != nil {
				return SigningKey{}, fmt.Errorf("recorder: write %s: %w", pubKeyFile, err)
			}
		}
		return sk, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return SigningKey{}, fmt.Errorf("recorder: read %s: %w", privKeyFile, err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKey{}, fmt.Errorf("recorder: generate key: %w", err)
	}
	sk, err := newSigningKey(priv, pub)
	if err != nil {
		return SigningKey{}, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return SigningKey{}, fmt.Errorf("recorder: marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return SigningKey{}, fmt.Errorf("recorder: write %s: %w", privKeyFile, err)
	}
	if err := os.WriteFile(pubPath, []byte(sk.PubPEM), 0o644); err != nil {
		return SigningKey{}, fmt.Errorf("recorder: write %s: %w", pubKeyFile, err)
	}
	return sk, nil
}

// newSigningKey builds a SigningKey and computes the PKIX PEM of the public key.
func newSigningKey(priv ed25519.PrivateKey, pub ed25519.PublicKey) (SigningKey, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return SigningKey{}, fmt.Errorf("recorder: marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return SigningKey{Priv: priv, Pub: pub, PubPEM: string(pubPEM)}, nil
}

// parsePrivateKeyPEM decodes a PKCS8 Ed25519 private key PEM into a SigningKey.
func parsePrivateKeyPEM(pemBytes []byte) (SigningKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return SigningKey{}, errors.New("recorder: recorder.key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return SigningKey{}, fmt.Errorf("recorder: parse private key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return SigningKey{}, fmt.Errorf("recorder: recorder.key is %T, want ed25519.PrivateKey", parsed)
	}
	return newSigningKey(priv, priv.Public().(ed25519.PublicKey))
}
