// Package testutil holds test-only helpers. Never import it from non-test code.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword/fake"
)

// Key is a generated SSH key pair in the formats 1Password returns.
type Key struct {
	PublicKey     ssh.PublicKey
	PrivatePEM    []byte // OpenSSH private key PEM
	AuthorizedKey string // "ssh-ed25519 AAAA…", no comment, no newline
	Recipient     age.Recipient
}

// Ed25519 generates an Ed25519 key.
func Ed25519(t testing.TB) Key {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newKey(t, priv)
}

// RSA generates a 2048-bit RSA key.
func RSA(t testing.TB) Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return newKey(t, priv)
}

// Fingerprint returns the fingerprint as 1Password reports it ("SHA256:…").
func (k Key) Fingerprint() string {
	return ssh.FingerprintSHA256(k.PublicKey)
}

// FakeKey returns k as an item for fake.Client.
func (k Key) FakeKey(vaultID, vaultName, itemID, title string) fake.Key {
	return fake.Key{
		Item: onepassword.SSHKeyItem{
			ID:          itemID,
			Title:       title,
			VaultID:     vaultID,
			VaultName:   vaultName,
			Fingerprint: k.Fingerprint(),
		},
		PublicKey:  []byte(k.AuthorizedKey),
		PrivateKey: k.PrivatePEM,
	}
}

// FileKey returns a fixed 16-byte age file key.
func FileKey() []byte {
	return []byte("0123456789abcdef")
}

// Wrap wraps fileKey for every recipient and returns all stanzas in order.
func Wrap(t testing.TB, fileKey []byte, rs ...age.Recipient) []*age.Stanza {
	t.Helper()
	var out []*age.Stanza
	for _, r := range rs {
		ss, err := r.Wrap(fileKey)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ss...)
	}
	return out
}

func newKey(t testing.TB, priv any) Key {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	var r age.Recipient
	if pub.Type() == ssh.KeyAlgoED25519 {
		r, err = agessh.NewEd25519Recipient(pub)
	} else {
		r, err = agessh.NewRSARecipient(pub)
	}
	if err != nil {
		t.Fatal(err)
	}
	return Key{
		PublicKey:     pub,
		PrivatePEM:    pem.EncodeToMemory(block),
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Recipient:     r,
	}
}
