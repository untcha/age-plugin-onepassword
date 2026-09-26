// Package identity implements age identities backed by SSH keys in 1Password.
package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

// tagSize is the number of SHA-256 bytes age puts in an SSH stanza tag.
const tagSize = 4

// TagFromFingerprint converts a 1Password fingerprint ("SHA256:<base64>") into
// the stanza tag age writes for the same SSH public key.
func TagFromFingerprint(fp string) (string, error) {
	b64, ok := strings.CutPrefix(fp, "SHA256:")
	if !ok {
		return "", fmt.Errorf("fingerprint %q: missing SHA256: prefix", fp)
	}
	sum, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("fingerprint %q: %w", fp, err)
	}
	if len(sum) != sha256.Size {
		return "", fmt.Errorf("fingerprint %q: got %d bytes, want %d", fp, len(sum), sha256.Size)
	}
	return base64.RawStdEncoding.EncodeToString(sum[:tagSize]), nil
}

// TagFromPubKey returns the stanza tag age writes for pk.
func TagFromPubKey(pk ssh.PublicKey) string {
	sum := sha256.Sum256(pk.Marshal())
	return base64.RawStdEncoding.EncodeToString(sum[:tagSize])
}

// StanzaTags collects the tags of all ssh-ed25519 and ssh-rsa stanzas.
func StanzaTags(stanzas []*age.Stanza) map[string]bool {
	tags := make(map[string]bool)
	for _, s := range stanzas {
		if (s.Type == ssh.KeyAlgoED25519 || s.Type == ssh.KeyAlgoRSA) && len(s.Args) > 0 {
			tags[s.Args[0]] = true
		}
	}
	return tags
}
