package identity

import (
	"bytes"
	"errors"
	"fmt"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

// pinnedIdentity reads one known item. It needs a single 1Password call and
// falls back to a fingerprint search if the item was moved or recreated.
type pinnedIdentity struct {
	d   *Decoder
	pin Pin
}

func (i *pinnedIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if !StanzaTags(stanzas)[TagFromPubKey(i.pin.PubKey)] {
		return nil, age.ErrIncorrectIdentity
	}
	key, err := i.d.privateKey(i.pin.VaultID, i.pin.ItemID)
	switch {
	case errors.Is(err, onepassword.ErrNotFound):
		i.d.logger.Warn("pinned 1Password item not found, searching by fingerprint; regenerate the identity",
			"vault", i.pin.VaultID, "item", i.pin.ItemID)
		if key, err = i.findByFingerprint(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("read pinned private key: %w", err)
	}
	if err := matchesPubKey(key, i.pin.PubKey); err != nil {
		return nil, err
	}
	fileKey, err := unwrapWithKey(key, stanzas)
	if err != nil {
		return nil, fmt.Errorf("pinned identity: %w", err)
	}
	return fileKey, nil
}

func (i *pinnedIdentity) findByFingerprint() ([]byte, error) {
	fp := ssh.FingerprintSHA256(i.pin.PubKey)
	items, err := i.d.client.ListSSHKeys(i.d.ctx)
	if err != nil {
		return nil, fmt.Errorf("list SSH keys in 1Password: %w", err)
	}
	for _, it := range items {
		if it.Fingerprint != fp {
			continue
		}
		key, err := i.d.privateKey(it.VaultID, it.ID)
		if err != nil {
			return nil, fmt.Errorf("read private key of 1Password item %q: %w", it.Title, err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("pinned SSH key %s not found in 1Password: %w", fp, age.ErrIncorrectIdentity)
}

// matchesPubKey ensures the key read from 1Password is the pinned key.
func matchesPubKey(key []byte, want ssh.PublicKey) error {
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("pinned identity: parse private key: %w", err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), want.Marshal()) {
		return fmt.Errorf("pinned identity: 1Password key %s does not match pinned key %s",
			ssh.FingerprintSHA256(signer.PublicKey()), ssh.FingerprintSHA256(want))
	}
	return nil
}
