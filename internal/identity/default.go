package identity

import (
	"errors"
	"fmt"

	"filippo.io/age"
)

// defaultIdentity finds the key a file was encrypted to by matching stanza
// tags against 1Password fingerprints, then reads only matching keys.
type defaultIdentity struct {
	d *Decoder
}

func (i *defaultIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	tags := StanzaTags(stanzas)
	if len(tags) == 0 {
		return nil, age.ErrIncorrectIdentity
	}
	items, err := i.d.client.ListSSHKeys(i.d.ctx)
	if err != nil {
		return nil, fmt.Errorf("list SSH keys in 1Password: %w", err)
	}
	for _, it := range items {
		tag, err := TagFromFingerprint(it.Fingerprint)
		if err != nil {
			i.d.logger.Warn("skipping 1Password item", "item", it.Title, "vault", it.VaultID, "err", err)
			continue
		}
		if !tags[tag] {
			continue
		}
		i.d.logger.Debug("stanza tag matches 1Password item", "item", it.Title, "vault", it.VaultID, "tag", tag)
		key, err := i.d.privateKey(it.VaultID, it.ID)
		if err != nil {
			return nil, fmt.Errorf("read private key of 1Password item %q: %w", it.Title, err)
		}
		fileKey, err := unwrapWithKey(key, stanzas)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			i.d.logger.Debug("tag collision, trying next item", "item", it.Title)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("1Password item %q: %w", it.Title, err)
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}
