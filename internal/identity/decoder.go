package identity

import (
	"context"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/charmbracelet/log"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

// Decoder turns identity payloads into age identities backed by 1Password.
// All identities it returns share one in-memory private-key cache, so each
// key is fetched at most once per process. Not safe for concurrent use; age
// calls Unwrap sequentially.
type Decoder struct {
	// ctx bounds 1Password calls; age.Identity.Unwrap has no context parameter.
	ctx    context.Context
	client onepassword.Client
	logger *log.Logger
	cache  map[string][]byte
}

// NewDecoder returns a Decoder using client for all 1Password access.
func NewDecoder(ctx context.Context, client onepassword.Client, logger *log.Logger) *Decoder {
	return &Decoder{ctx: ctx, client: client, logger: logger, cache: make(map[string][]byte)}
}

// Decode parses an identity payload as passed by the age plugin framework.
// An empty payload yields the default identity.
func (d *Decoder) Decode(data []byte) (age.Identity, error) {
	pin, err := DecodePayload(data)
	if err != nil {
		return nil, err
	}
	if pin == nil {
		return &defaultIdentity{d: d}, nil
	}
	return &pinnedIdentity{d: d, pin: *pin}, nil
}

// privateKey returns the item's private key, fetching it at most once.
func (d *Decoder) privateKey(vaultID, itemID string) ([]byte, error) {
	k := vaultID + "/" + itemID
	if key, ok := d.cache[k]; ok {
		return key, nil
	}
	key, err := d.client.PrivateKey(d.ctx, vaultID, itemID)
	if err != nil {
		return nil, err
	}
	d.cache[k] = key
	return key, nil
}

// unwrapWithKey unwraps stanzas with an OpenSSH private key. The error wraps
// age.ErrIncorrectIdentity when the key does not match any stanza.
func unwrapWithKey(key []byte, stanzas []*age.Stanza) ([]byte, error) {
	id, err := agessh.ParseIdentity(key)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return id.Unwrap(stanzas)
}
