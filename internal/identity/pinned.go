package identity

import (
	"errors"

	"filippo.io/age"
)

type pinnedIdentity struct {
	d   *Decoder
	pin Pin
}

func (i *pinnedIdentity) Unwrap(_ []*age.Stanza) ([]byte, error) {
	return nil, errors.New("pinned identity: not implemented")
}
