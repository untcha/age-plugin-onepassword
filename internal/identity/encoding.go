package identity

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	ageplugin "filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

// PluginName is the age plugin name: binary age-plugin-onepassword, `age -j onepassword`.
const PluginName = "onepassword"

// payloadV1 is the version byte of the pinned identity payload.
const payloadV1 byte = 0x01

// Pin identifies exactly one SSH Key item in 1Password. It holds no secrets.
type Pin struct {
	VaultID string
	ItemID  string
	PubKey  ssh.PublicKey
}

// EncodeDefault returns the default identity (empty payload). It matches any
// SSH key in 1Password and is equivalent to `age -j onepassword`.
func EncodeDefault() string {
	return ageplugin.EncodeIdentity(PluginName, nil)
}

// EncodePinned returns the identity string for p.
//
// Payload v1: version byte, then vault ID, item ID and SSH wire-format public
// key, each prefixed with a big-endian uint16 length.
func EncodePinned(p Pin) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	b := []byte{payloadV1}
	for _, f := range [][]byte{[]byte(p.VaultID), []byte(p.ItemID), p.PubKey.Marshal()} {
		if len(f) > math.MaxUint16 {
			return "", fmt.Errorf("pin: field of %d bytes too long", len(f))
		}
		b = binary.BigEndian.AppendUint16(
			b,
			uint16(len(f)), //nolint:gosec // G115: bounded by the MaxUint16 check above.
		)
		b = append(b, f...)
	}
	return ageplugin.EncodeIdentity(PluginName, b), nil
}

// DecodePayload parses an identity payload. An empty payload is the default
// identity and returns (nil, nil).
func DecodePayload(data []byte) (*Pin, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[0] != payloadV1 {
		return nil, fmt.Errorf("identity payload: unsupported version %d", data[0])
	}
	rest := data[1:]
	var fields [3][]byte
	for i := range fields {
		var err error
		if fields[i], rest, err = readField(rest); err != nil {
			return nil, fmt.Errorf("identity payload: %w", err)
		}
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("identity payload: %d trailing bytes", len(rest))
	}
	pk, err := ssh.ParsePublicKey(fields[2])
	if err != nil {
		return nil, fmt.Errorf("identity payload: public key: %w", err)
	}
	p := &Pin{VaultID: string(fields[0]), ItemID: string(fields[1]), PubKey: pk}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("identity payload: %w", err)
	}
	return p, nil
}

func (p Pin) validate() error {
	if !onepassword.ValidID(p.VaultID) {
		return fmt.Errorf("pin: invalid vault ID %q", p.VaultID)
	}
	if !onepassword.ValidID(p.ItemID) {
		return fmt.Errorf("pin: invalid item ID %q", p.ItemID)
	}
	if p.PubKey == nil {
		return errors.New("pin: missing public key")
	}
	if t := p.PubKey.Type(); t != ssh.KeyAlgoED25519 && t != ssh.KeyAlgoRSA {
		return fmt.Errorf("pin: unsupported key type %s", t)
	}
	return nil
}

func readField(b []byte) (field, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errors.New("truncated field length")
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if n == 0 {
		return nil, nil, errors.New("empty field")
	}
	if len(b) < n {
		return nil, nil, errors.New("truncated field")
	}
	return b[:n], b[n:], nil
}
