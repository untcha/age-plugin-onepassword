// Package onepassword is the boundary to 1Password. Callers depend on Client;
// OpClient implements it with the op CLI.
package onepassword

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// maxIDLength bounds vault and item IDs (1Password IDs are 26 characters).
const maxIDLength = 255

// ErrNotFound reports a vault or item that does not exist.
var ErrNotFound = errors.New("1password: item not found")

// SSHKeyItem is the metadata of an SSH Key item. It never holds secrets.
type SSHKeyItem struct {
	ID          string
	Title       string
	VaultID     string
	VaultName   string
	Fingerprint string // "SHA256:<base64>", as reported by 1Password
}

// Client is the subset of 1Password the plugin needs.
type Client interface {
	// ListSSHKeys returns metadata of SSH Key items. No secrets.
	ListSSHKeys(ctx context.Context) ([]SSHKeyItem, error)
	// ResolveSSHKey looks up one SSH Key item by vault and item (name or ID).
	ResolveSSHKey(ctx context.Context, vault, item string) (SSHKeyItem, error)
	// PublicKey returns the item's public key in authorized_keys format.
	PublicKey(ctx context.Context, vaultID, itemID string) ([]byte, error)
	// PrivateKey returns the item's private key in OpenSSH format.
	PrivateKey(ctx context.Context, vaultID, itemID string) ([]byte, error)
}

// ValidID reports whether s is a plausible 1Password vault or item ID:
// 1..255 ASCII letters or digits. It keeps untrusted IDs out of op:// references.
func ValidID(s string) bool {
	if s == "" || len(s) > maxIDLength {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// ParseItemRef parses "op://<vault>/<item>" into vault and item (names or IDs).
func ParseItemRef(ref string) (vault, item string, err error) {
	rest, ok := strings.CutPrefix(ref, "op://")
	if !ok {
		return "", "", fmt.Errorf("item reference %q: must start with op://", ref)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("item reference %q: want op://<vault>/<item>", ref)
	}
	return parts[0], parts[1], nil
}
