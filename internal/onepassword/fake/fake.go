// Package fake provides an in-memory onepassword.Client for tests.
package fake

import (
	"context"
	"fmt"
	"strings"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

var _ onepassword.Client = (*Client)(nil)

// Key is one SSH Key item with its key material.
type Key struct {
	Item       onepassword.SSHKeyItem
	PublicKey  []byte
	PrivateKey []byte
}

// Client serves Keys and records every call. Not safe for concurrent use.
type Client struct {
	Keys  []Key
	Err   error // when set, every call fails with it
	calls []string
}

func (c *Client) ListSSHKeys(_ context.Context) ([]onepassword.SSHKeyItem, error) {
	c.calls = append(c.calls, "list")
	if c.Err != nil {
		return nil, c.Err
	}
	items := make([]onepassword.SSHKeyItem, 0, len(c.Keys))
	for _, k := range c.Keys {
		items = append(items, k.Item)
	}
	return items, nil
}

func (c *Client) ResolveSSHKey(_ context.Context, vault, item string) (onepassword.SSHKeyItem, error) {
	c.calls = append(c.calls, "resolve "+vault+"/"+item)
	if c.Err != nil {
		return onepassword.SSHKeyItem{}, c.Err
	}
	for _, k := range c.Keys {
		it := k.Item
		if (it.VaultID == vault || it.VaultName == vault) && (it.ID == item || it.Title == item) {
			return it, nil
		}
	}
	return onepassword.SSHKeyItem{}, fmt.Errorf("resolve %s/%s: %w", vault, item, onepassword.ErrNotFound)
}

func (c *Client) PublicKey(_ context.Context, vaultID, itemID string) ([]byte, error) {
	c.calls = append(c.calls, "public "+vaultID+"/"+itemID)
	k, err := c.find(vaultID, itemID)
	if err != nil {
		return nil, err
	}
	return k.PublicKey, nil
}

func (c *Client) PrivateKey(_ context.Context, vaultID, itemID string) ([]byte, error) {
	c.calls = append(c.calls, "private "+vaultID+"/"+itemID)
	k, err := c.find(vaultID, itemID)
	if err != nil {
		return nil, err
	}
	return k.PrivateKey, nil
}

// Calls returns the recorded calls in order.
func (c *Client) Calls() []string {
	return append([]string(nil), c.calls...)
}

// Count returns how many recorded calls start with prefix.
func (c *Client) Count(prefix string) int {
	n := 0
	for _, call := range c.calls {
		if strings.HasPrefix(call, prefix) {
			n++
		}
	}
	return n
}

func (c *Client) find(vaultID, itemID string) (Key, error) {
	if c.Err != nil {
		return Key{}, c.Err
	}
	for _, k := range c.Keys {
		if k.Item.VaultID == vaultID && k.Item.ID == itemID {
			return k, nil
		}
	}
	return Key{}, fmt.Errorf("%s/%s: %w", vaultID, itemID, onepassword.ErrNotFound)
}
