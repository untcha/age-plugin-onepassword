package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

var _ Client = (*OpClient)(nil)

// OpOptions configures OpClient.
type OpOptions struct {
	Bin     string        // op binary; "op" resolves via PATH
	Vault   string        // optional: limit ListSSHKeys to this vault
	Account string        // optional: --account for every call
	Timeout time.Duration // per call; 0 means none
	Logger  *log.Logger
}

// OpClient implements Client with the 1Password CLI.
type OpClient struct {
	opts OpOptions
}

// NewOpClient returns a Client that shells out to op.
func NewOpClient(opts OpOptions) *OpClient {
	if opts.Bin == "" {
		opts.Bin = "op"
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard)
	}
	return &OpClient{opts: opts}
}

func (c *OpClient) ListSSHKeys(ctx context.Context) ([]SSHKeyItem, error) {
	args := []string{"item", "list", "--categories", "SSH Key", "--format", "json"}
	if c.opts.Vault != "" {
		args = append(args, "--vault", c.opts.Vault)
	}
	out, err := c.run(ctx, "item list", args...)
	if err != nil {
		return nil, err
	}
	var raw []opItem
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("decode op item list: %w", err)
	}
	items := make([]SSHKeyItem, 0, len(raw))
	for _, r := range raw {
		if !ValidID(r.ID) || !ValidID(r.Vault.ID) {
			c.opts.Logger.Warn("skipping 1Password item with invalid ID", "item", r.Title)
			continue
		}
		items = append(items, r.sshKeyItem())
	}
	return items, nil
}

func (c *OpClient) ResolveSSHKey(ctx context.Context, vault, item string) (SSHKeyItem, error) {
	out, err := c.run(ctx, "item get", "item", "get", item, "--vault", vault, "--format", "json")
	if err != nil {
		return SSHKeyItem{}, err
	}
	var r opItem
	if err := json.Unmarshal(out, &r); err != nil {
		return SSHKeyItem{}, fmt.Errorf("decode op item get: %w", err)
	}
	if r.Category != "SSH_KEY" {
		return SSHKeyItem{}, fmt.Errorf("1Password item %q is a %s item, not an SSH key", r.Title, r.Category)
	}
	if !ValidID(r.ID) || !ValidID(r.Vault.ID) {
		return SSHKeyItem{}, fmt.Errorf("1Password item %q: invalid ID", r.Title)
	}
	return r.sshKeyItem(), nil
}

func (c *OpClient) PublicKey(ctx context.Context, vaultID, itemID string) ([]byte, error) {
	ref, err := secretRef(vaultID, itemID, "public key")
	if err != nil {
		return nil, err
	}
	out, err := c.run(ctx, "read", "read", ref)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(out), nil
}

func (c *OpClient) PrivateKey(ctx context.Context, vaultID, itemID string) ([]byte, error) {
	ref, err := secretRef(vaultID, itemID, "private key?ssh-format=openssh")
	if err != nil {
		return nil, err
	}
	return c.run(ctx, "read", "read", ref)
}

// run executes op and returns stdout. stdin and stderr are never inherited:
// in plugin mode they carry the age protocol. stdout is never logged.
func (c *OpClient) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if c.opts.Account != "" {
		args = append(args, "--account", c.opts.Account)
	}
	if c.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.Timeout)
		defer cancel()
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, c.opts.Bin, args...) //nolint:gosec // G204: op path is config; args built here.
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	c.opts.Logger.Debug("op call", "cmd", name, "duration", time.Since(start), "ok", err == nil)
	if err == nil {
		return stdout.Bytes(), nil
	}
	msg := strings.TrimSpace(stderr.String())
	switch {
	case ctx.Err() != nil:
		return nil, fmt.Errorf("op %s: %w", name, ctx.Err())
	case isNotFound(msg):
		return nil, fmt.Errorf("op %s: %w: %s", name, ErrNotFound, msg)
	default:
		return nil, fmt.Errorf("op %s: %w: %s", name, err, msg)
	}
}

func secretRef(vaultID, itemID, field string) (string, error) {
	if !ValidID(vaultID) || !ValidID(itemID) {
		return "", fmt.Errorf("invalid 1Password IDs %q/%q", vaultID, itemID)
	}
	return "op://" + vaultID + "/" + itemID + "/" + field, nil
}

// isNotFound matches op's messages for missing items and vaults, verified
// against op 2.39.0 (docs/manual-verification.md). Keep fakeop messages in sync.
func isNotFound(stderr string) bool {
	return strings.Contains(stderr, "isn't an item") || strings.Contains(stderr, "isn't a vault")
}

// opItem is the subset of op's item JSON the plugin uses.
type opItem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Vault    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	AdditionalInformation string `json:"additional_information"`
}

func (r opItem) sshKeyItem() SSHKeyItem {
	return SSHKeyItem{
		ID:          r.ID,
		Title:       r.Title,
		VaultID:     r.Vault.ID,
		VaultName:   r.Vault.Name,
		Fingerprint: r.AdditionalInformation,
	}
}
