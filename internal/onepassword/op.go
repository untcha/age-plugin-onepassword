package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"golang.org/x/crypto/ssh"
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

// PublicKeys reads the public keys of items with one op call. op's output
// carries no item IDs, only names (verified against op 2.42.0), so keys are
// matched to items by fingerprint.
func (c *OpClient) PublicKeys(ctx context.Context, items []SSHKeyItem) (map[string][]byte, error) {
	keys := make(map[string][]byte, len(items))
	if len(items) == 0 {
		return keys, nil
	}
	type vaultRef struct {
		ID string `json:"id"`
	}
	type itemRef struct {
		ID    string   `json:"id"`
		Vault vaultRef `json:"vault"`
	}
	refs := make([]itemRef, 0, len(items))
	for _, it := range items {
		if !ValidID(it.VaultID) || !ValidID(it.ID) {
			return nil, fmt.Errorf("invalid 1Password IDs %q/%q", it.VaultID, it.ID)
		}
		refs = append(refs, itemRef{ID: it.ID, Vault: vaultRef{ID: it.VaultID}})
	}
	in, err := json.Marshal(refs)
	if err != nil {
		return nil, fmt.Errorf("encode op item get input: %w", err)
	}
	// --fields is required: without it op returns whole items, private keys included.
	out, err := c.runStdin(ctx, in, "item get -",
		"item", "get", "-", "--fields", "label=public key", "--format", "json")
	if err != nil {
		return nil, err
	}
	// op prints one JSON object per item, not an array.
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var f struct {
			Value string `json:"value"`
		}
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("decode op item get: %w", err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(f.Value))
		if err != nil {
			c.opts.Logger.Warn("skipping unparsable public key from op item get", "err", err)
			continue
		}
		keys[ssh.FingerprintSHA256(pub)] = []byte(strings.TrimSpace(f.Value))
	}
	return keys, nil
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
	return c.runStdin(ctx, nil, name, args...)
}

// runStdin is run with stdin fed to op; nil means no input.
func (c *OpClient) runStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
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
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
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
	case errors.Is(ctx.Err(), context.DeadlineExceeded) && c.opts.Timeout > 0:
		return nil, fmt.Errorf("op %s: %w (hint: no answer within %s; approve any open 1Password "+
			"prompt or raise the timeout setting)", name, ctx.Err(), c.opts.Timeout)
	case ctx.Err() != nil:
		return nil, fmt.Errorf("op %s: %w", name, ctx.Err())
	case isNotFound(msg):
		return nil, fmt.Errorf("op %s: %w: %s", name, ErrNotFound, msg)
	case hintFor(msg) != "":
		return nil, fmt.Errorf("op %s: %w: %s (hint: %s)", name, err, msg, hintFor(msg))
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
