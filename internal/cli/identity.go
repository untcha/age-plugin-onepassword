package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

func newIdentityCmd(a *app) *cobra.Command {
	var (
		keys   []string
		output string
	)
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Write an age identity file (contains no key material)",
		Long: `Without --key, writes the default identity. At decrypt time the plugin finds the SSH key
matching the file in 1Password. Equivalent to "age -d -j onepassword"; makes no 1Password calls.

With --key "op://<vault>/<item>", writes a pinned identity for exactly that SSH Key item.
Decrypting then needs a single 1Password call. Repeat --key for several keys in one file.
Reads only public keys. Nothing is written unless every key resolves.`,
		Example: `  age-plugin-onepassword identity -o ~/.config/chezmoi/op.id
  age-plugin-onepassword identity --key "op://Private/chezmoi-age" -o op.id
  age-plugin-onepassword identity --key "op://Private/laptop" --key "op://Private/backup" -o op.id`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			text := defaultIdentityText()
			if len(keys) > 0 {
				var err error
				if text, err = a.pinnedIdentitiesText(cmd.Context(), keys); err != nil {
					return err
				}
			}
			return writeOutput(output, a.opts.Stdout, text)
		},
	}
	cmd.Flags().StringArrayVar(&keys, "key", nil, `pin to the SSH Key item at "op://<vault>/<item>" (repeatable)`)
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to FILE (must not exist) instead of stdout")
	return cmd
}

// pinnedIdentitiesText builds a pinned identity file for refs. All refs are
// validated and resolved before anything is returned (all or nothing).
func (a *app) pinnedIdentitiesText(ctx context.Context, refs []string) (string, error) {
	for _, ref := range refs {
		if _, _, err := onepassword.ParseItemRef(ref); err != nil {
			return "", err
		}
	}
	cfg, logger, closeLog, err := a.setup(false)
	if err != nil {
		return "", err
	}
	defer closeLog()
	client := a.opts.NewClient(cfg, logger)

	var b strings.Builder
	b.WriteString("# age-plugin-onepassword pinned identity file (contains no key material)\n")
	seen := make(map[string]string) // vaultID/itemID -> first ref
	for _, ref := range refs {
		block, id, err := pinnedBlock(ctx, client, ref)
		if err != nil {
			return "", err
		}
		if prev, dup := seen[id]; dup {
			return "", fmt.Errorf("%s and %s are the same 1Password item", prev, ref)
		}
		seen[id] = ref
		b.WriteString("\n")
		b.WriteString(block)
	}
	return b.String(), nil
}

// pinnedBlock resolves ref and returns its identity block and "vaultID/itemID".
func pinnedBlock(ctx context.Context, client onepassword.Client, ref string) (block, id string, err error) {
	vault, item, err := onepassword.ParseItemRef(ref)
	if err != nil {
		return "", "", err
	}
	it, err := client.ResolveSSHKey(ctx, vault, item)
	if err != nil {
		return "", "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	raw, err := client.PublicKey(ctx, it.VaultID, it.ID)
	if err != nil {
		return "", "", fmt.Errorf("read public key of %s: %w", ref, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse public key of %s: %w", ref, err)
	}
	enc, err := identity.EncodePinned(identity.Pin{VaultID: it.VaultID, ItemID: it.ID, PubKey: pub})
	if err != nil {
		return "", "", err
	}
	block = fmt.Sprintf("# Item: %s/%s\n# Recipient: %s\n%s\n", it.VaultName, it.Title, authorizedKey(pub), enc)
	return block, it.VaultID + "/" + it.ID, nil
}

func defaultIdentityText() string {
	return "# age-plugin-onepassword default identity (contains no key material)\n" +
		"# Finds the matching SSH key in 1Password at decrypt time.\n" +
		identity.EncodeDefault() + "\n"
}

func authorizedKey(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}
