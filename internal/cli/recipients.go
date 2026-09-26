package cli

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

type recipient struct {
	Vault     string `json:"vault"`
	Item      string `json:"item"`
	VaultID   string `json:"vault_id"`
	ItemID    string `json:"item_id"`
	PublicKey string `json:"public_key"`
}

func newRecipientsCmd(a *app) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "recipients",
		Short: "List SSH public keys in 1Password, usable with age -r",
		Long:  "Lists every SSH Key item's public key. Never reads private keys.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, logger, closeLog, err := a.setup(false)
			if err != nil {
				return err
			}
			defer closeLog()
			rs, err := listRecipients(cmd.Context(), a.opts.NewClient(cfg, logger), logger)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(a.opts.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rs)
			}
			for _, r := range rs {
				fmt.Fprintf(a.opts.Stdout, "op://%s/%s: %s\n", r.Vault, r.Item, r.PublicKey)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}

// listRecipients returns public keys sorted by vault, item title and item ID.
func listRecipients(ctx context.Context, client onepassword.Client, logger *log.Logger) ([]recipient, error) {
	items, err := client.ListSSHKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list SSH keys in 1Password: %w", err)
	}
	rs := make([]recipient, 0, len(items))
	for _, it := range items {
		pub, err := client.PublicKey(ctx, it.VaultID, it.ID)
		if err != nil {
			logger.Warn("skipping item: cannot read public key", "item", it.Title, "vault", it.VaultName, "err", err)
			continue
		}
		rs = append(rs, recipient{
			Vault:     it.VaultName,
			Item:      it.Title,
			VaultID:   it.VaultID,
			ItemID:    it.ID,
			PublicKey: string(bytes.TrimSpace(pub)),
		})
	}
	slices.SortFunc(rs, func(x, y recipient) int {
		return cmp.Or(cmp.Compare(x.Vault, y.Vault), cmp.Compare(x.Item, y.Item), cmp.Compare(x.ItemID, y.ItemID))
	})
	return rs, nil
}
