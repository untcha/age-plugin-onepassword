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
			rs, skipped, err := listRecipients(cmd.Context(), a.opts.NewClient(cfg, logger), logger)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(a.opts.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rs); err != nil {
					return err
				}
			} else {
				for _, r := range rs {
					fmt.Fprintf(a.opts.Stdout, "op://%s/%s: %s\n", r.Vault, r.Item, r.PublicKey)
				}
			}
			// Print what worked, but fail so scripts notice the list is incomplete.
			if skipped > 0 {
				return fmt.Errorf("%d of %d SSH Key items skipped, output is incomplete", skipped, skipped+len(rs))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}

// listRecipients returns public keys sorted by vault, item title and item ID,
// and how many items were skipped because no public key matched them.
func listRecipients(
	ctx context.Context, client onepassword.Client, logger *log.Logger,
) (rs []recipient, skipped int, err error) {
	items, err := client.ListSSHKeys(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list SSH keys in 1Password: %w", err)
	}
	pubs, err := client.PublicKeys(ctx, items)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, fmt.Errorf("list recipients: %w", ctx.Err())
		}
		return nil, 0, fmt.Errorf("read public keys from 1Password: %w", err)
	}
	rs = make([]recipient, 0, len(items))
	for _, it := range items {
		pub, ok := pubs[it.Fingerprint]
		if !ok {
			logger.Warn("skipping item: no public key matches its fingerprint", "item", it.Title, "vault", it.VaultName)
			skipped++
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
	return rs, skipped, nil
}
