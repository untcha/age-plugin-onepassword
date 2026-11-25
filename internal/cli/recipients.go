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
		Long: "Lists every SSH Key item's public key. Never reads private keys.\n\n" +
			"Each line starts with the item's op://<vault ID>/<item ID> reference, usable with\n" +
			"identity --key, followed by the vault and item names.",
		Args: cobra.NoArgs,
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
				// IDs in the reference: names can repeat or contain "/", so only IDs
				// always resolve with identity --key (#8).
				for _, r := range rs {
					fmt.Fprintf(
						a.opts.Stdout,
						"op://%s/%s (%s/%s): %s\n",
						r.VaultID,
						r.ItemID,
						r.Vault,
						r.Item,
						r.PublicKey,
					)
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
// and how many items were skipped because their public key could not be read.
func listRecipients(
	ctx context.Context, client onepassword.Client, logger *log.Logger,
) (rs []recipient, skipped int, err error) {
	items, err := client.ListSSHKeys(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list SSH keys in 1Password: %w", err)
	}
	rs = make([]recipient, 0, len(items))
	for _, it := range items {
		// One read per item: op's bulk `item get -` measured no faster (#6).
		pub, err := client.PublicKey(ctx, it.VaultID, it.ID)
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, fmt.Errorf("list recipients: %w", ctx.Err())
			}
			logger.Warn("skipping item: cannot read public key", "item", it.Title, "vault", it.VaultName, "err", err)
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
