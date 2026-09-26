package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/untcha/age-plugin-onepassword/internal/appmeta"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "age-plugin-onepassword %s\n", appmeta.String())
			return err
		},
	}
}
