package cmd

import (
	"github.com/spf13/cobra"
)

func caCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "ca",
		Short: "自己署名CA証明書作成",
		Long:  "自己署名CA証明書作成",
	}
	cmd.AddCommand(newCACommand())
	cmd.AddCommand(updateCACommand())
	return &cmd
}
