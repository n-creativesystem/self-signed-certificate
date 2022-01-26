package cmd

import (
	"github.com/spf13/cobra"
)

func serverCertificateCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "server",
		Short: "サーバー証明書作成",
		Long:  "サーバー証明書作成",
	}
	cmd.AddCommand(newServerCertificateCommand())
	return &cmd
}
