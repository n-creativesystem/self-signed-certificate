package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func rootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssc",
		Short: "自己証明書生成",
		Long:  "自己証明書生成",
	}
	cmd.AddCommand(caCommand())
	cmd.AddCommand(serverCertificateCommand())
	return cmd
}

func Execute() {
	cmd := rootCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
