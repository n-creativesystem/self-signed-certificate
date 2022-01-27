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

type caArgs struct {
	serialNumber     int
	bits             int
	country          []string
	organization     []string
	organizationUnit []string
	commonName       string
	certFile         readWrite
	keyFile          readWrite
	days             int
}
