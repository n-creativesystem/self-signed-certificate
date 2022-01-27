package cmd

import (
	"crypto/rsa"
	"net"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func serverCertificateCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "server",
		Short: "サーバー証明書作成",
		Long:  "サーバー証明書作成",
	}
	cmd.AddCommand(newServerCertificateCommand())
	cmd.AddCommand(serverCSRCommand())
	return &cmd
}

type serverArgs struct {
	serialNumber     int
	bits             int
	country          []string
	organization     []string
	organizationUnit []string
	commonName       string
	days             int
	dnsNames         []string
	ipAddresses      []net.IP
	emails           []string
	urls             []*url.URL
	caCert           []byte
	caKey            *rsa.PrivateKey
	csrFilename      string
	cert             readWrite
	key              readWrite
}

func parseServerArgs() serverArgs {
	var err error
	var srvArg serverArgs
	srvArg.serialNumber = viper.GetInt("serialNumber")
	srvArg.bits = viper.GetInt("bits")
	srvArg.days = viper.GetInt("days")
	srvArg.country = viper.GetStringSlice("country")
	srvArg.organization = viper.GetStringSlice("organization")
	srvArg.organizationUnit = viper.GetStringSlice("organizationUnit")
	srvArg.commonName = viper.GetString("commonName")
	srvArg.dnsNames = viper.GetStringSlice("dnsNames")
	srvArg.emails = viper.GetStringSlice("emailAddresses")
	ipAddresses := viper.GetStringSlice("ipAddresses")
	srvArg.ipAddresses = make([]net.IP, 0, len(ipAddresses))
	for _, strIP := range ipAddresses {
		srvArg.ipAddresses = append(srvArg.ipAddresses, net.ParseIP(strIP))
	}
	urls := viper.GetStringSlice("urls")
	srvArg.urls = make([]*url.URL, 0, len(urls))
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			errorExit(err)
		}
		srvArg.urls = append(srvArg.urls, u)
	}
	srvArg.caCert, srvArg.caKey, err = readCERTandKEY(viper.GetString("caCert"), viper.GetString("caKey"))
	if err != nil {
		errorExit(err)
	}
	srvArg.csrFilename = viper.GetString("csr")

	return srvArg

}
