package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newServerCertificateCommand() *cobra.Command {
	initialize := initialize("server_config")
	cmd := cobra.Command{
		Use:   "new",
		Short: "サーバー証明書作成(cert,key)",
		Long:  "certファイルとkeyファイルのセットでサーバー証明書を作成します",
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			config, err := cmd.Flags().GetString("config")
			if err != nil {
				errorExit(err)
			}
			initialize(cmd, config)
			var srvArg serverArgs = parseServerArgs()
			certFilename := viper.GetString("cert")
			keyFilename := viper.GetString("key")
			srvArg.cert = &bytes.Buffer{}
			srvArg.key = &bytes.Buffer{}

			if err := runServerCertificate(srvArg); err != nil {
				errorExit(err)
			}
			fileCreate(certFilename, srvArg.cert)
			fileCreate(keyFilename, srvArg.key)
		},
	}

	flags := cmd.Flags()
	flags.String("config", "", "server configuration")
	flags.Int("serialNumber", 1, "serial number")
	flags.Int("bits", 2048, "rsa bits")
	flags.StringSlice("country", []string{"JP"}, "country")
	flags.StringSlice("organization", nil, "organization")
	flags.StringSlice("organizationUnit", nil, "organization unit")
	flags.String("commonName", "", "common name")
	flags.Int("days", 365, "days")
	flags.StringSlice("dnsNames", nil, "subject alternate name dns names")
	flags.StringSlice("ipAddresses", nil, "subject alternate name ip addresses")
	flags.StringSlice("emailAddresses", nil, "subject alternate name email addresses")
	flags.StringSlice("urls", nil, "subject alternate name urls")
	flags.String("caCert", "ca.crt", "ca cert file name")
	flags.String("caKey", "ca.key", "ca private key file name")
	flags.String("cert", "server.crt", "server cert file name")
	flags.String("key", "server.key", "server private key file name")
	return &cmd
}

func runServerCertificate(args serverArgs) error {
	p, _ := pem.Decode(args.caCert)
	caCert := append([]byte{}, p.Bytes...)
	caTpl, err := x509.ParseCertificate(caCert)
	if err != nil {
		return err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, args.bits)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public()

	subject := pkix.Name{
		CommonName:         args.commonName,
		Organization:       args.organization,
		OrganizationalUnit: args.organizationUnit,
		Country:            args.country,
	}

	sslTpl := x509.Certificate{
		SerialNumber:   big.NewInt(int64(args.serialNumber)),
		Subject:        subject,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour * 24 * time.Duration(args.days)),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       args.dnsNames,
		IPAddresses:    args.ipAddresses,
		EmailAddresses: args.emails,
		URIs:           args.urls,
	}

	derCertificate, err := x509.CreateCertificate(rand.Reader, &sslTpl, caTpl, publicKey, args.caKey)
	if err != nil {
		return err
	}
	err = pem.Encode(args.cert, &pem.Block{Type: "CERTIFICATE", Bytes: derCertificate})
	if err != nil {
		return err
	}

	derPrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(args.key, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derPrivateKey})
	if err != nil {
		return err
	}
	return nil
}
