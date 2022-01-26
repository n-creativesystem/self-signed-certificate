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

func newCACommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "new",
		Short: "自己署名CA証明書作成(key, cert)",
		Long:  `certファイルとkeyファイルのセットで自己署名CA証明書を作成します`,
		PreRun: func(cmd *cobra.Command, args []string) {
			initialize(cmd, "ca_config")
		},
		Run: func(cmd *cobra.Command, args []string) {
			var caArg caArgs
			caArg.serialNumber = viper.GetInt("serialNumber")
			caArg.keyLength = viper.GetInt("bits")
			caArg.days = viper.GetInt("days")
			caArg.country = viper.GetStringSlice("country")
			caArg.commonName = viper.GetString("commonName")
			caArg.organization = viper.GetStringSlice("organization")
			caArg.organizationUnit = viper.GetStringSlice("organizationUnit")
			certFilename := viper.GetString("cert")
			keyFilename := viper.GetString("key")
			caArg.certFile = &bytes.Buffer{}
			caArg.keyFile = &bytes.Buffer{}
			if err := certificateRun(caArg); err != nil {
				errorExit(err)
			}
			fileCreate(certFilename, caArg.certFile)
			fileCreate(keyFilename, caArg.keyFile)
		},
	}
	flags := cmd.Flags()
	flags.Int("serialNumber", 1, "serial number")
	flags.Int("bits", 2048, "key length")
	flags.StringSlice("country", []string{"JP"}, "country")
	flags.StringSlice("organization", nil, "organization")
	flags.StringSlice("organizationUnit", nil, "organization unit")
	flags.String("commonName", "", "common name")
	flags.String("cert", "ca.crt", "ca cert file name")
	flags.String("key", "ca.key", "ca private key file name")
	flags.Int("days", 365, "days")
	return &cmd
}

type caArgs struct {
	serialNumber     int
	keyLength        int
	country          []string
	organization     []string
	organizationUnit []string
	commonName       string
	certFile         readWrite
	keyFile          readWrite
	days             int
}

func certificateRun(args caArgs) error {
	privateCaKey, err := rsa.GenerateKey(rand.Reader, args.keyLength)
	if err != nil {
		return err
	}
	publicCaKey := privateCaKey.Public()

	subjectCa := pkix.Name{
		CommonName:         args.commonName,
		Organization:       args.organization,
		OrganizationalUnit: args.organizationUnit,
		Country:            args.country,
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(args.serialNumber)),
		Subject:               subjectCa,
		IsCA:                  true,
		NotAfter:              time.Now().Add(time.Hour * 24 * time.Duration(args.days)),
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caCertificate, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, publicCaKey, privateCaKey)
	if err != nil {
		return err
	}
	err = pem.Encode(args.certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertificate,
	})
	if err != nil {
		return err
	}
	derCaPrivateKey := x509.MarshalPKCS1PrivateKey(privateCaKey)
	err = pem.Encode(args.keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derCaPrivateKey})
	if err != nil {
		return err
	}
	return nil
}
