package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func updateCACommand() *cobra.Command {
	initialize := initialize("ca_config")
	cmd := cobra.Command{
		Use:   "update",
		Short: "自己署名CA証明書serial numberの更新",
		Long:  `certファイルのserial numberをインクリメントしてファイルの更新を行います。`,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			config, err := cmd.Flags().GetString("config")
			if err != nil {
				errorExit(err)
			}
			initialize(cmd, config)
			var caArg caUpdateArgs
			certFilename := viper.GetString("cert")
			keyFilename := viper.GetString("key")
			caArg.days = viper.GetInt("days")
			caArg.cert, caArg.key, err = readCERTandKEY(certFilename, keyFilename)
			if err != nil {
				errorExit(err)
			}
			caArg.certFile = &bytes.Buffer{}
			caArg.keyFile = &bytes.Buffer{}
			if err := runCAUpdate(caArg, args); err != nil {
				errorExit(err)
			}
			fileCreate(certFilename, caArg.certFile)
			fileCreate(keyFilename, caArg.keyFile)
		},
	}
	flags := cmd.Flags()
	flags.String("config", "", "CA configuration")
	flags.String("cert", "ca.crt", "ca cert file name")
	flags.String("key", "ca.key", "ca private key file name")
	return &cmd
}

type caUpdateArgs struct {
	cert []byte
	key  *rsa.PrivateKey

	days int

	certFile readWrite
	keyFile  readWrite
}

func runCAUpdate(caArgs caUpdateArgs, args []string) error {
	p, _ := pem.Decode(caArgs.cert)
	caCert := append([]byte{}, p.Bytes...)
	caTpl, err := x509.ParseCertificate(caCert)
	if err != nil {
		return err
	}
	public := caArgs.key.Public()
	for _, arg := range args {
		switch arg {
		case "serial":
			updateSerialNumber(caTpl)
		case "after":
			caTpl.NotAfter.Add(time.Hour * 24 * time.Duration(caArgs.days))
		}
	}
	caCertificate, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, public, caArgs.key)
	if err != nil {
		return err
	}
	err = pem.Encode(caArgs.certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertificate,
	})
	if err != nil {
		return err
	}
	derCaPrivateKey := x509.MarshalPKCS1PrivateKey(caArgs.key)
	err = pem.Encode(caArgs.keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derCaPrivateKey})
	if err != nil {
		return err
	}
	return nil
}

func updateSerialNumber(caTpl *x509.Certificate) {
	serialNumber := caTpl.SerialNumber.Int64()
	serialNumber++
	caTpl.SerialNumber.SetInt64(serialNumber)
}
