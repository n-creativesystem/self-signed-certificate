package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func serverCSRCommand() *cobra.Command {
	initialize := initialize("server_config")
	cmd := cobra.Command{
		Use:   "csr",
		Short: "サーバー証明書作成(cert,key)",
		Long:  "証明書要求(CSR)からcertファイルとkeyファイルのセットでサーバー証明書を作成します",
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			config, err := cmd.Flags().GetString("config")
			if err != nil {
				errorExit(err)
			}
			initialize(cmd, config)
			var srvArg serverArgs = parseServerArgs()
			certFilename := viper.GetString("cert")
			srvArg.cert = &bytes.Buffer{}
			if err := runServerCSR(srvArg); err != nil {
				errorExit(err)
			}
			fileCreate(certFilename, srvArg.cert)
		},
	}

	flags := cmd.Flags()
	flags.String("config", "", "server configuration")
	flags.Int("serialNumber", 1, "serial number")
	flags.Int("bits", 2048, "rsa bits")
	flags.Int("days", 365, "days")
	flags.StringSlice("dnsNames", nil, "subject alternate name dns names")
	flags.StringSlice("ipAddresses", nil, "subject alternate name ip addresses")
	flags.StringSlice("emailAddresses", nil, "subject alternate name email addresses")
	flags.StringSlice("urls", nil, "subject alternate name urls")
	flags.String("caCert", "ca.crt", "ca cert file name")
	flags.String("caKey", "ca.key", "ca private key file name")
	flags.String("csr", "server.csr", "server certificate request file name")
	flags.String("cert", "server.crt", "server cert file name")
	flags.String("key", "server.key", "server private key file name")
	return &cmd
}

func runServerCSR(args serverArgs) error {
	p, _ := pem.Decode(args.caCert)
	caCert := append([]byte{}, p.Bytes...)
	caTpl, err := x509.ParseCertificate(caCert)
	if err != nil {
		return err
	}
	csr, err := readCSRFile(args.csrFilename)
	if err != nil {
		return err
	}
	if err := csr.CheckSignature(); err != nil {
		return err
	}
	sslTpl := x509.Certificate{
		SerialNumber: big.NewInt(int64(args.serialNumber)),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * time.Duration(args.days)),

		KeyUsage:           x509.KeyUsageDigitalSignature,
		Version:            csr.Version,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		Subject:            csr.Subject,
		Extensions:         csr.Extensions,
		ExtraExtensions:    csr.ExtraExtensions,

		DNSNames:    args.dnsNames,
		IPAddresses: args.ipAddresses,

		EmailAddresses: args.emails,
		URIs:           args.urls,
	}

	derCertificate, err := x509.CreateCertificate(rand.Reader, &sslTpl, caTpl, csr.PublicKey, args.caKey)
	if err != nil {
		return err
	}
	err = pem.Encode(args.cert, &pem.Block{Type: "CERTIFICATE", Bytes: derCertificate})
	if err != nil {
		return err
	}
	return nil
}

func readCSRFile(filename string) (*x509.CertificateRequest, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readCSR(file)
}

func readCSR(reader io.Reader) (*x509.CertificateRequest, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	raw := bytes
	var p *pem.Block
	rest := bytes
	for {
		p, rest = pem.Decode(rest)
		if p == nil {
			break
		}
		if p.Type == "CERTIFICATE REQUEST" {
			raw = p.Bytes
		}
	}
	return x509.ParseCertificateRequest(raw)
}
