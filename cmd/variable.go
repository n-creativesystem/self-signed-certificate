package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type readWrite interface {
	io.Reader
	io.Writer
}

func fileCreate(filename string, reader io.Reader) {
	if f, err := os.Create(filename); err != nil {
		errorExit(err)
	} else {
		if _, err := io.Copy(f, reader); err != nil {
			errorExit(err)
		}
		if err := f.Close(); err != nil {
			errorExit(err)
		}
	}
}

func errorExit(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}

func (flags *flags) mustString(key string) string {
	v, err := flags.GetString(key)
	if err != nil {
		panic(err)
	}
	return v
}

func (flags *flags) mustStrings(key string) []string {
	v, err := flags.GetStringSlice(key)
	if err != nil {
		panic(err)
	}
	return v
}

func (flags *flags) mustInt(key string) int {
	v, err := flags.GetInt(key)
	if err != nil {
		panic(err)
	}
	return v
}

type flags struct {
	*pflag.FlagSet
}

var (
	configFile string
	envPrefix  = "SELF_CERT"
)

func initialize(cmd *cobra.Command, configFile string) {
	home, err := os.UserHomeDir()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	viper.AddConfigPath(path.Join("/etc", "self_certificate"))
	viper.AddConfigPath(".")
	viper.AddConfigPath(path.Join(home, "self_certificate"))
	viper.SetConfigName(configFile)

	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			// config file does not found in search path
		default:
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	bindFlags(cmd, viper.GetViper())
}

func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			v.BindEnv(f.Name, fmt.Sprintf("%s_%s", envPrefix, envVarSuffix))
		}
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
		}
	})
}

func toSnakeCase(s string) string {
	if s == "" {
		return s
	}
	if len(s) == 1 {
		return strings.ToLower(s)
	}
	source := []rune(s)
	dist := strings.Builder{}
	dist.Grow(len(s) + len(s)/3) // avoid reallocation memory, 33% ~ 50% is recommended
	skipNext := false
	for i := 0; i < len(source); i++ {
		cur := source[i]
		switch cur {
		case '-', '_':
			dist.WriteRune('_')
			skipNext = true
			continue
		}
		if unicode.IsLower(cur) || unicode.IsDigit(cur) {
			dist.WriteRune(cur)
			continue
		}

		if i == 0 {
			dist.WriteRune(unicode.ToLower(cur))
			continue
		}

		last := source[i-1]
		if (!unicode.IsLetter(last)) || unicode.IsLower(last) {
			if skipNext {
				skipNext = false
			} else {
				dist.WriteRune('_')
			}
			dist.WriteRune(unicode.ToLower(cur))
			continue
		}
		// last is upper case
		if i < len(source)-1 {
			next := source[i+1]
			if unicode.IsLower(next) {
				if skipNext {
					skipNext = false
				} else {
					dist.WriteRune('_')
				}
				dist.WriteRune(unicode.ToLower(cur))
				continue
			}
		}
		dist.WriteRune(unicode.ToLower(cur))
	}

	return dist.String()
}

func readCERTandKEY(certFile, keyFile string) ([]byte, *rsa.PrivateKey, error) {
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	buf, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, nil, errors.New("invalid CA private key data")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
	case "PRIVATE KEY":
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("not RSA private key is ca.key")
		}
	default:
		return nil, nil, fmt.Errorf("invalid private key type %s is ca.key", block.Type)
	}
	return cert, key, nil
}
