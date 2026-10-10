// ssh3-cmxsafe-cert provisions a long-lived certificate for a CMXsafe gateway.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const certificateLifetimeYears = 1000

type options struct {
	gatewayName string
	certPath    string
	keyPath     string
}

type result struct {
	fingerprint string
	notAfter    time.Time
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}

func run(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	flags := flag.NewFlagSet("ssh3-cmxsafe-cert", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var opts options
	flags.StringVar(&opts.gatewayName, "gateway-name", "", "exact DNS name or IP address of the CMXsafe gateway")
	flags.StringVar(&opts.certPath, "cert", "", "destination PEM certificate file")
	flags.StringVar(&opts.keyPath, "key", "", "destination PEM private-key file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}

	generated, err := provision(opts, now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "provision CMXsafe gateway certificate: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "sha256_der=%s\nnot_after=%s\n", generated.fingerprint, generated.notAfter.Format(time.RFC3339))
	return 0
}

func provision(opts options, now time.Time) (result, error) {
	if err := validateGatewayName(opts.gatewayName); err != nil {
		return result{}, err
	}
	if strings.TrimSpace(opts.certPath) == "" {
		return result{}, errors.New("-cert is required")
	}
	if strings.TrimSpace(opts.keyPath) == "" {
		return result{}, errors.New("-key is required")
	}
	certAbs, err := filepath.Abs(opts.certPath)
	if err != nil {
		return result{}, fmt.Errorf("resolve certificate path: %w", err)
	}
	keyAbs, err := filepath.Abs(opts.keyPath)
	if err != nil {
		return result{}, fmt.Errorf("resolve private-key path: %w", err)
	}
	if certAbs == keyAbs {
		return result{}, errors.New("certificate and private-key destinations must differ")
	}

	notBefore := now.UTC().Truncate(time.Second)
	notAfter := notBefore.AddDate(certificateLifetimeYears, 0, 0)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return result{}, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return result{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip := net.ParseIP(opts.gatewayName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{opts.gatewayName}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return result{}, fmt.Errorf("create certificate: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return result{}, fmt.Errorf("marshal private key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	if err := writeExclusive(opts.keyPath, keyPEM, 0600); err != nil {
		return result{}, fmt.Errorf("write private key: %w", err)
	}
	if err := writeExclusive(opts.certPath, certPEM, 0644); err != nil {
		if removeErr := os.Remove(opts.keyPath); removeErr != nil {
			return result{}, fmt.Errorf("write certificate: %w (also failed to remove newly created private key: %v)", err, removeErr)
		}
		return result{}, fmt.Errorf("write certificate: %w", err)
	}

	digest := sha256.Sum256(der)
	return result{fingerprint: hex.EncodeToString(digest[:]), notAfter: notAfter}, nil
}

func writeExclusive(path string, contents []byte, mode os.FileMode) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("remove incomplete file: %w", removeErr))
			}
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	written, err := file.Write(contents)
	if err != nil {
		return err
	}
	if written != len(contents) {
		return io.ErrShortWrite
	}
	return file.Sync()
}

func validateGatewayName(name string) error {
	if name == "" {
		return errors.New("-gateway-name is required")
	}
	if strings.Contains(name, "*") || strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return errors.New("gateway name must not contain wildcards or whitespace")
	}
	if net.ParseIP(name) != nil {
		return nil
	}
	if len(name) > 253 || strings.HasSuffix(name, ".") {
		return fmt.Errorf("gateway name %q is not a valid DNS name or IP address", name)
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("gateway name %q is not a valid DNS name or IP address", name)
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return fmt.Errorf("gateway name %q is not a valid DNS name or IP address", name)
			}
		}
	}
	return nil
}
