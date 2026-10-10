package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProvisionDNSCertificate(t *testing.T) {
	now := time.Date(2026, time.October, 10, 15, 30, 45, 123, time.FixedZone("test", 3600))
	dir := t.TempDir()
	certPath := filepath.Join(dir, "gateway.pem")
	keyPath := filepath.Join(dir, "gateway.key")

	generated, err := provision(options{gatewayName: "gateway-a.cmxsafe", certPath: certPath, keyPath: keyPath}, now)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("certificate file is not exactly one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	wantNotBefore := time.Date(2026, time.October, 10, 14, 30, 45, 0, time.UTC)
	wantNotAfter := time.Date(3026, time.October, 10, 14, 30, 45, 0, time.UTC)
	if !cert.NotBefore.Equal(wantNotBefore) || !cert.NotAfter.Equal(wantNotAfter) || !generated.notAfter.Equal(wantNotAfter) {
		t.Fatalf("unexpected validity: %s - %s", cert.NotBefore, cert.NotAfter)
	}
	if cert.IsCA || !cert.BasicConstraintsValid {
		t.Fatal("certificate is not a constrained non-CA leaf")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("unexpected key usage: %v", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("unexpected extended key usage: %v", cert.ExtKeyUsage)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "gateway-a.cmxsafe" || len(cert.IPAddresses) != 0 {
		t.Fatalf("unexpected SANs: DNS=%v IP=%v", cert.DNSNames, cert.IPAddresses)
	}
	if cert.PublicKeyAlgorithm != x509.Ed25519 || cert.SignatureAlgorithm != x509.PureEd25519 {
		t.Fatalf("certificate is not Ed25519: public=%v signature=%v", cert.PublicKeyAlgorithm, cert.SignatureAlgorithm)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("certificate is not self-signed: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		DNSName:     "gateway-a.cmxsafe",
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("certificate does not verify at the current time: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("certificate and private key do not form a valid pair: %v", err)
	}

	assertMode(t, certPath, 0644)
	assertMode(t, keyPath, 0600)
	if len(generated.fingerprint) != 64 {
		t.Fatalf("unexpected SHA-256 fingerprint %q", generated.fingerprint)
	}
	wantFingerprint := sha256.Sum256(cert.Raw)
	if generated.fingerprint != fmt.Sprintf("%x", wantFingerprint) {
		t.Fatalf("reported fingerprint does not match certificate DER")
	}
}

func TestProvisionIPCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "gateway.pem")
	keyPath := filepath.Join(dir, "gateway.key")
	if _, err := provision(options{gatewayName: "2001:db8::10", certPath: certPath, keyPath: keyPath}, time.Now()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(contents)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("unexpected SANs: DNS=%v IP=%v", cert.DNSNames, cert.IPAddresses)
	}
	if err := cert.VerifyHostname("2001:db8::10"); err != nil {
		t.Fatalf("IP SAN does not verify: %v", err)
	}
}

func TestWrongPrivateKeyIsRejected(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "gateway.pem")
	keyPath := filepath.Join(dir, "gateway.key")
	if _, err := provision(options{gatewayName: "gateway-a.cmxsafe", certPath: certPath, keyPath: keyPath}, time.Now()); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(certPath)
	_, wrongKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := x509.MarshalPKCS8PrivateKey(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wrongDER})
	if _, err := tls.X509KeyPair(certPEM, wrongPEM); err == nil {
		t.Fatal("certificate was accepted with the wrong private key")
	}
}

func TestProvisionDoesNotOverwrite(t *testing.T) {
	for _, existing := range []string{"cert", "key"} {
		t.Run(existing, func(t *testing.T) {
			dir := t.TempDir()
			certPath := filepath.Join(dir, "gateway.pem")
			keyPath := filepath.Join(dir, "gateway.key")
			path := certPath
			if existing == "key" {
				path = keyPath
			}
			if err := os.WriteFile(path, []byte("keep-me"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := provision(options{gatewayName: "gateway-a.cmxsafe", certPath: certPath, keyPath: keyPath}, time.Now()); err == nil {
				t.Fatal("provision unexpectedly overwrote an existing destination")
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(contents) != "keep-me" {
				t.Fatalf("existing %s was modified", existing)
			}
			if existing == "cert" {
				if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
					t.Fatalf("new private key was not rolled back: %v", err)
				}
			}
		})
	}
}

func TestInvalidGatewayNames(t *testing.T) {
	for _, name := range []string{"", " ", "*.cmxsafe", "gateway a.cmxsafe", "gateway\ta.cmxsafe", "gateway\u00a0a.cmxsafe", "-gateway.cmxsafe", "gateway_.cmxsafe"} {
		t.Run(strings.ReplaceAll(name, " ", "_"), func(t *testing.T) {
			if err := validateGatewayName(name); err == nil {
				t.Fatalf("gateway name %q was accepted", name)
			}
		})
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode is %04o, want %04o", path, got, want)
	}
}
