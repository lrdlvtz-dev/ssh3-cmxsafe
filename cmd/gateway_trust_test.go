package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeGatewayCertificate(t *testing.T, serverName string, now time.Time, mutate func(*x509.Certificate)) (*x509.Certificate, tls.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: serverName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{serverName},
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyPair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
	return cert, keyPair, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeGatewayTrustBundle(t *testing.T, serverName string, entries []struct {
	state string
	cert  *x509.Certificate
	pem   []byte
}) string {
	t.Helper()
	dir := t.TempDir()
	manifest := gatewayTrustManifest{Version: 1, GatewayID: "gateway-a", ServerName: serverName}
	for _, source := range entries {
		name := source.state + ".pem"
		if err := os.WriteFile(filepath.Join(dir, name), source.pem, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(source.cert.Raw)
		manifest.Certificates = append(manifest.Certificates, gatewayTrustCertificate{
			State:  source.state,
			File:   name,
			SHA256: hex.EncodeToString(digest[:]),
		})
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadGatewayTrustBundleAcceptsActiveAndNext(t *testing.T) {
	now := time.Now()
	active, _, activePEM := makeGatewayCertificate(t, "gateway-a.cmxsafe", now, nil)
	next, _, nextPEM := makeGatewayCertificate(t, "gateway-a.cmxsafe", now, nil)
	path := writeGatewayTrustBundle(t, "gateway-a.cmxsafe", []struct {
		state string
		cert  *x509.Certificate
		pem   []byte
	}{{"active", active, activePEM}, {"next", next, nextPEM}})

	bundle, err := loadGatewayTrustBundle(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.GatewayID != "gateway-a" || len(bundle.Certificates) != 2 {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
	config := bundle.tlsConfig(nil)
	if config.InsecureSkipVerify || config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatal("CMXsafe TLS config must use normal verification and TLS 1.3 only")
	}
	for _, cert := range bundle.Certificates {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: config.RootCAs, DNSName: bundle.ServerName, CurrentTime: now}); err != nil {
			t.Fatalf("pinned certificate does not verify against the private roots: %v", err)
		}
	}
}

func TestGatewayTrustRejectsUnknownCertificate(t *testing.T) {
	now := time.Now()
	active, _, activePEM := makeGatewayCertificate(t, "gateway-a.cmxsafe", now, nil)
	unknown, _, _ := makeGatewayCertificate(t, "gateway-a.cmxsafe", now, nil)
	path := writeGatewayTrustBundle(t, "gateway-a.cmxsafe", []struct {
		state string
		cert  *x509.Certificate
		pem   []byte
	}{{"active", active, activePEM}})
	bundle, err := loadGatewayTrustBundle(path, now)
	if err != nil {
		t.Fatal(err)
	}
	err = bundle.tlsConfig(nil).VerifyConnection(tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{unknown},
	})
	if err == nil {
		t.Fatal("unknown certificate was accepted")
	}
}

func TestGatewayTrustRejectsUnsafeCertificates(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		serverName string
		mutate     func(*x509.Certificate)
	}{
		{"wildcard-san", "gateway-a.cmxsafe", func(c *x509.Certificate) { c.DNSNames = []string{"*.cmxsafe"} }},
		{"wrong-san", "gateway-a.cmxsafe", func(c *x509.Certificate) { c.DNSNames = []string{"gateway-b.cmxsafe"} }},
		{"ca", "gateway-a.cmxsafe", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{"no-server-auth", "gateway-a.cmxsafe", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"expired", "gateway-a.cmxsafe", func(c *x509.Certificate) { c.NotBefore = now.Add(-2 * time.Hour); c.NotAfter = now.Add(-time.Hour) }},
		{"not-yet-valid", "gateway-a.cmxsafe", func(c *x509.Certificate) { c.NotBefore = now.Add(time.Hour); c.NotAfter = now.Add(2 * time.Hour) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert, _, certPEM := makeGatewayCertificate(t, tc.serverName, now, tc.mutate)
			path := writeGatewayTrustBundle(t, tc.serverName, []struct {
				state string
				cert  *x509.Certificate
				pem   []byte
			}{{"active", cert, certPEM}})
			if _, err := loadGatewayTrustBundle(path, now); err == nil {
				t.Fatal("unsafe certificate was accepted")
			}
		})
	}
}

func TestGatewayTrustRejectsMalformedManifest(t *testing.T) {
	now := time.Now()
	cert, _, certPEM := makeGatewayCertificate(t, "gateway-a.cmxsafe", now, nil)
	basePath := writeGatewayTrustBundle(t, "gateway-a.cmxsafe", []struct {
		state string
		cert  *x509.Certificate
		pem   []byte
	}{{"active", cert, certPEM}})
	baseDir := filepath.Dir(basePath)

	tests := map[string]string{
		"unknown-field":  `{"version":1,"gateway_id":"gateway-a","server_name":"gateway-a.cmxsafe","certificates":[],"extra":true}`,
		"missing-active": `{"version":1,"gateway_id":"gateway-a","server_name":"gateway-a.cmxsafe","certificates":[{"state":"next","certificate_file":"active.pem","sha256":"` + hex.EncodeToString(sha256Sum(cert.Raw)) + `"}]}`,
		"path-traversal": `{"version":1,"gateway_id":"gateway-a","server_name":"gateway-a.cmxsafe","certificates":[{"state":"active","certificate_file":"../active.pem","sha256":"` + hex.EncodeToString(sha256Sum(cert.Raw)) + `"}]}`,
		"bad-hash":       `{"version":1,"gateway_id":"gateway-a","server_name":"gateway-a.cmxsafe","certificates":[{"state":"active","certificate_file":"active.pem","sha256":"00"}]}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(baseDir, name+".json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadGatewayTrustBundle(path, now); err == nil {
				t.Fatal("malformed manifest was accepted")
			}
		})
	}
}

func TestValidateGatewayServerKeyPair(t *testing.T) {
	now := time.Now()
	_, pair, _ := makeGatewayCertificate(t, "gateway-a.cmxsafe", now, nil)
	if err := validateGatewayServerKeyPair(pair, "gateway-a.cmxsafe", now); err != nil {
		t.Fatal(err)
	}
	if err := validateGatewayServerKeyPair(pair, "gateway-b.cmxsafe", now); err == nil {
		t.Fatal("server key pair with the wrong logical gateway SAN was accepted")
	}
}

func sha256Sum(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}
