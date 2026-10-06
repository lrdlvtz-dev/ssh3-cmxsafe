package cmd

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const gatewayTrustBundleVersion = 1

type gatewayTrustManifest struct {
	Version      int                       `json:"version"`
	GatewayID    string                    `json:"gateway_id"`
	ServerName   string                    `json:"server_name"`
	Certificates []gatewayTrustCertificate `json:"certificates"`
}

type gatewayTrustCertificate struct {
	State       string `json:"state"`
	File        string `json:"certificate_file"`
	SHA256      string `json:"sha256"`
	certificate *x509.Certificate
}

// gatewayTrustBundle is the direct, per-gateway trust contract used by
// CMXsafe clients. It deliberately contains no CA roots: the exact active or
// next leaf certificate is the trust anchor.
type gatewayTrustBundle struct {
	GatewayID    string
	ServerName   string
	Certificates []*x509.Certificate
}

func loadGatewayTrustBundle(manifestPath string, now time.Time) (*gatewayTrustBundle, error) {
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read gateway trust manifest: %w", err)
	}
	if len(manifestBytes) > 1<<20 {
		return nil, fmt.Errorf("gateway trust manifest exceeds 1 MiB")
	}

	var manifest gatewayTrustManifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse gateway trust manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("gateway trust manifest must contain exactly one JSON object")
	}
	if manifest.Version != gatewayTrustBundleVersion {
		return nil, fmt.Errorf("unsupported gateway trust manifest version %d", manifest.Version)
	}
	if strings.TrimSpace(manifest.GatewayID) == "" {
		return nil, fmt.Errorf("gateway_id is required")
	}
	if strings.TrimSpace(manifest.ServerName) == "" {
		return nil, fmt.Errorf("server_name is required")
	}
	if len(manifest.Certificates) == 0 || len(manifest.Certificates) > 2 {
		return nil, fmt.Errorf("certificates must contain one active and at most one next certificate")
	}

	baseDir := filepath.Dir(manifestPath)
	seenStates := make(map[string]bool)
	bundle := &gatewayTrustBundle{GatewayID: manifest.GatewayID, ServerName: manifest.ServerName}
	for i := range manifest.Certificates {
		entry := &manifest.Certificates[i]
		if entry.State != "active" && entry.State != "next" {
			return nil, fmt.Errorf("certificate %d has invalid state %q", i, entry.State)
		}
		if seenStates[entry.State] {
			return nil, fmt.Errorf("certificate state %q is duplicated", entry.State)
		}
		seenStates[entry.State] = true
		if entry.File == "" || filepath.IsAbs(entry.File) || filepath.Base(entry.File) != entry.File {
			return nil, fmt.Errorf("certificate %d file must be a plain relative filename", i)
		}

		pemBytes, err := os.ReadFile(filepath.Join(baseDir, entry.File))
		if err != nil {
			return nil, fmt.Errorf("read %s certificate: %w", entry.State, err)
		}
		if len(pemBytes) > 1<<20 {
			return nil, fmt.Errorf("%s certificate exceeds 1 MiB", entry.State)
		}
		block, rest := pem.Decode(pemBytes)
		if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, fmt.Errorf("%s certificate file must contain exactly one PEM certificate", entry.State)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse %s certificate: %w", entry.State, err)
		}
		if err := validatePinnedGatewayCertificate(cert, manifest.ServerName, now); err != nil {
			return nil, fmt.Errorf("validate %s certificate: %w", entry.State, err)
		}
		digest := sha256.Sum256(cert.Raw)
		declaredDigest, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(declaredDigest) != sha256.Size {
			return nil, fmt.Errorf("%s certificate sha256 must be 64 hexadecimal characters", entry.State)
		}
		if !equalBytes(digest[:], declaredDigest) {
			return nil, fmt.Errorf("%s certificate sha256 does not match its DER encoding", entry.State)
		}
		entry.certificate = cert
		bundle.Certificates = append(bundle.Certificates, cert)
	}
	if !seenStates["active"] {
		return nil, fmt.Errorf("an active certificate is required")
	}
	return bundle, nil
}

func validatePinnedGatewayCertificate(cert *x509.Certificate, serverName string, now time.Time) error {
	if cert.IsCA {
		return fmt.Errorf("gateway certificate must be a leaf, not a CA")
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("gateway certificate is not valid at the current time")
	}
	serverAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
			break
		}
	}
	if !serverAuth {
		return fmt.Errorf("gateway certificate must explicitly allow ServerAuth")
	}
	if !hasExactSAN(cert, serverName) {
		return fmt.Errorf("gateway certificate has no exact SAN for %q", serverName)
	}
	return nil
}

func hasExactSAN(cert *x509.Certificate, serverName string) bool {
	if ip := net.ParseIP(serverName); ip != nil {
		for _, candidate := range cert.IPAddresses {
			if candidate.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, candidate := range cert.DNSNames {
		if strings.EqualFold(candidate, serverName) {
			return true
		}
	}
	return false
}

func (bundle *gatewayTrustBundle) tlsConfig(keylog interface{ Write([]byte) (int, error) }) *tls.Config {
	roots := x509.NewCertPool()
	for _, cert := range bundle.Certificates {
		roots.AddCert(cert)
	}
	return &tls.Config{
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
		KeyLogWriter: keylog,
		ServerName:   bundle.ServerName,
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.Version != tls.VersionTLS13 {
				return fmt.Errorf("gateway must negotiate TLS 1.3")
			}
			if len(state.PeerCertificates) != 1 {
				return fmt.Errorf("gateway must present exactly one directly trusted certificate")
			}
			leaf := state.PeerCertificates[0]
			matched := false
			for _, trusted := range bundle.Certificates {
				if equalBytes(leaf.Raw, trusted.Raw) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("gateway certificate is not active or next for %q", bundle.GatewayID)
			}
			return validatePinnedGatewayCertificate(leaf, bundle.ServerName, time.Now())
		},
	}
}

func validateGatewayServerKeyPair(certificate tls.Certificate, serverName string, now time.Time) error {
	if len(certificate.Certificate) == 0 {
		return fmt.Errorf("server key pair contains no certificate")
	}
	if len(certificate.Certificate) != 1 {
		return fmt.Errorf("CMXsafe gateway key pair must contain exactly one leaf certificate")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse server leaf certificate: %w", err)
	}
	if err := validatePinnedGatewayCertificate(leaf, serverName, now); err != nil {
		return err
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}
