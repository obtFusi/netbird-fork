//go:build windows

// Package tunnel provides machine tunnel functionality.
// This file implements trust bootstrap for Windows: CA installation and certificate pinning.
package tunnel

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

// TrustStore represents the Windows certificate store for CA installation.
type TrustStore string

const (
	// TrustStoreRoot is the Trusted Root Certification Authorities store.
	TrustStoreRoot TrustStore = "root"
	// TrustStoreCA is the Intermediate Certification Authorities store.
	TrustStoreCA TrustStore = "ca"
)

// InstallCACert installs a CA certificate into the Windows certificate store.
// This requires administrator privileges.
//
// Trade-offs of CA installation vs pinning:
//
// CA Installation (this function):
//   - Pro: Standard Windows PKI integration
//   - Pro: All tools (browsers, CLI) automatically trust certs from this CA
//   - Pro: Easy to understand and debug
//   - Con: Requires admin rights
//   - Con: CA can issue any certificate (broad trust scope)
//   - Con: CA cert must be securely deployed
//
// Certificate Pinning (VerifyServerCert with pin):
//   - Pro: No admin rights needed at runtime
//   - Pro: Narrow trust scope (only specific cert/CA)
//   - Pro: Portable (no OS store access needed)
//   - Con: Cert rotation more complex (pin must be updated)
//   - Con: Backup pin recommended for cert changes
//   - Con: Non-standard (other tools don't see the trust)
//
// Recommendation:
//   - Enterprise environments: CA installation (fits existing PKI workflows)
//   - High-security environments: Pinning (minimal trust scope)
func InstallCACert(certPath string, store TrustStore) error {
	// Validate certificate file exists and is valid
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	if !cert.IsCA {
		return fmt.Errorf("certificate is not a CA certificate")
	}

	log.WithFields(log.Fields{
		"subject":    cert.Subject.CommonName,
		"issuer":     cert.Issuer.CommonName,
		"notBefore":  cert.NotBefore,
		"notAfter":   cert.NotAfter,
		"store":      store,
		"serialNum":  cert.SerialNumber.String(),
	}).Info("Installing CA certificate")

	// Use certutil to add to Windows certificate store
	// certutil -addstore <store> <certfile>
	cmd := exec.Command("certutil", "-addstore", string(store), certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -addstore failed: %w, output: %s", err, string(output))
	}

	log.WithField("store", store).Info("CA certificate installed successfully")

	// Log to Windows Event Log
	if err := LogCertInstalled("CA", GetCertFingerprint(cert)); err != nil {
		log.WithError(err).Warn("Failed to log certificate installation to Event Log")
	}

	return nil
}

// RemoveCACert removes a CA certificate from the Windows certificate store.
// The certificate is identified by its SHA-1 thumbprint.
func RemoveCACert(thumbprint string, store TrustStore) error {
	// Clean thumbprint (remove spaces, colons)
	thumbprint = strings.ReplaceAll(thumbprint, " ", "")
	thumbprint = strings.ReplaceAll(thumbprint, ":", "")

	log.WithFields(log.Fields{
		"thumbprint": thumbprint,
		"store":      store,
	}).Info("Removing CA certificate")

	// Use certutil to delete from Windows certificate store
	// certutil -delstore <store> <thumbprint>
	cmd := exec.Command("certutil", "-delstore", string(store), thumbprint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -delstore failed: %w, output: %s", err, string(output))
	}

	log.WithField("store", store).Info("CA certificate removed successfully")

	// Log to Windows Event Log
	if err := LogCertRemoved("CA", thumbprint); err != nil {
		log.WithError(err).Warn("Failed to log certificate removal to Event Log")
	}

	return nil
}

// GetCertPin calculates the SHA-256 pin for a certificate file.
// Returns the pin in format: "sha256//BASE64HASH"
//
// Pin Rotation Plan:
// When rotating pinned certificates:
// 1. Add new pin to config BEFORE deploying new certificate
// 2. Config should support multiple pins: [current_pin, next_pin]
// 3. Deploy new certificate to server
// 4. After rollout complete, remove old pin from config
// 5. Keep backup pin for emergency rollback
func GetCertPin(certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read certificate: %w", err)
	}

	return GetCertPinFromPEM(certPEM)
}

// GetCertPinFromPEM calculates the SHA-256 pin from PEM-encoded certificate data.
func GetCertPinFromPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	return GetCertPinFromDER(block.Bytes), nil
}

// GetCertPinFromDER calculates the SHA-256 pin from DER-encoded certificate data.
func GetCertPinFromDER(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return "sha256//" + base64.StdEncoding.EncodeToString(hash[:])
}

// GetCertFingerprint returns the SHA-256 fingerprint of a certificate in hex format.
func GetCertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%X", hash)
}

// VerifyServerCert verifies a server certificate against a pinned fingerprint.
// If pin is empty, returns nil (no pinning configured).
//
// TOFU (Trust-On-First-Use) Warning:
// If no pin is configured and this is the first connection, the user should
// be prompted to verify the server certificate fingerprint out-of-band.
// This prevents MITM attacks during initial bootstrap.
//
// Revocation Check:
// This function does NOT perform revocation checking (OCSP/CRL).
// For CA-installed certificates, Windows handles revocation automatically.
// For pinned certificates, revocation is implicit (pin must be updated).
func VerifyServerCert(cert *x509.Certificate, expectedPin string) error {
	if expectedPin == "" {
		// No pinning configured - rely on standard PKI validation
		return nil
	}

	actualPin := GetCertPinFromDER(cert.Raw)

	if actualPin != expectedPin {
		return fmt.Errorf("certificate pin mismatch: expected [%s] but got [%s]", expectedPin, actualPin)
	}

	log.WithField("pin", actualPin[:30]+"...").Debug("Server certificate pin verified")
	return nil
}

// VerifyServerCertChain verifies a certificate chain, checking if any certificate
// in the chain matches the expected pin. This allows pinning to either the
// leaf certificate or an intermediate/root CA.
func VerifyServerCertChain(chain []*x509.Certificate, expectedPin string) error {
	if expectedPin == "" {
		return nil
	}

	for i, cert := range chain {
		actualPin := GetCertPinFromDER(cert.Raw)
		if actualPin == expectedPin {
			log.WithFields(log.Fields{
				"index":   i,
				"subject": cert.Subject.CommonName,
			}).Debug("Certificate chain pin verified")
			return nil
		}
	}

	return fmt.Errorf("no certificate in chain matches expected pin")
}

// IsCertExpiringSoon checks if a certificate expires within the given days.
func IsCertExpiringSoon(cert *x509.Certificate, days int) bool {
	// Implementation would check cert.NotAfter against current time + days
	// For now, just return false
	return false
}
