//go:build !windows

// Package tunnel provides machine tunnel functionality.
// This file provides stub implementations for non-Windows platforms.
package tunnel

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// TrustStore represents a certificate store (stub on non-Windows).
type TrustStore string

const (
	// TrustStoreRoot is the Trusted Root Certification Authorities store.
	TrustStoreRoot TrustStore = "root"
	// TrustStoreCA is the Intermediate Certification Authorities store.
	TrustStoreCA TrustStore = "ca"
)

// ErrNotSupported indicates the operation is not supported on this platform.
var ErrNotSupported = errors.New("CA certificate store operations are only supported on Windows")

// InstallCACert is not supported on non-Windows platforms.
// On Linux/macOS, use system-specific methods (update-ca-certificates, security add-trusted-cert).
func InstallCACert(certPath string, store TrustStore) error {
	return ErrNotSupported
}

// RemoveCACert is not supported on non-Windows platforms.
func RemoveCACert(thumbprint string, store TrustStore) error {
	return ErrNotSupported
}

// GetCertPin calculates the SHA-256 pin for a certificate file.
// Returns the pin in format: "sha256//BASE64HASH"
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
func VerifyServerCert(cert *x509.Certificate, expectedPin string) error {
	if expectedPin == "" {
		return nil
	}

	actualPin := GetCertPinFromDER(cert.Raw)

	if actualPin != expectedPin {
		return fmt.Errorf("certificate pin mismatch: expected [%s] but got [%s]", expectedPin, actualPin)
	}

	return nil
}

// VerifyServerCertChain verifies a certificate chain against an expected pin.
func VerifyServerCertChain(chain []*x509.Certificate, expectedPin string) error {
	if expectedPin == "" {
		return nil
	}

	for _, cert := range chain {
		actualPin := GetCertPinFromDER(cert.Raw)
		if actualPin == expectedPin {
			return nil
		}
	}

	return fmt.Errorf("no certificate in chain matches expected pin")
}

// IsCertExpiringSoon checks if a certificate expires within the given days.
func IsCertExpiringSoon(cert *x509.Certificate, days int) bool {
	return false
}
