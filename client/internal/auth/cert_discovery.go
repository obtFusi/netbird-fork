// Machine Tunnel Fork - Certificate Discovery
// This file provides certificate discovery for machine authentication.
// It supports both Windows Certificate Store and file-based certificates.

package auth

import (
	"crypto"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/tunnel"
)

// CertSource indicates where the certificate was loaded from
type CertSource string

const (
	// CertSourceWindowsStore indicates certificate from Windows Certificate Store
	CertSourceWindowsStore CertSource = "windows-store"
	// CertSourceFile indicates certificate from file system
	CertSourceFile CertSource = "file"
)

// LoadedCertificate represents a loaded certificate with its private key
type LoadedCertificate struct {
	// Certificate is the X.509 certificate
	Certificate *x509.Certificate

	// PrivateKey is the private key (can be crypto.Signer for Windows Store)
	PrivateKey crypto.PrivateKey

	// Source indicates where the certificate was loaded from
	Source CertSource

	// Thumbprint is the SHA-1 thumbprint of the certificate
	Thumbprint string

	// TemplateOID is the AD CS template OID (if present)
	TemplateOID string

	// TemplateName is the AD CS template name (if present)
	TemplateName string

	// Identity is the parsed machine identity from the certificate
	Identity *tunnel.MachineIdentity
}

// CertDiscoveryConfig configures certificate discovery
type CertDiscoveryConfig struct {
	// MachineCert contains the machine certificate configuration
	MachineCert tunnel.MachineCertConfig

	// FallbackCertPath is the path to a PEM certificate file (fallback)
	FallbackCertPath string

	// FallbackKeyPath is the path to a PEM private key file (fallback)
	FallbackKeyPath string

	// Hostname is the expected hostname for SAN matching
	Hostname string
}

// DiscoverCertificate finds the best matching certificate for machine authentication
// It uses the following priority:
// 1. Explicit thumbprint override
// 2. Windows Certificate Store (if enabled and on Windows)
// 3. File-based certificate (fallback)
func DiscoverCertificate(config *CertDiscoveryConfig) (*LoadedCertificate, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	log.WithFields(log.Fields{
		"enabled":     config.MachineCert.Enabled,
		"template":    config.MachineCert.TemplateOID,
		"thumbprint":  config.MachineCert.ThumbprintOverride != "",
		"fallback":    config.FallbackCertPath != "",
	}).Debug("Discovering machine certificate")

	if !config.MachineCert.Enabled {
		return nil, fmt.Errorf("machine certificate not enabled")
	}

	// Priority 1: Explicit thumbprint override (for debugging)
	if config.MachineCert.ThumbprintOverride != "" {
		cert, err := discoverByThumbprint(config)
		if err == nil {
			return cert, nil
		}
		log.WithError(err).Warn("Failed to find certificate by thumbprint")
	}

	// Priority 2: Windows Certificate Store
	cert, err := discoverFromWindowsStore(config)
	if err == nil {
		return cert, nil
	}
	log.WithError(err).Debug("Windows Certificate Store discovery failed")

	// Priority 3: File-based certificate (fallback)
	if config.FallbackCertPath != "" && config.FallbackKeyPath != "" {
		cert, err := discoverFromFile(config)
		if err == nil {
			return cert, nil
		}
		log.WithError(err).Warn("File-based certificate discovery failed")
	}

	return nil, fmt.Errorf("no matching machine certificate found")
}

// discoverByThumbprint finds a certificate by exact thumbprint match
func discoverByThumbprint(config *CertDiscoveryConfig) (*LoadedCertificate, error) {
	// First try Windows Store
	cert, err := findCertByThumbprintFromStore(config.MachineCert.ThumbprintOverride)
	if err == nil {
		return cert, nil
	}

	// Then try file-based
	if config.FallbackCertPath != "" {
		cert, err := loadCertificateFromFile(config.FallbackCertPath, config.FallbackKeyPath)
		if err == nil && cert.Thumbprint == config.MachineCert.ThumbprintOverride {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("certificate with thumbprint %s not found", config.MachineCert.ThumbprintOverride)
}

// discoverFromWindowsStore finds a certificate from Windows Certificate Store
// This is implemented in cert_discovery_windows.go
func discoverFromWindowsStore(config *CertDiscoveryConfig) (*LoadedCertificate, error) {
	return discoverFromWindowsStoreImpl(config)
}

// discoverFromFile loads a certificate from PEM files
func discoverFromFile(config *CertDiscoveryConfig) (*LoadedCertificate, error) {
	cert, err := loadCertificateFromFile(config.FallbackCertPath, config.FallbackKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load certificate from file: %w", err)
	}

	// Validate certificate
	if err := validateCertificate(cert, config); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	return cert, nil
}

// loadCertificateFromFile loads a certificate and key from PEM files
func loadCertificateFromFile(certPath, keyPath string) (*LoadedCertificate, error) {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode key PEM")
	}

	var privateKey crypto.PrivateKey
	privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS1 for RSA keys
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			// Try EC key
			privateKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse private key: %w", err)
			}
		}
	}

	// Calculate thumbprint
	thumbprint := fmt.Sprintf("%x", sha1.Sum(cert.Raw))

	// Parse identity from certificate
	identity, _ := ParseMachineIdentity(cert)

	// Parse template info
	templateInfo, _ := parseTemplateInfo(cert)
	templateOID := ""
	templateName := ""
	if templateInfo != nil {
		templateOID = templateInfo.OID
		templateName = templateInfo.Name
	}

	return &LoadedCertificate{
		Certificate:  cert,
		PrivateKey:   privateKey,
		Source:       CertSourceFile,
		Thumbprint:   thumbprint,
		TemplateOID:  templateOID,
		TemplateName: templateName,
		Identity:     identity,
	}, nil
}

// validateCertificate validates a certificate against the configuration
func validateCertificate(cert *LoadedCertificate, config *CertDiscoveryConfig) error {
	if cert == nil || cert.Certificate == nil {
		return fmt.Errorf("certificate is nil")
	}

	x509Cert := cert.Certificate

	// Check expiry
	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid (notBefore: %v)", x509Cert.NotBefore)
	}
	if now.After(x509Cert.NotAfter) {
		return fmt.Errorf("certificate expired (notAfter: %v)", x509Cert.NotAfter)
	}

	// Check EKU if required
	if config.MachineCert.RequiredEKU != "" {
		if !hasEKU(x509Cert, config.MachineCert.RequiredEKU) {
			return fmt.Errorf("certificate missing required EKU: %s", config.MachineCert.RequiredEKU)
		}
	}

	// Check SAN hostname match if required
	if config.MachineCert.SANMustMatch && config.Hostname != "" {
		if !sanContainsHostname(x509Cert, config.Hostname) {
			return fmt.Errorf("certificate SAN does not contain hostname: %s", config.Hostname)
		}
	}

	// Check template OID if specified
	if config.MachineCert.TemplateOID != "" {
		if cert.TemplateOID != config.MachineCert.TemplateOID {
			return fmt.Errorf("certificate template OID mismatch: got %s, want %s",
				cert.TemplateOID, config.MachineCert.TemplateOID)
		}
	}

	// Check template name if specified
	if config.MachineCert.TemplateName != "" {
		if cert.TemplateName != config.MachineCert.TemplateName {
			return fmt.Errorf("certificate template name mismatch: got %s, want %s",
				cert.TemplateName, config.MachineCert.TemplateName)
		}
	}

	return nil
}

// hasEKU checks if a certificate has a specific Extended Key Usage
func hasEKU(cert *x509.Certificate, ekuOID string) bool {
	// Map common EKU names to OIDs
	ekuMap := map[string]x509.ExtKeyUsage{
		tunnel.DefaultClientAuthEKU: x509.ExtKeyUsageClientAuth,
		"1.3.6.1.5.5.7.3.1":         x509.ExtKeyUsageServerAuth,
	}

	// Check if it's a known EKU
	if expectedEKU, ok := ekuMap[ekuOID]; ok {
		for _, eku := range cert.ExtKeyUsage {
			if eku == expectedEKU {
				return true
			}
		}
		return false
	}

	// Check unknown EKUs in UnknownExtKeyUsage
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.String() == ekuOID {
			return true
		}
	}

	return false
}

// sanContainsHostname checks if certificate SAN contains the hostname
func sanContainsHostname(cert *x509.Certificate, hostname string) bool {
	for _, dnsName := range cert.DNSNames {
		// Check exact match
		if dnsName == hostname {
			return true
		}
		// Check FQDN match (hostname.domain)
		if len(dnsName) > len(hostname)+1 && dnsName[:len(hostname)] == hostname && dnsName[len(hostname)] == '.' {
			return true
		}
	}
	return false
}

// ToTLSCertificate converts LoadedCertificate to tls.Certificate
func (c *LoadedCertificate) ToTLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{c.Certificate.Raw},
		PrivateKey:  c.PrivateKey,
		Leaf:        c.Certificate,
	}
}

// findCertByThumbprintFromStore is implemented in platform-specific files
func findCertByThumbprintFromStore(thumbprint string) (*LoadedCertificate, error) {
	return findCertByThumbprintFromStoreImpl(thumbprint)
}
