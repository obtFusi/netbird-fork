// Machine Tunnel Fork - Windows Certificate Store Signer
// This file provides mTLS authentication using certificates from Windows Certificate Store.

//go:build windows

package auth

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/netbirdio/netbird/client/internal/tunnel"
)

// WinCertSigner implements crypto.Signer using a certificate from Windows Certificate Store
// This is used for mTLS authentication without exporting the private key.
type WinCertSigner struct {
	// cert is the X.509 certificate
	cert *x509.Certificate

	// identity contains the parsed machine identity
	identity *tunnel.MachineIdentity

	// handle is the NCrypt key handle (from CNG)
	// Note: Actual NCrypt implementation requires CGO - see Spike 1 results
	// For pure-Go fallback, we use file-based certificates
	handle uintptr
}

// CertSelectionCriteria defines how to select a machine certificate
type CertSelectionCriteria struct {
	// TemplateOID matches AD CS template OID (1.3.6.1.4.1.311.21.7)
	TemplateOID string

	// TemplateName matches AD CS template name
	TemplateName string

	// RequiredEKU matches Extended Key Usage OID
	RequiredEKU string

	// SANMustContain requires SAN DNSName to contain this string
	SANMustContain string

	// ThumbprintExact matches an exact certificate thumbprint (SHA-1)
	ThumbprintExact string
}

// FindMachineCertificate searches Windows Certificate Store for a matching machine certificate
// Store: LocalMachine\My (Personal certificates)
//
// Selection priority:
// 1. ThumbprintExact match (if specified)
// 2. TemplateOID match
// 3. TemplateName match
// 4. EKU = Client Authentication + SAN contains hostname
// 5. Newest valid certificate with Client Authentication EKU
func FindMachineCertificate(criteria CertSelectionCriteria) (*WinCertSigner, error) {
	// TODO: Implement in T-4.2 using NCrypt/CNG APIs
	// This requires CGO for actual Windows implementation
	//
	// Key APIs needed:
	// - CertOpenStore (CERT_STORE_PROV_SYSTEM)
	// - CertFindCertificateInStore
	// - CertGetCertificateContextProperty (for template info)
	// - NCryptOpenStorageProvider
	// - NCryptOpenKey
	//
	// Pure-Go fallback uses file-based certificates (ClientCertPath/ClientCertKeyPath)

	return nil, fmt.Errorf("FindMachineCertificate not yet implemented - requires T-4.2")
}

// Certificate returns the X.509 certificate
func (s *WinCertSigner) Certificate() *x509.Certificate {
	return s.cert
}

// Identity returns the parsed machine identity from the certificate
func (s *WinCertSigner) Identity() *tunnel.MachineIdentity {
	return s.identity
}

// Public returns the public key from the certificate
func (s *WinCertSigner) Public() crypto.PublicKey {
	if s.cert == nil {
		return nil
	}
	return s.cert.PublicKey
}

// Sign signs digest using the Windows CNG private key
// This is the crypto.Signer interface implementation
func (s *WinCertSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// TODO: Implement in T-4.2 using NCrypt APIs
	// - NCryptSignHash for actual signing
	// - Handle RSA-PSS vs PKCS#1 v1.5 based on opts
	// - Handle ECDSA with proper curve handling

	return nil, fmt.Errorf("Sign not yet implemented - requires T-4.2 NCrypt integration")
}

// Close releases the NCrypt handles
func (s *WinCertSigner) Close() error {
	// TODO: Implement in T-4.2
	// - NCryptFreeObject(s.handle)
	return nil
}

// ParseMachineIdentity extracts machine identity from a certificate's SAN DNSName
func ParseMachineIdentity(cert *x509.Certificate) (*tunnel.MachineIdentity, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	// Find first SAN DNSName that looks like hostname.domain
	for _, dnsName := range cert.DNSNames {
		hostname, domain, ok := splitFQDN(dnsName)
		if ok {
			return &tunnel.MachineIdentity{
				Hostname:       hostname,
				Domain:         domain,
				FQDN:           dnsName,
				CertThumbprint: fmt.Sprintf("%x", cert.Raw), // Placeholder - should be SHA-1
			}, nil
		}
	}

	return nil, fmt.Errorf("no valid SAN DNSName found in certificate")
}

// splitFQDN splits "hostname.domain.tld" into ("hostname", "domain.tld")
func splitFQDN(fqdn string) (hostname, domain string, ok bool) {
	// Find first dot
	for i, c := range fqdn {
		if c == '.' {
			if i > 0 && i < len(fqdn)-1 {
				return fqdn[:i], fqdn[i+1:], true
			}
			return "", "", false
		}
	}
	return "", "", false
}
