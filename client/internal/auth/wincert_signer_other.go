// Machine Tunnel Fork - Stub for non-Windows platforms
// Windows Certificate Store integration is only available on Windows.

//go:build !windows

package auth

import (
	"crypto/x509"
	"fmt"
)

// WinCertSigner is not supported on non-Windows platforms
type WinCertSigner struct{}

// CertSelectionCriteria is not used on non-Windows platforms
type CertSelectionCriteria struct {
	TemplateOID     string
	TemplateName    string
	RequiredEKU     string
	SANMustContain  string
	ThumbprintExact string
}

// FindMachineCertificate returns an error on non-Windows platforms
func FindMachineCertificate(criteria CertSelectionCriteria) (*WinCertSigner, error) {
	return nil, fmt.Errorf("windows certificate store is only available on windows")
}

// ParseMachineIdentity extracts machine identity from a certificate's SAN DNSName
// This is a shared implementation that works on all platforms
func ParseMachineIdentity(cert *x509.Certificate) (*MachineIdentity, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	// Find first SAN DNSName that looks like hostname.domain
	for _, dnsName := range cert.DNSNames {
		hostname, domain, ok := splitFQDN(dnsName)
		if ok {
			return &MachineIdentity{
				Hostname:       hostname,
				Domain:         domain,
				FQDN:           dnsName,
				CertThumbprint: "", // No thumbprint calculation on non-Windows
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
