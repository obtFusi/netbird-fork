// Machine Tunnel Fork - Stub for non-Windows platforms
// Windows Certificate Store integration is only available on Windows.

//go:build !windows

package auth

import (
	"fmt"

	"github.com/netbirdio/netbird/client/internal/tunnel"
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
	return nil, fmt.Errorf("Windows Certificate Store is only available on Windows")
}

// ParseMachineIdentity is not implemented on non-Windows platforms
func ParseMachineIdentity(cert interface{}) (*tunnel.MachineIdentity, error) {
	return nil, fmt.Errorf("ParseMachineIdentity is only available on Windows")
}
