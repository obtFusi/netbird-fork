// Machine Tunnel Fork - Certificate Discovery Stub for non-Windows
// Windows Certificate Store is only available on Windows.

//go:build !windows

package auth

import (
	"fmt"
)

// discoverFromWindowsStoreImpl returns an error on non-Windows platforms
func discoverFromWindowsStoreImpl(config *CertDiscoveryConfig) (*LoadedCertificate, error) {
	return nil, fmt.Errorf("windows certificate store is only available on windows")
}

// findCertByThumbprintFromStoreImpl returns an error on non-Windows platforms
func findCertByThumbprintFromStoreImpl(thumbprint string) (*LoadedCertificate, error) {
	return nil, fmt.Errorf("windows certificate store is only available on windows")
}
