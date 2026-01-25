// Package tunnel provides machine tunnel functionality.
// This file defines the shared MachineConfig type used across platforms.
package tunnel

// TrustConfig contains server certificate verification settings.
type TrustConfig struct {
	// ServerCertFingerprint is the expected SHA-256 fingerprint of the management server certificate.
	// Format: "sha256//BASE64HASH" (e.g., "sha256//ABC123...")
	// If empty, standard PKI validation is used.
	ServerCertFingerprint string `yaml:"server_cert_fingerprint,omitempty"`

	// CACertPath is the path to a custom CA certificate for server validation.
	// On Windows, this can also be installed to the system store.
	CACertPath string `yaml:"ca_cert_path,omitempty"`

	// InsecureSkipVerify disables server certificate validation (DANGEROUS - for testing only).
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty"`
}

// StoredMachineConfig represents the persisted machine tunnel configuration.
// Sensitive fields are encrypted with DPAPI on Windows.
// This is separate from the runtime MachineConfig in bootstrap.go.
type StoredMachineConfig struct {
	// ManagementURL is the NetBird management server URL.
	ManagementURL string `yaml:"management_url"`

	// SetupKeyEncrypted is the DPAPI-encrypted setup key (used only for bootstrap).
	// This field is removed after successful mTLS upgrade.
	// On non-Windows platforms, this field is not used.
	SetupKeyEncrypted string `yaml:"setup_key_encrypted,omitempty"`

	// MachineCertEnabled indicates whether machine certificate auth is enabled.
	MachineCertEnabled bool `yaml:"machine_cert_enabled,omitempty"`

	// MachineCertThumbprint is the thumbprint of the machine certificate.
	MachineCertThumbprint string `yaml:"machine_cert_thumbprint,omitempty"`

	// Trust configuration for server certificate verification.
	Trust *TrustConfig `yaml:"trust,omitempty"`
}

// HasSetupKey returns true if a setup key is configured.
func (c *StoredMachineConfig) HasSetupKey() bool {
	return c.SetupKeyEncrypted != ""
}
