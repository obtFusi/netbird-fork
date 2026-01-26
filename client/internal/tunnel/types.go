// Package tunnel provides Machine Tunnel functionality for Windows pre-login VPN.
// Machine Tunnel runs as SYSTEM service and authenticates via machine certificates.
package tunnel

// Mode defines the operating mode of the NetBird client
type Mode string

const (
	// TunnelModeUser is the default mode - user authentication after login via SSO/Setup-Key
	ModeUser Mode = "user"

	// TunnelModeMachine is the new mode for Windows pre-login VPN
	// Uses machine certificate from Windows Certificate Store for authentication
	ModeMachine Mode = "machine"
)

// MachineCertConfig holds configuration for machine certificate authentication
type MachineCertConfig struct {
	// Enabled activates machine certificate authentication
	Enabled bool `yaml:"machine_cert_enabled" json:"machineCertEnabled"`

	// TemplateOID is the AD CS template OID to match (1.3.6.1.4.1.311.21.7)
	// If set, only certificates with this template are considered
	TemplateOID string `yaml:"machine_cert_template_oid,omitempty" json:"machineCertTemplateOid,omitempty"`

	// TemplateName is the AD CS template name to match
	// Alternative to TemplateOID for template-based selection
	TemplateName string `yaml:"machine_cert_template_name,omitempty" json:"machineCertTemplateName,omitempty"`

	// RequiredEKU specifies the required Extended Key Usage OID
	// Default: 1.3.6.1.5.5.7.3.2 (Client Authentication)
	RequiredEKU string `yaml:"machine_cert_required_eku,omitempty" json:"machineCertRequiredEku,omitempty"`

	// SANMustMatch if true, requires SAN DNSName to contain the machine hostname
	SANMustMatch bool `yaml:"machine_cert_san_must_match,omitempty" json:"machineCertSanMustMatch,omitempty"`

	// ThumbprintOverride allows specifying an exact certificate thumbprint
	// Bypasses template/EKU selection - use only for testing or specific cert pinning
	ThumbprintOverride string `yaml:"machine_cert_thumbprint,omitempty" json:"machineCertThumbprint,omitempty"`
}

// MachineIdentity represents the identity extracted from a machine certificate
type MachineIdentity struct {
	// Hostname is the machine hostname from SAN DNSName
	Hostname string

	// Domain is the AD domain from SAN DNSName (e.g., "corp.local")
	Domain string

	// FQDN is the full hostname.domain (e.g., "win10-pc.corp.local")
	FQDN string

	// CertThumbprint is the SHA-1 thumbprint of the certificate
	CertThumbprint string

	// IssuerFingerprint is the SHA-256 fingerprint of the issuing CA
	IssuerFingerprint string

	// TemplateOID is the AD CS template OID if present
	TemplateOID string

	// TemplateName is the AD CS template name if present
	TemplateName string
}

// DefaultClientAuthEKU is the standard Client Authentication EKU
const DefaultClientAuthEKU = "1.3.6.1.5.5.7.3.2"

// ADCSTemplateOID is the Microsoft AD CS Certificate Template extension OID
const ADCSTemplateOID = "1.3.6.1.4.1.311.21.7"
