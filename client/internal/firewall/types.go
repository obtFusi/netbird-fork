// Machine Tunnel Fork - Windows Firewall Types
// This file defines types for Windows Firewall rule management.

package firewall

// Protocol defines the network protocol for firewall rules
type Protocol string

const (
	// ProtocolTCP represents TCP protocol
	ProtocolTCP Protocol = "TCP"

	// ProtocolUDP represents UDP protocol
	ProtocolUDP Protocol = "UDP"
)

// Direction defines the traffic direction for firewall rules
type Direction string

const (
	// DirectionInbound represents inbound traffic
	DirectionInbound Direction = "in"

	// DirectionOutbound represents outbound traffic
	DirectionOutbound Direction = "out"
)

// Action defines the firewall rule action
type Action string

const (
	// ActionAllow allows traffic
	ActionAllow Action = "allow"

	// ActionBlock blocks traffic
	ActionBlock Action = "block"
)

// Rule represents a Windows Firewall rule
type Rule struct {
	// Name is the rule name for display and identification
	Name string

	// Description is a human-readable description
	Description string

	// Group is the rule group for easy management
	Group string

	// Direction is the traffic direction (in/out)
	Direction Direction

	// Action is the rule action (allow/block)
	Action Action

	// Protocol is the network protocol (TCP/UDP)
	Protocol Protocol

	// LocalPorts are the local ports to match (comma-separated or range)
	LocalPorts string

	// RemotePorts are the remote ports to match (comma-separated or range)
	RemotePorts string

	// LocalAddresses are the local IP addresses (comma-separated)
	LocalAddresses string

	// RemoteAddresses are the remote IP addresses (comma-separated)
	RemoteAddresses string

	// InterfaceAlias is the network interface name
	InterfaceAlias string

	// Profile is the firewall profile (domain, private, public, any)
	Profile string

	// Enabled indicates if the rule is active
	Enabled bool
}

// ADPortConfig defines the AD service ports
type ADPortConfig struct {
	// DNS port (usually 53)
	DNS int

	// Kerberos port (usually 88)
	Kerberos int

	// NTP port (usually 123)
	NTP int

	// LDAP port (usually 389)
	LDAP int

	// LDAPS port (usually 636)
	LDAPS int

	// SMB port (usually 445)
	SMB int

	// RPC Endpoint Mapper port (usually 135)
	RPCEndpoint int

	// RPC Dynamic port range start (usually 49152)
	RPCDynamicStart int

	// RPC Dynamic port range end (usually 65535)
	RPCDynamicEnd int

	// Global Catalog port (usually 3268)
	GlobalCatalog int

	// Global Catalog SSL port (usually 3269)
	GlobalCatalogSSL int
}

// DefaultADPorts returns the default AD port configuration
func DefaultADPorts() ADPortConfig {
	return ADPortConfig{
		DNS:              53,
		Kerberos:         88,
		NTP:              123,
		LDAP:             389,
		LDAPS:            636,
		SMB:              445,
		RPCEndpoint:      135,
		RPCDynamicStart:  49152,
		RPCDynamicEnd:    65535,
		GlobalCatalog:    3268,
		GlobalCatalogSSL: 3269,
	}
}

// RestrictedRPCPorts returns the recommended restricted RPC port range
// This should match the GPO-configured RPC port range on DCs
func RestrictedRPCPorts() (start, end int) {
	// GPO-restricted range (recommended for security)
	return 5000, 5100
}
