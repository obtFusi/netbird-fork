// Machine Tunnel Fork - Windows Firewall Manager
// This file provides firewall rule management for the Machine Tunnel.
// It creates Windows Firewall rules to restrict tunnel traffic to DC IPs only.

package firewall

import (
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	// RuleGroupName is the group name for all Machine Tunnel firewall rules
	RuleGroupName = "NetBird Machine"

	// RuleNamePrefix is the prefix for all rule names
	RuleNamePrefix = "NetBird Machine - "

	// DefaultInterfaceName is the default Machine Tunnel interface name
	DefaultInterfaceName = "wg-nb-machine"
)

// Manager manages Windows Firewall rules for the Machine Tunnel
type Manager struct {
	mu sync.Mutex

	// interfaceName is the WireGuard interface name
	interfaceName string

	// dcIPs are the allowed Domain Controller IP addresses
	dcIPs []string

	// adPorts are the AD service port configuration
	adPorts ADPortConfig

	// createdRules tracks all rules created by this manager
	createdRules []string

	// closed indicates if the manager has been closed
	closed bool
}

// ManagerConfig configures the firewall manager
type ManagerConfig struct {
	// InterfaceName is the WireGuard interface name
	InterfaceName string

	// DCIPs are the allowed Domain Controller IP addresses
	DCIPs []string

	// ADPorts is the AD service port configuration (nil = defaults)
	ADPorts *ADPortConfig

	// UseRestrictedRPC uses GPO-restricted RPC port range (5000-5100)
	UseRestrictedRPC bool
}

// NewManager creates a new firewall manager
func NewManager(config *ManagerConfig) (*Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	interfaceName := config.InterfaceName
	if interfaceName == "" {
		interfaceName = DefaultInterfaceName
	}

	if len(config.DCIPs) == 0 {
		return nil, fmt.Errorf("at least one DC IP is required")
	}

	// Validate DC IPs
	for _, ip := range config.DCIPs {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid DC IP: %s", ip)
		}
	}

	adPorts := DefaultADPorts()
	if config.ADPorts != nil {
		adPorts = *config.ADPorts
	}

	// Use restricted RPC range if requested
	if config.UseRestrictedRPC {
		adPorts.RPCDynamicStart, adPorts.RPCDynamicEnd = RestrictedRPCPorts()
	}

	return &Manager{
		interfaceName: interfaceName,
		dcIPs:         config.DCIPs,
		adPorts:       adPorts,
		createdRules:  make([]string, 0),
	}, nil
}

// Configure creates all firewall rules for AD traffic
func (m *Manager) Configure() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("firewall manager is closed")
	}

	dcAddressFilter := strings.Join(m.dcIPs, ",")

	log.WithFields(log.Fields{
		"interface": m.interfaceName,
		"dc_ips":    m.dcIPs,
	}).Info("Configuring firewall rules for Machine Tunnel")

	// Create rules in order of importance
	rules := m.buildADRules(dcAddressFilter)

	for _, rule := range rules {
		if err := m.addRule(rule); err != nil {
			// Log error but continue with other rules
			log.WithError(err).WithField("rule", rule.Name).Warn("Failed to add firewall rule")
		} else {
			m.createdRules = append(m.createdRules, rule.Name)
			log.WithField("rule", rule.Name).Debug("Added firewall rule")
		}
	}

	log.WithField("count", len(m.createdRules)).Info("Firewall rules configured")
	return nil
}

// buildADRules builds all AD service firewall rules
func (m *Manager) buildADRules(dcAddressFilter string) []FirewallRule {
	rules := []FirewallRule{}

	// DNS (UDP + TCP)
	rules = append(rules,
		m.buildRule("DNS UDP", ProtocolUDP, fmt.Sprintf("%d", m.adPorts.DNS), dcAddressFilter),
		m.buildRule("DNS TCP", ProtocolTCP, fmt.Sprintf("%d", m.adPorts.DNS), dcAddressFilter),
	)

	// Kerberos (UDP + TCP) - UDP is primary!
	rules = append(rules,
		m.buildRule("Kerberos UDP", ProtocolUDP, fmt.Sprintf("%d", m.adPorts.Kerberos), dcAddressFilter),
		m.buildRule("Kerberos TCP", ProtocolTCP, fmt.Sprintf("%d", m.adPorts.Kerberos), dcAddressFilter),
	)

	// NTP (UDP only)
	rules = append(rules,
		m.buildRule("NTP UDP", ProtocolUDP, fmt.Sprintf("%d", m.adPorts.NTP), dcAddressFilter),
	)

	// LDAP (TCP, UDP for referrals)
	rules = append(rules,
		m.buildRule("LDAP TCP", ProtocolTCP, fmt.Sprintf("%d", m.adPorts.LDAP), dcAddressFilter),
		m.buildRule("LDAP UDP", ProtocolUDP, fmt.Sprintf("%d", m.adPorts.LDAP), dcAddressFilter),
	)

	// LDAPS (TCP)
	rules = append(rules,
		m.buildRule("LDAPS TCP", ProtocolTCP, fmt.Sprintf("%d", m.adPorts.LDAPS), dcAddressFilter),
	)

	// SMB for SYSVOL/NETLOGON (TCP)
	rules = append(rules,
		m.buildRule("SMB TCP", ProtocolTCP, fmt.Sprintf("%d", m.adPorts.SMB), dcAddressFilter),
	)

	// RPC Endpoint Mapper (TCP)
	rules = append(rules,
		m.buildRule("RPC Endpoint", ProtocolTCP, fmt.Sprintf("%d", m.adPorts.RPCEndpoint), dcAddressFilter),
	)

	// RPC Dynamic Ports (TCP)
	rules = append(rules,
		m.buildRule("RPC Dynamic", ProtocolTCP,
			fmt.Sprintf("%d-%d", m.adPorts.RPCDynamicStart, m.adPorts.RPCDynamicEnd),
			dcAddressFilter),
	)

	// Global Catalog (TCP)
	rules = append(rules,
		m.buildRule("Global Catalog", ProtocolTCP,
			fmt.Sprintf("%d", m.adPorts.GlobalCatalog), dcAddressFilter),
	)

	// Global Catalog SSL (TCP)
	rules = append(rules,
		m.buildRule("Global Catalog SSL", ProtocolTCP,
			fmt.Sprintf("%d", m.adPorts.GlobalCatalogSSL), dcAddressFilter),
	)

	return rules
}

// buildRule creates a single firewall rule
func (m *Manager) buildRule(name string, protocol Protocol, remotePorts, remoteAddresses string) FirewallRule {
	return FirewallRule{
		Name:            RuleNamePrefix + name,
		Description:     fmt.Sprintf("NetBird Machine Tunnel - %s", name),
		Group:           RuleGroupName,
		Direction:       DirectionOutbound,
		Action:          ActionAllow,
		Protocol:        protocol,
		RemotePorts:     remotePorts,
		RemoteAddresses: remoteAddresses,
		InterfaceAlias:  m.interfaceName,
		Profile:         "any",
		Enabled:         true,
	}
}

// addRule adds a single firewall rule (platform-specific)
func (m *Manager) addRule(rule FirewallRule) error {
	return addFirewallRuleImpl(rule)
}

// UpdateDCIPs updates the DC IP list and reconfigures rules
func (m *Manager) UpdateDCIPs(dcIPs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("firewall manager is closed")
	}

	// Validate new IPs
	for _, ip := range dcIPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid DC IP: %s", ip)
		}
	}

	// Check if IPs actually changed
	if equalStringSlices(m.dcIPs, dcIPs) {
		log.Debug("DC IP list unchanged, skipping firewall update")
		return nil
	}

	log.WithFields(log.Fields{
		"old_ips": m.dcIPs,
		"new_ips": dcIPs,
	}).Info("Updating DC IP list in firewall rules")

	// Remove old rules
	if err := m.removeAllRulesLocked(); err != nil {
		log.WithError(err).Warn("Failed to remove old firewall rules")
	}

	// Update IP list
	m.dcIPs = dcIPs

	// Create new rules
	dcAddressFilter := strings.Join(m.dcIPs, ",")
	rules := m.buildADRules(dcAddressFilter)

	for _, rule := range rules {
		if err := m.addRule(rule); err != nil {
			log.WithError(err).WithField("rule", rule.Name).Warn("Failed to add firewall rule")
		} else {
			m.createdRules = append(m.createdRules, rule.Name)
		}
	}

	return nil
}

// RemoveAllRules removes all firewall rules created by this manager
func (m *Manager) RemoveAllRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.removeAllRulesLocked()
}

// removeAllRulesLocked removes all rules (must hold lock)
func (m *Manager) removeAllRulesLocked() error {
	var errors []string

	for _, ruleName := range m.createdRules {
		if err := removeFirewallRuleImpl(ruleName); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", ruleName, err))
		} else {
			log.WithField("rule", ruleName).Debug("Removed firewall rule")
		}
	}

	m.createdRules = make([]string, 0)

	if len(errors) > 0 {
		return fmt.Errorf("failed to remove some rules: %s", strings.Join(errors, "; "))
	}

	return nil
}

// Cleanup removes all Machine Tunnel firewall rules
// This includes rules from previous manager instances
func (m *Manager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	// Remove tracked rules
	if err := m.removeAllRulesLocked(); err != nil {
		log.WithError(err).Warn("Failed to remove tracked firewall rules")
	}

	// Also clean up any orphaned rules by group
	if err := removeFirewallRulesByGroupImpl(RuleGroupName); err != nil {
		log.WithError(err).Warn("Failed to remove orphaned firewall rules by group")
	}

	log.Info("Firewall rules cleaned up")
	return nil
}

// GetCreatedRules returns a copy of the created rule names
func (m *Manager) GetCreatedRules() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]string, len(m.createdRules))
	copy(result, m.createdRules)
	return result
}

// GetDCIPs returns a copy of the configured DC IPs
func (m *Manager) GetDCIPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]string, len(m.dcIPs))
	copy(result, m.dcIPs)
	return result
}

// equalStringSlices checks if two string slices are equal
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
