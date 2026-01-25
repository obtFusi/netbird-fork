// Machine Tunnel Fork - Windows Firewall Manager
// This file provides firewall rule management for the Machine Tunnel.
// It creates Windows Firewall rules to restrict tunnel traffic to DC IPs only.

package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// RuleGroupName is the group name for all Machine Tunnel firewall rules
	RuleGroupName = "NetBird Machine"

	// RuleNamePrefix is the prefix for all rule names
	RuleNamePrefix = "NetBird Machine - "

	// DefaultInterfaceName is the default Machine Tunnel interface name
	DefaultInterfaceName = "wg-nb-machine"

	// DenyAllRuleName is the name of the deny-all rule
	DenyAllRuleName = RuleNamePrefix + "Deny All"

	// DefaultSafeModeTimeout is the default timeout for safe mode rollback
	DefaultSafeModeTimeout = 60 * time.Second
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

	// denyAllEnabled indicates if the deny-all rule is active
	denyAllEnabled bool

	// safeModeEnabled indicates if safe mode rollback is active
	safeModeEnabled bool

	// safeModeTimeout is the timeout for safe mode rollback
	safeModeTimeout time.Duration

	// safeModeCancel cancels the safe mode timer
	safeModeCancel context.CancelFunc

	// connectivityTestFunc tests if DC is reachable
	connectivityTestFunc func() error

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

	// EnableDenyDefault enables the deny-all rule after allow rules
	EnableDenyDefault bool

	// SafeModeEnabled enables safe mode with auto-rollback
	// If connectivity test fails, rules are removed automatically
	SafeModeEnabled bool

	// SafeModeTimeout is the timeout for safe mode rollback (default 60s)
	SafeModeTimeout time.Duration

	// ConnectivityTestFunc is a function to test DC connectivity
	// Used during safe mode to verify rules don't break connectivity
	ConnectivityTestFunc func() error
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

	safeModeTimeout := config.SafeModeTimeout
	if safeModeTimeout == 0 {
		safeModeTimeout = DefaultSafeModeTimeout
	}

	return &Manager{
		interfaceName:        interfaceName,
		dcIPs:                config.DCIPs,
		adPorts:              adPorts,
		createdRules:         make([]string, 0),
		denyAllEnabled:       false,
		safeModeEnabled:      config.SafeModeEnabled,
		safeModeTimeout:      safeModeTimeout,
		connectivityTestFunc: config.ConnectivityTestFunc,
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

// EnableDenyDefault adds the deny-all rule
// This should be called AFTER Configure() to create the catch-all block
func (m *Manager) EnableDenyDefault() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("firewall manager is closed")
	}

	if m.denyAllEnabled {
		log.Debug("Deny-all rule already enabled")
		return nil
	}

	log.Info("Enabling deny-default firewall rule")

	if err := AddDenyAllRule(m.interfaceName); err != nil {
		return fmt.Errorf("add deny-all rule: %w", err)
	}

	m.denyAllEnabled = true
	m.createdRules = append(m.createdRules, DenyAllRuleName)

	log.Info("Deny-default rule enabled - all non-AD traffic is now blocked")
	return nil
}

// DisableDenyDefault removes the deny-all rule
func (m *Manager) DisableDenyDefault() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.denyAllEnabled {
		log.Debug("Deny-all rule not enabled")
		return nil
	}

	log.Info("Disabling deny-default firewall rule")

	if err := RemoveDenyAllRule(); err != nil {
		return fmt.Errorf("remove deny-all rule: %w", err)
	}

	m.denyAllEnabled = false

	// Remove from tracked rules
	newRules := make([]string, 0, len(m.createdRules)-1)
	for _, r := range m.createdRules {
		if r != DenyAllRuleName {
			newRules = append(newRules, r)
		}
	}
	m.createdRules = newRules

	log.Info("Deny-default rule disabled")
	return nil
}

// IsDenyDefaultEnabled returns whether the deny-all rule is active
func (m *Manager) IsDenyDefaultEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denyAllEnabled
}

// ConfigureWithDenyDefault creates all allow rules and then adds the deny-all rule
// If safe mode is enabled, it will auto-rollback if connectivity test fails
func (m *Manager) ConfigureWithDenyDefault() error {
	// First configure the allow rules
	if err := m.Configure(); err != nil {
		return fmt.Errorf("configure allow rules: %w", err)
	}

	// If safe mode is enabled, start the safety timer
	if m.safeModeEnabled {
		if err := m.startSafeMode(); err != nil {
			log.WithError(err).Warn("Failed to start safe mode")
		}
	}

	// Add the deny-all rule
	if err := m.EnableDenyDefault(); err != nil {
		// If deny-all fails, cleanup allow rules
		log.WithError(err).Warn("Failed to enable deny-default, cleaning up")
		_ = m.RemoveAllRules()
		return fmt.Errorf("enable deny-default: %w", err)
	}

	// If safe mode is enabled, verify connectivity
	if m.safeModeEnabled && m.connectivityTestFunc != nil {
		if err := m.connectivityTestFunc(); err != nil {
			log.WithError(err).Warn("Connectivity test failed, rolling back firewall rules")
			_ = m.Cleanup()
			return fmt.Errorf("connectivity test failed after firewall rules: %w", err)
		}

		// Connectivity test passed, cancel safe mode timer
		m.cancelSafeMode()
		log.Info("Connectivity test passed, firewall rules confirmed working")
	}

	return nil
}

// startSafeMode starts the safe mode timer
// If ConfirmSafeMode is not called before timeout, rules are rolled back
func (m *Manager) startSafeMode() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.safeModeCancel != nil {
		// Already in safe mode
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.safeModeCancel = cancel

	log.WithField("timeout", m.safeModeTimeout).Info("Safe mode started - rules will auto-rollback if not confirmed")

	go func() {
		select {
		case <-ctx.Done():
			// Safe mode cancelled (confirmed or explicitly cancelled)
			return
		case <-time.After(m.safeModeTimeout):
			// Timeout - rollback
			log.Warn("Safe mode timeout reached - rolling back firewall rules")
			if err := m.Cleanup(); err != nil {
				log.WithError(err).Error("Failed to rollback firewall rules")
			}
		}
	}()

	return nil
}

// cancelSafeMode cancels the safe mode timer
func (m *Manager) cancelSafeMode() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.safeModeCancel != nil {
		m.safeModeCancel()
		m.safeModeCancel = nil
		log.Debug("Safe mode cancelled")
	}
}

// ConfirmSafeMode confirms that the firewall rules are working correctly
// This cancels the safe mode auto-rollback timer
func (m *Manager) ConfirmSafeMode() {
	m.cancelSafeMode()
	log.Info("Safe mode confirmed - firewall rules will persist")
}

// SetConnectivityTestFunc sets the connectivity test function
func (m *Manager) SetConnectivityTestFunc(fn func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectivityTestFunc = fn
}
