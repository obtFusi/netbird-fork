// Machine Tunnel Fork - NRPT Registry Integration
// This file provides Name Resolution Policy Table (NRPT) management for DNS routing.
// NRPT is used to route AD domain DNS queries through the Machine Tunnel to DCs.

package dns

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	// RulePrefix is the prefix for all NRPT rules created by Machine Tunnel
	RulePrefix = "NetBird-Machine-"

	// NRPTBasePath is the registry path for NRPT rules (Service-based, not GPO)
	// Using Service path instead of Policy path for non-GPO environments
	NRPTBasePath = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

	// ConfigOptionsGenericDNS indicates Generic DNS Server configuration
	ConfigOptionsGenericDNS = 8

	// NRPTVersion is the version number for NRPT rules
	NRPTVersion = 2
)

// NRPTManager manages NRPT rules for the Machine Tunnel
type NRPTManager struct {
	mu sync.Mutex

	// activeRules tracks all rules created by this manager
	activeRules map[string]string // namespace -> ruleName

	// closed indicates if the manager has been closed
	closed bool
}

// NRPTRule represents an NRPT rule configuration
type NRPTRule struct {
	// Namespace is the DNS namespace (e.g., ".corp.local")
	// Must start with "." for suffix matching
	Namespace string

	// DNSServers are the DNS server IPs for this namespace
	DNSServers []string

	// Comment is a human-readable description
	Comment string
}

// NewNRPTManager creates a new NRPT manager
func NewNRPTManager() *NRPTManager {
	return &NRPTManager{
		activeRules: make(map[string]string),
	}
}

// ConfigureForDomain sets up NRPT rules for an AD domain
// This creates rules for both the domain and _msdcs subdomain
func (m *NRPTManager) ConfigureForDomain(domain string, dnsServers []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("NRPT manager is closed")
	}

	// Normalize domain (remove leading dot if present)
	domain = strings.TrimPrefix(domain, ".")

	log.WithFields(log.Fields{
		"domain":      domain,
		"dns_servers": dnsServers,
	}).Info("Configuring NRPT for AD domain")

	// Rule 1: Domain itself (.corp.local -> DCs)
	domainNamespace := "." + domain
	if err := m.addRule(NRPTRule{
		Namespace:  domainNamespace,
		DNSServers: dnsServers,
		Comment:    "NetBird Machine Tunnel - Domain",
	}); err != nil {
		return fmt.Errorf("add domain rule: %w", err)
	}

	// Rule 2: _msdcs subdomain (critical for DC Locator!)
	// _msdcs records are used by nltest /dsgetdc and similar AD tools
	forestRoot := getForestRoot(domain)
	msdcsNamespace := "._msdcs." + forestRoot
	if err := m.addRule(NRPTRule{
		Namespace:  msdcsNamespace,
		DNSServers: dnsServers,
		Comment:    "NetBird Machine Tunnel - MSDCS",
	}); err != nil {
		return fmt.Errorf("add _msdcs rule: %w", err)
	}

	// Notify DNS client of changes
	if err := notifyDNSClient(); err != nil {
		log.WithError(err).Warn("Failed to notify DNS client")
		// Don't fail - the rule is still created
	}

	return nil
}

// addRule adds a single NRPT rule
func (m *NRPTManager) addRule(rule NRPTRule) error {
	// Compute hash for stable rule name (see T-4.4a)
	ruleName := computeRuleName(rule.Namespace)

	// Add to registry (platform-specific)
	if err := addNRPTRuleImpl(ruleName, rule); err != nil {
		return err
	}

	// Track the rule
	m.activeRules[rule.Namespace] = ruleName

	log.WithFields(log.Fields{
		"namespace": rule.Namespace,
		"rule_name": ruleName,
	}).Debug("Added NRPT rule")

	return nil
}

// RemoveRule removes a single NRPT rule by namespace
func (m *NRPTManager) RemoveRule(namespace string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ruleName, exists := m.activeRules[namespace]
	if !exists {
		// Try to compute the rule name
		ruleName = computeRuleName(namespace)
	}

	if err := removeNRPTRuleImpl(ruleName); err != nil {
		return err
	}

	delete(m.activeRules, namespace)

	log.WithFields(log.Fields{
		"namespace": namespace,
		"rule_name": ruleName,
	}).Debug("Removed NRPT rule")

	return nil
}

// RemoveAllRules removes all NRPT rules created by this manager
func (m *NRPTManager) RemoveAllRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []string

	for namespace, ruleName := range m.activeRules {
		if err := removeNRPTRuleImpl(ruleName); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", namespace, err))
		} else {
			log.WithFields(log.Fields{
				"namespace": namespace,
				"rule_name": ruleName,
			}).Debug("Removed NRPT rule")
		}
	}

	// Clear the map
	m.activeRules = make(map[string]string)

	// Notify DNS client
	if err := notifyDNSClient(); err != nil {
		log.WithError(err).Warn("Failed to notify DNS client after rule removal")
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to remove some rules: %s", strings.Join(errors, "; "))
	}

	return nil
}

// Cleanup removes all NetBird Machine Tunnel NRPT rules
// This is called on service stop to ensure clean state
func (m *NRPTManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	// Remove all tracked rules
	var errors []string
	for namespace, ruleName := range m.activeRules {
		if err := removeNRPTRuleImpl(ruleName); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", namespace, err))
		}
	}

	// Also scan for any orphaned rules
	if err := cleanupOrphanedRules(); err != nil {
		errors = append(errors, fmt.Sprintf("orphan cleanup: %v", err))
	}

	// Clear tracked rules
	m.activeRules = make(map[string]string)

	// Notify DNS client
	if err := notifyDNSClient(); err != nil {
		log.WithError(err).Warn("Failed to notify DNS client after cleanup")
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// GetActiveRules returns a copy of the active rules
func (m *NRPTManager) GetActiveRules() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make(map[string]string, len(m.activeRules))
	for k, v := range m.activeRules {
		result[k] = v
	}
	return result
}

// computeRuleName generates a stable, short rule name from namespace
// Uses SHA-256 hash truncated to 8 hex chars for uniqueness
func computeRuleName(namespace string) string {
	h := sha256.Sum256([]byte(namespace))
	hash := fmt.Sprintf("%x", h[:4]) // 32 bits = 8 hex chars
	return RulePrefix + hash
}

// getForestRoot extracts the forest root domain from a child domain
// For simple cases, returns the domain itself
// e.g., "child.corp.local" -> "corp.local"
func getForestRoot(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	// Return the last two parts (e.g., corp.local)
	return strings.Join(parts[len(parts)-2:], ".")
}

// ValidateNamespace checks if a namespace is valid for NRPT
func ValidateNamespace(namespace string) error {
	if namespace == "" {
		return fmt.Errorf("namespace cannot be empty")
	}

	// NRPT namespaces should start with "." for suffix matching
	if !strings.HasPrefix(namespace, ".") {
		return fmt.Errorf("namespace should start with '.' for suffix matching: %s", namespace)
	}

	// Check for valid characters
	for _, c := range namespace {
		if !isValidDNSChar(c) {
			return fmt.Errorf("invalid character in namespace: %c", c)
		}
	}

	return nil
}

func isValidDNSChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '.' || c == '-' || c == '_'
}
