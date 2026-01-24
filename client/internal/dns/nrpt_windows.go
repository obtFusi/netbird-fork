// Machine Tunnel Fork - NRPT Windows Implementation
// This file provides the Windows-specific NRPT registry operations.

//go:build windows

package dns

import (
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

// addNRPTRuleImpl adds an NRPT rule to the Windows registry
func addNRPTRuleImpl(ruleName string, rule NRPTRule) error {
	rulePath := NRPTBasePath + `\` + ruleName

	// Create or open the registry key
	key, _, err := registry.CreateKey(
		registry.LOCAL_MACHINE,
		rulePath,
		registry.ALL_ACCESS,
	)
	if err != nil {
		return fmt.Errorf("create NRPT key %s: %w", rulePath, err)
	}
	defer key.Close()

	// Name = Namespace (REG_MULTI_SZ)
	// This is the DNS suffix to match
	if err := key.SetStringsValue("Name", []string{rule.Namespace}); err != nil {
		return fmt.Errorf("set Name: %w", err)
	}

	// GenericDNSServers = DC-IPs (REG_MULTI_SZ)
	// These are the DNS servers to use for this namespace
	if err := key.SetStringsValue("GenericDNSServers", rule.DNSServers); err != nil {
		return fmt.Errorf("set GenericDNSServers: %w", err)
	}

	// Comment for identification and debugging
	comment := rule.Comment
	if comment == "" {
		comment = "NetBird Machine Tunnel"
	}
	commentWithNS := fmt.Sprintf("%s (Namespace: %s)", comment, rule.Namespace)
	if err := key.SetStringValue("Comment", commentWithNS); err != nil {
		return fmt.Errorf("set Comment: %w", err)
	}

	// ConfigOptions = 8 (Generic DNS Server)
	// This tells NRPT to use the GenericDNSServers for this namespace
	if err := key.SetDWordValue("ConfigOptions", ConfigOptionsGenericDNS); err != nil {
		return fmt.Errorf("set ConfigOptions: %w", err)
	}

	// Version = 2 (current NRPT version)
	if err := key.SetDWordValue("Version", NRPTVersion); err != nil {
		return fmt.Errorf("set Version: %w", err)
	}

	log.WithFields(log.Fields{
		"rule_name":   ruleName,
		"namespace":   rule.Namespace,
		"dns_servers": rule.DNSServers,
		"path":        rulePath,
	}).Debug("Created NRPT registry key")

	return nil
}

// removeNRPTRuleImpl removes an NRPT rule from the Windows registry
func removeNRPTRuleImpl(ruleName string) error {
	rulePath := NRPTBasePath + `\` + ruleName

	err := registry.DeleteKey(registry.LOCAL_MACHINE, rulePath)
	if err != nil {
		// Check if key doesn't exist (not an error)
		if err == registry.ErrNotExist {
			log.WithField("rule_name", ruleName).Debug("NRPT rule already removed")
			return nil
		}
		return fmt.Errorf("delete NRPT key %s: %w", rulePath, err)
	}

	log.WithFields(log.Fields{
		"rule_name": ruleName,
		"path":      rulePath,
	}).Debug("Deleted NRPT registry key")

	return nil
}

// notifyDNSClient notifies the DNS Client service of NRPT changes
// This ensures the new rules take effect immediately
func notifyDNSClient() error {
	// Method 1: Clear-DnsClientCache + Register-DnsClient (preferred)
	// This properly refreshes the NRPT rules
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Clear-DnsClientCache; Register-DnsClient")
	output, err := cmd.CombinedOutput()
	if err == nil {
		log.Debug("DNS client notified via PowerShell")
		return nil
	}
	log.WithError(err).WithField("output", string(output)).Debug("PowerShell DNS refresh failed, trying ipconfig")

	// Method 2: ipconfig /flushdns (fallback)
	// This at least clears the DNS cache
	cmd = exec.Command("ipconfig", "/flushdns")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipconfig /flushdns failed: %w (output: %s)", err, string(output))
	}

	log.Debug("DNS cache flushed via ipconfig")
	return nil
}

// cleanupOrphanedRules removes any NRPT rules with the NetBird prefix
// that are not tracked by the current manager instance
func cleanupOrphanedRules() error {
	// Open the NRPT base key
	baseKey, err := registry.OpenKey(registry.LOCAL_MACHINE, NRPTBasePath, registry.READ)
	if err != nil {
		if err == registry.ErrNotExist {
			// No NRPT rules exist
			return nil
		}
		return fmt.Errorf("open NRPT base key: %w", err)
	}
	defer baseKey.Close()

	// List all subkeys
	subkeys, err := baseKey.ReadSubKeyNames(-1)
	if err != nil {
		return fmt.Errorf("read NRPT subkeys: %w", err)
	}

	var errors []string

	// Find and remove all NetBird Machine Tunnel rules
	for _, subkey := range subkeys {
		if strings.HasPrefix(subkey, RulePrefix) {
			if err := removeNRPTRuleImpl(subkey); err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", subkey, err))
			} else {
				log.WithField("rule_name", subkey).Debug("Removed orphaned NRPT rule")
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to remove some orphaned rules: %s", strings.Join(errors, "; "))
	}

	return nil
}

// ListNRPTRules lists all NRPT rules with the NetBird prefix
func ListNRPTRules() ([]string, error) {
	baseKey, err := registry.OpenKey(registry.LOCAL_MACHINE, NRPTBasePath, registry.READ)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil, nil
		}
		return nil, fmt.Errorf("open NRPT base key: %w", err)
	}
	defer baseKey.Close()

	subkeys, err := baseKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("read NRPT subkeys: %w", err)
	}

	var rules []string
	for _, subkey := range subkeys {
		if strings.HasPrefix(subkey, RulePrefix) {
			rules = append(rules, subkey)
		}
	}

	return rules, nil
}

// GetNRPTRuleDetails retrieves the details of an NRPT rule
func GetNRPTRuleDetails(ruleName string) (*NRPTRule, error) {
	rulePath := NRPTBasePath + `\` + ruleName

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, rulePath, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("open NRPT key: %w", err)
	}
	defer key.Close()

	// Read Name (namespace)
	names, _, err := key.GetStringsValue("Name")
	if err != nil {
		return nil, fmt.Errorf("read Name: %w", err)
	}

	// Read GenericDNSServers
	dnsServers, _, err := key.GetStringsValue("GenericDNSServers")
	if err != nil {
		return nil, fmt.Errorf("read GenericDNSServers: %w", err)
	}

	// Read Comment (optional)
	comment, _, _ := key.GetStringValue("Comment")

	namespace := ""
	if len(names) > 0 {
		namespace = names[0]
	}

	return &NRPTRule{
		Namespace:  namespace,
		DNSServers: dnsServers,
		Comment:    comment,
	}, nil
}
