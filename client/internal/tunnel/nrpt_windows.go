// Machine Tunnel Fork - NRPT (Name Resolution Policy Table) Manager
// Manages DNS routing rules for Active Directory DNS resolution.
// Implements T-4.4: Client: NRPT Registry Integration

//go:build windows

package tunnel

import (
	"crypto/sha256"
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

const (
	// NRPTRegistryPath is the path to NRPT rules in the registry
	// v3.6: Using service path (not policy path) for direct DNS client control
	NRPTRegistryPath = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

	// NRPTKeyPrefix is the prefix for Machine Tunnel NRPT rules
	NRPTKeyPrefix = "NetBird-Machine-"
)

// NRPTManager handles Name Resolution Policy Table rules for AD DNS routing
type NRPTManager struct {
	keyPrefix string
}

// NewNRPTManager creates a new NRPT manager
func NewNRPTManager() *NRPTManager {
	return &NRPTManager{
		keyPrefix: NRPTKeyPrefix,
	}
}

// AddRule adds an NRPT rule for a namespace
func (m *NRPTManager) AddRule(namespace string, dnsServers []string) error {
	if namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if len(dnsServers) == 0 {
		return fmt.Errorf("at least one DNS server is required")
	}

	// Generate unique key name based on namespace hash (T-4.4a)
	keyName := m.generateKeyName(namespace)

	log.WithFields(log.Fields{
		"namespace":   namespace,
		"dns_servers": dnsServers,
		"key_name":    keyName,
	}).Info("Adding NRPT rule")

	// Open or create the DnsPolicyConfig key
	baseKey, _, err := registry.CreateKey(
		registry.LOCAL_MACHINE,
		NRPTRegistryPath,
		registry.ALL_ACCESS,
	)
	if err != nil {
		return fmt.Errorf("failed to open NRPT registry key: %w", err)
	}
	defer baseKey.Close()

	// Create the rule subkey
	ruleKey, _, err := registry.CreateKey(baseKey, keyName, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to create NRPT rule key: %w", err)
	}
	defer ruleKey.Close()

	// Set Name (REG_MULTI_SZ - the namespace with leading dot for suffix match)
	nameValue := namespace
	if namespace[0] != '.' {
		nameValue = "." + namespace
	}
	// REG_MULTI_SZ as per T-4.4 spec
	if err := ruleKey.SetStringsValue("Name", []string{nameValue}); err != nil {
		return fmt.Errorf("failed to set Name: %w", err)
	}

	// Set GenericDNSServers (REG_MULTI_SZ - DC IPs)
	if err := ruleKey.SetStringsValue("GenericDNSServers", dnsServers); err != nil {
		return fmt.Errorf("failed to set GenericDNSServers: %w", err)
	}

	// Set Comment for identification
	comment := fmt.Sprintf("NetBird Machine Tunnel (Namespace: %s)", namespace)
	if err := ruleKey.SetStringValue("Comment", comment); err != nil {
		return fmt.Errorf("failed to set Comment: %w", err)
	}

	// Set ConfigOptions = 8 (Generic DNS Server)
	if err := ruleKey.SetDWordValue("ConfigOptions", 8); err != nil {
		return fmt.Errorf("failed to set ConfigOptions: %w", err)
	}

	// Set Version = 2
	if err := ruleKey.SetDWordValue("Version", 2); err != nil {
		return fmt.Errorf("failed to set Version: %w", err)
	}

	log.WithField("key_name", keyName).Info("NRPT rule added successfully")

	// Notify DNS Client to reload rules
	if err := m.notifyDNSClient(); err != nil {
		log.WithError(err).Warn("Failed to notify DNS client (rule may not be active until restart)")
	}

	return nil
}

// RemoveRule removes an NRPT rule for a namespace
func (m *NRPTManager) RemoveRule(namespace string) error {
	keyName := m.generateKeyName(namespace)

	log.WithFields(log.Fields{
		"namespace": namespace,
		"key_name":  keyName,
	}).Info("Removing NRPT rule")

	baseKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		NRPTRegistryPath,
		registry.ALL_ACCESS,
	)
	if err != nil {
		// Key doesn't exist, nothing to remove
		return nil
	}
	defer baseKey.Close()

	if err := registry.DeleteKey(baseKey, keyName); err != nil {
		// Ignore if key doesn't exist
		if err != registry.ErrNotExist {
			return fmt.Errorf("failed to delete NRPT rule: %w", err)
		}
	}

	log.WithField("key_name", keyName).Info("NRPT rule removed")

	// Notify DNS Client to reload rules
	_ = m.notifyDNSClient()

	return nil
}

// RemoveAllRules removes all Machine Tunnel NRPT rules
func (m *NRPTManager) RemoveAllRules() error {
	log.Info("Removing all Machine Tunnel NRPT rules")

	baseKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		NRPTRegistryPath,
		registry.ALL_ACCESS,
	)
	if err != nil {
		// Key doesn't exist, nothing to remove
		return nil
	}
	defer baseKey.Close()

	// List all subkeys
	names, err := baseKey.ReadSubKeyNames(-1)
	if err != nil {
		return fmt.Errorf("failed to list NRPT rules: %w", err)
	}

	// Delete only our keys (those starting with our prefix)
	removedCount := 0
	for _, name := range names {
		if len(name) >= len(m.keyPrefix) && name[:len(m.keyPrefix)] == m.keyPrefix {
			log.WithField("key_name", name).Debug("Removing NRPT rule")
			if err := registry.DeleteKey(baseKey, name); err != nil && err != registry.ErrNotExist {
				log.WithError(err).Warnf("Failed to remove NRPT rule %s", name)
			} else {
				removedCount++
			}
		}
	}

	log.WithField("removed_count", removedCount).Info("Machine Tunnel NRPT rules removed")

	// Notify DNS Client to reload rules
	if removedCount > 0 {
		_ = m.notifyDNSClient()
	}

	return nil
}

// ListRules lists all Machine Tunnel NRPT rules
func (m *NRPTManager) ListRules() ([]string, error) {
	baseKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		NRPTRegistryPath,
		registry.READ,
	)
	if err != nil {
		// Key doesn't exist, no rules
		return nil, nil
	}
	defer baseKey.Close()

	names, err := baseKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to list NRPT rules: %w", err)
	}

	var rules []string
	for _, name := range names {
		if len(name) >= len(m.keyPrefix) && name[:len(m.keyPrefix)] == m.keyPrefix {
			rules = append(rules, name)
		}
	}

	return rules, nil
}

// generateKeyName generates a unique registry key name for a namespace
// Uses hash to ensure unique, stable, short key names (T-4.4a)
func (m *NRPTManager) generateKeyName(namespace string) string {
	h := sha256.Sum256([]byte(namespace))
	return fmt.Sprintf("%s%x", m.keyPrefix, h[:4])
}

// notifyDNSClient clears the DNS client cache to force rule reload
// This is required for NRPT changes to take effect immediately
func (m *NRPTManager) notifyDNSClient() error {
	log.Debug("Notifying DNS client to reload NRPT rules")

	// Method 1: Clear-DnsClientCache (preferred)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", "Clear-DnsClientCache")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.WithFields(log.Fields{
			"error":  err,
			"output": string(output),
		}).Debug("Clear-DnsClientCache failed, trying alternative method")

		// Method 2: ipconfig /flushdns (fallback)
		cmd = exec.Command("ipconfig", "/flushdns")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to flush DNS cache: %w, output: %s", err, string(output))
		}
	}

	log.Debug("DNS client notified successfully")
	return nil
}
