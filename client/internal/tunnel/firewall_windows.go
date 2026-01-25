// Machine Tunnel Fork - Windows Firewall Manager
// Manages Windows Firewall rules for DC traffic over the Machine Tunnel.

//go:build windows

package tunnel

import (
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// FirewallRulePrefix is the prefix for Machine Tunnel firewall rules
	FirewallRulePrefix = "NetBird-Machine-"

	// FirewallGroupName is the group name for Machine Tunnel firewall rules
	FirewallGroupName = "NetBird Machine Tunnel"
)

// FirewallManager handles Windows Firewall rules for DC traffic
type FirewallManager struct {
	interfaceName string
	rulePrefix    string
}

// NewFirewallManager creates a new Firewall manager
func NewFirewallManager(interfaceName string) *FirewallManager {
	return &FirewallManager{
		interfaceName: interfaceName,
		rulePrefix:    FirewallRulePrefix,
	}
}

// AllowDCTraffic adds a firewall rule to allow traffic to a DC IP/CIDR
func (m *FirewallManager) AllowDCTraffic(ipOrCIDR string) error {
	ruleName := m.generateRuleName(ipOrCIDR, "allow")

	log.WithFields(log.Fields{
		"ip_or_cidr": ipOrCIDR,
		"rule_name":  ruleName,
		"interface":  m.interfaceName,
	}).Info("Adding firewall allow rule for DC traffic")

	// Add inbound rule
	if err := m.addRule(ruleName+"-in", "in", ipOrCIDR); err != nil {
		return fmt.Errorf("add inbound rule: %w", err)
	}

	// Add outbound rule
	if err := m.addRule(ruleName+"-out", "out", ipOrCIDR); err != nil {
		return fmt.Errorf("add outbound rule: %w", err)
	}

	log.WithField("rule_name", ruleName).Info("Firewall rules added successfully")
	return nil
}

// addRule adds a single firewall rule using netsh
func (m *FirewallManager) addRule(ruleName, direction, remoteIP string) error {
	// First, try to delete existing rule (ignore errors)
	_ = m.deleteRule(ruleName)

	// Build netsh command
	// netsh advfirewall firewall add rule name="..." dir=in/out action=allow
	//   remoteip=... localip=any protocol=any interface="wg-nb-machine"
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		fmt.Sprintf("dir=%s", direction),
		"action=allow",
		fmt.Sprintf("remoteip=%s", remoteIP),
		"localip=any",
		"protocol=any",
		fmt.Sprintf("interfacetype=any"),
		fmt.Sprintf("group=%s", FirewallGroupName),
	}

	cmd := exec.Command("netsh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh add rule failed: %w, output: %s", err, string(output))
	}

	return nil
}

// deleteRule deletes a firewall rule by name
func (m *FirewallManager) deleteRule(ruleName string) error {
	args := []string{
		"advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName),
	}

	cmd := exec.Command("netsh", args...)
	_, err := cmd.CombinedOutput()
	return err
}

// EnableDenyDefault enables a deny-default rule for the Machine Tunnel interface
// This implements the T-4.6 requirement for deny-by-default security
func (m *FirewallManager) EnableDenyDefault() error {
	ruleName := m.rulePrefix + "deny-default"

	log.WithFields(log.Fields{
		"rule_name": ruleName,
		"interface": m.interfaceName,
	}).Info("Enabling deny-default firewall rule")

	// Delete existing rule first
	_ = m.deleteRule(ruleName + "-in")
	_ = m.deleteRule(ruleName + "-out")

	// Add deny-default inbound rule (lowest priority)
	argsIn := []string{
		"advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s-in", ruleName),
		"dir=in",
		"action=block",
		"localip=any",
		"remoteip=any",
		"protocol=any",
		fmt.Sprintf("group=%s", FirewallGroupName),
	}

	cmd := exec.Command("netsh", argsIn...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh add deny-default inbound failed: %w, output: %s", err, string(output))
	}

	// Add deny-default outbound rule
	argsOut := []string{
		"advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s-out", ruleName),
		"dir=out",
		"action=block",
		"localip=any",
		"remoteip=any",
		"protocol=any",
		fmt.Sprintf("group=%s", FirewallGroupName),
	}

	cmd = exec.Command("netsh", argsOut...)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh add deny-default outbound failed: %w, output: %s", err, string(output))
	}

	log.Info("Deny-default firewall rules enabled")
	return nil
}

// RemoveAllRules removes all Machine Tunnel firewall rules
func (m *FirewallManager) RemoveAllRules() error {
	log.Info("Removing all Machine Tunnel firewall rules")

	// Delete rules by group name
	args := []string{
		"advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("group=%s", FirewallGroupName),
	}

	cmd := exec.Command("netsh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if error is "No rules match the specified criteria"
		outputStr := string(output)
		if strings.Contains(outputStr, "No rules match") {
			log.Debug("No firewall rules to remove")
			return nil
		}
		return fmt.Errorf("netsh delete rules failed: %w, output: %s", err, outputStr)
	}

	log.Info("All Machine Tunnel firewall rules removed")
	return nil
}

// ListRules lists all Machine Tunnel firewall rules
func (m *FirewallManager) ListRules() ([]string, error) {
	args := []string{
		"advfirewall", "firewall", "show", "rule",
		fmt.Sprintf("group=%s", FirewallGroupName),
	}

	cmd := exec.Command("netsh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "No rules match") {
			return nil, nil
		}
		return nil, fmt.Errorf("netsh show rules failed: %w, output: %s", err, outputStr)
	}

	// Parse output to extract rule names
	var rules []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Rule Name:") {
			ruleName := strings.TrimPrefix(line, "Rule Name:")
			ruleName = strings.TrimSpace(ruleName)
			if strings.HasPrefix(ruleName, m.rulePrefix) {
				rules = append(rules, ruleName)
			}
		}
	}

	return rules, nil
}

// generateRuleName generates a unique firewall rule name
func (m *FirewallManager) generateRuleName(ipOrCIDR, action string) string {
	// Sanitize IP/CIDR for use in rule name
	sanitized := strings.ReplaceAll(ipOrCIDR, "/", "-")
	sanitized = strings.ReplaceAll(sanitized, ".", "_")
	return fmt.Sprintf("%s%s-%s", m.rulePrefix, action, sanitized)
}
