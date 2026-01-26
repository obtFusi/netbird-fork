// Machine Tunnel Fork - Windows Firewall Implementation
// This file provides Windows-specific firewall rule management using netsh.

//go:build windows

package firewall

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// addFirewallRuleImpl adds a firewall rule using netsh
func addFirewallRuleImpl(rule Rule) error {
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", rule.Name),
		fmt.Sprintf("dir=%s", rule.Direction),
		fmt.Sprintf("action=%s", rule.Action),
		fmt.Sprintf("protocol=%s", rule.Protocol),
		fmt.Sprintf("remoteport=%s", rule.RemotePorts),
		fmt.Sprintf("remoteip=%s", rule.RemoteAddresses),
		fmt.Sprintf("profile=%s", rule.Profile),
		"enable=yes",
	}

	// Note: Interface-specific rules are applied via PowerShell commands
	// in AddDenyAllRule as netsh has limited interface filtering support

	// Add description if specified
	if rule.Description != "" {
		args = append(args, fmt.Sprintf("description=%s", rule.Description))
	}

	netshCmd := getSystem32Command("netsh")
	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh add rule failed: %w (output: %s)", err, string(output))
	}

	log.WithFields(log.Fields{
		"rule":      rule.Name,
		"protocol":  rule.Protocol,
		"ports":     rule.RemotePorts,
		"remote_ip": rule.RemoteAddresses,
	}).Debug("Added firewall rule via netsh")

	return nil
}

// removeFirewallRuleImpl removes a firewall rule by name
func removeFirewallRuleImpl(ruleName string) error {
	args := []string{
		"advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName),
	}

	netshCmd := getSystem32Command("netsh")
	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if the rule doesn't exist (not really an error)
		if strings.Contains(string(output), "No rules match the specified criteria") {
			log.WithField("rule", ruleName).Debug("Firewall rule already removed")
			return nil
		}
		return fmt.Errorf("netsh delete rule failed: %w (output: %s)", err, string(output))
	}

	log.WithField("rule", ruleName).Debug("Removed firewall rule via netsh")
	return nil
}

// removeFirewallRulesByGroupImpl removes all firewall rules in a group
// This is used for cleanup to ensure no orphaned rules remain
func removeFirewallRulesByGroupImpl(groupName string) error {
	// netsh doesn't support group deletion directly, so we use PowerShell
	psScript := fmt.Sprintf(`Get-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`, groupName)

	psCmd := getSystem32Command("powershell")
	cmd := exec.Command(psCmd, "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// PowerShell may return error if no rules found, which is OK
		outputStr := string(output)
		if strings.Contains(outputStr, "No MSFT_NetFirewallRule objects found") ||
			strings.Contains(outputStr, "ObjectNotFound") {
			log.WithField("group", groupName).Debug("No firewall rules found in group")
			return nil
		}
		return fmt.Errorf("PowerShell remove rules by group failed: %w (output: %s)", err, outputStr)
	}

	log.WithField("group", groupName).Debug("Removed firewall rules by group via PowerShell")
	return nil
}

// getSystem32Command returns the full path to a System32 command
func getSystem32Command(command string) string {
	_, err := exec.LookPath(command)
	if err == nil {
		return command
	}

	log.Tracef("Command %s not found in PATH, using C:\\windows\\system32\\%s.exe path", command, command)
	return "C:\\windows\\system32\\" + command + ".exe"
}

// AddDenyAllRule adds a deny-all rule for the interface
// This should be called after all allow rules to create a deny-by-default policy
func AddDenyAllRule(interfaceName string) error {
	rule := Rule{
		Name:           RuleNamePrefix + "Deny All",
		Description:    "NetBird Machine Tunnel - Block all other traffic",
		Group:          RuleGroupName,
		Direction:      DirectionOutbound,
		Action:         ActionBlock,
		Protocol:       "any",
		RemotePorts:    "any",
		RemoteAddresses: "any",
		InterfaceAlias: interfaceName,
		Profile:        "any",
		Enabled:        true,
	}

	// Use PowerShell for deny-all rule as netsh has protocol limitations
	psScript := fmt.Sprintf(`
New-NetFirewallRule -DisplayName '%s' `+
		`-Description '%s' `+
		`-Group '%s' `+
		`-Direction Outbound `+
		`-Action Block `+
		`-Profile Any `+
		`-Enabled True `+
		`-ErrorAction Stop`,
		rule.Name, rule.Description, rule.Group)

	psCmd := getSystem32Command("powershell")
	cmd := exec.Command(psCmd, "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("PowerShell add deny-all rule failed: %w (output: %s)", err, string(output))
	}

	log.WithField("rule", rule.Name).Debug("Added deny-all firewall rule")
	return nil
}

// RemoveDenyAllRule removes the deny-all rule
func RemoveDenyAllRule() error {
	return removeFirewallRuleImpl(RuleNamePrefix + "Deny All")
}
