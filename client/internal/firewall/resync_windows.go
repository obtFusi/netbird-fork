// Machine Tunnel Fork - Firewall Rule Resync (Windows)
// This file provides Windows-specific firewall rule resync via PowerShell.

//go:build windows

package firewall

import (
	"fmt"
	"os/exec"
	"syscall"
)

// updateRuleInterface updates a firewall rule's interface alias using PowerShell
func updateRuleInterface(ruleName, newInterfaceName string) error {
	// Use Set-NetFirewallRule to update the interface alias
	script := fmt.Sprintf(`Set-NetFirewallRule -DisplayName "%s" -InterfaceAlias "%s"`, ruleName, newInterfaceName)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("update rule interface failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// GetRulesWithWrongInterface returns firewall rules that reference the wrong interface
func GetRulesWithWrongInterface(expectedInterface string) ([]string, error) {
	script := fmt.Sprintf(`
$rules = Get-NetFirewallRule -DisplayGroup "%s" -ErrorAction SilentlyContinue
$wrongRules = @()
foreach ($rule in $rules) {
    $filter = $rule | Get-NetFirewallInterfaceFilter
    if ($filter.InterfaceAlias -ne "%s" -and $filter.InterfaceAlias -ne "Any") {
        $wrongRules += $rule.DisplayName
    }
}
$wrongRules -join [char]10
`, RuleGroupName, expectedInterface)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("get rules with wrong interface failed: %w", err)
	}

	// Parse output
	outputStr := string(output)
	if outputStr == "" {
		return nil, nil
	}

	var rules []string
	for _, line := range splitLines(outputStr) {
		if line != "" {
			rules = append(rules, line)
		}
	}

	return rules, nil
}

// splitLines splits a string by newlines
func splitLines(s string) []string {
	var lines []string
	var current string
	for _, c := range s {
		if c == '\n' {
			lines = append(lines, current)
			current = ""
		} else if c != '\r' {
			current += string(c)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
