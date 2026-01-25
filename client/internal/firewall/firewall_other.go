// Machine Tunnel Fork - Firewall Stub for non-Windows platforms
// Windows Firewall management is Windows-specific.

//go:build !windows

package firewall

import "fmt"

// addFirewallRuleImpl is not supported on non-Windows platforms
func addFirewallRuleImpl(rule Rule) error {
	return fmt.Errorf("windows firewall is only available on windows")
}

// removeFirewallRuleImpl is not supported on non-Windows platforms
func removeFirewallRuleImpl(ruleName string) error {
	return fmt.Errorf("windows firewall is only available on windows")
}

// removeFirewallRulesByGroupImpl is not supported on non-Windows platforms
func removeFirewallRulesByGroupImpl(groupName string) error {
	return fmt.Errorf("windows firewall is only available on windows")
}

// AddDenyAllRule is not supported on non-Windows platforms
func AddDenyAllRule(interfaceName string) error {
	return fmt.Errorf("windows firewall is only available on windows")
}

// RemoveDenyAllRule is not supported on non-Windows platforms
func RemoveDenyAllRule() error {
	return fmt.Errorf("windows firewall is only available on windows")
}
