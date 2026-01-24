// Machine Tunnel Fork - Firewall Stub for non-Windows platforms
// Windows Firewall management is Windows-specific.

//go:build !windows

package firewall

import "fmt"

// addFirewallRuleImpl is not supported on non-Windows platforms
func addFirewallRuleImpl(rule FirewallRule) error {
	return fmt.Errorf("Windows Firewall is only available on Windows")
}

// removeFirewallRuleImpl is not supported on non-Windows platforms
func removeFirewallRuleImpl(ruleName string) error {
	return fmt.Errorf("Windows Firewall is only available on Windows")
}

// removeFirewallRulesByGroupImpl is not supported on non-Windows platforms
func removeFirewallRulesByGroupImpl(groupName string) error {
	return fmt.Errorf("Windows Firewall is only available on Windows")
}

// isFirewallRuleExists is not supported on non-Windows platforms
func isFirewallRuleExists(ruleName string) bool {
	return false
}

// isWindowsFirewallReachable is not supported on non-Windows platforms
func isWindowsFirewallReachable() bool {
	return false
}

// listFirewallRulesByPrefix is not supported on non-Windows platforms
func listFirewallRulesByPrefix(prefix string) ([]string, error) {
	return nil, fmt.Errorf("Windows Firewall is only available on Windows")
}

// AddDenyAllRule is not supported on non-Windows platforms
func AddDenyAllRule(interfaceName string) error {
	return fmt.Errorf("Windows Firewall is only available on Windows")
}

// RemoveDenyAllRule is not supported on non-Windows platforms
func RemoveDenyAllRule() error {
	return fmt.Errorf("Windows Firewall is only available on Windows")
}
