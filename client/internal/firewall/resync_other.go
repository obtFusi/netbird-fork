// Machine Tunnel Fork - Firewall Rule Resync (Non-Windows Stub)
// This file provides stub implementations for non-Windows platforms.

//go:build !windows

package firewall

import "fmt"

// updateRuleInterface is not implemented on non-Windows platforms
func updateRuleInterface(ruleName, newInterfaceName string) error {
	return fmt.Errorf("firewall rule update not implemented on this platform")
}

// verifyRuleInterface is not implemented on non-Windows platforms
func verifyRuleInterface(ruleName, expectedInterface string) (bool, error) {
	return false, fmt.Errorf("firewall rule verification not implemented on this platform")
}

// GetRulesWithWrongInterface is not implemented on non-Windows platforms
func GetRulesWithWrongInterface(expectedInterface string) ([]string, error) {
	return nil, fmt.Errorf("firewall rule query not implemented on this platform")
}
