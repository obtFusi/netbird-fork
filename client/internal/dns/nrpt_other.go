// Machine Tunnel Fork - NRPT Stub for non-Windows platforms
// NRPT (Name Resolution Policy Table) is Windows-specific.

//go:build !windows

package dns

import "fmt"

// addNRPTRuleImpl is not supported on non-Windows platforms
func addNRPTRuleImpl(ruleName string, rule NRPTRule) error {
	return fmt.Errorf("NRPT is only available on Windows")
}

// removeNRPTRuleImpl is not supported on non-Windows platforms
func removeNRPTRuleImpl(ruleName string) error {
	return fmt.Errorf("NRPT is only available on Windows")
}

// notifyDNSClient is not supported on non-Windows platforms
func notifyDNSClient() error {
	return fmt.Errorf("NRPT is only available on Windows")
}

// cleanupOrphanedRules is not supported on non-Windows platforms
func cleanupOrphanedRules() error {
	return fmt.Errorf("NRPT is only available on Windows")
}

// ListNRPTRules is not supported on non-Windows platforms
func ListNRPTRules() ([]string, error) {
	return nil, fmt.Errorf("NRPT is only available on Windows")
}

// GetNRPTRuleDetails is not supported on non-Windows platforms
func GetNRPTRuleDetails(ruleName string) (*NRPTRule, error) {
	return nil, fmt.Errorf("NRPT is only available on Windows")
}
