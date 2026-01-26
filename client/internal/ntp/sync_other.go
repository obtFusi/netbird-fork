// Machine Tunnel Fork - NTP Non-Windows Stub
// This file provides stub implementations for non-Windows platforms.

//go:build !windows

package ntp

import (
	"context"
	"fmt"
	"time"
)

// getTimeOffsetImpl is not implemented on non-Windows platforms
func getTimeOffsetImpl(ctx context.Context, server string, timeout time.Duration) (time.Duration, error) {
	return 0, fmt.Errorf("NTP sync not implemented on this platform")
}

// forceSyncImpl is not implemented on non-Windows platforms
func forceSyncImpl(ctx context.Context, timeout time.Duration) error {
	return fmt.Errorf("NTP sync not implemented on this platform")
}

// switchToManualPeerImpl is not implemented on non-Windows platforms
func switchToManualPeerImpl(dcIP string) error {
	return fmt.Errorf("NTP peer switch not implemented on this platform")
}

// switchToDomainHierarchyImpl is not implemented on non-Windows platforms
func switchToDomainHierarchyImpl() error {
	return fmt.Errorf("NTP domain hierarchy not implemented on this platform")
}
