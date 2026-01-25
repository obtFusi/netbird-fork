//go:build !windows

// Package tunnel provides machine tunnel functionality.
// This file provides stub implementations for non-Windows platforms.
package tunnel

import "errors"

const (
	// EventLogSource is the Windows Event Log source name (stub on non-Windows).
	EventLogSource = "NetBirdMachine"

	// Event IDs (stubs for non-Windows)
	EventIDServiceStart       = 1000
	EventIDServiceStop        = 1001
	EventIDTunnelConnected    = 1100
	EventIDTunnelDisconnected = 1101
	EventIDAuthSuccess        = 1200
	EventIDAuthFailure        = 1201
	EventIDCertInstalled      = 1300
	EventIDCertRemoved        = 1301
	EventIDSetupKeyUsed       = 1400
	EventIDSetupKeyRemoved    = 1401
	EventIDACLHardened        = 1500
	EventIDConfigError        = 2000
	EventIDSecurityWarning    = 2100
)

// ErrEventLogNotSupported indicates event log is not supported on this platform.
var ErrEventLogNotSupported = errors.New("windows event log not supported on this platform")

// InitEventLog is a no-op on non-Windows platforms.
func InitEventLog() error {
	return nil // No-op on non-Windows
}

// CloseEventLog is a no-op on non-Windows platforms.
func CloseEventLog() {
	// No-op on non-Windows
}

// RegisterEventSource is not supported on non-Windows platforms.
func RegisterEventSource() error {
	return ErrEventLogNotSupported
}

// RemoveEventSource is not supported on non-Windows platforms.
func RemoveEventSource() error {
	return ErrEventLogNotSupported
}

// LogInfo is a no-op on non-Windows platforms.
func LogInfo(eventID uint32, message string) error {
	return nil // No-op - use standard logging instead
}

// LogWarning is a no-op on non-Windows platforms.
func LogWarning(eventID uint32, message string) error {
	return nil // No-op - use standard logging instead
}

// LogError is a no-op on non-Windows platforms.
func LogError(eventID uint32, message string) error {
	return nil // No-op - use standard logging instead
}

// LogServiceStart is a no-op on non-Windows platforms.
func LogServiceStart(version string) error {
	return nil
}

// LogServiceStop is a no-op on non-Windows platforms.
func LogServiceStop() error {
	return nil
}

// LogTunnelConnected is a no-op on non-Windows platforms.
func LogTunnelConnected(serverAddr string) error {
	return nil
}

// LogTunnelDisconnected is a no-op on non-Windows platforms.
func LogTunnelDisconnected(reason string) error {
	return nil
}

// LogAuthSuccess is a no-op on non-Windows platforms.
func LogAuthSuccess(authMethod string) error {
	return nil
}

// LogAuthFailure is a no-op on non-Windows platforms.
func LogAuthFailure(authMethod, reason string) error {
	return nil
}

// LogCertInstalled is a no-op on non-Windows platforms.
func LogCertInstalled(certType, thumbprint string) error {
	return nil
}

// LogCertRemoved is a no-op on non-Windows platforms.
func LogCertRemoved(certType, thumbprint string) error {
	return nil
}

// LogSetupKeyUsed is a no-op on non-Windows platforms.
func LogSetupKeyUsed() error {
	return nil
}

// LogSetupKeyRemoved is a no-op on non-Windows platforms.
func LogSetupKeyRemoved() error {
	return nil
}

// LogACLHardened is a no-op on non-Windows platforms.
func LogACLHardened(path string) error {
	return nil
}

// LogConfigError is a no-op on non-Windows platforms.
func LogConfigError(err string) error {
	return nil
}

// LogSecurityWarning is a no-op on non-Windows platforms.
func LogSecurityWarning(warning string) error {
	return nil
}
