//go:build windows

// Package tunnel provides machine tunnel functionality for Windows.
// This file implements Windows Event Log integration for security auditing.
package tunnel

import (
	"fmt"

	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	// EventLogSource is the Windows Event Log source name for NetBird Machine Tunnel.
	EventLogSource = "NetBirdMachine"

	// Event IDs for different event types
	EventIDServiceStart      = 1000
	EventIDServiceStop       = 1001
	EventIDTunnelConnected   = 1100
	EventIDTunnelDisconnected = 1101
	EventIDAuthSuccess       = 1200
	EventIDAuthFailure       = 1201
	EventIDCertInstalled     = 1300
	EventIDCertRemoved       = 1301
	EventIDSetupKeyUsed      = 1400
	EventIDSetupKeyRemoved   = 1401
	EventIDACLHardened       = 1500
	EventIDConfigError       = 2000
	EventIDSecurityWarning   = 2100
)

// eventLog is the global event log instance.
var eventLog *eventlog.Log

// InitEventLog initializes the Windows Event Log source.
// This should be called once during service startup.
// Note: The event source must be registered with admin privileges before first use.
func InitEventLog() error {
	var err error
	eventLog, err = eventlog.Open(EventLogSource)
	if err != nil {
		return fmt.Errorf("open event log: %w", err)
	}
	return nil
}

// CloseEventLog closes the event log handle.
func CloseEventLog() {
	if eventLog != nil {
		eventLog.Close()
		eventLog = nil
	}
}

// RegisterEventSource registers the NetBird Machine event source.
// This requires administrator privileges and should be done during installation.
func RegisterEventSource() error {
	err := eventlog.InstallAsEventCreate(EventLogSource, eventlog.Info|eventlog.Warning|eventlog.Error)
	if err != nil {
		return fmt.Errorf("install event source: %w", err)
	}
	return nil
}

// RemoveEventSource removes the NetBird Machine event source.
// This requires administrator privileges and should be done during uninstallation.
func RemoveEventSource() error {
	err := eventlog.Remove(EventLogSource)
	if err != nil {
		return fmt.Errorf("remove event source: %w", err)
	}
	return nil
}

// LogInfo logs an informational event.
func LogInfo(eventID uint32, message string) error {
	if eventLog == nil {
		return fmt.Errorf("event log not initialized")
	}
	return eventLog.Info(eventID, message)
}

// LogWarning logs a warning event.
func LogWarning(eventID uint32, message string) error {
	if eventLog == nil {
		return fmt.Errorf("event log not initialized")
	}
	return eventLog.Warning(eventID, message)
}

// LogError logs an error event.
func LogError(eventID uint32, message string) error {
	if eventLog == nil {
		return fmt.Errorf("event log not initialized")
	}
	return eventLog.Error(eventID, message)
}

// LogServiceStart logs a service start event.
func LogServiceStart(version string) error {
	return LogInfo(EventIDServiceStart, fmt.Sprintf("NetBird Machine Tunnel service started (version %s)", version))
}

// LogServiceStop logs a service stop event.
func LogServiceStop() error {
	return LogInfo(EventIDServiceStop, "NetBird Machine Tunnel service stopped")
}

// LogTunnelConnected logs a tunnel connection event.
func LogTunnelConnected(serverAddr string) error {
	return LogInfo(EventIDTunnelConnected, fmt.Sprintf("Tunnel connected to %s", serverAddr))
}

// LogTunnelDisconnected logs a tunnel disconnection event.
func LogTunnelDisconnected(reason string) error {
	return LogInfo(EventIDTunnelDisconnected, fmt.Sprintf("Tunnel disconnected: %s", reason))
}

// LogAuthSuccess logs a successful authentication event.
func LogAuthSuccess(authMethod string) error {
	return LogInfo(EventIDAuthSuccess, fmt.Sprintf("Authentication successful via %s", authMethod))
}

// LogAuthFailure logs a failed authentication event.
func LogAuthFailure(authMethod, reason string) error {
	return LogWarning(EventIDAuthFailure, fmt.Sprintf("Authentication failed via %s: %s", authMethod, reason))
}

// LogCertInstalled logs a certificate installation event.
func LogCertInstalled(certType, thumbprint string) error {
	return LogInfo(EventIDCertInstalled, fmt.Sprintf("%s certificate installed (thumbprint: %s...)", certType, truncateForLog(thumbprint, 16)))
}

// LogCertRemoved logs a certificate removal event.
func LogCertRemoved(certType, thumbprint string) error {
	return LogInfo(EventIDCertRemoved, fmt.Sprintf("%s certificate removed (thumbprint: %s...)", certType, truncateForLog(thumbprint, 16)))
}

// LogSetupKeyUsed logs that a setup key was used for authentication.
func LogSetupKeyUsed() error {
	return LogInfo(EventIDSetupKeyUsed, "Setup key used for initial authentication")
}

// LogSetupKeyRemoved logs that the setup key was removed from config after successful mTLS upgrade.
func LogSetupKeyRemoved() error {
	return LogInfo(EventIDSetupKeyRemoved, "Setup key removed from config after successful mTLS upgrade")
}

// LogACLHardened logs that ACL hardening was applied.
func LogACLHardened(path string) error {
	return LogInfo(EventIDACLHardened, fmt.Sprintf("ACL hardening applied to %s", path))
}

// LogConfigError logs a configuration error.
func LogConfigError(err string) error {
	return LogError(EventIDConfigError, fmt.Sprintf("Configuration error: %s", err))
}

// LogSecurityWarning logs a security-related warning.
func LogSecurityWarning(warning string) error {
	return LogWarning(EventIDSecurityWarning, fmt.Sprintf("Security warning: %s", warning))
}

// truncateForLog truncates a string for logging purposes.
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
