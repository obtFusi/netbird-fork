//go:build !windows

// Machine Tunnel Fork - Non-Windows Health Logging Stub
// Provides standard logging for platforms without Windows Event Log.

package tunnel

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

// InitEventLog is a no-op on non-Windows platforms.
// Exported for API compatibility with health_windows.go.
func InitEventLog() error {
	// No-op: Windows Event Log not available
	return nil
}

// CloseEventLog is a no-op on non-Windows platforms.
// Exported for API compatibility with health_windows.go.
func CloseEventLog() {
	// No-op: Windows Event Log not available
}

// logStateChange logs tunnel state changes to standard output.
func (h *HealthChecker) logStateChange(oldState, newState string) {
	msg := fmt.Sprintf("Machine Tunnel state changed: %s -> %s", oldState, newState)

	if h.degradedReason != "" && (newState == "degraded" || newState == "failed") {
		msg = fmt.Sprintf("%s (reason: %s)", msg, h.degradedReason)
	}

	switch newState {
	case "healthy":
		log.Info(msg)
	case "degraded":
		log.Warn(msg)
	case "failed":
		log.Error(msg)
	default:
		log.Info(msg)
	}
}
