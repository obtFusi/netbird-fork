//go:build windows

// Machine Tunnel Fork - Windows Health Logging
// Uses existing eventlog_windows.go infrastructure for Event Log.

package tunnel

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

// Health-specific Event Log event IDs (extending eventlog_windows.go constants)
const (
	EventIDHealthStateHealthy  uint32 = 1500
	EventIDHealthStateDegraded uint32 = 1501
	EventIDHealthStateFailed   uint32 = 1502
)

// logStateChange logs tunnel state changes to Windows Event Log.
func (h *HealthChecker) logStateChange(oldState, newState string) {
	msg := fmt.Sprintf("Machine Tunnel state changed: %s -> %s", oldState, newState)

	if h.degradedReason != "" && (newState == "degraded" || newState == "failed") {
		msg = fmt.Sprintf("%s (reason: %s)", msg, h.degradedReason)
	}

	// Log to Windows Event Log using existing infrastructure
	switch newState {
	case "healthy":
		if err := LogInfo(EventIDHealthStateHealthy, msg); err != nil {
			log.WithError(err).Debug("Failed to write Event Log entry")
		}
		log.Info(msg)
	case "degraded":
		if err := LogWarning(EventIDHealthStateDegraded, msg); err != nil {
			log.WithError(err).Debug("Failed to write Event Log entry")
		}
		log.Warn(msg)
	case "failed":
		if err := LogError(EventIDHealthStateFailed, msg); err != nil {
			log.WithError(err).Debug("Failed to write Event Log entry")
		}
		log.Error(msg)
	default:
		log.Info(msg)
	}
}
