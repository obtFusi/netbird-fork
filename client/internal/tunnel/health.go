// Machine Tunnel Fork - Health Check
// This file provides health monitoring for the Machine Tunnel.
//
// Platform-specific Event Log integration is in:
// - health_windows.go (Windows Event Log)
// - health_other.go (stub for non-Windows)

package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
)

const (
	// DefaultHealthCheckInterval is the default interval between health checks
	DefaultHealthCheckInterval = 30 * time.Second

	// DefaultHandshakeTimeout is the maximum age of the last WireGuard handshake
	DefaultHandshakeTimeout = 2 * time.Minute

	// DefaultGRPCPingTimeout is the timeout for gRPC keepalive ping
	DefaultGRPCPingTimeout = 10 * time.Second

	// DefaultConsecutiveFailures is the number of consecutive failures before triggering reconnect
	DefaultConsecutiveFailures = 3
)

// HealthStatus represents the current health status
type HealthStatus int

const (
	// HealthStatusUnknown indicates unknown health status
	HealthStatusUnknown HealthStatus = iota

	// HealthStatusHealthy indicates all checks pass
	HealthStatusHealthy

	// HealthStatusDegraded indicates some checks fail but tunnel is functional
	HealthStatusDegraded

	// HealthStatusUnhealthy indicates tunnel is not functional
	HealthStatusUnhealthy
)

func (s HealthStatus) String() string {
	switch s {
	case HealthStatusUnknown:
		return "unknown"
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusDegraded:
		return "degraded"
	case HealthStatusUnhealthy:
		return "unhealthy"
	default:
		return "invalid"
	}
}

// PeerHealth represents the health status of a single peer connection.
type PeerHealth struct {
	PeerKey    string    `json:"peer_key"`
	Connected  bool      `json:"connected"`
	UseRelay   bool      `json:"use_relay"`
	LastSeen   time.Time `json:"last_seen"`
	FailReason string    `json:"fail_reason,omitempty"`
}

// Health represents the aggregated health status of the tunnel.
// Named "Health" instead of "TunnelHealth" to avoid repetition (tunnel.Health vs tunnel.TunnelHealth).
type Health struct {
	State     string       `json:"state"` // "healthy", "degraded", "failed", "unknown"
	PeerCount int          `json:"peer_count"`
	Connected int          `json:"connected"`
	Degraded  int          `json:"degraded"`
	Peers     []PeerHealth `json:"peers"`
}

// HealthCheckConfig configures the health check behavior
type HealthCheckConfig struct {
	// Interval is the time between health checks
	Interval time.Duration

	// HandshakeTimeout is the maximum age of the last WireGuard handshake
	HandshakeTimeout time.Duration

	// GRPCPingTimeout is the timeout for gRPC keepalive ping
	GRPCPingTimeout time.Duration

	// ConsecutiveFailures is the number of failures before triggering reconnect
	ConsecutiveFailures int

	// InterfaceName is the WireGuard interface name to monitor
	InterfaceName string
}

// DefaultHealthCheckConfig returns the default health check configuration
func DefaultHealthCheckConfig() HealthCheckConfig {
	return HealthCheckConfig{
		Interval:            DefaultHealthCheckInterval,
		HandshakeTimeout:    DefaultHandshakeTimeout,
		GRPCPingTimeout:     DefaultGRPCPingTimeout,
		ConsecutiveFailures: DefaultConsecutiveFailures,
	}
}

// HealthCheckResult contains the result of a health check
type HealthCheckResult struct {
	Status       HealthStatus
	Timestamp    time.Time
	InterfaceUp  bool
	GRPCAlive    bool
	HandshakeOK  bool
	LastError    error
	CheckDetails map[string]string
}

// HealthChecker performs periodic health checks on the tunnel
type HealthChecker struct {
	mu sync.RWMutex

	config HealthCheckConfig

	// consecutiveFailures tracks the number of consecutive health check failures
	consecutiveFailures int

	// lastResult is the result of the most recent health check
	lastResult *HealthCheckResult

	// degradedReason stores the reason for degraded state
	degradedReason string

	// currentState stores the current tunnel state for change detection
	currentState string

	// statusRecorder provides per-peer connection status
	statusRecorder *peer.Status

	// peerKeys stores the list of peer keys to monitor
	peerKeys []string

	// onUnhealthy is called when the tunnel becomes unhealthy
	onUnhealthy func()

	// interfaceChecker checks if the WireGuard interface is up
	interfaceChecker func() (bool, error)

	// grpcChecker checks if the gRPC connection is alive
	grpcChecker func(ctx context.Context) error

	// handshakeChecker checks if the last handshake is recent
	handshakeChecker func() (time.Time, error)

	// stopCh signals when to stop the health check loop
	stopCh chan struct{}

	// running indicates if the health check loop is running
	running bool
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(config HealthCheckConfig) *HealthChecker {
	if config.Interval == 0 {
		config.Interval = DefaultHealthCheckInterval
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if config.GRPCPingTimeout == 0 {
		config.GRPCPingTimeout = DefaultGRPCPingTimeout
	}
	if config.ConsecutiveFailures == 0 {
		config.ConsecutiveFailures = DefaultConsecutiveFailures
	}

	return &HealthChecker{
		config: config,
		stopCh: make(chan struct{}),
	}
}

// SetOnUnhealthy sets the callback function called when tunnel becomes unhealthy
func (h *HealthChecker) SetOnUnhealthy(callback func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onUnhealthy = callback
}

// SetInterfaceChecker sets the function to check interface status
func (h *HealthChecker) SetInterfaceChecker(checker func() (bool, error)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.interfaceChecker = checker
}

// SetGRPCChecker sets the function to check gRPC connection
func (h *HealthChecker) SetGRPCChecker(checker func(ctx context.Context) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.grpcChecker = checker
}

// SetHandshakeChecker sets the function to check last handshake time
func (h *HealthChecker) SetHandshakeChecker(checker func() (time.Time, error)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handshakeChecker = checker
}

// SetStatusRecorder sets the peer status recorder for detailed health status.
func (h *HealthChecker) SetStatusRecorder(recorder *peer.Status) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.statusRecorder = recorder
}

// SetPeerKeys sets the list of peer keys to monitor.
func (h *HealthChecker) SetPeerKeys(keys []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.peerKeys = keys
}

// GetDetailedStatus returns aggregated health status from all monitored peers.
func (h *HealthChecker) GetDetailedStatus() Health {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.statusRecorder == nil || len(h.peerKeys) == 0 {
		return Health{State: "unknown"}
	}

	health := Health{
		PeerCount: len(h.peerKeys),
		Peers:     make([]PeerHealth, 0, len(h.peerKeys)),
	}

	for _, key := range h.peerKeys {
		state, err := h.statusRecorder.GetPeer(key)
		ph := PeerHealth{
			PeerKey: key[:8] + "...", // Truncated for privacy
		}

		if err != nil {
			ph.FailReason = err.Error()
			health.Degraded++
		} else {
			ph.Connected = state.ConnStatus == peer.StatusConnected
			ph.UseRelay = state.Relayed
			ph.LastSeen = state.LastWireguardHandshake

			if ph.Connected {
				health.Connected++
			} else {
				health.Degraded++
				// ConnStatus is an int, use String() for message
				ph.FailReason = state.ConnStatus.String()
			}
		}

		health.Peers = append(health.Peers, ph)
	}

	// Determine overall state
	switch {
	case health.Connected == health.PeerCount && health.PeerCount > 0:
		health.State = "healthy"
	case health.Connected > 0:
		health.State = "degraded"
	case health.PeerCount > 0:
		health.State = "failed"
	default:
		health.State = "unknown"
	}

	return health
}

// SetDegraded marks the tunnel as degraded with a reason and logs the state change.
func (h *HealthChecker) SetDegraded(reason string) {
	h.mu.Lock()
	oldState := h.currentState
	h.currentState = "degraded"
	h.degradedReason = reason
	h.mu.Unlock()

	if oldState != "degraded" {
		h.logStateChange(oldState, "degraded")
	}
}

// Start begins the health check loop
func (h *HealthChecker) Start(ctx context.Context) error {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return fmt.Errorf("health checker already running")
	}
	h.running = true
	h.stopCh = make(chan struct{})
	h.mu.Unlock()

	go h.healthCheckLoop(ctx)
	return nil
}

// Stop stops the health check loop
func (h *HealthChecker) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return
	}

	close(h.stopCh)
	h.running = false
}

// Check performs a single health check and stores the result
func (h *HealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Timestamp:    time.Now(),
		Status:       HealthStatusHealthy,
		CheckDetails: make(map[string]string),
	}

	h.mu.RLock()
	interfaceChecker := h.interfaceChecker
	grpcChecker := h.grpcChecker
	handshakeChecker := h.handshakeChecker
	h.mu.RUnlock()

	defer func() {
		h.mu.Lock()
		h.lastResult = &result
		h.mu.Unlock()
	}()

	// Check 1: Interface status
	if interfaceChecker != nil {
		up, err := interfaceChecker()
		result.InterfaceUp = up
		switch {
		case err != nil:
			result.CheckDetails["interface"] = fmt.Sprintf("error: %v", err)
			result.Status = HealthStatusUnhealthy
			result.LastError = err
		case !up:
			result.CheckDetails["interface"] = "down"
			result.Status = HealthStatusUnhealthy
		default:
			result.CheckDetails["interface"] = "up"
		}
	} else {
		result.InterfaceUp = true
		result.CheckDetails["interface"] = "not configured"
	}

	// Check 2: gRPC connection
	if grpcChecker != nil {
		pingCtx, cancel := context.WithTimeout(ctx, h.config.GRPCPingTimeout)
		err := grpcChecker(pingCtx)
		cancel()

		result.GRPCAlive = err == nil
		if err != nil {
			result.CheckDetails["grpc"] = fmt.Sprintf("error: %v", err)
			if result.Status == HealthStatusHealthy {
				result.Status = HealthStatusDegraded
			}
			result.LastError = err
		} else {
			result.CheckDetails["grpc"] = "alive"
		}
	} else {
		result.GRPCAlive = true
		result.CheckDetails["grpc"] = "not configured"
	}

	// Check 3: Last handshake
	if handshakeChecker != nil {
		lastHandshake, err := handshakeChecker()
		if err != nil {
			result.CheckDetails["handshake"] = fmt.Sprintf("error: %v", err)
			result.HandshakeOK = false
		} else {
			age := time.Since(lastHandshake)
			result.HandshakeOK = age < h.config.HandshakeTimeout
			if !result.HandshakeOK {
				result.CheckDetails["handshake"] = fmt.Sprintf("stale (age: %v)", age)
				if result.Status == HealthStatusHealthy {
					result.Status = HealthStatusDegraded
				}
			} else {
				result.CheckDetails["handshake"] = fmt.Sprintf("ok (age: %v)", age)
			}
		}
	} else {
		result.HandshakeOK = true
		result.CheckDetails["handshake"] = "not configured"
	}

	return result
}

// GetLastResult returns the most recent health check result
func (h *HealthChecker) GetLastResult() *HealthCheckResult {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.lastResult == nil {
		return nil
	}

	// Return a copy
	result := *h.lastResult
	return &result
}

// GetStatus returns the current health status
func (h *HealthChecker) GetStatus() HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.lastResult == nil {
		return HealthStatusUnknown
	}
	return h.lastResult.Status
}

// healthCheckLoop is the main health check loop
func (h *HealthChecker) healthCheckLoop(ctx context.Context) {
	log.Info("Health check loop started")

	ticker := time.NewTicker(h.config.Interval)
	defer ticker.Stop()

	// Initial check
	h.performCheck(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Info("Health check loop stopped (context cancelled)")
			return
		case <-h.stopCh:
			log.Info("Health check loop stopped")
			return
		case <-ticker.C:
			h.performCheck(ctx)
		}
	}
}

// performCheck performs a health check and handles the result
func (h *HealthChecker) performCheck(ctx context.Context) {
	result := h.Check(ctx)

	h.mu.Lock()
	h.lastResult = &result

	if result.Status == HealthStatusUnhealthy {
		h.consecutiveFailures++
		log.WithFields(log.Fields{
			"status":              result.Status,
			"consecutiveFailures": h.consecutiveFailures,
			"threshold":           h.config.ConsecutiveFailures,
			"details":             result.CheckDetails,
		}).Warn("Health check failed")

		if h.consecutiveFailures >= h.config.ConsecutiveFailures {
			callback := h.onUnhealthy
			h.mu.Unlock()

			log.Error("Consecutive health check failures exceeded threshold, triggering reconnect")
			if callback != nil {
				callback()
			}
			return
		}
	} else {
		if h.consecutiveFailures > 0 {
			log.WithFields(log.Fields{
				"status":              result.Status,
				"previousFailures":    h.consecutiveFailures,
			}).Info("Health check recovered")
		}
		h.consecutiveFailures = 0
	}
	h.mu.Unlock()

	log.WithFields(log.Fields{
		"status":  result.Status,
		"details": result.CheckDetails,
	}).Debug("Health check completed")
}

// CheckInterface is a helper function to check if a network interface is up
func CheckInterface(name string) (bool, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false, fmt.Errorf("interface not found: %w", err)
	}

	return iface.Flags&net.FlagUp != 0, nil
}
