// Machine Tunnel Fork - NTP Synchronization
// This file provides NTP synchronization to solve the chicken-and-egg problem:
// - TLS/Kerberos need correct time
// - Time sync might need tunnel access
// Solution: Sync to Public NTP BEFORE tunnel start, then switch to DC after tunnel

package ntp

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultMaxDrift is the maximum acceptable time drift before forcing sync
	DefaultMaxDrift = 2 * time.Minute

	// KerberosMaxDrift is the Kerberos tolerance (5 minutes)
	KerberosMaxDrift = 5 * time.Minute

	// TLSWarningDrift is the threshold for TLS warning
	TLSWarningDrift = 3 * time.Minute

	// DefaultSyncTimeout is the timeout for NTP sync operations
	DefaultSyncTimeout = 30 * time.Second
)

// Phase represents the NTP sync phase
type Phase int

const (
	// PhasePreTunnel - Before tunnel, sync to public NTP
	PhasePreTunnel Phase = iota

	// PhasePreJoin - Tunnel up, before domain join, sync to DC
	PhasePreJoin

	// PhasePostJoin - After domain join, use domain hierarchy
	PhasePostJoin
)

func (p Phase) String() string {
	switch p {
	case PhasePreTunnel:
		return "pre-tunnel"
	case PhasePreJoin:
		return "pre-join"
	case PhasePostJoin:
		return "post-join"
	default:
		return "unknown"
	}
}

// TrustedNTPServers is the allowlist of trusted public NTP servers
var TrustedNTPServers = []string{
	"time.windows.com",
	"time.nist.gov",
	"pool.ntp.org",
	"0.pool.ntp.org",
	"1.pool.ntp.org",
	"2.pool.ntp.org",
	"3.pool.ntp.org",
}

// Manager manages NTP synchronization for the Machine Tunnel
type Manager struct {
	mu sync.Mutex

	// currentPhase is the current NTP sync phase
	currentPhase Phase

	// maxDrift is the maximum acceptable time drift
	maxDrift time.Duration

	// syncTimeout is the timeout for sync operations
	syncTimeout time.Duration

	// publicNTPServer is the public NTP server for pre-tunnel sync
	publicNTPServer string

	// dcIP is the Domain Controller IP for post-tunnel sync
	dcIP string

	// closed indicates if the manager has been closed
	closed bool
}

// ManagerConfig configures the NTP manager
type ManagerConfig struct {
	// MaxDrift is the maximum acceptable time drift before forcing sync
	MaxDrift time.Duration

	// SyncTimeout is the timeout for sync operations
	SyncTimeout time.Duration

	// PublicNTPServer is the preferred public NTP server
	// Must be in TrustedNTPServers list or empty for default
	PublicNTPServer string

	// DCIP is the Domain Controller IP for post-tunnel sync
	DCIP string
}

// NewManager creates a new NTP manager
func NewManager(config *ManagerConfig) (*Manager, error) {
	if config == nil {
		config = &ManagerConfig{}
	}

	maxDrift := config.MaxDrift
	if maxDrift == 0 {
		maxDrift = DefaultMaxDrift
	}

	syncTimeout := config.SyncTimeout
	if syncTimeout == 0 {
		syncTimeout = DefaultSyncTimeout
	}

	publicNTPServer := config.PublicNTPServer
	if publicNTPServer == "" {
		publicNTPServer = TrustedNTPServers[0] // time.windows.com
	} else {
		// Verify server is in trusted list
		trusted := false
		for _, server := range TrustedNTPServers {
			if server == publicNTPServer {
				trusted = true
				break
			}
		}
		if !trusted {
			return nil, fmt.Errorf("NTP server %q not in trusted list", publicNTPServer)
		}
	}

	return &Manager{
		currentPhase:    PhasePreTunnel,
		maxDrift:        maxDrift,
		syncTimeout:     syncTimeout,
		publicNTPServer: publicNTPServer,
		dcIP:            config.DCIP,
	}, nil
}

// EnsureTimeSync ensures time is synchronized before tunnel start
// This is called during service startup, BEFORE mTLS authentication
func (m *Manager) EnsureTimeSync(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("NTP manager is closed")
	}

	log.WithField("phase", m.currentPhase).Info("Checking time synchronization")

	// Get current time offset from public NTP
	offset, err := m.getTimeOffset(ctx, m.publicNTPServer)
	if err != nil {
		// Not fatal - log warning and continue
		log.WithError(err).Warn("Failed to check time offset from public NTP")
		return nil
	}

	absOffset := time.Duration(math.Abs(float64(offset)))

	log.WithFields(log.Fields{
		"offset_seconds": offset.Seconds(),
		"max_drift":      m.maxDrift,
		"server":         m.publicNTPServer,
	}).Debug("Time offset check complete")

	// Check thresholds
	if absOffset > KerberosMaxDrift {
		log.WithField("offset", offset).Error("Time drift exceeds Kerberos tolerance! TLS/Kerberos will fail!")
	} else if absOffset > TLSWarningDrift {
		log.WithField("offset", offset).Warn("Time drift exceeds TLS warning threshold")
	}

	// Force sync if beyond max drift
	if absOffset > m.maxDrift {
		log.WithField("offset", offset).Info("Time drift exceeds threshold, forcing sync")
		if err := m.forceSync(ctx); err != nil {
			log.WithError(err).Warn("Failed to force time sync")
			return fmt.Errorf("time sync failed: %w", err)
		}
		log.Info("Time sync completed successfully")
	} else {
		log.WithField("offset", offset).Debug("Time drift within acceptable range")
	}

	return nil
}

// getTimeOffset gets the time offset from an NTP server
func (m *Manager) getTimeOffset(ctx context.Context, server string) (time.Duration, error) {
	return getTimeOffsetImpl(ctx, server, m.syncTimeout)
}

// forceSync forces time synchronization
func (m *Manager) forceSync(ctx context.Context) error {
	return forceSyncImpl(ctx, m.syncTimeout)
}

// SwitchToDC switches NTP source to Domain Controller
// Called after tunnel is up, before domain join
func (m *Manager) SwitchToDC(dcIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("NTP manager is closed")
	}

	if dcIP == "" {
		return fmt.Errorf("DC IP is required")
	}

	m.dcIP = dcIP
	m.currentPhase = PhasePreJoin

	log.WithFields(log.Fields{
		"dc_ip": dcIP,
		"phase": m.currentPhase,
	}).Info("Switching NTP source to Domain Controller")

	return switchToManualPeerImpl(dcIP)
}

// SwitchToDomainHierarchy switches NTP to domain hierarchy
// Called after domain join is complete
func (m *Manager) SwitchToDomainHierarchy() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("NTP manager is closed")
	}

	m.currentPhase = PhasePostJoin

	log.WithField("phase", m.currentPhase).Info("Switching NTP to domain hierarchy")

	return switchToDomainHierarchyImpl()
}

// GetCurrentPhase returns the current NTP sync phase
func (m *Manager) GetCurrentPhase() Phase {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentPhase
}

// GetTimeOffset returns the current time offset from the configured source
func (m *Manager) GetTimeOffset(ctx context.Context) (time.Duration, error) {
	m.mu.Lock()
	server := m.publicNTPServer
	if m.currentPhase != PhasePreTunnel && m.dcIP != "" {
		server = m.dcIP
	}
	timeout := m.syncTimeout
	m.mu.Unlock()

	return getTimeOffsetImpl(ctx, server, timeout)
}

// Close closes the NTP manager
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	log.Info("NTP manager closed")
	return nil
}

// IsTrustedNTPServer checks if a server is in the trusted NTP server list
func IsTrustedNTPServer(server string) bool {
	for _, trusted := range TrustedNTPServers {
		if trusted == server {
			return true
		}
	}
	return false
}

// GetDefaultNTPServer returns the default public NTP server
func GetDefaultNTPServer() string {
	return TrustedNTPServers[0]
}
