// Machine Tunnel Fork - Core Machine Tunnel Logic
// This file contains the main orchestration for Windows pre-login VPN.

//go:build windows

package tunnel

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// MachineState represents the current state of the Machine Tunnel
type MachineState int

const (
	// StateDisconnected - tunnel is not running
	StateDisconnected MachineState = iota
	// StateConnecting - establishing connection to management server
	StateConnecting
	// StateConnected - tunnel is up and running
	StateConnected
	// StateReconnecting - lost connection, attempting to reconnect
	StateReconnecting
	// StateError - unrecoverable error state
	StateError
)

func (s MachineState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// MachineTunnel orchestrates the Windows pre-login VPN connection
type MachineTunnel struct {
	config *MachineTunnelConfig

	// State management
	state    MachineState
	stateMu  sync.RWMutex
	stateErr error

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Callbacks
	onStateChange func(MachineState, error)
}

// MachineTunnelConfig holds the configuration for Machine Tunnel
type MachineTunnelConfig struct {
	// ManagementURL is the URL of the NetBird management server (mTLS port)
	ManagementURL string

	// MachineCert contains machine certificate configuration
	MachineCert MachineCertConfig

	// InterfaceName is the WireGuard interface name (default: wg-nb-machine)
	InterfaceName string

	// ReconnectInterval is the base interval for reconnection attempts
	ReconnectInterval time.Duration

	// MaxReconnectInterval is the maximum backoff interval
	MaxReconnectInterval time.Duration

	// DNSServers is the list of DNS servers for NRPT rules (typically DC IPs)
	DNSServers []string

	// DNSNamespaces is the list of DNS namespaces for NRPT rules
	DNSNamespaces []string

	// AllowedDCIPs is the list of allowed DC IPs for firewall rules
	AllowedDCIPs []string
}

// DefaultConfig returns a MachineTunnelConfig with sensible defaults
func DefaultConfig() *MachineTunnelConfig {
	return &MachineTunnelConfig{
		InterfaceName:        "wg-nb-machine",
		ReconnectInterval:    5 * time.Second,
		MaxReconnectInterval: 5 * time.Minute,
		MachineCert: MachineCertConfig{
			RequiredEKU:  DefaultClientAuthEKU,
			SANMustMatch: true,
		},
	}
}

// NewMachineTunnel creates a new Machine Tunnel instance
func NewMachineTunnel(config *MachineTunnelConfig) (*MachineTunnel, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if config.ManagementURL == "" {
		return nil, fmt.Errorf("ManagementURL is required")
	}

	return &MachineTunnel{
		config: config,
		state:  StateDisconnected,
	}, nil
}

// SetStateChangeCallback sets a callback that is invoked on state changes
func (t *MachineTunnel) SetStateChangeCallback(cb func(MachineState, error)) {
	t.onStateChange = cb
}

// State returns the current tunnel state
func (t *MachineTunnel) State() MachineState {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.state
}

// StateError returns the error if state is StateError
func (t *MachineTunnel) StateError() error {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.stateErr
}

// setState updates the tunnel state and notifies callbacks
func (t *MachineTunnel) setState(state MachineState, err error) {
	t.stateMu.Lock()
	oldState := t.state
	t.state = state
	t.stateErr = err
	t.stateMu.Unlock()

	if oldState != state {
		log.WithFields(log.Fields{
			"old_state": oldState.String(),
			"new_state": state.String(),
			"error":     err,
		}).Info("Machine Tunnel state changed")

		if t.onStateChange != nil {
			t.onStateChange(state, err)
		}
	}
}

// Start begins the Machine Tunnel connection process
// This is non-blocking and runs the connection loop in a goroutine
func (t *MachineTunnel) Start(ctx context.Context) error {
	if t.State() != StateDisconnected {
		return fmt.Errorf("tunnel already started (state: %s)", t.State())
	}

	t.ctx, t.cancel = context.WithCancel(ctx)
	t.setState(StateConnecting, nil)

	t.wg.Add(1)
	go t.connectionLoop()

	return nil
}

// Stop gracefully stops the Machine Tunnel
func (t *MachineTunnel) Stop() error {
	if t.cancel != nil {
		t.cancel()
	}

	// Wait for connection loop to finish
	t.wg.Wait()

	t.setState(StateDisconnected, nil)
	log.Info("Machine Tunnel stopped")
	return nil
}

// connectionLoop is the main connection loop with reconnection logic
func (t *MachineTunnel) connectionLoop() {
	defer t.wg.Done()

	reconnectInterval := t.config.ReconnectInterval

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		err := t.connect()
		if err == nil {
			// Connection successful, reset backoff
			reconnectInterval = t.config.ReconnectInterval
			t.setState(StateConnected, nil)

			// Wait for connection to be terminated
			t.maintainConnection()

			// If context is done, exit
			select {
			case <-t.ctx.Done():
				return
			default:
			}

			// Otherwise, attempt reconnect
			t.setState(StateReconnecting, nil)
		} else {
			log.WithError(err).Warn("Machine Tunnel connection failed")

			// Exponential backoff
			select {
			case <-t.ctx.Done():
				return
			case <-time.After(reconnectInterval):
			}

			reconnectInterval = min(reconnectInterval*2, t.config.MaxReconnectInterval)
		}
	}
}

// connect establishes the Machine Tunnel connection
// This includes:
// 1. Loading machine certificate from Windows store
// 2. Connecting to management server via mTLS
// 3. Registering as machine peer
// 4. Setting up WireGuard interface
// 5. Configuring NRPT and firewall rules
func (t *MachineTunnel) connect() error {
	log.Info("Machine Tunnel connecting...")

	// TODO: Implement in subsequent tasks (T-4.2 through T-4.6)
	// This is the skeleton that will be filled in by other tasks:
	//
	// Step 1: Load machine certificate (T-4.2)
	// cert, err := t.loadMachineCertificate()
	//
	// Step 2: Connect to management server (T-4.3)
	// client, err := t.connectToManagement(cert)
	//
	// Step 3: Register as machine peer
	// config, err := client.RegisterMachinePeer(...)
	//
	// Step 4: Setup WireGuard interface (T-4.9)
	// err = t.setupInterface(config)
	//
	// Step 5: Configure NRPT (T-4.4, T-4.4a)
	// err = t.configureNRPT()
	//
	// Step 6: Configure firewall (T-4.5, T-4.5a, T-4.6)
	// err = t.configureFirewall()

	// For now, return error indicating not implemented
	return fmt.Errorf("connection not yet implemented - pending T-4.2 through T-4.6")
}

// maintainConnection monitors the connection and handles keepalives
func (t *MachineTunnel) maintainConnection() {
	// TODO: Implement connection maintenance
	// - WireGuard keepalives
	// - Management server sync
	// - Health checks

	// For now, just block until context is done
	<-t.ctx.Done()
}

// Cleanup removes NRPT rules, firewall rules, and WireGuard interface
func (t *MachineTunnel) Cleanup() error {
	log.Info("Machine Tunnel cleanup...")

	// TODO: Implement in subsequent tasks
	// - Remove NRPT rules (T-4.4)
	// - Remove firewall rules (T-4.5, T-4.6)
	// - Remove WireGuard interface (T-4.9)

	return nil
}
