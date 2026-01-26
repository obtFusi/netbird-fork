// Machine Tunnel Fork - Stub for non-Windows platforms
// Machine Tunnel is Windows-only as it uses Windows Certificate Store and NRPT.

//go:build !windows

package tunnel

import (
	"context"
	"fmt"
)

// MachineTunnel is not supported on non-Windows platforms
type MachineTunnel struct{}

// MachineState is not used on non-Windows platforms
type MachineState int

const (
	StateDisconnected MachineState = iota
	StateConnecting
	StateConnected
	StateReconnecting
	StateError
)

func (s MachineState) String() string {
	return "unsupported"
}

// MachineTunnelConfig is not used on non-Windows platforms
type MachineTunnelConfig struct {
	ManagementURL string
}

// NewMachineTunnel returns an error on non-Windows platforms
func NewMachineTunnel(config *MachineTunnelConfig) (*MachineTunnel, error) {
	return nil, fmt.Errorf("machine tunnel is only supported on windows")
}

// DefaultConfig returns nil on non-Windows platforms
func DefaultConfig() *MachineTunnelConfig {
	return nil
}

// Start returns an error on non-Windows platforms
func (t *MachineTunnel) Start(ctx context.Context) error {
	return fmt.Errorf("machine tunnel is only supported on windows")
}

// Stop is a no-op on non-Windows platforms
func (t *MachineTunnel) Stop() error {
	return nil
}

// State returns StateError on non-Windows platforms
func (t *MachineTunnel) State() MachineState {
	return StateError
}

// Cleanup is a no-op on non-Windows platforms
func (t *MachineTunnel) Cleanup() error {
	return nil
}
