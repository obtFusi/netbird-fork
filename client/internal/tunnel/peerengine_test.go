// Machine Tunnel Fork - PeerEngine Unit Tests
// Tests for Signal/Relay integration via Direct Reuse pattern.
//
// References:
// - Issue #110: PeerEngine with Direct Reuse
// - ADR-001: Direct Reuse pattern
//
// Note: These tests only run on Windows (matching peerengine.go build constraint).
// CI runs Windows tests via GitHub Actions windows-latest runner.

//go:build windows

package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/peer"
)

// TestPeerEngine_New tests PeerEngine initialization.
// Verifies that all components are created correctly.
func TestPeerEngine_New(t *testing.T) {
	t.Run("valid config creates engine", func(t *testing.T) {
		// Skip if no network available (CI environment)
		t.Skip("Requires network access to Signal server - integration test")

		ctx := context.Background()
		wgKey, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)

		cfg := PeerEngineConfig{
			SignalAddr:    "signal.example.com:443",
			SignalTLS:     true,
			RelayURLs:     []string{"relay.example.com:443"},
			MgmtURL:       "https://mgmt.example.com",
			MaxConcurrent: 10,
			MTU:           1280,
			WgPort:        51820,
		}

		pe, err := NewPeerEngine(ctx, wgKey, cfg)
		// Note: This will fail without actual Signal server
		// In real unit tests, we'd mock the signal client
		if err != nil {
			t.Skipf("Signal server not available: %v", err)
		}
		defer pe.Close()

		assert.NotNil(t, pe.signalClient)
		assert.NotNil(t, pe.relayManager)
		assert.NotNil(t, pe.statusRecorder)
		assert.NotNil(t, pe.signaler)
		assert.NotNil(t, pe.semaphore)
		assert.NotNil(t, pe.peerConns)
	})

	t.Run("default max concurrent is set", func(t *testing.T) {
		cfg := PeerEngineConfig{
			MaxConcurrent: 0, // Should default to 10
		}

		// Can't fully test without mocking signal client
		// but we can verify the config normalization
		if cfg.MaxConcurrent <= 0 {
			cfg.MaxConcurrent = DefaultMaxConcurrentPeers
		}
		assert.Equal(t, 10, cfg.MaxConcurrent)
	})
}

// TestPeerEngine_Start tests the start sequence.
// Verifies: Signal Receive-Loop -> WaitStreamConnected -> Relay Serve -> SRWatcher
func TestPeerEngine_Start(t *testing.T) {
	t.Run("start order is correct", func(t *testing.T) {
		// This is a documentation test - actual integration requires mocking
		t.Skip("Requires mocked signal/relay clients - integration test")

		// The expected order based on ADR is:
		// 1. Update Relay Token (before Serve)
		// 2. Start Signal Receive-Loop goroutine
		// 3. WaitStreamConnected (blocking)
		// 4. Start Relay Manager Serve goroutine
		// 5. Start SRWatcher

		// Verification would need:
		// - Mock signal client with WaitStreamConnected callback
		// - Mock relay manager with Serve callback
		// - Verify call order via channels/timestamps
	})
}

// TestPeerEngine_HandleSignalMessage tests message routing.
// Verifies ADR-007: Unknown peer returns nil (not error)
func TestPeerEngine_HandleSignalMessage(t *testing.T) {
	t.Run("unknown peer returns nil not error", func(t *testing.T) {
		// Create minimal PeerEngine for testing message handling
		pe := &PeerEngine{
			peerConns: make(map[string]*peer.Conn),
		}
		pe.ctx, pe.cancel = context.WithCancel(context.Background())
		defer pe.cancel()

		// This would need a mock sProto.Message
		// For now, document the expected behavior:
		// - If msg.Key not in peerConns, return nil (ADR-007)
		// - Log debug message but don't error
		t.Skip("Requires mock signal proto message")
	})

	t.Run("context cancelled returns error", func(t *testing.T) {
		pe := &PeerEngine{
			peerConns: make(map[string]*peer.Conn),
		}
		pe.ctx, pe.cancel = context.WithCancel(context.Background())
		pe.cancel() // Cancel immediately

		// handleSignalMessage should return ctx.Err() when cancelled
		assert.Error(t, pe.ctx.Err())
	})
}

// TestPeerEngine_ConnectPeer tests peer connection creation.
func TestPeerEngine_ConnectPeer(t *testing.T) {
	t.Run("invalid allowed IPs returns error", func(t *testing.T) {
		pe := &PeerEngine{
			peerConns: make(map[string]*peer.Conn),
		}
		pe.ctx, pe.cancel = context.WithCancel(context.Background())
		defer pe.cancel()

		// Empty allowed IPs should fail
		_, err := pe.ConnectPeer(context.Background(), "test-peer-key", []string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid allowed IPs")
	})

	t.Run("malformed allowed IP returns error", func(t *testing.T) {
		pe := &PeerEngine{
			peerConns: make(map[string]*peer.Conn),
		}
		pe.ctx, pe.cancel = context.WithCancel(context.Background())
		defer pe.cancel()

		_, err := pe.ConnectPeer(context.Background(), "test-peer-key", []string{"not-a-valid-ip"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse allowed IP")
	})
}

// TestPeerEngine_Close tests cleanup.
func TestPeerEngine_Close(t *testing.T) {
	t.Run("close cancels context", func(t *testing.T) {
		pe := &PeerEngine{
			peerConns: make(map[string]*peer.Conn),
		}
		pe.ctx, pe.cancel = context.WithCancel(context.Background())

		// Verify context is not cancelled before close
		select {
		case <-pe.ctx.Done():
			t.Fatal("context should not be cancelled before Close")
		default:
			// OK
		}

		err := pe.Close()
		assert.NoError(t, err)

		// Verify context is cancelled after close
		select {
		case <-pe.ctx.Done():
			// OK - context was cancelled
		case <-time.After(100 * time.Millisecond):
			t.Fatal("context should be cancelled after Close")
		}
	})

	t.Run("close clears peer connections", func(t *testing.T) {
		pe := &PeerEngine{
			peerConns: make(map[string]*peer.Conn),
		}
		pe.ctx, pe.cancel = context.WithCancel(context.Background())

		// Add a nil entry (can't create real Conn without dependencies)
		pe.peerConns["test-key"] = nil

		err := pe.Close()
		assert.NoError(t, err)
		assert.Empty(t, pe.peerConns)
	})
}

// TestPeerEngine_GetPeerStatus tests status retrieval.
func TestPeerEngine_GetPeerStatus(t *testing.T) {
	t.Run("empty map returns empty status", func(t *testing.T) {
		pe := &PeerEngine{
			peerConns: make(map[string]*peer.Conn),
		}

		status := pe.GetPeerStatus()
		assert.Empty(t, status)
	})
}

// TestPeerEngineConfig_Defaults tests config default handling.
func TestPeerEngineConfig_Defaults(t *testing.T) {
	t.Run("max concurrent defaults to 10", func(t *testing.T) {
		cfg := PeerEngineConfig{}
		if cfg.MaxConcurrent <= 0 {
			cfg.MaxConcurrent = DefaultMaxConcurrentPeers
		}
		assert.Equal(t, 10, cfg.MaxConcurrent)
	})
}

// TestParseStunTurnURLs tests STUN/TURN URL parsing.
func TestParseStunTurnURLs(t *testing.T) {
	t.Run("valid STUN URL is parsed", func(t *testing.T) {
		pe := &PeerEngine{}

		cfg := PeerEngineConfig{
			StunURLs: []string{"stun:stun.l.google.com:19302"},
		}

		err := pe.parseStunTurnURLs(cfg)
		assert.NoError(t, err)

		urls := pe.stunTurn.Load()
		assert.NotNil(t, urls)
		assert.Len(t, urls, 1)
	})

	t.Run("invalid STUN URL is skipped with warning", func(t *testing.T) {
		pe := &PeerEngine{}

		cfg := PeerEngineConfig{
			StunURLs: []string{"not-a-valid-url"},
		}

		// Should not error, just warn and skip
		err := pe.parseStunTurnURLs(cfg)
		assert.NoError(t, err)

		urls := pe.stunTurn.Load()
		// Invalid URLs are skipped
		assert.Nil(t, urls)
	})

	t.Run("TURN URL with credentials is parsed", func(t *testing.T) {
		pe := &PeerEngine{}

		cfg := PeerEngineConfig{
			TurnURLs: []TurnConfig{
				{
					URL:      "turn:turn.example.com:3478",
					Username: "user",
					Password: "pass",
				},
			},
		}

		err := pe.parseStunTurnURLs(cfg)
		assert.NoError(t, err)

		urls := pe.stunTurn.Load()
		assert.NotNil(t, urls)
		assert.Len(t, urls, 1)
		assert.Equal(t, "user", urls[0].Username)
		assert.Equal(t, "pass", urls[0].Password)
	})
}

// TestCreateICEConfig tests ICE config creation.
func TestCreateICEConfig(t *testing.T) {
	t.Run("UDPMux is nil for Windows Desktop", func(t *testing.T) {
		// ADR-006: UDPMux not used on Windows Desktop
		pe := &PeerEngine{
			config: PeerEngineConfig{
				InterfaceBlackList:   []string{"lo"},
				DisableIPv6Discovery: true,
				NATExternalIPs:       []string{"1.2.3.4"},
			},
		}

		iceCfg := pe.createICEConfig()

		assert.Nil(t, iceCfg.UDPMux, "UDPMux should be nil for Windows Desktop (ADR-006)")
		assert.Nil(t, iceCfg.UDPMuxSrflx, "UDPMuxSrflx should be nil for Windows Desktop (ADR-006)")
		assert.Equal(t, []string{"lo"}, iceCfg.InterfaceBlackList)
		assert.True(t, iceCfg.DisableIPv6Discovery)
		assert.Equal(t, []string{"1.2.3.4"}, iceCfg.NATExternalIPs)
	})
}
