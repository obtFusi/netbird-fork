package ntp

import (
	"context"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name    string
		config  *ManagerConfig
		wantErr bool
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "empty config uses defaults",
			config:  &ManagerConfig{},
			wantErr: false,
		},
		{
			name: "valid config with custom max drift",
			config: &ManagerConfig{
				MaxDrift: 5 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "valid config with trusted NTP server",
			config: &ManagerConfig{
				PublicNTPServer: "time.nist.gov",
			},
			wantErr: false,
		},
		{
			name: "invalid untrusted NTP server",
			config: &ManagerConfig{
				PublicNTPServer: "untrusted.ntp.server",
			},
			wantErr: true,
		},
		{
			name: "valid config with DC IP",
			config: &ManagerConfig{
				DCIP: "192.168.100.20",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewManager(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && m == nil {
				t.Error("NewManager() returned nil manager without error")
			}
		})
	}
}

func TestManagerDefaults(t *testing.T) {
	m, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if m.maxDrift != DefaultMaxDrift {
		t.Errorf("maxDrift = %v, want %v", m.maxDrift, DefaultMaxDrift)
	}

	if m.syncTimeout != DefaultSyncTimeout {
		t.Errorf("syncTimeout = %v, want %v", m.syncTimeout, DefaultSyncTimeout)
	}

	if m.publicNTPServer != TrustedNTPServers[0] {
		t.Errorf("publicNTPServer = %q, want %q", m.publicNTPServer, TrustedNTPServers[0])
	}

	if m.currentPhase != PhasePreTunnel {
		t.Errorf("currentPhase = %v, want %v", m.currentPhase, PhasePreTunnel)
	}
}

func TestPhaseString(t *testing.T) {
	tests := []struct {
		phase    Phase
		expected string
	}{
		{PhasePreTunnel, "pre-tunnel"},
		{PhasePreJoin, "pre-join"},
		{PhasePostJoin, "post-join"},
		{Phase(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.phase.String(); got != tt.expected {
				t.Errorf("Phase.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestIsTrustedNTPServer(t *testing.T) {
	tests := []struct {
		server   string
		expected bool
	}{
		{"time.windows.com", true},
		{"time.nist.gov", true},
		{"pool.ntp.org", true},
		{"0.pool.ntp.org", true},
		{"1.pool.ntp.org", true},
		{"2.pool.ntp.org", true},
		{"3.pool.ntp.org", true},
		{"untrusted.server.com", false},
		{"malicious.ntp.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.server, func(t *testing.T) {
			if got := IsTrustedNTPServer(tt.server); got != tt.expected {
				t.Errorf("IsTrustedNTPServer(%q) = %v, want %v", tt.server, got, tt.expected)
			}
		})
	}
}

func TestGetDefaultNTPServer(t *testing.T) {
	expected := "time.windows.com"
	if got := GetDefaultNTPServer(); got != expected {
		t.Errorf("GetDefaultNTPServer() = %q, want %q", got, expected)
	}
}

func TestManagerGetCurrentPhase(t *testing.T) {
	m, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if phase := m.GetCurrentPhase(); phase != PhasePreTunnel {
		t.Errorf("GetCurrentPhase() = %v, want %v", phase, PhasePreTunnel)
	}
}

func TestManagerClose(t *testing.T) {
	m, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// First close should succeed
	if err := m.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Second close should also succeed (idempotent)
	if err := m.Close(); err != nil {
		t.Errorf("Close() second call error = %v", err)
	}

	// Operations should fail after close
	ctx := context.Background()
	if err := m.EnsureTimeSync(ctx); err == nil {
		t.Error("EnsureTimeSync() should fail after Close()")
	}
}

func TestManagerSwitchToDC(t *testing.T) {
	m, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// Empty DC IP should fail
	if err := m.SwitchToDC(""); err == nil {
		t.Error("SwitchToDC() should fail with empty DC IP")
	}

	// Valid DC IP should update phase (actual switch will fail on non-Windows)
	_ = m.SwitchToDC("192.168.100.20")
	// On non-Windows, this will fail, but phase should not change
	// On Windows, it would succeed and change the phase
}

func TestManagerSwitchToDCClosed(t *testing.T) {
	m, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	m.Close()

	if err := m.SwitchToDC("192.168.100.20"); err == nil {
		t.Error("SwitchToDC() should fail when manager is closed")
	}
}

func TestManagerSwitchToDomainHierarchyClosed(t *testing.T) {
	m, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	m.Close()

	if err := m.SwitchToDomainHierarchy(); err == nil {
		t.Error("SwitchToDomainHierarchy() should fail when manager is closed")
	}
}

func TestConstants(t *testing.T) {
	if DefaultMaxDrift != 2*time.Minute {
		t.Errorf("DefaultMaxDrift = %v, want 2m", DefaultMaxDrift)
	}

	if KerberosMaxDrift != 5*time.Minute {
		t.Errorf("KerberosMaxDrift = %v, want 5m", KerberosMaxDrift)
	}

	if TLSWarningDrift != 3*time.Minute {
		t.Errorf("TLSWarningDrift = %v, want 3m", TLSWarningDrift)
	}

	if DefaultSyncTimeout != 30*time.Second {
		t.Errorf("DefaultSyncTimeout = %v, want 30s", DefaultSyncTimeout)
	}
}

func TestTrustedNTPServersNotEmpty(t *testing.T) {
	if len(TrustedNTPServers) == 0 {
		t.Error("TrustedNTPServers should not be empty")
	}

	// Verify first server is time.windows.com (default)
	if TrustedNTPServers[0] != "time.windows.com" {
		t.Errorf("TrustedNTPServers[0] = %q, want 'time.windows.com'", TrustedNTPServers[0])
	}
}
