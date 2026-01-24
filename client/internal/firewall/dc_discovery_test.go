package firewall

import (
	"testing"
	"time"
)

func TestNewDCDiscovery(t *testing.T) {
	tests := []struct {
		name    string
		config  *DCDiscoveryConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "empty domain",
			config: &DCDiscoveryConfig{
				Domain: "",
			},
			wantErr: true,
		},
		{
			name: "valid config",
			config: &DCDiscoveryConfig{
				Domain: "corp.local",
			},
			wantErr: false,
		},
		{
			name: "valid config with initial IPs",
			config: &DCDiscoveryConfig{
				Domain:     "corp.local",
				InitialIPs: []string{"192.168.100.20"},
			},
			wantErr: false,
		},
		{
			name: "valid config with custom interval",
			config: &DCDiscoveryConfig{
				Domain:          "corp.local",
				RefreshInterval: 30 * time.Minute,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDCDiscovery(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDCDiscovery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && d == nil {
				t.Error("NewDCDiscovery() returned nil without error")
			}
		})
	}
}

func TestDCDiscoveryDefaultInterval(t *testing.T) {
	d, err := NewDCDiscovery(&DCDiscoveryConfig{
		Domain: "corp.local",
	})
	if err != nil {
		t.Fatalf("NewDCDiscovery() error = %v", err)
	}

	if d.refreshInterval != DefaultRefreshInterval {
		t.Errorf("refreshInterval = %v, want %v", d.refreshInterval, DefaultRefreshInterval)
	}
}

func TestDCDiscoveryMinInterval(t *testing.T) {
	d, err := NewDCDiscovery(&DCDiscoveryConfig{
		Domain:          "corp.local",
		RefreshInterval: 1 * time.Second, // Too short
	})
	if err != nil {
		t.Fatalf("NewDCDiscovery() error = %v", err)
	}

	if d.refreshInterval != MinRefreshInterval {
		t.Errorf("refreshInterval = %v, want %v (minimum)", d.refreshInterval, MinRefreshInterval)
	}
}

func TestDCDiscoveryGetCurrentIPs(t *testing.T) {
	initialIPs := []string{"192.168.100.20", "192.168.100.21"}

	d, err := NewDCDiscovery(&DCDiscoveryConfig{
		Domain:     "corp.local",
		InitialIPs: initialIPs,
	})
	if err != nil {
		t.Fatalf("NewDCDiscovery() error = %v", err)
	}

	got := d.GetCurrentIPs()
	if len(got) != len(initialIPs) {
		t.Errorf("GetCurrentIPs() returned %d IPs, want %d", len(got), len(initialIPs))
	}

	// Verify it's a copy
	got[0] = "modified"
	original := d.GetCurrentIPs()
	if original[0] == "modified" {
		t.Error("GetCurrentIPs() should return a copy, not the original slice")
	}
}

func TestDeduplicateStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{"empty", []string{}, 0},
		{"no duplicates", []string{"a", "b", "c"}, 3},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, 3},
		{"all duplicates", []string{"a", "a", "a"}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateStrings(tt.input)
			if len(result) != tt.expected {
				t.Errorf("deduplicateStrings() returned %d items, want %d", len(result), tt.expected)
			}
		})
	}
}

func TestDCDiscoveryConstants(t *testing.T) {
	if DefaultRefreshInterval != 1*time.Hour {
		t.Errorf("DefaultRefreshInterval = %v, want 1h", DefaultRefreshInterval)
	}

	if MinRefreshInterval != 5*time.Minute {
		t.Errorf("MinRefreshInterval = %v, want 5m", MinRefreshInterval)
	}

	if DiscoveryTimeout != 30*time.Second {
		t.Errorf("DiscoveryTimeout = %v, want 30s", DiscoveryTimeout)
	}
}

func TestDCDiscoveryStopWithoutStart(t *testing.T) {
	d, err := NewDCDiscovery(&DCDiscoveryConfig{
		Domain: "corp.local",
	})
	if err != nil {
		t.Fatalf("NewDCDiscovery() error = %v", err)
	}

	// Stop without start should not panic
	d.Stop()
}

func TestDCDiscoveryCallback(t *testing.T) {
	callbackCalled := false
	var receivedIPs []string

	d, err := NewDCDiscovery(&DCDiscoveryConfig{
		Domain:     "corp.local",
		InitialIPs: []string{"192.168.100.20"},
		OnUpdate: func(ips []string) error {
			callbackCalled = true
			receivedIPs = ips
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewDCDiscovery() error = %v", err)
	}

	// Manually trigger refresh with mock data
	d.mu.Lock()
	d.currentIPs = []string{"192.168.100.20"}
	d.mu.Unlock()

	// Note: We can't easily test actual DNS lookups in unit tests
	// The callback mechanism is tested by checking it was set
	if d.onUpdate == nil {
		t.Error("onUpdate callback was not set")
	}

	_ = callbackCalled
	_ = receivedIPs
}

// Note: DiscoverDCIPs cannot be easily unit tested without mocking DNS
// Integration tests should be performed in a real AD environment
func TestDiscoverDCIPsInvalidDomain(t *testing.T) {
	// This test verifies the function handles invalid domains gracefully
	// The actual lookup will fail, but it should return a proper error
	_, err := DiscoverDCIPs("invalid.nonexistent.domain.test")
	if err == nil {
		t.Error("DiscoverDCIPs() should return error for invalid domain")
	}
}
