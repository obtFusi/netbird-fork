package firewall

import (
	"testing"
	"time"
)

func TestDefaultADPorts(t *testing.T) {
	ports := DefaultADPorts()

	tests := []struct {
		name     string
		got      int
		expected int
	}{
		{"DNS", ports.DNS, 53},
		{"Kerberos", ports.Kerberos, 88},
		{"NTP", ports.NTP, 123},
		{"LDAP", ports.LDAP, 389},
		{"LDAPS", ports.LDAPS, 636},
		{"SMB", ports.SMB, 445},
		{"RPCEndpoint", ports.RPCEndpoint, 135},
		{"RPCDynamicStart", ports.RPCDynamicStart, 49152},
		{"RPCDynamicEnd", ports.RPCDynamicEnd, 65535},
		{"GlobalCatalog", ports.GlobalCatalog, 3268},
		{"GlobalCatalogSSL", ports.GlobalCatalogSSL, 3269},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestRestrictedRPCPorts(t *testing.T) {
	start, end := RestrictedRPCPorts()

	if start != 5000 {
		t.Errorf("RestrictedRPCPorts start = %d, want 5000", start)
	}

	if end != 5100 {
		t.Errorf("RestrictedRPCPorts end = %d, want 5100", end)
	}
}

func TestNewManager(t *testing.T) {
	tests := []struct {
		name    string
		config  *ManagerConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "empty DC IPs",
			config: &ManagerConfig{
				InterfaceName: "wg-nb-machine",
				DCIPs:         []string{},
			},
			wantErr: true,
		},
		{
			name: "invalid DC IP",
			config: &ManagerConfig{
				InterfaceName: "wg-nb-machine",
				DCIPs:         []string{"invalid-ip"},
			},
			wantErr: true,
		},
		{
			name: "valid config",
			config: &ManagerConfig{
				InterfaceName: "wg-nb-machine",
				DCIPs:         []string{"192.168.100.20"},
			},
			wantErr: false,
		},
		{
			name: "valid config with multiple DCs",
			config: &ManagerConfig{
				InterfaceName: "wg-nb-machine",
				DCIPs:         []string{"192.168.100.20", "192.168.100.21"},
			},
			wantErr: false,
		},
		{
			name: "valid config with default interface",
			config: &ManagerConfig{
				DCIPs: []string{"192.168.100.20"},
			},
			wantErr: false,
		},
		{
			name: "valid config with restricted RPC",
			config: &ManagerConfig{
				DCIPs:            []string{"192.168.100.20"},
				UseRestrictedRPC: true,
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

func TestManagerDefaultInterface(t *testing.T) {
	m, err := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if m.interfaceName != DefaultInterfaceName {
		t.Errorf("interface = %q, want %q", m.interfaceName, DefaultInterfaceName)
	}
}

func TestManagerRestrictedRPC(t *testing.T) {
	m, err := NewManager(&ManagerConfig{
		DCIPs:            []string{"192.168.100.20"},
		UseRestrictedRPC: true,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	expectedStart, expectedEnd := RestrictedRPCPorts()
	if m.adPorts.RPCDynamicStart != expectedStart {
		t.Errorf("RPCDynamicStart = %d, want %d", m.adPorts.RPCDynamicStart, expectedStart)
	}
	if m.adPorts.RPCDynamicEnd != expectedEnd {
		t.Errorf("RPCDynamicEnd = %d, want %d", m.adPorts.RPCDynamicEnd, expectedEnd)
	}
}

func TestManagerGetDCIPs(t *testing.T) {
	dcIPs := []string{"192.168.100.20", "192.168.100.21"}
	m, err := NewManager(&ManagerConfig{
		DCIPs: dcIPs,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	got := m.GetDCIPs()
	if len(got) != len(dcIPs) {
		t.Errorf("GetDCIPs() returned %d IPs, want %d", len(got), len(dcIPs))
	}

	// Verify it's a copy
	got[0] = "modified"
	original := m.GetDCIPs()
	if original[0] == "modified" {
		t.Error("GetDCIPs() should return a copy, not the original slice")
	}
}

func TestManagerGetCreatedRules(t *testing.T) {
	m, err := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// Initially empty
	rules := m.GetCreatedRules()
	if len(rules) != 0 {
		t.Errorf("GetCreatedRules() returned %d rules, want 0", len(rules))
	}
}

func TestBuildRule(t *testing.T) {
	m, _ := NewManager(&ManagerConfig{
		InterfaceName: "test-iface",
		DCIPs:         []string{"192.168.100.20"},
	})

	rule := m.buildRule("Test Rule", ProtocolTCP, "389", "192.168.100.20,192.168.100.21")

	if rule.Name != RuleNamePrefix+"Test Rule" {
		t.Errorf("rule.Name = %q, want %q", rule.Name, RuleNamePrefix+"Test Rule")
	}

	if rule.Group != RuleGroupName {
		t.Errorf("rule.Group = %q, want %q", rule.Group, RuleGroupName)
	}

	if rule.Direction != DirectionOutbound {
		t.Errorf("rule.Direction = %q, want %q", rule.Direction, DirectionOutbound)
	}

	if rule.Action != ActionAllow {
		t.Errorf("rule.Action = %q, want %q", rule.Action, ActionAllow)
	}

	if rule.Protocol != ProtocolTCP {
		t.Errorf("rule.Protocol = %q, want %q", rule.Protocol, ProtocolTCP)
	}

	if rule.RemotePorts != "389" {
		t.Errorf("rule.RemotePorts = %q, want %q", rule.RemotePorts, "389")
	}

	if rule.RemoteAddresses != "192.168.100.20,192.168.100.21" {
		t.Errorf("rule.RemoteAddresses = %q, want %q", rule.RemoteAddresses, "192.168.100.20,192.168.100.21")
	}

	if rule.InterfaceAlias != "test-iface" {
		t.Errorf("rule.InterfaceAlias = %q, want %q", rule.InterfaceAlias, "test-iface")
	}
}

func TestBuildADRules(t *testing.T) {
	m, _ := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})

	rules := m.buildADRules("192.168.100.20")

	// Count expected rules:
	// DNS (UDP + TCP) = 2
	// Kerberos (UDP + TCP) = 2
	// NTP (UDP) = 1
	// LDAP (TCP + UDP) = 2
	// LDAPS (TCP) = 1
	// SMB (TCP) = 1
	// RPC Endpoint (TCP) = 1
	// RPC Dynamic (TCP) = 1
	// Global Catalog (TCP) = 1
	// Global Catalog SSL (TCP) = 1
	// Total = 13
	expectedCount := 13

	if len(rules) != expectedCount {
		t.Errorf("buildADRules() returned %d rules, want %d", len(rules), expectedCount)
	}

	// Verify all rules have the correct group
	for _, rule := range rules {
		if rule.Group != RuleGroupName {
			t.Errorf("rule %q has group %q, want %q", rule.Name, rule.Group, RuleGroupName)
		}
	}
}

func TestEqualStringSlices(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{"both empty", []string{}, []string{}, true},
		{"both nil", nil, nil, true},
		{"equal", []string{"a", "b"}, []string{"a", "b"}, true},
		{"different length", []string{"a"}, []string{"a", "b"}, false},
		{"different content", []string{"a", "b"}, []string{"a", "c"}, false},
		{"different order", []string{"a", "b"}, []string{"b", "a"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := equalStringSlices(tt.a, tt.b); got != tt.want {
				t.Errorf("equalStringSlices(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestManagerClosedState(t *testing.T) {
	m, _ := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})

	// Close the manager
	m.closed = true

	// Configure should fail
	if err := m.Configure(); err == nil {
		t.Error("Configure() should return error when manager is closed")
	}

	// UpdateDCIPs should fail
	if err := m.UpdateDCIPs([]string{"192.168.100.21"}); err == nil {
		t.Error("UpdateDCIPs() should return error when manager is closed")
	}
}

func TestFirewallRuleTypes(t *testing.T) {
	// Test Protocol constants
	if ProtocolTCP != "TCP" {
		t.Errorf("ProtocolTCP = %q, want TCP", ProtocolTCP)
	}
	if ProtocolUDP != "UDP" {
		t.Errorf("ProtocolUDP = %q, want UDP", ProtocolUDP)
	}

	// Test Direction constants
	if DirectionInbound != "in" {
		t.Errorf("DirectionInbound = %q, want in", DirectionInbound)
	}
	if DirectionOutbound != "out" {
		t.Errorf("DirectionOutbound = %q, want out", DirectionOutbound)
	}

	// Test Action constants
	if ActionAllow != "allow" {
		t.Errorf("ActionAllow = %q, want allow", ActionAllow)
	}
	if ActionBlock != "block" {
		t.Errorf("ActionBlock = %q, want block", ActionBlock)
	}
}

func TestRuleNameConstants(t *testing.T) {
	if RuleGroupName != "NetBird Machine" {
		t.Errorf("RuleGroupName = %q, want 'NetBird Machine'", RuleGroupName)
	}

	if RuleNamePrefix != "NetBird Machine - " {
		t.Errorf("RuleNamePrefix = %q, want 'NetBird Machine - '", RuleNamePrefix)
	}

	if DefaultInterfaceName != "wg-nb-machine" {
		t.Errorf("DefaultInterfaceName = %q, want 'wg-nb-machine'", DefaultInterfaceName)
	}

	if DenyAllRuleName != "NetBird Machine - Deny All" {
		t.Errorf("DenyAllRuleName = %q, want 'NetBird Machine - Deny All'", DenyAllRuleName)
	}
}

func TestManagerDenyDefaultState(t *testing.T) {
	m, err := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// Initially deny-all should be disabled
	if m.IsDenyDefaultEnabled() {
		t.Error("Deny-default should be disabled initially")
	}
}

func TestManagerSafeModeConfig(t *testing.T) {
	callbackCalled := false

	m, err := NewManager(&ManagerConfig{
		DCIPs:           []string{"192.168.100.20"},
		SafeModeEnabled: true,
		SafeModeTimeout: 30 * time.Second,
		ConnectivityTestFunc: func() error {
			callbackCalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if !m.safeModeEnabled {
		t.Error("Safe mode should be enabled")
	}

	if m.safeModeTimeout != 30*time.Second {
		t.Errorf("safeModeTimeout = %v, want 30s", m.safeModeTimeout)
	}

	if m.connectivityTestFunc == nil {
		t.Error("Connectivity test func should be set")
	}

	_ = callbackCalled // Callback will be called during ConfigureWithDenyDefault
}

func TestManagerDefaultSafeModeTimeout(t *testing.T) {
	m, err := NewManager(&ManagerConfig{
		DCIPs:           []string{"192.168.100.20"},
		SafeModeEnabled: true,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if m.safeModeTimeout != DefaultSafeModeTimeout {
		t.Errorf("safeModeTimeout = %v, want %v", m.safeModeTimeout, DefaultSafeModeTimeout)
	}
}

func TestManagerSetConnectivityTestFunc(t *testing.T) {
	m, err := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if m.connectivityTestFunc != nil {
		t.Error("Connectivity test func should be nil initially")
	}

	testCalled := false
	m.SetConnectivityTestFunc(func() error {
		testCalled = true
		return nil
	})

	if m.connectivityTestFunc == nil {
		t.Error("Connectivity test func should be set after SetConnectivityTestFunc")
	}

	_ = testCalled
}

func TestManagerConfirmSafeMode(t *testing.T) {
	m, err := NewManager(&ManagerConfig{
		DCIPs:           []string{"192.168.100.20"},
		SafeModeEnabled: true,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// ConfirmSafeMode should not panic even when no safe mode is active
	m.ConfirmSafeMode()

	// Verify no panic with nil cancel func
	if m.safeModeCancel != nil {
		t.Error("safeModeCancel should be nil after ConfirmSafeMode")
	}
}

func TestManagerEnableDenyDefaultClosed(t *testing.T) {
	m, _ := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})

	m.closed = true

	if err := m.EnableDenyDefault(); err == nil {
		t.Error("EnableDenyDefault() should return error when manager is closed")
	}
}
