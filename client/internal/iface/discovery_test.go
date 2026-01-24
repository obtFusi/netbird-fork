package iface

import (
	"testing"
	"time"
)

func TestDefaultDiscoveryConfig(t *testing.T) {
	config := DefaultDiscoveryConfig()

	if config.NamePrefix != DefaultInterfacePrefix {
		t.Errorf("NamePrefix = %q, want %q", config.NamePrefix, DefaultInterfacePrefix)
	}

	if config.DescriptionPattern != DefaultInterfaceDescription {
		t.Errorf("DescriptionPattern = %q, want %q", config.DescriptionPattern, DefaultInterfaceDescription)
	}

	if config.Retries != DefaultDiscoveryRetries {
		t.Errorf("Retries = %d, want %d", config.Retries, DefaultDiscoveryRetries)
	}

	if config.InitialBackoff != DefaultDiscoveryBackoff {
		t.Errorf("InitialBackoff = %v, want %v", config.InitialBackoff, DefaultDiscoveryBackoff)
	}

	if config.MaxBackoff != DefaultDiscoveryMaxBackoff {
		t.Errorf("MaxBackoff = %v, want %v", config.MaxBackoff, DefaultDiscoveryMaxBackoff)
	}
}

func TestNewDiscovery(t *testing.T) {
	tests := []struct {
		name   string
		config DiscoveryConfig
	}{
		{
			name:   "default config",
			config: DefaultDiscoveryConfig(),
		},
		{
			name: "zero values get defaults",
			config: DiscoveryConfig{
				NamePrefix:         "",
				DescriptionPattern: "",
				Retries:            0,
				InitialBackoff:     0,
				MaxBackoff:         0,
			},
		},
		{
			name: "custom config",
			config: DiscoveryConfig{
				NamePrefix:         "custom-",
				DescriptionPattern: "Custom*",
				GUID:               "{12345678-1234-1234-1234-123456789ABC}",
				Retries:            5,
				InitialBackoff:     1 * time.Second,
				MaxBackoff:         10 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDiscovery(tt.config)
			if d == nil {
				t.Error("NewDiscovery returned nil")
			}
		})
	}
}

func TestDiscoveryGetCurrentInterface(t *testing.T) {
	d := NewDiscovery(DefaultDiscoveryConfig())

	// Initially nil
	if info := d.GetCurrentInterface(); info != nil {
		t.Error("GetCurrentInterface() should return nil initially")
	}

	// Set a mock interface
	d.currentInterface = &InterfaceInfo{
		Name: "wg-nb-test",
		GUID: "{test-guid}",
	}

	info := d.GetCurrentInterface()
	if info == nil {
		t.Error("GetCurrentInterface() should return interface after setting")
	}

	// Verify it's a copy
	info.Name = "modified"
	if d.currentInterface.Name == "modified" {
		t.Error("GetCurrentInterface() should return a copy")
	}
}

func TestDiscoveryGetCurrentGUID(t *testing.T) {
	d := NewDiscovery(DefaultDiscoveryConfig())

	// Initially empty
	if guid := d.GetCurrentGUID(); guid != "" {
		t.Errorf("GetCurrentGUID() = %q, want empty", guid)
	}

	// Set a mock interface
	d.currentInterface = &InterfaceInfo{
		Name: "wg-nb-test",
		GUID: "{test-guid}",
	}

	if guid := d.GetCurrentGUID(); guid != "{test-guid}" {
		t.Errorf("GetCurrentGUID() = %q, want %q", guid, "{test-guid}")
	}
}

func TestDiscoveryGetCurrentName(t *testing.T) {
	d := NewDiscovery(DefaultDiscoveryConfig())

	// Initially empty
	if name := d.GetCurrentName(); name != "" {
		t.Errorf("GetCurrentName() = %q, want empty", name)
	}

	// Set a mock interface
	d.currentInterface = &InterfaceInfo{
		Name: "wg-nb-test",
		GUID: "{test-guid}",
	}

	if name := d.GetCurrentName(); name != "wg-nb-test" {
		t.Errorf("GetCurrentName() = %q, want %q", name, "wg-nb-test")
	}
}

func TestDiscoverySetKnownGUID(t *testing.T) {
	d := NewDiscovery(DefaultDiscoveryConfig())

	guid := "{12345678-1234-1234-1234-123456789ABC}"
	d.SetKnownGUID(guid)

	if d.config.GUID != guid {
		t.Errorf("config.GUID = %q, want %q", d.config.GUID, guid)
	}
}

func TestDiscoverySetOnInterfaceChange(t *testing.T) {
	d := NewDiscovery(DefaultDiscoveryConfig())

	called := false
	d.SetOnInterfaceChange(func(oldName, newName string) {
		called = true
	})

	if d.onInterfaceChange == nil {
		t.Error("onInterfaceChange should be set")
	}

	// Simulate interface change
	oldInfo := &InterfaceInfo{Name: "old-name"}
	newInfo := &InterfaceInfo{Name: "new-name"}
	d.currentInterface = oldInfo
	d.updateInterface(newInfo, oldInfo)

	if !called {
		t.Error("onInterfaceChange callback should have been called")
	}
}

func TestDiscoveryIsInterfaceNameChanged(t *testing.T) {
	d := NewDiscovery(DefaultDiscoveryConfig())

	// No interface yet
	if d.IsInterfaceNameChanged("any") {
		t.Error("Should return false when no interface is set")
	}

	// Set interface
	d.currentInterface = &InterfaceInfo{Name: "wg-nb-test"}

	// Same name
	if d.IsInterfaceNameChanged("wg-nb-test") {
		t.Error("Should return false for same name")
	}

	// Different name
	if !d.IsInterfaceNameChanged("wg-nb-other") {
		t.Error("Should return true for different name")
	}
}

func TestDiscoveryGetLastDiscoveryTime(t *testing.T) {
	d := NewDiscovery(DefaultDiscoveryConfig())

	// Initially zero
	if !d.GetLastDiscoveryTime().IsZero() {
		t.Error("GetLastDiscoveryTime() should be zero initially")
	}

	// Set a time
	now := time.Now()
	d.lastDiscovery = now

	if !d.GetLastDiscoveryTime().Equal(now) {
		t.Error("GetLastDiscoveryTime() should return set time")
	}
}

func TestDiscoveryConstants(t *testing.T) {
	if DefaultInterfacePrefix != "wg-nb-" {
		t.Errorf("DefaultInterfacePrefix = %q, want 'wg-nb-'", DefaultInterfacePrefix)
	}

	if DefaultInterfaceDescription != "WireGuard*" {
		t.Errorf("DefaultInterfaceDescription = %q, want 'WireGuard*'", DefaultInterfaceDescription)
	}

	if DefaultDiscoveryRetries != 10 {
		t.Errorf("DefaultDiscoveryRetries = %d, want 10", DefaultDiscoveryRetries)
	}

	if DefaultDiscoveryBackoff != 500*time.Millisecond {
		t.Errorf("DefaultDiscoveryBackoff = %v, want 500ms", DefaultDiscoveryBackoff)
	}

	if DefaultDiscoveryMaxBackoff != 5*time.Second {
		t.Errorf("DefaultDiscoveryMaxBackoff = %v, want 5s", DefaultDiscoveryMaxBackoff)
	}
}

func TestInterfaceInfoFields(t *testing.T) {
	info := &InterfaceInfo{
		Name:        "wg-nb-machine",
		GUID:        "{12345678-1234-1234-1234-123456789ABC}",
		Index:       10,
		Description: "WireGuard Tunnel",
		Status:      "Up",
		MTU:         1420,
	}

	if info.Name != "wg-nb-machine" {
		t.Errorf("Name = %q, want 'wg-nb-machine'", info.Name)
	}

	if info.GUID != "{12345678-1234-1234-1234-123456789ABC}" {
		t.Errorf("GUID = %q", info.GUID)
	}

	if info.Index != 10 {
		t.Errorf("Index = %d, want 10", info.Index)
	}

	if info.Description != "WireGuard Tunnel" {
		t.Errorf("Description = %q", info.Description)
	}

	if info.Status != "Up" {
		t.Errorf("Status = %q, want 'Up'", info.Status)
	}

	if info.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", info.MTU)
	}
}
