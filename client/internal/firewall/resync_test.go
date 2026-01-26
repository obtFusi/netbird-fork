package firewall

import (
	"testing"
)

func TestDefaultResyncConfig(t *testing.T) {
	config := DefaultResyncConfig()

	if !config.AutoResync {
		t.Error("AutoResync should be true by default")
	}

	if !config.RemoveOrphaned {
		t.Error("RemoveOrphaned should be true by default")
	}
}

func TestNewResyncer(t *testing.T) {
	manager, _ := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})

	resyncer := NewResyncer(manager, DefaultResyncConfig())

	if resyncer == nil {
		t.Fatal("NewResyncer returned nil")
	}

	if resyncer.manager != manager {
		t.Error("Resyncer should reference the provided manager")
	}
}

func TestResyncerGetResyncCallback(t *testing.T) {
	manager, _ := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})

	resyncer := NewResyncer(manager, DefaultResyncConfig())

	callback := resyncer.GetResyncCallback()
	if callback == nil {
		t.Error("GetResyncCallback should return a callback function")
	}
}

func TestResyncerVerifyRulesEmpty(t *testing.T) {
	manager, _ := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})

	resyncer := NewResyncer(manager, DefaultResyncConfig())

	// With no rules (and on non-Windows where query returns error), verification should pass
	ok, mismatched := resyncer.VerifyRules("wg-nb-machine")

	if !ok {
		t.Error("VerifyRules should return true on non-Windows or with no rules")
	}

	if len(mismatched) != 0 {
		t.Errorf("mismatched should be empty, got %v", mismatched)
	}
}

func TestResyncerOnInterfaceNameChangeNoRules(t *testing.T) {
	manager, _ := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})

	resyncer := NewResyncer(manager, DefaultResyncConfig())

	// With no rules, should succeed without doing anything
	err := resyncer.OnInterfaceNameChange("old-name", "new-name")
	if err != nil {
		t.Errorf("OnInterfaceNameChange error = %v", err)
	}
}

func TestResyncerResyncAllNoRules(t *testing.T) {
	manager, _ := NewManager(&ManagerConfig{
		InterfaceName: "old-interface",
		DCIPs:         []string{"192.168.100.20"},
	})

	resyncer := NewResyncer(manager, DefaultResyncConfig())

	// With no rules, should succeed
	err := resyncer.ResyncAll("new-interface")
	if err != nil {
		t.Errorf("ResyncAll error = %v", err)
	}

	// Manager's interface name should be updated
	if manager.interfaceName != "new-interface" {
		t.Errorf("interfaceName = %q, want 'new-interface'", manager.interfaceName)
	}
}

func TestResyncerAutoResyncDisabled(t *testing.T) {
	manager, _ := NewManager(&ManagerConfig{
		DCIPs: []string{"192.168.100.20"},
	})

	config := DefaultResyncConfig()
	config.AutoResync = false

	resyncer := NewResyncer(manager, config)

	// Add a mock rule name
	manager.mu.Lock()
	manager.createdRules = []string{"Rule1"}
	oldInterface := manager.interfaceName
	manager.mu.Unlock()

	// With AutoResync disabled, callback should not trigger resync
	callback := resyncer.GetResyncCallback()

	// Call callback (should do nothing because AutoResync is disabled)
	callback("old-interface", "new-interface")

	// Interface name should NOT be updated (AutoResync is disabled)
	manager.mu.Lock()
	currentInterface := manager.interfaceName
	manager.mu.Unlock()

	if currentInterface != oldInterface {
		t.Error("Interface should not be updated when AutoResync is disabled")
	}
}

func TestResyncConfigFields(t *testing.T) {
	config := ResyncConfig{
		AutoResync:     false,
		RemoveOrphaned: false,
	}

	if config.AutoResync {
		t.Error("AutoResync should be false")
	}

	if config.RemoveOrphaned {
		t.Error("RemoveOrphaned should be false")
	}
}

func TestResyncerOnInterfaceNameChangeWithRules(t *testing.T) {
	manager, _ := NewManager(&ManagerConfig{
		InterfaceName: "old-interface",
		DCIPs:         []string{"192.168.100.20"},
	})

	// Add mock rule names
	manager.mu.Lock()
	manager.createdRules = []string{"Rule1", "Rule2"}
	manager.mu.Unlock()

	resyncer := NewResyncer(manager, DefaultResyncConfig())

	// On non-Windows, updateRuleInterface will fail, but interface name should still be updated
	_ = resyncer.OnInterfaceNameChange("old-interface", "new-interface")

	// Manager's interface name should be updated
	manager.mu.Lock()
	newInterface := manager.interfaceName
	manager.mu.Unlock()

	if newInterface != "new-interface" {
		t.Errorf("interfaceName = %q, want 'new-interface'", newInterface)
	}
}

func TestResyncerResyncAllWithRules(t *testing.T) {
	manager, _ := NewManager(&ManagerConfig{
		InterfaceName: "old-interface",
		DCIPs:         []string{"192.168.100.20"},
	})

	// Add mock rule names
	manager.mu.Lock()
	manager.createdRules = []string{"Rule1", "Rule2"}
	manager.mu.Unlock()

	resyncer := NewResyncer(manager, DefaultResyncConfig())

	// On non-Windows, updateRuleInterface will fail, but the function should still work
	_ = resyncer.ResyncAll("new-interface")

	// Manager's interface name should be updated
	if manager.interfaceName != "new-interface" {
		t.Errorf("interfaceName = %q, want 'new-interface'", manager.interfaceName)
	}
}
