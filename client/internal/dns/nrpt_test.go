package dns

import (
	"testing"
)

func TestComputeRuleName(t *testing.T) {
	tests := []struct {
		namespace string
		wantLen   int // Expected length should be RulePrefix + 8 hex chars
	}{
		{".corp.local", len(RulePrefix) + 8},
		{"._msdcs.corp.local", len(RulePrefix) + 8},
		{".example.com", len(RulePrefix) + 8},
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			got := computeRuleName(tt.namespace)
			if len(got) != tt.wantLen {
				t.Errorf("computeRuleName(%q) length = %d, want %d", tt.namespace, len(got), tt.wantLen)
			}
			// Ensure it starts with the prefix
			if got[:len(RulePrefix)] != RulePrefix {
				t.Errorf("computeRuleName(%q) = %q, doesn't start with %q", tt.namespace, got, RulePrefix)
			}
		})
	}
}

func TestComputeRuleNameDeterministic(t *testing.T) {
	// Same namespace should produce same rule name
	namespace := ".corp.local"
	name1 := computeRuleName(namespace)
	name2 := computeRuleName(namespace)

	if name1 != name2 {
		t.Errorf("computeRuleName is not deterministic: %q != %q", name1, name2)
	}
}

func TestComputeRuleNameUnique(t *testing.T) {
	// Different namespaces should produce different rule names
	name1 := computeRuleName(".corp.local")
	name2 := computeRuleName(".example.com")

	if name1 == name2 {
		t.Errorf("Different namespaces produced same rule name: %q", name1)
	}
}

func TestGetForestRoot(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"corp.local", "corp.local"},
		{"child.corp.local", "corp.local"},
		{"deep.child.corp.local", "corp.local"},
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := getForestRoot(tt.domain)
			if got != tt.want {
				t.Errorf("getForestRoot(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestValidateNamespace(t *testing.T) {
	tests := []struct {
		namespace string
		wantErr   bool
	}{
		{".corp.local", false},
		{"._msdcs.corp.local", false},
		{".example.com", false},
		{"corp.local", true},    // Missing leading dot
		{"", true},              // Empty
		{".corp local", true},   // Space
		{".corp\tlocal", true},  // Tab
		{".corp;local", true},   // Semicolon
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			err := ValidateNamespace(tt.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNamespace(%q) error = %v, wantErr %v", tt.namespace, err, tt.wantErr)
			}
		})
	}
}

func TestIsValidDNSChar(t *testing.T) {
	valid := []rune{'a', 'z', 'A', 'Z', '0', '9', '.', '-', '_'}
	invalid := []rune{' ', '\t', ';', '/', '\\', '@', '#', '$'}

	for _, c := range valid {
		if !isValidDNSChar(c) {
			t.Errorf("isValidDNSChar(%q) = false, want true", c)
		}
	}

	for _, c := range invalid {
		if isValidDNSChar(c) {
			t.Errorf("isValidDNSChar(%q) = true, want false", c)
		}
	}
}

func TestNewNRPTManager(t *testing.T) {
	m := NewNRPTManager()
	if m == nil {
		t.Fatal("NewNRPTManager returned nil")
	}
	if m.activeRules == nil {
		t.Error("activeRules map not initialized")
	}
	if m.closed {
		t.Error("manager should not be closed initially")
	}
}

func TestNRPTManagerGetActiveRules(t *testing.T) {
	m := NewNRPTManager()

	// Initially empty
	rules := m.GetActiveRules()
	if len(rules) != 0 {
		t.Errorf("Expected 0 active rules, got %d", len(rules))
	}

	// Simulate adding a rule (direct map access for testing)
	m.activeRules[".test.local"] = "NetBird-Machine-12345678"

	rules = m.GetActiveRules()
	if len(rules) != 1 {
		t.Errorf("Expected 1 active rule, got %d", len(rules))
	}
	if rules[".test.local"] != "NetBird-Machine-12345678" {
		t.Errorf("Unexpected rule value: %v", rules)
	}

	// Ensure it's a copy
	rules[".other"] = "other"
	if len(m.activeRules) != 1 {
		t.Error("GetActiveRules should return a copy, not the original map")
	}
}
