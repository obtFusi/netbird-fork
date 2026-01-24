// Machine Tunnel Fork - Firewall Rule Resync
// This file provides firewall rule resynchronization when interface names change.

package firewall

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
)

// ResyncConfig configures the firewall resync behavior
type ResyncConfig struct {
	// AutoResync enables automatic resync when interface name changes
	AutoResync bool

	// RemoveOrphaned removes rules that reference non-existent interfaces
	RemoveOrphaned bool
}

// DefaultResyncConfig returns the default resync configuration
func DefaultResyncConfig() ResyncConfig {
	return ResyncConfig{
		AutoResync:     true,
		RemoveOrphaned: true,
	}
}

// Resyncer manages firewall rule resynchronization
type Resyncer struct {
	mu sync.Mutex

	manager *Manager
	config  ResyncConfig
}

// NewResyncer creates a new firewall resyncer
func NewResyncer(manager *Manager, config ResyncConfig) *Resyncer {
	return &Resyncer{
		manager: manager,
		config:  config,
	}
}

// OnInterfaceNameChange handles interface name changes by updating firewall rules
// This is typically called as a callback from the interface discovery module
func (r *Resyncer) OnInterfaceNameChange(oldName, newName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	log.WithFields(log.Fields{
		"oldName": oldName,
		"newName": newName,
	}).Info("Interface name changed, resyncing firewall rules")

	// Get current rule names
	ruleNames := r.manager.GetCreatedRules()
	if len(ruleNames) == 0 {
		log.Debug("No firewall rules to resync")
		return nil
	}

	// Update interface name in manager
	r.manager.mu.Lock()
	r.manager.interfaceName = newName
	r.manager.mu.Unlock()

	// Update all rules to use the new interface name
	resyncCount := 0
	var errors []error

	for _, ruleName := range ruleNames {
		log.WithFields(log.Fields{
			"rule":    ruleName,
			"oldName": oldName,
			"newName": newName,
		}).Debug("Updating rule interface alias")

		if err := updateRuleInterface(ruleName, newName); err != nil {
			log.WithError(err).Warnf("Failed to update rule %s", ruleName)
			errors = append(errors, err)
		} else {
			resyncCount++
		}
	}

	log.WithField("count", resyncCount).Info("Firewall rules resynced")

	if len(errors) > 0 {
		return fmt.Errorf("resync completed with %d errors", len(errors))
	}

	return nil
}

// VerifyRules verifies that all firewall rules reference the correct interface
// On non-Windows platforms, this always returns true since we can't query firewall rules
func (r *Resyncer) VerifyRules(expectedInterfaceName string) (bool, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Use platform-specific implementation to check rules
	wrongRules, err := GetRulesWithWrongInterface(expectedInterfaceName)
	if err != nil {
		// On non-Windows or if query fails, assume rules are correct
		log.WithError(err).Debug("Could not verify firewall rules")
		return true, nil
	}

	return len(wrongRules) == 0, wrongRules
}

// ResyncAll resyncs all firewall rules to use the specified interface name
func (r *Resyncer) ResyncAll(interfaceName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	ruleNames := r.manager.GetCreatedRules()
	if len(ruleNames) == 0 {
		// Update manager's interface name even with no rules
		r.manager.mu.Lock()
		r.manager.interfaceName = interfaceName
		r.manager.mu.Unlock()
		return nil
	}

	log.WithFields(log.Fields{
		"interfaceName": interfaceName,
		"ruleCount":     len(ruleNames),
	}).Info("Resyncing all firewall rules")

	var errors []error

	for _, ruleName := range ruleNames {
		if err := updateRuleInterface(ruleName, interfaceName); err != nil {
			errors = append(errors, err)
		}
	}

	// Update manager's interface name
	r.manager.mu.Lock()
	r.manager.interfaceName = interfaceName
	r.manager.mu.Unlock()

	if len(errors) > 0 {
		return fmt.Errorf("resync completed with %d errors", len(errors))
	}

	return nil
}

// GetResyncCallback returns a callback function suitable for interface discovery
func (r *Resyncer) GetResyncCallback() func(oldName, newName string) {
	return func(oldName, newName string) {
		if r.config.AutoResync {
			if err := r.OnInterfaceNameChange(oldName, newName); err != nil {
				log.WithError(err).Error("Auto-resync failed")
			}
		}
	}
}
