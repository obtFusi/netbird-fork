// Machine Tunnel Fork - Interface Discovery
// This file provides interface discovery and GUID-based identification.

package iface

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultInterfacePrefix is the prefix for NetBird Machine WireGuard interfaces
	DefaultInterfacePrefix = "wg-nb-"

	// DefaultInterfaceDescription is the WireGuard adapter description pattern
	DefaultInterfaceDescription = "WireGuard*"

	// DefaultDiscoveryRetries is the number of retries when discovering interface
	DefaultDiscoveryRetries = 10

	// DefaultDiscoveryBackoff is the initial backoff between discovery retries
	DefaultDiscoveryBackoff = 500 * time.Millisecond

	// DefaultDiscoveryMaxBackoff is the maximum backoff between retries
	DefaultDiscoveryMaxBackoff = 5 * time.Second
)

// InterfaceInfo contains information about a discovered network interface
type InterfaceInfo struct {
	// Name is the interface name (e.g., "wg-nb-machine")
	Name string

	// GUID is the interface GUID (Windows-specific, empty on other platforms)
	GUID string

	// Index is the interface index
	Index int

	// Description is the interface description (e.g., "WireGuard Tunnel")
	Description string

	// Status is the interface status (up, down)
	Status string

	// MTU is the interface MTU
	MTU int
}

// DiscoveryConfig configures the interface discovery
type DiscoveryConfig struct {
	// NamePrefix is the interface name prefix to search for
	NamePrefix string

	// DescriptionPattern is the interface description pattern (for Windows)
	DescriptionPattern string

	// GUID is the known interface GUID (for GUID-based lookup)
	GUID string

	// Retries is the number of discovery retries
	Retries int

	// InitialBackoff is the initial backoff between retries
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff between retries
	MaxBackoff time.Duration
}

// DefaultDiscoveryConfig returns the default discovery configuration
func DefaultDiscoveryConfig() DiscoveryConfig {
	return DiscoveryConfig{
		NamePrefix:         DefaultInterfacePrefix,
		DescriptionPattern: DefaultInterfaceDescription,
		Retries:            DefaultDiscoveryRetries,
		InitialBackoff:     DefaultDiscoveryBackoff,
		MaxBackoff:         DefaultDiscoveryMaxBackoff,
	}
}

// Discovery manages interface discovery and tracking
type Discovery struct {
	mu sync.RWMutex

	config DiscoveryConfig

	// currentInterface is the currently discovered interface
	currentInterface *InterfaceInfo

	// lastDiscovery is the time of the last successful discovery
	lastDiscovery time.Time

	// onInterfaceChange is called when the interface name changes
	onInterfaceChange func(oldName, newName string)
}

// NewDiscovery creates a new interface discovery manager
func NewDiscovery(config DiscoveryConfig) *Discovery {
	if config.NamePrefix == "" {
		config.NamePrefix = DefaultInterfacePrefix
	}
	if config.DescriptionPattern == "" {
		config.DescriptionPattern = DefaultInterfaceDescription
	}
	if config.Retries == 0 {
		config.Retries = DefaultDiscoveryRetries
	}
	if config.InitialBackoff == 0 {
		config.InitialBackoff = DefaultDiscoveryBackoff
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = DefaultDiscoveryMaxBackoff
	}

	return &Discovery{
		config: config,
	}
}

// SetOnInterfaceChange sets the callback for interface name changes
func (d *Discovery) SetOnInterfaceChange(callback func(oldName, newName string)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onInterfaceChange = callback
}

// SetKnownGUID sets a known GUID for GUID-based lookup
func (d *Discovery) SetKnownGUID(guid string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.config.GUID = guid
}

// GetCurrentInterface returns the current interface info
func (d *Discovery) GetCurrentInterface() *InterfaceInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.currentInterface == nil {
		return nil
	}

	// Return a copy
	info := *d.currentInterface
	return &info
}

// GetCurrentGUID returns the current interface GUID
func (d *Discovery) GetCurrentGUID() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.currentInterface == nil {
		return ""
	}
	return d.currentInterface.GUID
}

// GetCurrentName returns the current interface name
func (d *Discovery) GetCurrentName() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.currentInterface == nil {
		return ""
	}
	return d.currentInterface.Name
}

// Discover attempts to discover the WireGuard interface using the configured strategies
// Lookup priority: 1. GUID, 2. Description, 3. Name prefix
func (d *Discovery) Discover() (*InterfaceInfo, error) {
	d.mu.Lock()
	config := d.config
	oldInterface := d.currentInterface
	d.mu.Unlock()

	var info *InterfaceInfo
	var err error

	// Priority 1: GUID-based lookup (most reliable)
	if config.GUID != "" {
		info, err = discoverByGUID(config.GUID)
		if err == nil && info != nil {
			log.WithFields(log.Fields{
				"guid": config.GUID,
				"name": info.Name,
			}).Debug("Interface found by GUID")
			d.updateInterface(info, oldInterface)
			return info, nil
		}
		log.WithField("guid", config.GUID).Debug("GUID lookup failed, trying description")
	}

	// Priority 2: Description-based lookup (stable across renames)
	info, err = discoverByDescription(config.DescriptionPattern)
	if err == nil && info != nil {
		log.WithFields(log.Fields{
			"description": config.DescriptionPattern,
			"name":        info.Name,
			"guid":        info.GUID,
		}).Debug("Interface found by description")
		d.updateInterface(info, oldInterface)
		return info, nil
	}

	// Priority 3: Name prefix lookup (fallback)
	info, err = discoverByNamePrefix(config.NamePrefix)
	if err == nil && info != nil {
		log.WithFields(log.Fields{
			"prefix": config.NamePrefix,
			"name":   info.Name,
			"guid":   info.GUID,
		}).Debug("Interface found by name prefix")
		d.updateInterface(info, oldInterface)
		return info, nil
	}

	return nil, fmt.Errorf("interface not found using GUID, description, or name prefix")
}

// DiscoverWithRetry attempts to discover the interface with exponential backoff
func (d *Discovery) DiscoverWithRetry() (*InterfaceInfo, error) {
	config := d.config
	backoff := config.InitialBackoff

	var lastErr error

	for i := 0; i < config.Retries; i++ {
		info, err := d.Discover()
		if err == nil {
			return info, nil
		}

		lastErr = err
		log.WithFields(log.Fields{
			"retry":   i + 1,
			"backoff": backoff,
			"error":   err,
		}).Debug("Interface discovery failed, retrying")

		time.Sleep(backoff)

		// Increase backoff
		backoff = time.Duration(float64(backoff) * 1.5)
		if backoff > config.MaxBackoff {
			backoff = config.MaxBackoff
		}
	}

	return nil, fmt.Errorf("interface not found after %d retries: %w", config.Retries, lastErr)
}

// updateInterface updates the current interface and triggers callback if changed
func (d *Discovery) updateInterface(info *InterfaceInfo, oldInterface *InterfaceInfo) {
	d.mu.Lock()
	d.currentInterface = info
	d.lastDiscovery = time.Now()
	callback := d.onInterfaceChange
	d.mu.Unlock()

	// Check if name changed
	if callback != nil && oldInterface != nil && oldInterface.Name != info.Name {
		log.WithFields(log.Fields{
			"oldName": oldInterface.Name,
			"newName": info.Name,
		}).Info("Interface name changed")
		callback(oldInterface.Name, info.Name)
	}
}

// IsInterfaceNameChanged checks if the interface name has changed from the expected name
func (d *Discovery) IsInterfaceNameChanged(expectedName string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.currentInterface == nil {
		return false
	}
	return d.currentInterface.Name != expectedName
}

// GetLastDiscoveryTime returns the time of the last successful discovery
func (d *Discovery) GetLastDiscoveryTime() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastDiscovery
}
