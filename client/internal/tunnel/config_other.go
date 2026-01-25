//go:build !windows

// Package tunnel provides machine tunnel functionality.
// This file provides stub implementations for non-Windows platforms.
package tunnel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// LoadMachineConfig loads the machine configuration from the default path.
func LoadMachineConfig() (*StoredMachineConfig, error) {
	return LoadMachineConfigFrom(GetConfigPath())
}

// LoadMachineConfigFrom loads the machine configuration from the specified path.
func LoadMachineConfigFrom(configPath string) (*StoredMachineConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config StoredMachineConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	return &config, nil
}

// Save saves the configuration to the default path.
func (c *StoredMachineConfig) Save() error {
	return c.SaveTo(GetConfigPath())
}

// SaveTo saves the configuration to the specified path.
func (c *StoredMachineConfig) SaveTo(configPath string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Write config file
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// GetSetupKey is not supported on non-Windows platforms.
func (c *StoredMachineConfig) GetSetupKey() (string, error) {
	return "", errors.New("setup key with DPAPI encryption is only supported on Windows")
}

// SetSetupKey is not supported on non-Windows platforms.
func (c *StoredMachineConfig) SetSetupKey(setupKey string) error {
	return errors.New("setup key with DPAPI encryption is only supported on Windows")
}

// CleanupAfterBootstrap is a no-op on non-Windows platforms.
func (c *StoredMachineConfig) CleanupAfterBootstrap() error {
	log.Debug("Cleanup after bootstrap is a no-op on non-Windows platforms")
	return nil
}

// InitializeConfig creates a new configuration.
// Setup key encryption is not supported on non-Windows.
func InitializeConfig(managementURL, setupKey string) (*StoredMachineConfig, error) {
	if setupKey != "" {
		return nil, errors.New("setup key with DPAPI encryption is only supported on Windows")
	}

	config := &StoredMachineConfig{
		ManagementURL: managementURL,
	}

	return config, nil
}

// ValidateConfig checks if the configuration is valid.
func (c *StoredMachineConfig) ValidateConfig() error {
	if c.ManagementURL == "" {
		return fmt.Errorf("management_url is required")
	}

	if !c.MachineCertEnabled {
		return fmt.Errorf("machine_cert_enabled must be true on non-Windows platforms (DPAPI not available)")
	}

	return nil
}
