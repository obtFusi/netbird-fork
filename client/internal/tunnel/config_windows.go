//go:build windows

// Package tunnel provides machine tunnel functionality for Windows.
// This file implements secure configuration management with DPAPI and cleanup.
package tunnel

import (
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

	// Ensure directory exists with secure ACLs
	dir := filepath.Dir(configPath)
	if err := EnsureSecureConfigDir(dir); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}

	// Write config file
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	// Apply secure ACLs to config file
	if err := HardenConfigFile(configPath); err != nil {
		log.WithError(err).Warn("Failed to harden config file ACLs")
	}

	return nil
}

// GetSetupKey decrypts and returns the setup key.
// Returns empty string if no setup key is configured.
func (c *StoredMachineConfig) GetSetupKey() (string, error) {
	if c.SetupKeyEncrypted == "" {
		return "", nil
	}
	return DecryptSetupKey(c.SetupKeyEncrypted)
}

// SetSetupKey encrypts and stores the setup key.
func (c *StoredMachineConfig) SetSetupKey(setupKey string) error {
	if setupKey == "" {
		c.SetupKeyEncrypted = ""
		return nil
	}

	encrypted, err := EncryptSetupKey(setupKey)
	if err != nil {
		return err
	}

	c.SetupKeyEncrypted = encrypted
	return nil
}

// CleanupAfterBootstrap removes sensitive bootstrap data after successful mTLS upgrade.
// This should be called after the machine has successfully authenticated via mTLS.
//
// Cleanup includes:
// - Removing the encrypted setup key from config
// - Logging the cleanup to Windows Event Log
// - Saving the updated config
func (c *StoredMachineConfig) CleanupAfterBootstrap() error {
	if c.SetupKeyEncrypted == "" {
		log.Debug("No setup key to cleanup")
		return nil
	}

	log.Info("Cleaning up bootstrap data after successful mTLS upgrade")

	// Clear the setup key
	c.SetupKeyEncrypted = ""

	// Save the updated config
	if err := c.Save(); err != nil {
		return fmt.Errorf("save config after cleanup: %w", err)
	}

	// Log to Windows Event Log
	if err := LogSetupKeyRemoved(); err != nil {
		log.WithError(err).Warn("Failed to log setup key removal to Event Log")
	}

	log.Info("Setup key removed from config - machine now uses mTLS only")
	return nil
}

// InitializeConfig creates a new configuration with the provided setup key.
// The setup key is encrypted with DPAPI before storage.
func InitializeConfig(managementURL, setupKey string) (*StoredMachineConfig, error) {
	config := &StoredMachineConfig{
		ManagementURL: managementURL,
	}

	if setupKey != "" {
		if err := config.SetSetupKey(setupKey); err != nil {
			return nil, fmt.Errorf("encrypt setup key: %w", err)
		}
	}

	return config, nil
}

// ValidateConfig checks if the configuration is valid.
func (c *StoredMachineConfig) ValidateConfig() error {
	if c.ManagementURL == "" {
		return fmt.Errorf("management_url is required")
	}

	// Either setup key or machine cert must be configured
	if c.SetupKeyEncrypted == "" && !c.MachineCertEnabled {
		return fmt.Errorf("either setup_key_encrypted or machine_cert_enabled must be configured")
	}

	return nil
}
