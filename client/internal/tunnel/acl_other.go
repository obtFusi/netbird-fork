//go:build !windows

// Package tunnel provides machine tunnel functionality.
// This file provides stub implementations for non-Windows platforms.
package tunnel

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrACLNotSupported is returned when ACL functions are called on non-Windows platforms.
var ErrACLNotSupported = errors.New("windows ACL functions are only supported on Windows")

// ACLConfig defines the desired ACL configuration for a path.
type ACLConfig struct {
	SystemFullControl  bool
	AdminReadOnly      bool
	DisableInheritance bool
}

// DefaultConfigACL returns the recommended ACL config for sensitive config directories.
func DefaultConfigACL() ACLConfig {
	return ACLConfig{
		SystemFullControl:  true,
		AdminReadOnly:      true,
		DisableInheritance: true,
	}
}

// HardenConfigDirectory is not supported on non-Windows platforms.
// On Unix-like systems, use standard file permissions (0700 for directories, 0600 for files).
func HardenConfigDirectory(dirPath string) error {
	return os.Chmod(dirPath, 0700)
}

// HardenPath is not supported on non-Windows platforms.
func HardenPath(path string, config ACLConfig) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return os.Chmod(path, 0700)
	}
	return os.Chmod(path, 0600)
}

// VerifyConfigACL is not supported on non-Windows platforms.
func VerifyConfigACL(dirPath string) error {
	return ErrACLNotSupported
}

// EnsureSecureConfigDir creates the config directory with secure permissions.
func EnsureSecureConfigDir(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(dirPath, 0700); err != nil {
			return err
		}
	}
	return os.Chmod(dirPath, 0700)
}

// HardenConfigFile sets secure permissions on a config file.
func HardenConfigFile(filePath string) error {
	return os.Chmod(filePath, 0600)
}

// GetConfigDir returns the default config directory for the current platform.
func GetConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/netbird"
	}
	return filepath.Join(home, ".netbird")
}

// GetConfigPath returns the default config file path.
func GetConfigPath() string {
	return filepath.Join(GetConfigDir(), "config.yaml")
}
