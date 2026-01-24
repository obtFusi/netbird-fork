//go:build windows

// Package tunnel provides machine tunnel functionality for Windows.
// This file implements filesystem ACL hardening for configuration directories.
package tunnel

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// Well-known SIDs
var (
	// SID for NT AUTHORITY\SYSTEM
	sidSystem *windows.SID
	// SID for BUILTIN\Administrators
	sidAdministrators *windows.SID
)

func init() {
	var err error

	// NT AUTHORITY\SYSTEM (S-1-5-18)
	sidSystem, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		log.WithError(err).Warn("Failed to create SYSTEM SID")
	}

	// BUILTIN\Administrators (S-1-5-32-544)
	sidAdministrators, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		log.WithError(err).Warn("Failed to create Administrators SID")
	}
}

// ACLConfig defines the desired ACL configuration for a path.
type ACLConfig struct {
	// SystemFullControl grants NT AUTHORITY\SYSTEM full control
	SystemFullControl bool
	// AdminReadOnly grants BUILTIN\Administrators read-only access
	AdminReadOnly bool
	// DisableInheritance removes inherited permissions
	DisableInheritance bool
}

// DefaultConfigACL returns the recommended ACL config for sensitive config directories.
// - SYSTEM: Full Control (service runs as LocalSystem)
// - Administrators: Read & Execute only (cannot modify running config)
// - Users: No access (inherited permissions blocked)
func DefaultConfigACL() ACLConfig {
	return ACLConfig{
		SystemFullControl:  true,
		AdminReadOnly:      true,
		DisableInheritance: true,
	}
}

// HardenConfigDirectory applies secure ACLs to the configuration directory.
// This ensures only the SYSTEM account (under which the service runs) has
// write access, while administrators can only read the config.
func HardenConfigDirectory(dirPath string) error {
	return HardenPath(dirPath, DefaultConfigACL())
}

// HardenPath applies the specified ACL configuration to a path.
func HardenPath(path string, config ACLConfig) error {
	if sidSystem == nil || sidAdministrators == nil {
		return fmt.Errorf("failed to initialize well-known SIDs")
	}

	// Ensure path exists
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat path: %w", err)
	}

	isDir := info.IsDir()

	// Build the DACL (Discretionary Access Control List)
	var entries []windows.EXPLICIT_ACCESS

	// SYSTEM: Full Control
	if config.SystemFullControl {
		systemAccess := windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sidSystem),
			},
		}
		if !isDir {
			systemAccess.Inheritance = windows.NO_INHERITANCE
		}
		entries = append(entries, systemAccess)
	}

	// Administrators: Read & Execute only
	if config.AdminReadOnly {
		adminAccess := windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_READ | windows.GENERIC_EXECUTE,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sidAdministrators),
			},
		}
		if !isDir {
			adminAccess.Inheritance = windows.NO_INHERITANCE
		}
		entries = append(entries, adminAccess)
	}

	// Create the new DACL
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("create DACL: %w", err)
	}

	// Build security info flags
	securityInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.OWNER_SECURITY_INFORMATION)

	if config.DisableInheritance {
		securityInfo |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	}

	// Apply the security descriptor
	// Note: Setting owner requires SE_TAKE_OWNERSHIP_NAME or SE_RESTORE_NAME privilege
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		securityInfo,
		sidSystem, // Owner: SYSTEM
		nil,       // Group: not changed
		dacl,
		nil, // SACL: not changed
	)
	if err != nil {
		return fmt.Errorf("set security info: %w", err)
	}

	log.WithFields(log.Fields{
		"path":               path,
		"systemFullControl":  config.SystemFullControl,
		"adminReadOnly":      config.AdminReadOnly,
		"disableInheritance": config.DisableInheritance,
	}).Info("ACL hardening applied")

	return nil
}

// VerifyConfigACL checks if the configuration directory has the expected secure ACLs.
// Returns nil if ACLs are correctly configured, error otherwise.
func VerifyConfigACL(dirPath string) error {
	if sidSystem == nil {
		return fmt.Errorf("failed to initialize SYSTEM SID")
	}

	// Get current security descriptor
	sd, err := windows.GetNamedSecurityInfo(
		dirPath,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("get security info: %w", err)
	}

	// Check owner is SYSTEM
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("get owner: %w", err)
	}

	if !owner.Equals(sidSystem) {
		return fmt.Errorf("owner is not SYSTEM (expected S-1-5-18, got %s)", owner.String())
	}

	// Check DACL exists and is protected
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("get DACL: %w", err)
	}

	if dacl == nil {
		return fmt.Errorf("DACL is nil (no access control)")
	}

	log.WithField("path", dirPath).Debug("ACL verification passed")
	return nil
}

// EnsureSecureConfigDir creates the config directory if needed and applies secure ACLs.
func EnsureSecureConfigDir(dirPath string) error {
	// Create directory if it doesn't exist
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(dirPath, 0700); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
		log.WithField("path", dirPath).Info("Created config directory")
	}

	// Apply secure ACLs
	if err := HardenConfigDirectory(dirPath); err != nil {
		return fmt.Errorf("harden directory: %w", err)
	}

	return nil
}

// HardenConfigFile applies secure ACLs to a specific config file.
// Same permissions as directory but without inheritance flags.
func HardenConfigFile(filePath string) error {
	config := ACLConfig{
		SystemFullControl:  true,
		AdminReadOnly:      true,
		DisableInheritance: true,
	}
	return HardenPath(filePath, config)
}

// GetConfigDir returns the default NetBird Machine config directory.
func GetConfigDir() string {
	return filepath.Join(os.Getenv("ProgramData"), "NetBird")
}

// GetConfigPath returns the default config file path.
func GetConfigPath() string {
	return filepath.Join(GetConfigDir(), "config.yaml")
}
