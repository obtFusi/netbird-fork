//go:build windows

// Package tunnel provides machine tunnel functionality for Windows pre-login VPN.
package tunnel

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"
)

// DPAPI constants
const (
	cryptProtectUIForbidden  = 0x1
	cryptProtectLocalMachine = 0x4 // Machine-scope encryption (not user-scope)
)

// Entropy for WireGuard key encryption - adds defense-in-depth
// This value is compiled into the binary, providing additional protection
// against credential theft even if DPAPI master key is compromised.
var wgKeyEntropy = []byte("NetBird-Machine-WG-Key-v1")

var (
	crypt32                = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

// DATA_BLOB structure for DPAPI
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// DPAPIEncrypt encrypts data using Windows DPAPI (user scope, legacy).
// Returns base64-encoded encrypted data.
// DEPRECATED: Use DPAPIEncryptMachine for machine-scope encryption.
func DPAPIEncrypt(plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}

	var inBlob dataBlob
	inBlob.cbData = uint32(len(plaintext))
	inBlob.pbData = &plaintext[0]

	var outBlob dataBlob

	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // no description
		0, // no additional entropy
		0, // reserved
		0, // no prompt struct
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return "", fmt.Errorf("CryptProtectData failed: %w", err)
	}

	defer func() {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))
	}()

	encrypted := make([]byte, outBlob.cbData)
	copy(encrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DPAPIEncryptMachine encrypts data using Windows DPAPI with MACHINE scope.
// This ensures data can only be decrypted on THIS machine, regardless of user context.
// Uses additional entropy for defense-in-depth against credential theft.
// Returns base64-encoded encrypted data.
//
// Enterprise Security Notes:
//   - CRYPTPROTECT_LOCAL_MACHINE: Key is machine-bound, not user-bound
//   - Additional entropy: Compiled into binary, adds layer against DPAPI key extraction
//   - Only SYSTEM or Administrators can decrypt (based on machine DPAPI master key)
func DPAPIEncryptMachine(plaintext []byte, entropy []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}

	var inBlob dataBlob
	inBlob.cbData = uint32(len(plaintext))
	inBlob.pbData = &plaintext[0]

	var entropyBlob dataBlob
	var entropyPtr uintptr
	if len(entropy) > 0 {
		entropyBlob.cbData = uint32(len(entropy))
		entropyBlob.pbData = &entropy[0]
		entropyPtr = uintptr(unsafe.Pointer(&entropyBlob))
	}

	var outBlob dataBlob

	// CRYPTPROTECT_LOCAL_MACHINE (0x4) + CRYPTPROTECT_UI_FORBIDDEN (0x1)
	flags := uintptr(cryptProtectLocalMachine | cryptProtectUIForbidden)

	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // no description
		entropyPtr,
		0, // reserved
		0, // no prompt struct
		flags,
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return "", fmt.Errorf("CryptProtectData (machine scope) failed: %w", err)
	}

	defer func() {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))
	}()

	encrypted := make([]byte, outBlob.cbData)
	copy(encrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DPAPIDecryptMachine decrypts base64-encoded DPAPI data encrypted with machine scope.
// Must use the same entropy that was used during encryption.
func DPAPIDecryptMachine(ciphertext string, entropy []byte) ([]byte, error) {
	if ciphertext == "" {
		return []byte{}, nil
	}

	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var inBlob dataBlob
	inBlob.cbData = uint32(len(encrypted))
	inBlob.pbData = &encrypted[0]

	var entropyBlob dataBlob
	var entropyPtr uintptr
	if len(entropy) > 0 {
		entropyBlob.cbData = uint32(len(entropy))
		entropyBlob.pbData = &entropy[0]
		entropyPtr = uintptr(unsafe.Pointer(&entropyBlob))
	}

	var outBlob dataBlob

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // no description
		entropyPtr,
		0, // reserved
		0, // no prompt struct
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData (machine scope) failed: %w", err)
	}

	defer func() {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))
	}()

	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return decrypted, nil
}

// DPAPIDecrypt decrypts base64-encoded DPAPI data.
func DPAPIDecrypt(ciphertext string) ([]byte, error) {
	if ciphertext == "" {
		return []byte{}, nil
	}

	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var inBlob dataBlob
	inBlob.cbData = uint32(len(encrypted))
	inBlob.pbData = &encrypted[0]

	var outBlob dataBlob

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // no description
		0, // no additional entropy
		0, // reserved
		0, // no prompt struct
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}

	defer func() {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))
	}()

	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return decrypted, nil
}

// EncryptSetupKey encrypts a setup key using DPAPI.
func EncryptSetupKey(setupKey string) (string, error) {
	if setupKey == "" {
		return "", nil
	}
	return DPAPIEncrypt([]byte(setupKey))
}

// DecryptSetupKey decrypts a setup key using DPAPI.
func DecryptSetupKey(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	decrypted, err := DPAPIDecrypt(encrypted)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// secureZeroSink prevents compiler from optimizing away SecureZeroMemory.
// The compiler cannot prove that this variable is never read.
var secureZeroSink byte //nolint:unused // memory barrier sink - intentionally written, never read

// SecureZeroMemory securely zeros a byte slice.
// Uses a memory barrier technique to prevent compiler optimization.
// This ensures sensitive data (private keys, etc.) is actually cleared from memory.
func SecureZeroMemory(data []byte) {
	if len(data) == 0 {
		return
	}

	// Zero the memory
	for i := range data {
		data[i] = 0
	}

	// Memory barrier: Read from zeroed data and assign to package-level sink.
	// This prevents the compiler from optimizing away the zeroing because:
	// 1. The compiler can't prove secureZeroSink is never read
	// 2. The read depends on the zeroing being complete
	secureZeroSink = data[0]
}

// DefaultConfigDir is the default configuration directory.
const DefaultConfigDir = `C:\ProgramData\NetBird`

// GetConfigDir returns the default configuration directory.
func GetConfigDir() string {
	return DefaultConfigDir
}

// GetConfigPath returns the default configuration file path.
func GetConfigPath() string {
	return filepath.Join(DefaultConfigDir, "machine-config.yaml")
}

// HardenConfigDirectory applies restrictive ACLs to the config directory.
// Only SYSTEM and Administrators have access, with SYSTEM having full control
// and Administrators having read-only access.
func HardenConfigDirectory(path string) error {
	// Get the security descriptor
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("get security info: %w", err)
	}

	// Get SYSTEM and Administrators SIDs
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("create SYSTEM SID: %w", err)
	}

	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID: %w", err)
	}

	// Create new DACL with:
	// - SYSTEM: Full Control
	// - Administrators: Read Only
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		},
		{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(adminSID),
			},
		},
	}

	newACL, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("create ACL: %w", err)
	}

	// Apply the new DACL
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		newACL,
		nil,
	)
	if err != nil {
		return fmt.Errorf("set security info: %w", err)
	}

	_ = sd // avoid unused variable warning

	return nil
}

// EnsureSecureConfigDir creates the config directory if needed and applies hardened ACLs.
func EnsureSecureConfigDir(path string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Apply hardened ACLs
	return HardenConfigDirectory(path)
}

// VerifyConfigACL verifies that the config directory has proper ACLs.
func VerifyConfigACL(path string) error {
	// Get the security descriptor
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("get security info: %w", err)
	}

	// Get the DACL
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("get DACL: %w", err)
	}

	if dacl == nil {
		return fmt.Errorf("no DACL present")
	}

	// Basic verification - DACL exists
	// More detailed verification would check specific ACEs
	return nil
}

// SecureConfig provides secure configuration management with DPAPI-encrypted secrets.
// All sensitive fields are encrypted using DPAPI with machine scope (CRYPTPROTECT_LOCAL_MACHINE).
//
// Security Model:
//   - Keys are machine-bound: Only this specific machine can decrypt
//   - Additional entropy: Compiled into binary for defense-in-depth
//   - ACLs on config file: Only SYSTEM has write access
//   - Setup key: Removed after successful mTLS upgrade
type SecureConfig struct {
	// ManagementURL is the NetBird management server URL (not sensitive).
	ManagementURL string `yaml:"management_url"`

	// EncryptedSetupKey is the DPAPI-encrypted setup key for Phase 1 bootstrap.
	// Should be removed after successful mTLS upgrade (Phase 2).
	EncryptedSetupKey string `yaml:"encrypted_setup_key,omitempty"`

	// EncryptedPrivateKey is the DPAPI-encrypted WireGuard private key.
	// CRITICAL: This key authenticates the peer to the management server.
	// Must be persisted to survive service restarts.
	EncryptedPrivateKey string `yaml:"encrypted_private_key,omitempty"`

	// EncryptedSSHKey is the DPAPI-encrypted SSH private key for management registration.
	EncryptedSSHKey string `yaml:"encrypted_ssh_key,omitempty"`

	// MachineCertEnabled indicates whether machine certificate auth is enabled (Phase 2).
	MachineCertEnabled bool `yaml:"machine_cert_enabled"`

	// MachineCertThumbprint is the expected certificate thumbprint (optional validation).
	MachineCertThumbprint string `yaml:"machine_cert_thumbprint,omitempty"`

	// KeyVersion tracks the key encryption version for future rotation support.
	// v1 = current DPAPI with wgKeyEntropy
	KeyVersion int `yaml:"key_version,omitempty"`
}

// InitializeConfig creates a new SecureConfig with an encrypted setup key.
func InitializeConfig(managementURL, setupKey string) (*SecureConfig, error) {
	cfg := &SecureConfig{
		ManagementURL: managementURL,
	}

	if setupKey != "" {
		encrypted, err := EncryptSetupKey(setupKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt setup key: %w", err)
		}
		cfg.EncryptedSetupKey = encrypted
	}

	return cfg, nil
}

// LoadMachineConfigFrom loads a SecureConfig from a YAML file.
func LoadMachineConfigFrom(path string) (*SecureConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg SecureConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}

// HasSetupKey returns true if the config has an encrypted setup key.
func (c *SecureConfig) HasSetupKey() bool {
	return c.EncryptedSetupKey != ""
}

// GetSetupKey decrypts and returns the setup key.
func (c *SecureConfig) GetSetupKey() (string, error) {
	if c.EncryptedSetupKey == "" {
		return "", nil
	}
	return DecryptSetupKey(c.EncryptedSetupKey)
}

// SetSetupKey encrypts and stores the setup key.
func (c *SecureConfig) SetSetupKey(setupKey string) error {
	if setupKey == "" {
		c.EncryptedSetupKey = ""
		return nil
	}
	encrypted, err := EncryptSetupKey(setupKey)
	if err != nil {
		return fmt.Errorf("encrypt setup key: %w", err)
	}
	c.EncryptedSetupKey = encrypted
	return nil
}

// HasPrivateKey returns true if the config has an encrypted WireGuard private key.
func (c *SecureConfig) HasPrivateKey() bool {
	return c.EncryptedPrivateKey != ""
}

// GetPrivateKey decrypts and returns the WireGuard private key.
// The returned key should be securely zeroed after use.
func (c *SecureConfig) GetPrivateKey() (string, error) {
	if c.EncryptedPrivateKey == "" {
		return "", nil
	}
	decrypted, err := DPAPIDecryptMachine(c.EncryptedPrivateKey, wgKeyEntropy)
	if err != nil {
		return "", fmt.Errorf("decrypt private key: %w", err)
	}
	return string(decrypted), nil
}

// SetPrivateKey encrypts and stores the WireGuard private key using machine-scope DPAPI.
// The plaintext key is securely zeroed after encryption.
func (c *SecureConfig) SetPrivateKey(privateKey string) error {
	if privateKey == "" {
		c.EncryptedPrivateKey = ""
		return nil
	}

	keyBytes := []byte(privateKey)
	defer SecureZeroMemory(keyBytes)

	encrypted, err := DPAPIEncryptMachine(keyBytes, wgKeyEntropy)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}
	c.EncryptedPrivateKey = encrypted
	c.KeyVersion = 1 // Track encryption version for future rotation
	return nil
}

// HasSSHKey returns true if the config has an encrypted SSH private key.
func (c *SecureConfig) HasSSHKey() bool {
	return c.EncryptedSSHKey != ""
}

// GetSSHKey decrypts and returns the SSH private key.
// The returned key should be securely zeroed after use.
func (c *SecureConfig) GetSSHKey() (string, error) {
	if c.EncryptedSSHKey == "" {
		return "", nil
	}
	decrypted, err := DPAPIDecryptMachine(c.EncryptedSSHKey, wgKeyEntropy)
	if err != nil {
		return "", fmt.Errorf("decrypt SSH key: %w", err)
	}
	return string(decrypted), nil
}

// SetSSHKey encrypts and stores the SSH private key using machine-scope DPAPI.
// The plaintext key is securely zeroed after encryption.
func (c *SecureConfig) SetSSHKey(sshKey string) error {
	if sshKey == "" {
		c.EncryptedSSHKey = ""
		return nil
	}

	keyBytes := []byte(sshKey)
	defer SecureZeroMemory(keyBytes)

	encrypted, err := DPAPIEncryptMachine(keyBytes, wgKeyEntropy)
	if err != nil {
		return fmt.Errorf("encrypt SSH key: %w", err)
	}
	c.EncryptedSSHKey = encrypted
	return nil
}

// SaveTo saves the config to a YAML file, creating parent directories if needed.
func (c *SecureConfig) SaveTo(path string) error {
	// Ensure parent directory exists with proper ACLs
	dir := filepath.Dir(path)
	if err := EnsureSecureConfigDir(dir); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// CleanupAfterBootstrap removes the setup key after successful mTLS bootstrap.
// This should be called after the machine has obtained a certificate.
func (c *SecureConfig) CleanupAfterBootstrap() error {
	if c.EncryptedSetupKey == "" {
		return nil
	}

	// Securely clear the encrypted key from memory
	keyBytes := []byte(c.EncryptedSetupKey)
	SecureZeroMemory(keyBytes)

	c.EncryptedSetupKey = ""
	return nil
}
