//go:build windows

// dpapitest is a test program for DPAPI and ACL functions on Windows.
// Build: GOOS=windows GOARCH=amd64 go build -o dpapitest.exe ./client/internal/tunnel/cmd/dpapitest
// Run on Windows VM (as Administrator) to verify functionality.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/netbirdio/netbird/client/internal/tunnel"
)

func main() {
	fmt.Println("=== NetBird Machine Tunnel - DPAPI & ACL Test ===")
	fmt.Println()

	// Test 1: DPAPI Encrypt/Decrypt
	fmt.Println("[TEST 1] DPAPI Encryption/Decryption")
	testDPAPI()
	fmt.Println()

	// Test 2: Setup Key Encryption
	fmt.Println("[TEST 2] Setup Key Encryption Helper")
	testSetupKeyEncryption()
	fmt.Println()

	// Test 3: SecureZeroMemory
	fmt.Println("[TEST 3] SecureZeroMemory")
	testSecureZeroMemory()
	fmt.Println()

	// Test 4: ACL Hardening (requires admin)
	fmt.Println("[TEST 4] ACL Hardening (requires Administrator)")
	testACLHardening()
	fmt.Println()

	// Test 5: ACL Verification
	fmt.Println("[TEST 5] ACL Verification")
	testACLVerification()
	fmt.Println()

	fmt.Println("=== All tests completed ===")
}

func testDPAPI() {
	testData := "This is a secret NetBird setup key: NBSK-xxxx-xxxx-xxxx"

	// Encrypt
	encrypted, err := tunnel.DPAPIEncrypt([]byte(testData))
	if err != nil {
		fmt.Printf("  [FAIL] DPAPIEncrypt: %v\n", err)
		return
	}
	fmt.Printf("  [OK] DPAPIEncrypt: %d bytes -> %d chars base64\n", len(testData), len(encrypted))

	// Decrypt
	decrypted, err := tunnel.DPAPIDecrypt(encrypted)
	if err != nil {
		fmt.Printf("  [FAIL] DPAPIDecrypt: %v\n", err)
		return
	}
	fmt.Printf("  [OK] DPAPIDecrypt: %d chars base64 -> %d bytes\n", len(encrypted), len(decrypted))

	// Verify round-trip
	if string(decrypted) == testData {
		fmt.Println("  [OK] Round-trip verification passed")
	} else {
		fmt.Println("  [FAIL] Round-trip verification failed - data mismatch!")
	}

	// Test empty input
	emptyEnc, err := tunnel.DPAPIEncrypt([]byte{})
	if err != nil {
		fmt.Printf("  [FAIL] Empty encrypt: %v\n", err)
	} else if emptyEnc == "" {
		fmt.Println("  [OK] Empty input handled correctly")
	}
}

func testSetupKeyEncryption() {
	setupKey := "NBSK-test-1234-5678-abcd-efgh"

	// Encrypt
	encrypted, err := tunnel.EncryptSetupKey(setupKey)
	if err != nil {
		fmt.Printf("  [FAIL] EncryptSetupKey: %v\n", err)
		return
	}
	fmt.Printf("  [OK] EncryptSetupKey: %d char key -> %d chars encrypted\n", len(setupKey), len(encrypted))

	// Decrypt
	decrypted, err := tunnel.DecryptSetupKey(encrypted)
	if err != nil {
		fmt.Printf("  [FAIL] DecryptSetupKey: %v\n", err)
		return
	}

	if decrypted == setupKey {
		fmt.Println("  [OK] Setup key round-trip passed")
	} else {
		fmt.Println("  [FAIL] Setup key mismatch!")
	}

	// Test empty key
	emptyEnc, err := tunnel.EncryptSetupKey("")
	if err != nil {
		fmt.Printf("  [FAIL] Empty key encrypt: %v\n", err)
	} else if emptyEnc == "" {
		fmt.Println("  [OK] Empty setup key handled correctly")
	}
}

func testSecureZeroMemory() {
	data := []byte("sensitive data here")
	original := make([]byte, len(data))
	copy(original, data)

	tunnel.SecureZeroMemory(data)

	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		fmt.Println("  [OK] SecureZeroMemory cleared all bytes")
	} else {
		fmt.Println("  [FAIL] SecureZeroMemory did not clear all bytes!")
	}
}

func testACLHardening() {
	// Create a test directory
	tmpDir := os.TempDir()
	testDir := filepath.Join(tmpDir, "netbird-acl-test")

	// Clean up first
	os.RemoveAll(testDir)

	// Create directory
	if err := os.MkdirAll(testDir, 0700); err != nil {
		fmt.Printf("  [FAIL] Create test dir: %v\n", err)
		return
	}
	defer os.RemoveAll(testDir)

	fmt.Printf("  [INFO] Test directory: %s\n", testDir)

	// Apply ACL hardening
	err := tunnel.HardenConfigDirectory(testDir)
	if err != nil {
		fmt.Printf("  [FAIL] HardenConfigDirectory: %v\n", err)
		fmt.Println("  [INFO] Note: ACL operations require Administrator privileges")
		return
	}
	fmt.Println("  [OK] HardenConfigDirectory succeeded")

	// Test file hardening
	// Note: After ACL hardening, only SYSTEM can write to the directory.
	// Admin only has read access. Try to create a file - it SHOULD fail
	// because we're running as Admin, not SYSTEM.
	testFile := filepath.Join(testDir, "test.conf")
	err = os.WriteFile(testFile, []byte("test config"), 0600)
	if err != nil {
		// This is EXPECTED behavior - Admin only has read access after hardening
		fmt.Printf("  [OK] Write correctly denied after hardening: %v\n", err)
		fmt.Println("  [OK] ACL correctly restricts Admin to read-only")
	} else {
		// If we can still write, ACL hardening didn't work
		fmt.Println("  [WARN] Write succeeded - ACL may not be fully applied")
		// Try to harden the file anyway
		if err := tunnel.HardenConfigFile(testFile); err != nil {
			fmt.Printf("  [FAIL] HardenConfigFile: %v\n", err)
		} else {
			fmt.Println("  [OK] HardenConfigFile succeeded")
		}
	}
}

func testACLVerification() {
	// Use the same test directory
	tmpDir := os.TempDir()
	testDir := filepath.Join(tmpDir, "netbird-acl-test-verify")

	// Clean up first
	os.RemoveAll(testDir)

	// Test EnsureSecureConfigDir (creates and hardens)
	err := tunnel.EnsureSecureConfigDir(testDir)
	if err != nil {
		fmt.Printf("  [FAIL] EnsureSecureConfigDir: %v\n", err)
		fmt.Println("  [INFO] Note: ACL operations require Administrator privileges")
		return
	}
	defer os.RemoveAll(testDir)

	fmt.Println("  [OK] EnsureSecureConfigDir succeeded")

	// Verify ACLs
	err = tunnel.VerifyConfigACL(testDir)
	if err != nil {
		fmt.Printf("  [FAIL] VerifyConfigACL: %v\n", err)
		return
	}
	fmt.Println("  [OK] VerifyConfigACL passed")

	// Test GetConfigDir/GetConfigPath helpers
	configDir := tunnel.GetConfigDir()
	configPath := tunnel.GetConfigPath()
	fmt.Printf("  [INFO] Default config dir: %s\n", configDir)
	fmt.Printf("  [INFO] Default config path: %s\n", configPath)
}
