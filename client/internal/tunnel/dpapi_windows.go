//go:build windows

// Package tunnel provides machine tunnel functionality for Windows.
// This file implements DPAPI (Data Protection API) encryption for sensitive
// configuration data like setup keys.
package tunnel

import (
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

// DPAPI flags
const (
	// cryptprotectLocalMachine encrypts data that can only be decrypted on the same machine.
	// This is essential for machine-level secrets that shouldn't be portable.
	cryptprotectLocalMachine = 0x4

	// cryptprotectUIForbidden prevents any UI prompts during encryption/decryption.
	// Required for services running without a desktop session.
	cryptprotectUIForbidden = 0x1
)

// dataBlob represents the Windows DATA_BLOB structure used by DPAPI.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// DPAPIEncrypt encrypts data using Windows DPAPI with LocalMachine scope.
// The encrypted data can only be decrypted on the same machine by the same
// or equivalent security principal (SYSTEM in our case).
//
// Security properties:
//   - Uses CRYPTPROTECT_LOCAL_MACHINE: data is bound to this machine
//   - Uses CRYPTPROTECT_UI_FORBIDDEN: no UI prompts (safe for services)
//   - Returns base64-encoded blob for easy storage in config files
//
// Note: The encrypted blob is useless if copied to another machine or if
// the machine's DPAPI master key is rotated (rare, typically only on
// domain migration).
func DPAPIEncrypt(plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}

	var outBlob dataBlob
	inBlob := dataBlob{
		cbData: uint32(len(plaintext)),
		pbData: &plaintext[0],
	}

	flags := uint32(cryptprotectLocalMachine | cryptprotectUIForbidden)

	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // pszDataDescr - optional description
		0, // pOptionalEntropy - additional entropy (not used)
		0, // pvReserved - must be NULL
		0, // pPromptStruct - prompt info (not used with UI_FORBIDDEN)
		uintptr(flags),
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return "", fmt.Errorf("CryptProtectData failed: %w", err)
	}

	// Copy result before freeing Windows-allocated memory
	encrypted := make([]byte, outBlob.cbData)
	copy(encrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	// Free the memory allocated by Windows
	_, _ = syscall.LocalFree(syscall.Handle(unsafe.Pointer(outBlob.pbData)))

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DPAPIDecrypt decrypts DPAPI-encrypted data.
// The input must be a base64-encoded DPAPI blob created by DPAPIEncrypt.
//
// This will fail if:
//   - The data was encrypted on a different machine
//   - The data was encrypted by a different user (unless using LocalMachine scope)
//   - The data is corrupted or tampered with
func DPAPIDecrypt(encryptedBase64 string) ([]byte, error) {
	if encryptedBase64 == "" {
		return nil, nil
	}

	encrypted, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	if len(encrypted) == 0 {
		return nil, nil
	}

	var outBlob dataBlob
	inBlob := dataBlob{
		cbData: uint32(len(encrypted)),
		pbData: &encrypted[0],
	}

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // ppszDataDescr - receives description (not used)
		0, // pOptionalEntropy - must match encryption entropy
		0, // pvReserved - must be NULL
		0, // pPromptStruct - prompt info (not used with UI_FORBIDDEN)
		uintptr(cryptprotectUIForbidden),
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}

	// Copy result before freeing Windows-allocated memory
	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	// Free the memory allocated by Windows
	_, _ = syscall.LocalFree(syscall.Handle(unsafe.Pointer(outBlob.pbData)))

	return decrypted, nil
}

// SecureZeroMemory overwrites a byte slice with zeros.
// Use this to clear sensitive data from memory after use.
// Note: Go's GC may have already copied the data, so this is defense-in-depth.
func SecureZeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// EncryptSetupKey encrypts a setup key for secure storage in config.
// Returns a base64-encoded DPAPI blob.
func EncryptSetupKey(setupKey string) (string, error) {
	if setupKey == "" {
		return "", nil
	}

	encrypted, err := DPAPIEncrypt([]byte(setupKey))
	if err != nil {
		return "", fmt.Errorf("encrypt setup key: %w", err)
	}

	return encrypted, nil
}

// DecryptSetupKey decrypts a DPAPI-encrypted setup key.
// Returns the plaintext setup key.
func DecryptSetupKey(encryptedKey string) (string, error) {
	if encryptedKey == "" {
		return "", nil
	}

	decrypted, err := DPAPIDecrypt(encryptedKey)
	if err != nil {
		return "", fmt.Errorf("decrypt setup key: %w", err)
	}

	// Ensure we clean up the decrypted bytes when done
	// (caller should also clean up the returned string when done)
	defer SecureZeroMemory(decrypted)

	return string(decrypted), nil
}
