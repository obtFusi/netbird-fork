//go:build !windows

// Package tunnel provides machine tunnel functionality.
// This file provides stub implementations for non-Windows platforms.
package tunnel

import "errors"

// ErrDPAPINotSupported is returned when DPAPI functions are called on non-Windows platforms.
var ErrDPAPINotSupported = errors.New("DPAPI is only supported on Windows")

// DPAPIEncrypt is not supported on non-Windows platforms.
func DPAPIEncrypt(plaintext []byte) (string, error) {
	return "", ErrDPAPINotSupported
}

// DPAPIDecrypt is not supported on non-Windows platforms.
func DPAPIDecrypt(encryptedBase64 string) ([]byte, error) {
	return nil, ErrDPAPINotSupported
}

// SecureZeroMemory overwrites a byte slice with zeros.
func SecureZeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// EncryptSetupKey is not supported on non-Windows platforms.
func EncryptSetupKey(setupKey string) (string, error) {
	return "", ErrDPAPINotSupported
}

// DecryptSetupKey is not supported on non-Windows platforms.
func DecryptSetupKey(encryptedKey string) (string, error) {
	return "", ErrDPAPINotSupported
}
