//go:build windows

package tunnel

import (
	"strings"
	"testing"
)

func TestDPAPIEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple string",
			plaintext: "hello world",
		},
		{
			name:      "setup key format",
			plaintext: "nb-setup-abc123def456ghi789",
		},
		{
			name:      "unicode",
			plaintext: "Привет мир 你好世界",
		},
		{
			name:      "special characters",
			plaintext: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
		},
		{
			name:      "long string",
			plaintext: strings.Repeat("a", 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := DPAPIEncrypt([]byte(tt.plaintext))
			if err != nil {
				t.Fatalf("DPAPIEncrypt failed: %v", err)
			}

			if encrypted == "" {
				t.Fatal("Encrypted result is empty")
			}

			// Encrypted should be different from plaintext
			if encrypted == tt.plaintext {
				t.Error("Encrypted data equals plaintext")
			}

			// Decrypt
			decrypted, err := DPAPIDecrypt(encrypted)
			if err != nil {
				t.Fatalf("DPAPIDecrypt failed: %v", err)
			}

			// Should match original
			if string(decrypted) != tt.plaintext {
				t.Errorf("Decrypted doesn't match: got %q, want %q", string(decrypted), tt.plaintext)
			}
		})
	}
}

func TestDPAPIEncryptEmpty(t *testing.T) {
	encrypted, err := DPAPIEncrypt([]byte{})
	if err != nil {
		t.Fatalf("DPAPIEncrypt(empty) failed: %v", err)
	}
	if encrypted != "" {
		t.Errorf("Expected empty string for empty input, got %q", encrypted)
	}

	encrypted, err = DPAPIEncrypt(nil)
	if err != nil {
		t.Fatalf("DPAPIEncrypt(nil) failed: %v", err)
	}
	if encrypted != "" {
		t.Errorf("Expected empty string for nil input, got %q", encrypted)
	}
}

func TestDPAPIDecryptEmpty(t *testing.T) {
	decrypted, err := DPAPIDecrypt("")
	if err != nil {
		t.Fatalf("DPAPIDecrypt(empty) failed: %v", err)
	}
	if decrypted != nil {
		t.Errorf("Expected nil for empty input, got %v", decrypted)
	}
}

func TestDPAPIDecryptInvalidBase64(t *testing.T) {
	_, err := DPAPIDecrypt("not-valid-base64!!!")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

func TestDPAPIDecryptInvalidBlob(t *testing.T) {
	// Valid base64 but not a valid DPAPI blob
	_, err := DPAPIDecrypt("aGVsbG8gd29ybGQ=") // "hello world" in base64
	if err == nil {
		t.Error("Expected error for invalid DPAPI blob")
	}
}

func TestEncryptDecryptSetupKey(t *testing.T) {
	setupKey := "nb-setup-test123456789"

	encrypted, err := EncryptSetupKey(setupKey)
	if err != nil {
		t.Fatalf("EncryptSetupKey failed: %v", err)
	}

	if encrypted == "" {
		t.Fatal("Encrypted setup key is empty")
	}

	if encrypted == setupKey {
		t.Error("Encrypted setup key equals plaintext")
	}

	decrypted, err := DecryptSetupKey(encrypted)
	if err != nil {
		t.Fatalf("DecryptSetupKey failed: %v", err)
	}

	if decrypted != setupKey {
		t.Errorf("Decrypted setup key doesn't match: got %q, want %q", decrypted, setupKey)
	}
}

func TestEncryptSetupKeyEmpty(t *testing.T) {
	encrypted, err := EncryptSetupKey("")
	if err != nil {
		t.Fatalf("EncryptSetupKey(empty) failed: %v", err)
	}
	if encrypted != "" {
		t.Errorf("Expected empty string for empty input, got %q", encrypted)
	}
}

func TestDecryptSetupKeyEmpty(t *testing.T) {
	decrypted, err := DecryptSetupKey("")
	if err != nil {
		t.Fatalf("DecryptSetupKey(empty) failed: %v", err)
	}
	if decrypted != "" {
		t.Errorf("Expected empty string for empty input, got %q", decrypted)
	}
}

func TestSecureZeroMemory(t *testing.T) {
	data := []byte("sensitive data")
	original := make([]byte, len(data))
	copy(original, data)

	SecureZeroMemory(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %d", i, b)
		}
	}
}

func TestSecureZeroMemoryEmpty(t *testing.T) {
	// Should not panic on empty slice
	SecureZeroMemory([]byte{})
	SecureZeroMemory(nil)
}

// BenchmarkDPAPIEncrypt measures encryption performance
func BenchmarkDPAPIEncrypt(b *testing.B) {
	data := []byte("nb-setup-benchmark-test-key-12345")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DPAPIEncrypt(data)
	}
}

// BenchmarkDPAPIDecrypt measures decryption performance
func BenchmarkDPAPIDecrypt(b *testing.B) {
	data := []byte("nb-setup-benchmark-test-key-12345")
	encrypted, _ := DPAPIEncrypt(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DPAPIDecrypt(encrypted)
	}
}
