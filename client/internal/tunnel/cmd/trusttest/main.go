// +build ignore

// trusttest is a simple test program for DPAPI and Trust functions on Windows.
// Build: GOOS=windows GOARCH=amd64 go build -o trusttest.exe ./client/internal/tunnel/cmd/trusttest
// Run on Windows VM to verify functionality.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/netbirdio/netbird/client/internal/tunnel"
)

func main() {
	fmt.Println("=== NetBird Machine Tunnel - Trust & Security Test ===")
	fmt.Println()

	// Test 1: Certificate Pin Calculation
	fmt.Println("[TEST 1] Certificate Pin Calculation")
	testCertPin()
	fmt.Println()

	// Test 2: Certificate Pinning Verification
	fmt.Println("[TEST 2] Certificate Pinning Verification")
	testPinVerification()
	fmt.Println()

	// Test 3: Trust Bootstrap (pinning mode)
	fmt.Println("[TEST 3] Trust Bootstrap (Pinning Mode)")
	testTrustBootstrap()
	fmt.Println()

	fmt.Println("=== All tests completed ===")
}

func testCertPin() {
	// Generate a test certificate
	cert, certPEM := generateTestCert()

	// Write to temp file
	tmpDir := os.TempDir()
	certPath := filepath.Join(tmpDir, "test-cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		fmt.Printf("  [FAIL] Write cert file: %v\n", err)
		return
	}
	defer os.Remove(certPath)

	// Test GetCertPin from file
	pin1, err := tunnel.GetCertPin(certPath)
	if err != nil {
		fmt.Printf("  [FAIL] GetCertPin: %v\n", err)
		return
	}
	fmt.Printf("  [OK] GetCertPin from file: %s...\n", pin1[:30])

	// Test GetCertPinFromX509
	pin2 := tunnel.GetCertPinFromX509(cert)
	fmt.Printf("  [OK] GetCertPinFromX509: %s...\n", pin2[:30])

	// Verify consistency
	if pin1 == pin2 {
		fmt.Println("  [OK] Pin calculation is consistent across methods")
	} else {
		fmt.Println("  [FAIL] Pin calculation inconsistent!")
	}
}

func testPinVerification() {
	cert, _ := generateTestCert()
	correctPin := tunnel.GetCertPinFromX509(cert)

	// Test with correct pin
	cfg := &tunnel.TrustConfig{
		CertPin: correctPin,
	}
	verifyFunc := tunnel.VerifyServerCert(cfg)
	err := verifyFunc([][]byte{cert.Raw}, nil)
	if err == nil {
		fmt.Println("  [OK] Correct pin verification passed")
	} else {
		fmt.Printf("  [FAIL] Correct pin verification failed: %v\n", err)
	}

	// Test with wrong pin
	cfg2 := &tunnel.TrustConfig{
		CertPin: "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaa=",
	}
	verifyFunc2 := tunnel.VerifyServerCert(cfg2)
	err2 := verifyFunc2([][]byte{cert.Raw}, nil)
	if err2 != nil {
		fmt.Println("  [OK] Wrong pin verification correctly rejected")
	} else {
		fmt.Println("  [FAIL] Wrong pin should have been rejected!")
	}

	// Test backup pin
	cfg3 := &tunnel.TrustConfig{
		CertPin:   "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaa=",
		BackupPin: correctPin,
	}
	verifyFunc3 := tunnel.VerifyServerCert(cfg3)
	err3 := verifyFunc3([][]byte{cert.Raw}, nil)
	if err3 == nil {
		fmt.Println("  [OK] Backup pin verification passed")
	} else {
		fmt.Printf("  [FAIL] Backup pin verification failed: %v\n", err3)
	}
}

func testTrustBootstrap() {
	// Test with pinning (no CA installation needed)
	cfg := &tunnel.TrustConfig{
		CertPin: "sha256//dGVzdHBpbmZvcmJvb3RzdHJhcHRlc3RpbmcxMjM0NTY=",
	}

	err := tunnel.TrustBootstrap(cfg)
	if err == nil {
		fmt.Println("  [OK] Trust bootstrap with pinning succeeded")
	} else {
		fmt.Printf("  [FAIL] Trust bootstrap failed: %v\n", err)
	}
}

func generateTestCert() (*x509.Certificate, []byte) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"NetBird Test"},
			CommonName:   "test.netbird.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.netbird.local"},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return cert, certPEM
}
