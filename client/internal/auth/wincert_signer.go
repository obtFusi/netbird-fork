// Machine Tunnel Fork - Windows Certificate Store Signer
// This file provides mTLS authentication using certificates from Windows Certificate Store.
// It implements crypto.Signer using NCrypt APIs for signing without exporting the private key.

//go:build windows

package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// NCrypt API constants for signing
const (
	BCRYPT_PAD_PKCS1 = 0x00000002
	BCRYPT_PAD_PSS   = 0x00000008
)

// BCRYPT_PKCS1_PADDING_INFO for RSA PKCS#1 v1.5 padding
type BCRYPT_PKCS1_PADDING_INFO struct {
	pszAlgId *uint16
}

// BCRYPT_PSS_PADDING_INFO for RSA-PSS padding
type BCRYPT_PSS_PADDING_INFO struct {
	pszAlgId *uint16
	cbSalt   uint32
}

// procNCryptSignHash is loaded from ncrypt.dll (defined in cert_discovery_windows.go)
var procNCryptSignHash = ncrypt.NewProc("NCryptSignHash")

// Hash algorithm identifiers
var (
	algSHA1   *uint16
	algSHA256 *uint16
	algSHA384 *uint16
	algSHA512 *uint16
)

func init() {
	// These cannot fail as the strings don't contain NUL bytes
	algSHA1, _ = syscall.UTF16PtrFromString("SHA1")
	algSHA256, _ = syscall.UTF16PtrFromString("SHA256")
	algSHA384, _ = syscall.UTF16PtrFromString("SHA384")
	algSHA512, _ = syscall.UTF16PtrFromString("SHA512")
}

// WinCertSigner implements crypto.Signer using a certificate from Windows Certificate Store
// This is used for mTLS authentication without exporting the private key.
type WinCertSigner struct {
	// cert is the X.509 certificate
	cert *x509.Certificate

	// identity contains the parsed machine identity
	identity *MachineIdentity

	// handle is the NCrypt key handle (from CNG)
	handle uintptr

	// closed indicates if the signer has been closed
	closed bool
}

// CertSelectionCriteria defines how to select a machine certificate
type CertSelectionCriteria struct {
	// TemplateOID matches AD CS template OID (1.3.6.1.4.1.311.21.7)
	TemplateOID string

	// TemplateName matches AD CS template name
	TemplateName string

	// RequiredEKU matches Extended Key Usage OID
	RequiredEKU string

	// SANMustContain requires SAN DNSName to contain this string
	SANMustContain string

	// ThumbprintExact matches an exact certificate thumbprint (SHA-1)
	ThumbprintExact string
}

// FindMachineCertificate searches Windows Certificate Store for a matching machine certificate
// Store: LocalMachine\My (Personal certificates)
//
// Selection priority:
// 1. ThumbprintExact match (if specified)
// 2. TemplateOID match
// 3. TemplateName match
// 4. EKU = Client Authentication + SAN contains hostname
// 5. Newest valid certificate with Client Authentication EKU
func FindMachineCertificate(criteria CertSelectionCriteria) (*WinCertSigner, error) {
	config := &CertDiscoveryConfig{
		MachineCert: MachineCertConfig{
			Enabled:            true,
			TemplateOID:        criteria.TemplateOID,
			TemplateName:       criteria.TemplateName,
			RequiredEKU:        criteria.RequiredEKU,
			SANMustMatch:       criteria.SANMustContain != "",
			ThumbprintOverride: criteria.ThumbprintExact,
		},
		Hostname: criteria.SANMustContain,
	}

	// Use certificate discovery
	loadedCert, err := DiscoverCertificate(config)
	if err != nil {
		return nil, fmt.Errorf("discover certificate: %w", err)
	}

	// If the loaded certificate already has a WinCertSigner, return it
	if signer, ok := loadedCert.PrivateKey.(*WinCertSigner); ok {
		return signer, nil
	}

	// Otherwise create a new WinCertSigner from the loaded certificate
	return &WinCertSigner{
		cert:     loadedCert.Certificate,
		identity: loadedCert.Identity,
	}, nil
}

// Certificate returns the X.509 certificate
func (s *WinCertSigner) Certificate() *x509.Certificate {
	return s.cert
}

// Identity returns the parsed machine identity from the certificate
func (s *WinCertSigner) Identity() *MachineIdentity {
	return s.identity
}

// Thumbprint returns the SHA-1 thumbprint of the certificate
func (s *WinCertSigner) Thumbprint() string {
	if s.cert == nil {
		return ""
	}
	return fmt.Sprintf("%x", sha1.Sum(s.cert.Raw))
}

// Public returns the public key from the certificate
// This is part of the crypto.Signer interface
func (s *WinCertSigner) Public() crypto.PublicKey {
	if s.cert == nil {
		return nil
	}
	return s.cert.PublicKey
}

// Sign signs digest using the Windows CNG private key
// This is the crypto.Signer interface implementation
func (s *WinCertSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.closed {
		return nil, fmt.Errorf("signer is closed")
	}

	if s.handle == 0 {
		return nil, fmt.Errorf("no NCrypt key handle available")
	}

	// Determine the algorithm based on the public key type
	switch s.cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return s.signRSA(digest, opts)
	case *ecdsa.PublicKey:
		return s.signECDSA(digest, opts)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.cert.PublicKey)
	}
}

// signRSA signs with an RSA key using NCrypt
func (s *WinCertSigner) signRSA(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg := getHashAlgorithm(opts.HashFunc())
	if hashAlg == nil {
		return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
	}

	var paddingInfo unsafe.Pointer
	var flags uint32 = NCRYPT_SILENT_FLAG

	// Check if PSS padding is requested
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		pssInfo := &BCRYPT_PSS_PADDING_INFO{
			pszAlgId: hashAlg,
			cbSalt:   uint32(pssOpts.SaltLength),
		}
		paddingInfo = unsafe.Pointer(pssInfo)
		flags |= BCRYPT_PAD_PSS
	} else {
		// Use PKCS#1 v1.5 padding
		pkcs1Info := &BCRYPT_PKCS1_PADDING_INFO{
			pszAlgId: hashAlg,
		}
		paddingInfo = unsafe.Pointer(pkcs1Info)
		flags |= BCRYPT_PAD_PKCS1
	}

	// First call to get the signature size
	var sigLen uint32
	ret, _, _ := procNCryptSignHash.Call(
		s.handle,
		uintptr(paddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(flags),
	)

	if ret != 0 {
		return nil, fmt.Errorf("NCryptSignHash (size) failed: 0x%x", ret)
	}

	// Allocate signature buffer
	sig := make([]byte, sigLen)

	// Second call to actually sign
	ret, _, _ = procNCryptSignHash.Call(
		s.handle,
		uintptr(paddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(flags),
	)

	if ret != 0 {
		return nil, fmt.Errorf("NCryptSignHash failed: 0x%x", ret)
	}

	return sig[:sigLen], nil
}

// signECDSA signs with an ECDSA key using NCrypt
func (s *WinCertSigner) signECDSA(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// ECDSA signing with NCrypt - no padding info needed
	var flags uint32 = NCRYPT_SILENT_FLAG

	// First call to get the signature size
	var sigLen uint32
	ret, _, _ := procNCryptSignHash.Call(
		s.handle,
		0, // No padding info for ECDSA
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(flags),
	)

	if ret != 0 {
		return nil, fmt.Errorf("NCryptSignHash (size) failed: 0x%x", ret)
	}

	// Allocate signature buffer
	sigBuf := make([]byte, sigLen)

	// Second call to actually sign
	ret, _, _ = procNCryptSignHash.Call(
		s.handle,
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sigBuf[0])),
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(flags),
	)

	if ret != 0 {
		return nil, fmt.Errorf("NCryptSignHash failed: 0x%x", ret)
	}

	// NCrypt returns the signature as concatenated r||s
	// We need to convert to ASN.1 DER format for TLS
	return ecdsaRawToASN1(sigBuf[:sigLen])
}

// ecdsaRawToASN1 converts a raw ECDSA signature (r||s) to ASN.1 DER format
func ecdsaRawToASN1(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("invalid ECDSA signature length")
	}

	halfLen := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:halfLen])
	s := new(big.Int).SetBytes(raw[halfLen:])

	// Encode as ASN.1 SEQUENCE { INTEGER r, INTEGER s }
	type ecdsaSignature struct {
		R, S *big.Int
	}

	return asn1Marshal(ecdsaSignature{r, s})
}

// asn1Marshal marshals an ECDSA signature to ASN.1
func asn1Marshal(sig interface{}) ([]byte, error) {
	// Simple ASN.1 encoding for ECDSA signature
	type ecdsaSig struct {
		R, S *big.Int
	}
	s := sig.(ecdsaSig)

	// Encode R
	rBytes := s.R.Bytes()
	// Encode S
	sBytes := s.S.Bytes()

	// ASN.1 SEQUENCE { INTEGER R, INTEGER S }
	// We need to handle leading zeros for positive integers

	rEnc := encodeASN1Integer(rBytes)
	sEnc := encodeASN1Integer(sBytes)

	// SEQUENCE tag + length + content
	var content []byte
	content = append(content, rEnc...)
	content = append(content, sEnc...)
	return append([]byte{0x30, byte(len(content))}, content...), nil
}

// encodeASN1Integer encodes a byte slice as an ASN.1 INTEGER
func encodeASN1Integer(b []byte) []byte {
	// Remove leading zeros
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}

	// Add leading zero if high bit is set (to keep it positive)
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}

	return append([]byte{0x02, byte(len(b))}, b...)
}

// getHashAlgorithm returns the Windows algorithm identifier for a hash function
func getHashAlgorithm(hash crypto.Hash) *uint16 {
	switch hash {
	case crypto.SHA1:
		return algSHA1
	case crypto.SHA256:
		return algSHA256
	case crypto.SHA384:
		return algSHA384
	case crypto.SHA512:
		return algSHA512
	default:
		return nil
	}
}

// Close releases the NCrypt handles
func (s *WinCertSigner) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true

	if s.handle != 0 {
		ret, _, _ := procNCryptFreeObject.Call(s.handle)
		if ret != 0 {
			log.WithField("error", fmt.Sprintf("0x%x", ret)).Warn("NCryptFreeObject failed")
		}
		s.handle = 0
	}

	return nil
}

// ParseMachineIdentity extracts machine identity from a certificate's SAN DNSName
func ParseMachineIdentity(cert *x509.Certificate) (*MachineIdentity, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	// Calculate thumbprint
	thumbprint := fmt.Sprintf("%x", sha1.Sum(cert.Raw))

	// Find first SAN DNSName that looks like hostname.domain
	for _, dnsName := range cert.DNSNames {
		hostname, domain, ok := splitFQDN(dnsName)
		if ok {
			return &MachineIdentity{
				Hostname:       hostname,
				Domain:         domain,
				FQDN:           dnsName,
				CertThumbprint: thumbprint,
			}, nil
		}
	}

	return nil, fmt.Errorf("no valid SAN DNSName found in certificate")
}

// splitFQDN splits "hostname.domain.tld" into ("hostname", "domain.tld")
func splitFQDN(fqdn string) (hostname, domain string, ok bool) {
	// Find first dot
	for i, c := range fqdn {
		if c == '.' {
			if i > 0 && i < len(fqdn)-1 {
				return fqdn[:i], fqdn[i+1:], true
			}
			return "", "", false
		}
	}
	return "", "", false
}
