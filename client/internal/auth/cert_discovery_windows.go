// Machine Tunnel Fork - Windows Certificate Store Discovery
// This file implements certificate discovery from Windows Certificate Store.
// It uses the CryptoAPI and NCrypt APIs for accessing machine certificates.

//go:build windows

package auth

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/tunnel"
)

// Windows API constants
const (
	// Certificate store names
	CERT_STORE_PROV_SYSTEM          = 10
	CERT_STORE_OPEN_EXISTING_FLAG   = 0x00004000
	CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000

	// Certificate encoding
	X509_ASN_ENCODING   = 0x00000001
	PKCS_7_ASN_ENCODING = 0x00010000

	// Certificate find flags
	CERT_FIND_ANY        = 0
	CERT_FIND_HASH       = 0x00010000
	CERT_FIND_SUBJECT_STR = 0x00080007

	// Key spec
	AT_KEYEXCHANGE = 1
	AT_SIGNATURE   = 2

	// NCrypt
	NCRYPT_SILENT_FLAG = 0x00000040

	// Property IDs
	CERT_HASH_PROP_ID = 3
)

// Windows API structures
type CRYPT_HASH_BLOB struct {
	cbData uint32
	pbData *byte
}

type CERT_INFO struct {
	dwVersion            uint32
	SerialNumber         CRYPT_HASH_BLOB
	SignatureAlgorithm   CRYPT_ALGORITHM_IDENTIFIER
	Issuer               CRYPT_HASH_BLOB
	NotBefore            syscall.Filetime
	NotAfter             syscall.Filetime
	Subject              CRYPT_HASH_BLOB
	SubjectPublicKeyInfo CERT_PUBLIC_KEY_INFO
	IssuerUniqueId       CRYPT_BIT_BLOB
	SubjectUniqueId      CRYPT_BIT_BLOB
	cExtension           uint32
	rgExtension          *CERT_EXTENSION
}

type CRYPT_ALGORITHM_IDENTIFIER struct {
	pszObjId   *byte
	Parameters CRYPT_HASH_BLOB
}

type CERT_PUBLIC_KEY_INFO struct {
	Algorithm CRYPT_ALGORITHM_IDENTIFIER
	PublicKey CRYPT_BIT_BLOB
}

type CRYPT_BIT_BLOB struct {
	cbData      uint32
	pbData      *byte
	cUnusedBits uint32
}

type CERT_EXTENSION struct {
	pszObjId  *byte
	fCritical int32
	Value     CRYPT_HASH_BLOB
}

type CERT_CONTEXT struct {
	dwCertEncodingType uint32
	pbCertEncoded      *byte
	cbCertEncoded      uint32
	pCertInfo          *CERT_INFO
	hCertStore         syscall.Handle
}

var (
	crypt32                           = syscall.NewLazyDLL("crypt32.dll")
	ncrypt                            = syscall.NewLazyDLL("ncrypt.dll")
	procCertOpenStore                 = crypt32.NewProc("CertOpenStore")
	procCertCloseStore                = crypt32.NewProc("CertCloseStore")
	procCertEnumCertificatesInStore   = crypt32.NewProc("CertEnumCertificatesInStore")
	procCertFindCertificateInStore    = crypt32.NewProc("CertFindCertificateInStore")
	procCertFreeCertificateContext    = crypt32.NewProc("CertFreeCertificateContext")
	procCertGetCertificateContextProperty = crypt32.NewProc("CertGetCertificateContextProperty")
	procCryptAcquireCertificatePrivateKey = crypt32.NewProc("CryptAcquireCertificatePrivateKey")
	procNCryptFreeObject              = ncrypt.NewProc("NCryptFreeObject")
)

// discoverFromWindowsStoreImpl implements Windows Certificate Store discovery
func discoverFromWindowsStoreImpl(config *CertDiscoveryConfig) (*LoadedCertificate, error) {
	// Open the Local Machine Personal certificate store
	store, err := openCertStore("MY")
	if err != nil {
		return nil, fmt.Errorf("open certificate store: %w", err)
	}
	defer closeCertStore(store)

	// Enumerate certificates and find the best match
	var bestCert *LoadedCertificate
	var bestScore int

	err = enumCertificates(store, func(certCtx *CERT_CONTEXT) bool {
		// Parse the certificate
		cert, err := parseCertContext(certCtx)
		if err != nil {
			log.WithError(err).Debug("Failed to parse certificate")
			return true // Continue enumeration
		}

		// Score the certificate
		score := scoreCertificate(cert, config)
		if score > bestScore {
			// Try to get the private key
			signer, err := acquirePrivateKey(certCtx)
			if err != nil {
				log.WithError(err).Debug("Failed to acquire private key")
				return true // Continue enumeration
			}

			// Parse identity
			identity, _ := ParseMachineIdentity(cert)

			// Parse template info
			templateInfo, _ := parseTemplateInfo(cert)
			templateOID := ""
			templateName := ""
			if templateInfo != nil {
				templateOID = templateInfo.OID
				templateName = templateInfo.Name
			}

			// Calculate thumbprint
			thumbprint := fmt.Sprintf("%x", sha1.Sum(cert.Raw))

			bestCert = &LoadedCertificate{
				Certificate:  cert,
				PrivateKey:   signer,
				Source:       CertSourceWindowsStore,
				Thumbprint:   thumbprint,
				TemplateOID:  templateOID,
				TemplateName: templateName,
				Identity:     identity,
			}
			bestScore = score
		}

		return true // Continue enumeration
	})

	if err != nil {
		return nil, fmt.Errorf("enumerate certificates: %w", err)
	}

	if bestCert == nil {
		return nil, fmt.Errorf("no matching certificate found in store")
	}

	// Validate the best certificate
	if err := validateCertificate(bestCert, config); err != nil {
		return nil, fmt.Errorf("best certificate validation failed: %w", err)
	}

	log.WithFields(log.Fields{
		"thumbprint": bestCert.Thumbprint,
		"subject":    bestCert.Certificate.Subject.CommonName,
		"template":   bestCert.TemplateOID,
		"identity":   bestCert.Identity,
	}).Info("Found machine certificate")

	return bestCert, nil
}

// findCertByThumbprintFromStoreImpl finds a certificate by thumbprint
func findCertByThumbprintFromStoreImpl(thumbprint string) (*LoadedCertificate, error) {
	// Open the Local Machine Personal certificate store
	store, err := openCertStore("MY")
	if err != nil {
		return nil, fmt.Errorf("open certificate store: %w", err)
	}
	defer closeCertStore(store)

	// Decode thumbprint
	thumbprintBytes, err := hex.DecodeString(strings.ReplaceAll(thumbprint, " ", ""))
	if err != nil {
		return nil, fmt.Errorf("invalid thumbprint format: %w", err)
	}

	// Find certificate by hash
	hashBlob := CRYPT_HASH_BLOB{
		cbData: uint32(len(thumbprintBytes)),
		pbData: &thumbprintBytes[0],
	}

	certCtx, _, err := procCertFindCertificateInStore.Call(
		uintptr(store),
		uintptr(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING),
		0,
		uintptr(CERT_FIND_HASH),
		uintptr(unsafe.Pointer(&hashBlob)),
		0,
	)

	if certCtx == 0 {
		return nil, fmt.Errorf("certificate not found with thumbprint %s", thumbprint)
	}
	defer func() { _, _, _ = procCertFreeCertificateContext.Call(certCtx) }()

	// Parse the certificate
	ctx := (*CERT_CONTEXT)(unsafe.Pointer(certCtx))
	cert, err := parseCertContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	// Get private key
	signer, err := acquirePrivateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire private key: %w", err)
	}

	// Parse identity
	identity, _ := ParseMachineIdentity(cert)

	// Parse template info
	templateInfo, _ := parseTemplateInfo(cert)
	templateOID := ""
	templateName := ""
	if templateInfo != nil {
		templateOID = templateInfo.OID
		templateName = templateInfo.Name
	}

	return &LoadedCertificate{
		Certificate:  cert,
		PrivateKey:   signer,
		Source:       CertSourceWindowsStore,
		Thumbprint:   thumbprint,
		TemplateOID:  templateOID,
		TemplateName: templateName,
		Identity:     identity,
	}, nil
}

// openCertStore opens a certificate store
func openCertStore(storeName string) (syscall.Handle, error) {
	storeNamePtr, err := syscall.UTF16PtrFromString(storeName)
	if err != nil {
		return 0, err
	}

	store, _, err := procCertOpenStore.Call(
		uintptr(CERT_STORE_PROV_SYSTEM),
		0,
		0,
		uintptr(CERT_SYSTEM_STORE_LOCAL_MACHINE|CERT_STORE_OPEN_EXISTING_FLAG),
		uintptr(unsafe.Pointer(storeNamePtr)),
	)

	if store == 0 {
		return 0, fmt.Errorf("CertOpenStore failed: %w", err)
	}

	return syscall.Handle(store), nil
}

// closeCertStore closes a certificate store
func closeCertStore(store syscall.Handle) {
	_, _, _ = procCertCloseStore.Call(uintptr(store), 0)
}

// enumCertificates enumerates certificates in a store
func enumCertificates(store syscall.Handle, callback func(*CERT_CONTEXT) bool) error {
	var prevCtx uintptr

	for {
		certCtx, _, _ := procCertEnumCertificatesInStore.Call(
			uintptr(store),
			prevCtx,
		)

		if certCtx == 0 {
			break
		}

		ctx := (*CERT_CONTEXT)(unsafe.Pointer(certCtx))
		if !callback(ctx) {
			_, _, _ = procCertFreeCertificateContext.Call(certCtx)
			break
		}

		prevCtx = certCtx
	}

	return nil
}

// parseCertContext parses a CERT_CONTEXT into an x509.Certificate
func parseCertContext(ctx *CERT_CONTEXT) (*x509.Certificate, error) {
	if ctx == nil || ctx.pbCertEncoded == nil {
		return nil, fmt.Errorf("invalid certificate context")
	}

	// Copy certificate bytes
	certBytes := make([]byte, ctx.cbCertEncoded)
	copy(certBytes, unsafe.Slice(ctx.pbCertEncoded, ctx.cbCertEncoded))

	// Parse certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, nil
}

// scoreCertificate scores a certificate based on selection criteria
func scoreCertificate(cert *x509.Certificate, config *CertDiscoveryConfig) int {
	score := 0

	// Check validity
	if cert.NotBefore.After(cert.NotAfter) {
		return 0 // Invalid cert
	}

	// Check template OID match (highest priority)
	if config.MachineCert.TemplateOID != "" {
		templateInfo, _ := parseTemplateInfo(cert)
		if templateInfo != nil && templateInfo.OID == config.MachineCert.TemplateOID {
			score += 100
		}
	}

	// Check template name match
	if config.MachineCert.TemplateName != "" {
		templateInfo, _ := parseTemplateInfo(cert)
		if templateInfo != nil && templateInfo.Name == config.MachineCert.TemplateName {
			score += 80
		}
	}

	// Check EKU match
	if config.MachineCert.RequiredEKU != "" {
		if hasEKU(cert, config.MachineCert.RequiredEKU) {
			score += 50
		} else {
			return 0 // Required EKU missing
		}
	} else {
		// Default: require Client Authentication
		if hasEKU(cert, tunnel.DefaultClientAuthEKU) {
			score += 50
		}
	}

	// Check SAN hostname match
	if config.Hostname != "" {
		if sanContainsHostname(cert, config.Hostname) {
			score += 30
		} else if config.MachineCert.SANMustMatch {
			return 0 // SAN must match but doesn't
		}
	}

	// Prefer newer certificates
	score += int(cert.NotAfter.Unix() / 86400 % 1000) // Days until expiry (mod 1000)

	return score
}

// acquirePrivateKey acquires the private key for a certificate
func acquirePrivateKey(ctx *CERT_CONTEXT) (crypto.Signer, error) {
	var keyHandle uintptr
	var keySpec uint32
	var freeKey int32

	// Try to acquire the private key
	ret, _, err := procCryptAcquireCertificatePrivateKey.Call(
		uintptr(unsafe.Pointer(ctx)),
		uintptr(0x00040000), // CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
		0,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&freeKey)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptAcquireCertificatePrivateKey failed: %w", err)
	}

	// Parse the certificate for public key info
	cert, err := parseCertContext(ctx)
	if err != nil {
		if freeKey != 0 {
			_, _, _ = procNCryptFreeObject.Call(keyHandle)
		}
		return nil, err
	}

	// Create the WinCertSigner
	identity, _ := ParseMachineIdentity(cert)

	signer := &WinCertSigner{
		cert:     cert,
		identity: identity,
		handle:   keyHandle,
	}

	return signer, nil
}
