// Machine Tunnel Fork - AD CS Template Parser
// This file provides parsing of AD CS certificate template information
// from X.509 certificate extensions.

package auth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// TemplateInfo contains AD CS certificate template information
type TemplateInfo struct {
	// OID is the template OID (from szOID_CERTIFICATE_TEMPLATE extension)
	OID string

	// Name is the template name (from szOID_ENROLL_CERTTYPE_EXTENSION)
	Name string

	// MajorVersion is the template major version
	MajorVersion int

	// MinorVersion is the template minor version
	MinorVersion int
}

// OID constants for AD CS certificate extensions
var (
	// szOID_CERTIFICATE_TEMPLATE (1.3.6.1.4.1.311.21.7)
	// Contains: Template OID, Major Version, Minor Version
	oidCertificateTemplate = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}

	// szOID_ENROLL_CERTTYPE_EXTENSION (1.3.6.1.4.1.311.20.2)
	// Contains: Template Name (string)
	oidEnrollCertTypeExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
)

// CertificateTemplateExtension represents the ASN.1 structure of
// the Certificate Template extension (1.3.6.1.4.1.311.21.7)
type CertificateTemplateExtension struct {
	TemplateID   asn1.ObjectIdentifier
	MajorVersion int `asn1:"optional"`
	MinorVersion int `asn1:"optional"`
}

// parseTemplateInfo extracts AD CS template information from a certificate
func parseTemplateInfo(cert *x509.Certificate) (*TemplateInfo, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	info := &TemplateInfo{}

	// Look for szOID_CERTIFICATE_TEMPLATE extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidCertificateTemplate) {
			templateExt, err := parseCertificateTemplateExtension(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("parse certificate template extension: %w", err)
			}
			info.OID = templateExt.TemplateID.String()
			info.MajorVersion = templateExt.MajorVersion
			info.MinorVersion = templateExt.MinorVersion
		}

		if ext.Id.Equal(oidEnrollCertTypeExtension) {
			name, err := parseEnrollCertTypeExtension(ext.Value)
			if err != nil {
				// Non-fatal, just log
				continue
			}
			info.Name = name
		}
	}

	// If no template info found, return nil (not an error)
	if info.OID == "" && info.Name == "" {
		return nil, nil
	}

	return info, nil
}

// parseCertificateTemplateExtension parses the Certificate Template extension
func parseCertificateTemplateExtension(data []byte) (*CertificateTemplateExtension, error) {
	var ext CertificateTemplateExtension
	rest, err := asn1.Unmarshal(data, &ext)
	if err != nil {
		return nil, fmt.Errorf("unmarshal certificate template: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in certificate template extension")
	}
	return &ext, nil
}

// parseEnrollCertTypeExtension parses the Enroll CertType extension
// This extension contains the template name as a BMPString (UTF-16)
func parseEnrollCertTypeExtension(data []byte) (string, error) {
	// The extension value is a BMPString (UTF-16BE)
	var bmpString asn1.RawValue
	rest, err := asn1.Unmarshal(data, &bmpString)
	if err != nil {
		return "", fmt.Errorf("unmarshal enroll certtype: %w", err)
	}
	if len(rest) > 0 {
		return "", fmt.Errorf("trailing data in enroll certtype extension")
	}

	// Convert BMPString (UTF-16BE) to string
	if bmpString.Tag == asn1.TagBMPString {
		return decodeBMPString(bmpString.Bytes)
	}

	// Try as UTF8String or PrintableString
	if bmpString.Tag == asn1.TagUTF8String || bmpString.Tag == asn1.TagPrintableString {
		return string(bmpString.Bytes), nil
	}

	return "", fmt.Errorf("unexpected tag type: %d", bmpString.Tag)
}

// decodeBMPString decodes a BMPString (UTF-16BE) to a Go string
func decodeBMPString(data []byte) (string, error) {
	if len(data)%2 != 0 {
		return "", fmt.Errorf("invalid BMPString length")
	}

	// Convert UTF-16BE to runes
	runes := make([]rune, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		runes[i/2] = rune(uint16(data[i])<<8 | uint16(data[i+1]))
	}

	return string(runes), nil
}

// GetTemplateOIDFromName returns a well-known template OID from its name
// This is a mapping of common AD CS template names to their OIDs
func GetTemplateOIDFromName(name string) string {
	// Common Microsoft certificate template OIDs
	templates := map[string]string{
		"Workstation Authentication": "1.3.6.1.4.1.311.21.8.8744058.11022373.11498874.3808046.3809375.248.5990296.16385029",
		"Computer":                   "1.3.6.1.4.1.311.21.8.8744058.11022373.11498874.3808046.3809375.248.1.1",
		"WebServer":                  "1.3.6.1.4.1.311.21.8.8744058.11022373.11498874.3808046.3809375.248.2.1",
		// Add more as needed
	}

	if oid, ok := templates[name]; ok {
		return oid
	}
	return ""
}

// ExtractSubjectInfo extracts common subject information from a certificate
type SubjectInfo struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Locality           string
	Province           string
}

// ParseSubjectInfo extracts subject information from a certificate
func ParseSubjectInfo(cert *x509.Certificate) *SubjectInfo {
	if cert == nil {
		return nil
	}

	return &SubjectInfo{
		CommonName:         cert.Subject.CommonName,
		Organization:       getFirst(cert.Subject.Organization),
		OrganizationalUnit: getFirst(cert.Subject.OrganizationalUnit),
		Country:            getFirst(cert.Subject.Country),
		Locality:           getFirst(cert.Subject.Locality),
		Province:           getFirst(cert.Subject.Province),
	}
}

func getFirst(slice []string) string {
	if len(slice) > 0 {
		return slice[0]
	}
	return ""
}

// ExtractIssuerInfo extracts common issuer information from a certificate
type IssuerInfo struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
}

// ParseIssuerInfo extracts issuer information from a certificate
func ParseIssuerInfo(cert *x509.Certificate) *IssuerInfo {
	if cert == nil {
		return nil
	}

	return &IssuerInfo{
		CommonName:         cert.Issuer.CommonName,
		Organization:       getFirst(cert.Issuer.Organization),
		OrganizationalUnit: getFirst(cert.Issuer.OrganizationalUnit),
	}
}

// CertificateTemplateOIDExtension is a helper for working with template OIDs
type CertificateTemplateOIDExtension struct {
	OID pkix.Extension
}

// FindExtension finds an extension by OID in a certificate
func FindExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) *pkix.Extension {
	if cert == nil {
		return nil
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return &ext
		}
	}
	return nil
}
