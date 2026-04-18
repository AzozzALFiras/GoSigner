package certificate

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"
)

// SigningIdentity holds a certificate and private key for code signing.
type SigningIdentity struct {
	Certificate *x509.Certificate   // Leaf signing certificate
	PrivateKey  crypto.Signer       // RSA or ECDSA private key
	CertChain   []*x509.Certificate // Full chain: leaf → intermediate(s) → root
	RawCertDER  []byte              // Leaf certificate in DER encoding
	TeamID      string              // Extracted from OU field
	SubjectCN   string              // Common Name from subject
}

// IsExpired returns true if the certificate has expired.
func (s *SigningIdentity) IsExpired() bool {
	return time.Now().After(s.Certificate.NotAfter)
}

// ExpiresAt returns the certificate expiration time.
func (s *SigningIdentity) ExpiresAt() time.Time {
	return s.Certificate.NotAfter
}

// String returns a human-readable summary of the identity.
func (s *SigningIdentity) String() string {
	return fmt.Sprintf("CN=%s, TeamID=%s, Expires=%s",
		s.SubjectCN, s.TeamID, s.Certificate.NotAfter.Format("2006-01-02"))
}

// ExtractTeamID extracts the Team ID from a certificate's Organizational Unit field.
func ExtractTeamID(cert *x509.Certificate) string {
	for _, ou := range cert.Subject.OrganizationalUnit {
		if len(ou) > 0 {
			return ou
		}
	}
	return ""
}

// ExtractSubjectCN extracts the Common Name from a certificate.
func ExtractSubjectCN(cert *x509.Certificate) string {
	return cert.Subject.CommonName
}
