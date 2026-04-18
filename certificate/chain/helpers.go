package chain

import (
	"crypto/x509"
	"encoding/pem"
)

// AppleIntermediates returns the Apple intermediate CA certificates
// (WWDR G3 and Apple Root CA) as parsed x509.Certificates.
// These must be embedded in the CMS signature for iOS to validate the chain.
func AppleIntermediates() []*x509.Certificate {
	var certs []*x509.Certificate

	for _, pemStr := range []string{appleWWDRCAG3, appleRootCA} {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	return certs
}

// AppleWWDRG3 returns the WWDR G3 intermediate certificate.
func AppleWWDRG3() *x509.Certificate {
	block, _ := pem.Decode([]byte(appleWWDRCAG3))
	if block == nil {
		return nil
	}
	cert, _ := x509.ParseCertificate(block.Bytes)
	return cert
}

// AppleRoot returns the Apple Root CA certificate.
func AppleRoot() *x509.Certificate {
	block, _ := pem.Decode([]byte(appleRootCA))
	if block == nil {
		return nil
	}
	cert, _ := x509.ParseCertificate(block.Bytes)
	return cert
}
