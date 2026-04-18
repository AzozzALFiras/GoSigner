package chain

import (
	"crypto/x509"
	"fmt"
)

// Verify validates a certificate chain against Apple's root CAs.
func Verify(cert *x509.Certificate, intermediates []*x509.Certificate) error {
	pool := x509.NewCertPool()
	for _, inter := range intermediates {
		pool.AddCert(inter)
	}

	opts := x509.VerifyOptions{
		Intermediates: pool,
		Roots:         AppleRootPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}

// BuildChain attempts to build a complete certificate chain from a leaf certificate
// using Apple's embedded CA certificates.
func BuildChain(leaf *x509.Certificate, additionalCerts []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}

	pool := x509.NewCertPool()
	for _, cert := range additionalCerts {
		pool.AddCert(cert)
	}
	// Also add Apple CAs to the intermediate pool
	pool.AppendCertsFromPEM([]byte(appleWWDRCAG3))

	opts := x509.VerifyOptions{
		Intermediates: pool,
		Roots:         AppleRootPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := leaf.Verify(opts)
	if err == nil && len(chains) > 0 {
		return chains[0]
	}

	return chain
}
