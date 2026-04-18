package loader

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/AzozzALFiras/GoSigner/certificate"
	"software.sslmate.com/src/go-pkcs12"
)

// LoadP12 loads a PKCS#12 (.p12) file and returns a SigningIdentity.
// password can be empty for unencrypted p12 files.
func LoadP12(path string, password string) (*certificate.SigningIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read p12 file: %w", err)
	}

	return LoadP12FromBytes(data, password)
}

// LoadP12FromBytes loads a PKCS#12 from raw bytes.
func LoadP12FromBytes(data []byte, password string) (*certificate.SigningIdentity, error) {
	// Try DecodeChain first for p12 with intermediates
	privateKey, cert, chain, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		// Fallback to simple decode
		privateKey, cert, err = pkcs12.Decode(data, password)
		if err != nil {
			return nil, fmt.Errorf("decode p12: %w", err)
		}
		chain = nil
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key type %T does not implement crypto.Signer", privateKey)
	}

	fullChain := make([]*x509.Certificate, 0, 1+len(chain))
	fullChain = append(fullChain, cert)
	fullChain = append(fullChain, chain...)

	identity := &certificate.SigningIdentity{
		Certificate: cert,
		PrivateKey:  signer,
		CertChain:   fullChain,
		RawCertDER:  cert.Raw,
		TeamID:      certificate.ExtractTeamID(cert),
		SubjectCN:   certificate.ExtractSubjectCN(cert),
	}

	return identity, nil
}
