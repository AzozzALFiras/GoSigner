package loader

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/AzozzALFiras/GoSigner/certificate"
)

// LoadPEM loads a PEM-encoded private key and optional certificate file.
func LoadPEM(keyPath string, certPath string) (*certificate.SigningIdentity, error) {
	key, err := loadPEMKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load pem key: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key type %T does not implement crypto.Signer", key)
	}

	identity := &certificate.SigningIdentity{
		PrivateKey: signer,
	}

	if certPath != "" {
		cert, chain, err := loadPEMCerts(certPath)
		if err != nil {
			return nil, fmt.Errorf("load pem cert: %w", err)
		}
		identity.Certificate = cert
		identity.CertChain = chain
		identity.RawCertDER = cert.Raw
		identity.TeamID = certificate.ExtractTeamID(cert)
		identity.SubjectCN = certificate.ExtractSubjectCN(cert)
	}

	return identity, nil
}

func loadPEMKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS8 key type: %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

func loadPEMCerts(path string) (*x509.Certificate, []*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in %s", path)
	}

	return certs[0], certs, nil
}
