package loader

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadP8 loads an Apple Auth Key (.p8) file.
// These are PKCS#8 encoded EC P-256 private keys used for App Store Connect API.
func LoadP8(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read p8 file: %w", err)
	}

	return LoadP8FromBytes(data)
}

// LoadP8FromBytes loads an Apple Auth Key from raw PEM bytes.
func LoadP8FromBytes(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in p8 data")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse p8 key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("p8 key is not ECDSA (got %T)", key)
	}

	return ecKey, nil
}
