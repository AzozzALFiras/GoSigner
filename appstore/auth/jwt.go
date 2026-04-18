package auth

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/sha256"
)

// GenerateJWT creates a JWT token for App Store Connect API authentication.
func GenerateJWT(issuerID string, keyID string, privateKey *ecdsa.PrivateKey) (string, error) {
	now := time.Now()

	// Header
	header := map[string]string{
		"alg": "ES256",
		"kid": keyID,
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	// Payload
	payload := map[string]interface{}{
		"iss": issuerID,
		"iat": now.Unix(),
		"exp": now.Add(20 * time.Minute).Unix(),
		"aud": "appstoreconnect-v1",
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	// Encode
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64

	// Sign with ECDSA P-256
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	// Encode signature as R || S (32 bytes each for P-256)
	curveBits := privateKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	sigBytes := make([]byte, 2*keyBytes)
	copy(sigBytes[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(sigBytes[2*keyBytes-len(sBytes):], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return signingInput + "." + sigB64, nil
}

// VerifyJWT verifies a JWT token (for testing purposes).
func VerifyJWT(token string, publicKey *ecdsa.PublicKey) bool {
	// Split token
	parts := splitJWT(token)
	if len(parts) != 3 {
		return false
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	hash := sha256.Sum256([]byte(signingInput))

	keyBytes := publicKey.Curve.Params().BitSize / 8
	if len(sigBytes) != 2*keyBytes {
		return false
	}

	r := new(big.Int).SetBytes(sigBytes[:keyBytes])
	s := new(big.Int).SetBytes(sigBytes[keyBytes:])

	return ecdsa.Verify(publicKey, hash[:], r, s)
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

// Ensure crypto.Signer is satisfied (compile-time check)
var _ crypto.Hash = crypto.SHA256
