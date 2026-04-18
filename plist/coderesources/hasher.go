package coderesources

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

// FileHashes holds the SHA-1 and SHA-256 hashes of a file, base64-encoded.
type FileHashes struct {
	SHA1   []byte // Raw SHA-1 hash
	SHA256 []byte // Raw SHA-256 hash
}

// HashFile computes SHA-1 and SHA-256 hashes for a file using streaming reads.
func HashFile(path string) (*FileHashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file for hashing: %w", err)
	}
	defer f.Close()

	h1 := sha1.New()
	h256 := sha256.New()

	// Stream through both hashers simultaneously
	w := io.MultiWriter(h1, h256)
	if _, err := io.Copy(w, f); err != nil {
		return nil, fmt.Errorf("hash file: %w", err)
	}

	return &FileHashes{
		SHA1:   h1.Sum(nil),
		SHA256: h256.Sum(nil),
	}, nil
}

// HashBytes computes SHA-1 and SHA-256 hashes for raw bytes.
func HashBytes(data []byte) *FileHashes {
	h1 := sha1.Sum(data)
	h256 := sha256.Sum256(data)
	return &FileHashes{
		SHA1:   h1[:],
		SHA256: h256[:],
	}
}

// Base64SHA1 returns the base64-encoded SHA-1 hash.
func (h *FileHashes) Base64SHA1() string {
	return base64.StdEncoding.EncodeToString(h.SHA1)
}

// Base64SHA256 returns the base64-encoded SHA-256 hash.
func (h *FileHashes) Base64SHA256() string {
	return base64.StdEncoding.EncodeToString(h.SHA256)
}
