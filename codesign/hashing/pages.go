package hashing

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	cstypes "github.com/AzozzALFiras/GoSigner/codesign/types"
)

// ComputePageHashes computes hashes for all 4KB pages of code in a Mach-O binary.
// Uses streaming reads to avoid loading the entire binary into memory.
// Returns SHA-1 hashes and SHA-256 hashes as separate slices.
func ComputePageHashes(r io.ReaderAt, baseOffset uint64, codeLimit uint32) (sha1Hashes [][]byte, sha256Hashes [][]byte, err error) {
	pageSize := uint32(cstypes.CSPageSize)
	nPages := (codeLimit + pageSize - 1) / pageSize

	sha1Hashes = make([][]byte, nPages)
	sha256Hashes = make([][]byte, nPages)

	// Reusable buffer to avoid allocations
	buf := make([]byte, pageSize)

	for i := uint32(0); i < nPages; i++ {
		offset := int64(baseOffset) + int64(i)*int64(pageSize)
		remaining := codeLimit - i*pageSize
		readSize := pageSize
		if remaining < pageSize {
			readSize = remaining
			// Zero out the buffer for the last partial page
			clear(buf)
		}

		n, err := r.ReadAt(buf[:readSize], offset)
		if err != nil && err != io.EOF {
			return nil, nil, fmt.Errorf("read page %d at offset %d: %w", i, offset, err)
		}

		// Hash the data read
		data := buf[:n]

		h1 := sha1.Sum(data)
		sha1Hashes[i] = make([]byte, cstypes.CSHashSizeSHA1)
		copy(sha1Hashes[i], h1[:])

		h256 := sha256.Sum256(data)
		sha256Hashes[i] = make([]byte, cstypes.CSHashSizeSHA256)
		copy(sha256Hashes[i], h256[:])
	}

	return sha1Hashes, sha256Hashes, nil
}

// HashData computes hash of arbitrary data using the specified hash type.
func HashData(data []byte, hashType uint8) []byte {
	var h hash.Hash
	switch hashType {
	case cstypes.CSHashTypeSHA1:
		h = sha1.New()
	case cstypes.CSHashTypeSHA256:
		h = sha256.New()
	default:
		h = sha256.New()
	}
	h.Write(data)
	return h.Sum(nil)
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
