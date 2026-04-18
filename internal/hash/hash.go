package hash

import (
	"crypto/sha1"
	"crypto/sha256"
	"io"
)

// SHA1 computes SHA-1 hash of the given data.
func SHA1(data []byte) [20]byte {
	return sha1.Sum(data)
}

// SHA256 computes SHA-256 hash of the given data.
func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// SHA1Reader computes SHA-1 hash by streaming from a reader.
func SHA1Reader(r io.Reader) ([20]byte, error) {
	h := sha1.New()
	if _, err := io.Copy(h, r); err != nil {
		return [20]byte{}, err
	}
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// SHA256Reader computes SHA-256 hash by streaming from a reader.
func SHA256Reader(r io.Reader) ([32]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// SHA1Bytes computes SHA-1 hash and returns it as a byte slice.
func SHA1Bytes(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

// SHA256Bytes computes SHA-256 hash and returns it as a byte slice.
func SHA256Bytes(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
