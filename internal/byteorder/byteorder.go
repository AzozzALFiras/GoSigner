package byteorder

import (
	"encoding/binary"
	"io"
)

// ReadUint32BE reads a big-endian uint32 from the reader.
func ReadUint32BE(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

// ReadUint32LE reads a little-endian uint32 from the reader.
func ReadUint32LE(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

// PutUint32BE writes a big-endian uint32 into a byte slice.
func PutUint32BE(b []byte, v uint32) {
	binary.BigEndian.PutUint32(b, v)
}

// PutUint32LE writes a little-endian uint32 into a byte slice.
func PutUint32LE(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
}

// Uint32BE reads a big-endian uint32 from a byte slice.
func Uint32BE(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

// Uint32LE reads a little-endian uint32 from a byte slice.
func Uint32LE(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

// Uint64LE reads a little-endian uint64 from a byte slice.
func Uint64LE(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

// PutUint64LE writes a little-endian uint64 into a byte slice.
func PutUint64LE(b []byte, v uint64) {
	binary.LittleEndian.PutUint64(b, v)
}
