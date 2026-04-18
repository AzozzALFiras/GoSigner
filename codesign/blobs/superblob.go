package blobs

import (
	"encoding/binary"

	cstypes "github.com/AzozzALFiras/GoSigner/codesign/types"
)

// BuildSuperBlob assembles a complete SuperBlob from individual blob entries.
// Blobs are provided as a map of slot type to serialized blob data.
func BuildSuperBlob(blobs map[uint32][]byte) []byte {
	count := uint32(len(blobs))

	// SuperBlob header: magic(4) + length(4) + count(4) = 12
	// Index entries: count * (type(4) + offset(4)) = count * 8
	headerSize := 12 + count*8

	// Calculate total size
	totalSize := headerSize
	for _, blob := range blobs {
		totalSize += uint32(len(blob))
	}

	result := make([]byte, totalSize)

	// Write SuperBlob header (big-endian)
	binary.BigEndian.PutUint32(result[0:4], cstypes.CSMagicEmbeddedSignature)
	binary.BigEndian.PutUint32(result[4:8], totalSize)
	binary.BigEndian.PutUint32(result[8:12], count)

	// Build ordered slot list for deterministic output
	slotOrder := []uint32{
		cstypes.CSSlotCodeDirectory,
		cstypes.CSSlotRequirements,
		cstypes.CSSlotEntitlements,
		cstypes.CSSlotDEREntitlements,
		cstypes.CSSlotAltCodeDirectory,
		cstypes.CSSlotCMSSignature,
	}

	// Write index entries and blob data
	indexOffset := uint32(12)
	dataOffset := headerSize

	for _, slot := range slotOrder {
		blob, ok := blobs[slot]
		if !ok {
			continue
		}

		// Write index entry (big-endian)
		binary.BigEndian.PutUint32(result[indexOffset:indexOffset+4], slot)
		binary.BigEndian.PutUint32(result[indexOffset+4:indexOffset+8], dataOffset)
		indexOffset += 8

		// Write blob data
		copy(result[dataOffset:], blob)
		dataOffset += uint32(len(blob))
	}

	return result
}

// WrapBlob wraps raw data in a blob header with the given magic.
func WrapBlob(magic uint32, data []byte) []byte {
	totalSize := 8 + len(data) // magic(4) + length(4) + data
	result := make([]byte, totalSize)
	binary.BigEndian.PutUint32(result[0:4], magic)
	binary.BigEndian.PutUint32(result[4:8], uint32(totalSize))
	copy(result[8:], data)
	return result
}
