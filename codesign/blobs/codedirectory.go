package blobs

import (
	"encoding/binary"

	cstypes "github.com/AzozzALFiras/GoSigner/codesign/types"
)

// BuildCodeDirectory constructs a CodeDirectory blob.
// hashType: CSHashTypeSHA1 or CSHashTypeSHA256
// pageHashes: pre-computed hashes for each code page
// specialHashes: map of special slot index (1-7) to hash bytes
// execSegBase/Limit/Flags: executable segment info (required by iOS 13+)
//   execSegFlags must include CS_EXECSEG_MAIN_BINARY (0x1) for main app binary.
func BuildCodeDirectory(
	bundleID string,
	teamID string,
	codeLimit uint32,
	hashType uint8,
	pageHashes [][]byte,
	specialHashes map[uint32][]byte,
	flags uint32,
	execSegBase uint64,
	execSegLimit uint64,
	execSegFlags uint64,
) []byte {
	hashSize := cstypes.CSHashSizeSHA1
	if hashType == cstypes.CSHashTypeSHA256 {
		hashSize = cstypes.CSHashSizeSHA256
	}

	nCodeSlots := uint32(len(pageHashes))

	// Determine highest special slot
	nSpecialSlots := uint32(0)
	for slot := range specialHashes {
		if slot > nSpecialSlots {
			nSpecialSlots = slot
		}
	}

	// CodeDirectory fixed header size (version 0x20400)
	// magic(4) + length(4) + version(4) + flags(4) + hashOffset(4) + identOffset(4)
	// + nSpecialSlots(4) + nCodeSlots(4) + codeLimit(4) + hashSize(1) + hashType(1)
	// + platform(1) + pageSize(1) + spare2(4)
	// + scatterOffset(4) + teamOffset(4) + spare3(4) + codeLimit64(8)
	// + execSegBase(8) + execSegLimit(8) + execSegFlags(8)
	fixedHeaderSize := uint32(88)

	// Layout after fixed header:
	// 1. Identity string (null-terminated)
	// 2. Team ID string (null-terminated)
	// 3. Special slot hashes (nSpecialSlots * hashSize)
	// 4. Code slot hashes (nCodeSlots * hashSize)

	identBytes := append([]byte(bundleID), 0)
	teamBytes := append([]byte(teamID), 0)

	identOffset := fixedHeaderSize
	teamOffset := identOffset + uint32(len(identBytes))
	hashesStart := teamOffset + uint32(len(teamBytes))

	// Special hashes come first (in reverse order: slot N, ..., slot 1)
	specialHashesSize := nSpecialSlots * uint32(hashSize)
	hashOffset := hashesStart + specialHashesSize

	totalSize := hashOffset + nCodeSlots*uint32(hashSize)

	// Build the blob
	buf := make([]byte, totalSize)

	// Magic and length (big-endian)
	binary.BigEndian.PutUint32(buf[0:4], cstypes.CSMagicCodeDirectory)
	binary.BigEndian.PutUint32(buf[4:8], totalSize)

	// Version
	binary.BigEndian.PutUint32(buf[8:12], cstypes.CSCodeDirectoryVersion)

	// Flags
	binary.BigEndian.PutUint32(buf[12:16], flags)

	// Hash offset (offset from start of CodeDirectory to first code hash)
	binary.BigEndian.PutUint32(buf[16:20], hashOffset)

	// Ident offset
	binary.BigEndian.PutUint32(buf[20:24], identOffset)

	// nSpecialSlots
	binary.BigEndian.PutUint32(buf[24:28], nSpecialSlots)

	// nCodeSlots
	binary.BigEndian.PutUint32(buf[28:32], nCodeSlots)

	// codeLimit
	binary.BigEndian.PutUint32(buf[32:36], codeLimit)

	// hashSize
	buf[36] = uint8(hashSize)

	// hashType
	buf[37] = hashType

	// platform
	buf[38] = 0

	// pageSize (log2)
	buf[39] = 12 // log2(4096) = 12

	// spare2
	binary.BigEndian.PutUint32(buf[40:44], 0)

	// scatterOffset (version >= 0x20100)
	binary.BigEndian.PutUint32(buf[44:48], 0)

	// teamOffset (version >= 0x20200)
	binary.BigEndian.PutUint32(buf[48:52], teamOffset)

	// spare3 (version >= 0x20300)
	binary.BigEndian.PutUint32(buf[52:56], 0)

	// codeLimit64 (version >= 0x20300)
	binary.BigEndian.PutUint64(buf[56:64], 0)

	// execSegBase (version >= 0x20400) — offset of __TEXT segment in file
	binary.BigEndian.PutUint64(buf[64:72], execSegBase)

	// execSegLimit (version >= 0x20400) — size of __TEXT segment
	binary.BigEndian.PutUint64(buf[72:80], execSegLimit)

	// execSegFlags (version >= 0x20400) — CS_EXECSEG_MAIN_BINARY (0x1) for main binary
	binary.BigEndian.PutUint64(buf[80:88], execSegFlags)

	// Write identity string
	copy(buf[identOffset:], identBytes)

	// Write team ID string
	copy(buf[teamOffset:], teamBytes)

	// Write special slot hashes (stored before code hashes, in reverse order)
	for slot, hash := range specialHashes {
		if slot == 0 || slot > nSpecialSlots {
			continue
		}
		// Special slot N is stored at offset: hashOffset - N * hashSize
		slotOffset := hashOffset - slot*uint32(hashSize)
		copy(buf[slotOffset:], hash)
	}

	// Write code slot hashes
	for i, hash := range pageHashes {
		offset := hashOffset + uint32(i)*uint32(hashSize)
		copy(buf[offset:], hash)
	}

	return buf
}
