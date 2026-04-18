package parser

import (
	"encoding/binary"
	"fmt"
	"io"

	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
)

// ParseHeader reads and parses a Mach-O header from the given reader at the specified offset.
func ParseHeader(r io.ReaderAt, offset uint64) (*mtypes.MachOHeader, error) {
	// Read magic first to determine byte order and 32/64 bit
	var magicBuf [4]byte
	if _, err := r.ReadAt(magicBuf[:], int64(offset)); err != nil {
		return nil, fmt.Errorf("read magic at offset %d: %w", offset, err)
	}

	magic := binary.LittleEndian.Uint32(magicBuf[:])

	var byteOrder binary.ByteOrder
	var is64 bool

	switch magic {
	case mtypes.MHMagic32:
		byteOrder = binary.LittleEndian
		is64 = false
	case mtypes.MHMagic64:
		byteOrder = binary.LittleEndian
		is64 = true
	case mtypes.MHCigam32:
		byteOrder = binary.BigEndian
		is64 = false
	case mtypes.MHCigam64:
		byteOrder = binary.BigEndian
		is64 = true
	default:
		return nil, fmt.Errorf("not a mach-o binary (magic: 0x%08X)", magic)
	}

	headerSize := mtypes.MachOHeader32Size
	if is64 {
		headerSize = mtypes.MachOHeader64Size
	}

	buf := make([]byte, headerSize)
	if _, err := r.ReadAt(buf, int64(offset)); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	header := &mtypes.MachOHeader{
		Magic:      byteOrder.Uint32(buf[0:4]),
		CpuType:    byteOrder.Uint32(buf[4:8]),
		CpuSubtype: byteOrder.Uint32(buf[8:12]),
		FileType:   byteOrder.Uint32(buf[12:16]),
		NCmds:      byteOrder.Uint32(buf[16:20]),
		SizeOfCmds: byteOrder.Uint32(buf[20:24]),
		Flags:      byteOrder.Uint32(buf[24:28]),
	}

	if is64 {
		header.Reserved = byteOrder.Uint32(buf[28:32])
	}

	return header, nil
}

// DetectFormat reads the first 4 bytes to determine if this is a Mach-O, FAT, or unknown format.
func DetectFormat(r io.ReaderAt) (magic uint32, err error) {
	var buf [4]byte
	if _, err := r.ReadAt(buf[:], 0); err != nil {
		return 0, fmt.Errorf("read magic: %w", err)
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

// IsMachO returns true if the magic indicates a Mach-O binary.
func IsMachO(magic uint32) bool {
	switch magic {
	case mtypes.MHMagic32, mtypes.MHMagic64, mtypes.MHCigam32, mtypes.MHCigam64:
		return true
	}
	return false
}

// IsFAT returns true if the magic indicates a FAT/universal binary.
func IsFAT(magic uint32) bool {
	switch magic {
	case mtypes.FATMagic, mtypes.FATCigam, mtypes.FATMagic64, mtypes.FATCigam64:
		return true
	}
	return false
}
