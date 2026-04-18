package parser

import (
	"encoding/binary"
	"fmt"
	"io"

	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
)

// ParseFAT parses a FAT/universal binary header and returns all architecture entries.
func ParseFAT(r io.ReaderAt) ([]mtypes.FATArch, error) {
	// FAT header is always big-endian
	var headerBuf [mtypes.FATHeaderSize]byte
	if _, err := r.ReadAt(headerBuf[:], 0); err != nil {
		return nil, fmt.Errorf("read fat header: %w", err)
	}

	magic := binary.BigEndian.Uint32(headerBuf[0:4])
	if !IsFAT(magic) {
		return nil, fmt.Errorf("not a fat binary (magic: 0x%08X)", magic)
	}

	nArch := binary.BigEndian.Uint32(headerBuf[4:8])
	if nArch == 0 || nArch > 20 {
		return nil, fmt.Errorf("invalid number of architectures: %d", nArch)
	}

	arches := make([]mtypes.FATArch, nArch)
	archBuf := make([]byte, mtypes.FATArchSize)

	for i := uint32(0); i < nArch; i++ {
		offset := int64(mtypes.FATHeaderSize + i*mtypes.FATArchSize)
		if _, err := r.ReadAt(archBuf, offset); err != nil {
			return nil, fmt.Errorf("read fat arch %d: %w", i, err)
		}

		arches[i] = mtypes.FATArch{
			CpuType:    binary.BigEndian.Uint32(archBuf[0:4]),
			CpuSubtype: binary.BigEndian.Uint32(archBuf[4:8]),
			Offset:     binary.BigEndian.Uint32(archBuf[8:12]),
			Size:       binary.BigEndian.Uint32(archBuf[12:16]),
			Align:      binary.BigEndian.Uint32(archBuf[16:20]),
		}
	}

	return arches, nil
}
