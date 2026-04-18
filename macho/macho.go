package macho

import (
	"fmt"
	"io"
	"os"

	"github.com/AzozzALFiras/GoSigner/macho/parser"
	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
)

// Open parses a Mach-O file from an io.ReaderAt without loading the entire binary into memory.
func Open(r io.ReaderAt, size int64) (*mtypes.MachOFile, error) {
	magic, err := parser.DetectFormat(r)
	if err != nil {
		return nil, err
	}

	machO := &mtypes.MachOFile{
		Source: r,
	}

	if parser.IsFAT(magic) {
		return parseFATBinary(r, machO)
	}

	if parser.IsMachO(magic) {
		return parseThinBinary(r, uint64(size), machO)
	}

	return nil, fmt.Errorf("not a mach-o or fat binary (magic: 0x%08X)", magic)
}

// OpenFile opens a Mach-O file from disk.
func OpenFile(path string) (*mtypes.MachOFile, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("stat file: %w", err)
	}

	machO, err := Open(f, info.Size())
	if err != nil {
		f.Close()
		return nil, nil, err
	}

	return machO, f, nil
}

func parseFATBinary(r io.ReaderAt, machO *mtypes.MachOFile) (*mtypes.MachOFile, error) {
	machO.IsFAT = true

	arches, err := parser.ParseFAT(r)
	if err != nil {
		return nil, err
	}

	machO.Slices = make([]mtypes.MachOSlice, len(arches))

	for i, arch := range arches {
		header, err := parser.ParseHeader(r, uint64(arch.Offset))
		if err != nil {
			return nil, fmt.Errorf("parse header for arch %d: %w", i, err)
		}

		loadCmds, err := parser.ParseLoadCommands(r, uint64(arch.Offset), header)
		if err != nil {
			return nil, fmt.Errorf("parse load commands for arch %d: %w", i, err)
		}

		machO.Slices[i] = mtypes.MachOSlice{
			Offset:   uint64(arch.Offset),
			Size:     uint64(arch.Size),
			Header:   *header,
			LoadCmds: loadCmds,
			Is64Bit:  header.Magic == mtypes.MHMagic64 || header.Magic == mtypes.MHCigam64,
		}
	}

	return machO, nil
}

func parseThinBinary(r io.ReaderAt, fileSize uint64, machO *mtypes.MachOFile) (*mtypes.MachOFile, error) {
	machO.IsFAT = false

	header, err := parser.ParseHeader(r, 0)
	if err != nil {
		return nil, err
	}

	loadCmds, err := parser.ParseLoadCommands(r, 0, header)
	if err != nil {
		return nil, fmt.Errorf("parse load commands: %w", err)
	}

	machO.Slices = []mtypes.MachOSlice{{
		Offset:   0,
		Size:     fileSize,
		Header:   *header,
		LoadCmds: loadCmds,
		Is64Bit:  header.Magic == mtypes.MHMagic64 || header.Magic == mtypes.MHCigam64,
	}}

	return machO, nil
}
