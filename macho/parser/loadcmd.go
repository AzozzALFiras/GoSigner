package parser

import (
	"encoding/binary"
	"fmt"
	"io"

	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
)

// ParseLoadCommands reads all load commands from a Mach-O slice.
// baseOffset is the absolute offset of the Mach-O header in the file.
func ParseLoadCommands(r io.ReaderAt, baseOffset uint64, header *mtypes.MachOHeader) ([]mtypes.LoadCommand, error) {
	headerSize := uint64(header.HeaderSize())
	cmdOffset := baseOffset + headerSize

	commands := make([]mtypes.LoadCommand, 0, header.NCmds)

	for i := uint32(0); i < header.NCmds; i++ {
		// Read command header (cmd + cmdsize)
		var cmdHeader [mtypes.LoadCmdHeaderSize]byte
		if _, err := r.ReadAt(cmdHeader[:], int64(cmdOffset)); err != nil {
			return nil, fmt.Errorf("read load command header %d at offset %d: %w", i, cmdOffset, err)
		}

		cmd := binary.LittleEndian.Uint32(cmdHeader[0:4])
		cmdSize := binary.LittleEndian.Uint32(cmdHeader[4:8])

		if cmdSize < mtypes.LoadCmdHeaderSize {
			return nil, fmt.Errorf("load command %d has invalid size %d", i, cmdSize)
		}

		// Read entire command
		raw := make([]byte, cmdSize)
		if _, err := r.ReadAt(raw, int64(cmdOffset)); err != nil {
			return nil, fmt.Errorf("read load command %d data: %w", i, err)
		}

		commands = append(commands, mtypes.LoadCommand{
			Cmd:     cmd,
			CmdSize: cmdSize,
			Offset:  cmdOffset,
			Raw:     raw,
		})

		cmdOffset += uint64(cmdSize)
	}

	return commands, nil
}

// ParseSegmentCommand extracts segment details from a LC_SEGMENT or LC_SEGMENT_64 load command.
func ParseSegmentCommand(lc *mtypes.LoadCommand) (*mtypes.SegmentCommand, error) {
	raw := lc.Raw
	is64 := lc.Cmd == mtypes.LCSegment64

	if is64 {
		if len(raw) < 72 {
			return nil, fmt.Errorf("segment64 command too short: %d bytes", len(raw))
		}
		nameBytes := raw[8:24]
		n := 0
		for n < len(nameBytes) && nameBytes[n] != 0 {
			n++
		}

		return &mtypes.SegmentCommand{
			Name:     string(nameBytes[:n]),
			VMAddr:   binary.LittleEndian.Uint64(raw[24:32]),
			VMSize:   binary.LittleEndian.Uint64(raw[32:40]),
			FileOff:  binary.LittleEndian.Uint64(raw[40:48]),
			FileSize: binary.LittleEndian.Uint64(raw[48:56]),
			MaxProt:  binary.LittleEndian.Uint32(raw[56:60]),
			InitProt: binary.LittleEndian.Uint32(raw[60:64]),
			NSects:   binary.LittleEndian.Uint32(raw[64:68]),
			Flags:    binary.LittleEndian.Uint32(raw[68:72]),
		}, nil
	}

	// 32-bit segment
	if len(raw) < 56 {
		return nil, fmt.Errorf("segment command too short: %d bytes", len(raw))
	}
	nameBytes := raw[8:24]
	n := 0
	for n < len(nameBytes) && nameBytes[n] != 0 {
		n++
	}

	return &mtypes.SegmentCommand{
		Name:     string(nameBytes[:n]),
		VMAddr:   uint64(binary.LittleEndian.Uint32(raw[24:28])),
		VMSize:   uint64(binary.LittleEndian.Uint32(raw[28:32])),
		FileOff:  uint64(binary.LittleEndian.Uint32(raw[32:36])),
		FileSize: uint64(binary.LittleEndian.Uint32(raw[36:40])),
		MaxProt:  binary.LittleEndian.Uint32(raw[40:44]),
		InitProt: binary.LittleEndian.Uint32(raw[44:48]),
		NSects:   binary.LittleEndian.Uint32(raw[48:52]),
		Flags:    binary.LittleEndian.Uint32(raw[52:56]),
	}, nil
}

// ParseCodeSignatureCmd extracts the code signature command details.
func ParseCodeSignatureCmd(lc *mtypes.LoadCommand) (*mtypes.CodeSignatureCmd, error) {
	if lc.Cmd != mtypes.LCCodeSignature {
		return nil, fmt.Errorf("not a code signature command: 0x%X", lc.Cmd)
	}
	if len(lc.Raw) < 16 {
		return nil, fmt.Errorf("code signature command too short: %d bytes", len(lc.Raw))
	}

	return &mtypes.CodeSignatureCmd{
		DataOff:  binary.LittleEndian.Uint32(lc.Raw[8:12]),
		DataSize: binary.LittleEndian.Uint32(lc.Raw[12:16]),
	}, nil
}

// ParseDylibCommand extracts dylib details from LC_LOAD_DYLIB and similar commands.
func ParseDylibCommand(lc *mtypes.LoadCommand) (*mtypes.DylibCommand, error) {
	if len(lc.Raw) < 24 {
		return nil, fmt.Errorf("dylib command too short: %d bytes", len(lc.Raw))
	}

	nameOffset := binary.LittleEndian.Uint32(lc.Raw[8:12])
	timestamp := binary.LittleEndian.Uint32(lc.Raw[12:16])
	currentVer := binary.LittleEndian.Uint32(lc.Raw[16:20])
	compatVer := binary.LittleEndian.Uint32(lc.Raw[20:24])

	// Extract name string
	name := ""
	if nameOffset < uint32(len(lc.Raw)) {
		nameBytes := lc.Raw[nameOffset:]
		n := 0
		for n < len(nameBytes) && nameBytes[n] != 0 {
			n++
		}
		name = string(nameBytes[:n])
	}

	return &mtypes.DylibCommand{
		NameOffset:     nameOffset,
		Timestamp:      timestamp,
		CurrentVersion: currentVer,
		CompatVersion:  compatVer,
		Name:           name,
	}, nil
}
