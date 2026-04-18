package dylib

import (
	"encoding/binary"

	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
)

// Inject adds a LC_LOAD_DYLIB (or LC_LOAD_WEAK_DYLIB) command to a Mach-O slice.
func Inject(slice *mtypes.MachOSlice, dylibPath string, weak bool) {
	cmd := mtypes.LCLoadDylib
	if weak {
		cmd = mtypes.LCLoadDylibWeak
	}

	// Build the dylib_command structure:
	// cmd (4) + cmdsize (4) + name_offset (4) + timestamp (4) + current_version (4) + compat_version (4) + name string + null + padding
	nameOffset := uint32(24) // Fixed offset where name string starts
	nameBytes := append([]byte(dylibPath), 0)

	// Align cmdsize to 8 bytes (required by Mach-O format)
	cmdSize := nameOffset + uint32(len(nameBytes))
	cmdSize = (cmdSize + 7) & ^uint32(7)

	raw := make([]byte, cmdSize)
	binary.LittleEndian.PutUint32(raw[0:4], cmd)
	binary.LittleEndian.PutUint32(raw[4:8], cmdSize)
	binary.LittleEndian.PutUint32(raw[8:12], nameOffset)
	binary.LittleEndian.PutUint32(raw[12:16], 2) // timestamp
	binary.LittleEndian.PutUint32(raw[16:20], 0) // current_version
	binary.LittleEndian.PutUint32(raw[20:24], 0) // compat_version
	copy(raw[nameOffset:], nameBytes)

	lc := mtypes.LoadCommand{
		Cmd:     cmd,
		CmdSize: cmdSize,
		Raw:     raw,
	}

	slice.LoadCmds = append(slice.LoadCmds, lc)
	slice.Header.NCmds++
	slice.Header.SizeOfCmds += cmdSize
}
