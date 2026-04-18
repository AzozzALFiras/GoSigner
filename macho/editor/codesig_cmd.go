package editor

import (
	"encoding/binary"

	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
)

// SetCodeSignatureCmd updates or creates the LC_CODE_SIGNATURE load command.
// Returns the modified slice with the updated/added command.
func SetCodeSignatureCmd(slice *mtypes.MachOSlice, dataOff uint32, dataSize uint32) {
	existing := slice.GetCodeSignatureCmd()

	if existing != nil {
		// Update existing command
		binary.LittleEndian.PutUint32(existing.Raw[8:12], dataOff)
		binary.LittleEndian.PutUint32(existing.Raw[12:16], dataSize)
		return
	}

	// Create new LC_CODE_SIGNATURE command
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint32(raw[0:4], mtypes.LCCodeSignature)
	binary.LittleEndian.PutUint32(raw[4:8], 16) // cmdsize
	binary.LittleEndian.PutUint32(raw[8:12], dataOff)
	binary.LittleEndian.PutUint32(raw[12:16], dataSize)

	lc := mtypes.LoadCommand{
		Cmd:     mtypes.LCCodeSignature,
		CmdSize: 16,
		Raw:     raw,
	}

	slice.LoadCmds = append(slice.LoadCmds, lc)
	slice.Header.NCmds++
	slice.Header.SizeOfCmds += 16
}
