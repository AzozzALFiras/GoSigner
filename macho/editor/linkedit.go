package editor

import (
	"encoding/binary"
	"fmt"

	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
	"github.com/AzozzALFiras/GoSigner/macho/parser"
)

// CalculateCodeSignatureSpace calculates the required space for a code signature
// and returns the offset and required size.
func CalculateCodeSignatureSpace(slice *mtypes.MachOSlice, signatureSize uint32) (dataOff uint32, err error) {
	linkedit, linkeditLC, err := parser.FindLinkedit(slice.LoadCmds)
	if err != nil {
		return 0, fmt.Errorf("find __LINKEDIT: %w", err)
	}

	// The code signature goes at the end of __LINKEDIT
	// First check if there's already a code signature
	existingCS := slice.GetCodeSignatureCmd()
	if existingCS != nil {
		csCmd, err := parser.ParseCodeSignatureCmd(existingCS)
		if err != nil {
			return 0, err
		}
		// Reuse existing offset
		return csCmd.DataOff, nil
	}

	// Place signature at end of __LINKEDIT's current data
	_ = linkeditLC
	dataOff = uint32(linkedit.FileOff + linkedit.FileSize)
	return dataOff, nil
}

// UpdateLinkeditSize updates the __LINKEDIT segment to accommodate the code signature.
func UpdateLinkeditSize(slice *mtypes.MachOSlice, newTotalSize uint64) error {
	_, linkeditLC, err := parser.FindLinkedit(slice.LoadCmds)
	if err != nil {
		return fmt.Errorf("find __LINKEDIT: %w", err)
	}

	is64 := linkeditLC.Cmd == mtypes.LCSegment64

	if is64 {
		// Update filesize at offset 48
		binary.LittleEndian.PutUint64(linkeditLC.Raw[48:56], newTotalSize)
		// Update vmsize at offset 32 (round up to page boundary)
		vmsize := alignTo(newTotalSize, 0x4000)
		binary.LittleEndian.PutUint64(linkeditLC.Raw[32:40], vmsize)
	} else {
		binary.LittleEndian.PutUint32(linkeditLC.Raw[36:40], uint32(newTotalSize))
		vmsize := alignTo(newTotalSize, 0x4000)
		binary.LittleEndian.PutUint32(linkeditLC.Raw[28:32], uint32(vmsize))
	}

	return nil
}

func alignTo(value uint64, alignment uint64) uint64 {
	return (value + alignment - 1) & ^(alignment - 1)
}
