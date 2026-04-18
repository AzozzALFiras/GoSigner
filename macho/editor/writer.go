package editor

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
)

// WriteMachO writes a modified Mach-O slice to a writer.
// It reads original data from the source reader and applies modifications to the header
// and load commands, then appends the code signature.
func WriteMachO(w io.Writer, source io.ReaderAt, slice *mtypes.MachOSlice, codeSignature []byte) error {
	// Write the Mach-O header
	if err := writeHeader(w, &slice.Header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write all load commands
	for _, lc := range slice.LoadCmds {
		if _, err := w.Write(lc.Raw); err != nil {
			return fmt.Errorf("write load command 0x%X: %w", lc.Cmd, err)
		}
	}

	// Calculate how much padding we need after load commands
	headerSize := uint64(slice.Header.HeaderSize())
	lcEnd := headerSize + uint64(slice.Header.SizeOfCmds)

	// Find the start of data after the header + load commands in the original
	// We need to copy everything from after load commands to the code signature offset
	origLcEnd := headerSize
	for _, lc := range slice.LoadCmds {
		_ = lc
	}
	origLcEnd = lcEnd // They should be the same after our edits

	// Copy the rest of the binary data (sections, segments) from original
	// Find where the code signature starts (or end of file)
	var copyEnd uint64
	csCmd := slice.GetCodeSignatureCmd()
	if csCmd != nil && len(csCmd.Raw) >= 12 {
		copyEnd = uint64(binary.LittleEndian.Uint32(csCmd.Raw[8:12]))
	} else {
		copyEnd = slice.Size
	}

	if copyEnd > origLcEnd {
		dataSize := copyEnd - origLcEnd
		buf := make([]byte, 32*1024) // 32KB streaming buffer
		offset := int64(slice.Offset + origLcEnd)
		remaining := int64(dataSize)

		for remaining > 0 {
			toRead := int64(len(buf))
			if toRead > remaining {
				toRead = remaining
			}
			n, err := source.ReadAt(buf[:toRead], offset)
			if err != nil && err != io.EOF {
				return fmt.Errorf("read binary data at offset %d: %w", offset, err)
			}
			if n == 0 {
				break
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return fmt.Errorf("write binary data: %w", err)
			}
			offset += int64(n)
			remaining -= int64(n)
		}
	}

	// Append code signature
	if len(codeSignature) > 0 {
		if _, err := w.Write(codeSignature); err != nil {
			return fmt.Errorf("write code signature: %w", err)
		}
	}

	return nil
}

// WriteToFile writes a complete modified Mach-O file to disk.
// For FAT binaries, it handles all architectures.
func WriteToFile(path string, machO *mtypes.MachOFile, signatures [][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	if machO.IsFAT {
		return writeFATFile(f, machO, signatures)
	}

	if len(machO.Slices) != 1 {
		return fmt.Errorf("expected 1 slice for thin binary, got %d", len(machO.Slices))
	}

	var sig []byte
	if len(signatures) > 0 {
		sig = signatures[0]
	}

	return WriteMachO(f, machO.Source, &machO.Slices[0], sig)
}

func writeFATFile(f *os.File, machO *mtypes.MachOFile, signatures [][]byte) error {
	nArch := uint32(len(machO.Slices))

	// Write FAT header (big-endian)
	var fatHeader [mtypes.FATHeaderSize]byte
	binary.BigEndian.PutUint32(fatHeader[0:4], mtypes.FATMagic)
	binary.BigEndian.PutUint32(fatHeader[4:8], nArch)
	if _, err := f.Write(fatHeader[:]); err != nil {
		return fmt.Errorf("write fat header: %w", err)
	}

	// Calculate architecture offsets with alignment
	archOffset := uint32(mtypes.FATHeaderSize + nArch*mtypes.FATArchSize)

	// Write arch entries and track offsets
	type archInfo struct {
		offset uint32
		size   uint32
	}
	archInfos := make([]archInfo, nArch)

	for i := range machO.Slices {
		// Align to 16384 boundary
		archOffset = (archOffset + mtypes.FATAlign - 1) & ^uint32(mtypes.FATAlign-1)

		size := uint32(machO.Slices[i].Size)
		if i < len(signatures) && len(signatures[i]) > 0 {
			// Adjust size for new code signature
			csCmd := machO.Slices[i].GetCodeSignatureCmd()
			if csCmd != nil && len(csCmd.Raw) >= 12 {
				csOff := binary.LittleEndian.Uint32(csCmd.Raw[8:12])
				size = csOff + uint32(len(signatures[i]))
			}
		}

		archInfos[i] = archInfo{offset: archOffset, size: size}

		var archBuf [mtypes.FATArchSize]byte
		binary.BigEndian.PutUint32(archBuf[0:4], machO.Slices[i].Header.CpuType)
		binary.BigEndian.PutUint32(archBuf[4:8], machO.Slices[i].Header.CpuSubtype)
		binary.BigEndian.PutUint32(archBuf[8:12], archOffset)
		binary.BigEndian.PutUint32(archBuf[12:16], size)
		binary.BigEndian.PutUint32(archBuf[16:20], mtypes.FATAlignPower)
		if _, err := f.Write(archBuf[:]); err != nil {
			return fmt.Errorf("write fat arch %d: %w", i, err)
		}

		archOffset += size
	}

	// Write each architecture's Mach-O data
	for i := range machO.Slices {
		// Seek to aligned offset
		if _, err := f.Seek(int64(archInfos[i].offset), io.SeekStart); err != nil {
			return fmt.Errorf("seek to arch %d: %w", i, err)
		}

		var sig []byte
		if i < len(signatures) {
			sig = signatures[i]
		}

		if err := WriteMachO(f, machO.Source, &machO.Slices[i], sig); err != nil {
			return fmt.Errorf("write arch %d: %w", i, err)
		}
	}

	return nil
}

func writeHeader(w io.Writer, h *mtypes.MachOHeader) error {
	is64 := h.Magic == mtypes.MHMagic64 || h.Magic == mtypes.MHCigam64

	size := mtypes.MachOHeader32Size
	if is64 {
		size = mtypes.MachOHeader64Size
	}

	buf := make([]byte, size)
	binary.LittleEndian.PutUint32(buf[0:4], h.Magic)
	binary.LittleEndian.PutUint32(buf[4:8], h.CpuType)
	binary.LittleEndian.PutUint32(buf[8:12], h.CpuSubtype)
	binary.LittleEndian.PutUint32(buf[12:16], h.FileType)
	binary.LittleEndian.PutUint32(buf[16:20], h.NCmds)
	binary.LittleEndian.PutUint32(buf[20:24], h.SizeOfCmds)
	binary.LittleEndian.PutUint32(buf[24:28], h.Flags)
	if is64 {
		binary.LittleEndian.PutUint32(buf[28:32], h.Reserved)
	}

	_, err := w.Write(buf)
	return err
}
