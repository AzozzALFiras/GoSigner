package pipeline

import (
	"encoding/binary"
	"io"

	"github.com/AzozzALFiras/GoSigner/certificate"
	"github.com/AzozzALFiras/GoSigner/codesign/signer"
	"github.com/AzozzALFiras/GoSigner/macho"
	"github.com/AzozzALFiras/GoSigner/macho/dylib"
	"github.com/AzozzALFiras/GoSigner/macho/editor"
	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
)

// Bridge functions connecting macho/codesign to the pipeline

func machoOpen(r io.ReaderAt, size int64) (*mtypes.MachOFile, error) {
	return macho.Open(r, size)
}

func machoSetCodeSig(slice *mtypes.MachOSlice, dataOff uint32, dataSize uint32) {
	editor.SetCodeSignatureCmd(slice, dataOff, dataSize)
}

func machoWriteToFile(path string, machO *mtypes.MachOFile, signatures [][]byte) error {
	return editor.WriteToFile(path, machO, signatures)
}

func machoRemoveDylibs(slice *mtypes.MachOSlice, names []string) {
	dylib.Remove(slice, names)
}

func machoInjectDylib(slice *mtypes.MachOSlice, path string, weak bool) {
	dylib.Inject(slice, path, weak)
}

func signerSign(r io.ReaderAt, baseOffset uint64, codeLimit uint32, identity *certificate.SigningIdentity, opts *signer.Options) ([]byte, error) {
	return signer.SignMachOSlice(r, baseOffset, codeLimit, identity, opts)
}

func calculateCodeLimit(slice *mtypes.MachOSlice) uint32 {
	// The code limit is the offset where the code signature starts.
	// If there's an existing code signature, use its offset.
	// Otherwise, use the end of __LINKEDIT.
	csCmd := slice.GetCodeSignatureCmd()
	if csCmd != nil && len(csCmd.Raw) >= 12 {
		return binary.LittleEndian.Uint32(csCmd.Raw[8:12])
	}

	// Find __LINKEDIT end
	linkedit := slice.GetLinkeditSegment()
	if linkedit != nil && len(linkedit.Raw) >= 56 {
		// For 64-bit: fileoff at offset 40-48, filesize at offset 48-56
		if linkedit.Cmd == mtypes.LCSegment64 {
			fileOff := binary.LittleEndian.Uint64(linkedit.Raw[40:48])
			fileSize := binary.LittleEndian.Uint64(linkedit.Raw[48:56])
			return uint32(fileOff + fileSize)
		}
		// For 32-bit: fileoff at offset 32-36, filesize at offset 36-40
		fileOff := binary.LittleEndian.Uint32(linkedit.Raw[32:36])
		fileSize := binary.LittleEndian.Uint32(linkedit.Raw[36:40])
		return fileOff + fileSize
	}

	return uint32(slice.Size)
}

// getExecSegInfo extracts the __TEXT segment info for CodeDirectory execSegBase/Limit/Flags.
// iOS 13+ requires these fields to validate the executable segment.
// Returns (base, limit, flags) where:
//   base  = __TEXT.fileoff (usually 0)
//   limit = __TEXT.filesize (size of __TEXT segment)
//   flags = CS_EXECSEG_MAIN_BINARY (0x1) for main binary
func getExecSegInfo(slice *mtypes.MachOSlice, isMainBinary bool) (uint64, uint64, uint64) {
	var base, limit uint64

	// Find __TEXT segment
	for _, lc := range slice.LoadCmds {
		if lc.Cmd != mtypes.LCSegment && lc.Cmd != mtypes.LCSegment64 {
			continue
		}
		is64 := lc.Cmd == mtypes.LCSegment64
		if len(lc.Raw) < 24 {
			continue
		}
		// Segment name is at offset 8, 16 bytes
		nameBytes := lc.Raw[8:24]
		n := 0
		for n < 16 && nameBytes[n] != 0 {
			n++
		}
		name := string(nameBytes[:n])
		if name != "__TEXT" {
			continue
		}

		if is64 && len(lc.Raw) >= 56 {
			// 64-bit: fileoff at offset 40-48, filesize at offset 48-56
			base = binary.LittleEndian.Uint64(lc.Raw[40:48])
			limit = binary.LittleEndian.Uint64(lc.Raw[48:56])
		} else if len(lc.Raw) >= 40 {
			// 32-bit: fileoff at offset 32-36, filesize at offset 36-40
			base = uint64(binary.LittleEndian.Uint32(lc.Raw[32:36]))
			limit = uint64(binary.LittleEndian.Uint32(lc.Raw[36:40]))
		}
		break
	}

	var flags uint64
	if isMainBinary {
		flags = 0x1 // CS_EXECSEG_MAIN_BINARY
	}

	return base, limit, flags
}

// updateLinkeditForSignature adjusts __LINKEDIT segment filesize to match
// the actual end of the file (cs_off + cs_size).
// iOS validates that __LINKEDIT.fileoff + __LINKEDIT.filesize == file size.
func updateLinkeditForSignature(slice *mtypes.MachOSlice, csOff uint32, csSize uint32) {
	linkeditLC := slice.GetLinkeditSegment()
	if linkeditLC == nil {
		return
	}

	endOfFile := uint64(csOff) + uint64(csSize)

	if linkeditLC.Cmd == mtypes.LCSegment64 && len(linkeditLC.Raw) >= 56 {
		linkeditFileOff := binary.LittleEndian.Uint64(linkeditLC.Raw[40:48])
		newFileSize := endOfFile - linkeditFileOff
		binary.LittleEndian.PutUint64(linkeditLC.Raw[48:56], newFileSize)
		// Update vmsize (page-aligned)
		newVMSize := (newFileSize + 0x3FFF) & ^uint64(0x3FFF)
		binary.LittleEndian.PutUint64(linkeditLC.Raw[32:40], newVMSize)
	} else if len(linkeditLC.Raw) >= 40 {
		linkeditFileOff := uint64(binary.LittleEndian.Uint32(linkeditLC.Raw[32:36]))
		newFileSize := uint32(endOfFile - linkeditFileOff)
		binary.LittleEndian.PutUint32(linkeditLC.Raw[36:40], newFileSize)
		newVMSize := (newFileSize + 0x3FFF) & ^uint32(0x3FFF)
		binary.LittleEndian.PutUint32(linkeditLC.Raw[28:32], newVMSize)
	}
}

func buildSignerOptions(opts *ResignOptions, infoPlist []byte, codeResources []byte) *signer.Options {
	return &signer.Options{
		BundleID:        opts.BundleID,
		TeamID:          getTeamID(opts),
		InfoPlist:       infoPlist,
		CodeResources:   codeResources,
		EntitlementsXML: opts.EntitlementsXML,
		EntitlementsDER: opts.EntitlementsDER,
		IsAdhoc:         opts.IsAdhoc,
	}
}

func getTeamID(opts *ResignOptions) string {
	if opts.Identity != nil && opts.Identity.TeamID != "" {
		return opts.Identity.TeamID
	}
	if opts.Profile != nil {
		return opts.Profile.GetTeamID()
	}
	return ""
}
