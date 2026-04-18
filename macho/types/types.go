package types

import "io"

// MachOFile represents a parsed Mach-O file, which may be a FAT binary with multiple architectures.
type MachOFile struct {
	IsFAT  bool         // true if this is a FAT/universal binary
	Slices []MachOSlice // One per architecture (1 for thin binary)
	Source io.ReaderAt  // Original data source for streaming reads
}

// MachOSlice represents a single architecture within a Mach-O file.
type MachOSlice struct {
	Offset     uint64       // Offset within the file (0 for thin binaries)
	Size       uint64       // Size of this architecture's data
	Header     MachOHeader  // Parsed Mach-O header
	LoadCmds   []LoadCommand // All load commands
	Is64Bit    bool         // true for 64-bit architectures
	ByteSwap   bool         // true if byte order needs swapping
}

// MachOHeader represents the Mach-O file header.
type MachOHeader struct {
	Magic      uint32
	CpuType    uint32
	CpuSubtype uint32
	FileType   uint32
	NCmds      uint32
	SizeOfCmds uint32
	Flags      uint32
	Reserved   uint32 // Only used in 64-bit headers
}

// HeaderSize returns the size of this header in bytes.
func (h *MachOHeader) HeaderSize() uint32 {
	if h.Magic == MHMagic64 || h.Magic == MHCigam64 {
		return MachOHeader64Size
	}
	return MachOHeader32Size
}

// FATHeader represents the FAT binary header.
type FATHeader struct {
	Magic  uint32
	NArch  uint32
}

// FATArch describes one architecture in a FAT binary.
type FATArch struct {
	CpuType    uint32
	CpuSubtype uint32
	Offset     uint32
	Size       uint32
	Align      uint32
}

// LoadCommand represents a generic Mach-O load command.
type LoadCommand struct {
	Cmd     uint32 // Command type (LC_*)
	CmdSize uint32 // Total size of this command including header
	Offset  uint64 // Absolute offset within the slice where this command starts
	Raw     []byte // Full raw bytes of the command (including cmd+cmdsize header)
}

// SegmentCommand represents the data from LC_SEGMENT / LC_SEGMENT_64.
type SegmentCommand struct {
	Name     string
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64
	MaxProt  uint32
	InitProt uint32
	NSects   uint32
	Flags    uint32
}

// CodeSignatureCmd represents the LC_CODE_SIGNATURE load command payload.
type CodeSignatureCmd struct {
	DataOff  uint32 // Offset of code signature in the file
	DataSize uint32 // Size of the code signature
}

// DylibCommand represents LC_LOAD_DYLIB data.
type DylibCommand struct {
	NameOffset       uint32 // Offset of dylib name string from start of load command
	Timestamp        uint32
	CurrentVersion   uint32
	CompatVersion    uint32
	Name             string // The actual dylib path string
}

// GetCodeSignatureCmd finds and returns the LC_CODE_SIGNATURE command, or nil if absent.
func (s *MachOSlice) GetCodeSignatureCmd() *LoadCommand {
	for i := range s.LoadCmds {
		if s.LoadCmds[i].Cmd == LCCodeSignature {
			return &s.LoadCmds[i]
		}
	}
	return nil
}

// GetSegment finds a segment load command by name.
func (s *MachOSlice) GetSegment(name string) *LoadCommand {
	for i := range s.LoadCmds {
		cmd := &s.LoadCmds[i]
		if cmd.Cmd == LCSegment || cmd.Cmd == LCSegment64 {
			segName := extractSegmentName(cmd.Raw, cmd.Cmd == LCSegment64)
			if segName == name {
				return cmd
			}
		}
	}
	return nil
}

// GetLinkeditSegment returns the __LINKEDIT segment command.
func (s *MachOSlice) GetLinkeditSegment() *LoadCommand {
	return s.GetSegment(SegLinkEdit)
}

// extractSegmentName extracts the segment name from raw load command bytes.
func extractSegmentName(raw []byte, is64 bool) string {
	if len(raw) < LoadCmdHeaderSize+16 {
		return ""
	}
	nameBytes := raw[LoadCmdHeaderSize : LoadCmdHeaderSize+16]
	// Find null terminator
	n := 0
	for n < len(nameBytes) && nameBytes[n] != 0 {
		n++
	}
	return string(nameBytes[:n])
}

// CpuTypeName returns a human-readable name for a CPU type.
func CpuTypeName(cpuType uint32) string {
	switch cpuType {
	case CPUTypeX86:
		return "x86"
	case CPUTypeX86_64:
		return "x86_64"
	case CPUTypeARM:
		return "arm"
	case CPUTypeARM64:
		return "arm64"
	default:
		return "unknown"
	}
}
