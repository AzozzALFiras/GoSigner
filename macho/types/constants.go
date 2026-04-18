package types

// Mach-O magic numbers
const (
	MHMagic32    uint32 = 0xFEEDFACE // 32-bit Mach-O
	MHMagic64    uint32 = 0xFEEDFACF // 64-bit Mach-O
	MHCigam32    uint32 = 0xCEFAEDFE // 32-bit Mach-O (byte-swapped)
	MHCigam64    uint32 = 0xCFFAEDFE // 64-bit Mach-O (byte-swapped)
	FATMagic     uint32 = 0xCAFEBABE // FAT/Universal binary
	FATCigam     uint32 = 0xBEBAFECA // FAT (byte-swapped)
	FATMagic64   uint32 = 0xCAFEBABF // FAT 64-bit
	FATCigam64   uint32 = 0xBFBAFECA // FAT 64-bit (byte-swapped)
)

// CPU types
const (
	CPUTypeX86    uint32 = 7
	CPUTypeX86_64 uint32 = 7 | 0x01000000
	CPUTypeARM    uint32 = 12
	CPUTypeARM64  uint32 = 12 | 0x01000000
)

// File types
const (
	MHExecute uint32 = 2  // Executable
	MHDylib   uint32 = 6  // Dynamic library
	MHBundle  uint32 = 8  // Loadable bundle
	MHDsym    uint32 = 10 // Debug symbols
)

// Load command types
const (
	LCSegment              uint32 = 0x01
	LCSymtab               uint32 = 0x02
	LCThread               uint32 = 0x04
	LCUnixthread           uint32 = 0x05
	LCLoadDylib            uint32 = 0x0C
	LCIDDylib              uint32 = 0x0D
	LCLoadDylibWeak        uint32 = 0x80000018
	LCSegment64            uint32 = 0x19
	LCUUID                 uint32 = 0x1B
	LCCodeSignature        uint32 = 0x1D
	LCSegmentSplitInfo     uint32 = 0x1E
	LCReexportDylib        uint32 = 0x8000001F
	LCEncryptionInfo       uint32 = 0x21
	LCDyldInfo             uint32 = 0x22
	LCDyldInfoOnly         uint32 = 0x80000022
	LCLoadUpwardDylib      uint32 = 0x80000023
	LCFunctionStarts       uint32 = 0x26
	LCDataInCode           uint32 = 0x29
	LCSourceVersion        uint32 = 0x2A
	LCDylibCodeSignDRS     uint32 = 0x2B
	LCEncryptionInfo64     uint32 = 0x2C
	LCLinkerOption         uint32 = 0x2D
	LCLinkerOptimizationHint uint32 = 0x2E
	LCVersionMinMacOSX     uint32 = 0x24
	LCVersionMinIPhoneOS   uint32 = 0x25
	LCBuildVersion         uint32 = 0x32
	LCDyldExportsTrie      uint32 = 0x80000033
	LCDyldChainedFixups    uint32 = 0x80000034
	LCRpath                uint32 = 0x8000001C
	LCMain                 uint32 = 0x80000028
)

// Segment names
const (
	SegText     = "__TEXT"
	SegData     = "__DATA"
	SegLinkEdit = "__LINKEDIT"
)

// Mach-O header sizes
const (
	MachOHeader32Size = 28 // 7 * 4 bytes
	MachOHeader64Size = 32 // 8 * 4 bytes (includes reserved field)
	FATHeaderSize     = 8  // magic + nfat_arch
	FATArchSize       = 20 // cputype + cpusubtype + offset + size + align
	LoadCmdHeaderSize = 8  // cmd + cmdsize
)

// FAT binary alignment
const FATAlignPower = 14  // 2^14 = 16384 bytes
const FATAlign      = 1 << FATAlignPower
