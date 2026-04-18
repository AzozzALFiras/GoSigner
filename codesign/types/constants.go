package types

// Code signature blob magic numbers (big-endian)
const (
	CSMagicEmbeddedSignature uint32 = 0xFADE0CC0 // SuperBlob containing all signature data
	CSMagicCodeDirectory     uint32 = 0xFADE0C02 // CodeDirectory blob
	CSMagicRequirements      uint32 = 0xFADE0C01 // Requirements set
	CSMagicRequirement       uint32 = 0xFADE0C00 // Single requirement
	CSMagicEntitlements      uint32 = 0xFADE7171 // Entitlements blob (XML plist)
	CSMagicDEREntitlements   uint32 = 0xFADE7172 // DER-encoded entitlements
	CSMagicBlobWrapper       uint32 = 0xFADE0B01 // CMS signature wrapper
)

// Slot types in the SuperBlob
const (
	CSSlotCodeDirectory    uint32 = 0x00000
	CSSlotInfoSlot         uint32 = 0x00001 // Info.plist
	CSSlotRequirements     uint32 = 0x00002
	CSSlotResourceDir      uint32 = 0x00003 // CodeResources
	CSSlotApplication      uint32 = 0x00004
	CSSlotEntitlements     uint32 = 0x00005
	CSSlotDEREntitlements  uint32 = 0x00007
	CSSlotAltCodeDirectory uint32 = 0x1000 // SHA-256 CodeDirectory (Apple uses 0x1000-0x1005 for alternates)
	CSSlotCMSSignature     uint32 = 0x10000
)

// Hash types
const (
	CSHashTypeSHA1         uint8 = 1
	CSHashTypeSHA256       uint8 = 2
	CSHashTypeSHA256Trunc  uint8 = 3
	CSHashTypeSHA384       uint8 = 4
)

// Hash sizes
const (
	CSHashSizeSHA1   = 20
	CSHashSizeSHA256 = 32
)

// Code page size for hashing
const CSPageSize = 4096

// CodeDirectory version
const CSCodeDirectoryVersion uint32 = 0x20400

// CodeDirectory flags
const (
	CSAdhoc       uint32 = 0x00000002 // Ad-hoc signed
	CSForceHard   uint32 = 0x00000100
	CSForceKill   uint32 = 0x00000200
	CSForceExpire uint32 = 0x00000400
)

// execSegFlags (iOS 13+)
const (
	CSExecSegMainBinary     uint64 = 0x1     // Executable segment of main binary
	CSExecSegAllowUnsigned  uint64 = 0x10    // Allow unsigned pages (debug only)
	CSExecSegDebugger       uint64 = 0x20    // Main binary is debugger
	CSExecSegJit            uint64 = 0x40    // JIT enabled
	CSExecSegSkipLV         uint64 = 0x80    // Skip library validation
	CSExecSegCanLoadCDHash  uint64 = 0x100
	CSExecSegCanExecCDHash  uint64 = 0x200
)

// Special slot indices (negative, counted from special slots)
const (
	CSSpecialSlotInfoPlist        = 1 // -1: Info.plist hash
	CSSpecialSlotRequirements     = 2 // -2: Requirements hash
	CSSpecialSlotResourceDir      = 3 // -3: CodeResources hash
	CSSpecialSlotApplication      = 4 // -4: Application-specific
	CSSpecialSlotEntitlements     = 5 // -5: Entitlements hash
	CSSpecialSlotRepSpecific      = 6 // -6
	CSSpecialSlotDEREntitlements  = 7 // -7: DER entitlements hash
)

// Requirement opcodes
const (
	ReqOpFalse            uint32 = 0
	ReqOpTrue             uint32 = 1
	ReqOpIdent            uint32 = 2
	ReqOpAppleAnchor      uint32 = 3
	ReqOpAnchorHash       uint32 = 4
	ReqOpInfoKeyValue     uint32 = 5
	ReqOpAnd              uint32 = 6
	ReqOpOr               uint32 = 7
	ReqOpCDHash           uint32 = 8
	ReqOpNot              uint32 = 9
	ReqOpInfoKeyField     uint32 = 10
	ReqOpCertField        uint32 = 11
	ReqOpTrustedCert      uint32 = 12
	ReqOpTrustedCerts     uint32 = 13
	ReqOpCertGeneric      uint32 = 14
	ReqOpAppleGenericAnchor uint32 = 15
	ReqOpEntitlementField uint32 = 16
	ReqOpCertPolicy       uint32 = 17
	ReqOpNamedAnchor      uint32 = 18
	ReqOpNamedCode        uint32 = 19
	ReqOpPlatform         uint32 = 20
)

// Requirement match operations
const (
	ReqMatchExists    uint32 = 0
	ReqMatchEqual     uint32 = 1
	ReqMatchContains  uint32 = 2
	ReqMatchBeginsWith uint32 = 3
	ReqMatchEndsWith  uint32 = 4
	ReqMatchLessThan  uint32 = 5
	ReqMatchGreaterThan uint32 = 6
)

// Requirement expression types
const (
	ReqExprDesignated uint32 = 3
)
