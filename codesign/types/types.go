package types

// CodeSignature represents a complete code signature ready to embed in a Mach-O binary.
type CodeSignature struct {
	SuperBlob []byte // Serialized SuperBlob
	Size      uint32 // Total size in bytes
}

// BlobIndex represents a single entry in the SuperBlob index table.
type BlobIndex struct {
	Type   uint32 // Slot type (CSSlot*)
	Offset uint32 // Offset from start of SuperBlob
}

// Blob represents a generic signature blob.
type Blob struct {
	Magic uint32
	Data  []byte // Content after magic + length header
}

// SpecialSlotHashes contains hashes for the special slots in CodeDirectory.
type SpecialSlotHashes struct {
	InfoPlistSHA1   []byte // Hash of Info.plist
	InfoPlistSHA256 []byte
	RequirementsSHA1   []byte // Hash of Requirements blob
	RequirementsSHA256 []byte
	ResourceDirSHA1   []byte // Hash of CodeResources
	ResourceDirSHA256 []byte
	EntitlementsSHA1   []byte // Hash of Entitlements blob
	EntitlementsSHA256 []byte
	DEREntitlementsSHA1   []byte // Hash of DER Entitlements
	DEREntitlementsSHA256 []byte
}

// SigningInput holds all the data needed to build a code signature.
type SigningInput struct {
	BundleID       string
	TeamID         string
	CodeLimit      uint32 // Size of code to hash (offset of code signature)
	PageSize       uint32 // Hash page size (usually 4096)
	Flags          uint32 // CodeDirectory flags
	SpecialHashes  SpecialSlotHashes
	EntitlementsXML []byte // Raw XML plist entitlements
	EntitlementsDER []byte // DER-encoded entitlements
}
