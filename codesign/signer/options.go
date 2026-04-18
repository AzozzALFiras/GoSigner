package signer

// Options holds configuration for signing a Mach-O binary.
type Options struct {
	BundleID        string // App bundle identifier
	TeamID          string // Developer team ID
	InfoPlist       []byte // Raw Info.plist data for special slot hashing
	CodeResources   []byte // Raw CodeResources plist for special slot hashing
	EntitlementsXML []byte // XML plist entitlements
	EntitlementsDER []byte // DER-encoded entitlements
	// SkipDEREntitlements disables the DER entitlements slot (0x7 / -7)
	// entirely: no auto-generation from XML, no SuperBlob slot, no CD
	// special-slot hash. zsign/esign emit frameworks this way — only the
	// main binary and app extensions carry DER entitlements.
	SkipDEREntitlements bool
	Flags           uint32 // CodeDirectory flags (0 for normal, CSAdhoc for ad-hoc)
	IsAdhoc         bool   // Ad-hoc signing (no CMS signature)

	// Executable segment info (required by iOS 13+)
	// Taken from __TEXT segment of the Mach-O.
	// For the main binary, ExecSegFlags must include CS_EXECSEG_MAIN_BINARY (0x1).
	ExecSegBase  uint64
	ExecSegLimit uint64
	ExecSegFlags uint64
}
