package blobs

import (
	cstypes "github.com/AzozzALFiras/GoSigner/codesign/types"
)

// BuildEntitlementsBlob wraps XML plist entitlements in a code signature blob.
func BuildEntitlementsBlob(xmlPlist []byte) []byte {
	return WrapBlob(cstypes.CSMagicEntitlements, xmlPlist)
}

// BuildDEREntitlementsBlob wraps DER-encoded entitlements in a code signature blob.
func BuildDEREntitlementsBlob(derData []byte) []byte {
	return WrapBlob(cstypes.CSMagicDEREntitlements, derData)
}
