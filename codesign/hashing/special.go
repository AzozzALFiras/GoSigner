package hashing

import (
	"crypto/sha1"
	"crypto/sha256"

	cstypes "github.com/AzozzALFiras/GoSigner/codesign/types"
)

// ComputeSpecialSlotHashes computes all special slot hashes for the CodeDirectory.
func ComputeSpecialSlotHashes(
	infoPlist []byte,
	requirementsBlob []byte,
	resourceDir []byte,
	entitlementsBlob []byte,
	derEntitlementsBlob []byte,
) *cstypes.SpecialSlotHashes {
	hashes := &cstypes.SpecialSlotHashes{}

	if len(infoPlist) > 0 {
		h1 := sha1.Sum(infoPlist)
		h256 := sha256.Sum256(infoPlist)
		hashes.InfoPlistSHA1 = h1[:]
		hashes.InfoPlistSHA256 = h256[:]
	}

	if len(requirementsBlob) > 0 {
		h1 := sha1.Sum(requirementsBlob)
		h256 := sha256.Sum256(requirementsBlob)
		hashes.RequirementsSHA1 = h1[:]
		hashes.RequirementsSHA256 = h256[:]
	}

	if len(resourceDir) > 0 {
		h1 := sha1.Sum(resourceDir)
		h256 := sha256.Sum256(resourceDir)
		hashes.ResourceDirSHA1 = h1[:]
		hashes.ResourceDirSHA256 = h256[:]
	}

	if len(entitlementsBlob) > 0 {
		h1 := sha1.Sum(entitlementsBlob)
		h256 := sha256.Sum256(entitlementsBlob)
		hashes.EntitlementsSHA1 = h1[:]
		hashes.EntitlementsSHA256 = h256[:]
	}

	if len(derEntitlementsBlob) > 0 {
		h1 := sha1.Sum(derEntitlementsBlob)
		h256 := sha256.Sum256(derEntitlementsBlob)
		hashes.DEREntitlementsSHA1 = h1[:]
		hashes.DEREntitlementsSHA256 = h256[:]
	}

	return hashes
}
