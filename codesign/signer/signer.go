package signer

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/AzozzALFiras/GoSigner/certificate"
	"github.com/AzozzALFiras/GoSigner/certificate/chain"
	"github.com/AzozzALFiras/GoSigner/codesign/blobs"
	"github.com/AzozzALFiras/GoSigner/codesign/cms"
	"github.com/AzozzALFiras/GoSigner/codesign/hashing"
	cstypes "github.com/AzozzALFiras/GoSigner/codesign/types"
	"github.com/AzozzALFiras/GoSigner/provision/entitlements"
)

// SignMachOSlice generates a complete code signature for a single Mach-O architecture slice.
// source: reader for the binary data
// baseOffset: offset of this slice within the file
// codeLimit: size of code to sign (offset where signature will be placed)
// identity: signing certificate and key (nil for ad-hoc)
// opts: signing options
func SignMachOSlice(
	source io.ReaderAt,
	baseOffset uint64,
	codeLimit uint32,
	identity *certificate.SigningIdentity,
	opts *Options,
) ([]byte, error) {
	// Step 1: Compute page hashes
	sha1PageHashes, sha256PageHashes, err := hashing.ComputePageHashes(source, baseOffset, codeLimit)
	if err != nil {
		return nil, fmt.Errorf("compute page hashes: %w", err)
	}

	// Step 2: Build entitlements blobs
	var entitlementsBlob []byte
	var derEntitlementsBlob []byte
	if len(opts.EntitlementsXML) > 0 {
		entitlementsBlob = blobs.BuildEntitlementsBlob(opts.EntitlementsXML)

		// Auto-generate DER entitlements from XML unless the caller
		// explicitly opted out (frameworks / dylibs).
		if !opts.SkipDEREntitlements && len(opts.EntitlementsDER) == 0 {
			if ents, err := entitlements.LoadFromBytes(opts.EntitlementsXML); err == nil {
				if derBytes, err := entitlements.EncodeDER(ents); err == nil {
					opts.EntitlementsDER = derBytes
				}
			}
		}
	}
	if !opts.SkipDEREntitlements && len(opts.EntitlementsDER) > 0 {
		derEntitlementsBlob = blobs.BuildDEREntitlementsBlob(opts.EntitlementsDER)
	}

	// Step 3: Build designated requirement. Needs the leaf's common name so
	// the expression evaluates against the signing cert (esign does the same).
	leafCN := ""
	if identity != nil && identity.Certificate != nil {
		leafCN = identity.Certificate.Subject.CommonName
	}
	requirementsBlob := blobs.BuildRequirements(opts.BundleID, leafCN)

	// Step 4: Compute special slot hashes
	specialSlotData := hashing.ComputeSpecialSlotHashes(
		opts.InfoPlist,
		requirementsBlob,
		opts.CodeResources,
		entitlementsBlob,
		derEntitlementsBlob,
	)

	sha256SpecialHashes := buildSpecialHashMap(specialSlotData, cstypes.CSHashTypeSHA256)

	// Step 5: Build SHA-256 CodeDirectory ONLY.
	// Modern iOS (11+) requires SHA-256. Including SHA-1 causes modern tools like
	// esign/codesign NOT to produce it, and iOS rejects dual SHA-1+SHA-256 signatures
	// on iOS 17+. Place SHA-256 CD in slot 0 (primary), no alt slot 0x1000.
	cdSHA256 := blobs.BuildCodeDirectory(
		opts.BundleID, opts.TeamID, codeLimit,
		cstypes.CSHashTypeSHA256, sha256PageHashes,
		sha256SpecialHashes, opts.Flags,
		opts.ExecSegBase, opts.ExecSegLimit, opts.ExecSegFlags,
	)

	// Suppress unused warning
	_ = sha1PageHashes

	// Step 6: Build CMS signature
	var cmsBlob []byte
	if opts.IsAdhoc || identity == nil {
		cmsBlob = cms.BuildEmptyCMSBlob()
	} else {
		// Compute SHA-256 hash of CD blob for CMS signing
		cdHashSHA256 := hashing.HashData(cdSHA256, cstypes.CSHashTypeSHA256)

		// Build full cert chain: leaf + existing chain + Apple WWDR G3 + Apple Root CA.
		// iOS requires the full chain embedded in the CMS to validate the signature.
		fullChain := buildFullCertChain(identity.CertChain)

		// Pass SHA-256 hash for both args (no SHA-1 CD anymore)
		cmsSignature, err := cms.GenerateCMS(
			identity.Certificate,
			identity.PrivateKey,
			fullChain,
			nil, // no SHA-1 CD
			cdHashSHA256,
			opts.EntitlementsXML,
		)
		if err != nil {
			return nil, fmt.Errorf("generate cms signature: %w", err)
		}
		cmsBlob = cms.BuildCMSBlob(cmsSignature)
	}

	// Step 7: Assemble SuperBlob — SHA-256 CD is primary (slot 0), no alt slot.
	blobMap := map[uint32][]byte{
		cstypes.CSSlotCodeDirectory: cdSHA256,
		cstypes.CSSlotRequirements:  requirementsBlob,
		cstypes.CSSlotCMSSignature:  cmsBlob,
	}

	if len(entitlementsBlob) > 0 {
		blobMap[cstypes.CSSlotEntitlements] = entitlementsBlob
	}
	if len(derEntitlementsBlob) > 0 {
		blobMap[cstypes.CSSlotDEREntitlements] = derEntitlementsBlob
	}

	superBlob := blobs.BuildSuperBlob(blobMap)
	return superBlob, nil
}

// buildFullCertChain returns [WWDR G3, Apple Root CA, leaf] — matching the
// exact cert ordering that esign V5.0.2 emits and that iOS 26 accepts. The
// order in a CMS CertificateSet is not cryptographically significant, but
// matching the reference layout removes a needless source of divergence.
func buildFullCertChain(existing []*x509.Certificate) []*x509.Certificate {
	wwdr := chain.AppleWWDRG3()
	root := chain.AppleRoot()

	var leaf *x509.Certificate
	if len(existing) > 0 {
		leaf = existing[0]
	}

	var result []*x509.Certificate
	if wwdr != nil {
		result = append(result, wwdr)
	}
	if root != nil {
		result = append(result, root)
	}
	if leaf != nil {
		result = append(result, leaf)
	}
	_ = bytes.Equal
	return result
}

func buildSpecialHashMap(sh *cstypes.SpecialSlotHashes, hashType uint8) map[uint32][]byte {
	m := make(map[uint32][]byte)

	if hashType == cstypes.CSHashTypeSHA1 {
		if len(sh.InfoPlistSHA1) > 0 {
			m[cstypes.CSSpecialSlotInfoPlist] = sh.InfoPlistSHA1
		}
		if len(sh.RequirementsSHA1) > 0 {
			m[cstypes.CSSpecialSlotRequirements] = sh.RequirementsSHA1
		}
		if len(sh.ResourceDirSHA1) > 0 {
			m[cstypes.CSSpecialSlotResourceDir] = sh.ResourceDirSHA1
		}
		if len(sh.EntitlementsSHA1) > 0 {
			m[cstypes.CSSpecialSlotEntitlements] = sh.EntitlementsSHA1
		}
		if len(sh.DEREntitlementsSHA1) > 0 {
			m[cstypes.CSSpecialSlotDEREntitlements] = sh.DEREntitlementsSHA1
		}
	} else {
		if len(sh.InfoPlistSHA256) > 0 {
			m[cstypes.CSSpecialSlotInfoPlist] = sh.InfoPlistSHA256
		}
		if len(sh.RequirementsSHA256) > 0 {
			m[cstypes.CSSpecialSlotRequirements] = sh.RequirementsSHA256
		}
		if len(sh.ResourceDirSHA256) > 0 {
			m[cstypes.CSSpecialSlotResourceDir] = sh.ResourceDirSHA256
		}
		if len(sh.EntitlementsSHA256) > 0 {
			m[cstypes.CSSpecialSlotEntitlements] = sh.EntitlementsSHA256
		}
		if len(sh.DEREntitlementsSHA256) > 0 {
			m[cstypes.CSSpecialSlotDEREntitlements] = sh.DEREntitlementsSHA256
		}
	}

	return m
}
