package cms

import "encoding/asn1"

// Apple-specific OIDs used in CMS signatures for iOS code signing.
// These MUST be present in signedAttrs or iOS 15+ will reject the signature.
var (
	// OID 1.2.840.113635.100.9.1 — Apple CDHashes plist
	// Contains a plist with all CodeDirectory hashes (SHA-1 and SHA-256)
	OIDAppleCDHashes = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}

	// OID 1.2.840.113635.100.9.2 — Apple Entitlements plist
	// Contains the raw XML entitlements plist as a signed attribute
	OIDAppleEntitlements = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}

	// Standard PKCS#7/CMS OIDs
	OIDSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Hash algorithm OIDs
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// Signature algorithm OIDs
	OIDrsaEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDsha256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDsha1WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDecdsaWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// ============================================================================
// ASN.1 structures for CMS SignedData
// Layout follows RFC 5652 (CMS) with Apple extensions
// ============================================================================

// ContentInfo is the outermost wrapper of CMS messages:
//   ContentInfo ::= SEQUENCE {
//       contentType ContentType,
//       content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
//   }
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// SignedData is the main CMS structure:
//   SignedData ::= SEQUENCE {
//       version CMSVersion,
//       digestAlgorithms DigestAlgorithmIdentifiers,
//       encapContentInfo EncapsulatedContentInfo,
//       certificates [0] IMPLICIT CertificateSet OPTIONAL,
//       crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//       signerInfos SignerInfos
//   }
type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"` // IMPLICIT [0] SET OF Certificate
	SignerInfos      []SignerInfo  `asn1:"set"`
}

// EncapContentInfo describes the data being signed:
//   EncapsulatedContentInfo ::= SEQUENCE {
//       eContentType ContentType,
//       eContent [0] EXPLICIT OCTET STRING OPTIONAL
//   }
// For detached signatures (what Apple uses), eContent is OMITTED.
type EncapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// AlgorithmIdentifier represents hash/signature algorithms:
//   AlgorithmIdentifier ::= SEQUENCE {
//       algorithm OBJECT IDENTIFIER,
//       parameters ANY DEFINED BY algorithm OPTIONAL
//   }
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// IssuerAndSerialNumber identifies a certificate:
//   IssuerAndSerialNumber ::= SEQUENCE {
//       issuer Name,
//       serialNumber CertificateSerialNumber
//   }
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber asn1.RawValue
}

// SignerInfo describes one signer:
//   SignerInfo ::= SEQUENCE {
//       version CMSVersion,
//       sid SignerIdentifier,
//       digestAlgorithm DigestAlgorithmIdentifier,
//       signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//       signatureAlgorithm SignatureAlgorithmIdentifier,
//       signature SignatureValue,
//       unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
//   }
type SignerInfo struct {
	Version            int
	SID                IssuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"` // IMPLICIT [0] SET OF Attribute
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

// Attribute is a signed or unsigned attribute:
//   Attribute ::= SEQUENCE {
//       attrType OBJECT IDENTIFIER,
//       attrValues SET OF AttributeValue
//   }
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}
