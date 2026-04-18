package cms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/AzozzALFiras/GoSigner/codesign/blobs"
	cstypes "github.com/AzozzALFiras/GoSigner/codesign/types"
	"howett.net/plist"
)

// GenerateCMS creates an Apple-compatible CMS/PKCS7 signature with:
//   - Standard signed attributes (contentType, signingTime, messageDigest)
//   - Apple CDHashes plist attribute (1.2.840.113635.100.9.1)
//   - Apple Entitlements plist attribute (1.2.840.113635.100.9.2)
//   - Full certificate chain (leaf + intermediates)
//
// This is REQUIRED by iOS 15+ — without these Apple-specific attrs,
// installation fails with "Unable to install".
func GenerateCMS(
	cert *x509.Certificate,
	privateKey crypto.Signer,
	certChain []*x509.Certificate,
	codeDirectorySHA1 []byte,
	codeDirectorySHA256 []byte,
	entitlementsXML []byte,
) ([]byte, error) {
	// Build SignedAttributes set — match esign V5.0.2 exactly: only
	// contentType + signingTime + messageDigest. Do NOT include Apple
	// 1.2.840.113635.100.9.1 (CDHashes plist) or 100.9.2 (Entitlements plist)
	// — esign omits them and is accepted by iOS 26. Our prior inclusion
	// of these was the silent-rejection trigger.
	signedAttrs, err := buildSignedAttrs(codeDirectorySHA256)
	if err != nil {
		return nil, fmt.Errorf("build signed attrs: %w", err)
	}

	// DER-encode the SignedAttributes for signing
	// RFC 5652: signedAttrs is signed as DER-encoded SET OF Attribute (not IMPLICIT)
	signedAttrsDER, err := encodeSignedAttrsForSigning(signedAttrs)
	if err != nil {
		return nil, fmt.Errorf("encode signed attrs for signing: %w", err)
	}

	// Sign the DER-encoded signed attributes
	hashed := sha256.Sum256(signedAttrsDER)
	signature, err := privateKey.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Build SignerInfo
	signerInfo, err := buildSignerInfo(cert, signature, signedAttrs)
	if err != nil {
		return nil, fmt.Errorf("build signer info: %w", err)
	}

	// Build the full SignedData
	certsRaw, err := encodeCertificates(cert, certChain)
	if err != nil {
		return nil, fmt.Errorf("encode certificates: %w", err)
	}

	signedData := SignedData{
		Version: 1,
		DigestAlgorithms: []AlgorithmIdentifier{
			// Per RFC 5754: SHA-256 DigestAlgorithmIdentifier parameters
			// MUST be absent (not NULL). esign V5.0.2 also emits absent.
			{Algorithm: OIDSHA256},
		},
		EncapContentInfo: EncapContentInfo{
			EContentType: OIDData,
			// Detached: no eContent
		},
		Certificates: certsRaw,
		SignerInfos:  []SignerInfo{signerInfo},
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("marshal signed data: %w", err)
	}

	// Wrap in ContentInfo
	contentInfo := ContentInfo{
		ContentType: OIDSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	return asn1.Marshal(contentInfo)
}

// buildCDHashesPlist creates the cdhashes plist that Apple validates.
// Format (from Apple Security source):
//   { "cdhashes": [<20-byte data>, <20-byte data>, ...] }
// Each hash is truncated to 20 bytes regardless of hash algorithm.
func buildCDHashesPlist(cdSHA1 []byte, cdSHA256 []byte) ([]byte, error) {
	const truncLen = 20

	hashes := [][]byte{}
	if len(cdSHA1) >= truncLen {
		hashes = append(hashes, cdSHA1[:truncLen])
	}
	if len(cdSHA256) >= truncLen {
		hashes = append(hashes, cdSHA256[:truncLen])
	}

	data := map[string]interface{}{
		"cdhashes": hashes,
	}

	return plist.Marshal(data, plist.XMLFormat)
}

// buildSignedAttrs constructs the minimal set of signed attributes that
// match esign V5.0.2 byte-for-byte: contentType, signingTime, messageDigest.
func buildSignedAttrs(cdSHA256 []byte) ([]Attribute, error) {
	attrs := []Attribute{}

	// 1. contentType — points to pkcs7-data (for detached signature)
	ctValue, err := asn1.Marshal(OIDData)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, Attribute{
		Type: OIDContentType,
		Values: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      ctValue,
		},
	})

	// 2. signingTime
	signingTimeBytes, err := asn1.Marshal(time.Now().UTC())
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, Attribute{
		Type: OIDSigningTime,
		Values: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      signingTimeBytes,
		},
	})

	// 3. messageDigest — SHA-256 of the CodeDirectory blob.
	digestBytes, err := asn1.Marshal(cdSHA256)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, Attribute{
		Type: OIDMessageDigest,
		Values: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      digestBytes,
		},
	})

	return attrs, nil
}

// encodeSignedAttrsForSigning produces the DER bytes that get hashed and signed.
// Per RFC 5652 §5.4: the attributes are encoded as DER SET OF Attribute
// (NOT as the IMPLICIT [0] tagged form that appears in the final SignerInfo).
func encodeSignedAttrsForSigning(attrs []Attribute) ([]byte, error) {
	// Marshal each attribute separately and concatenate inside a SET (tag 0x31)
	var innerBuf bytes.Buffer
	for _, a := range attrs {
		b, err := asn1.Marshal(a)
		if err != nil {
			return nil, err
		}
		innerBuf.Write(b)
	}

	// Wrap in SET OF
	setRaw := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      innerBuf.Bytes(),
	}

	return asn1.Marshal(setRaw)
}

// buildSignerInfo assembles the complete SignerInfo for our single signer.
func buildSignerInfo(cert *x509.Certificate, signature []byte, signedAttrs []Attribute) (SignerInfo, error) {
	// Marshal signed attrs as IMPLICIT [0] for the SignerInfo
	var innerBuf bytes.Buffer
	for _, a := range signedAttrs {
		b, err := asn1.Marshal(a)
		if err != nil {
			return SignerInfo{}, err
		}
		innerBuf.Write(b)
	}

	signedAttrsImplicit := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      innerBuf.Bytes(),
	}

	// Issuer and serial number
	serialBytes, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return SignerInfo{}, err
	}

	sid := IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: asn1.RawValue{FullBytes: serialBytes},
	}

	// Determine SignerInfo.signatureAlgorithm OID. Apple's codesign and
	// esign V5.0.2 emit the plain key OID (rsaEncryption / id-ecPublicKey)
	// here — NOT the combined hash+sign OID. The actual digest algo is
	// already specified by digestAlgorithm; duplicating it via
	// sha256WithRSAEncryption here upset iOS 26's stricter CMS verifier.
	var sigAlgOID asn1.ObjectIdentifier
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		sigAlgOID = OIDrsaEncryption
	default:
		sigAlgOID = OIDecdsaWithSHA256
	}

	// Signature algorithm params: NULL for RSA (RFC 3370), absent for ECDSA (RFC 5754).
	sigAlg := AlgorithmIdentifier{Algorithm: sigAlgOID}
	if _, isRSA := cert.PublicKey.(*rsa.PublicKey); isRSA {
		sigAlg.Parameters = asn1.RawValue{Tag: 5} // NULL
	}

	return SignerInfo{
		Version: 1,
		SID:     sid,
		DigestAlgorithm: AlgorithmIdentifier{
			// SHA-256 digest algo params MUST be absent per RFC 5754.
			Algorithm: OIDSHA256,
		},
		SignedAttrs:        signedAttrsImplicit,
		SignatureAlgorithm: sigAlg,
		Signature:          signature,
	}, nil
}

// encodeCertificates wraps the certificate chain in the IMPLICIT [0] SET
// structure, emitting each cert in the exact order given. Callers decide the
// order (esign emits WWDR first, then leaf — we match that).
func encodeCertificates(_ *x509.Certificate, chain []*x509.Certificate) (asn1.RawValue, error) {
	var certBuf bytes.Buffer
	seen := map[string]bool{}
	for _, c := range chain {
		if c == nil {
			continue
		}
		key := string(c.Raw)
		if seen[key] {
			continue
		}
		seen[key] = true
		certBuf.Write(c.Raw)
	}

	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      certBuf.Bytes(),
	}, nil
}

// BuildCMSBlob wraps a CMS signature in the code signature blob format.
func BuildCMSBlob(cmsSignature []byte) []byte {
	return blobs.WrapBlob(cstypes.CSMagicBlobWrapper, cmsSignature)
}

// BuildEmptyCMSBlob creates an empty CMS blob (for ad-hoc signing).
func BuildEmptyCMSBlob() []byte {
	return blobs.WrapBlob(cstypes.CSMagicBlobWrapper, nil)
}

// ComputeCDHash computes the canonical hash of a CodeDirectory blob for CMS signing.
// Uses SHA-1 for SHA-1 CDs, SHA-256 for SHA-256 CDs.
func ComputeCDHash(cdBlob []byte, isSHA256 bool) []byte {
	if isSHA256 {
		h := sha256.Sum256(cdBlob)
		return h[:]
	}
	h := sha1.Sum(cdBlob)
	return h[:]
}
