package blobs

import (
	"encoding/asn1"
	"encoding/binary"

	cstypes "github.com/AzozzALFiras/GoSigner/codesign/types"
)

// Apple WWDR (Worldwide Developer Relations) OID. Present on the intermediate
// certificate that chains every Apple-signed developer/distribution leaf.
// DER value is `2A 86 48 86 F7 63 64 06 02 01` (10 bytes).
var appleWWDROID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}

// BuildRequirements builds the designated requirement blob, byte-for-byte
// matching the format Apple's codesign and esign emit:
//
//	identifier "<bundleID>" and
//	anchor apple generic and
//	certificate leaf[subject.CN] = "<leafCN>" and
//	certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */
//
// Opcode tree (matches esign):
//
//	AND
//	├── AND
//	│   ├── opIdent("bundleID")
//	│   └── opAppleGenericAnchor
//	└── AND
//	    ├── opCertField(leaf, "subject.CN", matchEqual, "leafCN")
//	    └── opCertGeneric(1, WWDR_OID_DER, matchExists)
//
// leafCN is the "iPhone Distribution: ... (TEAMID)" or "iPhone Developer:
// ... (TEAMID)" common name of the signing certificate.
func BuildRequirements(bundleID, leafCN string) []byte {
	expr := buildDesignatedRequirement(bundleID, leafCN)
	reqBlob := buildRequirementBlob(expr)
	return buildRequirementsSet(reqBlob)
}

// BuildEmptyRequirements creates an empty requirements set.
func BuildEmptyRequirements() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], cstypes.CSMagicRequirements)
	binary.BigEndian.PutUint32(buf[4:8], 12)
	binary.BigEndian.PutUint32(buf[8:12], 0) // count = 0
	return buf
}

func buildDesignatedRequirement(bundleID, leafCN string) []byte {
	identExpr := encodeOpIdent(bundleID)
	anchorExpr := encodeOp(cstypes.ReqOpAppleGenericAnchor)
	leafCNExpr := encodeCertFieldString(0, "subject.CN", cstypes.ReqMatchEqual, leafCN)
	wwdrExpr := encodeCertGenericExists(1, appleWWDROID)

	// Right-nested to match esign V5.0.2 byte-for-byte:
	//   ident AND (anchor AND (leafCN AND wwdr))
	innermost := encodeAnd(leafCNExpr, wwdrExpr)
	middle := encodeAnd(anchorExpr, innermost)
	return encodeAnd(identExpr, middle)
}

func buildRequirementBlob(expr []byte) []byte {
	totalSize := 12 + len(expr)
	buf := make([]byte, totalSize)
	binary.BigEndian.PutUint32(buf[0:4], cstypes.CSMagicRequirement)
	binary.BigEndian.PutUint32(buf[4:8], uint32(totalSize))
	binary.BigEndian.PutUint32(buf[8:12], 1) // kind = expression
	copy(buf[12:], expr)
	return buf
}

func buildRequirementsSet(reqBlob []byte) []byte {
	headerSize := 12 + 8 // magic + length + count + 1 index entry
	totalSize := headerSize + len(reqBlob)
	buf := make([]byte, totalSize)

	binary.BigEndian.PutUint32(buf[0:4], cstypes.CSMagicRequirements)
	binary.BigEndian.PutUint32(buf[4:8], uint32(totalSize))
	binary.BigEndian.PutUint32(buf[8:12], 1) // count = 1

	binary.BigEndian.PutUint32(buf[12:16], cstypes.ReqExprDesignated)
	binary.BigEndian.PutUint32(buf[16:20], uint32(headerSize))

	copy(buf[headerSize:], reqBlob)
	return buf
}

func encodeOp(op uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, op)
	return buf
}

// encodeOpIdent writes: opcode(4) | strLen(4) | strBytes (padded to 4).
// Length is the raw string length (no trailing NUL), matching esign.
func encodeOpIdent(s string) []byte {
	return append(encodeOp(cstypes.ReqOpIdent), encodeLenString(s)...)
}

func encodeAnd(left, right []byte) []byte {
	buf := make([]byte, 4+len(left)+len(right))
	binary.BigEndian.PutUint32(buf[0:4], cstypes.ReqOpAnd)
	copy(buf[4:], left)
	copy(buf[4+len(left):], right)
	return buf
}

// encodeCertFieldString: opCertField(11) | certSlot | fieldName(lenStr) | matchOp | value(lenStr)
func encodeCertFieldString(certSlot uint32, field string, matchOp uint32, value string) []byte {
	var buf []byte
	opHdr := make([]byte, 8)
	binary.BigEndian.PutUint32(opHdr[0:4], cstypes.ReqOpCertField)
	binary.BigEndian.PutUint32(opHdr[4:8], certSlot)
	buf = append(buf, opHdr...)
	buf = append(buf, encodeLenString(field)...)
	matchBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(matchBuf, matchOp)
	buf = append(buf, matchBuf...)
	buf = append(buf, encodeLenString(value)...)
	return buf
}

// encodeCertGenericExists: opCertGeneric(14) | certSlot | oidLen | oidDER (padded) | matchOp=Exists
func encodeCertGenericExists(certSlot uint32, oid asn1.ObjectIdentifier) []byte {
	oidDER := derOIDContents(oid)
	var buf []byte
	opHdr := make([]byte, 8)
	binary.BigEndian.PutUint32(opHdr[0:4], cstypes.ReqOpCertGeneric)
	binary.BigEndian.PutUint32(opHdr[4:8], certSlot)
	buf = append(buf, opHdr...)
	buf = append(buf, encodeLenBytes(oidDER)...)
	matchBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(matchBuf, cstypes.ReqMatchExists)
	buf = append(buf, matchBuf...)
	return buf
}

// encodeLenString writes length(4) + string bytes padded with zeros to a 4-byte boundary.
// Length is the string length itself (not including padding, no trailing NUL).
func encodeLenString(s string) []byte {
	return encodeLenBytes([]byte(s))
}

func encodeLenBytes(b []byte) []byte {
	padded := (len(b) + 3) &^ 3
	buf := make([]byte, 4+padded)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(b)))
	copy(buf[4:], b)
	return buf
}

// derOIDContents returns the DER content octets of the OID (without the
// outer tag/length). For 1.2.840.113635.100.6.2.1 this is the 10 bytes
// 2A 86 48 86 F7 63 64 06 02 01.
func derOIDContents(oid asn1.ObjectIdentifier) []byte {
	full, err := asn1.Marshal(oid)
	if err != nil {
		return nil
	}
	// asn1.Marshal produces `06 <len> <contents>`. Strip tag+length.
	if len(full) < 2 || full[0] != 0x06 {
		return nil
	}
	// Length may be short-form only (OIDs are small)
	return full[2:]
}
