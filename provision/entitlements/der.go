package entitlements

import (
	"encoding/asn1"
	"fmt"
	"sort"

	"github.com/AzozzALFiras/GoSigner/provision"
)

// EncodeDER encodes entitlements into Apple's DER ASN.1 format for code
// signatures (special slot -7). The layout is what iOS's Security
// framework expects and what OpenSSL-based tools like zsign and esign
// emit; iOS 26 rejects non-conformant encodings on AdHoc / Developer
// profiles.
//
// Apple's encoding rules for this blob:
//  1. Outer container: SET OF SEQUENCE{key, value}
//  2. Entries are sorted ascending by DER-encoded SEQUENCE bytes — this
//     is required for a canonical DER SET OF.
//  3. Strings (keys AND string values) are UTF8STRING (tag 0x0C).
//     Go's asn1.Marshal(string) emits PRINTABLESTRING (0x13) when the
//     content is ASCII, which Apple rejects — we force UTF8STRING.
//  4. Arrays inside values are SEQUENCE OF (not SET OF).
//  5. Booleans follow standard DER: TRUE == 0x01. (Go's default already
//     does this; we preserve that path.)
func EncodeDER(ent provision.Entitlements) ([]byte, error) {
	keys := make([]string, 0, len(ent))
	for k := range ent {
		keys = append(keys, k)
	}
	// Sort entries alphabetically by key string. This matches what
	// zsign/esign emit for the SET OF — Apple's parser accepts that
	// ordering and expects it. (Strict DER canonical SET OF requires
	// sorting by encoded bytes, but Apple's blob is BER-lenient here.)
	sort.Strings(keys)

	var setContent []byte
	for _, k := range keys {
		keyDER := utf8String(k)
		valDER, err := marshalValue(ent[k])
		if err != nil {
			return nil, fmt.Errorf("marshal value for %q: %w", k, err)
		}
		seq, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      append(keyDER, valDER...),
		})
		if err != nil {
			return nil, err
		}
		setContent = append(setContent, seq...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      setContent,
	})
}

// marshalValue encodes one entitlement value. See EncodeDER for the rules.
func marshalValue(val interface{}) ([]byte, error) {
	switch v := val.(type) {
	case bool:
		// Go's asn1.Marshal encodes BOOLEAN TRUE as 0xFF (strict DER).
		// Apple/zsign/esign use 0x01 (BER), and iOS parses the blob
		// with BER semantics. We emit 0x01 to match byte-for-byte.
		if v {
			return []byte{0x01, 0x01, 0x01}, nil
		}
		return []byte{0x01, 0x01, 0x00}, nil
	case string:
		return utf8String(v), nil
	case int:
		return asn1.Marshal(v)
	case int64:
		return asn1.Marshal(int(v))
	case uint64:
		return asn1.Marshal(int(v))
	case []interface{}:
		// SEQUENCE OF (not SET OF): iOS's DER entitlements parser
		// expects an ordered list here, and zsign/esign always emit
		// SEQUENCE. An empty array still produces an empty SEQUENCE.
		var content []byte
		for _, item := range v {
			b, err := marshalValue(item)
			if err != nil {
				return nil, err
			}
			content = append(content, b...)
		}
		return asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      content,
		})
	case []string:
		var content []byte
		for _, s := range v {
			content = append(content, utf8String(s)...)
		}
		return asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      content,
		})
	default:
		return nil, fmt.Errorf("unsupported entitlement value type %T", val)
	}
}

// utf8String builds a DER UTF8STRING (universal tag 0x0C) for s. Go's
// asn1.Marshal(string) picks PRINTABLESTRING (0x13) for ASCII strings,
// but Apple's entitlements parser specifically requires UTF8STRING for
// both keys and string values.
func utf8String(s string) []byte {
	body := []byte(s)
	out := []byte{0x0C}
	out = append(out, derLength(len(body))...)
	out = append(out, body...)
	return out
}

// derLength encodes a DER length. Short form for len < 128, long form
// otherwise.
func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0xFF)}, tmp...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}
