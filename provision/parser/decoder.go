package parser

import (
	"fmt"

	"go.mozilla.org/pkcs7"
)

// DecodeCMSEnvelope extracts the inner content from a CMS/PKCS7 signed data envelope.
// Provisioning profiles are DER-encoded PKCS7 SignedData wrapping an XML plist.
func DecodeCMSEnvelope(data []byte) ([]byte, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs7 envelope: %w", err)
	}

	return p7.Content, nil
}
