package entitlements

import (
	"fmt"
	"os"

	"github.com/AzozzALFiras/GoSigner/provision"
	"howett.net/plist"
)

// Merge combines profile entitlements with custom entitlements.
// Custom entitlements override profile entitlements for matching keys.
func Merge(profileEnts provision.Entitlements, customEnts provision.Entitlements) provision.Entitlements {
	result := make(provision.Entitlements)

	// Start with profile entitlements
	for k, v := range profileEnts {
		result[k] = v
	}

	// Override/add custom entitlements
	for k, v := range customEnts {
		result[k] = v
	}

	return result
}

// LoadFromFile loads entitlements from a plist file on disk.
func LoadFromFile(path string) (provision.Entitlements, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read entitlements file: %w", err)
	}

	return LoadFromBytes(data)
}

// LoadFromBytes parses entitlements from XML or binary plist bytes.
func LoadFromBytes(data []byte) (provision.Entitlements, error) {
	ent := make(provision.Entitlements)
	_, err := plist.Unmarshal(data, &ent)
	if err != nil {
		return nil, fmt.Errorf("unmarshal entitlements: %w", err)
	}

	return ent, nil
}

// MarshalXML marshals entitlements to XML plist format.
func MarshalXML(ent provision.Entitlements) ([]byte, error) {
	data, err := plist.MarshalIndent(ent, plist.XMLFormat, "\t")
	if err != nil {
		return nil, fmt.Errorf("marshal entitlements: %w", err)
	}
	return data, nil
}
