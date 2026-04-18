package parser

import (
	"fmt"
	"os"

	"github.com/AzozzALFiras/GoSigner/provision"
	"howett.net/plist"
)

// ParseFile loads and parses a .mobileprovision file from disk.
func ParseFile(path string) (*provision.ProvisioningProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provisioning profile: %w", err)
	}

	return ParseBytes(data)
}

// ParseBytes parses a provisioning profile from raw bytes.
func ParseBytes(data []byte) (*provision.ProvisioningProfile, error) {
	// Extract the inner plist from the CMS envelope
	plistData, err := DecodeCMSEnvelope(data)
	if err != nil {
		return nil, fmt.Errorf("decode cms envelope: %w", err)
	}

	// Parse the plist into the profile struct
	profile := &provision.ProvisioningProfile{}
	_, err = plist.Unmarshal(plistData, profile)
	if err != nil {
		return nil, fmt.Errorf("unmarshal provisioning profile plist: %w", err)
	}

	// Store the raw data for embedding later
	profile.RawPlist = plistData
	profile.RawData = data

	return profile, nil
}
