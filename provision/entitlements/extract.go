package entitlements

import (
	"fmt"

	"github.com/AzozzALFiras/GoSigner/provision"
	"howett.net/plist"
)

// Extract returns the entitlements from a provisioning profile as XML plist bytes.
func Extract(profile *provision.ProvisioningProfile) ([]byte, error) {
	if profile.Entitlements == nil {
		return nil, fmt.Errorf("no entitlements found in provisioning profile")
	}

	data, err := plist.MarshalIndent(profile.Entitlements, plist.XMLFormat, "\t")
	if err != nil {
		return nil, fmt.Errorf("marshal entitlements to plist: %w", err)
	}

	return data, nil
}

// ExtractMap returns the entitlements as a map.
func ExtractMap(profile *provision.ProvisioningProfile) provision.Entitlements {
	if profile.Entitlements == nil {
		return make(provision.Entitlements)
	}
	return profile.Entitlements
}
