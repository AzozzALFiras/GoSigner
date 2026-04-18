package provision

import "time"

// ProvisioningProfile represents a parsed Apple provisioning profile.
type ProvisioningProfile struct {
	Name                        string    `plist:"Name"`
	UUID                        string    `plist:"UUID"`
	TeamIdentifier              []string  `plist:"TeamIdentifier"`
	TeamName                    string    `plist:"TeamName"`
	AppIDName                   string    `plist:"AppIDName"`
	ApplicationIdentifierPrefix []string  `plist:"ApplicationIdentifierPrefix"`
	CreationDate                time.Time `plist:"CreationDate"`
	ExpirationDate              time.Time `plist:"ExpirationDate"`
	ProvisionsAllDevices        bool      `plist:"ProvisionsAllDevices"`
	ProvisionedDevices          []string  `plist:"ProvisionedDevices"`
	DeveloperCertificates       [][]byte  `plist:"DeveloperCertificates"`
	IsXcodeManaged              bool      `plist:"IsXcodeManaged"`
	Platform                    []string  `plist:"Platform"`

	// Entitlements extracted from the profile
	Entitlements Entitlements `plist:"Entitlements"`

	// RawPlist is the inner XML plist data extracted from the CMS envelope.
	RawPlist []byte `plist:"-"`

	// RawData is the entire mobileprovision file bytes (for embedding in the app).
	RawData []byte `plist:"-"`
}

// Entitlements is a flexible map representing app entitlements.
type Entitlements map[string]interface{}

// GetTeamID returns the first team identifier, or empty string if none.
func (p *ProvisioningProfile) GetTeamID() string {
	if len(p.TeamIdentifier) > 0 {
		return p.TeamIdentifier[0]
	}
	return ""
}

// GetAppID returns the application identifier from entitlements.
func (p *ProvisioningProfile) GetAppID() string {
	if v, ok := p.Entitlements["application-identifier"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// IsExpired returns true if the profile has expired.
func (p *ProvisioningProfile) IsExpired() bool {
	return time.Now().After(p.ExpirationDate)
}

// GetKeychainAccessGroups returns the keychain access groups from entitlements.
func (p *ProvisioningProfile) GetKeychainAccessGroups() []string {
	if v, ok := p.Entitlements["keychain-access-groups"]; ok {
		if groups, ok := v.([]interface{}); ok {
			result := make([]string, 0, len(groups))
			for _, g := range groups {
				if s, ok := g.(string); ok {
					result = append(result, s)
				}
			}
			return result
		}
	}
	return nil
}
