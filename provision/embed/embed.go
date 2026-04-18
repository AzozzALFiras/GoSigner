package embed

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AzozzALFiras/GoSigner/provision"
)

const embeddedProfileName = "embedded.mobileprovision"

// EmbedProfile writes the provisioning profile to the app bundle as embedded.mobileprovision.
// This is safe and never deletes existing profiles unless explicitly requested.
func EmbedProfile(profile *provision.ProvisioningProfile, appBundlePath string) error {
	if profile == nil || len(profile.RawData) == 0 {
		return fmt.Errorf("no profile data to embed")
	}

	destPath := filepath.Join(appBundlePath, embeddedProfileName)
	if err := os.WriteFile(destPath, profile.RawData, 0644); err != nil {
		return fmt.Errorf("write embedded profile: %w", err)
	}

	return nil
}

// RemoveProfile removes the embedded provisioning profile from the app bundle.
// Only call this when the user explicitly requests --strip-profile.
func RemoveProfile(appBundlePath string) error {
	destPath := filepath.Join(appBundlePath, embeddedProfileName)

	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		return nil // Nothing to remove
	}

	if err := os.Remove(destPath); err != nil {
		return fmt.Errorf("remove embedded profile: %w", err)
	}

	return nil
}

// ReadEmbeddedProfile reads an existing embedded.mobileprovision from an app bundle.
// Returns nil, nil if no embedded profile exists.
func ReadEmbeddedProfile(appBundlePath string) ([]byte, error) {
	destPath := filepath.Join(appBundlePath, embeddedProfileName)

	data, err := os.ReadFile(destPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read embedded profile: %w", err)
	}

	return data, nil
}
