package infoplist

import (
	"time"
	"fmt"
	"strconv"
	"strings"

	"howett.net/plist"
)

// Minimum MinimumOSVersion that modern iOS (26+) accepts for installation.
// Apps with lower MinOS get rejected silently. esign uses 10.0 as the safe floor.
const minAcceptableMinOS = "10.0"

// ModifyOptions specifies what to change in an Info.plist.
type ModifyOptions struct {
	BundleID      string // New bundle identifier (empty = keep)
	BundleName    string // New display name (empty = keep)
	BundleVersion string // New version (empty = keep)
	MinOSVersion  string // New minimum OS version (empty = keep, but auto-bump to 10.0 if lower)
	EnableDocs    bool   // Enable UIFileSharingEnabled
	IconName      string // CFBundleIconFiles base name (empty = keep existing icon)
}

// Modify updates Info.plist fields and returns the new plist bytes.
// Always applies iOS-26 compatibility fixes:
//   - Bumps MinimumOSVersion to 10.0 if lower (iOS 26 rejects apps with old MinOS)
//   - Removes UISupportedDevices (restricts app to specific old device models)
func Modify(data []byte, opts *ModifyOptions) ([]byte, error) {
	raw, err := ReadRaw(data)
	if err != nil {
		return nil, err
	}

	if opts.BundleID != "" {
		raw["CFBundleIdentifier"] = opts.BundleID
	}
	if opts.BundleName != "" {
		// Only the home-screen label. Never touch CFBundleName — changing it
		// (e.g. to a value with spaces) can break installation.
		raw["CFBundleDisplayName"] = opts.BundleName
	}
	if opts.BundleVersion != "" {
		raw["CFBundleShortVersionString"] = opts.BundleVersion
	}
	// Always bump the build number to a monotonic value so a re-signed app
	// installs as an UPDATE, never a downgrade (which makes iOS prompt
	// "Delete <app>?" instead of updating).
	raw["CFBundleVersion"] = fmt.Sprintf("%d", time.Now().Unix())

	// Apply MinimumOSVersion: explicit override takes priority,
	// otherwise auto-bump if current value is below 10.0
	if opts.MinOSVersion != "" {
		raw["MinimumOSVersion"] = opts.MinOSVersion
	} else {
		current, _ := raw["MinimumOSVersion"].(string)
		if shouldBumpMinOS(current) {
			raw["MinimumOSVersion"] = minAcceptableMinOS
		}
	}

	// Always remove UISupportedDevices — it restricts the app to listed device
	// models, and modern iPhones (iPhone 16+) are rarely in old apps' lists.
	// iOS rejects installation when device isn't listed.
	delete(raw, "UISupportedDevices")

	if opts.EnableDocs {
		raw["UIFileSharingEnabled"] = true
		raw["UISupportsDocumentBrowser"] = true
	}

	// Point CFBundleIcons at the loose PNGs we write so a replaced icon wins over
	// the one compiled into Assets.car.
	if opts.IconName != "" {
		primary := map[string]interface{}{
			"CFBundleIconFiles": []interface{}{opts.IconName},
			"CFBundleIconName":  opts.IconName,
		}
		raw["CFBundleIcons"] = map[string]interface{}{"CFBundlePrimaryIcon": primary}
		raw["CFBundleIcons~ipad"] = map[string]interface{}{"CFBundlePrimaryIcon": primary}
		delete(raw, "CFBundleIconName")
	}

	// Emit as XML plist. zsign with `-M <version>` also emits XML, and
	// that output installs fine on iOS 26 — so the format flip itself
	// is not the problem (earlier hypothesis incorrect).
	result, err := plist.MarshalIndent(raw, plist.XMLFormat, "\t")
	if err != nil {
		return nil, fmt.Errorf("marshal modified info.plist: %w", err)
	}

	return result, nil
}

// shouldBumpMinOS returns true if the current MinimumOSVersion is below 10.0.
func shouldBumpMinOS(current string) bool {
	if current == "" {
		return true
	}
	// Parse leading major version number
	parts := strings.SplitN(current, ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return true
	}
	return major < 10
}
