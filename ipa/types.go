package ipa

// AppBundle describes the structure of an iOS app found within an IPA.
type AppBundle struct {
	AppPath        string            // Relative path to .app dir (e.g., "Payload/MyApp.app")
	ExecutableName string            // Main executable name from Info.plist
	BundleID       string            // CFBundleIdentifier
	InfoPlistData  []byte            // Raw Info.plist bytes
	Frameworks     []BundleComponent // Frameworks/<name>.framework
	Plugins        []BundleComponent // PlugIns/<name>.appex
	WatchApps      []BundleComponent // Watch/<name>.app
	Dylibs         []string          // Loose .dylib file paths
}

// BundleComponent represents a nested bundle (framework, plugin, watch app).
type BundleComponent struct {
	Path           string // Relative path within the IPA
	ExecutableName string // Executable name from its Info.plist
	BundleID       string // Its own bundle identifier
	InfoPlistData  []byte // Its Info.plist data
	IsFramework    bool
}
