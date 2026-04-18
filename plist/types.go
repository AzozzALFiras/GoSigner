package plist

// InfoPlistData holds parsed Info.plist fields relevant to code signing.
type InfoPlistData struct {
	BundleID          string `plist:"CFBundleIdentifier"`
	BundleName        string `plist:"CFBundleName"`
	BundleDisplayName string `plist:"CFBundleDisplayName"`
	BundleExecutable  string `plist:"CFBundleExecutable"`
	BundleVersion     string `plist:"CFBundleVersion"`
	ShortVersion      string `plist:"CFBundleShortVersionString"`
	MinimumOSVersion  string `plist:"MinimumOSVersion"`
}

// CodeResourcesRuleV2 represents a single rule in the CodeResources rules2 dictionary.
type CodeResourcesRuleV2 struct {
	Omit     bool `plist:"omit,omitempty"`
	Optional bool `plist:"optional,omitempty"`
	Weight   int  `plist:"weight,omitempty"`
	Nested   bool `plist:"nested,omitempty"`
}
