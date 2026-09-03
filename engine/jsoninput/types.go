package jsoninput

// Request is the top-level JSON input for gosigner --data='...'
type Request struct {
	Apps []AppRequest `json:"apps"`
}

// AppRequest describes a single IPA to sign.
type AppRequest struct {
	// Required
	IPA  string `json:"ipa"`  // Full local path OR full URL (auto-downloads with retry)
	Cert string `json:"cert"` // Full path to .p12 certificate

	// Signing
	CertPassword  string `json:"cert_password"`  // Certificate password (empty if none)
	Profile       string `json:"profile"`         // Full path to .mobileprovision
	RemoveProfile bool   `json:"remove_profile"`  // Strip profile after signing

	// App modification
	Name     string `json:"name"`      // Override display name (empty = keep original)
	BundleID string `json:"bundle_id"` // Override bundle ID (empty = keep original)

	// Dylibs — each entry can have a .dylib AND an optional .bundle
	Dylibs []DylibEntry `json:"dylibs"`

	// Output paths
	Output      string `json:"output"`       // Output directory for signed IPA
	PlistOutput string `json:"plist_output"` // Output directory for install plist (separate from IPA)

	// CDN URL prefixes — GoSigner appends the random filename automatically
	IPABaseURL   string `json:"ipa_base_url"`   // e.g. "https://cdn.neon1.io/signature/ipa/"
	PlistBaseURL string `json:"plist_base_url"` // e.g. "https://cdn.neon1.io/signature/plist/"

	// Install plist generation
	URLIcon     string `json:"url_icon"`    // Public URL to the app icon
	CreatePlist bool   `json:"create_plist"` // Generate OTA install .plist

	// In-memory signing material (base64) + encrypted bundle. Populated by the FFI
	// layer; the plaintext cert/profile never touch disk.
	CertData    string `json:"cert_data"`
	ProfileData string `json:"profile_data"`
	Enc    string `json:"enc"`
	Udid   string `json:"udid"`
	CertID string `json:"cert_id"`

	// Edit-page options.
	BundleVersion   string     `json:"bundle_version"`
	MinOS           string     `json:"min_os"`
	StripExtensions bool       `json:"strip_extensions"`
	StripWatch      bool       `json:"strip_watch"`
	WeakInject      bool       `json:"weak_inject"`
	DeleteAssetsCar bool       `json:"delete_assets_car"`
	RemoveDylibs    []string   `json:"remove_dylibs"`
	IconName        string     `json:"icon_name"`
	IconFiles       []IconFile `json:"icon_files"`
	WorkDir         string     `json:"work_dir"`
}

// DylibEntry describes a dylib to inject, optionally with its .bundle resources.
type IconFile struct {
	Name string `json:"name"` // loose file written into the .app, e.g. AppIcon60x60@2x.png
	Data string `json:"data"` // base64 PNG bytes
}

type DylibEntry struct {
	FullDylib  string `json:"full_dylib"`  // Full path to the .dylib file
	FullBundle string `json:"full_bundle"` // Full path to .bundle directory (null/empty = none)
}

// Response is the JSON output returned by gosigner.
type Response struct {
	Success bool        `json:"success"`
	Results []AppResult `json:"results"`
	Errors  []string    `json:"errors,omitempty"`
}

// AppResult describes the outcome of signing a single app.
type AppResult struct {
	Success     bool   `json:"success"`
	IPA         string `json:"ipa"`                    // Original IPA path/URL
	OutputIPA   string `json:"output_ipa"`              // Final signed IPA full path
	OutputPlist string `json:"output_plist,omitempty"`   // Install plist full path
	PlistURL    string `json:"plist_url,omitempty"`      // Public plist URL for itms-services://
	Name        string `json:"name"`                    // Final app name
	BundleID    string `json:"bundle_id"`               // Final bundle ID
	Duration    string `json:"duration"`                // Time taken (e.g. "4.2s")
	Error       string `json:"error,omitempty"`          // Error message if failed
}
