package flags

import "github.com/spf13/cobra"

// SignFlags holds all flags for the sign command.
type SignFlags struct {
	CertPath        string
	CertPassword    string
	ProfilePath     string
	InputPath       string
	OutputPath      string
	BundleID        string
	BundleName      string
	BundleVersion   string
	EntitlementsPath string
	InjectDylibs    []string
	RemoveDylibs    []string
	WeakInject      bool
	Force           bool
	ZipLevel        int
	StripExtensions bool
	StripWatch      bool
	StripProfile    bool
	MinOSVersion    string
	EnableDocs      bool
	Adhoc           bool
}

// RegisterSignFlags adds all sign flags to a cobra command.
func RegisterSignFlags(cmd *cobra.Command, f *SignFlags) {
	cmd.Flags().StringVarP(&f.CertPath, "cert", "c", "", "Certificate file (.p12)")
	cmd.Flags().StringVarP(&f.CertPassword, "cert-password", "p", "", "Certificate password")
	cmd.Flags().StringVarP(&f.ProfilePath, "profile", "m", "", "Provisioning profile (.mobileprovision)")
	cmd.Flags().StringVarP(&f.InputPath, "input", "i", "", "Input IPA file (required)")
	cmd.Flags().StringVarP(&f.OutputPath, "output", "o", "", "Output IPA file (required)")
	cmd.Flags().StringVarP(&f.BundleID, "bundle-id", "b", "", "Override bundle identifier")
	cmd.Flags().StringVarP(&f.BundleName, "bundle-name", "n", "", "Override display name")
	cmd.Flags().StringVarP(&f.BundleVersion, "bundle-version", "r", "", "Override version")
	cmd.Flags().StringVarP(&f.EntitlementsPath, "entitlements", "e", "", "Custom entitlements file")
	cmd.Flags().StringSliceVarP(&f.InjectDylibs, "inject-dylib", "l", nil, "Inject dylib (repeatable)")
	cmd.Flags().StringSliceVarP(&f.RemoveDylibs, "remove-dylib", "D", nil, "Remove dylib (repeatable)")
	cmd.Flags().BoolVarP(&f.WeakInject, "weak", "w", false, "Use weak loading for injected dylibs")
	cmd.Flags().BoolVarP(&f.Force, "force", "f", false, "Force re-sign (skip cache)")
	cmd.Flags().IntVarP(&f.ZipLevel, "zip-level", "z", 6, "ZIP compression level (0-9)")
	cmd.Flags().BoolVarP(&f.StripExtensions, "strip-extensions", "E", false, "Remove app extensions")
	cmd.Flags().BoolVarP(&f.StripWatch, "strip-watch", "W", false, "Remove watch app")
	cmd.Flags().BoolVar(&f.StripProfile, "strip-profile", false, "Remove provisioning profile")
	cmd.Flags().StringVarP(&f.MinOSVersion, "min-version", "M", "", "Set minimum iOS version")
	cmd.Flags().BoolVarP(&f.EnableDocs, "enable-docs", "S", false, "Enable document browser")
	cmd.Flags().BoolVarP(&f.Adhoc, "adhoc", "a", false, "Ad-hoc signing (no certificate)")

	cmd.MarkFlagRequired("input")
	cmd.MarkFlagRequired("output")
}

// InfoFlags holds flags for the info command.
type InfoFlags struct {
	InputPath   string
	CertPath    string
	ProfilePath string
}

// RegisterInfoFlags adds info flags to a cobra command.
func RegisterInfoFlags(cmd *cobra.Command, f *InfoFlags) {
	cmd.Flags().StringVarP(&f.InputPath, "input", "i", "", "Input IPA file")
	cmd.Flags().StringVarP(&f.CertPath, "cert", "c", "", "Certificate file (.p12)")
	cmd.Flags().StringVarP(&f.ProfilePath, "profile", "m", "", "Provisioning profile")
}
