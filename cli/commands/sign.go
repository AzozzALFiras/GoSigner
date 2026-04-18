package commands

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/AzozzALFiras/GoSigner/certificate/loader"
	"github.com/AzozzALFiras/GoSigner/cli/flags"
	"github.com/AzozzALFiras/GoSigner/ipa/pipeline"
	"github.com/AzozzALFiras/GoSigner/provision/entitlements"
	"github.com/AzozzALFiras/GoSigner/provision/parser"
)

// NewSignCommand creates the "sign" subcommand.
func NewSignCommand() *cobra.Command {
	f := &flags.SignFlags{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign an iOS IPA file",
		Long:  "Re-sign an iOS IPA file with a new certificate and provisioning profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign(f)
		},
	}

	flags.RegisterSignFlags(cmd, f)
	return cmd
}

func runSign(f *flags.SignFlags) error {
	// Validate input file exists
	if _, err := os.Stat(f.InputPath); os.IsNotExist(err) {
		return fmt.Errorf("input file not found: %s", f.InputPath)
	}

	opts := &pipeline.ResignOptions{
		InputPath:       f.InputPath,
		OutputPath:      f.OutputPath,
		BundleID:        f.BundleID,
		BundleName:      f.BundleName,
		BundleVersion:   f.BundleVersion,
		InjectDylibs:    f.InjectDylibs,
		RemoveDylibs:    f.RemoveDylibs,
		WeakInject:      f.WeakInject,
		ForceSign:       f.Force,
		ZipLevel:        f.ZipLevel,
		StripExtensions: f.StripExtensions,
		StripWatch:      f.StripWatch,
		StripProfile:    f.StripProfile,
		MinOSVersion:    f.MinOSVersion,
		EnableDocs:      f.EnableDocs,
		IsAdhoc:         f.Adhoc,
	}

	// Load certificate (unless ad-hoc)
	if !f.Adhoc {
		if f.CertPath == "" {
			return fmt.Errorf("--cert is required (use --adhoc for ad-hoc signing)")
		}
		identity, err := loader.LoadP12(f.CertPath, f.CertPassword)
		if err != nil {
			return fmt.Errorf("load certificate: %w", err)
		}
		log.Printf("[GoSigner] Certificate: %s", identity.String())

		if identity.IsExpired() {
			log.Printf("[GoSigner] WARNING: Certificate has expired!")
		}

		opts.Identity = identity
	}

	// Load provisioning profile
	if f.ProfilePath != "" {
		profile, err := parser.ParseFile(f.ProfilePath)
		if err != nil {
			return fmt.Errorf("load profile: %w", err)
		}
		log.Printf("[GoSigner] Profile: %s (Team: %s, Expires: %s)",
			profile.Name, profile.GetTeamID(), profile.ExpirationDate.Format("2006-01-02"))

		if profile.IsExpired() {
			log.Printf("[GoSigner] WARNING: Provisioning profile has expired!")
		}

		opts.Profile = profile

		// Extract entitlements from profile if no custom entitlements provided
		if f.EntitlementsPath == "" {
			xmlEnts, err := entitlements.Extract(profile)
			if err == nil {
				opts.EntitlementsXML = xmlEnts
			}
		}
	}

	// Load custom entitlements
	if f.EntitlementsPath != "" {
		data, err := os.ReadFile(f.EntitlementsPath)
		if err != nil {
			return fmt.Errorf("read entitlements: %w", err)
		}
		opts.EntitlementsXML = data
	}

	return pipeline.Resign(opts)
}
