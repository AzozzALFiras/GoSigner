package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/AzozzALFiras/GoSigner/certificate/loader"
	"github.com/AzozzALFiras/GoSigner/cli/flags"
	"github.com/AzozzALFiras/GoSigner/ipa/archive"
	"github.com/AzozzALFiras/GoSigner/ipa/bundle"
	"github.com/AzozzALFiras/GoSigner/provision/parser"
)

// NewInfoCommand creates the "info" subcommand.
func NewInfoCommand() *cobra.Command {
	f := &flags.InfoFlags{}

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Display information about an IPA, certificate, or profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(f)
		},
	}

	flags.RegisterInfoFlags(cmd, f)
	return cmd
}

func runInfo(f *flags.InfoFlags) error {
	shown := false

	// Show IPA info
	if f.InputPath != "" {
		if err := showIPAInfo(f.InputPath); err != nil {
			return err
		}
		shown = true
	}

	// Show certificate info
	if f.CertPath != "" {
		if err := showCertInfo(f.CertPath); err != nil {
			return err
		}
		shown = true
	}

	// Show profile info
	if f.ProfilePath != "" {
		if err := showProfileInfo(f.ProfilePath); err != nil {
			return err
		}
		shown = true
	}

	if !shown {
		return fmt.Errorf("specify --input, --cert, or --profile")
	}

	return nil
}

func showIPAInfo(path string) error {
	ipaReader, err := archive.OpenIPA(path)
	if err != nil {
		return fmt.Errorf("open ipa: %w", err)
	}
	defer ipaReader.Close()

	appBundle, err := bundle.Discover(ipaReader.Files())
	if err != nil {
		return fmt.Errorf("discover bundle: %w", err)
	}

	fmt.Println("=== IPA Information ===")
	fmt.Printf("App Path:      %s\n", appBundle.AppPath)
	fmt.Printf("Bundle ID:     %s\n", appBundle.BundleID)
	fmt.Printf("Executable:    %s\n", appBundle.ExecutableName)
	fmt.Printf("Frameworks:    %d\n", len(appBundle.Frameworks))
	for _, fw := range appBundle.Frameworks {
		fmt.Printf("  - %s (%s)\n", fw.Path, fw.ExecutableName)
	}
	fmt.Printf("Plugins:       %d\n", len(appBundle.Plugins))
	for _, p := range appBundle.Plugins {
		fmt.Printf("  - %s (%s)\n", p.Path, p.BundleID)
	}
	fmt.Printf("Dylibs:        %d\n", len(appBundle.Dylibs))
	for _, d := range appBundle.Dylibs {
		fmt.Printf("  - %s\n", d)
	}
	fmt.Printf("Total files:   %d\n", len(ipaReader.Files()))
	fmt.Println()
	return nil
}

func showCertInfo(path string) error {
	identity, err := loader.LoadP12(path, "")
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	fmt.Println("=== Certificate Information ===")
	fmt.Printf("Common Name:   %s\n", identity.SubjectCN)
	fmt.Printf("Team ID:       %s\n", identity.TeamID)
	fmt.Printf("Not Before:    %s\n", identity.Certificate.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("Not After:     %s\n", identity.Certificate.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("Serial:        %s\n", identity.Certificate.SerialNumber.String())
	fmt.Printf("Expired:       %v\n", identity.IsExpired())
	fmt.Println()
	return nil
}

func showProfileInfo(path string) error {
	profile, err := parser.ParseFile(path)
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}

	fmt.Println("=== Provisioning Profile ===")
	fmt.Printf("Name:          %s\n", profile.Name)
	fmt.Printf("UUID:          %s\n", profile.UUID)
	fmt.Printf("Team:          %s (%s)\n", profile.TeamName, profile.GetTeamID())
	fmt.Printf("App ID:        %s\n", profile.GetAppID())
	fmt.Printf("Created:       %s\n", profile.CreationDate.Format("2006-01-02"))
	fmt.Printf("Expires:       %s\n", profile.ExpirationDate.Format("2006-01-02"))
	fmt.Printf("Expired:       %v\n", profile.IsExpired())
	fmt.Printf("All Devices:   %v\n", profile.ProvisionsAllDevices)
	fmt.Printf("Devices:       %d\n", len(profile.ProvisionedDevices))
	fmt.Printf("Certificates:  %d\n", len(profile.DeveloperCertificates))
	fmt.Printf("Platform:      %v\n", profile.Platform)

	// Show entitlements
	if len(profile.Entitlements) > 0 {
		fmt.Println("Entitlements:")
		for key, val := range profile.Entitlements {
			fmt.Printf("  %s: %v\n", key, val)
		}
	}

	fmt.Println()
	return nil
}
