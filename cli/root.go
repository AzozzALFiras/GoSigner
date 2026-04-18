package cli

import (
	"github.com/spf13/cobra"

	"github.com/AzozzALFiras/GoSigner/cli/commands"
)

// NewRootCommand creates the root GoSigner command.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "gosigner",
		Short: "GoSigner - iOS IPA Code Signing Tool",
		Long: `GoSigner is a fast, cross-platform iOS code signing tool written in Go.
It can re-sign IPA files with new certificates and provisioning profiles,
inject/remove dylibs, and modify app bundle properties.

https://github.com/AzozzALFiras/GoSigner`,
	}

	// Register subcommands
	root.AddCommand(commands.NewSignCommand())
	root.AddCommand(commands.NewInfoCommand())
	root.AddCommand(commands.NewVerifyCommand())
	root.AddCommand(commands.NewVersionCommand())

	return root
}
