package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewVerifyCommand creates the "verify" subcommand.
func NewVerifyCommand() *cobra.Command {
	var inputPath string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the code signature of an IPA or binary",
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputPath == "" {
				return fmt.Errorf("--input is required")
			}
			fmt.Printf("[GoSigner] Verifying: %s\n", inputPath)
			// TODO: Implement signature verification
			fmt.Println("[GoSigner] Verification not yet implemented")
			return nil
		},
	}

	cmd.Flags().StringVarP(&inputPath, "input", "i", "", "Input IPA or Mach-O file")
	cmd.MarkFlagRequired("input")

	return cmd
}
