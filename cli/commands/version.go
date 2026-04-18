package commands

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Build-time metadata — overridden via -ldflags "-X ..." in the Makefile.
var (
	Version   = "dev"     // semantic version, e.g. "1.0.0"
	Commit    = "unknown" // git short SHA
	BuildDate = "unknown" // RFC3339 build timestamp
)

// NewVersionCommand creates the "version" subcommand.
func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print GoSigner version and build info",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("GoSigner %s\n", Version)
			fmt.Printf("  commit:    %s\n", Commit)
			fmt.Printf("  built:     %s\n", BuildDate)
			fmt.Printf("  go:        %s\n", runtime.Version())
			fmt.Printf("  platform:  %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}
