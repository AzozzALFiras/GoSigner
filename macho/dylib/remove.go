package dylib

import (
	"strings"

	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
	"github.com/AzozzALFiras/GoSigner/macho/parser"
)

// Remove removes LC_LOAD_DYLIB commands matching the given dylib names from a Mach-O slice.
// Returns the number of commands removed.
func Remove(slice *mtypes.MachOSlice, dylibNames []string) int {
	if len(dylibNames) == 0 {
		return 0
	}

	// Build lookup set
	removeSet := make(map[string]bool, len(dylibNames))
	for _, name := range dylibNames {
		removeSet[name] = true
	}

	removed := 0
	filtered := make([]mtypes.LoadCommand, 0, len(slice.LoadCmds))

	for _, lc := range slice.LoadCmds {
		if isDylibLoadCmd(lc.Cmd) {
			dylib, err := parser.ParseDylibCommand(&lc)
			if err == nil && shouldRemove(dylib.Name, removeSet) {
				slice.Header.NCmds--
				slice.Header.SizeOfCmds -= lc.CmdSize
				removed++
				continue
			}
		}
		filtered = append(filtered, lc)
	}

	slice.LoadCmds = filtered
	return removed
}

// List returns all dylib load paths from a Mach-O slice.
func List(slice *mtypes.MachOSlice) []string {
	var names []string
	for _, lc := range slice.LoadCmds {
		if isDylibLoadCmd(lc.Cmd) {
			dylib, err := parser.ParseDylibCommand(&lc)
			if err == nil {
				names = append(names, dylib.Name)
			}
		}
	}
	return names
}

func isDylibLoadCmd(cmd uint32) bool {
	switch cmd {
	case mtypes.LCLoadDylib, mtypes.LCLoadDylibWeak, mtypes.LCReexportDylib, mtypes.LCLoadUpwardDylib:
		return true
	}
	return false
}

func shouldRemove(name string, removeSet map[string]bool) bool {
	if removeSet[name] {
		return true
	}
	// Also check basename
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		basename := parts[len(parts)-1]
		if removeSet[basename] {
			return true
		}
	}
	return false
}
