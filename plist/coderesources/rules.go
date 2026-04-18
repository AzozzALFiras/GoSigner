package coderesources

import plTypes "github.com/AzozzALFiras/GoSigner/plist"

// DefaultRulesV1 returns Apple's legacy signing rules (v1) — matches what
// esign V5.0.2 and zsign v1.0.2 emit byte-for-byte.
func DefaultRulesV1() map[string]interface{} {
	return map[string]interface{}{
		"^.*":                           true,
		"^.*\\.lproj/":                  map[string]interface{}{"optional": true, "weight": float64(1000)},
		"^.*\\.lproj/locversion.plist$": map[string]interface{}{"omit": true, "weight": float64(1100)},
		"^Base\\.lproj/":                map[string]interface{}{"weight": float64(1010)},
		"^version.plist$":               true,
	}
}

// DefaultRulesV2 returns Apple's modern signing rules (v2) — matches what
// esign and zsign emit. iOS 26's codesign evaluator compares the on-disk
// bundle layout against these rules, so they must match the canonical
// set exactly or validation of CodeResources will mismatch.
func DefaultRulesV2() map[string]plTypes.CodeResourcesRuleV2 {
	return map[string]plTypes.CodeResourcesRuleV2{
		".*\\.dSYM($|/)":                {Weight: 11},
		"^(.*/)?\\.DS_Store$":           {Omit: true, Weight: 2000},
		"^.*":                           {Weight: 1},
		"^.*\\.lproj/":                  {Optional: true, Weight: 1000},
		"^.*\\.lproj/locversion.plist$": {Omit: true, Weight: 1100},
		"^Base\\.lproj/":                {Weight: 1010},
		"^Info\\.plist$":                {Omit: true, Weight: 20},
		"^PkgInfo$":                     {Omit: true, Weight: 20},
		"^embedded\\.provisionprofile$": {Weight: 20},
		"^version\\.plist$":             {Weight: 20},
	}
}

// IsFileExcluded returns true for bundle paths that must never appear in
// the CodeResources files/files2 dictionaries. The main executable is
// covered by its own embedded code signature in __LINKEDIT, not by the
// bundle resource envelope — listing it here causes iOS to hash it twice
// with different semantics and the CodeResources hash fails verification.
func IsFileExcluded(relPath, mainExecutable string) bool {
	if relPath == mainExecutable {
		return true
	}
	excluded := []string{
		"_CodeSignature/CodeResources",
		"CodeResources",
	}
	for _, e := range excluded {
		if relPath == e {
			return true
		}
	}
	return false
}
