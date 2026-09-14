package coderesources

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	plTypes "github.com/AzozzALFiras/GoSigner/plist"
	"howett.net/plist"
)

// Generate creates the _CodeSignature/CodeResources plist for an app bundle.
// appPath is the path to the .app (or .appex/.framework) directory.
// mainExecutable is the bundle's primary executable name (e.g. "Jikir_count")
// and is excluded from the resource envelope — it's covered by its own
// embedded Mach-O code signature, not by CodeResources.
func Generate(appPath, mainExecutable string) ([]byte, error) {
	return GenerateWith(appPath, mainExecutable, nil)
}

// HashLookup returns hashes already known for a file, or nil to have the file
// read and hashed. It lets the pipeline seal resources it hashed while
// streaming them out of the archive, without ever writing their bytes to disk.
type HashLookup func(absPath string, info os.FileInfo) *FileHashes

// GenerateWith is Generate with a source of precomputed hashes.
func GenerateWith(appPath, mainExecutable string, lookup HashLookup) ([]byte, error) {
	files1 := make(map[string]interface{})
	files2 := make(map[string]interface{})
	rules := DefaultRulesV1()
	rules2 := DefaultRulesV2()

	err := filepath.Walk(appPath, func(absPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relPath, err := filepath.Rel(appPath, absPath)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}
		relPath = filepath.ToSlash(relPath)

		if info.IsDir() {
			if relPath == "_CodeSignature" {
				return filepath.SkipDir
			}
			return nil
		}

		if IsFileExcluded(relPath, mainExecutable) {
			return nil
		}
		if strings.HasPrefix(relPath, "_CodeSignature/") {
			return nil
		}

		var hashes *FileHashes
		if lookup != nil {
			hashes = lookup(absPath, info)
		}
		if hashes == nil {
			hashes, err = HashFile(absPath)
			if err != nil {
				return fmt.Errorf("hash %s: %w", relPath, err)
			}
		}

		// Match rules1 and rules2 INDEPENDENTLY. This is the same
		// behavior Apple's codesign and zsign/esign use: a file like
		// Info.plist is omitted from files2 (via rules2's `^Info\.plist$: omit`)
		// but still included in files1 (v1) because rules1's `^.*` catches it.
		// Matching both lists with rules2 (what we did before) produces an
		// empty files1 for frameworks — iOS 26 rejects on the resulting
		// mismatch between the CD's -3 slot and the on-disk bundle.
		omit1, optional1 := matchRulesV1(relPath, rules)
		if !omit1 {
			files1[relPath] = hashes.SHA1
			_ = optional1 // files1 v1 dict only stores the raw hash
		}

		omit2, optional2 := matchRulesV2(relPath, rules2)
		if !omit2 {
			entry := map[string]interface{}{
				"hash":  hashes.SHA1,
				"hash2": hashes.SHA256,
			}
			if optional2 {
				entry["optional"] = true
			}
			files2[relPath] = entry
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk app bundle: %w", err)
	}

	// Build the CodeResources plist
	codeResources := map[string]interface{}{
		"files":  files1,
		"files2": files2,
		"rules":  rules,
		"rules2": convertRules2ForPlist(rules2),
	}

	data, err := plist.MarshalIndent(codeResources, plist.XMLFormat, "\t")
	if err != nil {
		return nil, fmt.Errorf("marshal code resources: %w", err)
	}

	return data, nil
}

// matchRulesV1 picks the highest-weight rule matching relPath from the
// v1 rules dict. Values may be either a bare `true` (weight 1, no flags)
// or a map with optional `omit`, `optional`, `weight` keys — same shape
// as rules2 but in untyped form.
func matchRulesV1(relPath string, rules map[string]interface{}) (omit bool, optional bool) {
	bestWeight := -1
	for pattern, raw := range rules {
		matched, err := regexp.MatchString(pattern, relPath)
		if err != nil || !matched {
			continue
		}
		rOmit, rOpt, weight := false, false, 1
		if m, ok := raw.(map[string]interface{}); ok {
			if v, ok := m["omit"].(bool); ok {
				rOmit = v
			}
			if v, ok := m["optional"].(bool); ok {
				rOpt = v
			}
			if v, ok := m["weight"].(float64); ok {
				weight = int(v)
			}
		}
		if weight > bestWeight {
			bestWeight = weight
			omit = rOmit
			optional = rOpt
		}
	}
	return omit, optional
}

func matchRulesV2(relPath string, rules map[string]plTypes.CodeResourcesRuleV2) (omit bool, optional bool) {
	bestWeight := -1

	for pattern, rule := range rules {
		matched, err := regexp.MatchString(pattern, relPath)
		if err != nil || !matched {
			continue
		}
		weight := rule.Weight
		if weight == 0 {
			weight = 1
		}
		if weight > bestWeight {
			bestWeight = weight
			omit = rule.Omit
			optional = rule.Optional
		}
	}

	return omit, optional
}

// convertRules2ForPlist emits each rule in the exact shape Apple's
// codesign tool produces: the catch-all `^.*` (weight 1, no flags) is
// encoded as the bare boolean `<true/>`; the default-weight rules omit
// the `weight` key; everything else is a dict of its flags + weight.
func convertRules2ForPlist(rules map[string]plTypes.CodeResourcesRuleV2) map[string]interface{} {
	result := make(map[string]interface{})
	for pattern, rule := range rules {
		// Plain-true shorthand only for the default "include everything"
		// catch-all, where weight == 1 and no flags are set.
		if rule.Weight == 1 && !rule.Omit && !rule.Optional && !rule.Nested {
			result[pattern] = true
			continue
		}
		entry := make(map[string]interface{})
		if rule.Omit {
			entry["omit"] = true
		}
		if rule.Optional {
			entry["optional"] = true
		}
		if rule.Nested {
			entry["nested"] = true
		}
		if rule.Weight > 0 && rule.Weight != 1 {
			entry["weight"] = float64(rule.Weight)
		}
		result[pattern] = entry
	}
	return result
}
