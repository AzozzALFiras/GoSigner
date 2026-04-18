package installplist

import (
	"fmt"
	"os"
	"path/filepath"

	"howett.net/plist"
)

// Options for generating an OTA install manifest plist.
type Options struct {
	IPAURL    string // Full public download URL for the signed IPA
	IconURL   string // Public URL for the app icon
	BundleID  string // App bundle identifier
	AppName   string // App display name
	Version   string // App version
	PlistName string // Filename for the plist (without path) — e.g. "abc123.plist"
}

// Generate creates an OTA install manifest plist and writes it to disk.
func Generate(opts *Options, outputDir string) (string, error) {
	manifest := buildManifest(opts)

	data, err := plist.MarshalIndent(manifest, plist.XMLFormat, "\t")
	if err != nil {
		return "", fmt.Errorf("marshal install plist: %w", err)
	}

	os.MkdirAll(outputDir, 0755)
	plistPath := filepath.Join(outputDir, opts.PlistName)

	if err := os.WriteFile(plistPath, data, 0644); err != nil {
		return "", fmt.Errorf("write install plist: %w", err)
	}

	return plistPath, nil
}

func buildManifest(opts *Options) map[string]interface{} {
	assets := []interface{}{
		map[string]interface{}{
			"kind": "software-package",
			"url":  opts.IPAURL,
		},
	}

	if opts.IconURL != "" {
		assets = append(assets, map[string]interface{}{
			"kind":        "display-image",
			"needs-shine": true,
			"url":         opts.IconURL,
		})
		assets = append(assets, map[string]interface{}{
			"kind":        "full-size-image",
			"needs-shine": true,
			"url":         opts.IconURL,
		})
	}

	metadata := map[string]interface{}{
		"bundle-identifier": opts.BundleID,
		"bundle-version":    opts.Version,
		"kind":              "software",
		"title":             opts.AppName,
	}

	return map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{
				"assets":   assets,
				"metadata": metadata,
			},
		},
	}
}
