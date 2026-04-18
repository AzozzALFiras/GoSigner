package bundle

import (
	"archive/zip"
	"path"
	"strings"

	ipaTypes "github.com/AzozzALFiras/GoSigner/ipa"
	"github.com/AzozzALFiras/GoSigner/plist/infoplist"
)

// Discover analyzes an IPA's zip entries to find the main app bundle and all components.
func Discover(files []*zip.File) (*ipaTypes.AppBundle, error) {
	// Find the main .app directory
	appPath := findAppPath(files)
	if appPath == "" {
		return nil, &DiscoverError{"no .app directory found in Payload/"}
	}

	bundle := &ipaTypes.AppBundle{
		AppPath: appPath,
	}

	// Read and parse the main Info.plist
	infoPlistPath := appPath + "/Info.plist"
	for _, f := range files {
		if f.Name == infoPlistPath {
			data, err := readZipEntry(f)
			if err != nil {
				return nil, &DiscoverError{"read Info.plist: " + err.Error()}
			}
			bundle.InfoPlistData = data

			info, err := infoplist.ReadFromBytes(data)
			if err != nil {
				return nil, &DiscoverError{"parse Info.plist: " + err.Error()}
			}
			bundle.ExecutableName = info.BundleExecutable
			bundle.BundleID = info.BundleID
			break
		}
	}

	if bundle.ExecutableName == "" {
		return nil, &DiscoverError{"CFBundleExecutable not found in Info.plist"}
	}

	// Discover frameworks, plugins, watch apps, and dylibs
	frameworkPrefix := appPath + "/Frameworks/"
	pluginPrefix := appPath + "/PlugIns/"
	watchPrefix := appPath + "/Watch/"

	discoveredFrameworks := make(map[string]bool)
	discoveredPlugins := make(map[string]bool)
	discoveredWatch := make(map[string]bool)

	for _, f := range files {
		name := f.Name

		// Discover frameworks
		if strings.HasPrefix(name, frameworkPrefix) {
			rest := name[len(frameworkPrefix):]
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) >= 1 && strings.HasSuffix(parts[0], ".framework") {
				fwPath := frameworkPrefix + parts[0]
				if !discoveredFrameworks[fwPath] {
					discoveredFrameworks[fwPath] = true
					comp := discoverComponent(files, fwPath, true)
					bundle.Frameworks = append(bundle.Frameworks, comp)
				}
			}

			// Check for loose dylibs in Frameworks/
			if strings.HasSuffix(name, ".dylib") && !strings.Contains(rest, "/") {
				bundle.Dylibs = append(bundle.Dylibs, name)
			}
		}

		// Discover plugins
		if strings.HasPrefix(name, pluginPrefix) {
			rest := name[len(pluginPrefix):]
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) >= 1 && strings.HasSuffix(parts[0], ".appex") {
				plugPath := pluginPrefix + parts[0]
				if !discoveredPlugins[plugPath] {
					discoveredPlugins[plugPath] = true
					comp := discoverComponent(files, plugPath, false)
					bundle.Plugins = append(bundle.Plugins, comp)
				}
			}
		}

		// Discover watch apps
		if strings.HasPrefix(name, watchPrefix) {
			rest := name[len(watchPrefix):]
			parts := strings.SplitN(rest, "/", 2)
			if len(parts) >= 1 && strings.HasSuffix(parts[0], ".app") {
				watchPath := watchPrefix + parts[0]
				if !discoveredWatch[watchPath] {
					discoveredWatch[watchPath] = true
					comp := discoverComponent(files, watchPath, false)
					bundle.WatchApps = append(bundle.WatchApps, comp)
				}
			}
		}
	}

	return bundle, nil
}

func findAppPath(files []*zip.File) string {
	for _, f := range files {
		if strings.HasPrefix(f.Name, "Payload/") {
			parts := strings.SplitN(f.Name[len("Payload/"):], "/", 2)
			if len(parts) >= 1 && strings.HasSuffix(parts[0], ".app") {
				return "Payload/" + parts[0]
			}
		}
	}
	return ""
}

func discoverComponent(files []*zip.File, basePath string, isFramework bool) ipaTypes.BundleComponent {
	comp := ipaTypes.BundleComponent{
		Path:        basePath,
		IsFramework: isFramework,
	}

	// Look for Info.plist
	infoPlistPath := basePath + "/Info.plist"
	for _, f := range files {
		if f.Name == infoPlistPath {
			data, err := readZipEntry(f)
			if err == nil {
				comp.InfoPlistData = data
				info, err := infoplist.ReadFromBytes(data)
				if err == nil {
					comp.ExecutableName = info.BundleExecutable
					comp.BundleID = info.BundleID
				}
			}
			break
		}
	}

	// If no executable from Info.plist, use the directory name
	if comp.ExecutableName == "" {
		dirName := path.Base(basePath)
		// Strip extension
		if idx := strings.LastIndex(dirName, "."); idx > 0 {
			comp.ExecutableName = dirName[:idx]
		}
	}

	return comp
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var data []byte
	buf := make([]byte, 32*1024)
	for {
		n, err := rc.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return data, nil
}

// DiscoverError represents an error during app bundle discovery.
type DiscoverError struct {
	Detail string
}

func (e *DiscoverError) Error() string {
	return "discover app bundle: " + e.Detail
}
