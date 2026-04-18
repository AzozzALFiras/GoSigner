package bundle

import (
	"archive/zip"
	"strings"
)

// FilesForComponent returns all zip entries that belong to a given component path.
func FilesForComponent(files []*zip.File, componentPath string) []*zip.File {
	prefix := componentPath + "/"
	var result []*zip.File
	for _, f := range files {
		if strings.HasPrefix(f.Name, prefix) || f.Name == componentPath {
			result = append(result, f)
		}
	}
	return result
}

// IsExecutable checks if a zip file entry is likely an executable Mach-O binary.
func IsExecutable(f *zip.File) bool {
	mode := f.Mode()
	return mode&0111 != 0 && !f.FileInfo().IsDir()
}

// IsMachOFile checks if a file name suggests it's a Mach-O binary (no extension).
func IsMachOFile(name string) bool {
	base := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		base = name[idx+1:]
	}
	// No extension typically means it's a binary
	return !strings.Contains(base, ".") && base != ""
}
