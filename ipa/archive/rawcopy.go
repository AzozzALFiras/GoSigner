package archive

import (
	"archive/zip"
	"fmt"
	"io"
)

// CopyRaw copies a file from source IPA to destination IPA without decompressing.
// This is memory-efficient for large files that don't need modification.
func CopyRaw(dst *zip.Writer, src *zip.File) error {
	raw, err := src.OpenRaw()
	if err != nil {
		return fmt.Errorf("open raw %s: %w", src.Name, err)
	}

	header := src.FileHeader
	writer, err := dst.CreateRaw(&header)
	if err != nil {
		return fmt.Errorf("create raw %s: %w", src.Name, err)
	}

	if _, err := io.Copy(writer, raw); err != nil {
		return fmt.Errorf("copy raw %s: %w", src.Name, err)
	}

	return nil
}

// CopyFileDecompressed copies a file from source IPA, decompressing and recompressing it.
// Use this when you need to inspect or modify the data.
func CopyFileDecompressed(dst *IPAWriter, src *zip.File) error {
	rc, err := src.Open()
	if err != nil {
		return fmt.Errorf("open %s: %w", src.Name, err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("read %s: %w", src.Name, err)
	}

	return dst.AddFile(src.Name, data)
}
