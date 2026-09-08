package archive

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"time"
)

// IPAWriter writes a new IPA file with streaming compression.
type IPAWriter struct {
	file   *os.File
	writer *zip.Writer
	level  int // Compression level (0 = store, 1-9 = deflate)
}

// CreateIPA creates a new IPA file for writing.
func CreateIPA(path string, compressionLevel int) (*IPAWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create ipa: %w", err)
	}

	w := zip.NewWriter(f)

	return &IPAWriter{
		file:   f,
		writer: w,
		level:  compressionLevel,
	}, nil
}

// AddFile adds a new file to the IPA with the given data. We set Unix
// mode 0755 on every entry because iOS's IPA installer honors ZIP
// external_attr literally when it is set — writing 0644 stripped the
// execute bit from frameworks / dylibs / main binaries, which then
// failed to load at install time with the silent "integrity could not
// be verified" error. zsign emits external_attr == 0 (letting the
// installer apply defaults) and esign emits 0755; both install fine.
// We mirror esign: explicit 0755 for everything, identical for
// executables and resources alike — iOS doesn't care about the exec
// bit on non-binary resources.
func (w *IPAWriter) AddFile(name string, data []byte) error {
	header := &zip.FileHeader{
		Name:     name,
		Method:   w.compressionMethod(),
		Modified: time.Now(),
	}
	header.SetMode(0755)

	writer, err := w.writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip entry %s: %w", name, err)
	}

	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write zip entry %s: %w", name, err)
	}

	return nil
}

// AddFileFromReader adds a file to the IPA by streaming from a reader.
func (w *IPAWriter) AddFileFromReader(name string, r io.Reader, size int64) error {
	header := &zip.FileHeader{
		Name:     name,
		Method:   w.compressionMethod(),
		Modified: time.Now(),
	}
	header.SetMode(0755)

	writer, err := w.writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip entry %s: %w", name, err)
	}

	if _, err := io.Copy(writer, r); err != nil {
		return fmt.Errorf("write zip entry %s: %w", name, err)
	}

	return nil
}

// AddRaw copies an entry from a source zip verbatim — its already-compressed
// bytes are streamed straight through, with no decompress/recompress. Used for
// entries the signing pipeline did not modify, which keeps their original
// compression (a Store-only rewrite can inflate a compressed IPA substantially)
// and skips the CPU entirely. The mode is still forced to 0755 for the same
// reason AddFile does it: iOS honors external_attr literally.
func (w *IPAWriter) AddRaw(f *zip.File) error {
	header := &zip.FileHeader{
		Name:               f.Name,
		Method:             f.Method,
		Modified:           f.Modified,
		CRC32:              f.CRC32,
		CompressedSize64:   f.CompressedSize64,
		UncompressedSize64: f.UncompressedSize64,
	}
	header.SetMode(0755)

	dst, err := w.writer.CreateRaw(header)
	if err != nil {
		return fmt.Errorf("create raw zip entry %s: %w", f.Name, err)
	}
	src, err := f.OpenRaw()
	if err != nil {
		return fmt.Errorf("open raw zip entry %s: %w", f.Name, err)
	}
	buf := make([]byte, 64*1024)
	if _, err := io.CopyBuffer(dst, src, buf); err != nil {
		return fmt.Errorf("copy raw zip entry %s: %w", f.Name, err)
	}
	return nil
}

// AddExecutable adds an executable file with proper permissions.
func (w *IPAWriter) AddExecutable(name string, data []byte) error {
	header := &zip.FileHeader{
		Name:     name,
		Method:   w.compressionMethod(),
		Modified: time.Now(),
	}
	header.SetMode(0755)

	writer, err := w.writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip entry %s: %w", name, err)
	}

	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write zip entry %s: %w", name, err)
	}

	return nil
}

// AddDirectory adds a directory entry to the IPA.
func (w *IPAWriter) AddDirectory(name string) error {
	if name[len(name)-1] != '/' {
		name += "/"
	}
	header := &zip.FileHeader{
		Name:     name,
		Modified: time.Now(),
	}
	header.SetMode(0755 | os.ModeDir)

	_, err := w.writer.CreateHeader(header)
	return err
}

// Close finalizes the IPA file.
func (w *IPAWriter) Close() error {
	if err := w.writer.Close(); err != nil {
		w.file.Close()
		return fmt.Errorf("close zip writer: %w", err)
	}
	return w.file.Close()
}

func (w *IPAWriter) compressionMethod() uint16 {
	if w.level == 0 {
		return zip.Store
	}
	return zip.Deflate
}
