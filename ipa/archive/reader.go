package archive

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
)

// IPAReader provides streaming access to an IPA file without extracting everything to disk.
type IPAReader struct {
	file   *os.File
	reader *zip.Reader
	size   int64
}

// OpenIPA opens an IPA file for reading.
func OpenIPA(path string) (*IPAReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ipa: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat ipa: %w", err)
	}

	r, err := zip.NewReader(f, info.Size())
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("open zip reader: %w", err)
	}

	return &IPAReader{
		file:   f,
		reader: r,
		size:   info.Size(),
	}, nil
}

// Files returns all files in the IPA.
func (r *IPAReader) Files() []*zip.File {
	return r.reader.File
}

// ReadFile reads a specific file from the IPA by its path.
func (r *IPAReader) ReadFile(name string) ([]byte, error) {
	for _, f := range r.reader.File {
		if f.Name == name {
			return readZipFile(f)
		}
	}
	return nil, fmt.Errorf("file not found in ipa: %s", name)
}

// OpenFile opens a specific file in the IPA for streaming reads.
func (r *IPAReader) OpenFile(name string) (io.ReadCloser, error) {
	for _, f := range r.reader.File {
		if f.Name == name {
			return f.Open()
		}
	}
	return nil, fmt.Errorf("file not found in ipa: %s", name)
}

// Close closes the IPA reader.
func (r *IPAReader) Close() error {
	return r.file.Close()
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	return data, nil
}
