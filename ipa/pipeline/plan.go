package pipeline

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AzozzALFiras/GoSigner/ipa/archive"
)

// PlanResult is what plan mode returns instead of a signed file: where the
// plan is, how long the archive it describes will be, and the working
// directory holding the files it points at — which the caller owns and must
// delete once the install is done.
type PlanResult struct {
	Path    string
	WorkDir string
	Length  int64
}

// buildPlan describes the archive repackageIPA would have written.
//
// The two walks agree by construction: same order, same entries, same decision
// about what can be copied verbatim from the source. Only the destination
// differs — a description here, a file there.
func buildPlan(sourceDir, sourcePath string, src *archive.IPAReader, lay *layout) (*archive.Plan, error) {
	srcEntries := map[string]*zip.File{}
	if src != nil {
		for _, f := range src.Files() {
			srcEntries[f.Name] = f
		}
	}

	var entries []archive.PlanEntry
	err := filepath.Walk(sourceDir, func(absPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(sourceDir, absPath)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}
		relPath = strings.ReplaceAll(relPath, string(filepath.Separator), "/")

		if info.IsDir() {
			entries = append(entries, archive.PlanEntry{
				Name:     relPath + "/",
				Method:   zip.Store,
				Modified: info.ModTime().Unix(),
				Dir:      true,
			})
			return nil
		}

		// A placeholder nothing replaced, and anything the signing left
		// byte-identical: the source archive already holds those bytes.
		if lay != nil {
			if p, ok := lay.untouched(absPath, info); ok {
				return appendRaw(&entries, p.entry)
			}
		}
		if orig, ok := srcEntries[relPath]; ok && orig.UncompressedSize64 == uint64(info.Size()) {
			if sum, cerr := crc32OfFile(absPath); cerr == nil && sum == orig.CRC32 {
				return appendRaw(&entries, orig)
			}
		}

		// Modified or new: signing produced this file, and it is stored
		// uncompressed — the same as the file writer does at zip level 0.
		crc, err := crc32OfFile(absPath)
		if err != nil {
			return err
		}
		entries = append(entries, archive.PlanEntry{
			Name:         relPath,
			Method:       zip.Store,
			CRC32:        crc,
			Compressed:   uint64(info.Size()),
			Uncompressed: uint64(info.Size()),
			Modified:     time.Now().Unix(),
			File:         absPath,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return archive.NewPlan(sourcePath, entries)
}

func appendRaw(entries *[]archive.PlanEntry, f *zip.File) error {
	at, err := f.DataOffset()
	if err != nil {
		return err
	}
	*entries = append(*entries, archive.PlanEntry{
		Name:         f.Name,
		Method:       f.Method,
		CRC32:        f.CRC32,
		Compressed:   f.CompressedSize64,
		Uncompressed: f.UncompressedSize64,
		Modified:     f.Modified.Unix(),
		SourceOffset: at,
	})
	return nil
}
