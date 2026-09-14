package pipeline

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	ipaTypes "github.com/AzozzALFiras/GoSigner/ipa"
	"github.com/AzozzALFiras/GoSigner/plist/coderesources"
)

// Entries at or below this size are always written out for real. Everything
// the pipeline reads or rewrites that is not a Mach-O — plists, profiles,
// CodeResources, symlinks — is far smaller, so the threshold keeps them safe
// without having to enumerate them.
const smallEntryBytes = 1 << 20

// placeholderTime is stamped on every placeholder. Anything the pipeline writes
// gets the current time, so a placeholder that still carries this mtime has
// provably not been touched since it was laid out.
var placeholderTime = time.Unix(315532800, 0) // 1980-01-01, the zip epoch

// placeholder is a large resource that was hashed while streaming out of the
// archive instead of being written to disk. On disk it is a sparse file of the
// right size, so a directory walk, a remove, or a size check all behave as if
// the file were there; its bytes are only ever taken from the source archive.
type placeholder struct {
	entry  *zip.File
	hashes *coderesources.FileHashes
}

// layout is the on-disk bundle plus the table of placeholders in it.
type layout struct {
	mu           sync.Mutex
	placeholders map[string]placeholder // absolute path -> placeholder
	written      int64                  // bytes actually written to disk
}

// lookup serves precomputed hashes for untouched placeholders.
func (l *layout) lookup(absPath string, info os.FileInfo) *coderesources.FileHashes {
	p, ok := l.untouched(absPath, info)
	if !ok {
		return nil
	}
	return p.hashes
}

// untouched reports the placeholder at absPath if nothing has replaced it.
func (l *layout) untouched(absPath string, info os.FileInfo) (placeholder, bool) {
	l.mu.Lock()
	p, ok := l.placeholders[absPath]
	l.mu.Unlock()
	if !ok || !info.Mode().IsRegular() {
		return placeholder{}, false
	}
	if uint64(info.Size()) != p.entry.UncompressedSize64 || !info.ModTime().Equal(placeholderTime) {
		return placeholder{}, false
	}
	return p, true
}

var machoMagics = [][]byte{
	{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe}, // 32-bit
	{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe}, // 64-bit
	{0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca}, // fat
	{0xca, 0xfe, 0xba, 0xbf}, {0xbf, 0xba, 0xfe, 0xca}, // fat64
}

func isMachOMagic(head []byte) bool {
	for _, m := range machoMagics {
		if bytes.Equal(head, m) {
			return true
		}
	}
	return false
}

// codePaths lists the entries the pipeline signs, whatever their content turns
// out to be — they are written out for real even when they are large and do
// not start with a Mach-O magic, so a malformed binary fails the same way it
// always did rather than as a zero-filled placeholder.
func codePaths(b *ipaTypes.AppBundle) map[string]bool {
	out := map[string]bool{b.AppPath + "/" + b.ExecutableName: true}
	for _, d := range b.Dylibs {
		out[d] = true
	}
	for _, group := range [][]ipaTypes.BundleComponent{b.Frameworks, b.Plugins, b.WatchApps} {
		for _, c := range group {
			if c.ExecutableName != "" {
				out[c.Path+"/"+c.ExecutableName] = true
			}
		}
	}
	return out
}

// estimateSpace is the pre-flight figure: bytes that will be written out, plus
// the output archive. Large entries that are not code are assumed to become
// placeholders (a few MB of misjudged Mach-O is covered by the slack).
func estimateSpace(files []*zip.File, code map[string]bool) uint64 {
	var real, compressed uint64
	for _, f := range files {
		compressed += f.CompressedSize64
		if f.UncompressedSize64 <= smallEntryBytes || code[f.Name] || path.Ext(f.Name) == "" {
			real += f.UncompressedSize64
		}
	}
	return real + compressed + real + (64 << 20)
}

// materialise lays the archive out under dir.
//
// Every entry is decompressed exactly once, on a pool of workers. Small files,
// code, and anything that turns out to be a Mach-O are written for real; every
// other large resource — images packs, video, Assets.car, game data, usually
// the bulk of a big app — is streamed through the two seal hashes and left as a
// sparse placeholder. Compared with extracting everything, that removes the
// bulk of the disk writes, the second read to hash, and the third read to prove
// the file unchanged at repackage time.
func materialise(files []*zip.File, dir string, code map[string]bool) (*layout, error) {
	l := &layout{placeholders: map[string]placeholder{}}

	var work []*zip.File
	for _, f := range files {
		p := filepath.Join(dir, f.Name)
		if !strings.HasPrefix(p, filepath.Clean(dir)+string(os.PathSeparator)) {
			return nil, fmt.Errorf("unsafe entry path %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(p, 0755); err != nil {
				return nil, err
			}
			continue
		}
		work = append(work, f)
	}

	workers := runtime.NumCPU()
	if workers > 6 {
		workers = 6
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan *zip.File)
	errs := make(chan error, 1)
	var wg sync.WaitGroup
	var failed sync.Once
	stop := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 256*1024)
			for f := range jobs {
				if err := l.place(f, dir, code, buf); err != nil {
					failed.Do(func() {
						errs <- fmt.Errorf("extract %s: %w", f.Name, err)
						close(stop)
					})
					return
				}
			}
		}()
	}

feed:
	for _, f := range work {
		select {
		case jobs <- f:
		case <-stop:
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errs:
		return nil, err
	default:
		return l, nil
	}
}

func (l *layout) place(f *zip.File, dir string, code map[string]bool, buf []byte) error {
	dest := filepath.Join(dir, f.Name)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	perm := os.FileMode(0644)
	if f.Mode()&0111 != 0 {
		perm = 0755
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	if f.UncompressedSize64 <= smallEntryBytes || code[f.Name] {
		return l.writeOut(rc, dest, perm, nil, buf)
	}

	head := make([]byte, 4)
	n, err := io.ReadFull(rc, head)
	head = head[:n]
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return err
	}
	if isMachOMagic(head) {
		return l.writeOut(rc, dest, perm, head, buf)
	}

	h1, h256 := sha1.New(), sha256.New()
	sink := io.MultiWriter(h1, h256)
	sink.Write(head)
	if _, err := io.CopyBuffer(sink, rc, buf); err != nil {
		return err
	}

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if err := out.Truncate(int64(f.UncompressedSize64)); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(dest, placeholderTime, placeholderTime); err != nil {
		return err
	}

	l.mu.Lock()
	l.placeholders[dest] = placeholder{
		entry:  f,
		hashes: &coderesources.FileHashes{SHA1: h1.Sum(nil), SHA256: h256.Sum(nil)},
	}
	l.mu.Unlock()
	return nil
}

func (l *layout) writeOut(r io.Reader, dest string, perm os.FileMode, head []byte, buf []byte) error {
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	written := int64(0)
	if len(head) > 0 {
		if _, err := out.Write(head); err != nil {
			out.Close()
			return err
		}
		written += int64(len(head))
	}
	n, err := io.CopyBuffer(out, r, buf)
	written += n
	if err != nil {
		out.Close()
		return err
	}
	l.mu.Lock()
	l.written += written
	l.mu.Unlock()
	return out.Close()
}

// signConcurrently runs independent signing jobs on a bounded pool and returns
// the first error. Frameworks, loose dylibs and plugins each seal only their
// own directory, so their order never mattered — only the main executable,
// which seals all of them, has to come after.
func signConcurrently(jobs []func() error) error {
	workers := runtime.NumCPU()
	if workers > 6 {
		workers = 6
	}
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var once sync.Once
	var first error
	for _, job := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(run func() error) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := run(); err != nil {
				once.Do(func() { first = err })
			}
		}(job)
	}
	wg.Wait()
	return first
}
