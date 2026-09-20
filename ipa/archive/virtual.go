package archive

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// A signed archive described instead of written.
//
// Repackaging used to write the signed IPA next to the original, so signing a
// 2.6 GB game asked a phone for ~3.5 GB free and simply refused below that.
// Yet every byte of that output is either a file the signing just produced (a
// few hundred MB at worst) or a byte already sitting in the source archive.
// So the archive need not exist: this records where each byte comes from, and
// serves any range of it on demand — the install server hands iOS the bytes as
// it reads them, and nothing is ever written twice.
//
// The layout is plain zip: local header + data per entry, then the central
// directory, with zip64 records where a size or an offset does not fit in 32
// bits. Sizes and CRCs are known before a byte is served, so no entry needs a
// data descriptor and the total length is exact.

const (
	sigLocal   = 0x04034b50
	sigCentral = 0x02014b50
	sigEnd     = 0x06054b50
	sigEnd64   = 0x06064b50
	sigLoc64   = 0x07064b50

	zipVersion   = 20
	zipVersion64 = 45
	creatorUnix  = 3

	// Everything is written with the same mode the file writer used: iOS
	// honours external attributes literally, and a framework without its
	// execute bit fails to load at install time.
	unixModeFile = 0o100755
	unixModeDir  = 0o040755
	msdosDir     = 0x10

	max32 = 0xFFFFFFFF
)

// PlanEntry is one entry of the archive, and where its bytes live.
type PlanEntry struct {
	Name         string `json:"name"`
	Method       uint16 `json:"method"`
	CRC32        uint32 `json:"crc"`
	Compressed   uint64 `json:"compressed"`
	Uncompressed uint64 `json:"uncompressed"`
	Modified     int64  `json:"modified"`
	Dir          bool   `json:"dir,omitempty"`

	// Exactly one of these says where the data is: a byte offset into the
	// source archive (an entry signing did not touch, copied verbatim), or a
	// file the signing produced.
	SourceOffset int64  `json:"source_offset,omitempty"`
	File         string `json:"file,omitempty"`
}

// Plan is the whole archive: the source it copies from, and its entries.
type Plan struct {
	Source  string      `json:"source"`
	Entries []PlanEntry `json:"entries"`

	// Computed by prepare(), never serialised.
	headers   [][]byte
	headerAt  []int64
	dataAt    []int64
	central   []byte
	centralAt int64
	ending    []byte
	endingAt  int64
	length    int64
}

// NewPlan lays the entries out and works out the exact length of the archive.
func NewPlan(source string, entries []PlanEntry) (*Plan, error) {
	p := &Plan{Source: source, Entries: entries}
	if err := p.prepare(); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadPlan reads a plan saved by Save.
func LoadPlan(path string) (*Plan, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &Plan{}
	if err := json.Unmarshal(raw, p); err != nil {
		return nil, err
	}
	if err := p.prepare(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Plan) Save(path string) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0644)
}

// Length is the size of the archive iOS will download.
func (p *Plan) Length() int64 { return p.length }

func (p *Plan) prepare() error {
	p.headers = make([][]byte, len(p.Entries))
	p.headerAt = make([]int64, len(p.Entries))
	p.dataAt = make([]int64, len(p.Entries))

	var at int64
	central := make([]byte, 0, 64*len(p.Entries))
	for i, e := range p.Entries {
		if e.File == "" && e.SourceOffset == 0 && !e.Dir && e.Compressed > 0 {
			return fmt.Errorf("entry %q has no source", e.Name)
		}
		header := localHeader(e)
		p.headers[i] = header
		p.headerAt[i] = at
		at += int64(len(header))
		p.dataAt[i] = at
		at += int64(e.Compressed)
		central = append(central, centralRecord(e, p.headerAt[i])...)
	}

	p.central = central
	p.centralAt = at
	p.ending = endRecords(len(p.Entries), int64(len(central)), p.centralAt)
	p.endingAt = p.centralAt + int64(len(central))
	p.length = p.endingAt + int64(len(p.ending))
	return nil
}

// WriteRange writes the archive's bytes for [offset, offset+length) — the
// whole thing when length is zero or runs past the end. Ranges are what lets
// iOS resume an install that was interrupted.
func (p *Plan) WriteRange(w io.Writer, offset, length int64) error {
	if offset < 0 || offset >= p.length {
		return fmt.Errorf("offset %d outside the archive", offset)
	}
	end := offset + length
	if length <= 0 || end > p.length {
		end = p.length
	}

	var source *os.File
	defer func() {
		if source != nil {
			source.Close()
		}
	}()

	// One in-memory piece: headers, the central directory, the end records.
	piece := func(at int64, b []byte) error {
		from, to, ok := overlap(at, int64(len(b)), offset, end)
		if !ok {
			return nil
		}
		_, err := w.Write(b[from-at : to-at])
		return err
	}

	// One entry's data, from wherever it lives.
	data := func(at int64, e PlanEntry) error {
		from, to, ok := overlap(at, int64(e.Compressed), offset, end)
		if !ok {
			return nil
		}
		if e.File != "" {
			f, err := os.Open(e.File)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(w, io.NewSectionReader(f, from-at, to-from))
			return err
		}
		if source == nil {
			f, err := os.Open(p.Source)
			if err != nil {
				return err
			}
			source = f
		}
		_, err := io.Copy(w, io.NewSectionReader(source, e.SourceOffset+(from-at), to-from))
		return err
	}

	for i, e := range p.Entries {
		if p.headerAt[i] >= end {
			break
		}
		if err := piece(p.headerAt[i], p.headers[i]); err != nil {
			return err
		}
		if err := data(p.dataAt[i], e); err != nil {
			return err
		}
	}
	if err := piece(p.centralAt, p.central); err != nil {
		return err
	}
	return piece(p.endingAt, p.ending)
}

// overlap intersects a span at [at, at+size) with the wanted [from, to).
func overlap(at, size, from, to int64) (int64, int64, bool) {
	start := max64(at, from)
	stop := min64(at+size, to)
	if start >= stop {
		return 0, 0, false
	}
	return start, stop, true
}

func localHeader(e PlanEntry) []byte {
	zip64 := e.Compressed >= max32 || e.Uncompressed >= max32
	name := []byte(e.Name)

	var extra []byte
	if zip64 {
		extra = make([]byte, 20)
		binary.LittleEndian.PutUint16(extra[0:], 1)
		binary.LittleEndian.PutUint16(extra[2:], 16)
		binary.LittleEndian.PutUint64(extra[4:], e.Uncompressed)
		binary.LittleEndian.PutUint64(extra[12:], e.Compressed)
	}

	b := make([]byte, 30+len(name)+len(extra))
	binary.LittleEndian.PutUint32(b[0:], sigLocal)
	binary.LittleEndian.PutUint16(b[4:], version(zip64))
	binary.LittleEndian.PutUint16(b[6:], flags(e.Name))
	binary.LittleEndian.PutUint16(b[8:], e.Method)
	hhmm, yymmdd := dosTime(e.Modified)
	binary.LittleEndian.PutUint16(b[10:], hhmm)
	binary.LittleEndian.PutUint16(b[12:], yymmdd)
	binary.LittleEndian.PutUint32(b[14:], e.CRC32)
	if zip64 {
		binary.LittleEndian.PutUint32(b[18:], max32)
		binary.LittleEndian.PutUint32(b[22:], max32)
	} else {
		binary.LittleEndian.PutUint32(b[18:], uint32(e.Compressed))
		binary.LittleEndian.PutUint32(b[22:], uint32(e.Uncompressed))
	}
	binary.LittleEndian.PutUint16(b[26:], uint16(len(name)))
	binary.LittleEndian.PutUint16(b[28:], uint16(len(extra)))
	copy(b[30:], name)
	copy(b[30+len(name):], extra)
	return b
}

func centralRecord(e PlanEntry, headerOffset int64) []byte {
	zip64 := e.Compressed >= max32 || e.Uncompressed >= max32 || headerOffset >= max32
	name := []byte(e.Name)

	var extra []byte
	if zip64 {
		// The three fields the fixed record could not hold, in the order the
		// format requires: uncompressed, compressed, offset.
		extra = make([]byte, 28)
		binary.LittleEndian.PutUint16(extra[0:], 1)
		binary.LittleEndian.PutUint16(extra[2:], 24)
		binary.LittleEndian.PutUint64(extra[4:], e.Uncompressed)
		binary.LittleEndian.PutUint64(extra[12:], e.Compressed)
		binary.LittleEndian.PutUint64(extra[20:], uint64(headerOffset))
	}

	mode := uint32(unixModeFile)
	attrs := uint32(0)
	if e.Dir {
		mode = unixModeDir
		attrs |= msdosDir
	}
	attrs |= mode << 16

	b := make([]byte, 46+len(name)+len(extra))
	binary.LittleEndian.PutUint32(b[0:], sigCentral)
	binary.LittleEndian.PutUint16(b[4:], creatorUnix<<8|version(zip64))
	binary.LittleEndian.PutUint16(b[6:], version(zip64))
	binary.LittleEndian.PutUint16(b[8:], flags(e.Name))
	binary.LittleEndian.PutUint16(b[10:], e.Method)
	hhmm, yymmdd := dosTime(e.Modified)
	binary.LittleEndian.PutUint16(b[12:], hhmm)
	binary.LittleEndian.PutUint16(b[14:], yymmdd)
	binary.LittleEndian.PutUint32(b[16:], e.CRC32)
	if zip64 {
		binary.LittleEndian.PutUint32(b[20:], max32)
		binary.LittleEndian.PutUint32(b[24:], max32)
	} else {
		binary.LittleEndian.PutUint32(b[20:], uint32(e.Compressed))
		binary.LittleEndian.PutUint32(b[24:], uint32(e.Uncompressed))
	}
	binary.LittleEndian.PutUint16(b[28:], uint16(len(name)))
	binary.LittleEndian.PutUint16(b[30:], uint16(len(extra)))
	// comment, disk, internal attributes: none.
	binary.LittleEndian.PutUint32(b[38:], attrs)
	if zip64 {
		binary.LittleEndian.PutUint32(b[42:], max32)
	} else {
		binary.LittleEndian.PutUint32(b[42:], uint32(headerOffset))
	}
	copy(b[46:], name)
	copy(b[46+len(name):], extra)
	return b
}

func endRecords(entries int, centralSize, centralOffset int64) []byte {
	zip64 := entries > 0xFFFF || centralSize >= max32 || centralOffset >= max32

	var out []byte
	if zip64 {
		end64 := make([]byte, 56)
		binary.LittleEndian.PutUint32(end64[0:], sigEnd64)
		binary.LittleEndian.PutUint64(end64[4:], 44) // size of the rest
		binary.LittleEndian.PutUint16(end64[12:], creatorUnix<<8|zipVersion64)
		binary.LittleEndian.PutUint16(end64[14:], zipVersion64)
		binary.LittleEndian.PutUint64(end64[24:], uint64(entries))
		binary.LittleEndian.PutUint64(end64[32:], uint64(entries))
		binary.LittleEndian.PutUint64(end64[40:], uint64(centralSize))
		binary.LittleEndian.PutUint64(end64[48:], uint64(centralOffset))

		locator := make([]byte, 20)
		binary.LittleEndian.PutUint32(locator[0:], sigLoc64)
		binary.LittleEndian.PutUint64(locator[8:], uint64(centralOffset+centralSize))
		binary.LittleEndian.PutUint32(locator[16:], 1)

		out = append(out, end64...)
		out = append(out, locator...)
	}

	end := make([]byte, 22)
	binary.LittleEndian.PutUint32(end[0:], sigEnd)
	binary.LittleEndian.PutUint16(end[8:], count16(entries))
	binary.LittleEndian.PutUint16(end[10:], count16(entries))
	binary.LittleEndian.PutUint32(end[12:], size32(centralSize))
	binary.LittleEndian.PutUint32(end[16:], size32(centralOffset))

	return append(out, end...)
}

func version(zip64 bool) uint16 {
	if zip64 {
		return zipVersion64
	}
	return zipVersion
}

// Bit 11 tells the reader the name is UTF-8, which Arabic file names need.
func flags(name string) uint16 {
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return 0x800
		}
	}
	return 0
}

func dosTime(unix int64) (uint16, uint16) {
	t := time.Unix(unix, 0).UTC()
	if t.Year() < 1980 {
		return 0, 1<<5 | 1 // 1980-01-01
	}
	hhmm := uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2)
	yymmdd := uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day())
	return hhmm, yymmdd
}

func count16(v int) uint16 {
	if v > 0xFFFF {
		return 0xFFFF
	}
	return uint16(v)
}

func size32(v int64) uint32 {
	if v >= max32 {
		return max32
	}
	return uint32(v)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
