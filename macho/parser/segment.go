package parser

import (
	"fmt"
	"io"

	mtypes "github.com/AzozzALFiras/GoSigner/macho/types"
)

// FindSegment finds and parses a named segment from a Mach-O slice's load commands.
func FindSegment(lcs []mtypes.LoadCommand, name string) (*mtypes.SegmentCommand, *mtypes.LoadCommand, error) {
	for i := range lcs {
		lc := &lcs[i]
		if lc.Cmd != mtypes.LCSegment && lc.Cmd != mtypes.LCSegment64 {
			continue
		}
		seg, err := ParseSegmentCommand(lc)
		if err != nil {
			continue
		}
		if seg.Name == name {
			return seg, lc, nil
		}
	}
	return nil, nil, fmt.Errorf("segment %s not found", name)
}

// FindLinkedit finds and parses the __LINKEDIT segment.
func FindLinkedit(lcs []mtypes.LoadCommand) (*mtypes.SegmentCommand, *mtypes.LoadCommand, error) {
	return FindSegment(lcs, mtypes.SegLinkEdit)
}

// FindTextSegment finds and parses the __TEXT segment.
func FindTextSegment(lcs []mtypes.LoadCommand) (*mtypes.SegmentCommand, *mtypes.LoadCommand, error) {
	return FindSegment(lcs, mtypes.SegText)
}

// ReadSegmentData reads the file data for a given segment.
func ReadSegmentData(r io.ReaderAt, baseOffset uint64, seg *mtypes.SegmentCommand) ([]byte, error) {
	data := make([]byte, seg.FileSize)
	_, err := r.ReadAt(data, int64(baseOffset+seg.FileOff))
	if err != nil {
		return nil, fmt.Errorf("read segment %s data: %w", seg.Name, err)
	}
	return data, nil
}
