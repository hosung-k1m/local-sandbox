package view

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var errStreamDiscontinuity = errors.New("view: stream evidence continuity lost")

type streamPosition struct {
	sessionID string
	segment   int
	offset    int64
	sequence  int64
}

type streamReader struct {
	sessionDir string
	current    streamPosition
}

type streamSegment struct {
	number   int
	path     string
	size     int64
	manifest *streamSegmentManifest
}

type streamSegmentManifest struct {
	SessionID     string `json:"session_id"`
	Segment       int    `json:"segment_number"`
	FirstSequence int64  `json:"first_sequence"`
	LastSequence  int64  `json:"last_sequence"`
	RecordCount   int64  `json:"record_count"`
}

func newStreamReader(sessionDir, sessionID string, afterSequence int64) *streamReader {
	return &streamReader{
		sessionDir: sessionDir,
		current: streamPosition{
			sessionID: sessionID,
			sequence:  afterSequence,
		},
	}
}

func (r *streamReader) position() streamPosition {
	return r.current
}

func (r *streamReader) read(maxRecords int) ([]eventRow, error) {
	if r.current.sessionID == "" {
		return nil, fmt.Errorf("view: stream session id is empty")
	}
	if r.current.sequence < 0 || r.current.segment < 0 || r.current.offset < 0 {
		return nil, streamDiscontinuityf("invalid position %+v", r.current)
	}
	if maxRecords < 1 {
		return nil, fmt.Errorf("view: stream read limit must be positive")
	}

	segments, err := listStreamSegments(r.sessionDir)
	if err != nil {
		return nil, err
	}
	if len(segments) == 0 {
		if r.current.sequence != 0 || r.current.segment != 0 || r.current.offset != 0 {
			return nil, streamDiscontinuityf("position has no matching segment")
		}
		return nil, nil
	}

	start := r.current
	working := start
	highestObserved := int64(0)
	if start.segment != 0 {
		highestObserved = start.sequence
	}
	foundCurrentSegment := start.segment == 0
	rows := make([]eventRow, 0, min(maxRecords, 100))

	for segmentIndex, segment := range segments {
		if segment.number < start.segment {
			continue
		}
		if start.segment != 0 && segment.number == start.segment {
			foundCurrentSegment = true
		}
		if !foundCurrentSegment {
			return nil, streamDiscontinuityf("segment %d is missing", start.segment)
		}

		offset := int64(0)
		if segment.number == start.segment {
			offset = start.offset
		}
		if offset > segment.size {
			return nil, streamDiscontinuityf("segment %d shrank below offset %d", segment.number, offset)
		}
		if segment.manifest != nil && segment.manifest.SessionID != start.sessionID {
			return nil, streamDiscontinuityf("segment %d manifest names session %q, want %q", segment.number, segment.manifest.SessionID, start.sessionID)
		}

		if start.segment == 0 && offset == 0 && segment.manifest != nil && segment.manifest.LastSequence <= start.sequence {
			if highestObserved == 0 && segment.manifest.FirstSequence != 1 {
				return nil, streamDiscontinuityf("sealed sequence range starts at %d", segment.manifest.FirstSequence)
			}
			if highestObserved != 0 && segment.manifest.FirstSequence != highestObserved+1 {
				return nil, streamDiscontinuityf("sealed sequence %d follows %d", segment.manifest.FirstSequence, highestObserved)
			}
			working.segment = segment.number
			working.offset = segment.size
			highestObserved = segment.manifest.LastSequence
			continue
		}

		f, err := os.Open(segment.path)
		if err != nil {
			return nil, fmt.Errorf("view: open stream segment %s: %w", segment.path, err)
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, fmt.Errorf("view: seek stream segment %s: %w", segment.path, err)
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("view: stat open stream segment %s: %w", segment.path, err)
		}
		if offset > info.Size() {
			f.Close()
			return nil, streamDiscontinuityf("segment %d shrank below offset %d", segment.number, offset)
		}

		counter := &countingByteReader{reader: f}
		for {
			frameOffset := offset + counter.read
			events, err := decodeOTLPFrame(counter)
			if errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				if segment.manifest != nil || segmentIndex != len(segments)-1 {
					f.Close()
					return nil, streamDiscontinuityf("incomplete frame in closed segment %d at offset %d", segment.number, frameOffset)
				}
				break
			}
			if err != nil {
				f.Close()
				return nil, streamDiscontinuityf("decode segment %d at offset %d: %v", segment.number, frameOffset, err)
			}
			if len(events) > maxRecords-len(rows) {
				if len(rows) == 0 {
					f.Close()
					return nil, fmt.Errorf("view: stream frame has %d records, exceeding read limit %d", len(events), maxRecords)
				}
				if err := f.Close(); err != nil {
					return nil, fmt.Errorf("view: close stream segment %s: %w", segment.path, err)
				}
				r.current = working
				return rows, nil
			}

			for _, event := range events {
				if event.sessionID != start.sessionID {
					f.Close()
					return nil, streamDiscontinuityf("segment %d contains session %q, want %q", segment.number, event.sessionID, start.sessionID)
				}
				if event.row.Seq < 1 {
					f.Close()
					return nil, streamDiscontinuityf("segment %d contains invalid sequence %d", segment.number, event.row.Seq)
				}
				if event.row.Seq != highestObserved+1 {
					f.Close()
					return nil, streamDiscontinuityf("sequence %d follows %d", event.row.Seq, highestObserved)
				}
				highestObserved = event.row.Seq
				if event.row.Seq <= start.sequence {
					continue
				}
				if event.row.Seq != working.sequence+1 {
					f.Close()
					return nil, streamDiscontinuityf("sequence %d follows %d", event.row.Seq, working.sequence)
				}
				rows = append(rows, event.row)
				working.sequence = event.row.Seq
			}

			working.segment = segment.number
			working.offset = offset + counter.read
			if len(rows) == maxRecords {
				if err := f.Close(); err != nil {
					return nil, fmt.Errorf("view: close stream segment %s: %w", segment.path, err)
				}
				r.current = working
				return rows, nil
			}
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("view: close stream segment %s: %w", segment.path, err)
		}
	}

	if !foundCurrentSegment {
		return nil, streamDiscontinuityf("segment %d is missing", start.segment)
	}
	if start.segment == 0 && start.sequence > highestObserved {
		return nil, streamDiscontinuityf("sequence %d is newer than available sequence %d", start.sequence, highestObserved)
	}
	r.current = working
	return rows, nil
}

func listStreamSegments(sessionDir string) ([]streamSegment, error) {
	pattern := filepath.Join(sessionDir, "evidence", "segments", "segment-*.otlp")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("view: glob stream segments: %w", err)
	}

	segments := make([]streamSegment, 0, len(paths))
	for _, path := range paths {
		number, err := streamSegmentNumber(path)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("view: stat stream segment %s: %w", path, err)
		}
		manifest, err := loadStreamSegmentManifest(strings.TrimSuffix(path, ".otlp") + ".manifest.json")
		if err != nil {
			return nil, err
		}
		if manifest != nil {
			if manifest.Segment != number || manifest.FirstSequence < 1 || manifest.LastSequence < manifest.FirstSequence ||
				manifest.RecordCount != manifest.LastSequence-manifest.FirstSequence+1 {
				return nil, streamDiscontinuityf("invalid manifest for segment %d", number)
			}
		}
		segments = append(segments, streamSegment{
			number:   number,
			path:     path,
			size:     info.Size(),
			manifest: manifest,
		})
	}
	sort.Slice(segments, func(i, j int) bool {
		return segments[i].number < segments[j].number
	})
	for i, segment := range segments {
		if i == 0 {
			if segment.number != 1 {
				return nil, streamDiscontinuityf("first segment is %d, want 1", segment.number)
			}
			continue
		}
		if segment.number != segments[i-1].number+1 {
			return nil, streamDiscontinuityf("segment %d follows %d", segment.number, segments[i-1].number)
		}
	}
	return segments, nil
}

func streamSegmentNumber(path string) (int, error) {
	name := strings.TrimSuffix(filepath.Base(path), ".otlp")
	numberText := strings.TrimPrefix(name, "segment-")
	if numberText == name || numberText == "" {
		return 0, streamDiscontinuityf("invalid segment name %q", filepath.Base(path))
	}
	number, err := strconv.Atoi(numberText)
	if err != nil || number < 1 {
		return 0, streamDiscontinuityf("invalid segment name %q", filepath.Base(path))
	}
	return number, nil
}

func loadStreamSegmentManifest(path string) (*streamSegmentManifest, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("view: read stream manifest %s: %w", path, err)
	}
	var manifest streamSegmentManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return nil, streamDiscontinuityf("decode manifest %s: %v", filepath.Base(path), err)
	}
	return &manifest, nil
}

func streamDiscontinuityf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errStreamDiscontinuity, fmt.Sprintf(format, args...))
}

type countingByteReader struct {
	reader io.Reader
	read   int64
}

func (r *countingByteReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += int64(n)
	return n, err
}

func (r *countingByteReader) ReadByte() (byte, error) {
	var b [1]byte
	n, err := r.Read(b[:])
	if n == 1 {
		return b[0], nil
	}
	if err == nil {
		err = io.ErrNoProgress
	}
	return 0, err
}
