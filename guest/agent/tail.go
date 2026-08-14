package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// tailPollInterval is how often tailFollow checks a non-growing file for
// new data or rotation/truncation.
const tailPollInterval = 200 * time.Millisecond

// tailCheckpointSize bounds the already-consumed suffix used to distinguish
// an ordinary append from same-inode truncate-and-regrow.
const tailCheckpointSize = 4096

// tailFollow reads path from its current end-of-file and calls onLine for
// each complete line appended afterward, using filesystem notifications with
// polling as a fallback until ctx is cancelled. A missing file is tolerated:
// tailFollow waits for it to appear. If the file shrinks (rotated/truncated),
// it reopens from the start. A fragment read at EOF is retained until a later
// append supplies its newline.
func tailFollow(ctx context.Context, path string, onLine func(line string)) error {
	return tailFollowReady(ctx, path, nil, onLine)
}

// tailFollowReady installs an event-driven directory watch before opening path
// and calls onReady once the initial file position is established at EOF. The
// directory watch closes the race between seeking and waiting for the first
// append; the polling interval remains as a fallback for unsupported filesystems
// and dropped notifications.
func tailFollowReady(ctx context.Context, path string, onReady func(), onLine func(line string)) error {
	return tailFollowWithIntervalAndStrict(ctx, path, tailPollInterval, onReady, onLine, false)
}

func tailFollowWithInterval(ctx context.Context, path string, pollInterval time.Duration, onReady func(), onLine func(line string)) error {
	return tailFollowWithIntervalAndStrict(ctx, path, pollInterval, onReady, onLine, false)
}

func tailFollowReadyStrict(ctx context.Context, path string, onReady func(), onLine func(line string)) error {
	return tailFollowWithIntervalAndStrict(ctx, path, tailPollInterval, onReady, onLine, true)
}

func tailFollowWithIntervalAndStrict(ctx context.Context, path string, pollInterval time.Duration, onReady func(), onLine func(line string), strictGeneration bool) error {
	return tailFollowWithIntervalAndBeforeReadStrict(ctx, path, pollInterval, onReady, onLine, nil, strictGeneration)
}

// beforeRead is a test seam for forcing a generation change after wake-time
// validation and immediately before the next read. Production callers pass nil.
func tailFollowWithIntervalAndBeforeRead(ctx context.Context, path string, pollInterval time.Duration, onReady func(), onLine func(line string), beforeRead func()) error {
	return tailFollowWithIntervalAndBeforeReadStrict(ctx, path, pollInterval, onReady, onLine, beforeRead, false)
}

func tailFollowWithIntervalAndBeforeReadStrict(ctx context.Context, path string, pollInterval time.Duration, onReady func(), onLine func(line string), beforeRead func(), strictGeneration bool) error {
	var (
		f                *os.File
		reader           *bufio.Reader
		offset           int64
		fileInfo         os.FileInfo
		fragment         string
		checkpoint       []byte
		checkpointOffset int64
		candidate        []byte
		attached         bool
		readyOnce        sync.Once
		watchEvents      <-chan fsnotify.Event
		watchErrors      <-chan error
	)
	appendBounded := func(dst []byte, data string) []byte {
		dst = append(dst, data...)
		if len(dst) > tailCheckpointSize {
			dst = append([]byte(nil), dst[len(dst)-tailCheckpointSize:]...)
		}
		return dst
	}
	loadCheckpoint := func() error {
		size := offset
		if size > tailCheckpointSize {
			size = tailCheckpointSize
		}
		checkpoint = make([]byte, size)
		if size == 0 {
			checkpointOffset = offset
			candidate = nil
			return nil
		}
		_, err := f.ReadAt(checkpoint, offset-size)
		checkpointOffset = offset
		candidate = append([]byte(nil), checkpoint...)
		return err
	}
	checkpointMatches := func(data []byte, end int64) bool {
		if len(data) == 0 {
			return true
		}
		current := make([]byte, len(data))
		if _, err := f.ReadAt(current, end-int64(len(data))); err != nil {
			return false
		}
		return bytes.Equal(data, current)
	}
	watcher, err := fsnotify.NewWatcher()
	if err == nil {
		if err := watcher.Add(filepath.Dir(path)); err == nil {
			watchEvents = watcher.Events
			watchErrors = watcher.Errors
		} else {
			watcher.Close()
			watcher = nil
		}
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	defer func() {
		if f != nil {
			f.Close()
		}
		if watcher != nil {
			watcher.Close()
		}
	}()

	open := func() error {
		if f != nil {
			f.Close()
			f = nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		whence := io.SeekStart
		if !attached {
			whence = io.SeekEnd
		}
		off, err := file.Seek(0, whence)
		if err != nil {
			file.Close()
			return err
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}
		f, offset, fileInfo, reader = file, off, info, bufio.NewReader(file)
		fragment = ""
		if err := loadCheckpoint(); err != nil {
			file.Close()
			f = nil
			return err
		}
		attached = true
		if onReady != nil {
			readyOnce.Do(onReady)
		}
		return nil
	}

	wait := func() bool {
		for {
			select {
			case <-ctx.Done():
				return false
			case <-ticker.C:
				return true
			case event, ok := <-watchEvents:
				if !ok {
					watchEvents = nil
					continue
				}
				if filepath.Clean(event.Name) == filepath.Clean(path) {
					return true
				}
			case _, ok := <-watchErrors:
				if !ok {
					watchErrors = nil
				}
			}
		}
	}

	for {
		if f == nil {
			if err := open(); err != nil {
				if !wait() {
					return nil
				}
				continue
			}
		}

		line, readErr := reader.ReadString('\n')
		if !checkpointMatches(checkpoint, checkpointOffset) {
			if strictGeneration {
				return fmt.Errorf("agent: %s changed generation", path)
			}
			f.Close()
			f = nil
			continue
		}
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("agent: read %s: %w", path, readErr)
		}
		readOffset := offset + int64(len(line))
		nextCandidate := appendBounded(append([]byte(nil), candidate...), line)
		if len(checkpoint) == 0 && line != "" {
			if !checkpointMatches(nextCandidate, readOffset) {
				f.Close()
				f = nil
				continue
			}
			checkpoint = append([]byte(nil), nextCandidate...)
			checkpointOffset = readOffset
		}
		offset = readOffset
		candidate = nextCandidate
		if readErr == nil {
			onLine(fragment + strings.TrimRight(line, "\n"))
			fragment = ""
			continue
		}
		if line != "" {
			fragment += line
		}

		// Promote the rolling candidate only at a stable EOF, after both the
		// old fixed anchor and the candidate bytes have been revalidated.
		if !checkpointMatches(checkpoint, checkpointOffset) || !checkpointMatches(candidate, offset) {
			if strictGeneration {
				return fmt.Errorf("agent: %s changed generation", path)
			}
			f.Close()
			f = nil
			continue
		}
		checkpoint = append([]byte(nil), candidate...)
		checkpointOffset = offset

		// Drain the currently open descriptor through EOF before switching.
		// Replacement is detected by inode as well as truncation by size, so
		// the polling fallback also catches a same-size atomic replacement.
		if info, statErr := os.Stat(path); statErr == nil && (!os.SameFile(fileInfo, info) || info.Size() < offset) {
			if strictGeneration {
				return fmt.Errorf("agent: %s changed generation", path)
			}
			f.Close()
			f = nil
			continue
		}
		if !wait() {
			return nil
		}
		// Size alone cannot detect a same-inode file that was truncated and
		// rewritten past offset between observations. Validate the bounded
		// consumed suffix before reading newly available bytes.
		if !checkpointMatches(checkpoint, checkpointOffset) {
			if strictGeneration {
				return fmt.Errorf("agent: %s changed generation", path)
			}
			f.Close()
			f = nil
			continue
		}
		if beforeRead != nil {
			beforeRead()
		}
	}
}
