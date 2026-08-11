package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// tailPollInterval is how often tailFollow checks a non-growing file for
// new data or rotation/truncation.
const tailPollInterval = 200 * time.Millisecond

// tailFollow reads path from its current end-of-file and calls onLine for
// each complete line appended afterward, polling until ctx is cancelled.
// A missing file is tolerated: tailFollow waits for it to appear. If the
// file shrinks (rotated/truncated), it reopens from the start.
func tailFollow(ctx context.Context, path string, onLine func(line string)) error {
	var (
		f      *os.File
		reader *bufio.Reader
		offset int64
	)
	defer func() {
		if f != nil {
			f.Close()
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
		off, err := file.Seek(0, io.SeekEnd)
		if err != nil {
			file.Close()
			return err
		}
		f, offset, reader = file, off, bufio.NewReader(file)
		return nil
	}

	wait := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(tailPollInterval):
			return true
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

		line, err := reader.ReadString('\n')
		if err == nil {
			offset += int64(len(line))
			onLine(strings.TrimRight(line, "\n"))
			continue
		}
		if err != io.EOF {
			return fmt.Errorf("agent: read %s: %w", path, err)
		}

		// EOF: detect rotation/truncation (size shrank under us) before
		// waiting for more data.
		if info, statErr := os.Stat(path); statErr == nil && info.Size() < offset {
			f.Close()
			f = nil
			continue
		}
		if !wait() {
			return nil
		}
	}
}
