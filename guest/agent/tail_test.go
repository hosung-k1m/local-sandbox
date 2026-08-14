package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTailFollowDoesNotSkipAppendAtInitialEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, []byte("before-watch\n"), 0o600); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines := make(chan string, 1)
	errs := make(chan error, 1)
	appendErr := make(chan error, 1)
	go func() {
		errs <- tailFollowWithInterval(ctx, path, time.Hour, func() {
			appendErr <- appendLogLine(path, "after-ready\n")
		}, func(line string) {
			lines <- line
			cancel()
		})
	}()

	select {
	case line := <-lines:
		if line != "after-ready" {
			t.Fatalf("line = %q, want append after initial EOF", line)
		}
	case <-time.After(time.Second):
		t.Fatal("append made at initial EOF was not consumed")
	}
	if err := <-appendErr; err != nil {
		t.Fatalf("append during readiness: %v", err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("tailFollowWithInterval: %v", err)
	}
}

func TestTailFollowWakesOnFilesystemAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	lines := make(chan string, 1)
	errs := make(chan error, 1)
	go func() {
		errs <- tailFollowWithInterval(ctx, path, time.Hour, func() {
			close(ready)
		}, func(line string) {
			lines <- line
			cancel()
		})
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("tailer did not establish its initial EOF position")
	}
	if err := appendLogLine(path, "event-driven\n"); err != nil {
		t.Fatalf("append event-driven line: %v", err)
	}
	select {
	case line := <-lines:
		if line != "event-driven" {
			t.Fatalf("line = %q, want event-driven append", line)
		}
	case <-time.After(time.Second):
		t.Fatal("filesystem append did not wake tailer before polling fallback")
	}
	if err := <-errs; err != nil {
		t.Fatalf("tailFollowWithInterval: %v", err)
	}
}

func TestTailFollowPreservesSplitLineAcrossEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	lines := make(chan string, 1)
	errs := make(chan error, 1)
	go func() {
		errs <- tailFollowWithInterval(ctx, path, time.Hour, func() {
			close(ready)
		}, func(line string) {
			lines <- line
			cancel()
		})
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("tailer did not establish its initial EOF position")
	}
	if err := appendLogLine(path, `{"process_exec":{"process":`); err != nil {
		t.Fatalf("append first line fragment: %v", err)
	}
	// The long polling interval makes the first write's fsnotify wake consume
	// the fragment and encounter EOF before the second write completes it.
	time.Sleep(50 * time.Millisecond)
	if err := appendLogLine(path, "{}}}\n"); err != nil {
		t.Fatalf("append final line fragment: %v", err)
	}
	select {
	case line := <-lines:
		if line != `{"process_exec":{"process":{}}}` {
			t.Fatalf("line = %q, want complete split JSON line", line)
		}
	case <-time.After(time.Second):
		t.Fatal("tailer did not emit the completed split line")
	}
	if err := <-errs; err != nil {
		t.Fatalf("tailFollowWithInterval: %v", err)
	}
}

func TestTailFollowDrainsRenamedFileThenReadsPrepopulatedReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	if err := os.WriteFile(path, []byte("historical\n"), 0o600); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	lines := make(chan string, 2)
	errs := make(chan error, 1)
	go func() {
		errs <- tailFollowWithInterval(ctx, path, time.Hour, func() {
			close(ready)
		}, func(line string) {
			lines <- line
		})
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("tailer did not establish its initial EOF position")
	}

	old, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open old log: %v", err)
	}
	if err := os.Rename(path, filepath.Join(dir, "events.log.1")); err != nil {
		old.Close()
		t.Fatalf("rename old log: %v", err)
	}
	if _, err := old.WriteString("old-unread\n"); err != nil {
		old.Close()
		t.Fatalf("append renamed log: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatalf("close renamed log: %v", err)
	}

	replacement := filepath.Join(dir, "replacement.log")
	if err := os.WriteFile(replacement, []byte("replacement-first\n"), 0o600); err != nil {
		t.Fatalf("write replacement log: %v", err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatalf("install replacement log: %v", err)
	}

	for _, want := range []string{"old-unread", "replacement-first"} {
		select {
		case got := <-lines:
			if got != want {
				t.Fatalf("line = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %q", want)
		}
	}
	cancel()
	if err := <-errs; err != nil {
		t.Fatalf("tailFollowWithInterval: %v", err)
	}
}

func TestStrictTailFailsOnFileGenerationChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	if err := os.WriteFile(path, []byte("historical\n"), 0o600); err != nil {
		t.Fatalf("write initial log: %v", err)
	}
	ready := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		errs <- tailFollowWithIntervalAndStrict(context.Background(), path, time.Millisecond, func() { close(ready) }, func(string) {}, true)
	}()
	<-ready
	if err := os.Rename(path, filepath.Join(dir, "events.log.1")); err != nil {
		t.Fatalf("rotate log: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement\n"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	select {
	case err := <-errs:
		if err == nil || !strings.Contains(err.Error(), "changed generation") {
			t.Fatalf("strict tail error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("strict tail did not fail on rotation")
	}
}

// TestTailFollowReattachReportsGenerationChangeAndResumes covers the tetragon
// export path: a lumberjack-style rotation (rename aside, create fresh) must be
// reported to the caller and then recovered from, not treated as the end of the
// tail. Strict callers keep the old fail-fast behavior (see the test above).
func TestTailFollowReattachReportsGenerationChangeAndResumes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	if err := os.WriteFile(path, []byte("historical\n"), 0o600); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	reattached := make(chan struct{}, 4)
	lines := make(chan string, 4)
	offsets := make(chan int64, 8)
	errs := make(chan error, 1)
	go func() {
		errs <- tailFollowReadyReattach(ctx, path, func() {
			close(ready)
		}, func(line string) {
			lines <- line
		}, func() {
			reattached <- struct{}{}
		}, func(offset int64) {
			offsets <- offset
		})
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("tailer did not establish its initial EOF position")
	}
	// The attach position is reported so a caller can measure, at shutdown, how
	// much of the file it never reached.
	select {
	case got := <-offsets:
		if got != int64(len("historical\n")) {
			t.Fatalf("attach offset = %d, want %d", got, len("historical\n"))
		}
	case <-time.After(time.Second):
		t.Fatal("tailer did not report its attach offset")
	}
	if err := os.Rename(path, filepath.Join(dir, "events.log.1")); err != nil {
		t.Fatalf("rotate log: %v", err)
	}
	if err := os.WriteFile(path, []byte("after-rotation\n"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}

	select {
	case <-reattached:
	case err := <-errs:
		t.Fatalf("recoverable tailer ended on rotation: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("rotation was not reported to onGeneration")
	}
	select {
	case got := <-lines:
		if got != "after-rotation" {
			t.Fatalf("line = %q, want the replacement file read from its start", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tailer did not resume reading after the rotation")
	}
	waitForOffset(t, offsets, int64(len("after-rotation\n")))
	cancel()
	if err := <-errs; err != nil {
		t.Fatalf("tailFollowReadyReattach: %v", err)
	}
}

// waitForOffset waits for the tailer to report want, skipping the earlier
// positions it reports on the way there (the attach EOF, then 0 for the
// replacement file it reattaches to).
func waitForOffset(t *testing.T, offsets <-chan int64, want int64) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-offsets:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("tailer never reported offset %d", want)
		}
	}
}

func TestTailFollowReadsSameInodeTruncateAndFastRegrowFromStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, []byte("historical-content\n"), 0o600); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	lines := make(chan string, 2)
	errs := make(chan error, 1)
	go func() {
		errs <- tailFollowWithInterval(ctx, path, time.Hour, func() {
			close(ready)
		}, func(line string) {
			lines <- line
		})
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("tailer did not establish its initial EOF position")
	}
	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat initial log: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement-from-zero\nreplacement-second-line\n"), 0o600); err != nil {
		t.Fatalf("truncate and regrow log: %v", err)
	}
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat regrown log: %v", err)
	}
	if !os.SameFile(infoBefore, infoAfter) {
		t.Fatal("fixture replaced the inode instead of truncating it")
	}
	if infoAfter.Size() < infoBefore.Size() {
		t.Fatalf("regrown size = %d, want at least old offset %d", infoAfter.Size(), infoBefore.Size())
	}

	for _, want := range []string{"replacement-from-zero", "replacement-second-line"} {
		select {
		case got := <-lines:
			if got != want {
				t.Fatalf("line = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %q", want)
		}
	}
	cancel()
	if err := <-errs; err != nil {
		t.Fatalf("tailFollowWithInterval: %v", err)
	}
}

func TestTailFollowRevalidatesStableAnchorAfterRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, []byte("historical-anchor\n"), 0o600); err != nil {
		t.Fatalf("write initial log: %v", err)
	}
	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat initial log: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	rewritten := make(chan error, 1)
	lines := make(chan string, 2)
	errs := make(chan error, 1)
	didRewrite := false
	go func() {
		errs <- tailFollowWithIntervalAndBeforeRead(ctx, path, time.Hour, func() {
			close(ready)
		}, func(line string) {
			lines <- line
		}, func() {
			if didRewrite {
				return
			}
			didRewrite = true
			rewritten <- os.WriteFile(path, []byte("replacement-from-zero\nreplacement-after-race\n"), 0o600)
		})
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("tailer did not establish its initial EOF position")
	}
	// Wake the tailer without changing file contents. The hook then forces
	// truncate/regrow after the wake checkpoint validation and before ReadString.
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("wake tailer: %v", err)
	}
	select {
	case err := <-rewritten:
		if err != nil {
			t.Fatalf("truncate and regrow log: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("tailer did not reach the validate-before-read test seam")
	}
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat regrown log: %v", err)
	}
	if !os.SameFile(infoBefore, infoAfter) {
		t.Fatal("fixture replaced the inode instead of truncating it")
	}
	if infoAfter.Size() < infoBefore.Size() {
		t.Fatalf("regrown size = %d, want at least old offset %d", infoAfter.Size(), infoBefore.Size())
	}

	for _, want := range []string{"replacement-from-zero", "replacement-after-race"} {
		select {
		case got := <-lines:
			if got != want {
				t.Fatalf("line = %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %q", want)
		}
	}
	cancel()
	if err := <-errs; err != nil {
		t.Fatalf("tailFollowWithIntervalAndBeforeRead: %v", err)
	}
}

func appendLogLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
