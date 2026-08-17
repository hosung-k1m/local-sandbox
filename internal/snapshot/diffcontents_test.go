package snapshot

import (
	"strings"
	"testing"
)

// TestDiffContentsIdenticalReturnsEmpty exercises the "nothing changed" case:
// two in-memory versions with identical bytes must render as no diff at all,
// matching what a reader would expect from an unmodified file.
func TestDiffContentsIdenticalReturnsEmpty(t *testing.T) {
	content := []byte("line one\nline two\n")
	diff, err := DiffContents("src/main.go", content, content)
	if err != nil {
		t.Fatalf("DiffContents: %v", err)
	}
	if diff != "" {
		t.Errorf("diff = %q, want empty for identical content", diff)
	}
}

// TestDiffContentsModificationRendersUnifiedDiff checks the headers are
// rewritten to plain "a/<relPath>" / "b/<relPath>" (not the temporary file
// paths DiffContents writes under the hood) and that the hunk carries the
// expected +/- lines around the unchanged context line.
func TestDiffContentsModificationRendersUnifiedDiff(t *testing.T) {
	from := []byte("line one\nline two\n")
	to := []byte("line one\nline TWO changed\n")
	diff, err := DiffContents("src/main.go", from, to)
	if err != nil {
		t.Fatalf("DiffContents: %v", err)
	}
	for _, want := range []string{
		"--- a/src/main.go",
		"+++ b/src/main.go",
		"-line two",
		"+line TWO changed",
		" line one", // unchanged line survives as shared hunk context
	} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff missing %q; got:\n%s", want, diff)
		}
	}
}

// TestDiffContentsEmptyFromRendersAdditions covers the file-creation shape: an
// empty "from" side must diff as an all-additions hunk, per DiffContents' doc
// comment ("an empty 'from' already renders as an all-additions hunk").
func TestDiffContentsEmptyFromRendersAdditions(t *testing.T) {
	to := []byte("line one\nline two\n")
	diff, err := DiffContents("new.txt", nil, to)
	if err != nil {
		t.Fatalf("DiffContents: %v", err)
	}
	for _, want := range []string{"+line one", "+line two", "+++ b/new.txt"} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff missing %q; got:\n%s", want, diff)
		}
	}
	if strings.Contains(diff, "-line one") || strings.Contains(diff, "-line two") {
		t.Errorf("diff should contain no removed content lines for an empty from side; got:\n%s", diff)
	}
}

// TestDiffContentsBinaryContentReportsBinaryFiles covers content git detects
// as binary (a NUL byte): git renders its "Binary files ... differ" summary
// instead of a text hunk, and the rewritten a/ b/ labels must still apply to
// that line like any other.
func TestDiffContentsBinaryContentReportsBinaryFiles(t *testing.T) {
	from := []byte("abc\x00def")
	to := []byte("abc\x00xyz")
	diff, err := DiffContents("data.bin", from, to)
	if err != nil {
		t.Fatalf("DiffContents: %v", err)
	}
	if !strings.Contains(diff, "Binary files") {
		t.Fatalf("diff = %q, want git's Binary files message for NUL-containing content", diff)
	}
	if !strings.Contains(diff, "a/data.bin") || !strings.Contains(diff, "b/data.bin") {
		t.Errorf("diff = %q, want rewritten a/data.bin and b/data.bin labels", diff)
	}
	if strings.Contains(diff, "@@") {
		t.Errorf("diff = %q, binary content should not render a text hunk", diff)
	}
}
