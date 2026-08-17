package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"boxedai/internal/evidence"
)

// Tests for checkFileContentStore (DESIGN "File content capture"): the unsigned
// per-session blob store is resolved from the signed record and must be both
// complete (every capture="full" file.changed has a blob) and correct (every blob
// re-hashes to what was signed). Missing and mismatched blobs are deliberately
// distinguished throughout — see the contentStoreResult doc comment in checks.go.

// writeBlobAt writes content at the blob-store path named by digest (DESIGN
// layout: <sessionDir>/blobs/sha256/<hex>), independent of what digest content
// actually hashes to. That decoupling is what lets a test construct a blob that is
// present but mismatched — the exact shape checkFileContentStore exists to catch.
func writeBlobAt(t *testing.T, sessionDir, digest string, content []byte) {
	t.Helper()
	hexPart := strings.TrimPrefix(digest, blobDigestPrefix)
	blobDir := filepath.Join(sessionDir, blobsDirName, blobAlgoDirName)
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatalf("mkdir blob dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, hexPart), content, 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
}

// writeMatchingBlob writes content under the blob-store path named by its own
// SHA-256 digest and returns that digest — the common case where a file.changed
// event's recorded digest and the on-disk blob are meant to agree.
func writeMatchingBlob(t *testing.T, sessionDir string, content []byte) string {
	t.Helper()
	digest := evidence.SHA256Hex(content)
	writeBlobAt(t, sessionDir, digest, content)
	return digest
}

// TestVerify_LocalOnly_ContentStoreCapturedBlobMatchesDigest is the happy path
// composed through the full verifier: a guest-kernel file.changed stamped
// capture="full" whose blob is present and re-hashes to the recorded digest must
// pass, contribute the correct captured count, and leave the store valid.
func TestVerify_LocalOnly_ContentStoreCapturedBlobMatchesDigest(t *testing.T) {
	f := newFixture(t)
	digest := writeMatchingBlob(t, f.dir, []byte("hello from the workspace"))

	base := happyEvents(f.outDigest)
	stopIdx := len(base) - 2
	events := append([]eventSpec{}, base[:stopIdx]...)
	events = append(events, eventSpec{
		name:          evidence.EventFileChanged,
		contentDigest: digest,
		attrs:         map[string]any{evidence.AttrContentCapture: string(evidence.CaptureFull)},
	})
	events = append(events, base[stopIdx:]...)
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictLocalOnly {
		t.Fatalf("verdict = %s, want LOCAL_ONLY\n%s", rep.Verdict, rep.String())
	}
	if !checkPassed(rep, stepContentStore) {
		t.Error("file-content-store check should have passed")
	}
	if rep.Facets.FileContentCaptured != 1 {
		t.Errorf("captured = %d, want 1", rep.Facets.FileContentCaptured)
	}
	if !rep.Facets.FileContentStoreValid {
		t.Error("FileContentStoreValid = false, want true")
	}
}

// TestVerify_Incomplete_ContentStoreMissingBlob: a capture="full" event whose blob
// was never written (pruned, lost, or never stored) costs inspectability, not
// integrity — the signed digest still stands. It must drive INCOMPLETE, not
// TAMPER_SUSPECTED, and must not touch the crypto floor.
func TestVerify_Incomplete_ContentStoreMissingBlob(t *testing.T) {
	f := newFixture(t)
	digest := evidence.SHA256Hex([]byte("phantom content, never written to the blob store"))

	base := happyEvents(f.outDigest)
	stopIdx := len(base) - 2
	events := append([]eventSpec{}, base[:stopIdx]...)
	events = append(events, eventSpec{
		name:          evidence.EventFileChanged,
		contentDigest: digest,
		attrs:         map[string]any{evidence.AttrContentCapture: string(evidence.CaptureFull)},
	})
	events = append(events, base[stopIdx:]...)
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %s, want INCOMPLETE\n%s", rep.Verdict, rep.String())
	}
	if checkPassed(rep, stepContentStore) {
		t.Error("file-content-store check should have failed on a missing blob")
	}
	if rep.Facets.FileContentCaptured != 1 {
		t.Errorf("captured = %d, want 1 (intent to capture is counted even when the blob is absent)", rep.Facets.FileContentCaptured)
	}
	if rep.Facets.FileContentStoreValid {
		t.Error("FileContentStoreValid = true, want false for a missing blob")
	}
	if !rep.Facets.SignatureValid || !rep.Facets.ChainValid {
		t.Error("signature/chain must remain valid; a missing blob degrades completeness, not integrity")
	}
}

// TestVerify_TamperSuspected_ContentStoreMismatchedBlob: a blob present at the
// address a signed digest names, but hashing to something else, is an artifact
// contradicting the signed record — the same integrity-violation class as an
// output-manifest mismatch. It must drive TAMPER_SUSPECTED.
func TestVerify_TamperSuspected_ContentStoreMismatchedBlob(t *testing.T) {
	f := newFixture(t)
	digest := evidence.SHA256Hex([]byte("original content"))
	writeBlobAt(t, f.dir, digest, []byte("swapped content"))

	base := happyEvents(f.outDigest)
	stopIdx := len(base) - 2
	events := append([]eventSpec{}, base[:stopIdx]...)
	events = append(events, eventSpec{
		name:          evidence.EventFileChanged,
		contentDigest: digest,
		attrs:         map[string]any{evidence.AttrContentCapture: string(evidence.CaptureFull)},
	})
	events = append(events, base[stopIdx:]...)
	f.writeSegment(events)

	rep, err := Verify(f.dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictTamperSuspected {
		t.Fatalf("verdict = %s, want TAMPER_SUSPECTED\n%s", rep.Verdict, rep.String())
	}
	if checkPassed(rep, stepContentStore) {
		t.Error("file-content-store check should have failed on a mismatched blob")
	}
	if rep.Facets.FileContentCaptured != 1 {
		t.Errorf("captured = %d, want 1", rep.Facets.FileContentCaptured)
	}
	if rep.Facets.FileContentStoreValid {
		t.Error("FileContentStoreValid = true, want false for a mismatched blob")
	}
}

// TestCheckFileContentStore_DetailLeadsWithMismatchWhenBothClassesPresent pins the
// detail-ordering contract: when a session has both a mismatched and a missing
// blob, the worse finding (tamper) must lead the message, not be buried after the
// merely-incomplete one.
func TestCheckFileContentStore_DetailLeadsWithMismatchWhenBothClassesPresent(t *testing.T) {
	dir := t.TempDir()
	mismatchDigest := evidence.SHA256Hex([]byte("what the segment signed"))
	writeBlobAt(t, dir, mismatchDigest, []byte("something else entirely"))
	missingDigest := evidence.SHA256Hex([]byte("never stored"))

	records := []record{
		{seq: 1, name: evidence.EventFileChanged, attrs: map[string]any{
			evidence.AttrProducer:       string(evidence.ChannelGuestSupervisor),
			evidence.AttrEvidenceClass:  string(evidence.ClassKernelObserved),
			evidence.AttrContentCapture: string(evidence.CaptureFull),
			evidence.AttrContentDigest:  mismatchDigest,
		}},
		{seq: 2, name: evidence.EventFileChanged, attrs: map[string]any{
			evidence.AttrProducer:       string(evidence.ChannelGuestSupervisor),
			evidence.AttrEvidenceClass:  string(evidence.ClassKernelObserved),
			evidence.AttrContentCapture: string(evidence.CaptureFull),
			evidence.AttrContentDigest:  missingDigest,
		}},
	}

	res := checkFileContentStore(records, dir)
	if !res.tamper || !res.incomplete {
		t.Fatalf("tamper/incomplete = %v/%v, want both true", res.tamper, res.incomplete)
	}
	mismatchIdx := strings.Index(res.detail, "do not hash to their signed digest")
	missingIdx := strings.Index(res.detail, "absent or unreadable")
	if mismatchIdx < 0 || missingIdx < 0 || mismatchIdx > missingIdx {
		t.Fatalf("detail = %q, want the mismatch clause before the missing clause", res.detail)
	}
}

// TestCheckFileContentStore_UnusableDigestCountsAsMissingNotTamper: a capture="full"
// event whose digest attribute is malformed names no blob address at all. Nothing
// can be produced for it, which is the same "store is short by one entry" shape as
// a blob that is simply absent — it must never be treated as a hash mismatch.
func TestCheckFileContentStore_UnusableDigestCountsAsMissingNotTamper(t *testing.T) {
	dir := t.TempDir()
	records := []record{{seq: 1, name: evidence.EventFileChanged, attrs: map[string]any{
		evidence.AttrProducer:       string(evidence.ChannelGuestSupervisor),
		evidence.AttrEvidenceClass:  string(evidence.ClassKernelObserved),
		evidence.AttrContentCapture: string(evidence.CaptureFull),
		evidence.AttrContentDigest:  "sha256:not-sixty-four-hex-chars",
	}}}

	res := checkFileContentStore(records, dir)
	if res.captured != 1 {
		t.Errorf("captured = %d, want 1", res.captured)
	}
	if res.missingBlobs != 1 || !res.incomplete {
		t.Errorf("missingBlobs/incomplete = %d/%v, want 1/true", res.missingBlobs, res.incomplete)
	}
	if res.mismatchedBlobs != 0 || res.tamper {
		t.Errorf("mismatchedBlobs/tamper = %d/%v, want 0/false", res.mismatchedBlobs, res.tamper)
	}
	if !strings.Contains(res.detail, "unusable digest") {
		t.Errorf("detail = %q, want mention of the unusable digest", res.detail)
	}
}

// TestCheckFileContentStore_WithheldAndMissReasonsAreCountedSeparately pins each
// file.capture.reason value to its bucket: a deliberate policy withholding leaves a
// complete store (the host chose not to keep what it was never meant to), while a
// capture miss is a lossy one — but neither ever affects store validity, since
// neither class claims a blob was written.
func TestCheckFileContentStore_WithheldAndMissReasonsAreCountedSeparately(t *testing.T) {
	tests := []struct {
		reason       string
		wantWithheld bool // else counted as a miss
	}{
		{reason: reasonSecretPolicy, wantWithheld: true},
		{reason: reasonExcludedByPolicy, wantWithheld: true},
		{reason: reasonSizeCap, wantWithheld: true},
		{reason: reasonChangedBeforeCapture, wantWithheld: false},
		{reason: reasonMissingBeforeCapture, wantWithheld: false},
		{reason: reasonReadError, wantWithheld: false},
		{reason: reasonStoreError, wantWithheld: false},
	}
	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			dir := t.TempDir()
			records := []record{{seq: 1, name: evidence.EventFileChanged, attrs: map[string]any{
				evidence.AttrProducer:       string(evidence.ChannelGuestSupervisor),
				evidence.AttrEvidenceClass:  string(evidence.ClassKernelObserved),
				evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
				attrFileCaptureReason:       tt.reason,
			}}}

			res := checkFileContentStore(records, dir)
			switch {
			case tt.wantWithheld && (res.withheld != 1 || res.misses != 0):
				t.Errorf("withheld/misses = %d/%d, want 1/0", res.withheld, res.misses)
			case !tt.wantWithheld && (res.misses != 1 || res.withheld != 0):
				t.Errorf("withheld/misses = %d/%d, want 0/1", res.withheld, res.misses)
			}
			if res.captured != 0 {
				t.Errorf("captured = %d, want 0", res.captured)
			}
			if !res.storeValid || res.incomplete || res.tamper {
				t.Errorf("storeValid/incomplete/tamper = %v/%v/%v, want true/false/false: withheld and miss reasons must never affect store validity",
					res.storeValid, res.incomplete, res.tamper)
			}
		})
	}
}

// TestCheckFileContentStore_DetailReportsWithheldAndMissAlongsideCaptured composes
// a real captured blob with one withheld and one missed file.changed, confirming
// the success detail still names both counts and the store stays valid.
func TestCheckFileContentStore_DetailReportsWithheldAndMissAlongsideCaptured(t *testing.T) {
	dir := t.TempDir()
	digest := writeMatchingBlob(t, dir, []byte("captured bytes"))
	records := []record{
		{seq: 1, name: evidence.EventFileChanged, attrs: map[string]any{
			evidence.AttrProducer:       string(evidence.ChannelGuestSupervisor),
			evidence.AttrEvidenceClass:  string(evidence.ClassKernelObserved),
			evidence.AttrContentCapture: string(evidence.CaptureFull),
			evidence.AttrContentDigest:  digest,
		}},
		{seq: 2, name: evidence.EventFileChanged, attrs: map[string]any{
			evidence.AttrProducer:       string(evidence.ChannelGuestSupervisor),
			evidence.AttrEvidenceClass:  string(evidence.ClassKernelObserved),
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
			attrFileCaptureReason:       reasonSecretPolicy,
		}},
		{seq: 3, name: evidence.EventFileChanged, attrs: map[string]any{
			evidence.AttrProducer:       string(evidence.ChannelGuestSupervisor),
			evidence.AttrEvidenceClass:  string(evidence.ClassKernelObserved),
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
			attrFileCaptureReason:       reasonReadError,
		}},
	}

	res := checkFileContentStore(records, dir)
	if res.captured != 1 || res.withheld != 1 || res.misses != 1 {
		t.Fatalf("captured/withheld/misses = %d/%d/%d, want 1/1/1", res.captured, res.withheld, res.misses)
	}
	if !res.storeValid {
		t.Error("storeValid = false, want true: withheld and miss counts must not affect validity")
	}
	if !strings.Contains(res.detail, "withheld by policy") || !strings.Contains(res.detail, "capture miss(es)") {
		t.Errorf("detail = %q, want mention of both withheld and miss counts", res.detail)
	}
}

// TestCheckFileContentStore_WorkloadChannelFileChangedIsIgnored: the capture stamp
// is the host's account of what it stored, not the workload's to make. A
// workload-authored file.changed claiming capture="full" must not be resolved
// against the blob store at all — not even as a miss.
func TestCheckFileContentStore_WorkloadChannelFileChangedIsIgnored(t *testing.T) {
	dir := t.TempDir()
	digest := evidence.SHA256Hex([]byte("workload's own claim"))
	records := []record{{seq: 1, name: evidence.EventFileChanged, attrs: map[string]any{
		evidence.AttrProducer:       string(evidence.ChannelWorkload),
		evidence.AttrEvidenceClass:  string(evidence.ClassModelSelfReported),
		evidence.AttrContentCapture: string(evidence.CaptureFull),
		evidence.AttrContentDigest:  digest,
	}}}
	// No blob written anywhere — if the workload record were wrongly honored, this
	// would surface as a missing blob rather than being skipped outright.

	res := checkFileContentStore(records, dir)
	if res.captured != 0 || res.missingBlobs != 0 {
		t.Errorf("captured/missingBlobs = %d/%d, want 0/0: only guest-kernel file.changed counts", res.captured, res.missingBlobs)
	}
	if res.detail != "no captured content to check" {
		t.Errorf("detail = %q, want the plain skip message", res.detail)
	}
	if !res.storeValid || res.incomplete || res.tamper {
		t.Errorf("storeValid/incomplete/tamper = %v/%v/%v, want true/false/false", res.storeValid, res.incomplete, res.tamper)
	}
}

// TestCheckFileContentStore_SkipsHonestlyWhenNothingCaptured mirrors
// checkOutputManifest's skip contract: a session that captured nothing says so
// explicitly, and separately says whether an unreferenced blob store exists.
func TestCheckFileContentStore_SkipsHonestlyWhenNothingCaptured(t *testing.T) {
	// An unrelated guest-kernel event, so the check is genuinely exercised against a
	// non-empty record set rather than trivially against no records at all.
	other := []record{{seq: 1, name: evidence.EventProcessExecuted, attrs: map[string]any{
		evidence.AttrProducer:      string(evidence.ChannelGuestSupervisor),
		evidence.AttrEvidenceClass: string(evidence.ClassKernelObserved),
		"observer":                 "tetragon",
	}}}

	t.Run("no blobs dir", func(t *testing.T) {
		dir := t.TempDir()
		res := checkFileContentStore(other, dir)
		if res.detail != "no captured content to check" {
			t.Errorf("detail = %q, want the plain skip message", res.detail)
		}
		if !res.storeValid || res.incomplete || res.tamper {
			t.Errorf("storeValid/incomplete/tamper = %v/%v/%v, want true/false/false", res.storeValid, res.incomplete, res.tamper)
		}
	})

	t.Run("blobs dir present but unreferenced", func(t *testing.T) {
		dir := t.TempDir()
		writeMatchingBlob(t, dir, []byte("orphaned blob no event points at"))
		res := checkFileContentStore(other, dir)
		want := "no captured content to check (blob store directory present but unreferenced)"
		if res.detail != want {
			t.Errorf("detail = %q, want %q", res.detail, want)
		}
		if !res.storeValid || res.incomplete || res.tamper {
			t.Errorf("storeValid/incomplete/tamper = %v/%v/%v, want true/false/false", res.storeValid, res.incomplete, res.tamper)
		}
	})
}

// TestCheckFileContentStore_LegacyRecordsWithNoCaptureAttrsBehaveAsSkip: events
// recorded before the file-content-capture feature existed carry neither
// audit.content.capture nor file.capture.reason. They must fall into neither
// bucket, and the check must still skip cleanly rather than guessing.
func TestCheckFileContentStore_LegacyRecordsWithNoCaptureAttrsBehaveAsSkip(t *testing.T) {
	dir := t.TempDir()
	records := []record{{seq: 1, name: evidence.EventFileChanged, attrs: map[string]any{
		evidence.AttrProducer:      string(evidence.ChannelGuestSupervisor),
		evidence.AttrEvidenceClass: string(evidence.ClassKernelObserved),
	}}}

	res := checkFileContentStore(records, dir)
	if res.captured != 0 || res.withheld != 0 || res.misses != 0 {
		t.Errorf("captured/withheld/misses = %d/%d/%d, want 0/0/0", res.captured, res.withheld, res.misses)
	}
	if res.detail != "no captured content to check" {
		t.Errorf("detail = %q, want the plain skip message", res.detail)
	}
	if !res.storeValid || res.incomplete || res.tamper {
		t.Errorf("storeValid/incomplete/tamper = %v/%v/%v, want true/false/false", res.storeValid, res.incomplete, res.tamper)
	}
}
