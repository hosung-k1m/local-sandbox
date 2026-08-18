package view

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmaxmax/go-sse"

	"boxedai/internal/evidence"
	"boxedai/internal/session"
)

func TestStreamServerSendsSnapshotBeforeBoundedDeltas(t *testing.T) {
	_, id, sessionDir := newStreamTestSession(t, session.StateRunning, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	stream := newStreamServerWithConfig(streamConfig{
		fallbackInterval:  10 * time.Millisecond,
		heartbeatInterval: time.Hour,
	})
	appended := make([]testEvent, 0, streamBatchSize+1)
	for sequence := int64(2); sequence <= streamBatchSize+2; sequence++ {
		appended = append(appended, testEvent{
			seq: sequence, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
			producer: evidence.ChannelGuestSupervisor,
		})
	}
	frames := streamTestEventFrames(t, id, appended)
	originalBuild := buildStreamWebPayload
	var appendOnce sync.Once
	buildStreamWebPayload = func(dir string) (webPayload, error) {
		payload, err := originalBuild(dir)
		if err != nil {
			return webPayload{}, err
		}
		appendOnce.Do(func() {
			err = appendStreamTestFrames(dir, frames)
		})
		return payload, err
	}
	t.Cleanup(func() { buildStreamWebPayload = originalBuild })
	server := httptest.NewServer(stream.standaloneHandler(sessionDir))
	t.Cleanup(server.Close)

	response := openStreamResponse(t, server.Client(), server.URL, "")
	results := readStreamEvents(response.Body)
	first := nextStreamEvent(t, results)
	if first.Type != "session.snapshot" {
		t.Fatalf("first event type = %q, want session.snapshot", first.Type)
	}
	var snapshot webPayload
	decodeStreamData(t, first, &snapshot)
	if snapshot.SessionID != id || len(snapshot.Events) != 1 || snapshot.Events[0].Seq != 1 {
		t.Fatalf("snapshot = %+v, want %s through sequence 1", snapshot, id)
	}

	firstDeltaEvent := nextStreamEvent(t, results)
	secondDeltaEvent := nextStreamEvent(t, results)
	if firstDeltaEvent.Type != "session.delta" || secondDeltaEvent.Type != "session.delta" {
		t.Fatalf("delta event types = %q/%q, want session.delta/session.delta", firstDeltaEvent.Type, secondDeltaEvent.Type)
	}
	var firstDelta, secondDelta streamSessionDelta
	decodeStreamData(t, firstDeltaEvent, &firstDelta)
	decodeStreamData(t, secondDeltaEvent, &secondDelta)
	if len(firstDelta.Events) != streamBatchSize || firstDelta.Events[0].Seq != 2 || firstDelta.LastEventSeq != streamBatchSize+1 {
		t.Fatalf("first delta = %+v, want %d records through sequence %d", firstDelta, streamBatchSize, streamBatchSize+1)
	}
	if len(secondDelta.Events) != 1 || secondDelta.Events[0].Seq != streamBatchSize+2 || secondDelta.EventCount != streamBatchSize+2 {
		t.Fatalf("second delta = %+v, want final sequence/count %d", secondDelta, streamBatchSize+2)
	}
	if firstDeltaEvent.LastEventID == "" || secondDeltaEvent.LastEventID == "" || firstDeltaEvent.LastEventID == secondDeltaEvent.LastEventID {
		t.Fatalf("delta ids = %q/%q, want distinct resumable cursors", firstDeltaEvent.LastEventID, secondDeltaEvent.LastEventID)
	}

	response.Body.Close()
	waitForStreamActive(t, stream, 0)
	stats := stream.stats()
	if stats.Snapshots != 1 || stats.Deltas != 2 || stats.Rebuilds != 1 {
		t.Fatalf("stream stats = %+v, want one snapshot/rebuild and two deltas", stats)
	}
}

func TestStreamServerCleanTailMatchesFreshRebuildWithoutSnapshotPolling(t *testing.T) {
	_, id, sessionDir := newStreamTestSession(t, session.StateRunning, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	stream := newStreamServerWithConfig(streamConfig{
		fallbackInterval:  10 * time.Millisecond,
		heartbeatInterval: time.Hour,
	})
	var streamRequests atomic.Int64
	var snapshotRequests atomic.Int64
	handler := stream.standaloneHandler(sessionDir)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/stream":
			streamRequests.Add(1)
		case "/api/events":
			snapshotRequests.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	response := openStreamResponse(t, server.Client(), server.URL+"/api/stream", "")
	results := readStreamEvents(response.Body)
	first := nextStreamEvent(t, results)
	if first.Type != "session.snapshot" {
		t.Fatalf("first event type = %q, want session.snapshot", first.Type)
	}
	var snapshot webPayload
	decodeStreamData(t, first, &snapshot)

	if err := appendStreamTestFrames(sessionDir, streamTestEventFrames(t, id, []testEvent{{
		seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved,
		producer: evidence.ChannelGuestSupervisor, body: `<script>alert("tail")</script>`,
		attrs: map[string]any{"untrusted.value": `<img src=x onerror="boom">`},
	}})); err != nil {
		t.Fatalf("append clean stream tail: %v", err)
	}
	deltaEvent := nextStreamEvent(t, results)
	if deltaEvent.Type != "session.delta" {
		t.Fatalf("tail event type = %q, want session.delta", deltaEvent.Type)
	}
	var delta streamSessionDelta
	decodeStreamData(t, deltaEvent, &delta)

	db, err := Rebuild(sessionDir)
	if err != nil {
		t.Fatalf("fresh Rebuild: %v", err)
	}
	rows, err := queryEvents(db, Filter{})
	db.Close()
	if err != nil {
		t.Fatalf("query fresh rebuild: %v", err)
	}
	want, err := webEventsFromRows(rows)
	if err != nil {
		t.Fatalf("shape fresh rebuild events: %v", err)
	}
	got := append(append([]webEvent{}, snapshot.Events...), delta.Events...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot plus clean tail = %#v, want fresh rebuild %#v", got, want)
	}
	if delta.EventCount != 2 || delta.LastEventSeq != 2 {
		t.Fatalf("clean tail summary = %+v, want count/sequence 2", delta)
	}

	response.Body.Close()
	waitForStreamActive(t, stream, 0)
	stats := stream.stats()
	if stats.Snapshots != 1 || stats.Deltas != 1 || stats.Rebuilds != 1 {
		t.Fatalf("clean tail stats = %+v, want one initial rebuild/snapshot and one delta", stats)
	}
	if streamRequests.Load() != 1 || snapshotRequests.Load() != 0 {
		t.Fatalf("healthy-path requests = stream:%d snapshot:%d, want 1/0", streamRequests.Load(), snapshotRequests.Load())
	}
}

func TestStreamServerResumesValidStaleCursorAndResetsUnsafeCursor(t *testing.T) {
	_, id, sessionDir := newStreamTestSession(t, session.StateRunning, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
		{seq: 2, name: evidence.EventProcessExecuted, class: evidence.ClassKernelObserved, producer: evidence.ChannelGuestSupervisor},
		{seq: 3, name: evidence.EventSessionStopped, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})

	staleCursor, err := encodeStreamCursor(id, 1)
	if err != nil {
		t.Fatalf("encode valid stale cursor: %v", err)
	}
	stream := newStreamServerWithConfig(streamConfig{heartbeatInterval: time.Hour})
	server := httptest.NewServer(stream.standaloneHandler(sessionDir))
	response := openStreamResponse(t, server.Client(), server.URL, staleCursor)
	result := nextStreamEvent(t, readStreamEvents(response.Body))
	if result.Type != "session.delta" {
		t.Fatalf("valid stale resume first event = %q, want session.delta", result.Type)
	}
	var delta streamSessionDelta
	decodeStreamData(t, result, &delta)
	if len(delta.Events) != 2 || delta.Events[0].Seq != 2 || delta.Events[1].Seq != 3 {
		t.Fatalf("valid stale resume delta = %+v, want sequences 2 and 3", delta)
	}
	response.Body.Close()
	server.Close()
	waitForStreamActive(t, stream, 0)
	if stats := stream.stats(); stats.Resets != 0 || stats.Snapshots != 0 {
		t.Fatalf("valid stale resume stats = %+v, want no reset or snapshot", stats)
	}

	wrongSessionCursor, err := encodeStreamCursor("bx-wrong-session", 1)
	if err != nil {
		t.Fatalf("encode wrong-session cursor: %v", err)
	}
	futureCursor, err := encodeStreamCursor(id, 4)
	if err != nil {
		t.Fatalf("encode future cursor: %v", err)
	}
	for _, test := range []struct {
		name        string
		cursor      string
		resetReason string
	}{
		{name: "malformed", cursor: "not-a-cursor", resetReason: "malformed"},
		{name: "wrong session", cursor: wrongSessionCursor, resetReason: "wrong_session"},
		{name: "future", cursor: futureCursor, resetReason: "discontinuous"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := newStreamServerWithConfig(streamConfig{heartbeatInterval: time.Hour})
			server := httptest.NewServer(stream.standaloneHandler(sessionDir))
			defer server.Close()
			response := openStreamResponse(t, server.Client(), server.URL, test.cursor)
			result := nextStreamEvent(t, readStreamEvents(response.Body))
			if result.Type != "session.snapshot" {
				t.Fatalf("unsafe resume first event = %q, want session.snapshot", result.Type)
			}
			response.Body.Close()
			waitForStreamActive(t, stream, 0)
			stats := stream.stats()
			if stats.Resets != 1 || stats.LastResetReason != test.resetReason {
				t.Fatalf("unsafe resume stats = %+v, want one %q reset", stats, test.resetReason)
			}
		})
	}

}

func TestStreamServerTerminalProofMatchesFreshAuthoritativePayload(t *testing.T) {
	_, id, sessionDir := newStreamTestSession(t, session.StateRunning, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	stream := newStreamServerWithConfig(streamConfig{
		fallbackInterval:  10 * time.Millisecond,
		heartbeatInterval: time.Hour,
	})
	server := httptest.NewServer(stream.standaloneHandler(sessionDir))
	defer server.Close()

	response := openStreamResponse(t, server.Client(), server.URL, "")
	results := readStreamEvents(response.Body)
	initialEvent := nextStreamEvent(t, results)
	var initial webPayload
	decodeStreamData(t, initialEvent, &initial)
	if initialEvent.Type != "session.snapshot" || !initial.Proof.Provisional || initial.Proof.Status != "provisional" {
		t.Fatalf("initial snapshot proof = %+v, want provisional", initial.Proof)
	}

	sealStreamTestSegment(t, sessionDir, id, 1)
	if err := os.WriteFile(filepath.Join(sessionDir, "session.state"), []byte(session.StateSealed), 0o644); err != nil {
		t.Fatalf("write sealed state: %v", err)
	}
	lifecycleEvent := nextStreamEvent(t, results)
	if lifecycleEvent.Type != "session.delta" {
		t.Fatalf("terminal lifecycle event type = %q, want session.delta", lifecycleEvent.Type)
	}
	terminalEvent := nextStreamEvent(t, results)
	if terminalEvent.Type != "session.snapshot" {
		t.Fatalf("terminal proof event type = %q, want session.snapshot", terminalEvent.Type)
	}
	var terminal webPayload
	decodeStreamData(t, terminalEvent, &terminal)
	fresh, err := buildWebPayload(sessionDir)
	if err != nil {
		t.Fatalf("fresh terminal payload: %v", err)
	}
	if terminal.State != string(session.StateSealed) || terminal.Proof.Provisional {
		t.Fatalf("terminal state/proof = %q/%+v, want sealed non-provisional", terminal.State, terminal.Proof)
	}
	if !reflect.DeepEqual(terminal.Events, fresh.Events) || !reflect.DeepEqual(terminal.Proof, fresh.Proof) || terminal.VerifyError != fresh.VerifyError {
		t.Fatalf("terminal stream payload did not converge to fresh authoritative payload\nstream: %+v\nfresh: %+v", terminal, fresh)
	}
	encoded, err := json.Marshal(terminal)
	if err != nil {
		t.Fatalf("marshal terminal payload: %v", err)
	}
	if terminalEvent.LastEventID == "" || strings.Contains(string(encoded), terminalEvent.LastEventID) {
		t.Fatalf("delivery cursor leaked into authoritative payload: id=%q payload=%s", terminalEvent.LastEventID, encoded)
	}
	waitForStreamActive(t, stream, 0)
}

func TestStreamServerConvergesSealedRevisionToIncompleteAndCleansUp(t *testing.T) {
	_, _, sessionDir := newStreamTestSession(t, session.StateRunning, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	stream := newStreamServerWithConfig(streamConfig{
		fallbackInterval:  10 * time.Millisecond,
		heartbeatInterval: time.Hour,
	})
	server := httptest.NewServer(stream.standaloneHandler(sessionDir))
	defer server.Close()

	response := openStreamResponse(t, server.Client(), server.URL, "")
	results := readStreamEvents(response.Body)
	if first := nextStreamEvent(t, results); first.Type != "session.snapshot" {
		t.Fatalf("first event type = %q, want session.snapshot", first.Type)
	}
	originalBuild := buildStreamWebPayload
	buildStreamWebPayload = func(dir string) (webPayload, error) {
		if err := os.WriteFile(filepath.Join(dir, "session.state"), []byte(session.StateIncomplete), 0o644); err != nil {
			return webPayload{}, err
		}
		return originalBuild(dir)
	}
	t.Cleanup(func() { buildStreamWebPayload = originalBuild })
	if err := os.WriteFile(filepath.Join(sessionDir, "session.state"), []byte(session.StateSealed), 0o644); err != nil {
		t.Fatalf("write terminal state: %v", err)
	}

	lifecycleEvent := nextStreamEvent(t, results)
	if lifecycleEvent.Type != "session.delta" {
		t.Fatalf("lifecycle event type = %q, want session.delta", lifecycleEvent.Type)
	}
	var lifecycle streamSessionDelta
	decodeStreamData(t, lifecycleEvent, &lifecycle)
	if lifecycle.State != string(session.StateSealed) || len(lifecycle.Events) != 0 {
		t.Fatalf("lifecycle delta = %+v, want sealed state without new log records", lifecycle)
	}

	terminalEvent := nextStreamEvent(t, results)
	if terminalEvent.Type != "session.snapshot" {
		t.Fatalf("terminal event type = %q, want final session.snapshot", terminalEvent.Type)
	}
	var terminal webPayload
	decodeStreamData(t, terminalEvent, &terminal)
	if terminal.State != string(session.StateIncomplete) {
		t.Fatalf("terminal snapshot state = %q, want revised incomplete state", terminal.State)
	}
	waitForStreamActive(t, stream, 0)
	if stats := stream.stats(); stats.Active != 0 || stats.Deltas != 1 || stats.Snapshots != 2 {
		t.Fatalf("terminal stream stats = %+v, want released stream with lifecycle delta and final snapshot", stats)
	}
}

func TestDashboardStreamPublishesLifecycleChangesAndRemoval(t *testing.T) {
	_, id, sessionDir := newStreamTestSession(t, session.StateRunning, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	stream := newStreamServerWithConfig(streamConfig{
		fallbackInterval:  10 * time.Millisecond,
		heartbeatInterval: time.Hour,
	})
	server := httptest.NewServer(stream.dashboardHandler())
	defer server.Close()

	response := openStreamResponse(t, server.Client(), server.URL, "")
	results := readStreamEvents(response.Body)
	first := nextStreamEvent(t, results)
	if first.Type != "sessions.snapshot" {
		t.Fatalf("first dashboard event type = %q, want sessions.snapshot", first.Type)
	}
	if rebuilds := stream.stats().Rebuilds; rebuilds != 1 {
		t.Fatalf("dashboard snapshot rebuilds = %d, want 1", rebuilds)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "session.state"), []byte(session.StateSealed), 0o644); err != nil {
		t.Fatalf("write dashboard lifecycle state: %v", err)
	}
	upsertEvent := nextStreamEvent(t, results)
	if upsertEvent.Type != "sessions.upsert" {
		t.Fatalf("dashboard lifecycle event type = %q, want sessions.upsert", upsertEvent.Type)
	}
	var upsert dashboardSession
	decodeStreamData(t, upsertEvent, &upsert)
	if upsert.SessionID != id || upsert.State != string(session.StateSealed) || upsert.EventCount != 1 {
		t.Fatalf("dashboard lifecycle upsert = %+v, want sealed %s retaining count 1", upsert, id)
	}
	if err := os.RemoveAll(sessionDir); err != nil {
		t.Fatalf("remove dashboard session: %v", err)
	}
	removeEvent := nextStreamEvent(t, results)
	if removeEvent.Type != "sessions.remove" {
		t.Fatalf("dashboard removal event type = %q, want sessions.remove", removeEvent.Type)
	}
	var removal streamSessionRemoval
	decodeStreamData(t, removeEvent, &removal)
	if removal.SessionID != id {
		t.Fatalf("dashboard removal = %+v, want %s", removal, id)
	}
	response.Body.Close()
	waitForStreamActive(t, stream, 0)
}

func TestDashboardFallbackSkipsHistoricalProofWorkAndCountsNewSessionRebuild(t *testing.T) {
	_, _, _ = newStreamTestSession(t, session.StateSealed, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	originalProof := buildDashboardSummaryProof
	var proofBuilds atomic.Int64
	buildDashboardSummaryProof = func(sessionDir string, state session.State) proofState {
		proofBuilds.Add(1)
		return originalProof(sessionDir, state)
	}
	t.Cleanup(func() { buildDashboardSummaryProof = originalProof })

	stream := newStreamServerWithConfig(streamConfig{
		fallbackInterval:  10 * time.Millisecond,
		heartbeatInterval: time.Hour,
	})
	server := httptest.NewServer(stream.dashboardHandler())
	defer server.Close()
	response := openStreamResponse(t, server.Client(), server.URL, "")
	results := readStreamEvents(response.Body)
	if first := nextStreamEvent(t, results); first.Type != "sessions.snapshot" {
		t.Fatalf("first dashboard event type = %q, want sessions.snapshot", first.Type)
	}
	time.Sleep(75 * time.Millisecond)
	if builds := proofBuilds.Load(); builds != 1 {
		t.Fatalf("historical proof builds after repeated idle fallback ticks = %d, want initial build only", builds)
	}

	newID := "bx-20260817-120001-bbccddee"
	writeStreamTestSession(t, newID, session.StateRunning, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	upsertEvent := nextStreamEvent(t, results)
	if upsertEvent.Type != "sessions.upsert" {
		t.Fatalf("new session event type = %q, want sessions.upsert", upsertEvent.Type)
	}
	var upsert dashboardSession
	decodeStreamData(t, upsertEvent, &upsert)
	if upsert.SessionID != newID {
		t.Fatalf("new session upsert = %+v, want %s", upsert, newID)
	}
	if rebuilds := stream.stats().Rebuilds; rebuilds != 1 {
		t.Fatalf("new-session projection rebuilds = %d, want 1", rebuilds)
	}
	response.Body.Close()
	waitForStreamActive(t, stream, 0)
}

func TestStreamServerBoundsConnectionsHeartbeatAndWrites(t *testing.T) {
	_, _, sessionDir := newStreamTestSession(t, session.StateRunning, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})

	t.Run("connection limit and disconnect cleanup", func(t *testing.T) {
		stream := newStreamServerWithConfig(streamConfig{
			maxConnections:    1,
			heartbeatInterval: time.Hour,
		})
		server := httptest.NewServer(stream.standaloneHandler(sessionDir))
		defer server.Close()
		first := openStreamResponse(t, server.Client(), server.URL, "")
		waitForStreamActive(t, stream, 1)

		second, err := server.Client().Get(server.URL)
		if err != nil {
			t.Fatalf("open excess stream: %v", err)
		}
		second.Body.Close()
		if second.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("excess stream status = %d, want 503", second.StatusCode)
		}

		first.Body.Close()
		waitForStreamActive(t, stream, 0)
	})

	t.Run("default limit rejects sixty-fifth viewer", func(t *testing.T) {
		stream := newStreamServerWithConfig(streamConfig{
			fallbackInterval:  time.Hour,
			heartbeatInterval: time.Hour,
		})
		server := httptest.NewServer(stream.standaloneHandler(sessionDir))
		responses := make([]*http.Response, 0, streamMaxConnections)
		t.Cleanup(func() {
			for _, response := range responses {
				response.Body.Close()
			}
			server.CloseClientConnections()
			server.Close()
		})
		for viewer := 0; viewer < streamMaxConnections; viewer++ {
			responses = append(responses, openStreamResponse(t, server.Client(), server.URL, ""))
		}
		waitForStreamActive(t, stream, streamMaxConnections)
		excess, err := server.Client().Get(server.URL)
		if err != nil {
			t.Fatalf("open sixty-fifth stream: %v", err)
		}
		excess.Body.Close()
		if excess.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("sixty-fifth stream status = %d, want 503", excess.StatusCode)
		}
		for _, response := range responses {
			response.Body.Close()
		}
		responses = nil
		waitForStreamActive(t, stream, 0)
	})

	t.Run("heartbeat", func(t *testing.T) {
		stream := newStreamServerWithConfig(streamConfig{
			fallbackInterval:  time.Hour,
			heartbeatInterval: 10 * time.Millisecond,
		})
		server := httptest.NewServer(stream.standaloneHandler(sessionDir))
		defer server.Close()
		response := openStreamResponse(t, server.Client(), server.URL, "")
		reader := bufio.NewReader(response.Body)
		_ = nextSSEBlock(t, reader)
		heartbeat := nextSSEBlock(t, reader)
		if !strings.Contains(heartbeat, ": keepalive\n") {
			t.Fatalf("heartbeat block = %q, want keepalive comment", heartbeat)
		}
		response.Body.Close()
		waitForStreamActive(t, stream, 0)
	})

	t.Run("stalled write deadline", func(t *testing.T) {
		stream := newStreamServerWithConfig(streamConfig{
			heartbeatInterval: time.Hour,
			writeTimeout:      25 * time.Millisecond,
		})
		segmentPath := filepath.Join(sessionDir, "evidence", "segments", "segment-000001.otlp")
		segmentBefore, err := os.ReadFile(segmentPath)
		if err != nil {
			t.Fatalf("read segment before stream failure: %v", err)
		}
		stateBefore, err := os.ReadFile(filepath.Join(sessionDir, "session.state"))
		if err != nil {
			t.Fatalf("read state before stream failure: %v", err)
		}
		writer := &deadlineFailWriter{header: http.Header{}}
		request := httptest.NewRequest(http.MethodGet, "/api/stream", nil)
		stream.standaloneHandler(sessionDir).ServeHTTP(writer, request)
		if writer.deadline.IsZero() {
			t.Fatal("stream write deadline was not set before the stalled flush")
		}
		if !writer.timedOut {
			t.Fatal("stalled stream write did not remain blocked through its deadline")
		}
		if stats := stream.stats(); stats.Active != 0 {
			t.Fatalf("stalled stream active count = %d, want 0", stats.Active)
		}
		segmentAfter, err := os.ReadFile(segmentPath)
		if err != nil {
			t.Fatalf("read segment after stream failure: %v", err)
		}
		stateAfter, err := os.ReadFile(filepath.Join(sessionDir, "session.state"))
		if err != nil {
			t.Fatalf("read state after stream failure: %v", err)
		}
		if !reflect.DeepEqual(segmentAfter, segmentBefore) || !reflect.DeepEqual(stateAfter, stateBefore) {
			t.Fatal("presentation stream failure modified authoritative evidence or lifecycle state")
		}
	})
}

func TestBrowserStreamingNetworkEvidence(t *testing.T) {
	evidenceDir := os.Getenv("BOXEDAI_BROWSER_EVIDENCE_DIR")
	if evidenceDir == "" {
		t.Skip("set BOXEDAI_BROWSER_EVIDENCE_DIR for the interactive browser evidence pass")
	}
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		t.Fatalf("mkdir browser evidence directory: %v", err)
	}
	_, id, sessionDir := newStreamTestSession(t, session.StateRunning, []testEvent{
		{seq: 1, name: evidence.EventSessionStarted, class: evidence.ClassIntegrity, producer: evidence.ChannelController},
	})
	dashboardRequests := newBrowserRequestCounter(newDashboardMux())
	standaloneRequests := newBrowserRequestCounter(newWebMux(sessionDir))
	dashboardServer := httptest.NewServer(dashboardRequests)
	standaloneServer := httptest.NewServer(standaloneRequests)
	t.Cleanup(func() {
		dashboardServer.CloseClientConnections()
		standaloneServer.CloseClientConnections()
		dashboardServer.Close()
		standaloneServer.Close()
	})

	harness := map[string]string{
		"dashboard_url":  dashboardServer.URL,
		"session_id":     id,
		"standalone_url": standaloneServer.URL,
	}
	writeBrowserEvidenceJSON(t, filepath.Join(evidenceDir, "browser-harness.json"), harness)
	fmt.Printf("dashboard: %s\nstandalone: %s\n", dashboardServer.URL, standaloneServer.URL)

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if dashboardRequests.count("/") > 0 && dashboardRequests.count("/api/stream") >= 2 &&
			standaloneRequests.count("/") > 0 && standaloneRequests.count("/api/stream") > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if dashboardRequests.count("/api/stream") < 2 || standaloneRequests.count("/api/stream") == 0 {
		t.Fatalf("browser surfaces did not establish expected streams: dashboard=%v standalone=%v", dashboardRequests.snapshot(), standaloneRequests.snapshot())
	}

	baselineDashboardStreams := dashboardRequests.count("/api/stream")
	baselineStandaloneStreams := standaloneRequests.count("/api/stream")
	observationWindow := 3500 * time.Millisecond
	time.Sleep(observationWindow)
	dashboard := dashboardRequests.snapshot()
	standalone := standaloneRequests.snapshot()
	if dashboard["/api/sessions"] != 0 || dashboard["/api/session"] != 0 || standalone["/api/events"] != 0 {
		t.Fatalf("healthy browser path issued snapshot requests: dashboard=%v standalone=%v", dashboard, standalone)
	}
	if dashboard["/api/stream"] != baselineDashboardStreams || standalone["/api/stream"] != baselineStandaloneStreams {
		t.Fatalf("healthy browser path opened recurring streams: dashboard=%v standalone=%v", dashboard, standalone)
	}

	report := struct {
		SessionID           string         `json:"session_id"`
		ObservationWindowMS int64          `json:"observation_window_ms"`
		DashboardRequests   map[string]int `json:"dashboard_requests"`
		StandaloneRequests  map[string]int `json:"standalone_requests"`
		SnapshotPolling     bool           `json:"snapshot_polling_detected"`
	}{
		SessionID:           id,
		ObservationWindowMS: observationWindow.Milliseconds(),
		DashboardRequests:   dashboard,
		StandaloneRequests:  standalone,
		SnapshotPolling:     false,
	}
	writeBrowserEvidenceJSON(t, filepath.Join(evidenceDir, "browser-network.json"), report)
}

type streamTestResult struct {
	event sse.Event
	err   error
}

func newStreamTestSession(t *testing.T, state session.State, events []testEvent) (string, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("BOXEDAI_HOME", home)
	id := "bx-20260817-120000-aabbccdd"
	sessionDir := writeStreamTestSession(t, id, state, events)
	return home, id, sessionDir
}

func writeStreamTestSession(t *testing.T, id string, state session.State, events []testEvent) string {
	t.Helper()
	sessionDir := session.SessionDir(id)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatalf("mkdir stream session: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "session.state"), []byte(state), 0o644); err != nil {
		t.Fatalf("write stream session state: %v", err)
	}
	writeSegment(t, sessionDir, "segment-000001.otlp", id, "sha256:policydigest", events)
	return sessionDir
}

func streamTestEventFrames(t *testing.T, sessionID string, events []testEvent) []byte {
	t.Helper()
	sourceDir := t.TempDir()
	writeSegment(t, sourceDir, "segment-000001.otlp", sessionID, "sha256:policydigest", events)
	contents, err := os.ReadFile(filepath.Join(sourceDir, "evidence", "segments", "segment-000001.otlp"))
	if err != nil {
		t.Fatalf("read stream test frames: %v", err)
	}
	return contents
}

func appendStreamTestFrames(sessionDir string, contents []byte) error {
	path := filepath.Join(sessionDir, "evidence", "segments", "segment-000001.otlp")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func sealStreamTestSegment(t *testing.T, sessionDir, sessionID string, lastSequence int64) {
	t.Helper()
	manifest := map[string]any{
		"schema":              "boxedai.segment/v1",
		"session_id":          sessionID,
		"segment_number":      1,
		"record_count":        lastSequence,
		"first_sequence":      int64(1),
		"last_sequence":       lastSequence,
		"segment_digest":      "sha256:test-segment",
		"policy_digest":       "sha256:policydigest",
		"created_at":          "2026-08-17T12:00:00Z",
		"sealed_at":           "2026-08-17T12:00:01Z",
		"prev_segment_digest": "",
	}
	contents, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal sealed stream manifest: %v", err)
	}
	segmentsDir := filepath.Join(sessionDir, "evidence", "segments")
	if err := os.WriteFile(filepath.Join(segmentsDir, "segment-000001.manifest.json"), contents, 0o644); err != nil {
		t.Fatalf("write sealed stream manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(segmentsDir, "segment-000001.manifest.cose"), []byte("cose"), 0o644); err != nil {
		t.Fatalf("write sealed stream signature: %v", err)
	}
}

func openStreamResponse(t *testing.T, client *http.Client, url, lastEventID string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new stream request: %v", err)
	}
	if lastEventID != "" {
		request.Header.Set("Last-Event-ID", lastEventID)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("stream status = %d, want 200: %s", response.StatusCode, body)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "text/event-stream" {
		response.Body.Close()
		t.Fatalf("stream content type = %q, want text/event-stream", contentType)
	}
	return response
}

func readStreamEvents(body io.Reader) <-chan streamTestResult {
	results := make(chan streamTestResult, streamBatchSize+4)
	go func() {
		defer close(results)
		for event, err := range sse.Read(body, nil) {
			results <- streamTestResult{event: event, err: err}
			if err != nil {
				return
			}
		}
	}()
	return results
}

func nextStreamEvent(t *testing.T, results <-chan streamTestResult) sse.Event {
	t.Helper()
	select {
	case result, ok := <-results:
		if !ok {
			t.Fatal("stream closed before the expected event")
		}
		if result.err != nil {
			t.Fatalf("read stream event: %v", result.err)
		}
		return result.event
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for stream event")
		return sse.Event{}
	}
}

func decodeStreamData(t *testing.T, event sse.Event, target any) {
	t.Helper()
	if err := json.Unmarshal([]byte(event.Data), target); err != nil {
		t.Fatalf("decode %s event: %v\ndata: %s", event.Type, err, event.Data)
	}
}

func waitForStreamActive(t *testing.T, stream *streamServer, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if stream.stats().Active == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("active streams = %d, want %d", stream.stats().Active, want)
}

func nextSSEBlock(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	type result struct {
		block string
		err   error
	}
	results := make(chan result, 1)
	go func() {
		var block strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				results <- result{err: err}
				return
			}
			block.WriteString(line)
			if line == "\n" {
				results <- result{block: block.String()}
				return
			}
		}
	}()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("read SSE block: %v", result.err)
		}
		return result.block
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SSE block")
		return ""
	}
}

var errStalledStreamWrite = errors.New("stalled stream write")

type deadlineFailWriter struct {
	header   http.Header
	deadline time.Time
	timedOut bool
}

func (w *deadlineFailWriter) Header() http.Header {
	return w.header
}

func (w *deadlineFailWriter) Write([]byte) (int, error) {
	w.waitForDeadline()
	return 0, errStalledStreamWrite
}

func (w *deadlineFailWriter) waitForDeadline() {
	if wait := time.Until(w.deadline); wait > 0 {
		time.Sleep(wait)
	}
	w.timedOut = true
}

func (w *deadlineFailWriter) WriteHeader(int) {}

func (w *deadlineFailWriter) FlushError() error {
	w.waitForDeadline()
	return errStalledStreamWrite
}

func (w *deadlineFailWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

type browserRequestCounter struct {
	handler http.Handler
	mu      sync.Mutex
	paths   map[string]int
}

func newBrowserRequestCounter(handler http.Handler) *browserRequestCounter {
	return &browserRequestCounter{handler: handler, paths: map[string]int{}}
}

func (c *browserRequestCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.paths[r.URL.Path]++
	c.mu.Unlock()
	c.handler.ServeHTTP(w, r)
}

func (c *browserRequestCounter) count(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paths[path]
}

func (c *browserRequestCounter) snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make(map[string]int, len(c.paths))
	for path, count := range c.paths {
		result[path] = count
	}
	return result
}

func writeBrowserEvidenceJSON(t *testing.T, path string, value any) {
	t.Helper()
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal browser evidence: %v", err)
	}
	contents = append(contents, '\n')
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatalf("write browser evidence %s: %v", path, err)
	}
}
