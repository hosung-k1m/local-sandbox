package view

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/tmaxmax/go-sse"

	"boxedai/internal/session"
)

const (
	streamBatchSize         = 100
	streamMaxConnections    = 64
	streamFallbackInterval  = 250 * time.Millisecond
	streamHeartbeatInterval = 15 * time.Second
	streamWriteTimeout      = 10 * time.Second
	streamRetryInterval     = time.Second
)

var buildStreamWebPayload = buildWebPayload

type streamConfig struct {
	maxConnections    int
	batchSize         int
	fallbackInterval  time.Duration
	heartbeatInterval time.Duration
	writeTimeout      time.Duration
}

type streamServer struct {
	config   streamConfig
	permits  chan struct{}
	counters streamCounters
}

type streamCounters struct {
	active          atomic.Int64
	resets          atomic.Int64
	snapshots       atomic.Int64
	deltas          atomic.Int64
	rebuilds        atomic.Int64
	lastResetReason atomic.Value
}

type streamStats struct {
	Active          int64
	Resets          int64
	Snapshots       int64
	Deltas          int64
	Rebuilds        int64
	LastResetReason string
}

type streamCursor struct {
	Version   int    `json:"v"`
	SessionID string `json:"s"`
	Sequence  int64  `json:"q"`
}

type streamSessionDelta struct {
	SessionID    string     `json:"session_id"`
	State        string     `json:"state"`
	Events       []webEvent `json:"events"`
	EventCount   int64      `json:"event_count"`
	LastEventSeq int64      `json:"last_event_seq"`
	LastEventTS  string     `json:"last_event_ts,omitempty"`
}

type streamSessionRemoval struct {
	SessionID string `json:"session_id"`
}

type streamConnection struct {
	server          *streamServer
	writer          http.ResponseWriter
	request         *http.Request
	sse             *sse.Session
	watch           *streamWatchSet
	dashboard       bool
	selectedID      string
	selectedDir     string
	started         bool
	summaries       map[string]dashboardSession
	summaryReaders  map[string]*streamReader
	detailReader    *streamReader
	detailState     session.State
	detailLastEvent string
}

type streamWatchSet struct {
	watcher      *fsnotify.Watcher
	paths        map[string]struct{}
	sessionPaths map[string][]string
}

func newStreamServer() *streamServer {
	return newStreamServerWithConfig(streamConfig{})
}

func newStreamServerWithConfig(config streamConfig) *streamServer {
	if config.maxConnections < 1 {
		config.maxConnections = streamMaxConnections
	}
	if config.batchSize < 1 {
		config.batchSize = streamBatchSize
	}
	if config.fallbackInterval <= 0 {
		config.fallbackInterval = streamFallbackInterval
	}
	if config.heartbeatInterval <= 0 {
		config.heartbeatInterval = streamHeartbeatInterval
	}
	if config.writeTimeout <= 0 {
		config.writeTimeout = streamWriteTimeout
	}
	server := &streamServer{
		config:  config,
		permits: make(chan struct{}, config.maxConnections),
	}
	server.counters.lastResetReason.Store("")
	return server
}

func (s *streamServer) stats() streamStats {
	return streamStats{
		Active:          s.counters.active.Load(),
		Resets:          s.counters.resets.Load(),
		Snapshots:       s.counters.snapshots.Load(),
		Deltas:          s.counters.deltas.Load(),
		Rebuilds:        s.counters.rebuilds.Load(),
		LastResetReason: s.counters.lastResetReason.Load().(string),
	}
}

func (s *streamServer) standaloneHandler(sessionDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serve(w, r, false, filepath.Base(filepath.Clean(sessionDir)), sessionDir)
	})
}

func (s *streamServer) dashboardHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selectedID := r.URL.Query().Get("session")
		if len(r.URL.Query()["session"]) > 1 || selectedID != "" && !isSessionID(selectedID) {
			http.Error(w, "view: missing or invalid session id", http.StatusBadRequest)
			return
		}
		selectedDir := ""
		if selectedID != "" {
			selectedDir = session.SessionDir(selectedID)
			if !streamSessionDirExists(selectedDir) {
				http.NotFound(w, r)
				return
			}
		}
		s.serve(w, r, true, selectedID, selectedDir)
	})
}

func (s *streamServer) serve(w http.ResponseWriter, r *http.Request, dashboard bool, selectedID, selectedDir string) {
	if r.Method != http.MethodGet {
		http.Error(w, "view: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !dashboard && !streamSessionDirExists(selectedDir) {
		http.NotFound(w, r)
		return
	}
	select {
	case s.permits <- struct{}{}:
	default:
		http.Error(w, "view: too many active streams", http.StatusServiceUnavailable)
		return
	}
	s.counters.active.Add(1)
	defer func() {
		<-s.permits
		s.counters.active.Add(-1)
	}()

	watch, watchErr := newStreamWatchSet()
	if dashboard {
		watch.add(filepath.Join(session.Home(), "sessions"))
		if infos, err := session.ListSessions(); err == nil {
			for _, info := range infos {
				if streamStateIsActive(info.State) {
					watch.addSession(info.SessionID, info.Dir)
				}
			}
		}
	}
	if selectedID != "" {
		watch.addSession(selectedID, selectedDir)
	}
	defer watch.close()
	if watchErr != nil {
		logStreamNotice(selectedID, "filesystem notifications unavailable; fallback remains active")
	}

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	sseSession, err := sse.Upgrade(w, r)
	if err != nil {
		http.Error(w, "view: streaming is unsupported", http.StatusInternalServerError)
		return
	}
	connection := &streamConnection{
		server:         s,
		writer:         w,
		request:        r,
		sse:            sseSession,
		watch:          watch,
		dashboard:      dashboard,
		selectedID:     selectedID,
		selectedDir:    selectedDir,
		summaries:      map[string]dashboardSession{},
		summaryReaders: map[string]*streamReader{},
	}
	terminal, err := connection.initialize()
	if err != nil {
		if !connection.started {
			http.Error(w, "view: stream unavailable", http.StatusInternalServerError)
		}
		logStreamNotice(selectedID, "stream initialization failed")
		return
	}
	if terminal {
		return
	}
	if err := connection.run(); err != nil && !errors.Is(err, r.Context().Err()) {
		logStreamNotice(selectedID, "stream delivery stopped")
	}
}

func streamSessionDirExists(sessionDir string) bool {
	info, err := os.Lstat(sessionDir)
	return err == nil && info.IsDir()
}

func (c *streamConnection) initialize() (bool, error) {
	if c.dashboard {
		if err := c.initializeDashboard(); err != nil {
			return false, err
		}
	}
	if c.selectedID == "" {
		return false, nil
	}
	return c.initializeDetail()
}

func (c *streamConnection) initializeDashboard() error {
	payload, err := buildDashboardPayload()
	if err != nil {
		return err
	}
	for _, summary := range payload.Sessions {
		if session.State(summary.State) == session.StateRunning {
			c.server.counters.rebuilds.Add(1)
		}
	}
	if err := c.sendJSON("sessions.snapshot", payload, ""); err != nil {
		return err
	}
	c.server.counters.snapshots.Add(1)
	for _, summary := range payload.Sessions {
		c.summaries[summary.SessionID] = summary
		if streamStateIsActive(session.State(summary.State)) {
			c.summaryReaders[summary.SessionID] = newStreamReader(session.SessionDir(summary.SessionID), summary.SessionID, summary.LastEventSeq)
		}
	}
	return nil
}

func (c *streamConnection) initializeDetail() (bool, error) {
	if !c.sse.LastEventID.IsSet() {
		c.markReset("missing")
		return c.resetDetailSnapshot()
	}
	cursor, err := decodeStreamCursor(c.sse.LastEventID.String())
	if err != nil {
		c.markReset("malformed")
		return c.resetDetailSnapshot()
	}
	if cursor.SessionID != c.selectedID {
		c.markReset("wrong_session")
		return c.resetDetailSnapshot()
	}

	reader := newStreamReader(c.selectedDir, c.selectedID, cursor.Sequence)
	rows, err := reader.read(c.server.config.batchSize)
	if err != nil {
		c.markReset("discontinuous")
		return c.resetDetailSnapshot()
	}
	c.detailReader = reader
	state := loadSessionState(c.selectedDir)
	if err := c.sendDetailDelta(rows, state); err != nil {
		return false, err
	}
	c.detailState = state
	if streamStateIsTerminal(state) {
		return c.sendDetailSnapshot()
	}
	return c.syncDetail()
}

func (c *streamConnection) resetDetailSnapshot() (bool, error) {
	terminal, err := c.sendDetailSnapshot()
	if err != nil || terminal {
		return terminal, err
	}
	return c.syncDetail()
}

func (c *streamConnection) sendDetailSnapshot() (bool, error) {
	c.server.counters.rebuilds.Add(1)
	payload, err := buildStreamWebPayload(c.selectedDir)
	if err != nil {
		return false, err
	}
	if payload.SessionID == "" {
		payload.SessionID = c.selectedID
	}
	if payload.SessionID != c.selectedID {
		return false, fmt.Errorf("view: stream snapshot session mismatch")
	}
	sequence := int64(0)
	c.detailLastEvent = ""
	if len(payload.Events) != 0 {
		sequence = payload.Events[len(payload.Events)-1].Seq
		c.detailLastEvent = payload.Events[len(payload.Events)-1].TS
	}
	cursor, err := encodeStreamCursor(c.selectedID, sequence)
	if err != nil {
		return false, err
	}
	if err := c.sendJSON("session.snapshot", payload, cursor); err != nil {
		return false, err
	}
	c.server.counters.snapshots.Add(1)
	c.detailReader = newStreamReader(c.selectedDir, c.selectedID, sequence)
	c.detailState = session.State(payload.State)
	return streamStateIsTerminal(c.detailState), nil
}

func (c *streamConnection) syncDetail() (bool, error) {
	state := loadSessionState(c.selectedDir)
	sentDelta := false
	for {
		rows, err := c.detailReader.read(c.server.config.batchSize)
		if errors.Is(err, errStreamDiscontinuity) {
			c.markReset("discontinuous")
			return c.resetDetailSnapshot()
		}
		if err != nil {
			return false, err
		}
		if len(rows) != 0 {
			if err := c.sendDetailDelta(rows, state); err != nil {
				return false, err
			}
			sentDelta = true
		}
		if len(rows) < c.server.config.batchSize {
			break
		}
	}
	if state != c.detailState && !sentDelta {
		if err := c.sendDetailDelta(nil, state); err != nil {
			return false, err
		}
	}
	c.detailState = state
	if streamStateIsTerminal(state) {
		c.watch.removeSession(c.selectedID)
		return c.sendDetailSnapshot()
	}
	return false, nil
}

func (c *streamConnection) sendDetailDelta(rows []eventRow, state session.State) error {
	events, err := webEventsFromRows(rows)
	if err != nil {
		return err
	}
	if events == nil {
		events = []webEvent{}
	}
	if len(events) != 0 {
		c.detailLastEvent = events[len(events)-1].TS
	}
	position := c.detailReader.position()
	delta := streamSessionDelta{
		SessionID:    c.selectedID,
		State:        string(state),
		Events:       events,
		EventCount:   position.sequence,
		LastEventSeq: position.sequence,
		LastEventTS:  c.detailLastEvent,
	}
	cursor, err := encodeStreamCursor(c.selectedID, position.sequence)
	if err != nil {
		return err
	}
	if err := c.sendJSON("session.delta", delta, cursor); err != nil {
		return err
	}
	c.server.counters.deltas.Add(1)
	return nil
}

func (c *streamConnection) run() error {
	fallback := time.NewTicker(c.server.config.fallbackInterval)
	heartbeat := time.NewTicker(c.server.config.heartbeatInterval)
	defer fallback.Stop()
	defer heartbeat.Stop()

	var events <-chan fsnotify.Event
	var watchErrors <-chan error
	if c.watch.watcher != nil {
		events = c.watch.watcher.Events
		watchErrors = c.watch.watcher.Errors
	}
	for {
		select {
		case <-c.request.Context().Done():
			return c.request.Context().Err()
		case _, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			terminal, err := c.sync()
			if err != nil || terminal {
				return err
			}
		case _, ok := <-watchErrors:
			if !ok {
				watchErrors = nil
				continue
			}
			logStreamNotice(c.selectedID, "filesystem notification failed; fallback remains active")
		case <-fallback.C:
			terminal, err := c.sync()
			if err != nil || terminal {
				return err
			}
		case <-heartbeat.C:
			if err := c.sendHeartbeat(); err != nil {
				return err
			}
		}
	}
}

func (c *streamConnection) sync() (bool, error) {
	if c.dashboard {
		if err := c.syncDashboard(); err != nil {
			return false, err
		}
	}
	if c.detailReader != nil {
		return c.syncDetail()
	}
	return false, nil
}

func (c *streamConnection) syncDashboard() error {
	ids, err := streamDashboardSessionIDs()
	if err != nil {
		return err
	}
	c.watch.add(filepath.Join(session.Home(), "sessions"))
	newSession := false
	for id := range ids {
		if _, exists := c.summaries[id]; !exists {
			newSession = true
			break
		}
	}
	if newSession {
		infos, err := session.ListSessions()
		if err != nil {
			return err
		}
		for _, info := range infos {
			if _, exists := c.summaries[info.SessionID]; exists {
				continue
			}
			entry := c.buildDashboardSession(info)
			if streamStateIsActive(info.State) {
				c.watch.addSession(info.SessionID, info.Dir)
				c.summaryReaders[info.SessionID] = newStreamReader(info.Dir, info.SessionID, entry.LastEventSeq)
			}
			if err := c.sendJSON("sessions.upsert", entry, ""); err != nil {
				return err
			}
			c.summaries[info.SessionID] = entry
		}
	}
	for id := range c.summaries {
		if _, ok := ids[id]; ok {
			continue
		}
		if err := c.sendJSON("sessions.remove", streamSessionRemoval{SessionID: id}, ""); err != nil {
			return err
		}
		delete(c.summaries, id)
		delete(c.summaryReaders, id)
		c.watch.removeSession(id)
	}
	for id, reader := range c.summaryReaders {
		previous, exists := c.summaries[id]
		if !exists {
			continue
		}
		info := sessionInfoFromDashboardSession(previous, loadSessionState(session.SessionDir(id)))
		updated := previous
		updated.State = string(info.State)
		if streamStateIsActive(info.State) {
			c.watch.addSession(info.SessionID, info.Dir)
			if err := c.advanceDashboardSummary(reader, &updated); err != nil {
				if !errors.Is(err, errStreamDiscontinuity) {
					return err
				}
				c.markReset("summary_discontinuous")
				updated = c.buildDashboardSession(info)
				c.summaryReaders[info.SessionID] = newStreamReader(info.Dir, info.SessionID, updated.LastEventSeq)
			}
		} else {
			if err := c.advanceDashboardSummary(reader, &updated); err != nil && !errors.Is(err, errStreamDiscontinuity) {
				return err
			}
			delete(c.summaryReaders, info.SessionID)
			c.watch.removeSession(info.SessionID)
			if count, sequence, timestamp := manifestEventSummary(info.Dir); count != 0 || sequence != 0 {
				updated.EventCount = count
				updated.LastEventSeq = sequence
				updated.LastEventTS = timestamp
			}
		}
		updated.Proof = buildDashboardSummaryProof(info.Dir, info.State)
		if !reflect.DeepEqual(previous, updated) {
			if err := c.sendJSON("sessions.upsert", updated, ""); err != nil {
				return err
			}
			c.summaries[info.SessionID] = updated
		}
	}
	return nil
}

func (c *streamConnection) buildDashboardSession(info session.SessionInfo) dashboardSession {
	if info.State == session.StateRunning {
		c.server.counters.rebuilds.Add(1)
	}
	return buildDashboardSession(info)
}

func streamDashboardSessionIDs() (map[string]struct{}, error) {
	entries, err := os.ReadDir(filepath.Join(session.Home(), "sessions"))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, nil
		}
		return nil, fmt.Errorf("view: read dashboard sessions: %w", err)
	}
	ids := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			ids[entry.Name()] = struct{}{}
		}
	}
	return ids, nil
}

func sessionInfoFromDashboardSession(summary dashboardSession, state session.State) session.SessionInfo {
	return session.SessionInfo{
		SessionID:  summary.SessionID,
		Dir:        session.SessionDir(summary.SessionID),
		State:      state,
		Harness:    summary.Harness,
		Profile:    summary.Profile,
		CreatedAt:  summary.CreatedAt,
		Repository: summary.Repository,
		Branch:     summary.Branch,
	}
}

func (c *streamConnection) advanceDashboardSummary(reader *streamReader, summary *dashboardSession) error {
	for {
		rows, err := reader.read(c.server.config.batchSize)
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			position := reader.position()
			summary.EventCount = int(position.sequence)
			summary.LastEventSeq = position.sequence
			summary.LastEventTS = rows[len(rows)-1].TS
		}
		if len(rows) < c.server.config.batchSize {
			return nil
		}
	}
}

func (c *streamConnection) sendJSON(eventType string, payload any, id string) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("view: encode stream payload: %w", err)
	}
	message := &sse.Message{
		Type:  sse.Type(eventType),
		Retry: streamRetryInterval,
	}
	if id != "" {
		message.ID, err = sse.NewID(id)
		if err != nil {
			return fmt.Errorf("view: encode stream id: %w", err)
		}
	}
	message.AppendData(string(data))
	return c.sendMessage(message)
}

func (c *streamConnection) sendHeartbeat() error {
	message := &sse.Message{Retry: streamRetryInterval}
	message.AppendComment("keepalive")
	return c.sendMessage(message)
}

func (c *streamConnection) sendMessage(message *sse.Message) error {
	controller := http.NewResponseController(c.writer)
	if err := controller.SetWriteDeadline(time.Now().Add(c.server.config.writeTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return fmt.Errorf("view: set stream write deadline: %w", err)
	}
	c.started = true
	if err := c.sse.Send(message); err != nil {
		return fmt.Errorf("view: send stream event: %w", err)
	}
	if err := c.sse.Flush(); err != nil {
		return fmt.Errorf("view: flush stream event: %w", err)
	}
	return nil
}

func (c *streamConnection) markReset(reason string) {
	c.server.counters.resets.Add(1)
	c.server.counters.lastResetReason.Store(reason)
}

func encodeStreamCursor(sessionID string, sequence int64) (string, error) {
	if sessionID == "" || sequence < 0 {
		return "", fmt.Errorf("view: invalid stream cursor position")
	}
	contents, err := json.Marshal(streamCursor{Version: 1, SessionID: sessionID, Sequence: sequence})
	if err != nil {
		return "", fmt.Errorf("view: encode stream cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(contents), nil
}

func decodeStreamCursor(value string) (streamCursor, error) {
	contents, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return streamCursor{}, fmt.Errorf("view: decode stream cursor: %w", err)
	}
	var cursor streamCursor
	if err := json.Unmarshal(contents, &cursor); err != nil {
		return streamCursor{}, fmt.Errorf("view: decode stream cursor: %w", err)
	}
	if cursor.Version != 1 || cursor.SessionID == "" || cursor.Sequence < 0 {
		return streamCursor{}, fmt.Errorf("view: unsupported stream cursor")
	}
	return cursor, nil
}

func streamStateIsActive(state session.State) bool {
	return state == session.StateCreated || state == session.StateRunning
}

func streamStateIsTerminal(state session.State) bool {
	return state == session.StateSealed || state == session.StateIncomplete
}

func newStreamWatchSet() (*streamWatchSet, error) {
	watcher, err := fsnotify.NewWatcher()
	return &streamWatchSet{
		watcher:      watcher,
		paths:        map[string]struct{}{},
		sessionPaths: map[string][]string{},
	}, err
}

func (w *streamWatchSet) add(path string) {
	if w.watcher == nil || path == "" {
		return
	}
	if _, ok := w.paths[path]; ok {
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return
	}
	if err := w.watcher.Add(path); err != nil {
		return
	}
	w.paths[path] = struct{}{}
}

func (w *streamWatchSet) addSession(sessionID, sessionDir string) {
	paths := []string{sessionDir, filepath.Join(sessionDir, "evidence", "segments")}
	for _, path := range paths {
		w.add(path)
	}
	w.sessionPaths[sessionID] = paths
}

func (w *streamWatchSet) removeSession(sessionID string) {
	paths := w.sessionPaths[sessionID]
	delete(w.sessionPaths, sessionID)
	if w.watcher == nil {
		return
	}
	for _, path := range paths {
		if _, ok := w.paths[path]; !ok {
			continue
		}
		_ = w.watcher.Remove(path)
		delete(w.paths, path)
	}
}

func (w *streamWatchSet) close() {
	if w.watcher != nil {
		_ = w.watcher.Close()
	}
}

func logStreamNotice(sessionID, message string) {
	if sessionID == "" {
		sessionID = "dashboard"
	}
	fmt.Fprintf(os.Stderr, "view: stream %s: %s\n", sessionID, message)
}
