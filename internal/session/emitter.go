package session

import (
	"sort"
	"sync"
	"time"

	"boxedai/internal/evidence"
)

// attrToolName mirrors the broker's "tool.name" attribute key on
// internal_tool.dispatched events. It is duplicated here (rather than exported
// from broker) because it is a stable wire attribute name, not an API.
const attrToolName = "tool.name"

// countingEmitter wraps the recorder as an evidence.Emitter and tallies the
// mediated activity the run summary reports (network denials, internal tools
// used) as events flow through — every broker- and session-emitted event passes
// here, so the counts need no post-hoc evidence re-parse. It never alters or
// drops events: it forwards each to the inner emitter and returns its error
// verbatim (fail-closed).
type countingEmitter struct {
	inner evidence.Emitter

	mu         sync.Mutex
	netDenials int
	tools      map[string]struct{}
}

func newCountingEmitter(inner evidence.Emitter) *countingEmitter {
	return &countingEmitter{inner: inner, tools: map[string]struct{}{}}
}

// Emit records the event's summary contribution, then forwards it to the inner
// emitter. Wall-clock time is stamped here if unset so session-side callers need
// not.
func (c *countingEmitter) Emit(ch evidence.Channel, ev evidence.Event) error {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	c.mu.Lock()
	switch ev.Name {
	case evidence.EventNetworkDenied:
		c.netDenials++
	case evidence.EventInternalToolDispatched:
		if name, ok := ev.Attrs[attrToolName].(string); ok && name != "" {
			c.tools[name] = struct{}{}
		}
	}
	c.mu.Unlock()
	return c.inner.Emit(ch, ev)
}

// snapshot returns the tallies collected so far: the network-denial count and the
// sorted set of internal tools dispatched.
func (c *countingEmitter) snapshot() (netDenials int, toolsUsed []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	toolsUsed = make([]string, 0, len(c.tools))
	for t := range c.tools {
		toolsUsed = append(toolsUsed, t)
	}
	sort.Strings(toolsUsed)
	return c.netDenials, toolsUsed
}
