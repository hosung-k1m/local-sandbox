package broker

import (
	"encoding/json"
	"errors"
	"net/http"

	"boxedai/internal/evidence"
)

// eventsRequest is the guest ingest payload.
type eventsRequest struct {
	Events []evidence.Event `json:"events"`
}

// handleEvents serves POST /v1/events for both S and W tokens. The producer channel is
// derived from the authenticated token — S → guest_supervisor, W → workload — never from
// the payload, so the recorder assigns producer/class from an authenticated identity.
func (b *Broker) handleEvents(w http.ResponseWriter, r *http.Request, kind authKind) {
	ch := evidence.ChannelWorkload
	if kind == authSupervisor {
		ch = evidence.ChannelGuestSupervisor
	}

	body, err := readBody(r, maxEventsBody)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var req eventsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "body must be {\"events\":[...]}")
		return
	}

	accepted, rejected := 0, 0
	var firstErr string
	for i := range req.Events {
		if err := b.cfg.Emitter.Emit(ch, req.Events[i]); err != nil {
			rejected++
			if firstErr == "" {
				firstErr = err.Error()
			}
			continue
		}
		accepted++
	}

	resp := map[string]any{"accepted": accepted, "rejected": rejected}
	status := http.StatusOK
	if rejected > 0 {
		// A failed Emit means evidence capture is broken; surface it fail-closed.
		resp["error"] = firstErr
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, resp)
}
