package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"boxedai/internal/evidence"
)

// eventBatch is the wire body for POST /v1/events (DESIGN.md broker routes).
type eventBatch struct {
	Events []evidence.Event `json:"events"`
}

// EventClient submits evidence event batches to the host broker,
// authenticating on the guest supervisor channel with the bearer
// supervisor_token (token S).
type EventClient struct {
	brokerURL  string
	token      string
	httpClient *http.Client
}

// NewEventClient builds a client for the given broker base URL and
// supervisor token.
func NewEventClient(brokerURL, token string) *EventClient {
	return &EventClient{
		brokerURL:  strings.TrimRight(brokerURL, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Submit POSTs events to the broker's /v1/events route. A non-nil error
// means the batch was not accepted and the caller should retry later; it
// never mutates or drops events itself.
func (c *EventClient) Submit(events []evidence.Event) error {
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(eventBatch{Events: events})
	if err != nil {
		return fmt.Errorf("agent: marshal event batch: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.brokerURL+"/v1/events", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("agent: build events request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent: post events: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck // best-effort drain before close
		return fmt.Errorf("agent: broker rejected events: status %d", resp.StatusCode)
	}
	return nil
}
