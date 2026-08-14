package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"boxedai/internal/evidence"
)

// hookEventCapture records what the fake broker received from one runHook
// call: the request path/auth (to confirm the hook used the workload token
// against POST /v1/events) and the decoded event batch.
type hookEventCapture struct {
	path string
	auth string
	req  struct {
		Events []evidence.Event `json:"events"`
	}
}

// hookEventServer stands up a fake broker that always accepts the batch and
// wires BOXEDAI_BROKER_URL/BOXEDAI_WORKLOAD_TOKEN for the duration of the
// test (t.Setenv auto-restores).
func hookEventServer(t *testing.T) *hookEventCapture {
	t.Helper()
	capture := &hookEventCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.path = r.URL.Path
		capture.auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &capture.req); err != nil {
			t.Errorf("fake broker: decode posted events: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(brokerURLEnv, srv.URL)
	t.Setenv(workloadTokenEnv, "hook-workload-token")
	return capture
}

const lefthookToolInput = `{"command":"ls -la /workspace"}`

var lefthookFixture = `{"tool_name":"Bash","tool_input":` + lefthookToolInput +
	`,"tool_use_id":"abc123","permission_mode":"default"}`

func TestRunHook_LefthookBash(t *testing.T) {
	capture := hookEventServer(t)

	if got := runHook("lefthook", strings.NewReader(lefthookFixture)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}

	if capture.path != "/v1/events" {
		t.Errorf("path = %q, want /v1/events", capture.path)
	}
	if capture.auth != "Bearer hook-workload-token" {
		t.Errorf("Authorization = %q", capture.auth)
	}
	if len(capture.req.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(capture.req.Events))
	}
	ev := capture.req.Events[0]

	if ev.Name != evidence.EventToolRequested {
		t.Errorf("Name = %q, want %q", ev.Name, evidence.EventToolRequested)
	}
	if ev.Class != evidence.ClassHarnessObserved {
		t.Errorf("Class = %q, want %q", ev.Class, evidence.ClassHarnessObserved)
	}
	if ev.ActionID != "abc123" {
		t.Errorf("ActionID = %q, want abc123", ev.ActionID)
	}
	if ev.Outcome != evidence.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", ev.Outcome, evidence.OutcomeSuccess)
	}
	if ev.Body != "bash: ls -la /workspace" {
		t.Errorf("Body = %q, want %q", ev.Body, "bash: ls -la /workspace")
	}

	wantAttrs := map[string]any{
		attrToolName:                "Bash",
		attrHarnessToolUseID:        "abc123",
		attrHarnessPermissionMode:   "default",
		attrHarnessToolInput:        lefthookToolInput,
		evidence.AttrContentCapture: string(evidence.CaptureRedacted),
		evidence.AttrCorrelation:    string(evidence.CorrelationNone),
		evidence.AttrContentDigest:  evidence.SHA256Hex([]byte(lefthookToolInput)),
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("Attrs[%q] = %v, want %v", k, got, want)
		}
	}
	if _, ok := ev.Attrs[attrHarnessResponseBytes]; ok {
		t.Errorf("Attrs[%q] present on lefthook, want absent", attrHarnessResponseBytes)
	}
}

const righthookToolResponse = `{"is_error":true,"error":"boom"}`

var righthookFixture = `{"tool_name":"Read","tool_input":{"file_path":"/workspace/README.md"}` +
	`,"tool_response":` + righthookToolResponse + `,"tool_use_id":"xyz789"}`

func TestRunHook_RighthookIsError(t *testing.T) {
	capture := hookEventServer(t)

	if got := runHook("righthook", strings.NewReader(righthookFixture)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}

	if len(capture.req.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(capture.req.Events))
	}
	ev := capture.req.Events[0]

	if ev.Name != evidence.EventToolCompleted {
		t.Errorf("Name = %q, want %q", ev.Name, evidence.EventToolCompleted)
	}
	if ev.Outcome != evidence.OutcomeFailure {
		t.Errorf("Outcome = %q, want %q (is_error:true)", ev.Outcome, evidence.OutcomeFailure)
	}
	if ev.Body != "harness tool Read completed" {
		t.Errorf("Body = %q, want %q", ev.Body, "harness tool Read completed")
	}

	wantDigest := evidence.SHA256Hex([]byte(righthookToolResponse))
	if got := ev.Attrs[evidence.AttrContentDigest]; got != wantDigest {
		t.Errorf("audit.content.digest = %v, want %v (over full tool_response)", got, wantDigest)
	}
	wantBytes := float64(len(righthookToolResponse)) // JSON numbers decode to float64 in map[string]any
	if got := ev.Attrs[attrHarnessResponseBytes]; got != wantBytes {
		t.Errorf("harness.tool.response_bytes = %v, want %v", got, wantBytes)
	}
	if _, ok := ev.Attrs[attrHarnessPermissionMode]; ok {
		t.Errorf("harness.permission_mode present on righthook, want absent (lefthook-only)")
	}
}

func TestRunHook_MissingEnv(t *testing.T) {
	for _, tc := range []struct {
		name      string
		brokerURL string
		token     string
	}{
		{"missing both", "", ""},
		{"missing token", "http://127.0.0.1:1", ""},
		{"missing broker url", "", "tok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(brokerURLEnv, tc.brokerURL)
			t.Setenv(workloadTokenEnv, tc.token)
			if got := runHook("lefthook", strings.NewReader(lefthookFixture)); got != 0 {
				t.Fatalf("runHook = %d, want 0", got)
			}
		})
	}
}

func TestRunHook_OversizedToolInputCapsExcerptNotDigest(t *testing.T) {
	capture := hookEventServer(t)

	bigToolInput := fmt.Sprintf(`{"command":"%s"}`, strings.Repeat("a", 5000))
	fixture := fmt.Sprintf(`{"tool_name":"Bash","tool_input":%s,"tool_use_id":"big1"}`, bigToolInput)
	if len(bigToolInput) <= maxHookInputExcerpt {
		t.Fatalf("fixture tool_input is %d bytes, want > %d to exercise capping", len(bigToolInput), maxHookInputExcerpt)
	}

	if got := runHook("lefthook", strings.NewReader(fixture)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}
	if len(capture.req.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(capture.req.Events))
	}
	ev := capture.req.Events[0]

	excerpt, ok := ev.Attrs[attrHarnessToolInput].(string)
	if !ok {
		t.Fatalf("harness.tool.input = %v (%T), want string", ev.Attrs[attrHarnessToolInput], ev.Attrs[attrHarnessToolInput])
	}
	if len(excerpt) != maxHookInputExcerpt {
		t.Errorf("harness.tool.input length = %d, want capped to %d", len(excerpt), maxHookInputExcerpt)
	}

	wantDigest := evidence.SHA256Hex([]byte(bigToolInput))
	if got := ev.Attrs[evidence.AttrContentDigest]; got != wantDigest {
		t.Errorf("audit.content.digest = %v, want %v (over full uncapped tool_input)", got, wantDigest)
	}
}
