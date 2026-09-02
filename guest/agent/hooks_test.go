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

// TestRunHook_StampsActingAgent asserts a tool hook fired inside a subagent
// carries the derived agent.id/native_id/type and parents the action to the agent,
// plus the common harness.* context and the self pid anchor.
func TestRunHook_StampsActingAgent(t *testing.T) {
	capture := hookEventServer(t)
	t.Setenv(sessionIDEnv, "bx-hooktest")

	fixture := `{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"t1",` +
		`"agent_id":"sub-42","agent_type":"Explore","session_id":"cc-sess","cwd":"/workspace",` +
		`"transcript_path":"/t.json","hook_event_name":"PreToolUse"}`
	if got := runHook("lefthook", strings.NewReader(fixture)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}
	if len(capture.req.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(capture.req.Events))
	}
	ev := capture.req.Events[0]

	wantChild := evidence.ChildAgentID("bx-hooktest", "sub-42")
	if got := ev.Attrs[evidence.AttrAgentID]; got != wantChild {
		t.Errorf("agent.id = %v, want %s (derived from native id)", got, wantChild)
	}
	if got := ev.Attrs[evidence.AttrAgentNativeID]; got != "sub-42" {
		t.Errorf("agent.native_id = %v, want sub-42", got)
	}
	if got := ev.Attrs[evidence.AttrAgentType]; got != "Explore" {
		t.Errorf("agent.type = %v, want Explore", got)
	}
	if ev.ParentActionID != wantChild {
		t.Errorf("ParentActionID = %q, want %s (tool nested under its agent)", ev.ParentActionID, wantChild)
	}
	for k, want := range map[string]any{
		attrHarnessSessionID: "cc-sess",
		attrHarnessCwd:       "/workspace",
		attrHarnessHookEvent: "PreToolUse",
	} {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("Attrs[%q] = %v, want %v", k, got, want)
		}
	}
	if _, ok := ev.Attrs[evidence.AttrProcessPID]; !ok {
		t.Error("hook event is missing its own process.pid anchor")
	}
}

// TestRunHook_StampsPrimaryWhenNoAgentID asserts a main-loop tool call — hook JSON
// with no agent_id, the shape Claude Code sends outside a subagent — is attributed
// to the controller-minted Primary named by BOXEDAI_AGENT_ID, and that no
// harness-native identity is invented for it (the Primary has none).
func TestRunHook_StampsPrimaryWhenNoAgentID(t *testing.T) {
	capture := hookEventServer(t)
	t.Setenv(sessionIDEnv, "bx-hooktest")
	t.Setenv(agentIDEnv, "ag-primary000000")

	if got := runHook("lefthook", strings.NewReader(lefthookFixture)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}
	ev := capture.req.Events[0]
	if got := ev.Attrs[evidence.AttrAgentID]; got != "ag-primary000000" {
		t.Errorf("agent.id = %v, want the Primary id from %s", got, agentIDEnv)
	}
	if ev.ParentActionID != "ag-primary000000" {
		t.Errorf("ParentActionID = %q, want the Primary id (tool nested under the Primary)", ev.ParentActionID)
	}
	for _, k := range []string{evidence.AttrAgentNativeID, evidence.AttrAgentType} {
		if _, ok := ev.Attrs[k]; ok {
			t.Errorf("Attrs[%q] present, want absent: the Primary has no harness-native identity", k)
		}
	}
}

// TestRunHook_UnattributedWithoutPrimaryID asserts the residual Unattributed
// Workload path: with no Primary id in the hook environment there is nothing honest
// to stamp, so the event carries no agent.id rather than a guessed one.
func TestRunHook_UnattributedWithoutPrimaryID(t *testing.T) {
	capture := hookEventServer(t)
	t.Setenv(sessionIDEnv, "bx-hooktest")
	t.Setenv(agentIDEnv, "")

	if got := runHook("lefthook", strings.NewReader(lefthookFixture)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}
	ev := capture.req.Events[0]
	if _, ok := ev.Attrs[evidence.AttrAgentID]; ok {
		t.Error("tool call with no agent_id and no Primary id must not carry an agent.id")
	}
	if ev.ParentActionID != "" {
		t.Errorf("ParentActionID = %q, want empty for unattributed tool", ev.ParentActionID)
	}
}

// TestRunHook_ChildAttributionBeatsPrimary asserts the harness's own subagent tag
// wins: a tool call inside a child is never relabelled as the Primary's, even though
// the Primary id is in the hook environment for every hook process.
func TestRunHook_ChildAttributionBeatsPrimary(t *testing.T) {
	capture := hookEventServer(t)
	t.Setenv(sessionIDEnv, "bx-hooktest")
	t.Setenv(agentIDEnv, "ag-primary000000")

	fixture := `{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"t1",` +
		`"agent_id":"sub-42","agent_type":"Explore"}`
	if got := runHook("lefthook", strings.NewReader(fixture)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}
	ev := capture.req.Events[0]
	wantChild := evidence.ChildAgentID("bx-hooktest", "sub-42")
	if got := ev.Attrs[evidence.AttrAgentID]; got != wantChild {
		t.Errorf("agent.id = %v, want the child id %s (never the Primary)", got, wantChild)
	}
	if ev.ParentActionID != wantChild {
		t.Errorf("ParentActionID = %q, want %s", ev.ParentActionID, wantChild)
	}
}

const taskToolInput = `{"description":"Explore backend pipeline","prompt":"<long text>","subagent_type":"Explore"}`

// TestRunHook_TaskSpawnNarration asserts a spawn tool call lifts the harness's
// description and requested subagent type into dedicated attrs (the tool_input
// excerpt is capped and the embedded prompt can crowd them out) and reads as what
// the spawn was for in the timeline body. Claude Code has shipped the tool as both
// "Task" and "Agent" — a live v2.x CLI reports "Agent" — and both must behave
// identically, so the regression is pinned on both names.
func TestRunHook_TaskSpawnNarration(t *testing.T) {
	for _, toolName := range []string{"Task", "Agent"} {
		t.Run(toolName, func(t *testing.T) {
			capture := hookEventServer(t)

			fixture := `{"tool_name":"` + toolName + `","tool_input":` + taskToolInput + `,"tool_use_id":"task-1"}`
			if got := runHook("lefthook", strings.NewReader(fixture)); got != 0 {
				t.Fatalf("runHook = %d, want 0", got)
			}
			ev := capture.req.Events[0]
			for k, want := range map[string]any{
				evidence.AttrHarnessTaskDescription:  "Explore backend pipeline",
				evidence.AttrHarnessTaskSubagentType: "Explore",
			} {
				if got := ev.Attrs[k]; got != want {
					t.Errorf("Attrs[%q] = %v, want %v", k, got, want)
				}
			}
			if ev.Body != "task: Explore backend pipeline" {
				t.Errorf("Body = %q, want %q", ev.Body, "task: Explore backend pipeline")
			}
		})
	}
}

// TestRunHook_TaskSpawnSkipsUnusableInput asserts the narration is skipped silently
// when tool_input is malformed or carries neither field — hooks fail open, so a
// harness shape change drops the attribute, never the event.
func TestRunHook_TaskSpawnSkipsUnusableInput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fixture  string
		wantBody string
	}{
		{"tool_input is not an object", `{"tool_name":"Task","tool_input":"not-an-object","tool_use_id":"t"}`, "harness tool Task"},
		{"neither field present", `{"tool_name":"Agent","tool_input":{"prompt":"x"},"tool_use_id":"t"}`, "harness tool Agent"},
		{"no tool_input at all", `{"tool_name":"Task","tool_use_id":"t"}`, "harness tool Task"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := hookEventServer(t)
			if got := runHook("lefthook", strings.NewReader(tc.fixture)); got != 0 {
				t.Fatalf("runHook = %d, want 0", got)
			}
			if len(capture.req.Events) != 1 {
				t.Fatalf("events = %d, want 1 (hooks fail open, the event still ships)", len(capture.req.Events))
			}
			ev := capture.req.Events[0]
			for _, k := range []string{evidence.AttrHarnessTaskDescription, evidence.AttrHarnessTaskSubagentType} {
				if _, ok := ev.Attrs[k]; ok {
					t.Errorf("Attrs[%q] present, want absent", k)
				}
			}
			if ev.Body != tc.wantBody {
				t.Errorf("Body = %q, want the generic tool summary %q", ev.Body, tc.wantBody)
			}
		})
	}
}

// TestRunHook_SpawnEdgeNamesBothAgents asserts a completed spawn call records the
// harness-declared parent→child edge: the acting (spawning) agent in agent.id and
// the agent the harness says it produced in agent.spawned.*, with the child id
// derived exactly as the SubagentStart registration derives it. Both spawn-tool
// names and both tool_response.status values a live Claude Code returns
// (synchronous "completed" and backgrounded "async_launched") carry agentId, so
// all four combinations are pinned. A nested spawn — the acting agent is itself a
// child — is the case the edge exists for, so it leads.
func TestRunHook_SpawnEdgeNamesBothAgents(t *testing.T) {
	for _, toolName := range []string{"Task", "Agent"} {
		for _, status := range []string{"completed", "async_launched"} {
			t.Run(toolName+"/"+status, func(t *testing.T) {
				capture := hookEventServer(t)
				t.Setenv(sessionIDEnv, "bx-spawnedge")
				t.Setenv(agentIDEnv, "ag-primary000000")

				fixture := `{"tool_name":"` + toolName + `","tool_input":` + taskToolInput +
					`,"tool_response":{"status":"` + status + `","agentId":"grandchild-1"}` +
					`,"tool_use_id":"spawn-1","agent_id":"orchestrator-1","agent_type":"general-purpose"}`
				if got := runHook("righthook", strings.NewReader(fixture)); got != 0 {
					t.Fatalf("runHook = %d, want 0", got)
				}
				ev := capture.req.Events[0]
				for k, want := range map[string]any{
					evidence.AttrAgentID:              evidence.ChildAgentID("bx-spawnedge", "orchestrator-1"),
					evidence.AttrAgentSpawnedNativeID: "grandchild-1",
					evidence.AttrAgentSpawnedID:       evidence.ChildAgentID("bx-spawnedge", "grandchild-1"),
				} {
					if got := ev.Attrs[k]; got != want {
						t.Errorf("Attrs[%q] = %v, want %v", k, got, want)
					}
				}
			})
		}
	}
}

// TestRunHook_SpawnEdgeSkippedWhenUnavailable asserts the edge is stamped only
// where the harness actually declares it. A spawn request (PreToolUse) has no
// response yet, a non-spawn tool never carries one, and a malformed or agentId-less
// tool_response is a harness shape change the hook must survive: in every case the
// attribute is absent and the event still ships (hooks fail open).
func TestRunHook_SpawnEdgeSkippedWhenUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		fixture string
	}{
		{"spawn request carries no response", "lefthook", `{"tool_name":"Agent","tool_input":` + taskToolInput + `,"tool_use_id":"t"}`},
		{"non-spawn tool", "righthook", `{"tool_name":"Bash","tool_input":` + lefthookToolInput + `,"tool_response":{"agentId":"x"},"tool_use_id":"t"}`},
		{"tool_response is not an object", "righthook", `{"tool_name":"Agent","tool_response":"not-an-object","tool_use_id":"t"}`},
		{"tool_response carries no agentId", "righthook", `{"tool_name":"Task","tool_response":{"status":"completed"},"tool_use_id":"t"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := hookEventServer(t)
			t.Setenv(sessionIDEnv, "bx-spawnedge")

			if got := runHook(tc.mode, strings.NewReader(tc.fixture)); got != 0 {
				t.Fatalf("runHook = %d, want 0", got)
			}
			if len(capture.req.Events) != 1 {
				t.Fatalf("events = %d, want 1 (hooks fail open, the event still ships)", len(capture.req.Events))
			}
			for _, k := range []string{evidence.AttrAgentSpawnedID, evidence.AttrAgentSpawnedNativeID} {
				if _, ok := capture.req.Events[0].Attrs[k]; ok {
					t.Errorf("Attrs[%q] present, want absent", k)
				}
			}
		})
	}
}

// TestRunAgentHook_SubagentStartRegistersChild asserts SubagentStart mints an
// agent.started on the workload channel with the derived child id, the Primary as
// parent, and the agent-lifecycle action chain.
func TestRunAgentHook_SubagentStartRegistersChild(t *testing.T) {
	capture := hookEventServer(t)
	t.Setenv(sessionIDEnv, "bx-agenttest")
	t.Setenv(agentIDEnv, "ag-primary000000")

	fixture := `{"hook_event_name":"SubagentStart","agent_id":"sub-1","agent_type":"Explore","session_id":"cc","cwd":"/workspace"}`
	if got := runAgentHook(strings.NewReader(fixture)); got != 0 {
		t.Fatalf("runAgentHook = %d, want 0", got)
	}
	if len(capture.req.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(capture.req.Events))
	}
	ev := capture.req.Events[0]
	wantChild := evidence.ChildAgentID("bx-agenttest", "sub-1")

	if ev.Name != evidence.EventAgentStarted {
		t.Errorf("Name = %q, want %q", ev.Name, evidence.EventAgentStarted)
	}
	if ev.Class != evidence.ClassHarnessObserved {
		t.Errorf("Class = %q, want %q", ev.Class, evidence.ClassHarnessObserved)
	}
	for k, want := range map[string]any{
		evidence.AttrAgentID:       wantChild,
		evidence.AttrAgentNativeID: "sub-1",
		evidence.AttrAgentParentID: "ag-primary000000",
		evidence.AttrAgentRole:     string(evidence.AgentRoleChild),
		evidence.AttrAgentType:     "Explore",
	} {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("Attrs[%q] = %v, want %v", k, got, want)
		}
	}
	if ev.ActionID != wantChild || ev.ParentActionID != "ag-primary000000" {
		t.Errorf("action chain = %q/%q, want %s/ag-primary000000", ev.ActionID, ev.ParentActionID, wantChild)
	}
}

// TestRunAgentHook_SubagentStopClosesChild asserts SubagentStop closes the same
// derived child id with a success outcome.
func TestRunAgentHook_SubagentStopClosesChild(t *testing.T) {
	capture := hookEventServer(t)
	t.Setenv(sessionIDEnv, "bx-agenttest")
	t.Setenv(agentIDEnv, "ag-primary000000")

	fixture := `{"hook_event_name":"SubagentStop","agent_id":"sub-1","agent_type":"Explore"}`
	if got := runAgentHook(strings.NewReader(fixture)); got != 0 {
		t.Fatalf("runAgentHook = %d, want 0", got)
	}
	ev := capture.req.Events[0]
	if ev.Name != evidence.EventAgentCompleted {
		t.Errorf("Name = %q, want %q", ev.Name, evidence.EventAgentCompleted)
	}
	if got := ev.Attrs[evidence.AttrAgentID]; got != evidence.ChildAgentID("bx-agenttest", "sub-1") {
		t.Errorf("agent.id = %v, want derived child id", got)
	}
	if got := ev.Attrs[evidence.AttrAgentOutcome]; got != string(evidence.OutcomeSuccess) {
		t.Errorf("agent.outcome = %v, want success", got)
	}
}

// TestRunHook_CodexCanonicalEvents exercises the exact Codex names and result
// shape through the shared event path used by the Agent tab.
func TestRunHook_CodexCanonicalEvents(t *testing.T) {
	capture := hookEventServer(t)
	t.Setenv("BOXEDAI_HARNESS", "codex")
	t.Setenv(sessionIDEnv, "bx-codex")
	t.Setenv(agentIDEnv, "ag-primary")
	fixture := `{"tool_name":"spawn_agent","tool_input":{"message":"inspect hooks","agent_type":"explore"},"tool_response":"{\"agent_id\":\"child-1\",\"nickname\":\"Scout\"}","tool_use_id":"spawn-1"}`
	if got := runHook("righthook", strings.NewReader(fixture)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}
	ev := capture.req.Events[0]
	for k, want := range map[string]any{
		evidence.AttrHarnessTaskDescription:  "inspect hooks",
		evidence.AttrHarnessTaskSubagentType: "explore",
		evidence.AttrAgentSpawnedNativeID:    "child-1",
		evidence.AttrAgentSpawnedID:          evidence.ChildAgentID("bx-codex", "child-1"),
	} {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("Attrs[%q] = %v, want %v", k, got, want)
		}
	}
	if ev.Body != "task: inspect hooks" {
		t.Errorf("Body = %q, want task narration", ev.Body)
	}
}

func TestRunHook_CodexV2SpawnDoesNotInventChildID(t *testing.T) {
	capture := hookEventServer(t)
	t.Setenv("BOXEDAI_HARNESS", "codex")
	t.Setenv(sessionIDEnv, "bx-codex")
	fixture := `{"tool_name":"spawn_agent","tool_input":{"message":"inspect hooks","task_name":"exploration"},"tool_response":"{\"task_name\":\"exploration\"}","tool_use_id":"spawn-2"}`
	if got := runHook("righthook", strings.NewReader(fixture)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}
	ev := capture.req.Events[0]
	if _, ok := ev.Attrs[evidence.AttrAgentSpawnedID]; ok {
		t.Errorf("agent.spawned.id = %v, want absent for Codex v2 task_name-only response", ev.Attrs[evidence.AttrAgentSpawnedID])
	}
	if got := ev.Attrs[evidence.AttrHarnessTaskSubagentType]; got != nil {
		t.Errorf("task subagent type = %v, want absent: task_name is not an agent type", got)
	}
}

func TestRunHook_CodexApplyPatchAndLifecycle(t *testing.T) {
	capture := hookEventServer(t)
	t.Setenv("BOXEDAI_HARNESS", "codex")
	t.Setenv(sessionIDEnv, "bx-codex")
	t.Setenv(agentIDEnv, "ag-primary")
	if got := runHook("lefthook", strings.NewReader(`{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch"},"tool_use_id":"patch-1"}`)); got != 0 {
		t.Fatalf("runHook = %d, want 0", got)
	}
	if body := capture.req.Events[0].Body; body != "bash: *** Begin Patch" {
		t.Errorf("apply_patch body = %q", body)
	}
	capture = hookEventServer(t)
	t.Setenv("BOXEDAI_HARNESS", "codex")
	t.Setenv(sessionIDEnv, "bx-codex")
	t.Setenv(agentIDEnv, "ag-primary")
	if got := runAgentHook(strings.NewReader(`{"hook_event_name":"SubagentStart","agent_id":"child-1","agent_type":"explore"}`)); got != 0 {
		t.Fatalf("runAgentHook = %d, want 0", got)
	}
	if got := capture.req.Events[0].Attrs[evidence.AttrAgentHarness]; got != "codex" {
		t.Errorf("agent.harness = %v, want codex", got)
	}
}

// TestRunAgentHook_IgnoresUnhandled asserts an agenthook with no agent_id or an
// unrecognized hook_event_name submits nothing and still exits 0 (fail open).
func TestRunAgentHook_IgnoresUnhandled(t *testing.T) {
	for _, fixture := range []string{
		`{"hook_event_name":"SubagentStart"}`,                // no agent_id
		`{"hook_event_name":"SomethingElse","agent_id":"x"}`, // unhandled event
	} {
		capture := hookEventServer(t)
		t.Setenv(sessionIDEnv, "bx-agenttest")
		t.Setenv(agentIDEnv, "ag-primary000000")
		if got := runAgentHook(strings.NewReader(fixture)); got != 0 {
			t.Fatalf("runAgentHook(%s) = %d, want 0", fixture, got)
		}
		if capture.path != "" {
			t.Errorf("fixture %s submitted an event (path %q), want none", fixture, capture.path)
		}
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
