package broker

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"boxedai/internal/evidence"
)

// handleTool serves POST /v1/tools/{tool}/{op}: capability check, strict placeholder
// substitution, direct exec, and the internal_tool.* evidence trio. All events share
// one action id so the verifier can prove each dispatch was preceded by an allow.
func (b *Broker) handleTool(w http.ResponseWriter, r *http.Request, _ authKind) {
	tool := r.PathValue("tool")
	op := r.PathValue("op")
	args, err := decodeStringArgs(r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	actionID := newActionID()

	// authorization.decided — the capability decision, recorded before anything runs.
	allowed := b.cfg.Policy.AllowsTool(tool, op)
	decision, outcome := decisionDeny, evidence.OutcomeDenied
	if allowed {
		decision, outcome = decisionAllow, evidence.OutcomeSuccess
	}
	if err := b.emit(evidence.ChannelBroker, evidence.Event{
		Name:     evidence.EventAuthorizationDecided,
		Class:    evidence.ClassBrokerMediated,
		Outcome:  outcome,
		ActionID: actionID,
		Body:     fmt.Sprintf("tool %s/%s %s", tool, op, decision),
		Attrs:    map[string]any{attrToolName: tool, attrToolOp: op, attrDecision: decision},
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return
	}
	if !allowed {
		writeErr(w, http.StatusForbidden, fmt.Sprintf("tool %s/%s not permitted by policy", tool, op))
		return
	}

	// Resolve the adapter argv template. A policy-allowed tool with no adapter is a
	// host misconfiguration, recorded as a failure.
	template, ok := b.lookupAdapter(b.cfg.Tools, tool, op)
	if !ok {
		b.emitToolFailed(actionID, tool, op, "no adapter configured", nil)
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("no adapter configured for tool %s/%s", tool, op))
		return
	}
	argv, err := substituteArgv(template, args)
	if err != nil {
		b.emitToolFailed(actionID, tool, op, err.Error(), nil)
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// internal_tool.dispatched — argv is stored (workspace commands are not secrets).
	if err := b.emit(evidence.ChannelBroker, evidence.Event{
		Name:     evidence.EventInternalToolDispatched,
		Class:    evidence.ClassBrokerMediated,
		Outcome:  evidence.OutcomeSuccess,
		ActionID: actionID,
		Body:     fmt.Sprintf("tool %s/%s dispatched", tool, op),
		Attrs:    map[string]any{attrToolName: tool, attrToolOp: op, attrCommand: strings.Join(argv, " ")},
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return
	}

	stdout, truncated, runErr := runCommand(r.Context(), argv)
	if runErr != nil {
		b.emitToolFailed(actionID, tool, op, runErr.Error(), runErr)
		writeErr(w, http.StatusBadGateway, "tool execution failed")
		return
	}

	// internal_tool.completed — result digest only, never the body.
	if err := b.emit(evidence.ChannelBroker, evidence.Event{
		Name:     evidence.EventInternalToolCompleted,
		Class:    evidence.ClassBrokerMediated,
		Outcome:  evidence.OutcomeSuccess,
		ActionID: actionID,
		Body:     fmt.Sprintf("tool %s/%s completed", tool, op),
		Attrs: map[string]any{
			attrToolName:                tool,
			attrToolOp:                  op,
			evidence.AttrContentDigest:  evidence.SHA256Hex(stdout),
			evidence.AttrContentCapture: string(evidence.CaptureDigestOnly),
			attrTruncated:               truncated,
		},
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(stdout)
}

// lookupAdapter resolves an adapter/op argv template from a two-level table.
func (b *Broker) lookupAdapter(table map[string]map[string][]string, adapter, op string) ([]string, bool) {
	ops, ok := table[adapter]
	if !ok {
		return nil, false
	}
	argv, ok := ops[op]
	return argv, ok
}

// emitToolFailed records an internal_tool.failed event on any pre-dispatch or execution
// failure. Best-effort: a secondary emit error is ignored since the request is already
// failing.
func (b *Broker) emitToolFailed(actionID, tool, op, reason string, runErr error) {
	attrs := map[string]any{attrToolName: tool, attrToolOp: op, attrError: reason}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		attrs[attrExitCode] = int64(exitErr.ExitCode())
	}
	_ = b.emit(evidence.ChannelBroker, evidence.Event{
		Name:     evidence.EventInternalToolFailed,
		Class:    evidence.ClassBrokerMediated,
		Outcome:  evidence.OutcomeFailure,
		ActionID: actionID,
		Body:     fmt.Sprintf("tool %s/%s failed", tool, op),
		Attrs:    attrs,
	})
}
