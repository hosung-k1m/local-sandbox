package broker

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"boxedai/internal/evidence"
)

// handleEffect serves POST /v1/effects/{adapter}/{op}: normalize → digest →
// effect.requested → policy check → approval → dispatch. No dispatch ever precedes an
// approval; effect.requested/approved/dispatched all carry the SAME action digest.
func (b *Broker) handleEffect(w http.ResponseWriter, r *http.Request, _ authKind) {
	adapter := r.PathValue("adapter")
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

	action := NormalizedAction{Adapter: adapter, Op: op, Args: args}
	digest, err := action.Digest()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to normalize action")
		return
	}
	actionID := newActionID()

	// effect.requested — the normalized action digest, before any decision.
	if err := b.emit(evidence.ChannelBroker, effectEvent(evidence.EventEffectRequested, evidence.OutcomeSuccess, actionID, adapter, op, digest, nil)); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return
	}

	// Policy gate: an ungranted effect is denied without ever prompting.
	if !b.cfg.Policy.AllowsEffect(adapter, op) {
		b.emitEffectDenied(actionID, adapter, op, digest, "not permitted by policy")
		writeErr(w, http.StatusForbidden, fmt.Sprintf("effect %s/%s not permitted by policy", adapter, op))
		return
	}

	// A GitHub push must originate from Git inside the sandbox and flow through
	// the repository-scoped SSH bridge. Never run Git against the host
	// controller's working tree, even if a host config supplies an old adapter.
	if adapter == "github" && op == "push" {
		b.emitEffectDenied(actionID, adapter, op, digest, "legacy host Git adapter disabled")
		writeErr(w, http.StatusBadRequest, "GitHub push is available only through the brokered Git remote")
		return
	}

	// Approval gate: nil approver (non-interactive) auto-denies.
	approved := b.cfg.Approver != nil && b.cfg.Approver(action)
	if !approved {
		b.emitEffectDenied(actionID, adapter, op, digest, "not approved")
		writeErr(w, http.StatusForbidden, fmt.Sprintf("effect %s/%s not approved", adapter, op))
		return
	}
	if err := b.emit(evidence.ChannelBroker, effectEvent(evidence.EventEffectApproved, evidence.OutcomeSuccess, actionID, adapter, op, digest, nil)); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return
	}

	// Resolve and substitute the adapter argv only after approval.
	template, ok := b.lookupAdapter(b.cfg.Effects, adapter, op)
	if !ok {
		b.emitEffectFailed(actionID, adapter, op, digest, "no adapter configured", nil)
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("no adapter configured for effect %s/%s", adapter, op))
		return
	}
	argv, err := substituteArgv(template, args)
	if err != nil {
		b.emitEffectFailed(actionID, adapter, op, digest, err.Error(), nil)
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// effect.dispatched — SAME action digest as requested/approved, plus the argv run.
	dispatched := effectEvent(evidence.EventEffectDispatched, evidence.OutcomeSuccess, actionID, adapter, op, digest, nil)
	dispatched.Attrs[attrCommand] = strings.Join(argv, " ")
	if err := b.emit(evidence.ChannelBroker, dispatched); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return
	}

	stdout, _, runErr := runCommand(r.Context(), argv)
	if runErr != nil {
		b.emitEffectFailed(actionID, adapter, op, digest, runErr.Error(), runErr)
		writeErr(w, http.StatusBadGateway, "effect execution failed")
		return
	}

	// effect.completed — digest of the adapter output.
	completed := effectEvent(evidence.EventEffectCompleted, evidence.OutcomeSuccess, actionID, adapter, op, digest, nil)
	completed.Attrs[evidence.AttrContentDigest] = evidence.SHA256Hex(stdout)
	completed.Attrs[evidence.AttrContentCapture] = string(evidence.CaptureDigestOnly)
	if err := b.emit(evidence.ChannelBroker, completed); err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence emit failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "completed", "output": string(stdout)})
}

// effectEvent builds a broker-mediated effect event carrying the action digest.
func effectEvent(name string, outcome evidence.Outcome, actionID, adapter, op, digest string, extra map[string]any) evidence.Event {
	attrs := map[string]any{
		attrAdapter:                adapter,
		attrEffectOp:               op,
		evidence.AttrContentDigest: digest,
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return evidence.Event{
		Name:     name,
		Class:    evidence.ClassBrokerMediated,
		Outcome:  outcome,
		ActionID: actionID,
		Body:     fmt.Sprintf("effect %s/%s %s", adapter, op, strings.TrimPrefix(name, "effect.")),
		Attrs:    attrs,
	}
}

func (b *Broker) emitEffectDenied(actionID, adapter, op, digest, reason string) {
	_ = b.emit(evidence.ChannelBroker, effectEvent(evidence.EventEffectDenied, evidence.OutcomeDenied, actionID, adapter, op, digest, map[string]any{attrError: reason}))
}

func (b *Broker) emitEffectFailed(actionID, adapter, op, digest, reason string, runErr error) {
	extra := map[string]any{attrError: reason}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		extra[attrExitCode] = int64(exitErr.ExitCode())
	}
	_ = b.emit(evidence.ChannelBroker, effectEvent(evidence.EventEffectFailed, evidence.OutcomeFailure, actionID, adapter, op, digest, extra))
}
