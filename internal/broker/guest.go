package broker

import (
	"fmt"
	"net/http"
	"strconv"
)

// handleAgentBinary serves GET /v1/guest/agent-binary?arch=arm64|amd64 (S only): the
// cross-compiled guest agent binary for the provisioning script.
func (b *Broker) handleAgentBinary(w http.ResponseWriter, r *http.Request, _ authKind) {
	arch := r.URL.Query().Get("arch")
	if arch != "arm64" && arch != "amd64" {
		writeErr(w, http.StatusBadRequest, "arch must be arm64 or amd64")
		return
	}
	if b.cfg.AgentBinary == nil {
		writeErr(w, http.StatusInternalServerError, "no guest agent binary provider configured")
		return
	}
	data, err := b.cfg.AgentBinary(arch)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("guest agent binary: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
