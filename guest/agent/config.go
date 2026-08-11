// Guest agent: the root supervisor daemon that runs inside the Lima VM,
// tails process/file/network sensors, and forwards evidence to the host
// broker. See DESIGN.md "Guest agent duties".
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// defaultTetragonLog is the path DESIGN.md's provisioning step configures
// Tetragon's systemd unit to export JSON to, used when the config omits
// tetragon_log.
const defaultTetragonLog = "/var/log/tetragon/tetragon.log"

// Config is /etc/boxedai/agent.json, written by the host during
// provisioning (DESIGN.md "guest supervisor duties").
type Config struct {
	SessionID       string `json:"session_id"`
	BrokerURL       string `json:"broker_url"`
	SupervisorToken string `json:"supervisor_token"`
	WorkloadUID     int64  `json:"workload_uid"`
	WorkspacePath   string `json:"workspace_path"`
	TetragonLog     string `json:"tetragon_log"`
	NFTLogSource    string `json:"nft_log_source"`
}

// LoadConfig reads and validates the guest agent config from path.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("agent: read config %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("agent: parse config %s: %w", path, err)
	}
	switch {
	case cfg.SessionID == "":
		return Config{}, fmt.Errorf("agent: config %s missing session_id", path)
	case cfg.BrokerURL == "":
		return Config{}, fmt.Errorf("agent: config %s missing broker_url", path)
	case cfg.SupervisorToken == "":
		return Config{}, fmt.Errorf("agent: config %s missing supervisor_token", path)
	case cfg.WorkspacePath == "":
		return Config{}, fmt.Errorf("agent: config %s missing workspace_path", path)
	}
	if cfg.TetragonLog == "" {
		cfg.TetragonLog = defaultTetragonLog
	}
	return cfg, nil
}
