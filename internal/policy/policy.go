// Package policy defines BoxedAi session profiles and the capability model.
// See DESIGN.md "Policy profiles". It imports only internal/evidence.
package policy

import (
	"fmt"
	"slices"
	"strings"

	"boxedai/internal/evidence"
)

// Profile names a predefined isolation/capability level.
type Profile string

const (
	ProfileReview     Profile = "review"
	ProfileDevelop    Profile = "develop" // default
	ProfileRestricted Profile = "restricted"
)

// Capability grants. External writes are per-adapter: "external-write:github".
type Capability string

const (
	CapModel        Capability = "model"
	CapInternalRead Capability = "internal-read"
)

const capExternalWritePrefix = "external-write:"

// Limits map to systemd unit properties on the harness unit.
type Limits struct {
	MemoryMax string `json:"memory_max"` // e.g. "8G"
	CPUQuota  string `json:"cpu_quota"`  // e.g. "400%"
	TasksMax  int    `json:"tasks_max"`
}

// Policy is the resolved, immutable session policy. Its canonical-JSON digest is
// the audit.policy.digest stamped on every evidence record.
type Policy struct {
	Schema            string       `json:"schema"` // "boxedai.policy/v1"
	Profile           Profile      `json:"profile"`
	WorkspaceWritable bool         `json:"workspace_writable"`
	Capabilities      []Capability `json:"capabilities"`
	// Tools: internal read adapters -> allowed operations (no approval needed).
	Tools map[string][]string `json:"tools"`
	// Effects: external write adapters -> allowed operations (always approval-gated).
	Effects map[string][]string `json:"effects"`
	Limits  Limits              `json:"limits"`
}

// defaultTools granted by profiles with CapInternalRead.
var defaultTools = map[string][]string{
	"codesearch": {"search-code", "show-file"},
}

// knownEffects lists implemented external-write adapters and their operations.
var knownEffects = map[string][]string{
	"github": {"pr-comment", "push"},
}

var defaultLimits = Limits{MemoryMax: "8G", CPUQuota: "400%", TasksMax: 512}

// Resolve builds the session policy from a profile plus extra capability flags
// (each "--cap" value, e.g. "external-write:github").
func Resolve(profile Profile, extraCaps []string) (Policy, error) {
	p := Policy{
		Schema:  "boxedai.policy/v1",
		Profile: profile,
		Tools:   map[string][]string{},
		Effects: map[string][]string{},
		Limits:  defaultLimits,
	}
	switch profile {
	case ProfileReview:
		p.WorkspaceWritable = false
		p.Capabilities = []Capability{CapModel, CapInternalRead}
	case ProfileDevelop:
		p.WorkspaceWritable = true
		p.Capabilities = []Capability{CapModel, CapInternalRead, Capability(capExternalWritePrefix + "github")}
		p.Effects["github"] = slices.Clone(knownEffects["github"])
	case ProfileRestricted:
		p.WorkspaceWritable = true
		p.Capabilities = []Capability{CapModel}
	default:
		return Policy{}, fmt.Errorf("policy: unknown profile %q", profile)
	}
	if slices.Contains(p.Capabilities, CapInternalRead) {
		for tool, ops := range defaultTools {
			p.Tools[tool] = slices.Clone(ops)
		}
	}
	for _, c := range extraCaps {
		adapter, ok := strings.CutPrefix(c, capExternalWritePrefix)
		if !ok {
			return Policy{}, fmt.Errorf("policy: unknown capability %q (only %q<adapter> may be added)", c, capExternalWritePrefix)
		}
		ops, ok := knownEffects[adapter]
		if !ok {
			return Policy{}, fmt.Errorf("policy: unknown external-write adapter %q", adapter)
		}
		if !slices.Contains(p.Capabilities, Capability(c)) {
			p.Capabilities = append(p.Capabilities, Capability(c))
		}
		p.Effects[adapter] = slices.Clone(ops)
	}
	return p, nil
}

// AllowsTool reports whether the internal tool operation is granted.
func (p Policy) AllowsTool(tool, op string) bool {
	return slices.Contains(p.Tools[tool], op)
}

// AllowsEffect reports whether the external-write operation is grantable
// (it still requires per-action approval at dispatch time).
func (p Policy) AllowsEffect(adapter, op string) bool {
	return slices.Contains(p.Effects[adapter], op)
}

// Digest returns the canonical-JSON sha256 of the policy.
func (p Policy) Digest() (string, error) {
	b, err := evidence.CanonicalJSON(p)
	if err != nil {
		return "", err
	}
	return evidence.SHA256Hex(b), nil
}
