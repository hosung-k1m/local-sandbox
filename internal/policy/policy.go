// Package policy defines BoxedAi session profiles and the capability model.
// See DESIGN.md "Policy profiles". It imports only internal/evidence.
package policy

import (
	"fmt"
	"path"
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

// FileCapture governs host-side content capture for file.changed evidence:
// which changed workspace files may have their bytes stored in the session's
// content-addressed blob store, and how many of those bytes. It withholds
// content, never evidence — a secret or excluded file still produces a
// file.changed record carrying its content digest, so the change stays attested
// even when the bytes are deliberately not kept.
type FileCapture struct {
	// MaxBytes caps how much of a single file's content is captured.
	MaxBytes int64 `json:"max_bytes"`
	// SecretGlobs match files whose content is never captured (digest-only
	// evidence). See Secret for the matching semantics.
	SecretGlobs []string `json:"secret_globs"`
	// ExcludeDirs are directory names skipped wholesale at any depth. See
	// Excluded for the matching semantics.
	ExcludeDirs []string `json:"exclude_dirs"`
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
	// FileCapture governs host-side content capture of changed workspace files.
	// It rides in the policy (rather than a separate config) so the capture rules
	// in force are covered by the attested policy digest on every record.
	FileCapture FileCapture `json:"file_capture"`
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

// defaultFileCapture is the file-capture policy every profile starts from. The
// three profiles differ in what the agent may reach, not in what an observer may
// later read back, so the capture rules are deliberately uniform across them.
var defaultFileCapture = FileCapture{
	// MaxBytes MUST equal the guest scanner's digest cap (fileDigestCapBytes in
	// guest/agent/filewatcher.go). That scan digest attests only the first 8 MiB
	// of a file, so any captured content past the cap could never be verified
	// against the digest recorded on the file.changed event — it would be bytes
	// in the blob store that no evidence vouches for. Changing one cap without
	// the other silently manufactures unverifiable content.
	MaxBytes: 8 << 20,
	// Names that conventionally hold credentials or private key material. Their
	// content never reaches the blob store; the file.changed event still carries
	// the digest, so the fact and identity of the change remain attested.
	SecretGlobs: []string{".env*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*"},
	// Dependency, virtualenv, and build-output trees. Their churn is machine
	// output rather than agent-authored work, and capturing it would swamp the
	// blob store (and the reviewer) with noise that the workspace manifest
	// already accounts for.
	ExcludeDirs: []string{"node_modules", "vendor", ".venv", "venv", "target", "build", "dist", "__pycache__", ".gradle"},
}

// Resolve builds the session policy from a profile plus extra capability flags
// (each "--cap" value, e.g. "external-write:github") and extra secret globs
// (each "--secret" value), which are appended to the profile's default
// file-capture secret globs.
func Resolve(profile Profile, extraCaps, secretGlobs []string) (Policy, error) {
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
	// File capture: the profile defaults plus any caller-supplied globs. The
	// default slices are cloned rather than shared, so appending here can never
	// mutate the package-level defaults and leak one session's --secret globs
	// into the next Resolve.
	p.FileCapture = FileCapture{
		MaxBytes:    defaultFileCapture.MaxBytes,
		SecretGlobs: slices.Clone(defaultFileCapture.SecretGlobs),
		ExcludeDirs: slices.Clone(defaultFileCapture.ExcludeDirs),
	}
	for _, g := range secretGlobs {
		// Dry-run every user glob so a malformed pattern fails here, at resolution,
		// instead of silently never matching at capture time. path.Match reports
		// ErrBadPattern only for the pattern, so any probe subject works. A glob
		// the user believes is protecting a key file but that quietly matches
		// nothing is a secret leak, not a cosmetic error — it must be loud.
		if _, err := path.Match(g, "probe"); err != nil {
			return Policy{}, fmt.Errorf("policy: invalid secret glob %q: %w", g, err)
		}
		p.FileCapture.SecretGlobs = append(p.FileCapture.SecretGlobs, g)
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

// Secret reports whether relPath's content must never be captured, leaving
// digest-only evidence for the change. relPath is workspace-relative and
// slash-separated (e.g. "sub/dir/.env.local").
//
// Matching semantics, which are user-facing policy behavior: a glob containing
// "/" is matched with path.Match against the whole relative path, so a rule can
// be scoped to a subtree ("deploy/*.json"); a glob without "/" is matched
// against the base name alone, so the default ".env*" catches ".env.local" at
// any depth — which is what someone typing a bare filename pattern expects, and
// what path.Match on the full path would NOT do (its "*" never crosses "/").
//
// Resolve validates every pattern, so path.Match can only report ErrBadPattern
// here for a Policy assembled without it; such a pattern simply does not match.
func (f FileCapture) Secret(relPath string) bool {
	base := path.Base(relPath)
	for _, g := range f.SecretGlobs {
		subject := base
		if strings.Contains(g, "/") {
			subject = relPath
		}
		if ok, err := path.Match(g, subject); err == nil && ok {
			return true
		}
	}
	return false
}

// Excluded reports whether relPath lives in a directory capture skips entirely.
// relPath is workspace-relative and slash-separated.
//
// Matching semantics, which are user-facing policy behavior: an ExcludeDirs
// entry is a plain directory name compared exactly against each path segment,
// never a glob and never a path. "build" therefore excludes "build/out.js" and
// "app/build/out.js" (the tree can be nested at any depth) but not
// "buildscripts/main.go" (no partial-segment matching).
func (f FileCapture) Excluded(relPath string) bool {
	for _, segment := range strings.Split(relPath, "/") {
		if slices.Contains(f.ExcludeDirs, segment) {
			return true
		}
	}
	return false
}

// Digest returns the canonical-JSON sha256 of the policy.
func (p Policy) Digest() (string, error) {
	b, err := evidence.CanonicalJSON(p)
	if err != nil {
		return "", err
	}
	return evidence.SHA256Hex(b), nil
}
