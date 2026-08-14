# BoxedAi v0.1 — Architecture Contract

BoxedAi launches Claude Code or Codex inside a disposable Lima Linux VM on macOS and
produces independently verifiable, human-readable audit evidence. This document is the
binding contract between components. Implementation MUST match it; change it only by
editing this file first.

## Security claim (v0.1)

For sessions launched through BoxedAi, the system constrains and records the agent's
process tree, persistent workspace effects, network attempts, and brokered external
effects. The verifier can establish which session ran, which policy and VM image
governed it, which processes executed, which workspace changes resulted, which network
operations were attempted or denied, which internal tools were invoked, which external
effects were approved and dispatched, and whether host-side evidence was altered after
sealing.

v0.1 is **local assurance only** (`LOCAL_ONLY` ceiling): there is no external
transparency service, so a malicious host administrator could discard evidence before
sealing. Signed segments protect against post-hoc modification, not host-root
malice during execution. Attribution binds to a managed execution session, not to a
model's internal choices.

Explicitly NOT claimed in v0.1: hidden chain-of-thought capture, deterministic replay,
prompt-injection prevention, activity outside BoxedAi, host-root resistance, external
witnessing (SCITT receipts are Phase 5), Landlock (systemd hardening approximates the
filesystem policy — see Gaps).

## Threat model

Distrusted: the harness (Claude Code / Codex), model output, repository contents,
prompt-injected instructions, anything running inside the session (subprocesses, MCP
servers, build scripts). Harness transcripts are self-reported evidence, never
authoritative.

Trusted during execution: macOS controller, hypervisor, guest kernel, privileged guest
supervisor (root in VM), host broker, host recorder.

## Component map

```
cmd/boxedai            CLI entrypoint (thin main)
internal/cli           cobra commands: setup, doctor, build-image, run, sessions, view, diff, verify, verify-record, apply, stop
internal/setup         host preflight, corporate config, idempotent image setup
internal/session       session lifecycle orchestration, IDs, session dir, state file
internal/image         golden VM image build/resolve, manifest, digest verification
internal/policy        profiles (review/develop/restricted), capability model   [SCAFFOLDED]
internal/evidence      event model, schema constants, Emitter interface          [SCAFFOLDED]
internal/recorder      sequencing, OTLP WAL segments, manifests, COSE signing, keys
internal/trustrecord   strict schema, RFC 8785 envelope signing, sealed-evidence derivation
internal/verify        offline verifier, verdicts
internal/broker        host HTTP: model proxy, internal tools, external effects,
                       approvals, guest event ingest
internal/snapshot      APFS-clone workspace snapshot, content manifest, diff, apply
internal/vm            lima template generation, VM lifecycle, provisioning, launch
internal/view          SQLite projection, CLI timeline, embedded web viewer
guest/agent            guest supervisor binary (linux/arm64 + linux/amd64)
guest/provision        provisioning shell scripts embedded into lima.yaml
```

Dependency direction (no cycles):
`cli → setup → {session, image}`; `cli → {session, trustrecord}`;
`session → {vm, image, snapshot, broker, recorder, trustrecord, view, verify}`; `cli → image`
(`build-image` calls it directly); `image → vm` (drives `vm.BakeConfig`/`vm.BakeVM` to
provision the bake boot); `broker → {evidence, policy}`; `vm → {evidence, policy}`;
`recorder → evidence`; `trustrecord → evidence`; `verify → {evidence, trustrecord}`
(verify reads raw files; it must NOT import
recorder internals — independent implementation of digest/signature checking is the
point); `view → evidence`. `evidence` and `policy` import nothing else in the repo.

## Host filesystem layout

State root `~/.boxedai/` (override: env `BOXEDAI_HOME`):

```
~/.boxedai/
  keys/recorder.key            Ed25519 private key (0600), PEM PKCS8
  keys/recorder.pub            Ed25519 public key, PEM PKIX
  config.json                  host config (upstream refs, adapters, corporate CA/npm settings; 0600)
  images/<arch>/disk.img       golden VM disk, built by `boxedai build-image` (internal/image)
  images/<arch>/manifest.json  tag, build timestamp, disk sha256 digest (see below)
  sessions/<session-id>/
    session.json               session grant (see below)
    trust-record.json          signed session trust record (new v2 grants; see below)
    policy.json                resolved policy manifest (canonical JSON)
    workspace/                 APFS clone of the repo, mounted rw into the VM
    harness-home/              guest-mounted fresh Claude/Codex home and selected global instructions
      settings.json            BoxedAi-authored Claude hook wiring (lefthook/righthook; never host-copied)
      debug/claude-code.log    native verbose debug log
      raw-api-bodies/          untruncated Messages API request/response bodies
    claude-telemetry/          host-only OTLP HTTP/JSON exports (Claude sessions only)
      logs.jsonl               opaque OTLP log batches (0600)
      metrics.jsonl            opaque OTLP metric batches (0600)
      traces.jsonl             opaque OTLP trace batches (0600)
      projects/                native conversation transcripts
    input-manifest.json        content digests at snapshot time
    output-manifest.json       content digests at session end
    workspace.diff             unified diff, input → output
    evidence/segments/
      segment-000001.otlp           length-delimited OTLP LogRecords (raw, authoritative)
      segment-000001.manifest.json  segment manifest (canonical JSON)
      segment-000001.manifest.cose  COSE Sign1 over the manifest bytes
    projection/timeline.sqlite      disposable, rebuilt from evidence at view time
    vm/lima.yaml               generated lima instance config
    vm/serial.log              guest console log if available
```

Session IDs: `bx-<UTC yyyymmdd-hhmmss>-<8 hex random>` (e.g. `bx-20260810-193004-a1b2c3d4`).
Lima instance name = session ID. TraceID = 16 random bytes hex; the controller
generates all trace/span IDs. Agent-supplied IDs are recorded as attributes only,
never as authenticated identity.

Golden VM image (`internal/image`): `boxedai build-image [--arch arm64|amd64]` boots a
one-off, throwaway bake VM, provisions it (see "VM (internal/vm) and guest supervisor"
below for exactly which steps run at bake time), stops it, and copies its disk out to
`images/<arch>/disk.img` with a `manifest.json` recording `{tag, arch, built_at,
disk_path, disk_digest ("sha256:..."), ubuntu_image_url, claude_code_package,
codex_package, extra_ca_digest, npm_registry}`. `boxedai setup` uses the last two
fields to skip a valid current image and rebuild one whose corporate inputs are stale.
`boxedai run` calls `image.Resolve(arch)` before doing anything else
(before session dir creation, before VM boot): it reads the manifest, recomputes the
on-disk disk's sha256, and fails fast with a "run `boxedai build-image` first" error if
the manifest is missing, malformed, the disk is missing, or the recomputed digest does
not match. This is a **local integrity check only** — it guards against the disk file
being corrupted or hand-edited on this host after it was built. It does NOT verify the
image's *provenance*: there is no signature over who ran `build-image`, and no
reproducible-build guarantee that rebuilding produces identical bytes.

`session.json` (session grant, written before VM boot, digest recorded in evidence):

```json
{
  "schema": "boxedai.session/v2",
  "session_id": "bx-...",
  "trace_id": "hex32",
  "harness": "claude|codex|exec",
  "profile": "develop",
  "repo_path": "/abs/path",
  "created_at": "RFC3339",
  "policy_digest": "sha256:...",
  "input_manifest_digest": "sha256:...",
  "vm_image": "boxedai-base-arm64",
  "vm_image_digest": "sha256:...",
  "recorder_pub": "PEM",
  "assurance_mode": "local",
  "trust_record": {
    "schema": "boxedai.trust-record/v1",
    "path": "trust-record.json",
    "required": true
  }
}
```

## Policy profiles (internal/policy — scaffolded, do not redesign)

| Profile      | Workspace          | Capabilities                                        |
|--------------|--------------------|-----------------------------------------------------|
| `review`     | read-only mount    | model + internal reads                              |
| `develop`    | writable overlay   | model + internal reads + approval-gated GitHub push (DEFAULT) |
| `restricted` | writable overlay   | model only                                          |

`external-write` capability is per-adapter, per-operation, approval-gated. GitHub push
is present by default only in `develop`; it can be added to another profile via
`--cap external-write:<adapter>`. No root/unrestricted-internet
profile exists.

## Evidence model (internal/evidence — scaffolded, do not redesign)

Events are OTLP `logs.v1.LogRecord`s. `EventName` = catalog name. Session=trace, tool
action=span; process/file/network observations link via `audit.action.id` when
correlation exists, else stand alone with correlation strength `none`.

Required attributes on every record (inherited from Resource where constant):
`audit.schema.version`(=`boxedai.evidence/v1`), `audit.event.id` (uuid),
`audit.sequence` (int64, per-session, assigned ONLY by recorder),
`audit.session.id`, `audit.evidence.class`, `audit.producer`, `audit.monotonic_ns`,
`audit.policy.digest`, `audit.outcome` (`success|failure|denied|cancelled|interrupted`),
plus when applicable: `audit.action.id`, `audit.parent_action.id`,
`audit.content.digest`, `audit.content.capture` (`digest_only|redacted|full`),
`audit.correlation` (`strong|lineage|none`), `vm.id`, `vm.boot.id`,
`process.exec.id`, `process.pid`, `process.parent_pid`, `process.cgroup.id`.

Evidence classes (assigned by the recorder from the authenticated producer channel,
NEVER accepted from the payload):

| Producer channel                | audit.producer      | allowed classes                      |
|---------------------------------|---------------------|--------------------------------------|
| controller (in-process)         | `controller`        | `integrity`, `broker_mediated`       |
| broker model/tool/effect proxy  | `broker`            | `broker_mediated`, `target_confirmed`|
| guest supervisor (token S)      | `guest_supervisor`  | `kernel_observed`, `integrity`       |
| workload hooks (token W)        | `workload`          | `model_self_reported`, `harness_observed` |
| recorder itself                 | `recorder`          | `integrity`                          |

If a producer submits a class outside its allowance, the recorder records the event
with the class downgraded to the channel maximum and emits an `integrity` event noting
the attempt.

Event catalog (v0.1 set): `session.granted session.started session.stopped
session.sealed policy.loaded authorization.decided model.requested model.completed
tool.requested tool.completed process.created process.executed process.exited file.changed file.deleted
workspace.manifested network.connected network.denied internal_tool.dispatched
internal_tool.completed internal_tool.failed effect.requested effect.approved
effect.denied effect.dispatched effect.completed effect.failed credential.issued
credential.revoked sensor.started sensor.loss sensor.restarted segment.sealed`.

Signed evidence content capture defaults to `redacted` metadata + sha256 digests; the
broker's model evidence stores digest + token counts + model id only. Token usage is
parsed from both plain-JSON and SSE-streaming response bodies (Anthropic
`message_start`/`message_delta` usage, OpenAI chat-completions and Responses API
usage) and recorded on `model.completed` as `llm.usage.input_tokens` /
`llm.usage.output_tokens` / `llm.usage.total_tokens` — only the fields the provider
actually reported, never derived. The model proxy strips the workload's
Accept-Encoding so upstream compression is transport-negotiated gzip, transparently
decoded before evidence capture: the digest, the parsed usage, and the bytes
forwarded to the workload all cover the identical plain payload (a non-compliant
upstream that compresses anyway is gunzipped for parsing only). Claude sessions
separately retain explicitly enabled, unsigned native and OTLP diagnostics, including
full prompt/response bodies. Command argv is stored in evidence (workspace commands
are not secrets by policy), URLs stored, headers never.

## Recorder (internal/recorder)

Single writer goroutine. API surface:

```go
type Recorder interface {
    evidence.Emitter                    // Emit(evidence.Event) error — never silently drops
    SealSegment(reason string) error    // rotate: close WAL, write+sign manifest
    Close() (finalManifests []string, err error)  // drain, seal final segment
}
NewRecorder(dir string, key SigningKey, session SessionMeta) (Recorder, error)
```

Behavior:
1. Assign `audit.sequence` monotonically from 1; assign producer/class per channel table.
2. Marshal each event as an OTLP `LogRecord` inside a single-record `LogsData`,
   append length-delimited (protodelim) to the open `.otlp` WAL file, fsync per commit
   group: one fsync covers every record appended since the previous one, lands no later
   than ~50ms after the first unsynced append, and always precedes a seal. Emit returns
   once its record is appended, so a burst costs one fsync instead of one per record —
   per-record fsync capped host ingest near 230 events/second, which a fork storm
   outruns, and the events that could not be handed over died with the guest.
3. Emit failure = session-fatal: surface the error; callers must stop the session. A
   group fsync that fails is sticky: it fails the next Emit, seal, and Close, because a
   record whose fsync failed may never have reached disk.
4. Seal on: size threshold (default 8 MiB), explicit call, Close.
5. Segment manifest JSON: `{schema:"boxedai.segment/v1", session_id, segment_number,
   first_sequence, last_sequence, record_count, prev_segment_digest ("sha256:..." or
   "" for first), segment_digest, policy_digest, sensor_loss_count,
   sensor_restart_count, created_at, sealed_at}` — canonical JSON (sorted keys, no
   extra whitespace); digest = sha256 over exact segment file bytes.
6. Sign manifest bytes with COSE Sign1 (Ed25519, `veraison/go-cose`), write `.cose`,
   then fsync both sidecars and the segment directory before reporting the seal.
7. Key management: `LoadOrGenerateKey(dir)` — Ed25519 keypair under `~/.boxedai/keys/`.

## Verifier (internal/verify)

Input: session dir (offline; no network). Checks, in order: (1) COSE signature of every
manifest against the trust root (recorder.pub supplied or from session.json);
(2) segment digest matches file bytes; (3) prev-digest chain; (4) physical sequence
continuity 1..N with no gaps, duplicates, or reordering across segments;
(5) session.granted, session.started, session.stopped, session.sealed all present
exactly once and correctly ordered; (6) exact-byte session.json digest matches the
controller's session.granted event and the grant schema is exactly v1 or v2;
(7) policy digest consistent across grant, events, manifests; (8) sensor invariants:
sensor.started before workload launch; a started session has trusted Tetragon
process.executed and process.exited coverage; any sensor.loss/restart is flagged; (9) flow
invariants: every `effect.dispatched` is preceded by a successful `effect.approved`
with matching action digest, and every `internal_tool.dispatched` is preceded by a
successful `authorization.decided` for the same action; (10) output-manifest digest
matches `workspace.manifested`; (11) the session trust record passes its profile,
schema, key, signature, semantic, and independent cross-derivation gates.

Verdicts: `LOCAL_ONLY` (all checks pass; ceiling in v0.1), `INCOMPLETE` (missing
close/seal, sensor loss, or unresolved tail), `BYPASS_DETECTED` (flow invariant
violated), `TAMPER_SUSPECTED` (signature/digest/sequence inconsistency).
`VERIFIED` is unreachable in v0.1 and the verifier must say why when asked.
Also report facets: signature validity, chain validity, sequence continuity, close
status, sensor-loss count, ungated-activity count, trust-record status/profile,
trust-record signature validity, cross-derivation status, and assurance level.

## Session trust record (boxedai.trust-record/v1)

New sessions write `trust-record.json` after the final OTLP segment is sealed. The
record is a portable, host-produced summary and binding over the existing session
files and signed segment set. It does not replace the raw OTLP segments, their
manifests, or their COSE Sign1 signatures; those remain authoritative.

The envelope is one strict JSON object with `schema: "boxedai.trust-record/v1"` and
the following top-level objects: `session`, optional `source`, `runtime`, `origin`,
`policy`, `artifacts`, `evidence`, `activity`, `assurance`, and `signing`, plus
`issued_at` and `signature`. The Draft 2020-12 schema rejects unknown properties at
every level. Digests are lowercase `sha256:<64 hex>` strings. Counts and sequence
numbers are non-negative JSON integers no larger than 9,007,199,254,740,991, the
largest integer represented exactly by JCS's IEEE-754 number model. Optional facts are
omitted, never guessed.

The signed claims are:

- `session`: id, trace id, harness, and creation time from `session.json`.
- `source`: repository, branch, and commit when present in `session.json`.
- `runtime`: `platform: "software-only"`, `isolation: "lima-vm"`, and the image
  name/digest from `session.json`.
- `origin`: `kind: "host-control-plane"`, `producer: "boxedai-recorder"`.
- `policy`: resolved profile and policy digest.
- `artifacts`: exact-byte digests of `session.json`, `policy.json`,
  `input-manifest.json`, and `output-manifest.json`.
- `evidence`: `boxedai.evidence/v1`, total segment/record/sensor counts, sequence
  range, final segment digest as `chain_tip`, sorted observed sensor mechanisms
  (including `procfs` when that is what the guest reported), and one ordered
  descriptor per sealed segment containing its number, exact manifest-file digest,
  declared segment digest, sequence range, record count, and seal time.
- `activity`: sorted observed model provider/id pairs with request counts and only
  the input/output/total token usage fields actually reported by the provider,
  model request count, sorted internal-tool call counts, effect dispatch count,
  network denial count, and a tool transcript binding derived only from
  authoritative OTLP records.

The tool transcript binding is the SHA-256 digest of RFC 8785 JCS over an array of
broker-mediated events in `audit.sequence` order. It includes
`authorization.decided`, every `internal_tool.*` event, and every `effect.*` event.
Each normalized object always carries `sequence` and `event`, then carries only the
observed values among `action_id`, `parent_action_id`, `outcome`, `content_digest`,
`tool_name`, `tool_operation`, `effect_adapter`, and `effect_operation`. The binding
also carries the normalized event count and a call count that counts only
`internal_tool.dispatched` and `effect.dispatched`. No event body, command line,
error text, or other unbounded attribute enters this portable summary.

Derivation keys off recorder-assigned identity as well as event name: model/tool/effect
claims and transcript entries require `audit.producer=broker` with
`audit.evidence.class=broker_mediated`; sensor lifecycle mechanisms/loss/restart
require `audit.producer=guest_supervisor` with `integrity`; process and network
observations require `audit.producer=guest_supervisor` with `kernel_observed`;
lifecycle and artifact bindings require `audit.producer=controller`. A
workload-submitted event using one of those names cannot enter an authoritative
trust-record claim.

- `assurance`: fixed Level 0 claims: `level: 0`,
  `verdict_ceiling: "LOCAL_ONLY"`, `hardware_attested: false`, and
  `externally_witnessed: false`.
- `signing`: fixed `algorithm: "Ed25519"` and `canonicalization: "RFC8785"`, plus
  the existing recorder public-key fingerprint. The trust record never embeds a
  public key; verification requires a caller-supplied recorder public key.

The top-level `signature` is the recorder key's raw Ed25519 signature encoded as
unpadded base64url. Its preimage is RFC 8785 JSON Canonicalization Scheme (JCS) over
the complete record with only the `signature` field absent. The same persistent
recorder key signs both trust records and segment-manifest COSE Sign1 envelopes.
RFC 8785 applies only to trust-record signatures; `evidence.CanonicalJSON` remains
the encoding for existing policy, snapshot, and segment-manifest digests.
The implementation uses `gowebpki/jcs` for RFC 8785, `santhosh-tekuri/jsonschema/v6`
for Draft 2020-12 validation, and `go-json-experiment/json` strict decoding to reject
duplicate members and invalid UTF-8 before signature verification.

Trust-record production order is binding:

1. Stop/freeze the guest and drain its authenticated evidence.
2. Revoke credentials and stop the broker.
3. Write the output manifest and diff; emit `workspace.manifested(output)`.
4. Emit `session.stopped`, then `session.sealed`, into the open final segment.
5. Call `Recorder.Close()` to fsync and close the final WAL, compute its digest,
   write its manifest, and COSE-sign the exact manifest bytes.
6. Independently reread session files, manifests, and OTLP records from disk and
   construct the unsigned trust record.
7. Validate the unsigned record shape, RFC 8785-canonicalize it, sign it with the
   recorder Ed25519 key, validate the final envelope, and atomically write/fsync
   `trust-record.json` at mode 0600.
8. Set `session.state=sealed` only after the trust record is durable. Any failure
   after recorder creation leaves the session `incomplete`.

The trust record is deliberately not emitted into an OTLP event: doing so would
create a circular dependency between the record's final-chain binding and the
digest of the segment containing that binding.

New grants use `schema: "boxedai.session/v2"` and declare
`trust_record: {schema:"boxedai.trust-record/v1", path:"trust-record.json",
required:true}` before VM boot. A v1 grant without a trust record is a compatible
legacy session (`absent_legacy`) and retains its existing verifier verdict. A v2
grant missing its required record is `INCOMPLETE`, preventing deletion downgrade.
A present trust record is always verified regardless of grant version.

Trust-record verification is independent of its producer and uses this exact gate
order: (1) pin the `boxedai.trust-record/v1` profile; (2) validate the complete
envelope against its JSON Schema; (3) require and parse the caller-supplied Ed25519
recorder public key, checking the signed fingerprint; (4) verify the Ed25519
signature over the RFC 8785 preimage; (5) enforce the Level-0 honesty invariants and
independently rederive every session-file, segment, and OTLP claim, including exact
physical record order and every OTLP `TraceId` binding to the granted trace id. Only
after these gates do the existing segment/lifecycle/flow checks determine the final verdict.
Schema, signature, key-binding, or derivation mismatches are
`TAMPER_SUSPECTED`; an unsupported profile or required missing record is
`INCOMPLETE`; a clean record remains `LOCAL_ONLY`. `VERIFIED` remains unreachable
without an external witness.

## Broker (internal/broker)

One HTTP server per session on `127.0.0.1:<port>` (host loopback; reachable from guest
because lima's user-mode network NATs guest→host-loopback via the gateway — the actual
listen address is what lima's `host.lima.internal` maps to; bind `0.0.0.0:<random
port>` restricted by bearer auth in v0.1, gap-noted). Two bearer tokens minted per
session: workload token W (in harness env), supervisor token S (root-only file in
guest). 256-bit random, constant-time compare, revoked at session stop.

Routes (all require bearer):

```
POST /v1/model/anthropic/{path...}   W  reverse proxy → configured Anthropic upstream;
                                        strips inbound auth, injects real key from host
                                        config/env/device-credential (below); emits
                                        model.requested/model.completed (digest+usage only)
POST /v1/model/openai/{path...}      W  same for OpenAI-compatible upstream
POST /v1/tools/{tool}/{op}           W  internal read adapters; JSON body {args...};
                                        capability check → authorization.decided →
                                        internal_tool.dispatched/completed/failed;
                                        result digest recorded
POST /v1/effects/{adapter}/{op}      W  external writes: normalize action → digest →
                                        effect.requested → decision from the configured
                                        session approver →
                                        effect.approved/denied → dispatch →
                                        effect.completed/failed
POST /v1/git/{git-upload-pack|git-receive-pack}
                                     W  full-duplex Git wire stream for the exact
                                        snapshotted repository; broker invokes host
                                        `/usr/bin/ssh` with the gh-resolved SSH target
                                        and fixed hardening arguments; upload-pack is
                                        internal-read, receive-pack is gated by the
                                        repository's session-scoped github/push
                                        preapproval and reports final SSH/evidence
                                        status in authenticated HTTP trailers
POST /v1/telemetry/claude/{logs|metrics|traces}
                                     W  validates each OTLP HTTP/JSON batch as JSON,
                                        then appends it opaquely to a host-only 0600
                                        JSONL file without parsing the OTLP schema
POST /v1/events                      S|W batch event ingest; body {"events":[Event...]}
                                        (evidence.Event JSON); producer/class assigned
                                        from token identity per the channel table
GET  /v1/guest/agent-binary?arch=    S  serves the cross-compiled guest agent binary
                                        to the provisioning script
GET  /v1/healthz                     any
```

Model upstream credential resolution (`internal/session/devicecred.go`), per provider,
first match wins: (1) `ProviderConfig.Key` inline in `config.json`; (2) `ProviderConfig.KeyEnv`
naming an env var; (3) the provider's default env var (`ANTHROPIC_API_KEY` /
`OPENAI_API_KEY`); (4) a host device credential, tried only when (1)-(3) are all empty
AND the provider is the one the requested harness drives (claude → anthropic, codex →
openai, exec → neither) — the lookup has host-visible side effects (a macOS Keychain
access can raise an authorization dialog), so a session that never uses the provider
must not trigger it:

- Anthropic: `CLAUDE_CODE_OAUTH_TOKEN` env var, else the macOS Keychain
  `Claude Code-credentials` item that `claude` itself maintains. A Keychain credential
  within 2 minutes of its recorded expiry fails the session at start with refresh
  guidance (run `claude`, which refreshes it, or `claude setup-token` for a new
  long-lived token) — BoxedAi never performs an OAuth refresh itself, since consuming
  the stored refresh token behind the host CLI's back would rotate it and corrupt the
  host's own `claude` login.
- OpenAI/Codex: `~/.codex/auth.json` as written by `codex login` — either a plain
  `OPENAI_API_KEY` field, or (ChatGPT mode) an `access_token`/`account_id` pair. ChatGPT
  mode sends `chatgpt-account-id: <account_id>` (below) and defaults `OPENAI_BASE_URL`
  to `https://chatgpt.com/backend-api/codex` unless host config or `OPENAI_BASE_URL`
  names an explicit upstream; this path is best-effort — token expiry is never checked,
  so a stale token surfaces as an ordinary upstream 401 rather than a fail-fast error
  (see Known Gaps).

Resolving to no credential at all is fatal only for the provider the requested harness
actually drives (claude → anthropic, codex → openai): the session aborts before VM boot
with a clear error. For the harness's other provider, and always for `exec`, an
unresolved credential just yields an empty upstream `Key`, not an aborted session — the
proxy still forwards requests (unauthenticated) to the real provider, which returns its
own 401. Device credentials flow host-side into `broker.Upstream` exactly like an
explicit config `Key` — like every upstream credential, they are read only by the host
broker process and never appear in `lima.yaml`, guest config/env, evidence, or
log/error text.

Anthropic keys shaped like a Claude Code OAuth token (prefix `sk-ant-oat`) authenticate
as `Authorization: Bearer <key>` plus the `anthropic-beta: oauth-2025-04-20` flag —
required for the API to accept a Bearer credential in place of `X-Api-Key` — merged into
whatever `anthropic-beta` values the guest's Claude Code already sent, never clobbering
them. Plain API keys keep the existing `X-Api-Key` path.

Internal tool adapters are config-driven allowlisted host commands:

```json
{"tools": {"codesearch": {
   "search-code": {"argv": ["sq","agent-tools","sourcegraph","search-code","--query","{{query}}"]},
   "show-file":   {"argv": ["sq","agent-tools","sourcegraph","show-file","--repo","{{repo}}","--path","{{path}}"]}}}}
```

Template substitution is strict: `{{name}}` placeholders fill from JSON string fields
only, no shell, exec direct argv, reject unknown fields, 60s timeout, output capped
(1 MiB), stdout returned as the tool result, digest recorded. The `develop` profile
grants tool reads; `restricted` grants none.

Git branch access for Claude and Codex sessions uses Git's `ext::` transport to start the guest
agent in `git-bridge` mode. The controller resolves the exact current repository and
SSH URL with the host `gh` CLI and rewrites only exact and canonical URLs for that
repository in the harness environment. The bridge sends the Git wire stream
through the authenticated broker; the broker invokes `/usr/bin/ssh` directly with a
strictly validated `git@github.com` or `org-N@github.com` target, the exact configured
repository, fixed hardening arguments, and an allowlisted `git-upload-pack` or
`git-receive-pack` service. It never invokes a shell or host Git against the
agent-mutated snapshot, so repository hooks, remote helpers, and filters cannot
execute on the host. Host SSH credentials remain owned by `/usr/bin/ssh` and no
GitHub token or private key enters the broker or guest.

`git-upload-pack` reads require `internal-read`; `git-receive-pack` requires
`external-write:github` and a host TTY approval before the broker or VM starts. The
immutable in-session approver accepts only that exact repository's normalized
`github/push` digest and never reads stdin; non-interactive sessions and every other
effect remain denied. The bridge verifies the broker's final SSH exit and evidence
trailers after copying the response, so an SSH failure or missing completion evidence
causes Git itself to fail. Receive-pack output cannot be buffered until SSH exits:
its initial ref advertisement must reach Git before Git sends updates. Consequently,
a remote ref update may already have happened if recording the final completion event
then fails; the bridge reports a failed transport to Git but cannot roll back that
external effect.

The JSON external-effect adapter retains `github/pr-comment`, but the session-scoped
approver does not preapprove it, so it remains fail-closed.

## Harness hook capture — lefthook / righthook

Claude sessions record every harness tool invocation — each Bash command, file read,
edit, search, and subagent tool call — as workload-channel evidence, independent of
the kernel sensor (whose diagnostic procfs path cannot see short-lived processes like `ls`,
and can never see shell builtins like `cd`). The controller stages a BoxedAi-authored
`settings.json` into the session harness home (never copied from the host — the
existing host-settings exclusion stands) wiring two Claude Code hooks, named for the
box the agent runs in:

- `PreToolUse` → `boxedai-guest-agent lefthook` → emits `tool.requested`
- `PostToolUse` → `boxedai-guest-agent righthook` → emits `tool.completed`

Both hooks match every tool (`matcher: "*"`). Each reads the harness's hook JSON on
stdin and POSTs one event to `POST /v1/events` using `BOXEDAI_BROKER_URL` and the
workload token from `BOXEDAI_WORKLOAD_TOKEN` (token W, already present in the
workload environment as the harness auth token — no new exposure), so the recorder
assigns `audit.producer=workload` and `audit.evidence.class=harness_observed` from
the authenticated channel, never from the payload. Attributes: `tool.name`, the
harness-reported tool-use id as `harness.tool_use_id` (also set as a best-effort
`audit.action.id` to pair requested/completed — self-reported correlation, never
authenticated identity), `harness.permission_mode`, a size-capped
`harness.tool.input` excerpt with `audit.content.capture=redacted` and
`audit.content.digest` over the full input JSON, and `audit.correlation=none`. For
Bash the event body carries the command string (workspace command lines are not
secrets by policy). `tool.completed` adds the tool-response digest and byte size,
never response content. A `tool.requested` with no matching `tool.completed` means
the tool was denied, failed, or interrupted before completing.

Hook and kernel events arrive over independent authenticated channels. The recorder
sequences them in arrival order; a harness tool-use id does not authenticate a
specific kernel process, and Tetragon's JSON export supplies no broker-visible
watermark proving that every causally earlier process event has arrived. BoxedAi
therefore does not reorder or delay `tool.completed` based on workload-supplied
process metadata. The guest does preserve that sensor's source order — every Tetragon
fork/exec/exit line is queued in read order and POSTed in that order, a burst of
consecutive lines coalesced into one batch — but this is not a cross-channel causal
watermark: the JSON tailer installs an fsnotify directory watch before seeking the
export to EOF and retains polling only as a fallback, but kernel notification and
broker scheduling remain independent of the harness hook channel. `tool.completed`
can still reach the broker first. Hook events remain `harness_observed` with
`audit.correlation=none`, and Tetragon process correlation remains `lineage`.
Procfs `sensor.started` and `sensor.restarted` evidence additionally reports
`sensor.coverage="incomplete: polling can miss short-lived processes"`; offline
verification returns `INCOMPLETE` whenever authoritative process coverage used
procfs.

Hook capture is honest-but-self-reported: it originates inside the distrusted
workload, so a compromised harness can suppress or forge it. It exists to make the
timeline complete, not to strengthen the security claim — hook events never enter
the trust record's broker-derived activity claims or tool-transcript binding. Hooks
fail open (always exit 0, errors to stderr → native debug log) so evidence-capture
problems never break the workload. Codex and exec harnesses have no hook mechanism
in v0.1 (gap-noted).

## Snapshot / workspace (internal/snapshot)

- `Snapshot(repo, dest) error` — APFS clone via `cp -Rc` (fallback plain copy),
  excludes nothing (the VM sees exactly the repo state), refuses if dest exists.
- `Manifest(dir) (Manifest, error)` — walk; per file: relpath, size, mode, sha256,
  symlink target. Skip `.git/` contents but record `.git` presence; deterministic
  order; canonical JSON; digest of the manifest itself.
- `Diff(inManifest, outManifest, dir) (DiffReport, error)` — added/modified/deleted
  lists + unified text diff for text files (use `git diff --no-index` against the
  input snapshot copy held in a temp location — v0.1 keeps a second pristine clone at
  `workspace.orig/` for diffing, cheap because APFS COW).
- `Apply(sessionDir, repoPath) error` — apply `workspace.diff` via `git apply` (or
  file copy for binaries); refuse if repo dirty; explicit command only.

## VM (internal/vm) and guest supervisor (guest/agent)

Lima config now splits bake-time from session-time. The bake boot (`internal/image`'s
`boxedai build-image`, `vm.GenerateBakeLimaYAML`) downloads the stock Ubuntu 24.04
cloud image once and provisions it into the golden image; every real session
(`vm.GenerateLimaYAML`) instead boots that pre-baked disk directly at `cfg.ImagePath` —
no download, no package installs. Both are vmType `vz` on the host's own arch,
`mountTypesUnsupported: [reverse-sshfs]`, containerd disabled, no port forwards. The
bake boot mounts nothing from the host (it only installs software) and uses a smaller
logical disk size (20GiB) than Lima's vz default; a real session mounts
`sessions/<id>/workspace` → `/workspace` writable (read-only for `review`). A session
VM also requests `memory: 10GiB` and `cpus: 4` rather than taking Lima's vz defaults
(4GiB/4cpu), which must stay coherent with the workload unit's own limits: the
harness's `MemoryMax` (8G, from the policy limits) has to sit at least ~1GiB below the
VM's RAM, or systemd's cgroup limit exceeds what the guest actually has and a heavy
session is killed by the guest kernel's OOM reaper instead of the policy. The bake
boot keeps Lima's defaults — it only installs software. Claude
sessions additionally mount a fresh `sessions/<id>/claude-code` directory at
`/home/agent/.claude` for native diagnostics; the host's real `~/.claude` is never
mounted. Other harnesses mount nothing else. Sessions get `host.lima.internal` for the
broker.

Provisioning splits the same way — bake-time steps run ONCE, amortized across every
future session; session-time steps run on every `boxedai run` against that
already-baked image:

Bake-time (`boxedai build-image`, system scripts, root, network open throughout — no
lockdown; the bake boot never runs a workload):
1. Create unprivileged user `agent` (uid 4242, no sudo), home `/home/agent`.
2. If configured, install and activate the corporate CA before the first network
   operation. Then install runtime deps: nodejs 22 (NodeSource), git. Install BOTH harness CLIs
   unconditionally — `@anthropic-ai/claude-code` and `@openai/codex` via npm --global —
   so the image is harness-agnostic and no session ever installs anything at boot
   regardless of which one it requests. Corporate CA injection (`extra_ca_pem`, read
   from `~/.boxedai/config.json` at build-image time) is trusted into
   /usr/local/share/ca-certificates before apt, curl, or npm runs, plus exported via
   `NODE_EXTRA_CA_CERTS` since Node ignores the system store update-ca-certificates
   just updated.
3. Install tetragon (release tarball, systemd unit, JSON export to
   /var/log/tetragon/tetragon.log) and enable+start it, so every session's guest already
   has it running. The unit pins the export's rotation flags
   (`--export-file-max-size-mb`, `--export-file-max-backups`,
   `--export-file-rotation-interval`) far beyond any realistic session so the export
   is a single append-only file for the whole session: Tetragon's own 10 MB default
   rotates a busy session's export within minutes, and every rotation is a guest-side
   sensor coverage gap. Best-effort: if the release tarball is unavailable for the arch, bake
   provisioning logs and continues, but session launch remains fail-closed until a
   process lifecycle sensor proves readiness (Tetragon, else the bounded procfs
   fallback in session-time step 4).
4. Install (but do not configure) the nftables and rsyslog packages, and enable
   rsyslog's systemd unit. No ruleset is written and rsyslog is not started yet — the
   ruleset needs a real session's broker IP, which does not exist at bake time.

`build-image` verifies both harness CLIs plus any configured CA and npm registry,
then stops the bake VM, copies its disk to `images/<arch>/disk.img`,
hashes it, and writes `manifest.json` (see "Host filesystem layout" above) — this is
the golden image `boxedai run` boots from via `image.Resolve`.

Session-time (`boxedai run`, system scripts, root, network still open until step 3 —
lockdown is the LAST provisioning step, before the workload can run; no apt-get, npm,
or downloads beyond the guest agent binary itself):
1. Idempotent guard: create user `agent` only if not already present (`if ! id -u
   agent`) — already true of the golden image; this is a no-op safety net, not real
   work.
2. Fetch `boxedai-guest-agent` binary from the broker (`GET
   /v1/guest/agent-binary?arch=`, host cross-compiles linux/{arm64,amd64}), write
   `/etc/boxedai/agent.json` (0600 root): session id, broker URL, supervisor token,
   workload uid, workspace path, tetragon/nftables log paths. Drop the
   `boxedai-guest-agent` systemd unit file (not started yet — see step 4).
3. Apply nftables lockdown: restart rsyslog (confirms the log sink baked in bake-time
   step 4 is live for this session), resolve `host.lima.internal` and pin
   `/etc/resolv.conf` at the upstream nameserver (disabling systemd-resolved) so a
   workload DNS query is an attributable uid-4242 packet aimed at a single known IP,
   append the guest's own hostname to `/etc/hosts` (the golden image carries the bake
   boot's hostname, and with resolved stopped and DNS dropped `sudo` otherwise stalls
   on a doomed lookup of its own host name on every single invocation — including every
   `limactl shell` teardown step),
   then write and enable the default-deny ruleset: allow lo; allow established; allow
   tcp to <broker ip>:<port> only. Denied egress *from the workload uid (4242)* is `log
   prefix "boxedai-denied: "` + drop, rate-limited (20/s, burst 40) — except the
   workload's own UDP/53 to that configured upstream resolver, a dead path by design
   (no DNS egress) that the harness tooling retries constantly, which is dropped
   silently so it does not flood the audit log; DNS to any *other* host still logs as
   network.denied evidence. All other denied traffic (system daemons: systemd-resolved,
   chrony, …) is likewise dropped silently so their background DNS/NTP retries do not
   flood the audit log. No DNS. nftables/kernel `log`
   records land in `/var/log/kern.log` via the rsyslog enabled at bake-time step 4, a
   regular growing file the guest agent tails (unlike `/dev/kmsg`, a char device that
   defeats size-based rotation detection).
4. Enable+start guest agent systemd unit now that egress is locked down, so its first
   packet is already governed by the ruleset above. Immediately before that start,
   stop Tetragon, remove the baked export log, write a `tetragon.service` drop-in
   re-pinning the bake-time ExecStart (so an already-built golden image gets the
   rotation flags of bake-time step 3 without a rebuild), restart the service, and
   wait boundedly (30s) for it to remain active and create the fresh export path.
   Leave the log absent on failure so Tetragon readiness cannot be published. The agent
   POSTs sensor.started. The
   process watcher writes `/run/boxedai/process-sensor-ready` only after fresh valid
   `sched_process_fork`, built-in exec, and built-in exit observations plus two
   Tetragon loss-metrics scrapes (at least a second apart) that agree the
   readiness-blocking counters have stopped moving. Merely attaching at Tetragon EOF is
   not ready. Counters that are still moving re-anchor the gate's baseline and the gate
   looks again instead of failing the watcher: a fresh VM keeps accruing benign loss
   counts for as long as it is booting, so a delta means "not settled yet", not "sensor
   broken". For the same reason the readiness-blocking set is narrowed to counters that
   only move on genuine event loss (ring buffer lost/errors/queue, notify overflow,
   rate-limit drops); the wider set, including the boot-noisy per-process lookup misses,
   still governs ongoing loss detection once readiness is established.
   Procfs publishes readiness only as a bounded fallback: if Tetragon has not
   satisfied that gate within 30s of the agent starting, the process sensor degrades
   to procfs (sensor.loss with the reason, then sensor.restarted with
   `mechanism=procfs` and the incomplete-coverage attribute) and procfs publishes the
   marker instead, so a session always launches with honestly labelled coverage
   rather than never launching. That window applies only until readiness is first
   established: readiness is a once-per-session gate, so the moment the marker exists —
   by either mechanism — the fallback is retired for the rest of the session, and every
   later coverage question belongs to the health monitor. A fallback that stayed armed
   past its own success degrades a sensor that is demonstrably working. The guest agent unit never gives up restarting
   (`RestartSec=2`, `StartLimitIntervalSec=0`): a crash-looped supervisor that
   systemd retires permanently can publish no readiness at all. Launch stays
   fail-closed only when NEITHER mechanism can observe processes.

Guest agent duties (root daemon):
- Health: prefer Tetragon, and require it for un-degraded launch readiness. Sensor
  degradation NEVER stops the workload: after loss the agent reports sensor.loss,
  switches to procfs (which keeps recording fork/exec/exit with explicit incomplete
  coverage), and keeps trying to recover to Tetragon (sensor.restarted). Killing a
  running session because one sensor hiccuped destroys more evidence than the
  degraded coverage costs, and the verifier already returns INCOMPLETE for any
  sensor.loss or procfs coverage, so the honesty is preserved in the verdict rather
  than in a SIGKILL. The workload is stopped only for the kill switch (stop sentinel
  or broker signal) and when NEITHER mechanism can observe processes at all; the
  guest-side stop tolerates a `boxedai-session.service` that is not loaded (the
  harness has not launched yet, or already exited and was collected).
- Loss is declared conservatively, not on a single bad observation: the health
  monitor requires several consecutive failed polls before flipping to procfs, and
  a Tetragon metrics endpoint that is not answering yet is "not up" rather than
  instant failure. A slow broker is likewise not loss — events stay queued for the
  batcher's retry while the watcher keeps reading the export. The ongoing loss gate is
  anchored at readiness rather than at agent start: the counters are monotonic, so a
  baseline captured while the VM was still booting would make settled boot noise look
  like session loss for the rest of the session, and loss before readiness cannot be
  workload evidence loss because readiness is what gates the launch.
- Periodically launch a root-owned no-op process and treat Tetragon freshness from
  export growth observed after those probes, not from service activity or the last
  health check. Root events are filtered from workload evidence. While using procfs,
  an existing export establishes only a size baseline; recovery to Tetragon requires
  subsequent post-baseline growth.
- Tail the Tetragon JSON export using fsnotify with a polling fallback. An export
  rotation, truncation, or generation change is sensor loss, but a recoverable one:
  the tailer reattaches from the start of the new file and reports
  sensor.loss + sensor.restarted rather than dying (the strict, fail-on-generation
  tailer remains available for callers that genuinely want it). In the dedicated VM,
  scope lifecycle evidence to the exact workload uid; no unavailable cgroup filter
  is claimed. Forward process.created/process.executed/process.exited in source-log
  order to `POST /v1/events` with token S.
- Forward evidence in ordered micro-batches: every event is queued in observation
  order and POSTed in that order, coalescing whatever is already queued into a single
  batch (at most 500 events), flushing as soon as the queue goes idle so a lone event
  waits for nothing, with the ~500ms timed flush left as the floor. Order survives
  because one batcher submits sequentially from a FIFO queue. Round-tripping one POST
  per source line is what pinned process evidence at roughly 30 events/second, well
  under a fork storm's rate, so the export outgrew the guest and its unread tail was
  dropped without a word.
- Periodic content scan of /workspace (every 2s) → file.changed (capped sha256
  digest) / file.deleted, forwarded as kernel_observed with `observer=scan`. A
  scan is used, not fsnotify: inotify does not deliver events on the virtiofs
  mount BoxedAi uses for /workspace. The first scan seeds the baseline silently
  (input files are the snapshot, not effects). The final host-side workspace
  manifest/diff remains authoritative for persistent output; these live events
  are the timeline view.
- Tail nftables log (`/var/log/kern.log`) → network.denied events
  (`observer=nftables`), workload-scoped and rate-limited (see session-time provisioning
  step 3, above).
- On `/etc/boxedai/stop` sentinel or broker signal: freeze the session cgroup, drain,
  final flush. Draining includes the Tetragon export itself: the process watcher reads
  whatever it has not reached yet through to EOF, bounded so it stays inside the 5s
  kill-switch grace. If unread export bytes still remain beyond a small teardown
  tolerance (the export's own tail — the shell that wrote the sentinel, the liveness
  probe, a partial line), the watcher records sensor.loss naming the undrained
  backlog, so an export the guest could not keep up with becomes an INCOMPLETE verdict
  instead of silently discarded evidence. The same honesty covers the send queue: if the
  bounded final drain still holds events when the agent exits, it spends its last act on
  a single-event sensor.loss POST naming how many are being abandoned — one event fits
  in a grace the backlog itself did not.
- Hook mode (not a daemon duty; runs as the workload uid): `lefthook`/`righthook`
  subcommands invoked by the harness's PreToolUse/PostToolUse hooks read the hook
  JSON from stdin and emit one `tool.requested`/`tool.completed` event via
  `POST /v1/events` with token W from the workload environment; always exit 0
  (see "Harness hook capture").

Harness launch: controller executes
`limactl shell <id> -- sudo systemd-run --unit boxedai-session <stream-mode> --collect
 --uid=agent --property=NoNewPrivileges=yes --property=TasksMax=512
 --property=MemoryMax=8G --property=CPUQuota=400%
 --property=ProtectSystem=strict --property=ReadWritePaths="/workspace /home/agent /tmp"
 --property=WorkingDirectory=/workspace
 --property=PrivateDevices=yes --property=RestrictNamespaces=yes
 --property=SystemCallFilter=@system-service --property=CapabilityBoundingSet=
 --setenv=ANTHROPIC_BASE_URL=... --setenv=ANTHROPIC_AUTH_TOKEN=<W> ...
 <harness argv>`.
`MemoryMax` comes from the resolved policy limits and must stay below the session VM's
own RAM (see above). `<stream-mode>` is `--pty --wait` when the controller's stdin is a real terminal
(interactive claude/codex — genuine pty passthrough) and `--pipe` otherwise
(scripted `exec`/CI: `--pty` never returns without a controlling terminal, so it
would hang teardown; `--pipe` streams stdio and exits when the unit exits).
TTY detection uses an isatty ioctl, not `os.ModeCharDevice` — `/dev/null` is a
character device but not a terminal. `WorkingDirectory=/workspace` so the agent's
relative file operations land in the writable overlay, not read-only `/`. Harness adapters set
env: claude → `ANTHROPIC_BASE_URL=http://host.lima.internal:<port>/v1/model/anthropic`,
`ANTHROPIC_AUTH_TOKEN=<W>`, `CLAUDE_CONFIG_DIR=/home/agent/.claude`,
`BOXEDAI_BROKER_URL=http://host.lima.internal:<port>` and
`BOXEDAI_WORKLOAD_TOKEN=<W>` for the staged lefthook/righthook tool-capture hooks,
`DISABLE_AUTOUPDATER=1`, narrow error-reporting/feedback/marketplace controls, verbose native
debug, and authenticated OTLP HTTP/JSON logs, metrics, and beta traces. Prompt text,
assistant text, tool details/content, and untruncated raw Messages API bodies are all
enabled; the raw bodies remain in the guest-mounted config directory while OTLP
exports go to the host-only `claude-telemetry` sibling. Claude starts with
`--debug-file /home/agent/.claude/debug/claude-code.log`; codex → `OPENAI_BASE_URL=...openai`,
`OPENAI_API_KEY=<W>`, plus the same `BOXEDAI_BROKER_URL`/`BOXEDAI_WORKLOAD_TOKEN`
pair (read by the git bridge; codex has no capture hooks); exec → runs `sh -lc <cmd>`
(scripted/e2e testing harness, recorded like any other).

Kill switch: `boxedai stop <id>` → revoke tokens, broker returns 401s, guest agent
freeze+drain (5s grace), `limactl stop -f` then `limactl delete` after evidence seal.

## Session flow (internal/session)

Startup order (fail-closed at every step):
1. Resolve the golden VM image (`image.Resolve(runtime.GOARCH)`) — before any session
   directory, recorder, or broker exists, so a missing/corrupt image aborts with a
   clear "run `boxedai build-image` first" error before anything else is set up.
2. Validate harness/repo/profile → resolve policy → write policy.json.
3. Mint IDs + tokens; LoadOrGenerateKey; NewRecorder (records the resolved image's
   `Tag`/`DiskDigest` as `VMImage`/`VMImageDigest`); emit session.granted (grant
   digest — the grant itself also carries `vm_image`/`vm_image_digest`), policy.loaded.
4. Snapshot a local repo, or fresh-clone the requested remote branch, into `workspace`;
   record remote/branch/commit provenance in `session.json`; copy only supported
   host-global `CLAUDE*.md`/`AGENTS*.md` files into the session harness home at 0600;
   input-manifest → emit workspace.manifested(input).
5. Resolve model upstream credentials (host config/env, else device credential;
   fail-fast if the harness's own provider resolves to none) → start broker (emit
   credential.issued ×2).
6. Generate lima.yaml (`images:` pointed at the resolved golden disk, no download) →
   limactl create+start (progress to user).
7. Wait for the guest agent unit to be active and its process-sensor readiness marker
   to exist (timeout 120s → abort, INCOMPLETE).
8. Emit session.started → launch harness interactively (user drives).
9. On harness exit: guest drain, revoke tokens (credential.revoked), final output
   manifest + diff, workspace.manifested(output), session.stopped, session.sealed,
   Close recorder, write the signed session trust record, mark state sealed, then
   limactl delete and print the summary
   (files changed, network denials, tools used, evidence path, verify hint).

Crash safety: a deferred cleanup handler must revoke tokens, seal what exists, and
leave the session marked incomplete (state file `session.state` = one of
`created|running|sealed|incomplete`).

## CLI (internal/cli)

```
boxedai setup [--arch arm64|amd64] [--json] configure corporate CA/npm settings and
            idempotently build or reuse the verified golden image
boxedai doctor [--arch arm64|amd64] [--json] read-only host/config/image readiness
boxedai --web [--addr 127.0.0.1:0]        serve global local evidence dashboard
boxedai build-image [--arch arm64|amd64]  build/rebuild the golden VM image (required
            before `run` will work, and again after upgrading); default arch is the host's
boxedai run <claude|codex|exec> [path] [--profile develop|review|restricted]
            [--repo <remote> [--branch <branch>]]
            [--cap external-write:github] [--cmd '...' (exec only)] [--keep-vm]
            [-- harness-args...]
boxedai sessions            list sessions + state + verdict cache
boxedai view <session> [--web [--addr]]   timeline (evidence-class badges) / web UI
boxedai diff <session>      show workspace.diff
boxedai verify <session> [--json]         run verifier, print verdict + facets
boxedai verify-record <trust-record.json> --public-key <pkix.pem> [--json]
                            verify a portable envelope only; do not rederive a session
boxedai apply <session>     apply diff to original repo (asks confirmation)
boxedai stop <session>      kill switch
```

`setup --json` writes newline-delimited `boxedai.setup/v1` objects to stdout:
`type:"stage"` events for `preflight`, `configure`, and `image`, followed by exactly
one `type:"result"`. Lima provisioning output goes to stderr so stdout remains valid
NDJSON. `doctor --json` writes exactly one result object. Results carry `command`,
`status` (`ready|action_required|failed`), `ready`, `arch`, `home`, `checks`, optional
`actions`, optional image metadata, and optional `error:{code,message}`; they never
contain the CA PEM or credentials. Exit status is 0 for ready, 2 for a retryable user
action gate, and 1 for an operational failure. `BOXEDAI_HOME` governs configuration,
images, and sessions for both commands.

Anything after a literal `--` is harness passthrough argv, not a positional
(harness/path) argument: it is appended to the claude/codex CLI invocation inside the
guest so the harness can be driven non-interactively, e.g.
`boxedai run claude . -- -p 'summarize this repo'`. `exec` already takes its command via
`--cmd` and rejects passthrough args after `--`, both at the CLI (fails before any
session setup) and, defense in depth, in `session.validateHarness`.

## Viewer (internal/view)

`Rebuild(sessionDir) (*sql.DB, error)` — parse raw segments (independent of recorder),
project into SQLite tables `events(seq, ts, name, class, producer, action_id, outcome,
attrs_json)`, `summary`. CLI timeline: chronological, one line per event,
`[class-badge] name outcome — body | curated-details`, filters `--name`, `--class`, `--since`. Web
viewer: embedded HTML pages (no build step, vanilla JS) served locally. `boxedai
--web` is a global dashboard over every known session; it lists live/running
sessions first, retains historical sessions, polls `/api/sessions` and the
selected `/api/session?id=<session>` payload, and lets the user inspect the
complete timeline for any session. `/api/sessions` is a summary endpoint: for
sealed historical sessions it reads only session/manifest metadata and caches the
immutable row in memory, while running sessions may rebuild their active
projection so live event counts advance. Sealed historical summary rows are
`sealed_unverified`: manifest presence and COSE sidecar presence are reported as
metadata, manifest-declared OTLP digests are named `declared_segment_digest`, and
no verifier verdict, chain-valid result, recorder fingerprint, or checks are
populated. Full event projection and cryptographic verification run on the
selected `/api/session` payload. `boxedai view <session> --web` remains the single-session viewer. Both viewers show overview header (session, policy,
verdict), timeline table with class badges, event bodies and attributes, action
and parent-action ids, process tree, file changes, network attempts, and tool
calls. Every displayed event shows its evidence class. Verdict output names
SHA-256, COSE Sign1, EdDSA/Ed25519, the public-key fingerprint, segment/chain
outcomes, close status, and sensor-loss count. A running session with an
unsealed `.otlp` tail is explicitly marked provisional; the UI must not imply
that open-segment events are signed before their manifest and COSE Sign1 sidecar
exist.

## Failure behavior (binding)

| Condition                          | Response                                   |
|------------------------------------|--------------------------------------------|
| Guest agent unhealthy before launch| Do not start workload; abort + INCOMPLETE  |
| Tetragon loss during a session     | sensor.loss, degrade to procfs, keep recovering; workload untouched; verify=INCOMPLETE |
| No process sensor at all           | Stop workload; sensor.loss; INCOMPLETE     |
| Direct egress attempt              | nftables deny + network.denied event       |
| Tool not granted by profile        | 403 + authorization.decided(deny) event    |
| Effect without approval            | 403 + effect.denied event                  |
| Recorder write failure             | Session-fatal, never silent                |
| Broker shutdown grace expires      | Force-close connections; log; still seal + write the record |
| Kill switch                        | Revoke → freeze → seal → destroy           |
| Crash/missing seal                 | session.state=incomplete; verify=INCOMPLETE|

## Known gaps (v0.1, keep this list honest)

- No external transparency/receipts → verdict ceiling LOCAL_ONLY.
- Broker is HTTP with bearer tokens on the lima user-net, not TLS.
- No Landlock; filesystem policy is systemd hardening (ProtectSystem=strict etc.).
- Tetragon network/file TracingPolicies not shipped; network evidence = nftables logs,
  file evidence = periodic /workspace scan + final manifest (authoritative).
- Tetragon may fail to load in the Lima vz guest (BPF/BTF/kernel), or lose its export
  mid-session. Such a session still runs: after the bounded readiness window (or on
  loss) the sensor degrades to procfs, which records `correlation=none`, unknown exit
  status, and explicit incomplete coverage, and offline verification returns
  INCOMPLETE for the whole session. This is a deliberate trade — availability with an
  honest verdict instead of a killed workload — and it means a `LOCAL_ONLY` verdict,
  not merely a completed session, is the thing that attests full kernel process
  coverage. Neither sensor currently supplies trusted tool/process
  correlation or a completion watermark, so process/tool lifecycle ordering is not
  guaranteed even though each sensor's own source order is. Fork observations whose
  parent Tetragon has not enriched yet are skipped without a loss marker, so
  `process.created` lineage is best-effort wherever forks nest faster than Tetragon's
  exec cache fills; the forking subprocess's own exec/exit still lands, which is what
  the sensor invariants check.
  Honestly recorded; hardening tetragon-in-vz is deferred.
- A kernel event drained at teardown can be physically sequenced after
  `session.sealed` while its own timestamp shows the earlier moment it happened. The
  verifier's lifecycle ordering check deliberately covers only the four controller
  lifecycle events among themselves: refusing or dropping a late-arriving kernel
  observation would destroy real evidence to protect a cosmetic ordering.
- The teardown export drain is bounded, and "did the guest catch up" is decided by a
  byte tolerance (64 KiB of unread export is treated as the tail Tetragon writes about
  teardown itself). A backlog smaller than that is neither drained nor reported.
- Group-commit fsync means a host crash (as opposed to a workload or VM crash) can lose
  the last records appended to the open segment — up to ~50ms of them. Such a session
  never recorded `session.sealed` either, so verification already returns INCOMPLETE;
  every sealed segment's digest is computed over bytes that were fsynced first.
- Export rotation is pushed far out rather than truly disabled (Tetragon's rotation is
  lumberjack-backed, where a max size of 0 means 100 MB, not "never"). A session that
  somehow outgrows the pinned size still rotates, and the reattach that follows is
  recorded as sensor.loss + sensor.restarted, which is a real coverage gap: lines
  written to the old file between the last read and the reattach are not recovered.
- Live file.changed granularity is the 2s scan interval; changes fully created and
  deleted within one interval are only caught by the authoritative final diff.
- Evidence at rest is not encrypted (FileVault assumed).
- VM image digest is verified for LOCAL integrity only: `image.Resolve` recomputes the
  on-disk `disk.img`'s sha256 against `manifest.json` on every `run`, catching
  corruption or hand-editing after `build-image` produced it. There is no provenance
  verification on top of that — no signature over who ran `build-image`, and no
  reproducible-build guarantee that a rebuild yields identical bytes.
- Model request/response bodies stored as digest+usage only (no forensic body capture).
- Harness hook capture (`tool.requested`/`tool.completed`) is workload self-reported
  and fail-open: a compromised harness can suppress it, and a hook that cannot reach
  the broker loses that event silently (stderr only). Claude only — codex and exec
  have no hook mechanism.
- Codex adapter untested against a real OpenAI credential.
- ChatGPT-mode Codex device credentials (`access_token`+`account_id` from `codex login`)
  are proxied best-effort: host-side token expiry is never checked, so a stale token
  surfaces as an ordinary upstream 401 instead of the fail-fast error a missing/expired
  config or Keychain credential gets.
