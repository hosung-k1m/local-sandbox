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
internal/blobstore     per-session content-addressed store for captured file bytes (unsigned)
internal/vm            lima template generation, VM lifecycle, provisioning, launch
internal/view          SQLite projection, CLI timeline, embedded web viewer
guest/agent            guest supervisor binary (linux/arm64 + linux/amd64)
internal/vm/provision.go provisioning shell scripts embedded into lima.yaml
```

Dependency direction (no cycles):
`cli → setup → {session, image}`; `cli → {session, trustrecord}`;
`session → {vm, image, snapshot, blobstore, broker, recorder, trustrecord, view, verify}`;
`cli → image`
(`build-image` calls it directly); `image → vm` (drives `vm.BakeConfig`/`vm.BakeVM` to
provision the bake boot); `broker → {evidence, policy}`; `vm → {evidence, policy}`;
`recorder → evidence`; `trustrecord → evidence`; `blobstore → evidence`;
`verify → {evidence, trustrecord}`
(verify reads raw files; it must NOT import
recorder internals, and for the same reason must NOT import `blobstore` — an
independent implementation of digest/signature checking, and of blob addressing, is
the point); `view → {evidence, session, verify, blobstore, policy, snapshot}`.
`evidence` and `policy` import nothing else in the repo.

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
    workspace.orig/            pristine session-start clone, never mounted; baseline for
                               workspace.diff and the viewer's /api/filediff
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
    blobs/sha256/<hex>         captured workload file bytes, named by the signed digest
                               they hash to (unsigned side artifact; created on first capture)
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

The resolved policy also carries the host-side file-capture rules (see "File content
capture"), so the rules in force are covered by the `audit.policy.digest` stamped on
every record rather than living in a separate, unattested config:

```json
{"file_capture": {
  "max_bytes": 8388608,
  "secret_globs": [".env*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*"],
  "exclude_dirs": ["node_modules", "vendor", ".venv", "venv", "target", "build", "dist",
                   "__pycache__", ".gradle"]}}
```

The defaults are identical in all three profiles: the profiles differ in what the
agent may reach, not in what an observer may later read back. `boxedai run --secret
<glob>` (repeatable) appends to a profile's secret globs; it never removes a default,
and there is no flag to widen capture. Every supplied glob is dry-run through
`path.Match` while the policy resolves, so a malformed pattern fails the session at
resolution instead of silently matching nothing at capture time — a glob the operator
believes is protecting a key file but that quietly matches nothing is a secret leak,
not a cosmetic error.

Matching semantics are user-facing policy behavior, not an implementation detail. A
secret glob containing `/` is matched against the whole workspace-relative path, so a
rule can be scoped to a subtree (`deploy/*.json`); a glob without `/` is matched
against the base name alone, so `.env*` catches `.env.local` at any depth — which is
what a bare filename pattern is expected to mean, and what `path.Match` over the full
path would NOT do, since its `*` never crosses `/`. An `exclude_dirs` entry is a plain
directory name compared exactly against each path segment: never a glob, never a path.
`build` therefore excludes `build/out.js` and `app/build/out.js`, at any nesting depth,
but not `buildscripts/main.go`.

`max_bytes` MUST equal the guest scanner's digest cap (`fileDigestCapBytes` in
`guest/agent/filewatcher.go`, 8 MiB). The scan digest attests only the first 8 MiB of a
file, so content captured past that bound could never be checked against the digest the
`file.changed` record carries — it would be bytes in the store that no signed evidence
vouches for. Changing one cap without the other silently manufactures unverifiable
content, and the coupling is also what makes a capture-time hash mismatch mean
"the file changed" rather than "the two sides hashed different amounts of it".

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

An `agent.*` family groups workload activity under the logical agent (Primary
Agent or subagent) responsible: `agent.id` (session-scoped BoxedAi id — see
"Agent hierarchy and attribution"), `agent.native_id` (the harness-reported id
the BoxedAi id derives from — an attribute only, never identity),
`agent.parent.id`, `agent.role` (`primary|child`), `agent.type` (harness
subagent type), `agent.harness`, `agent.outcome`, `agent.execution_scope`
(`session`; `cgroup` is reserved for a future trusted-executor phase and is
produced by nothing today), `agent.attribution.method`
(`controller|native_harness|trusted_cgroup|process_inheritance|broker_context|unattributed`),
and `agent.attribution.strength` (`strong|lineage|self_reported|none`). Like
`audit.evidence.class`, the method and strength are assigned by the recorder from
the authenticated producer channel, never accepted from the payload.

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
tool.requested tool.completed agent.started agent.completed process.created process.executed process.exited file.changed file.deleted
workspace.manifested network.connected network.denied internal_tool.dispatched
internal_tool.completed internal_tool.failed effect.requested effect.approved
effect.denied effect.dispatched effect.completed effect.failed credential.issued
credential.revoked sensor.started sensor.loss sensor.restarted segment.sealed`.

Signed evidence content capture defaults to `redacted` metadata + sha256 digests; the
broker's model evidence stores digest + token counts + model id only. The one record
that carries `audit.content.capture=full` is a `file.changed` whose bytes the host
stored (see "File content capture"), and even there the value names a blob in an
unsigned side store — no workload content of any kind is ever written into a signed
OTLP segment. Token usage is
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
schema, key, signature, semantic, and independent cross-derivation gates;
(12) when agent tracking is present, the hierarchy reconstructed from the signed
segments satisfies the ownership invariants (see "Agent hierarchy and
attribution") — hierarchy anomalies and unattributed workload in a
capability-gated category are INCOMPLETE, never TAMPER;
(13) `file-content-store`: every kernel-observed `file.changed` stamped
`audit.content.capture=full` resolves in the unsigned per-session blob store and
re-hashes to the digest its sealed segment signed (see "File content capture"). The
number is its position in this list; the verifier emits it directly after check (10),
before the trust-record and agent checks. The verifier re-derives the blob path
and the hash itself and must NOT import `internal/blobstore`: a check that resolves a
blob through the code that wrote it proves only that the code is self-consistent. Only
`guest_supervisor`/`kernel_observed` records are counted, so workload narration cannot
move the content facets. A session that captured nothing and has no store passes with
an explicit skip; a store directory holding blobs no signed event points at is
reported, never judged — unreferenced bytes make no claim.

Verdicts: `LOCAL_ONLY` (all checks pass; ceiling in v0.1), `INCOMPLETE` (missing
close/seal, sensor loss, unresolved tail, an invalid agent hierarchy, or a captured
blob that is absent or unreadable),
`BYPASS_DETECTED` (flow invariant violated), `TAMPER_SUSPECTED`
(signature/digest/sequence/grant/trust-record inconsistency, or a blob present under a
digest it does not hash to — all host-side
artifacts). The two content failures are deliberately split: the store is unsigned and
derivable, so a pruned, lost, or never-written blob forges nothing and costs only
inspectability — history degrades honestly and must not be dressed up as an attack —
whereas a blob that is present while hashing to something other than its signed digest
is an artifact wearing a verified label while being something else. That is the
output-manifest mismatch class, and content addressing proves it without key material.
The store sits beside the mounted workspace rather than inside it and no guest mount
reaches it, so the existing rule stands unchanged.
No workload-forgeable input maps to `TAMPER_SUSPECTED`: the distrusted
workload can force at most `INCOMPLETE`, never brand its own session host-tampered.
`VERIFIED` is unreachable in v0.1 and the verifier must say why when asked.
Also report facets: signature validity, chain validity, sequence continuity, close
status, sensor-loss count, ungated-activity count, trust-record status/profile,
trust-record signature validity, cross-derivation status, agent tracking, agent
count, agent-hierarchy validity, unattributed-workload count, captured-content count,
content withheld by policy, content capture misses, content-store validity, and
assurance level. `file_content_store_valid` is true only when every claimed blob is
both present and correct, so it reads false for a merely incomplete store as well as a
wrong one; the three counts are what say which. All four are omitted from the CLI
summary when the session neither captured nor declined to capture anything, where four
zeroes would read as a finding rather than as the feature's absence.

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

Claude sessions can narrate harness tool invocations — Bash commands, file reads,
edits, searches, and subagent tool calls — as workload-channel evidence independent
of the kernel sensor (whose diagnostic procfs path can miss short-lived processes like
`ls` and can never see shell builtins like `cd`). The controller stages a BoxedAi-authored
`settings.json` into the session harness home (never copied from the host — the
existing host-settings exclusion stands) wiring two Claude Code hooks, named for the
box the agent runs in:

- `PreToolUse` → `boxedai-guest-agent lefthook` → emits `tool.requested`
- `PostToolUse` → `boxedai-guest-agent righthook` → emits `tool.completed`
- `SubagentStart`/`SubagentStop` → `boxedai-guest-agent agenthook` → emit
  `agent.started`/`agent.completed` for subagents (see "Agent hierarchy and
  attribution")

The Pre/PostToolUse hooks match every tool (`matcher: "*"`); the subagent hooks
carry no matcher. The controller records the SHA-256 digest of the exact staged
`settings.json` bytes as controller evidence. This proves which staged artifact was
measured, not that the workload ran under those settings: the harness home is
writable by the untrusted workload. Each hook reads the harness's hook JSON on
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

Each hook additionally records the harness-supplied `session_id`,
`transcript_path`, `cwd`, and `hook_event_name` as bounded `harness.*`
attributes, and — when the harness identifies the acting agent — its
`agent_id`/`agent_type` (Claude Code sends these in every hook fired inside a
subagent). Because that tagging is exhaustive for subagents, a tool event with no
`agent_id` is the harness main loop's own call and is stamped with the
controller-minted Primary's id from `BOXEDAI_AGENT_ID` — `self_reported` like all
hook narration, and without `agent.native_id`/`agent.type`, which the Primary does
not have. A hook process with no Primary id in its environment leaves the event
Unattributed Workload rather than guessing.

A subagent-spawning call additionally records its spawn narration, lifted out of the
size-capped `harness.tool.input` excerpt because the embedded subagent prompt can
crowd the description out of it. Claude Code names that tool `Task` in some versions
and `Agent` in others — both are in the wild, so both are matched:

- `harness.task.description` — the harness's one-line description of the spawn.
- `harness.task.subagent_type` — the subagent type it asked for.

Both are `self_reported` narration used for display-only spawn pairing: the viewer
pairs a spawn with the child that likely followed it, and the record claims no such
linkage (nothing correlates a spawn call to a `SubagentStart`).

The hook also records its own `process.pid`/`process.parent_pid`. When
authenticated guest-supervisor evidence contains exactly one trusted incarnation
for that PID, offline verification can use it as a plausibility anchor for the
self-reported hook event. It is recorded with `audit.correlation=none` — the join
is derived in verify/view, never claimed on the wire (the
no-cross-channel-causal-join rule stands).

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
timeline more useful, not to make it complete or strengthen the security claim —
hook events (tool capture AND subagent `agent.*` registration) never enter the trust
record's broker-derived activity claims or tool-transcript binding. Hooks fail open (always
exit 0, errors to stderr → native debug log) so evidence-capture problems never
break the workload. The `exec` harness has no hook mechanism; Codex ships a
compatible hooks system but its adapter is deferred, so only Claude sessions stage
hook wiring in v0.1 (gap-noted).

## Agent hierarchy and attribution

BoxedAi groups positively labelled workload events under the claimed logical agent
— the Primary Agent (the top-level harness loop) or a Child Agent (a subagent it
spawned) — and leaves all other workload activity explicitly Unattributed. Grouping
is narrated by the distrusted harness and is therefore self-reported; it never
strengthens the security claim, and no self-reported label is ever presented as
authenticated fact.

Two tracks, never merged:

- Narration (distrusted, fail-open): hook-submitted `agent.started`/
  `agent.completed` registrations and the `agent.id` label stamped on tool
  events. Class `harness_observed`, strength `self_reported`, always.
- Observation (authenticated and independent of narration): Tetragon or explicitly
  degraded procfs process evidence, broker-mediated model/tool/git egress, nftables
  denials, and workspace scans. Coverage is category-limited rather than complete:
  fail-open hooks can suppress tool and lifecycle narration, file reads remain
  invisible, and some short-lived activity can be missed under degraded sensing.
  "Did the available observation corroborate it" and "who claims it" (attribution
  strength) are orthogonal and reported separately; corroboration never upgrades
  strength.

Identity. A BoxedAi agent id is `ag-` followed by the first 16 hex characters of
`sha256("boxedai.agent/v1|" + session_id + "|" + scope + "|" + native_id)`.
Derivation is deterministic, so the stateless hook processes, the controller, and
the offline verifier all compute the same id independently; an id that does not
match its claimed `agent.native_id` is mechanically detectable, and duplicate
registrations collapse. The Primary Agent is controller-minted and
controller-emitted (`agent.started` right after `session.started`, closed in
teardown before `session.stopped`), attribution `controller`/`strong`. Child
Agents are hook-registered on the workload channel, attribution
`native_harness`/`self_reported`; a child's `native_id` is the harness-native
subagent id supplied by Claude Code's `SubagentStart`/`SubagentStop` hooks. The
recorder derives `agent.attribution.method`/`strength` from the
authenticated channel and clobbers any payload value, so a workload event can
never present as `controller`/`strong`.

Ownership invariants (checked offline; a violation is INCOMPLETE, never TAMPER):

1. Exactly one Primary Agent per session, on the controller channel.
2. A process's agent is inherited by its forked/exec'd children; fork and exec
   never create a new agent.
3. Model, tool, and network calls never create an agent.
4. A Child Agent exists only from `SubagentStart` lifecycle evidence and is closed
   by the corresponding `SubagentStop`; v0.1 registers every child directly under
   the Primary because these hooks provide no trusted nested-parent relationship.
5. Every child id equals the deterministic derivation of its `native_id`.
6. Every child has a nonempty `agent.parent.id` referring to an agent in the same
   session; accepted parent links are acyclic and rooted at the Primary. Sequence
   order is not used to require that the parent arrived first.
7. Child registration arrives only on the workload channel; provenance is the
   authenticated producer, never a payload string.
8. Ordering is set-based: `audit.sequence` is arrival order, so an
   `agent.started` MAY be sequenced after its child's activity (hook POSTs race
   kernel forwarding by design). Checks are id-uniqueness, parent-existence,
   acyclicity, and closure accounting — never "parent sequence < child sequence".
9. For an adapter whose hooks positively tag subagent activity (the Claude
   adapter, Claude Code v2.1.69+), a workload TOOL event carrying no harness
   `agent_id` is main-loop activity and is attributed to the Primary at
   `self_reported` strength; if no Primary id is available to the hook process the
   event remains Unattributed Workload. Per-agent attribution never exceeds
   `self_reported`. Non-hook channels (`model.*`, kernel events) remain
   unattributed by construction.
10. Concurrent byte-identical commands from different agents that cannot be
    disambiguated are marked ambiguous, never resolved by timestamp.
11. A missing child or Primary closure makes the hierarchy INCOMPLETE; the
    controller emits only the Primary closure and does not synthesize missing
    `SubagentStop` events.

Per-category attribution capability (what strength each evidence category can
carry in v0.1):

| Category | Attribution         | Notes                                                                      |
|----------|---------------------|----------------------------------------------------------------------------|
| process  | lineage-to-session  | kernel truth, uid-scoped; in-process subagents have no pid, so no per-agent kernel id exists |
| tool     | self_reported       | hook `agent_id` when present, else the Primary (main-loop call); Unattributed only when the hook has no Primary id |
| model    | session (self_reported labels) | broker sees a session TCP connection, not an agent; claimed agent headers are recorded then stripped upstream |
| file     | session_only        | scan/manifest have no actor                                                |
| network  | session_only        | nftables log lines carry no pid/uid                                        |

The adapter's capabilities are declared on the Primary's `agent.started` as
controller-attested `agent.capability.*` attributes. Unattributed events flip the
verdict to INCOMPLETE only in categories the declaration claims to attribute;
categories declared `session_only`/`self_reported` are reported in facets without
gating (otherwise every session is INCOMPLETE from day one). This is the same
honesty principle as "no unavailable cgroup filter is claimed".

Verifier. A twelfth check reconstructs the hierarchy from the signed segment
events and validates the invariants above, emitting facets (`agent_tracking`,
`agent_count`, `agent_hierarchy_valid`, `unattributed_workload_count`). Hierarchy
anomalies — forged or duplicate ids, unknown parents, cycles, or a workload event
claiming `role=primary`/`method=controller` — map to INCOMPLETE, never
TAMPER_SUSPECTED: these inputs are workload-forgeable, and letting the distrusted
workload force a TAMPER verdict would hand it a repudiation attack.
TAMPER_SUSPECTED stays reserved for signed-evidence inconsistency (signature,
digest, chain, sequence, grant, or trust-record rederivation), all host-side.
Sessions with zero agent events verify exactly as before (`agent_tracking: none`)
— legacy records are unaffected.

Trust record. The agent hierarchy is NOT a top-level claim in
`boxedai.trust-record/v1`. The `agent.*` lifecycle and label events live in the
signed OTLP segments, so they are already tamper-evident through the record's
existing `evidence` claim and `chain_tip` binding; an external verifier holding an
older embedded copy of the strict (`additionalProperties:false`) schema is
therefore never surprised by a new record property. A future profile may promote a
signed `agents` block once external conformance is settled.

Harness version. Harness CLIs are not pinned to a fixed version — the golden image
installs the latest at bake time, and the image manifest records the package
identity that produced it (`claude_code_package`/`codex_package` names plus the
`npm_registry`), not a frozen version string. The precise resolved version is
deliberately not captured in v0.1: reading it back would mean shelling into the
bake VM and copying a file out before teardown — real machinery for a nicety (see
`internal/image/manifest.go`). Because every identity signal above is
version-gated and hooks are fail-open with optional fields, some drift is
therefore silent at the manifest level; the hook events are partly
self-describing (they record which optional fields were present), which bounds
the blind spot. Capturing the resolved `claude`/`codex` version — either as a bake
provisioning step that writes it into the manifest, or as a `harness.version`
guest-supervisor observation at session start — is a known, low-risk follow-up.

Reconciliation (offline). Every hook invocation launches a process that Tetragon
can observe when coverage captures the hook-binary exec. v0.1 performs only a
one-way, non-gating PID plausibility check from workload narration to trusted kernel
observation: `hook_processes_unanchored` records a submitted hook event whose self-reported PID
has zero or multiple trusted guest-supervisor process incarnations. This does not
prove fabrication or detect suppression.

The reverse direction (a hook-binary exec with no submitted event), plus
exec-narration coverage, effect-narration coverage, and agent-liveness
decomposition, is deferred. Each needs real-probe calibration to separate a genuine
gap from normalization noise and would couple the independent verifier to
guest-agent argv/path vocabulary. The one-way PID facet never gates a verdict:
process attribution is lineage, not strong.

Honest ceiling. Per-agent labels never exceed `self_reported` in v0.1: a
compromised harness can suppress or forge hook narration and shuffle labels among
its own agents. Authenticated observation remains independent, but covers only the
categories and sensor quality described above and cannot recover an in-process
agent decomposition. File reads are invisible until an LSM read policy ships;
concurrent byte-identical commands pair ambiguously. The trusted per-agent executor
and cgroup-joined ingestion that would raise the
process-level ceiling are deferred (no Tetragon cgroup export exists for a
non-containerized workload at any current version).

## File content capture (internal/session, internal/blobstore)

The guest's periodic workspace scan reports that a file changed and what it hashes to;
it never ships the bytes. Host-side content capture is what turns that digest into
something a reader can open. At evidence ingest — before the record is sealed — the
host reads the changed file out of its own view of the session workspace and stores
the bytes in the session's content-addressed store.

`captureEmitter` (`internal/session/capture.go`) sits in the emitter chain directly
above the recorder: innermost last, `recorder ← capture ← counter`. Every producer
reaches it, including the broker's `POST /v1/events` ingest handler, and its stamp
lands on the event before the recorder assigns `audit.sequence` and appends the record
to the WAL. It touches exactly one shape of event: a `file.changed` arriving on the
`guest_supervisor` channel. `file.deleted` carries no content, and a `file.changed` on
any other channel is workload narration rather than an observation of the workspace,
where a host capture stamp would not be the producer's to make. Nothing else about an
event is dropped, reordered, or rewritten, and no capture problem can fail an `Emit` —
only the inner emitter's error propagates. A signed record of the change must flow
even when its bytes could not be kept, because that is precisely the case where an
observer most needs the record.

Who claims what. `audit.content.digest` stays the GUEST's `kernel_observed` claim:
capture never recomputes it, never overwrites it, and never invents one where the guest
left none — an event missing `file.path` or the digest passes through unstamped, since
a reason there would describe the host's confusion rather than the capture policy.
`audit.content.capture`, `file.size`, and `file.capture.reason` are the HOST's own
assertion about an action the host itself performed, stamped before sealing so they
ride inside the signature instead of beside it. That is what makes `capture="full"` a
checkable claim rather than a note: the blob it names must exist and must still hash to
the signed digest, which is exactly what verifier check (13) enforces.

Outcome vocabulary. `audit.content.capture` flips from the guest's `digest_only` to
`full`, and `file.size` is added, only when the bytes actually reached the store.
Otherwise the guest's `digest_only` stands and `file.capture.reason` records which of
two very different things happened. The ladder is evaluated in this order:

| `file.capture.reason`    | Meaning                                                                 |
|--------------------------|-------------------------------------------------------------------------|
| `secret_policy`          | the path matches a secret glob; the file is never opened                |
| `excluded_by_policy`     | the path lies under an excluded directory; the file is never opened     |
| `read_error`             | the host refused or failed the read: a `file.path` that is not workspace-local, or an I/O error |
| `missing_before_capture` | the file was gone by the time capture read it                          |
| `size_cap`               | the file is larger than `max_bytes`                                     |
| `changed_before_capture` | the bytes read do not hash to the digest the guest recorded            |
| `store_error`            | the blob store refused or failed the write                             |

The first two are decided before the file is opened at all: a secret's bytes must not
be read into the host process merely to be discarded, and an excluded tree's churn
should cost no I/O to ignore. Locality is checked on the converted path *before* the
join, because an authenticated channel is not a containment argument — a `..`, an
absolute path, or a volume name must never be opened by the host no matter who sent it,
and that is a read the host refused rather than content it withheld. `read_error` is
therefore the one reason reached from two places: a path the host refuses to open, and
a read that fails once opened.

The vocabulary splits in two, and the verifier counts the halves separately.
`secret_policy`, `excluded_by_policy`, and `size_cap` are policy WITHHOLDING: capture
could have run and deliberately did not, so the store is complete with respect to what
it was allowed to hold (`size_cap` belongs here because `max_bytes` is a policy number,
not an I/O accident). `changed_before_capture`, `missing_before_capture`, `read_error`,
and `store_error` are capture MISSES: the host meant to store the bytes and could not,
so the store holds less than the session intended. Either way the change stays fully
attested — the digest is on the signed record — which is why this mechanism withholds
content, never evidence.

The scan → ingest window is real and is reported honestly rather than papered over. The
guest hashes a file during its ~2s scan tick; the host reads it milliseconds later, by
which time the file may have changed again (`changed_before_capture`) or been removed
(`missing_before_capture`). Those are races, not faults, and they self-heal: if the file
still exists in some state, the next scan tick emits a fresh `file.changed` and capture
gets another attempt against a digest that matches. Because `max_bytes` equals the
guest's digest cap, any file small enough to capture was hashed whole by the guest too,
so a hash mismatch means the file genuinely changed — never that the two sides hashed
different amounts of the same file.

The store (`internal/blobstore`) is one file per blob at
`<sessionDir>/blobs/sha256/<64 lowercase hex>`, blobs 0600 under 0700 directories like
the rest of the session directory. Writes are atomic (temp file, fsync, rename) so a
crash mid-capture leaves either no blob or a complete one, never a truncated file
wearing a verified name; the directory entry is deliberately not fsynced, because a blob
lost to a host crash is a capture that simply did not happen, which an unsigned store
tolerates. `Put` is idempotent and rejects content that does not hash to its key — a
blob filed under a name it does not hash to would resolve, look verified, and be wrong.
`Get` re-verifies on the way out, so serving unverified bytes under a verified label is
impossible by construction. The algorithm subdirectory leaves room for a second digest
algorithm beside `sha256` without a migration. There is no global cache and no
cross-session dedup: workload file content is session-scoped data and must not outlive,
or leak between, sessions. The store materializes on the first successful capture, so a
session that captured nothing simply has no `blobs/` directory.

What is NOT claimed. Content bytes NEVER enter a signed OTLP segment. A segment carries
the guest's digest and the host's capture stamp; the bytes live beside it in an
unsigned side artifact anchored to the signed stream by nothing but the digest they
hash to. Nothing in the store is COSE-signed and nothing in it is required for a
session to verify: losing it costs a reader the ability to see what a file contained
and takes nothing away from the record. Tampering with it needs no key material to
detect — rehash and compare against the signed digest — and a modified blob simply
stops resolving. Capture is also not a read sensor: it observes only what the scan
reported as changed, so files the agent merely read remain invisible until an LSM read
policy ships.

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
- `DiffContents(relPath string, from, to []byte) (string, error)` — the per-file
  counterpart for callers holding content rather than two trees (the viewer's
  `/api/filediff`): both sides are written to a 0700 temp directory, removed on every
  return, and diffed with the same `git diff --no-index`, with the temp paths rewritten
  back to `relPath` in the headers. An empty side is written as a real empty file
  rather than special-cased, so a creation renders as all-additions and a deletion as
  all-deletions; the cost is that the result is a plain content diff carrying no "new
  file mode"/"deleted file mode" metadata. Nothing produced here is meant to be
  applied — that is `Apply`'s job, from the whole-tree `workspace.diff`.
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
   `Tag`/`DiskDigest` as `VMImage`/`VMImageDigest`); build the emitter chain around it
   (`recorder ← capture ← counter`, so the content-capture stamp lands before sealing —
   see "File content capture"); emit session.granted (grant
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

Teardown never abandons the seal for a shutdown problem. Stopping the broker is
bounded: in-flight guest POSTs get a short grace, then the remaining connections are
force-closed, so a slow ingest handler cannot hold teardown open (and cannot keep
emitting into a recorder that is being closed). A broker that fails to shut down inside
that window is logged, not fatal — the output manifest/diff, session.stopped,
session.sealed, the recorder Close, and the trust-record write all still run, and a
session whose evidence sealed and whose record was written ends `sealed`. Only a
failure that actually breaks the evidence (a recorder, seal, or trust-record error)
marks the session incomplete.

Crash safety: a deferred cleanup handler must revoke tokens, seal what exists, and
leave the session marked incomplete (state file `session.state` = one of
`created|running|sealed|incomplete`). Any run that ends in an error also writes the
reason to `session.error` (0600, human-readable). Without it an abort between recorder
creation and the first evidence record — a failed `--repo` clone, for instance — leaves
only `policy.json`, an empty sealed segment, and `session.state=incomplete` on disk,
with the cause surviving nowhere but the CLI's own stderr. The file holds exactly the
error text the CLI prints, which by contract never contains credentials.

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
            [--cap external-write:github] [--secret <glob>] [--cmd '...' (exec only)]
            [--keep-vm] [-- harness-args...]
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
calls. Every displayed event shows its evidence class. An Agents grouping built
from `agent.started`/`agent.completed` events nests children under their parent with
an attribution-strength badge (self-reported children are visibly labeled), the
harness-declared subagent type, and a lifecycle status (completed, the reported
outcome, never closed, or running). Children are displayed numbered in
`agent.started` order ("Child Agent 1 · general-purpose") — a viewer-assigned
ordinal, since the harness narrates no subagent name and no spawn-call description
can be tied to a specific child: concurrent same-type spawns were observed
registering out of call order, and the record contains no spawn↔agent linkage to
settle it. It always renders two
groups: "Unattributed Workload", now the residue (recordings made before Primary
attribution, hooks that ran without a Primary id, non-hook workload channels), and
"BoxedAi Infrastructure" (controller/recorder/supervisor events). A session with no
agent events shows "no agent decomposition reported", never a fabricated single
agent. Process-tree nodes are badged by `audit.producer`/`audit.evidence.class`,
so a workload-forged `process.executed` cannot render as a trusted
kernel-observed process. Verdict output names
SHA-256, COSE Sign1, EdDSA/Ed25519, the public-key fingerprint, segment/chain
outcomes, close status, and sensor-loss count. A running session with an
unsealed `.otlp` tail is explicitly marked provisional; the UI must not imply
that open-segment events are signed before their manifest and COSE Sign1 sidecar
exist.

Two endpoints hand back workload bytes rather than evidence metadata (see "File
content capture"). Both are registered on both muxes, are GET-only, and answer
`Cache-Control: no-store` — this is the content of files from someone's workspace and
it must not outlive the session directory in a proxy or an on-disk browser cache. The
dashboard resolves the session from the same `?id=<session>` its timeline fetch uses,
with the same "not a session id is 400, missing directory is 404" behavior; the
single-session viewer is already bound to one directory and takes no id.

- `GET /api/blob?digest=sha256:<64 hex>` — one captured blob's raw bytes as
  `application/octet-stream` with `X-Content-Type-Options: nosniff`, so a browser can
  never be talked into rendering captured workload content as HTML or script inside
  the viewer's own origin. A malformed digest is 400, a digest nothing captured is 404
  (expected, not exceptional — the capture policy declines files whose `file.changed`
  events still carry a digest), and a blob that no longer hashes to its own name is 500.
- `GET /api/filediff?path=&from=&to=` — `{path, from, to, diff}` as JSON. `from` is
  `baseline` (the session-start copy) or a blob digest; `to` is `empty` (a deletion) or
  a blob digest. The vocabularies are closed sets, so everything a client can ask for is
  either content the session already captured under its own policy, or content that
  policy is re-checked against here before it is read.

`/api/blob` needs no policy read: the store can only hold what the capture policy
already allowed into it, so a digest that resolves is by construction content the
session consented to keep. `/api/filediff` can reach past the store into
`workspace.orig`, so it gates on the session's own `policy.json` — never a viewer
default, and an
unreadable or unparsable policy is a hard failure rather than a fallback, since serving
content under rules the session never agreed to is exactly the outcome the gate exists
to prevent. A policy with no `max_bytes` is a session recorded before content capture
existed, and it never consented to have workspace content served back, so `/api/filediff`
answers 403; that is what closes the legacy read path into a `workspace.orig` sitting on
disk regardless. A path the session's own policy classifies as secret is likewise 403
even though `workspace.orig` still holds its session-start copy: withholding only counts
if it also holds on the read side, or a baseline diff would hand back the very `.env` or
private key capture refused to keep. `from=baseline` reads through `os.OpenRoot` rather
than a bare join — the validated path settles the literal string but says nothing about
symlinks, which `workspace.orig` preserves verbatim from the snapshot, and rooting the
open is what makes "workspace-relative" true of the bytes actually read. A missing file,
or a session directory with no `workspace.orig` at all, is empty content rather than an
error (a path created during the session has no session-start version, and a new-file
diff is what happened); a baseline larger than the capture cap is 422 rather than a
silent truncation, because half a file rendered as a diff misrepresents the change.
Diffs are computed on demand by `snapshot.DiffContents` and are never stored, never
digested, and never signed.

What the UI may claim. Both endpoints re-hash a blob on the way out, so bytes served
under a digest are bytes that still hash to a digest a sealed segment recorded. A diff
is a derived view between two endpoints and is trustworthy exactly as far as both of
those endpoints verify: blob↔blob is anchored at both ends, blob↔`empty` trivially at
one, and blob↔`baseline` only at the captured end — `workspace.orig` is an unsigned
host-side copy that the viewer does not re-check against `input-manifest.json`. The
diff text itself is derived at request time and is signed by nothing.

The Files tab's latest-per-path rows expand into that path's version history: every
`file.changed`/`file.deleted` carrying that exact `file.path`, newest first, derived
entirely client-side from events already loaded and deliberately ignoring the tab's
active filter — the diff base must be resolved against every version, not the visible
ones. Each version shows its sequence, digest, observer, and a capture chip:
`content · <size>` when `audit.content.capture=full`, the policy reason when the bytes
were withheld (secret, excluded, and oversized read muted; a lost scan race reads as a
warning; a read or store failure as serious), an unrecognized `file.capture.reason`
reported as an unexplained non-capture rather than flattened into "digest only", and
plain "digest only" for a session that recorded no capture at all. A version's diff is
fetched only when a reader opens it — one version at a time, cached per path+from+to,
dropped whenever the view switches sessions — because what comes back is captured
workload content. Its base is the nearest OLDER captured version of the same path, else
the session-start baseline, and the header states how many uncaptured versions the diff
jumps over instead of implying a change-by-change history. Diff rendering is bounded
(600 lines, tail dropped with a visible note), every line is escaped before it reaches
the DOM, and git's binary-content marker is lifted out as a plain note rather than
rendered as a diff body, which would imply the bytes are renderable text. A file
event's Timeline detail row offers a "file history" jump into that path's expansion.

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
| Invalid agent hierarchy            | Facets + verify=INCOMPLETE (never TAMPER)  |
| Captured blob absent/unreadable    | Facets + verify=INCOMPLETE (signed digests stand) |
| Captured blob digest mismatch      | TAMPER_SUSPECTED (host-side artifact)      |

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
  Per-version content capture inherits that granularity exactly: a version the scan
  never saw has no digest, therefore no blob and no row in the viewer's file history,
  so the version list is the scan's view of a file's history and not every write to it.
- Persisting workload file content is a policy-gated decision, not a default of the
  evidence model. Captured bytes sit unsigned at 0600 inside the session directory and
  are deleted with it; secret globs withhold by digest only, so the change stays
  attested while the bytes never leave the workspace. The globs are a name-shaped
  heuristic: a credential in a path the defaults (and any `--secret`) do not name is
  captured like any other file.
- The blob store can be pruned or lost at any time. That degrades the verdict to
  INCOMPLETE and flips `file_content_store_valid` — never silently — while the signed
  digests still stand, so history remains intact and merely becomes less inspectable.
- Capture races the workload rather than locking against it. A file rewritten faster
  than the host reads it records `changed_before_capture`/`missing_before_capture` and
  may never be captured at any version, even though every version's digest is on the
  record. The race self-heals only while the file still exists to be re-scanned.
- Content under an excluded directory is never in the store at any version; the only
  view of what changed there is the authoritative final `workspace.diff`.
- Evidence at rest is not encrypted (FileVault assumed).
- VM image digest is verified for LOCAL integrity only: `image.Resolve` recomputes the
  on-disk `disk.img`'s sha256 against `manifest.json` on every `run`, catching
  corruption or hand-editing after `build-image` produced it. There is no provenance
  verification on top of that — no signature over who ran `build-image`, and no
  reproducible-build guarantee that a rebuild yields identical bytes.
- Model request/response bodies stored as digest+usage only (no forensic body capture).
- Harness hook capture (`tool.requested`/`tool.completed`, and subagent `agent.*`
  registration) is workload self-reported and fail-open: a compromised harness can
  suppress or forge it. v0.1 only offers a one-way, non-gating PID plausibility
  check from submitted hook events to kernel observations; reverse suppression
  detection and agent/activity decomposition are deferred. Per-agent grouping is a
  `self_reported` ceiling. The `exec` harness has no hooks; Codex ships a compatible
  hooks system but its adapter is deferred, so only Claude sessions register
  subagents today.
- Subagents run in-process inside the harness (no pid ever exists for them), so the
  kernel sensor cannot see them by construction. Per-agent attribution above the
  process level is narration-derived; the observation track attributes activity to
  the session, and to a process subtree by lineage, but never to an in-process
  agent. The trusted per-agent executor and cgroup-joined ingestion that would
  raise this ceiling are deferred (no Tetragon cgroup export exists for a
  non-containerized workload at any current version).
- Concurrent byte-identical Bash commands from different agents pair ambiguously
  and are marked ambiguous rather than timestamp-guessed. An optional PreToolUse
  argv marker that would make the tool-use id kernel-visible is deferred — it would
  rewrite the workload's own command line.
- Codex adapter untested against a real OpenAI credential.
- ChatGPT-mode Codex device credentials (`access_token`+`account_id` from `codex login`)
  are proxied best-effort: host-side token expiry is never checked, so a stale token
  surfaces as an ordinary upstream 401 instead of the fail-fast error a missing/expired
  config or Keychain credential gets.
