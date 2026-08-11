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
internal/cli           cobra commands: build-image, run, sessions, view, diff, verify, apply, stop
internal/session       session lifecycle orchestration, IDs, session dir, state file
internal/image         golden VM image build/resolve, manifest, digest verification
internal/policy        profiles (review/develop/restricted), capability model   [SCAFFOLDED]
internal/evidence      event model, schema constants, Emitter interface          [SCAFFOLDED]
internal/recorder      sequencing, OTLP WAL segments, manifests, COSE signing, keys
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
`cli → session → {vm, image, snapshot, broker, recorder, view, verify}`; `cli → image`
(`build-image` calls it directly); `image → vm` (drives `vm.BakeConfig`/`vm.BakeVM` to
provision the bake boot); `broker → {evidence, policy}`; `vm → {evidence, policy}`;
`recorder → evidence`; `verify → evidence` (verify reads raw files; it must NOT import
recorder internals — independent implementation of digest/signature checking is the
point); `view → evidence`. `evidence` and `policy` import nothing else in the repo.

## Host filesystem layout

State root `~/.boxedai/` (override: env `BOXEDAI_HOME`):

```
~/.boxedai/
  keys/recorder.key            Ed25519 private key (0600), PEM PKCS8
  keys/recorder.pub            Ed25519 public key, PEM PKIX
  config.json                  host config (upstream creds refs, adapter allowlists)
  images/<arch>/disk.img       golden VM disk, built by `boxedai build-image` (internal/image)
  images/<arch>/manifest.json  tag, build timestamp, disk sha256 digest (see below)
  sessions/<session-id>/
    session.json               session grant (see below)
    policy.json                resolved policy manifest (canonical JSON)
    workspace/                 APFS clone of the repo, mounted rw into the VM
    harness-home/              guest-mounted fresh Claude/Codex home and selected global instructions
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
codex_package}`. `boxedai run` calls `image.Resolve(arch)` before doing anything else
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
  "schema": "boxedai.session/v1",
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
  "assurance_mode": "local"
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
tool.requested process.executed process.exited file.changed file.deleted
workspace.manifested network.connected network.denied internal_tool.dispatched
internal_tool.completed internal_tool.failed effect.requested effect.approved
effect.denied effect.dispatched effect.completed effect.failed credential.issued
credential.revoked sensor.started sensor.loss sensor.restarted segment.sealed`.

Signed evidence content capture defaults to `redacted` metadata + sha256 digests; the
broker's model evidence stores digest + token counts + model id only. Claude sessions
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
   append length-delimited (protodelim) to the open `.otlp` WAL file, fsync per batch.
3. Emit failure = session-fatal: surface the error; callers must stop the session.
4. Seal on: size threshold (default 8 MiB), explicit call, Close.
5. Segment manifest JSON: `{schema:"boxedai.segment/v1", session_id, segment_number,
   first_sequence, last_sequence, record_count, prev_segment_digest ("sha256:..." or
   "" for first), segment_digest, policy_digest, sensor_loss_count,
   sensor_restart_count, created_at, sealed_at}` — canonical JSON (sorted keys, no
   extra whitespace); digest = sha256 over exact segment file bytes.
6. Sign manifest bytes with COSE Sign1 (Ed25519, `veraison/go-cose`), write `.cose`.
7. Key management: `LoadOrGenerateKey(dir)` — Ed25519 keypair under `~/.boxedai/keys/`.

## Verifier (internal/verify)

Input: session dir (offline; no network). Checks, in order: (1) COSE signature of every
manifest against the trust root (recorder.pub supplied or from session.json);
(2) segment digest matches file bytes; (3) prev-digest chain; (4) sequence continuity
1..N with no gaps or duplicates across segments; (5) session.granted, session.started,
session.stopped, session.sealed all present exactly once and correctly ordered;
(6) policy digest consistent across grant, events, manifests; (7) sensor invariants:
sensor.started before workload launch, any sensor.loss/restart flagged; (8) flow
invariants: every `effect.dispatched` preceded by `effect.approved` with matching
action digest; every `internal_tool.dispatched` preceded by `authorization.decided`
allow; (9) output-manifest digest matches `workspace.manifested` event.

Verdicts: `LOCAL_ONLY` (all checks pass; ceiling in v0.1), `INCOMPLETE` (missing
close/seal, sensor loss, or unresolved tail), `BYPASS_DETECTED` (flow invariant
violated), `TAMPER_SUSPECTED` (signature/digest/sequence inconsistency).
`VERIFIED` is unreachable in v0.1 and the verifier must say why when asked.
Also report facets: signature validity, chain validity, sequence continuity, close
status, sensor-loss count, ungated-activity count.

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
`sessions/<id>/workspace` → `/workspace` writable (read-only for `review`). Claude
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
2. Install runtime deps: nodejs 22 (NodeSource), git. Install BOTH harness CLIs
   unconditionally — `@anthropic-ai/claude-code` and `@openai/codex` via npm --global —
   so the image is harness-agnostic and no session ever installs anything at boot
   regardless of which one it requests. Corporate CA injection (`extra_ca_pem`, read
   from `~/.boxedai/config.json` at build-image time) is trusted into
   /usr/local/share/ca-certificates before npm runs, plus exported via
   `NODE_EXTRA_CA_CERTS` since Node ignores the system store update-ca-certificates
   just updated.
3. Install tetragon (release tarball, systemd unit, JSON export to
   /var/log/tetragon/tetragon.log) and enable+start it, so every session's guest already
   has it running. Best-effort: if the release tarball is unavailable for the arch, bake
   provisioning logs and continues; the guest agent then falls back to procfs polling
   and reports `sensor.started` with `sensor.mechanism=procfs` (weaker, recorded
   honestly).
4. Install (but do not configure) the nftables and rsyslog packages, and enable
   rsyslog's systemd unit. No ruleset is written and rsyslog is not started yet — the
   ruleset needs a real session's broker IP, which does not exist at bake time.

`build-image` then stops the bake VM, copies its disk to `images/<arch>/disk.img`,
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
   packet is already governed by the ruleset above; agent POSTs sensor.started.

Guest agent duties (root daemon):
- Health: verify tetragon running (or start procfs fallback), report sensor events.
- Tail tetragon JSON export; filter to the session unit's cgroup subtree; forward
  process.executed/process.exited (+ network events if tetragon policy loaded) in
  batches to `POST /v1/events` with token S.
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
  final flush.

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
`<stream-mode>` is `--pty --wait` when the controller's stdin is a real terminal
(interactive claude/codex — genuine pty passthrough) and `--pipe` otherwise
(scripted `exec`/CI: `--pty` never returns without a controlling terminal, so it
would hang teardown; `--pipe` streams stdio and exits when the unit exits).
TTY detection uses an isatty ioctl, not `os.ModeCharDevice` — `/dev/null` is a
character device but not a terminal. `WorkingDirectory=/workspace` so the agent's
relative file operations land in the writable overlay, not read-only `/`. Harness adapters set
env: claude → `ANTHROPIC_BASE_URL=http://host.lima.internal:<port>/v1/model/anthropic`,
`ANTHROPIC_AUTH_TOKEN=<W>`, `CLAUDE_CONFIG_DIR=/home/agent/.claude`,
`DISABLE_AUTOUPDATER=1`, narrow error-reporting/feedback/marketplace controls, verbose native
debug, and authenticated OTLP HTTP/JSON logs, metrics, and beta traces. Prompt text,
assistant text, tool details/content, and untruncated raw Messages API bodies are all
enabled; the raw bodies remain in the guest-mounted config directory while OTLP
exports go to the host-only `claude-telemetry` sibling. Claude starts with
`--debug-file /home/agent/.claude/debug/claude-code.log`; codex → `OPENAI_BASE_URL=...openai`,
`OPENAI_API_KEY=<W>`; exec → runs `sh -lc <cmd>` (scripted/e2e testing harness,
recorded like any other).

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
7. Wait for guest agent sensor.started (timeout 120s → abort, INCOMPLETE).
8. Emit session.started → launch harness interactively (user drives).
9. On harness exit: revoke tokens (credential.revoked), guest drain, final output
   manifest + diff, workspace.manifested(output), session.stopped, Close recorder →
   session.sealed inside final segment, limactl delete, print summary
   (files changed, network denials, tools used, evidence path, verify hint).

Crash safety: a deferred cleanup handler must revoke tokens, seal what exists, and
leave the session marked incomplete (state file `session.state` = one of
`created|running|sealed|incomplete`).

## CLI (internal/cli)

```
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
boxedai apply <session>     apply diff to original repo (asks confirmation)
boxedai stop <session>      kill switch
```

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
| Direct egress attempt              | nftables deny + network.denied event       |
| Tool not granted by profile        | 403 + authorization.decided(deny) event    |
| Effect without approval            | 403 + effect.denied event                  |
| Recorder write failure             | Session-fatal, never silent                |
| Kill switch                        | Revoke → freeze → seal → destroy           |
| Crash/missing seal                 | session.state=incomplete; verify=INCOMPLETE|

## Known gaps (v0.1, keep this list honest)

- No external transparency/receipts → verdict ceiling LOCAL_ONLY.
- Broker is HTTP with bearer tokens on the lima user-net, not TLS.
- No Landlock; filesystem policy is systemd hardening (ProtectSystem=strict etc.).
- Tetragon network/file TracingPolicies not shipped; network evidence = nftables logs,
  file evidence = periodic /workspace scan + final manifest (authoritative).
- Tetragon frequently fails to load in the Lima vz guest (BPF/BTF/kernel), so process
  evidence in practice is the procfs fallback: `sensor.mechanism=procfs`,
  `correlation=none`, exit codes reported as `-1` (procfs sees the PID vanish, not the
  real status). Honestly recorded; hardening tetragon-in-vz is deferred.
- Live file.changed granularity is the 2s scan interval; changes fully created and
  deleted within one interval are only caught by the authoritative final diff.
- Evidence at rest is not encrypted (FileVault assumed).
- VM image digest is verified for LOCAL integrity only: `image.Resolve` recomputes the
  on-disk `disk.img`'s sha256 against `manifest.json` on every `run`, catching
  corruption or hand-editing after `build-image` produced it. There is no provenance
  verification on top of that — no signature over who ran `build-image`, and no
  reproducible-build guarantee that a rebuild yields identical bytes.
- Model request/response bodies stored as digest+usage only (no forensic body capture).
- Codex adapter untested against a real OpenAI credential.
- ChatGPT-mode Codex device credentials (`access_token`+`account_id` from `codex login`)
  are proxied best-effort: host-side token expiry is never checked, so a stale token
  surfaces as an ordinary upstream 401 instead of the fail-fast error a missing/expired
  config or Keychain credential gets.
