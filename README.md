# BoxedAi

BoxedAi runs Claude Code, Codex, or a shell command in a disposable Linux VM
and turns the session into independently verifiable audit evidence. It is a
local control plane for agentic development: agents get a useful workspace and
approved tools, while operators get isolation, explicit policy, a timeline of
what happened, and a reviewable diff.

The project is designed to make trustworthy agent workflows practical—and to
give contributors clear seams for improving sensors, policy, adapters, the
viewer, and verification.

## Why BoxedAi is interesting

- Disposable Lima VMs on macOS, with a pre-baked Ubuntu image and no host
  workspace mounted into the guest except the session clone.
- Kernel-observed process lifecycle evidence from Tetragon's eBPF sensors,
  including fork, exec, and exit events. If eBPF/BTF support is unavailable,
  the guest supervisor degrades to explicitly labelled procfs coverage and the
  verifier reports the loss honestly.
- Default-deny networking enforced inside the guest with nftables. Direct
  egress—including DNS—is denied and logged; model traffic, internal tools,
  and approved effects travel through the authenticated host broker.
- Append-only OTLP evidence segments with monotonically assigned sequence
  numbers, SHA-256 segment digests, a previous-segment digest, and COSE Sign1
  signatures using Ed25519. Sealed manifests form a tamper-evident,
  hash-chained log that can be checked offline.
- A portable, signed session trust record that binds the policy, VM image,
  evidence chain, workspace manifests, sensor status, and verification facets.
- An independent offline verifier that checks signatures, exact bytes,
  sequence continuity, lifecycle invariants, authorization gates, sensor
  coverage, and captured content. It distinguishes `LOCAL_ONLY`,
  `INCOMPLETE`, `BYPASS_DETECTED`, and `TAMPER_SUSPECTED`.
- Three capability-oriented profiles: `review` (read-only workspace),
  `develop` (writable workspace and approval-gated GitHub push), and
  `restricted` (model-only access).
- A host-side broker that proxies Anthropic/OpenAI traffic without placing
  provider credentials in the VM, exposes allowlisted internal read tools,
  and mediates external effects with action digests and approvals.
- Git transport isolation for the exact repository, while host SSH
  credentials remain with `/usr/bin/ssh` and never enter the guest or broker
  payloads.
- Harness-aware capture for Claude Code hooks, model/tool/effect events,
  subagent lifecycle and attribution, process observations, network denials,
  file changes, workspace manifests, and GitHub activity.
- Content-aware workspace auditing: policy-controlled capped SHA-256 file
  digests, secret globs, excluded directories, optional host-side blobs, and
  an authoritative input/output manifest plus unified diff.
- Crash-safe teardown and a kill switch that revokes broker tokens, freezes
  the workload, drains sensors, seals evidence, and destroys the VM.
- A CLI timeline, web dashboard, session diff, evidence verification, and
  apply workflow for reviewing and selectively bringing changes back to the
  original repository.

## Architecture at a glance

```text
macOS host / controller
┌─────────────────────────────────────────────────────────────────────────┐
│ boxedai CLI → session orchestrator → Lima VM lifecycle                  │
│      │                    │                                             │
│      ├── policy + snapshot + image manifest                             │
│      ├── host broker ─────┼── model proxy / tools / effects / Git bridge  │
│      ├── recorder         │                                             │
│      │   OTLP WAL → SHA-256 manifests → COSE Sign1 chain                 │
│      ├── verifier + trust record                                         │
│      └── viewer / diff / apply                                           │
└───────────────┬─────────────────────────────────────────────────────────┘
                │ authenticated broker and supervisor channels
                ▼
guest: disposable Ubuntu Lima VM
┌─────────────────────────────────────────────────────────────────────────┐
│ nftables default-deny egress + rsyslog                                  │
│ Tetragon eBPF process sensor → guest supervisor → ordered event batches  │
│ periodic workspace scanner → file digests                               │
│ agent user (uid 4242) → Claude Code / Codex / exec                       │
└─────────────────────────────────────────────────────────────────────────┘
```

The workload is unprivileged and runs under systemd resource and filesystem
hardening. The root guest supervisor owns sensor setup, authenticated event
forwarding, health monitoring, bounded draining, and the kill path. The host
recorder is the sole authority for event sequence numbers and evidence class;
workload narration cannot label its own events as kernel-observed or trusted.

## Session lifecycle

1. Resolve and verify the golden VM image by its local disk digest.
2. Resolve the profile and capture policy, create the session grant, and start
   the recorder.
3. Snapshot the repository and create an input manifest. The VM receives the
   session clone, not the host checkout.
4. Start the per-session broker and mint short-lived workload and supervisor
   bearer tokens. Provider credentials stay host-side.
5. Boot the Lima VM from the pre-baked image. Session-time provisioning
   installs the guest agent, applies nftables lockdown, and establishes fresh
   sensor boundaries before launching the workload.
6. Wait for process-sensor readiness, then launch the selected harness inside a
   bounded systemd unit. Claude Code and Codex reach their providers only via
   the broker.
7. Capture kernel/process events, hook events, file digests, network denials,
   model calls, tool calls, approvals, effects, and agent lifecycle events.
8. On exit or `boxedai stop`, drain the guest, revoke credentials, create the
   output manifest and diff, seal all evidence segments, write the signed trust
   record, and delete the VM.

## Evidence and integrity model

Every event is represented as an OTLP `LogRecord` with a recorder-assigned
session sequence, event ID, policy digest, producer identity, evidence class,
outcome, and correlation metadata. Events are written to a length-delimited
write-ahead log. When a segment is sealed, BoxedAi:

1. hashes the exact segment bytes with SHA-256;
2. records the digest and the prior segment digest in a canonical manifest;
3. signs the exact manifest bytes with COSE Sign1 / Ed25519; and
4. fsyncs the segment, sidecars, and directory before reporting the seal.

The result is an append-only, hash-chained, signed evidence set. “Immutable”
here means sealed history cannot be changed without breaking its signature,
digest, or chain. In v0.1 this is local assurance: a host administrator could
still delete evidence before sealing, so there is no claim of external
transparency or host-root resistance.

The offline verifier independently reads the raw segments and checks:

- COSE signatures and the Ed25519 trust root;
- exact segment bytes, previous-digest links, and physical sequence order;
- session grant, policy, lifecycle, workspace, and trust-record bindings;
- sensor readiness, loss, restart, and process coverage;
- approval-before-dispatch rules for tools and external effects; and
- content-addressed captured blobs against the signed file digest.

Signed evidence defaults to metadata and digests. Explicitly captured file
bytes live in a separate per-session content-addressed store and are never
written into signed OTLP segments.

## Networking and broker boundaries

The guest's nftables ruleset is installed at session startup after the broker
address is known. It permits only the paths needed for the authenticated
session broker and drops all other egress, including DNS. Kernel log lines for
denials are tailed by the guest agent and become `network.denied` evidence.

The broker provides separate authenticated routes for:

- Anthropic and OpenAI-compatible model requests, recording request/response
  digests, model identity, and token usage;
- configuration-driven internal read tools with strict argv substitution,
  timeouts, output limits, and capability checks;
- external effects such as GitHub operations, normalized and approval-gated by
  action digest;
- exact-repository Git upload-pack and receive-pack streams; and
- guest supervisor event ingest and Claude telemetry forwarding.

No provider key, GitHub token, or private key is copied into the guest. A
failed authorization is itself recorded, and an effect cannot dispatch without
the matching successful approval.

## Repository map

| Package | Responsibility |
| --- | --- |
| `internal/cli` | User-facing commands: setup, run, view, verify, diff, apply, stop |
| `internal/session` | Session lifecycle, grants, snapshots, teardown, orchestration |
| `internal/vm` | Lima configuration, image boot, provisioning, guest hardening |
| `internal/image` | Golden image build, manifest, and disk digest checks |
| `internal/policy` | Profiles, capabilities, resource limits, capture rules |
| `internal/broker` | Model proxy, internal tools, effects, Git bridge, event ingest |
| `internal/evidence` | Event schema, catalog, attributes, and emitter contract |
| `internal/recorder` | Ordered OTLP WAL, segment manifests, COSE signing, keys |
| `internal/verify` | Independent offline verification and verdict facets |
| `internal/trustrecord` | Signed portable session summary and cross-derivation |
| `internal/blobstore` | Per-session content-addressed captured file bytes |
| `internal/view` | SQLite projection, CLI timeline, embedded web dashboard |
| `guest/agent` | Root supervisor, Tetragon/procfs watcher, nftables watcher, scanner, hooks |

See [DESIGN.md](DESIGN.md) for the binding component contract, event catalog,
threat model, failure behavior, and known gaps.

## Requirements

- macOS on Apple Silicon or Intel
- Go 1.25 or newer
- [Lima](https://lima-vm.io/) (`limactl` on `PATH`)
- Git and SSH
- GitHub CLI (`gh`) when using `--repo` or GitHub integration
- Internet access for the Ubuntu image and VM dependencies

BoxedAi uses the official Ubuntu cloud image and public package registries. It
does not require a company VPN, proxy, certificate, private registry, or
prebuilt image.

## Setup and run

Build the CLI and guest agent:

```sh
make
```

Run the read-only preflight or friendly setup command:

```sh
dist/boxedai doctor
dist/boxedai setup
```

Build the golden image before the first run when setup has not done so:

```sh
dist/boxedai build-image
```

Run an agent or command:

```sh
dist/boxedai run claude .
dist/boxedai run codex .
dist/boxedai run exec . --cmd 'go test ./...'
dist/boxedai run claude . -- -p 'explain this repository'
```

The default `develop` profile uses a writable workspace. Use
`--profile review` for a read-only workspace or `--profile restricted` for
model-only access. For a fresh GitHub clone:

```sh
gh auth login
dist/boxedai run codex --repo owner/project.git --branch feature
```

Anything after `--` is passed to Claude Code or Codex. Use `--keep-vm` while
debugging guest behavior.

## Inspect, verify, and contribute

```sh
dist/boxedai sessions
dist/boxedai view <session>
dist/boxedai diff <session>
dist/boxedai verify <session>
dist/boxedai apply <session>
dist/boxedai stop <session>
dist/boxedai --web
make test
```

State and evidence live under `~/.boxedai`; set `BOXEDAI_HOME` to relocate it.
Session directories are sensitive because optional diagnostics can include
prompts, responses, tool inputs, and source content.

Contributions are especially welcome in the areas that make agent execution
more observable and collaborative: new evidence producers and sensors,
policy profiles and adapters, verifier invariants, dashboard views, image and
Lima portability, harness integrations, performance, tests, and documentation.
Start with [DESIGN.md](DESIGN.md), keep security claims aligned with the
verifier's actual checks, add focused tests, and run `make test` before opening
a pull request. For changes that affect the evidence contract, update the
design contract first and include the corresponding verification coverage.
