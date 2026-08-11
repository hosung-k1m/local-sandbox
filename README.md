# BoxedAi

BoxedAi launches Claude Code or Codex inside a disposable Lima Linux VM on macOS and
produces independently verifiable, human-readable audit evidence: which session ran,
under which policy and VM image, which processes executed, which workspace files
changed, which network egress was attempted or denied, which internal tools were
invoked, and whether the host-side evidence was altered after it was sealed.

The binding architecture contract is [`DESIGN.md`](DESIGN.md). Read it before changing code.

## Status

v0.1 vertical slice (threat-model tiers 1–3 plus signed evidence and an offline
verifier). Assurance ceiling is `LOCAL_ONLY`: evidence is COSE-signed so it cannot be
altered after sealing, but there is no external transparency witness yet, so a malicious
host administrator could discard evidence before it is sealed. `VERIFIED` requires the
external witnessing planned for a later phase. See `DESIGN.md` "Known gaps".

## Prerequisites

- macOS on Apple Silicon or Intel.
- Toolchain is managed by Hermit and pinned in this repo: `./bin/go` (Go 1.26) and
  `./bin/limactl` (Lima 2.2). No global installs needed.
- For brokered internal tools (codesearch), the host `sq` CLI must be authenticated.

## Build

```
make        # builds dist/boxedai and the cross-compiled guest agent
make test   # runs the full test suite
```

`make guest` cross-compiles the Linux guest supervisor for both arm64 and amd64 into
`dist/guest/`; `boxedai run` serves the matching binary to the VM over the broker.

## Run

Before the first `run` (and again after upgrading BoxedAi), build the golden VM image:

```
dist/boxedai build-image                              # bakes Node, Claude Code, Codex,
                                                        # and Tetragon into a golden disk
```

`build-image` boots a throwaway VM, installs Node plus both `@anthropic-ai/claude-code`
and `@openai/codex` (the image is harness-agnostic) and Tetragon into it, and saves the
resulting disk under `~/.boxedai/images/<arch>/`. `boxedai run` boots directly from that
disk instead of provisioning a fresh Ubuntu image every session, and fails fast with a
clear error if the image is missing.

```
dist/boxedai run claude .                             # interactive Claude Code in a sandbox
dist/boxedai run codex .                               # interactive Codex
dist/boxedai run exec . --cmd 'go test ./...'          # scripted, non-interactive
dist/boxedai run claude . -- -p 'explain this repo'    # non-interactive, passthrough argv
dist/boxedai run codex . -- exec 'go test ./...'       # same, for codex
dist/boxedai run codex --repo org-49461806@github.com:squareup/repo.git --branch feature
```

`--repo` is mutually exclusive with the local `[path]`. It creates a fresh,
single-branch clone and records the remote, branch, and commit in `session.json`.

If you're logged into Claude Code (or Codex) on the host, `boxedai run claude`/`codex`
just works: the broker picks up your device login automatically (Claude Code's Keychain
credential, or `~/.codex/auth.json` for Codex — see `DESIGN.md` "Broker" for the full
resolution order and the ChatGPT-mode caveat). An explicit `ANTHROPIC_API_KEY` /
`OPENAI_API_KEY` (or host config key) always overrides the device login.

For Claude and Codex sessions started from a GitHub repository, BoxedAi asks the host `gh` CLI
for that repository's canonical name and SSH URL, then exposes only that repository
through the broker. Git inside the VM can fetch and pull normally. The default
`develop` profile makes push grantable, with one session-scoped approval on the host TTY before
the broker or VM starts. That approval is cached only for `github/push` against the
exact current repository; no approval prompt reads stdin while Claude is running, and
all other effects remain denied. Non-interactive sessions auto-deny the push. The
harness rewrites that repository's exact and canonical GitHub URLs to an
authenticated guest bridge; the host broker runs `/usr/bin/ssh` with the host's
existing GitHub SSH identity. No GitHub token or SSH key enters the broker or VM, and
the VM still has no direct GitHub egress. Configure the host with `gh auth login`
first and ensure its GitHub SSH URL works noninteractively.

Anything after a literal `--` is passed through as argv to the claude/codex CLI inside
the guest, so the harness can be driven non-interactively.

Harnesses use `~/.boxedai/sessions/<session>/harness-home/`. BoxedAi copies only
conventional host-global `CLAUDE*.md` or `AGENTS*.md` instruction files into that
session-scoped home as regular 0600 files; it never mounts complete host config
directories. Repository-local instructions remain in the workspace. Claude Code's
verbose native debug log is `debug/claude-code.log`, conversation transcripts are
under `projects/`, and untruncated Messages API request/response bodies are under
`raw-api-bodies/`. Claude Code also exports complete OTLP HTTP/JSON logs, metrics, and
beta traces through the authenticated broker into the host-only sibling directory
`~/.boxedai/sessions/<session>/claude-telemetry/` as `logs.jsonl`, `metrics.jsonl`,
and `traces.jsonl` (0600). These files can contain prompts, responses, tool inputs,
tool output, source, and account metadata, so treat the entire session directory as
sensitive. They are diagnostic artifacts, not signed evidence segments. The host's
complete `~/.claude` directory and credential never enter the VM; model authentication
remains behind the broker.

Flags: `--profile develop|review|restricted` (default `develop`), `--repo <remote>`,
`--branch <branch>`, `--cap external-write:github` (repeatable), `--keep-vm`.

Profiles: `develop` (writable overlay, model + brokered internal reads — the default),
`review` (read-only snapshot), `restricted` (model only, no internal tools). No
host credentials enter the VM and egress is default-deny except the host broker.

## Inspect and verify

```
dist/boxedai --web                 # global local dashboard for live and historical sessions
dist/boxedai sessions              # list recorded sessions and their state
dist/boxedai view <session>        # evidence timeline (each event shows its class)
dist/boxedai view <session> --web  # local web viewer
dist/boxedai diff <session>        # workspace changes (input -> output)
dist/boxedai verify <session>      # offline verifier: verdict + per-check facets
dist/boxedai apply <session>       # apply the workspace diff back to the repo (confirms first)
dist/boxedai stop <session>        # kill switch: freeze, seal, destroy
```

Every displayed event carries an evidence class distinguishing what was self-reported by
the harness from what was independently observed by the guest kernel witness, mediated by
the broker, or confirmed by a target. Timeline rows show event bodies and curated
details. The verifier explicitly reports SHA-256, COSE Sign1, EdDSA/Ed25519, the
public-key fingerprint, and segment/chain outcomes while re-deriving signatures, digests, the
segment hash chain, sequence continuity, lifecycle ordering, and request→approval→dispatch
flow invariants entirely offline, and reports one of `LOCAL_ONLY`, `INCOMPLETE`,
`BYPASS_DETECTED`, or `TAMPER_SUSPECTED`.

State lives under `~/.boxedai/` (override with `BOXEDAI_HOME`). Raw signed evidence
segments are authoritative; the SQLite/web projections are rebuilt from them on demand.
The global dashboard binds to `127.0.0.1` by default, prints the reachable URL, polls
for session and timeline updates, and marks active open-segment evidence as
provisional until that segment has a manifest and COSE Sign1 signature. Its session
list uses session and segment-manifest metadata, with an in-memory cache for sealed
historical sessions; those rows are labeled as unverified summaries and expose the
manifest-declared segment digest as `declared_segment_digest`. Selecting a session
runs the full projection and verifier, including recomputed hashes, chain checks,
verdict, and recorder fingerprint.
