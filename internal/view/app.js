// BoxedAi web UI client. Plain script (no modules, no build step — DESIGN.md
// "Viewer": "embedded HTML pages (no build step, vanilla JS)"). Boots off
// document.body.dataset.page ("session" or "dashboard") and renders one
// shared SessionView component; the dashboard wraps it with a session-list
// sidebar. See internal/view/web.go for the JSON payload shapes this reads.

// ---- helpers/esc ----

// esc HTML-escapes any value for safe interpolation into innerHTML. Workload
// -controlled data (event names, bodies, attrs, argv, ids, digests, check
// details...) is adversarial and MUST always pass through this before it
// reaches the DOM as markup.
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

// fmtClock renders an RFC3339Nano timestamp as a local HH:MM:SS.mmm string
// for compact table cells. Falls back to the raw string if it doesn't parse.
function fmtClock(ts) {
  var d = new Date(ts);
  if (isNaN(d.getTime())) return ts || "";
  return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds()) +
    "." + pad3(d.getMilliseconds());
}

// fmtClockShort is fmtClock without the millisecond tail, for header chips.
function fmtClockShort(ts) {
  var d = new Date(ts);
  if (isNaN(d.getTime())) return ts || "";
  return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
}

// fmtTs is the timestamp formatter exposed to the phase-2 Processes hook via
// the `api` object; it matches the Timeline's own HH:MM:SS.mmm label so pid
// focus / hover tooltips read consistently across tabs.
function fmtTs(ts) {
  return fmtClock(ts);
}

function pad2(n) { return String(n).padStart(2, "0"); }
function pad3(n) { return String(n).padStart(3, "0"); }

// numFmt renders an integer with thousands separators ("12,431").
function numFmt(n) {
  return Number(n || 0).toLocaleString("en-US");
}

// fmtBytes renders a byte count compactly ("812 B", "12.4 KiB", "3.1 MiB").
// Binary units, not decimal: the only byte counts the UI shows are captured
// file sizes, which are read against a capture cap the policy states in binary
// (max_bytes 8388608 = 8 MiB), and a "8.4 MB" label next to an "8 MiB" cap
// reads like a contradiction.
function fmtBytes(n) {
  var v = Number(n);
  if (!isFinite(v) || v < 0) return String(n);
  if (v < 1024) return v + " B";
  var units = ["KiB", "MiB", "GiB"];
  var u = -1;
  do { v /= 1024; u++; } while (v >= 1024 && u < units.length - 1);
  return (v < 10 ? v.toFixed(1) : String(Math.round(v))) + " " + units[u];
}

// relTime buckets a timestamp against now into a coarse human label for the
// dashboard's session cards ("just now", "4m ago", "3h ago", "2d ago").
function relTime(ts) {
  if (!ts) return "";
  var then = new Date(ts).getTime();
  if (isNaN(then)) return "";
  var deltaS = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (deltaS < 10) return "just now";
  if (deltaS < 60) return deltaS + "s ago";
  var m = Math.floor(deltaS / 60);
  if (m < 60) return m + "m ago";
  var h = Math.floor(m / 60);
  if (h < 24) return h + "h ago";
  var days = Math.floor(h / 24);
  return days + "d ago";
}

// truncateDigest middle-truncates an "algo:hex" digest to "algo:ab12…ef90"
// so long SHA-256 hex strings don't blow out table columns; the full value
// is always kept in a title attribute and behind the accompanying copy
// button.
function truncateDigest(d) {
  if (!d) return "";
  var m = /^([a-zA-Z0-9_-]+):([0-9a-fA-F]+)$/.exec(d);
  if (!m) return d.length > 14 ? d.slice(0, 6) + "…" + d.slice(-4) : d;
  var algo = m[1], hex = m[2];
  if (hex.length <= 12) return d;
  return algo + ":" + hex.slice(0, 4) + "…" + hex.slice(-4);
}

// debounce returns a wrapper that only invokes fn after ms have elapsed
// since the last call, used for the search input and hash-state writes.
function debounce(fn, ms) {
  var t = null;
  return function () {
    var args = arguments, ctx = this;
    clearTimeout(t);
    t = setTimeout(function () { fn.apply(ctx, args); }, ms);
  };
}

// copyToClipboard writes text to the clipboard and flashes "copied" feedback
// on the triggering element (restored after a short delay).
function copyToClipboard(text, el) {
  var restore = el ? el.textContent : null;
  function flash() {
    if (!el) return;
    el.textContent = "copied";
    el.classList.add("copied-flash");
    setTimeout(function () {
      el.textContent = restore;
      el.classList.remove("copied-flash");
    }, 900);
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(flash, flash);
  } else {
    flash();
  }
}

// attrRaw reads one attrs value off a webEvent without coercion (attrs
// values are already scalars: string|number|bool per the JSON payload).
function attrRaw(ev, key) {
  return ev && ev.attrs ? ev.attrs[key] : undefined;
}

// statusColor maps a semantic role to its design-system CSS color, shared by
// every colored chip/text in the app and exposed to the phase-2 Processes
// hook so it can color process nodes consistently with the rest of the UI.
var STATUS_COLOR_VARS = {
  good: "var(--s-good)",
  warn: "var(--s-warn)",
  serious: "var(--s-serious)",
  crit: "var(--s-crit)",
  info: "var(--info)",
  muted: "var(--ink-3)",
};
function statusColor(role) {
  return STATUS_COLOR_VARS[role] || STATUS_COLOR_VARS.muted;
}

// classColorVar maps an evidence-class badge (server-sent, e.g. "KERNEL") to
// its categorical CSS color; unrecognized/forward-compatible badges fall
// back to --ink-3 rather than asserting an identity color for them.
var CLASS_COLOR_VARS = {
  KERNEL: "var(--c-kernel)",
  BROKER: "var(--c-broker)",
  HARNESS: "var(--c-harness)",
  SELF: "var(--c-self)",
  TARGET: "var(--c-target)",
  INTEG: "var(--c-integ)",
};
function classColorVar(badge) {
  return CLASS_COLOR_VARS[badge] || "var(--ink-3)";
}

// outcomeColorVar/verdictColorVar/proofStatusColorVar/sessionStateColorVar
// implement the fixed status-color mappings from the design spec.
function outcomeColorVar(outcome) {
  switch (outcome) {
    case "success": return statusColor("good");
    case "failure": return statusColor("serious");
    case "denied": return statusColor("crit");
    case "cancelled": case "interrupted": return statusColor("warn");
    default: return statusColor("muted");
  }
}
function verdictColorVar(verdict) {
  switch (verdict) {
    case "VERIFIED": case "LOCAL_ONLY": return verdict === "VERIFIED" ? statusColor("good") : statusColor("info");
    case "INCOMPLETE": return statusColor("warn");
    case "BYPASS_DETECTED": case "TAMPER_SUSPECTED": return statusColor("crit");
    default: return statusColor("muted");
  }
}
function proofStatusColorVar(status) {
  switch (status) {
    case "sealed": return statusColor("good");
    case "sealed_unverified": return statusColor("warn");
    case "provisional": return statusColor("info");
    case "unavailable": return statusColor("serious");
    default: return statusColor("muted");
  }
}
function sessionStateColorVar(state) {
  switch (state) {
    case "running": return statusColor("info");
    case "sealed": return statusColor("good");
    case "incomplete": return statusColor("warn");
    case "created": return statusColor("muted");
    default: return statusColor("muted");
  }
}
function connectionStateColorVar(state) {
  switch (state) {
    case "live": return statusColor("good");
    case "reconnecting": return statusColor("warn");
    case "stale": return statusColor("serious");
    case "complete": return statusColor("good");
    default: return statusColor("muted");
  }
}
function boolColorVar(b) {
  return b ? statusColor("good") : statusColor("crit");
}

// chipHtml renders one colored pill with the shared .chip component; color
// is a CSS color expression (usually a var(--...) reference), never the
// only channel — the label text is always present.
function chipHtml(label, color, extraClass, title) {
  var cls = "chip" + (extraClass ? " " + extraClass : "");
  var t = title ? ' title="' + esc(title) + '"' : "";
  return '<span class="' + cls + '" style="--chip-color:' + color + '"' + t + '>' + esc(label) + "</span>";
}
function ktextHtml(label, color) {
  return '<span class="ktext" style="--chip-color:' + color + '">' + esc(label) + "</span>";
}

// ---- constants ----

// BOOKKEEPING_ATTRS are attrs already shown as their own column/chip (or
// pure recorder plumbing) and so are hidden from summaries and the search
// corpus — the same set the CLI timeline and old dashboard hid.
var BOOKKEEPING_ATTRS = new Set([
  "audit.schema.version", "audit.event.id", "audit.sequence", "audit.session.id",
  "audit.evidence.class", "audit.producer", "audit.monotonic_ns", "audit.policy.digest",
  "audit.outcome", "audit.action.id", "audit.parent_action.id", "vm.id",
]);

var OUTCOMES = ["success", "failure", "denied", "cancelled", "interrupted"];

var FILES_DOMAIN = new Set(["file.changed", "file.deleted", "workspace.manifested"]);
// FILE_VERSION_NAMES are the two events that make up one path's version
// history. Deliberately narrower than FILES_DOMAIN, which also carries
// workspace.manifested — a whole-tree event that belongs to no single path.
var FILE_VERSION_NAMES = new Set(["file.changed", "file.deleted"]);
var NETWORK_DOMAIN = new Set(["network.connected", "network.denied"]);
var ACTIONS_DOMAIN = new Set([
  "authorization.decided", "tool.requested", "tool.completed",
  "internal_tool.dispatched", "internal_tool.completed", "internal_tool.failed",
  "effect.requested", "effect.approved", "effect.denied", "effect.dispatched", "effect.completed", "effect.failed",
  "credential.issued", "credential.revoked",
  "model.requested", "model.completed",
  // Agent lifecycle: including these lets the "by action chain" mode nest a
  // subagent's tools under its agent.started (ParentActionID chain), and the
  // "by agent" mode group them by responsible agent (see computeAgentGroups).
  "agent.started", "agent.completed",
]);

// INFRASTRUCTURE_PRODUCERS are the authenticated non-workload channels. A
// workload-channel event with no positively-identified agent.id is Unattributed
// Workload; anything on these channels is BoxedAi's own infrastructure. Used by
// the "by agent" grouping to keep those two mandatory buckets honest and
// distinct — self-reported workload labels never leak into the infra bucket.
var INFRASTRUCTURE_PRODUCERS = new Set(["controller", "broker", "guest_supervisor", "recorder"]);

var NAME_GROUP_PREFIXES = ["process.", "file.", "network.", "internal_tool.", "effect.", "session.", "sensor."];
function nameGroup(name) {
  for (var i = 0; i < NAME_GROUP_PREFIXES.length; i++) {
    if (name.indexOf(NAME_GROUP_PREFIXES[i]) === 0) return NAME_GROUP_PREFIXES[i];
  }
  return "other";
}

var PROCESS_CREATED = "process.created";

// GUEST_AGENT_BINARY_PATH/isGuestAgentBinaryExec mirror
// internal/view/timeline.go's guestAgentBinaryPath/isGuestAgentBinaryExec for
// the "Agent activity" preset (the include-set itself is served from Go as
// ctx.agentActivityNames, see setSessionViewPayload). Claude Code invokes
// hooks via a shell, so the common shape is process.binary=/bin/sh with the
// full guest-agent path in process.argv, not process.binary itself; this
// predicate — unlike the static name set — can't be served from the Go side
// without a redundant per-event server-side flag, so it is mirrored by hand
// here. Keep it in sync with timeline.go if either changes.
var GUEST_AGENT_BINARY_PATH = "/usr/local/bin/boxedai-guest-agent";
function isGuestAgentBinaryExec(ev) {
  if (ev.name !== "process.executed") return false;
  if (attrRaw(ev, "process.binary") === GUEST_AGENT_BINARY_PATH) return true;
  var argv = attrRaw(ev, "process.argv");
  return typeof argv === "string" && argv.indexOf(GUEST_AGENT_BINARY_PATH) !== -1;
}

// DIFF_MAX_LINES bounds how much of one unified diff is rendered. Diff text is
// derived from workload-controlled file content, so a single expansion could
// otherwise ask the browser for hundreds of thousands of DOM nodes; the tail is
// dropped with a visible note rather than silently.
var DIFF_MAX_LINES = 600;

var HASH_DEBOUNCE_MS = 200;
var SEARCH_DEBOUNCE_MS = 150;
var CHUNK_SIZE = 1000;
var CHUNK_ALL_THRESHOLD = 5000;
var STREAM_EVENT_TYPES = ["sessions.snapshot", "sessions.upsert", "sessions.remove", "session.snapshot", "session.delta"];

// createEventSourceOwner is the one connection-lifecycle boundary shared by
// the standalone and dashboard pages. Replacing or closing a source increments
// its generation before close(), so a callback already queued by the browser
// cannot mutate the next session's view. Native EventSource reconnect handles
// transient transport failures; restart() creates a fresh source and therefore
// intentionally resumes without the superseded source's Last-Event-ID.
function createEventSourceOwner(opts) {
  var source = null;
  var sourceURL = "";
  var generation = 0;

  function notifyState(state) {
    if (opts.onState) opts.onState(state);
  }

  function replace(nextURL, state) {
    generation++;
    if (source) source.close();
    source = null;
    sourceURL = nextURL;
    notifyState(state || "connecting");

    var ownGeneration = generation;
    var nextSource = new EventSource(nextURL);
    source = nextSource;
    function current() {
      return generation === ownGeneration && source === nextSource;
    }

    nextSource.onopen = function () {
      if (current()) notifyState("live");
    };
    nextSource.onerror = function () {
      if (!current()) return;
      notifyState(nextSource.readyState === EventSource.CLOSED ? "stale" : "reconnecting");
    };
    opts.eventTypes.forEach(function (type) {
      nextSource.addEventListener(type, function (message) {
        if (!current()) return;
        var payload;
        try {
          payload = JSON.parse(message.data);
        } catch (err) {
          notifyState("stale");
          if (opts.onMalformed) opts.onMalformed(type, err);
          return;
        }
        opts.onEvent(type, payload, message.lastEventId || "");
      });
    });
  }

  return {
    open: function (url) { replace(url, "connecting"); },
    ensure: function (url) {
      if (source && sourceURL === url && source.readyState !== EventSource.CLOSED) return;
      replace(url, "connecting");
    },
    restart: function () {
      if (sourceURL) replace(sourceURL, "reconnecting");
    },
    close: function (state) {
      generation++;
      if (source) source.close();
      source = null;
      if (state) notifyState(state);
    },
  };
}

function eventAttrsEqual(a, b) {
  var aKeys = Object.keys(a || {}).sort();
  var bKeys = Object.keys(b || {}).sort();
  if (aKeys.length !== bKeys.length) return false;
  for (var i = 0; i < aKeys.length; i++) {
    if (aKeys[i] !== bKeys[i] || a[aKeys[i]] !== b[bKeys[i]]) return false;
  }
  return true;
}

function streamEventsEqual(a, b) {
  var fields = ["seq", "ts", "name", "class", "badge", "producer", "action_id", "parent_action_id", "outcome", "body"];
  for (var i = 0; i < fields.length; i++) {
    if ((a[fields[i]] || "") !== (b[fields[i]] || "")) return false;
  }
  return eventAttrsEqual(a.attrs, b.attrs);
}

function validSequence(seq) {
  return typeof seq === "number" && isFinite(seq) && Math.floor(seq) === seq && seq > 0;
}

function reduceSessionSnapshot(snapshot, expectedSessionID) {
  if (!snapshot || typeof snapshot.session_id !== "string" || !Array.isArray(snapshot.events)) {
    return { kind: "reset", reason: "snapshot_shape" };
  }
  if (expectedSessionID && snapshot.session_id !== expectedSessionID) {
    return { kind: "reset", reason: "snapshot_session" };
  }
  var lastSeq = 0;
  for (var i = 0; i < snapshot.events.length; i++) {
    if (!snapshot.events[i] || !validSequence(snapshot.events[i].seq) || snapshot.events[i].seq <= lastSeq) {
      return { kind: "reset", reason: "snapshot_order" };
    }
    lastSeq = snapshot.events[i].seq;
  }
  return { kind: "applied", payload: snapshot };
}

// reduceSessionDelta merges only a contiguous immutable tail. Overlap is safe
// when the complete event agrees; a gap, conflicting duplicate, wrong session,
// or inconsistent summary forces a cursorless authoritative snapshot instead.
function reduceSessionDelta(current, delta) {
  if (!current || !delta || current.session_id !== delta.session_id || !Array.isArray(delta.events)) {
    return { kind: "reset", reason: "session_or_shape" };
  }

  var events = (current.events || []).slice();
  var bySeq = new Map();
  var lastSeq = 0;
  for (var i = 0; i < events.length; i++) {
    if (!validSequence(events[i].seq) || events[i].seq <= lastSeq) {
      return { kind: "reset", reason: "current_order" };
    }
    lastSeq = events[i].seq;
    bySeq.set(events[i].seq, events[i]);
  }

  var incomingSeq = 0;
  for (var j = 0; j < delta.events.length; j++) {
    var event = delta.events[j];
    if (!event || !validSequence(event.seq) || event.seq <= incomingSeq) {
      return { kind: "reset", reason: "delta_order" };
    }
    incomingSeq = event.seq;
    if (event.seq <= lastSeq) {
      var existing = bySeq.get(event.seq);
      if (!existing || !streamEventsEqual(existing, event)) {
        return { kind: "reset", reason: "conflicting_overlap" };
      }
      continue;
    }
    if (event.seq !== lastSeq + 1) {
      return { kind: "reset", reason: "sequence_gap" };
    }
    events.push(event);
    bySeq.set(event.seq, event);
    lastSeq = event.seq;
  }

  if (typeof delta.last_event_seq === "number" && delta.last_event_seq !== lastSeq) {
    return { kind: "reset", reason: "last_sequence" };
  }
  if (typeof delta.event_count === "number" && delta.event_count !== events.length) {
    return { kind: "reset", reason: "event_count" };
  }

  var next = {};
  Object.keys(current).forEach(function (key) { next[key] = current[key]; });
  next.events = events;
  if (typeof delta.state === "string") next.state = delta.state;
  if (typeof delta.event_count === "number") next.event_count = delta.event_count;
  if (typeof delta.last_event_seq === "number") next.last_event_seq = delta.last_event_seq;
  if (typeof delta.last_event_ts === "string") next.last_event_ts = delta.last_event_ts;
  return { kind: "applied", payload: next };
}

function sortDashboardSessions(sessions) {
  return sessions.slice().sort(function (a, b) {
    var aRunning = a.state === "running";
    var bRunning = b.state === "running";
    if (aRunning !== bRunning) return aRunning ? -1 : 1;
    if (a.session_id === b.session_id) return 0;
    return a.session_id < b.session_id ? 1 : -1;
  });
}

function reduceSessionsSnapshot(payload) {
  if (!payload || !Array.isArray(payload.sessions)) return null;
  for (var i = 0; i < payload.sessions.length; i++) {
    if (!payload.sessions[i] || typeof payload.sessions[i].session_id !== "string") return null;
  }
  return sortDashboardSessions(payload.sessions);
}

function reduceSessionsUpsert(sessions, update) {
  if (!update || typeof update.session_id !== "string") return null;
  var next = sessions.filter(function (session) { return session.session_id !== update.session_id; });
  next.push(update);
  return sortDashboardSessions(next);
}

function reduceSessionsRemove(sessions, removal) {
  if (!removal || typeof removal.session_id !== "string") return null;
  return {
    sessions: sessions.filter(function (session) { return session.session_id !== removal.session_id; }),
    removedId: removal.session_id,
  };
}

function dashboardStreamURL(sessionID, detailLive) {
  return sessionID && detailLive ? "/api/stream?session=" + encodeURIComponent(sessionID) : "/api/stream";
}

// ---- state ----

// defaultState is the single state object described in the spec: filters,
// tab, sort, per-tab toggles, expanded rows and (dashboard-only) the
// selected session id. A fresh object is created per SessionView instance.
function defaultState() {
  return {
    tab: "timeline",
    sort: "desc", // "desc" (newest first, default) | "asc"
    search: "",
    classes: [], // selected badge strings; [] = unconstrained
    names: [], // selected event names; [] = unconstrained
    outcomes: [], // selected outcome strings; [] = unconstrained
    producers: [], // selected producer strings; [] = unconstrained
    pid: "",
    hideNoise: true, // "Hide process noise" preset, default ON
    agentActivity: true, // "Agent activity" preset, default ON; implies hideNoise (see computeTimelineFilter)
    errorsOnly: false,
    filesMode: "latest", // "all" | "latest"
    actionsMode: "chain", // "flat" | "chain"
    agentsMode: "list", // Agents tab sub-view: "list" | "graph" (in-memory only, like the two modes above — see serializeStateForHash)
    expandedSeqs: new Set(),
    expandedActionGroups: new Set(), // Actions-tab chain groups expanded (in-memory only, not URL-persisted)
    // Files-tab per-path expansion, per-version diff expansion, and the
    // one-shot "scroll this path into view" request the Timeline's "file
    // history" action sets. All in-memory only, like the two sets above and
    // filesMode itself — none of them are URL-persisted.
    expandedFilePaths: new Set(),
    expandedFileDiffs: new Set(), // fileDiffKey(path, from, to) values
    filesFocusPath: "",
    // Files/Network/Actions have no chunk cap of their own — those domains
    // are inherently small subsets of the full event stream (see the doc
    // comment above the Timeline renderers section), so only Timeline needs
    // a "shown" counter.
    timelineShown: CHUNK_SIZE,
    selectedSession: "", // dashboard only
    liveOn: false,
    namePopoverOpen: false,
  };
}

// serializeStateForHash picks the compact subset of state that round-trips
// through location.hash (tab, search, facet selections, pid, presets,
// selected session id) — sort/filesMode/actionsMode/expandedSeqs are kept
// in memory only, not persisted, per spec.
function serializeStateForHash(state) {
  var out = {
    tab: state.tab,
    q: state.search,
    cls: state.classes,
    names: state.names,
    out: state.outcomes,
    prod: state.producers,
    pid: state.pid,
    noise: state.hideNoise,
    aa: state.agentActivity,
    err: state.errorsOnly,
  };
  if (state.selectedSession) out.sess = state.selectedSession;
  return out;
}

// readHashObject/writeHashObjectMerged treat location.hash as one shared,
// URL-encoded JSON object. Both the SessionView (tab/filters) and, on the
// dashboard, the sidebar (selected session) read/write it, so writes are
// merged against whatever is currently there instead of blindly overwriting
// the other component's keys.
function readHashObject() {
  var raw = location.hash.replace(/^#/, "");
  if (!raw) return {};
  try {
    var obj = JSON.parse(decodeURIComponent(raw));
    return (obj && typeof obj === "object") ? obj : {};
  } catch (e) {
    return {}; // malformed hash: defaults stand, never a crash
  }
}
function writeHashObjectMerged(patch) {
  var obj = readHashObject();
  Object.keys(patch).forEach(function (k) {
    if (patch[k] === undefined) delete obj[k];
    else obj[k] = patch[k];
  });
  location.hash = encodeURIComponent(JSON.stringify(obj));
}

// restoreStateFromHash mutates state in place from the shared hash object.
function restoreStateFromHash(state) {
  var obj = readHashObject();
  // Only a known tab key is accepted: the hash is attacker-influenceable via a
  // shared link, and an unknown key would render no tab at all.
  if (typeof obj.tab === "string" && isKnownTab(obj.tab)) state.tab = obj.tab;
  if (typeof obj.q === "string") state.search = obj.q;
  if (Array.isArray(obj.cls)) state.classes = obj.cls.filter(isStr);
  if (Array.isArray(obj.names)) state.names = obj.names.filter(isStr);
  if (Array.isArray(obj.out)) state.outcomes = obj.out.filter(isStr);
  if (Array.isArray(obj.prod)) state.producers = obj.prod.filter(isStr);
  if (typeof obj.pid === "string") state.pid = obj.pid;
  if (typeof obj.noise === "boolean") state.hideNoise = obj.noise;
  if (typeof obj.aa === "boolean") state.agentActivity = obj.aa;
  if (typeof obj.err === "boolean") state.errorsOnly = obj.err;
  if (typeof obj.sess === "string") state.selectedSession = obj.sess;
}
function isStr(v) { return typeof v === "string"; }
function isKnownTab(tab) {
  for (var i = 0; i < TAB_DEFS.length; i++) {
    if (TAB_DEFS[i].key === tab) return true;
  }
  return false;
}

var writeHashDebounced = debounce(function (state) {
  writeHashObjectMerged(serializeStateForHash(state));
}, HASH_DEBOUNCE_MS);

// clearFilters resets every filter/preset (but not tab/sort/mode toggles) to
// defaults, per the "Clear filters" button.
function clearFilters(state) {
  state.search = "";
  state.classes = [];
  state.names = [];
  state.outcomes = [];
  state.producers = [];
  state.pid = "";
  state.hideNoise = true;
  state.agentActivity = true; // resets to the default preset (see defaultState); the results-line "show everything" link is the escape hatch to the full stream
  state.errorsOnly = false;
}

function toggleInArray(arr, v) {
  var i = arr.indexOf(v);
  if (i === -1) arr.push(v); else arr.splice(i, 1);
  return arr;
}

// ---- payload ingestion/derivation ----

// summarizeAttrs renders the non-bookkeeping attrs of one event as a sorted
// "k=v k2=v2" string (unescaped; callers esc() at render time).
function summarizeAttrs(attrs) {
  if (!attrs) return "";
  var keys = Object.keys(attrs).filter(function (k) { return !BOOKKEEPING_ATTRS.has(k); });
  keys.sort();
  return keys.map(function (k) { return k + "=" + attrs[k]; }).join(" ");
}

// corpusOf builds the lowercased search-corpus string for one event. Includes
// action_id/parent_action_id (not just name/body/attrs) so the Timeline
// detail row's "filter action chain" button — which sets the free-text
// search box to a chain id — actually matches the events that carry it;
// those two fields live outside attrs (already their own webEvent columns)
// so summarizeAttrs never sees them.
function corpusOf(ev, kvStr) {
  return (ev.name + " " + (ev.body || "") + " " + kvStr + " " +
    (ev.action_id || "") + " " + (ev.parent_action_id || "")).toLowerCase();
}

// buildModel precomputes, once per payload load, the per-event data the filter
// engine and renderers need so no render pass re-derives it: a lowercased
// search corpus and a formatted clock label, as parallel arrays indexed like
// payload.events. The non-bookkeeping "k=v" attrs are still folded into the
// search corpus (so a search over an attr value still matches) but are no
// longer displayed, so they aren't retained per row.
function buildModel(events) {
  var n = events.length;
  var corpus = new Array(n);
  var tsLabel = new Array(n);
  var bySeq = new Map();
  for (var i = 0; i < n; i++) {
    var ev = events[i];
    corpus[i] = corpusOf(ev, summarizeAttrs(ev.attrs));
    tsLabel[i] = fmtClock(ev.ts);
    bySeq.set(ev.seq, i);
  }
  return { events: events, corpus: corpus, tsLabel: tsLabel, bySeq: bySeq };
}

// extendModel appends derived fields for newly-arrived tail events onto an
// existing model in place (the live-refresh append-only path), avoiding a
// full O(n) recompute of unchanged rows.
function extendModel(model, events) {
  for (var i = model.events.length; i < events.length; i++) {
    var ev = events[i];
    model.corpus.push(corpusOf(ev, summarizeAttrs(ev.attrs)));
    model.tsLabel.push(fmtClock(ev.ts));
    model.bySeq.set(ev.seq, i);
  }
  model.events = events;
}

// tabCounts computes the six sticky-tab live count badges directly off the
// full (unfiltered) event list, per the fixed domain definitions in the
// spec — these are payload-derived totals, not filtered-view counts.
function tabCounts(payload) {
  var events = payload.events || [];
  var processes = 0, files = 0, network = 0, actions = 0, agents = 0;
  for (var i = 0; i < events.length; i++) {
    var name = events[i].name;
    if (name.indexOf("process.") === 0) processes++;
    if (FILES_DOMAIN.has(name)) files++;
    if (NETWORK_DOMAIN.has(name)) network++;
    if (ACTIONS_DOMAIN.has(name)) actions++;
    if (name === "tool.requested") agents++;
  }
  return {
    timeline: events.length,
    processes: processes,
    files: files,
    network: network,
    actions: actions,
    agents: agents,
    proof: (payload.proof && payload.proof.segments ? payload.proof.segments.length : 0),
  };
}

// ---- filter engine ----

function bump(map, key) {
  map.set(key, (map.get(key) || 0) + 1);
}

// computeTimelineFilter runs the one O(n) pass described in the spec: it
// produces the filtered index list for the Timeline tab and, in the same
// pass, tallies facet counts for the class/name/outcome/producer chips.
//
// Facet counts use standard faceted-search semantics: each facet's count is
// computed with all OTHER facets applied but not itself, so picking a
// value in one facet narrows the others without hiding the remaining
// options within that same facet (e.g. selecting KERNEL still shows how
// many BROKER/HARNESS/... events are available). Free-text search, the pid
// filter, and the errors-only/hide-noise/agent-activity presets are not
// enumerable facets (no per-value picklist), so they gate everything as plain
// AND conditions — this stays a single O(n) walk with O(1) per-event work.
//
// agentActivityNames is the --agent-activity include-set served by the
// server (payload.agent_activity_names, see ctx.agentActivityNames) so both
// the CLI and this client-side filter derive the name list from one Go-side
// definition (internal/view/view.go's agentActivityNames); it is a Set of
// event names, unrelated to the per-event isGuestAgentBinaryExec predicate
// applied alongside it below.
function computeTimelineFilter(model, state, agentActivityNames) {
  var events = model.events;
  var searchQ = state.search.trim().toLowerCase();
  var pidQ = state.pid.trim();
  var wantClasses = new Set(state.classes);
  var wantNames = new Set(state.names);
  var wantOutcomes = new Set(state.outcomes);
  var wantProducers = new Set(state.producers);
  var activityNames = agentActivityNames || new Set();

  var indices = [];
  var classCounts = new Map();
  var nameCounts = new Map();
  var outcomeCounts = new Map();
  var producerCounts = new Map();
  var hiddenNoise = 0;

  for (var i = 0; i < events.length; i++) {
    var ev = events[i];
    var outcomeKey = ev.outcome || "";

    var okSearch = !searchQ || model.corpus[i].indexOf(searchQ) !== -1;
    var okPid = true;
    if (pidQ) {
      var pid = attrRaw(ev, "process.pid");
      var ppid = attrRaw(ev, "process.parent_pid");
      okPid = String(pid == null ? "" : pid) === pidQ || String(ppid == null ? "" : ppid) === pidQ;
    }
    var okErrors = !state.errorsOnly || outcomeKey === "failure" || outcomeKey === "denied";
    if (!okSearch || !okPid || !okErrors) continue; // hard gates, not facets

    var okClass = !wantClasses.size || wantClasses.has(ev.badge);
    var okName = !wantNames.size || wantNames.has(ev.name);
    var okOutcome = !wantOutcomes.size || wantOutcomes.has(outcomeKey);
    var okProducer = !wantProducers.size || wantProducers.has(ev.producer);

    if (okName && okOutcome && okProducer) bump(classCounts, ev.badge);
    if (okClass && okOutcome && okProducer) bump(nameCounts, ev.name);
    if (okClass && okName && okProducer) bump(outcomeCounts, outcomeKey);
    if (okClass && okName && okOutcome) bump(producerCounts, ev.producer);

    if (!okClass || !okName || !okOutcome || !okProducer) continue;

    // agent-activity is a stronger preset than hide-noise (it implies hiding
    // process.created/process.exited too, plus the guest agent's own hook
    // subprocess execs), so it takes over the noise-hiding slot entirely
    // rather than stacking with it — matching the CLI's --agent-activity,
    // which is mutually exclusive with --all/no-filter in the same spirit.
    if (state.agentActivity) {
      if (!activityNames.has(ev.name) || isGuestAgentBinaryExec(ev)) {
        hiddenNoise++;
        continue;
      }
    } else if (state.hideNoise && ev.name === PROCESS_CREATED) {
      hiddenNoise++;
      continue;
    }
    indices.push(i);
  }

  return {
    indices: indices,
    classCounts: classCounts,
    nameCounts: nameCounts,
    outcomeCounts: outcomeCounts,
    producerCounts: producerCounts,
    hiddenNoise: hiddenNoise,
  };
}

// domainFilterIndices applies a fixed domain event-name set plus the shared
// search box and outcome facet/preset to one of the Files/Network/Actions
// tabs. Per spec these tabs are "domain-scoped and get the free-text search
// + outcome filter applied too, but not the name/class facets" — read
// literally, so this intentionally does NOT apply the class/name/producer
// facets, the pid filter, or the "hide process noise" preset (meaningless
// here anyway: none of these domains include process.created). "Errors
// only" is folded in alongside the outcome chips since it is itself an
// outcome-shaped condition.
function domainFilterIndices(model, state, domainSet) {
  var events = model.events;
  var searchQ = state.search.trim().toLowerCase();
  var wantOutcomes = new Set(state.outcomes);
  var indices = [];
  var outcomeCounts = new Map();
  for (var i = 0; i < events.length; i++) {
    var ev = events[i];
    if (!domainSet.has(ev.name)) continue;
    if (searchQ && model.corpus[i].indexOf(searchQ) === -1) continue;
    var outcomeKey = ev.outcome || "";
    if (state.errorsOnly && outcomeKey !== "failure" && outcomeKey !== "denied") continue;
    // Tally before gating on the outcome facet itself so every outcome
    // value stays visible/pickable in the chip row (same reasoning as
    // computeTimelineFilter's per-facet counts above).
    bump(outcomeCounts, outcomeKey);
    if (wantOutcomes.size && !wantOutcomes.has(outcomeKey)) continue;
    indices.push(i);
  }
  return { indices: indices, outcomeCounts: outcomeCounts };
}

// activeFilterChips lists the removable chips shown on the results line;
// clearActiveFilter is the shared click handler that undoes one of them.
function activeFilterChips(state) {
  var chips = [];
  if (state.search) chips.push({ kind: "search", value: "", label: 'search "' + state.search + '"' });
  state.classes.forEach(function (c) { chips.push({ kind: "class", value: c, label: "class " + c }); });
  state.names.forEach(function (nm) { chips.push({ kind: "name", value: nm, label: "name " + nm }); });
  state.outcomes.forEach(function (o) { chips.push({ kind: "outcome", value: o, label: "outcome " + o }); });
  state.producers.forEach(function (p) { chips.push({ kind: "producer", value: p, label: "producer " + p }); });
  if (state.pid) chips.push({ kind: "pid", value: "", label: "pid " + state.pid });
  if (state.errorsOnly) chips.push({ kind: "errorsOnly", value: "", label: "errors only" });
  if (state.agentActivity) chips.push({ kind: "agentActivity", value: "", label: "agent activity only" });
  else if (!state.hideNoise) chips.push({ kind: "noiseShown", value: "", label: "process.created shown" });
  return chips;
}
function clearActiveFilter(state, kind, value) {
  switch (kind) {
    case "search": state.search = ""; break;
    case "class": toggleInArray(state.classes, value); break;
    case "name": toggleInArray(state.names, value); break;
    case "outcome": toggleInArray(state.outcomes, value); break;
    case "producer": toggleInArray(state.producers, value); break;
    case "pid": state.pid = ""; break;
    case "errorsOnly": state.errorsOnly = false; break;
    case "agentActivity": state.agentActivity = false; break;
    case "noiseShown": state.hideNoise = true; break;
  }
}

// sortedFacetEntries orders known values first (in `order`) then any
// forward-compatible unknown values discovered in the data, alphabetically.
function sortedFacetEntries(counts, order) {
  var seen = new Set();
  var out = [];
  order.forEach(function (k) {
    if (counts.has(k)) { out.push([k, counts.get(k)]); seen.add(k); }
  });
  var rest = [];
  counts.forEach(function (v, k) { if (!seen.has(k)) rest.push([k, v]); });
  rest.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
  return out.concat(rest);
}

var CLASS_BADGE_ORDER = ["KERNEL", "BROKER", "HARNESS", "SELF", "TARGET", "INTEG"];
var PRODUCER_ORDER = ["controller", "broker", "guest_supervisor", "workload", "recorder"];

function resetTimelineChunk(state) {
  state.timelineShown = CHUNK_SIZE;
}

// ---- per-tab renderers: timeline ----
//
// The Timeline tab is the one place the 10k+-event perf bar really bites
// (it's the tab that shows the process.created flood), so it alone gets
// true incremental DOM append on both the "show more" chunk reveal and the
// live-refresh tail-growth path; every other tab renderer below just
// replaces its container's innerHTML wholesale, which is cheap because
// their domains are comparatively small (see domainFilterIndices' doc
// comment for the parallel filtering simplification).

function timelineDisplayIndices(filtered, state) {
  // filtered.indices is always built in ascending-seq order; sort direction
  // is purely a display concern, so it is applied here, not in the filter.
  return state.sort === "desc" ? filtered.indices.slice().reverse() : filtered.indices;
}

function timelineFilterBarHtml(ctx, filtered) {
  var s = ctx.state;
  var classChips = sortedFacetEntries(filtered.classCounts, CLASS_BADGE_ORDER).map(function (e) {
    var on = s.classes.indexOf(e[0]) !== -1;
    return '<button type="button" class="chip selectable' + (on ? " on" : "") + '" style="--chip-color:' +
      classColorVar(e[0]) + '" data-act="toggle-class" data-value="' + esc(e[0]) + '">' + esc(e[0]) + " " + numFmt(e[1]) + "</button>";
  }).join("");
  var outcomeChips = sortedFacetEntries(filtered.outcomeCounts, OUTCOMES).filter(function (e) { return e[0] !== ""; }).map(function (e) {
    var on = s.outcomes.indexOf(e[0]) !== -1;
    return '<button type="button" class="chip selectable' + (on ? " on" : "") + '" style="--chip-color:' +
      outcomeColorVar(e[0]) + '" data-act="toggle-outcome" data-value="' + esc(e[0]) + '">' + esc(e[0]) + " " + numFmt(e[1]) + "</button>";
  }).join("");
  var producerChips = sortedFacetEntries(filtered.producerCounts, PRODUCER_ORDER).map(function (e) {
    var on = s.producers.indexOf(e[0]) !== -1;
    // Producers have no categorical identity color (unlike class/outcome), so
    // "selected" reuses --info — the same generic active-state color already
    // used for .btn.active/.tab-btn.active — rather than leaving --chip-color
    // unset, which would make an "on" chip render *more* muted than an "off"
    // one (the base .chip rule's default is --ink-3, the same as the
    // unselected state's explicit color).
    return '<button type="button" class="chip selectable' + (on ? " on" : "") + '" style="--chip-color:var(--info)" data-act="toggle-producer" data-value="' + esc(e[0]) + '">' + esc(e[0]) + " " + numFmt(e[1]) + "</button>";
  }).join("");
  var nameBadge = s.names.length ? " (" + s.names.length + ")" : "";

  return (
    '<input type="search" placeholder="search name, body, attrs…" value="' + esc(s.search) + '" data-act="search">' +
    '<div class="popover-wrap">' +
      '<button type="button" class="btn small" data-act="toggle-name-popover">event types' + esc(nameBadge) + ' ▾</button>' +
      (s.namePopoverOpen ? '<div class="popover" data-role="name-popover">' + nameGroupPopoverHtml(s, filtered.nameCounts) + "</div>" : "") +
    "</div>" +
    '<input type="text" inputmode="numeric" placeholder="pid" value="' + esc(s.pid) + '" data-act="pid" size="6">' +
    '<label class="toggle"><input type="checkbox" data-act="hide-noise"' + (s.hideNoise || s.agentActivity ? " checked" : "") +
      (s.agentActivity ? " disabled" : "") + "> hide process noise</label>" +
    '<label class="toggle"><input type="checkbox" data-act="agent-activity"' + (s.agentActivity ? " checked" : "") +
      "> agent activity</label>" +
    '<label class="toggle"><input type="checkbox" data-act="errors-only"' + (s.errorsOnly ? " checked" : "") + "> errors only</label>" +
    '<button type="button" class="btn small" data-act="clear-filters">clear filters</button>' +
    '<span class="spacer"></span>' +
    '<button type="button" class="btn small" data-act="tl-sort">' + (s.sort === "asc" ? "oldest first" : "newest first") + "</button>" +
    '<button type="button" class="btn small" data-act="tl-collapse-all" title="collapse every expanded row">collapse all</button>' +
    '<div class="facet-row">' +
      '<span class="facet-label">class</span>' + classChips +
      '<span class="facet-label">outcome</span>' + outcomeChips +
      '<span class="facet-label">producer</span>' + producerChips +
    "</div>"
  );
}

function nameGroupPopoverHtml(state, nameCounts) {
  var groups = {};
  nameCounts.forEach(function (count, name) {
    var g = nameGroup(name);
    (groups[g] = groups[g] || []).push([name, count]);
  });
  var order = NAME_GROUP_PREFIXES.concat(["other"]);
  var html = "";
  order.forEach(function (g) {
    var items = groups[g];
    if (!items || !items.length) return;
    items.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
    var allOn = items.every(function (it) { return state.names.indexOf(it[0]) !== -1; });
    html += '<div class="popover-group"><div class="popover-group-title"><label>' +
      '<input type="checkbox" data-act="toggle-name-group" data-value="' + esc(g) + '"' + (allOn ? " checked" : "") + ">" +
      esc(g) + "</label></div>";
    items.forEach(function (it) {
      var on = state.names.indexOf(it[0]) !== -1;
      html += '<label><input type="checkbox" data-act="toggle-name" data-value="' + esc(it[0]) + '"' + (on ? " checked" : "") +
        ">" + esc(it[0]) + ' <span class="meta">' + numFmt(it[1]) + "</span></label>";
    });
    html += "</div>";
  });
  return html || '<div class="empty" style="padding:6px;">no events</div>';
}

function timelineResultsLineHtml(ctx, filtered, total) {
  var bits = ["showing " + numFmt(filtered.indices.length) + " of " + numFmt(total) + " events"];
  if (filtered.hiddenNoise > 0 && ctx.state.agentActivity) {
    bits.push(numFmt(filtered.hiddenNoise) + ' hidden (agent activity) <button type="button" class="btn link" data-act="show-noise">show everything</button>');
  } else if (filtered.hiddenNoise > 0) {
    bits.push(numFmt(filtered.hiddenNoise) + ' process.created hidden <button type="button" class="btn link" data-act="show-noise">show</button>');
  }
  var chips = activeFilterChips(ctx.state).map(function (c) {
    return '<span class="active-chip">' + esc(c.label) +
      ' <button type="button" data-act="clear-chip" data-kind="' + esc(c.kind) + '" data-value="' + esc(c.value) + '">×</button></span>';
  }).join("");
  return "<span>" + bits.join(" · ") + "</span>" + chips;
}

function timelineMoreHtml(shown, total) {
  var remaining = total - shown;
  if (remaining <= 0) return "";
  var html = '<button type="button" class="btn small" data-act="tl-more">Show ' + numFmt(Math.min(CHUNK_SIZE, remaining)) +
    " more (" + numFmt(remaining) + " remaining)</button>";
  if (remaining <= CHUNK_ALL_THRESHOLD) {
    html += ' <button type="button" class="btn small" data-act="tl-more-all">Show all</button>';
  }
  return html;
}

// ---- readable summary enrichment ----
//
// The summary column is a single ellipsis-truncated line of plain white text
// meant to tell each event's story at a glance. It deliberately does NOT show
// the raw "k=v" attr soup (audit.content.digest=…, harness.claimed_session_id=…,
// credential.kind=… and friends): that noise is one expand-click away on the
// detail row. A few high-traffic event types carry their most useful detail
// only in the attrs, so enrichedSummaryText promotes just that — a process's
// argv, a tool's command + description, a model id, a completion's token counts
// — inline after the event body. Every value is workload-controlled; the caller
// esc()s the whole line before it reaches the DOM.

var SUMMARY_SEP = " · ";

// joinSummary drops empty/absent segments and joins the rest with the middot
// separator, returning a raw (un-escaped) string for summaryCellHtml to esc().
function joinSummary(parts) {
  return parts.filter(function (p) { return p !== "" && p != null; }).join(SUMMARY_SEP);
}

// enrichedSummaryText returns the promoted plain-text summary for the event
// types we special-case, or "" for everything else (caller falls back to the
// event body). The result is raw text; summaryCellHtml esc()s it.
function enrichedSummaryText(ev) {
  switch (ev.name) {
    case "process.executed": {
      // Body already reads "exec <binary>"; append the full argv the attrs bury.
      var argv = attrRaw(ev, "process.argv");
      if (typeof argv !== "string" || argv === "") return "";
      return joinSummary([ev.body || "", argv]);
    }
    case "tool.requested":
    case "tool.completed": {
      // Tool name + the salient argument + the human description, all lifted out
      // of the harness.tool.input JSON (a Bash call carries both a command and a
      // description).
      var s = toolActivitySummary(ev);
      return joinSummary([s.tool, s.text, s.desc]);
    }
    case "model.requested": {
      // Body already reads "model request to <provider>"; append the model id.
      var modelID = attrRaw(ev, "model.id");
      if (modelID === undefined || modelID === null || modelID === "") return "";
      return joinSummary([ev.body || "", String(modelID)]);
    }
    case "model.completed": {
      // Body already reads "model response from <provider>"; append the token
      // counts (either may be absent on a failed/partial completion).
      var inTok = attrRaw(ev, "llm.usage.input_tokens");
      var outTok = attrRaw(ev, "llm.usage.output_tokens");
      var hasIn = inTok !== undefined && inTok !== null && inTok !== "";
      var hasOut = outTok !== undefined && outTok !== null && outTok !== "";
      if (!hasIn && !hasOut) return "";
      return joinSummary([
        ev.body || "",
        hasIn ? "in " + numFmt(inTok) : "",
        hasOut ? "out " + numFmt(outTok) : "",
      ]);
    }
    default:
      return "";
  }
}

// summaryCellHtml is the summary-column renderer shared by the Timeline and
// Actions rows: the promoted readable summary when the event type has one, else
// the plain event body — a single tier of white text, no dim attr tail.
function summaryCellHtml(ev) {
  return esc(enrichedSummaryText(ev) || ev.body || "");
}

function timelineRowHtml(ctx, i) {
  var model = ctx.model, ev = model.events[i];
  var expanded = ctx.state.expandedSeqs.has(ev.seq);
  var outcome = ev.outcome || "";
  var summary = summaryCellHtml(ev);
  var html =
    '<tr class="clickable tl-row" data-seq="' + ev.seq + '">' +
      '<td class="mono-num">' + ev.seq + "</td>" +
      '<td title="' + esc(ev.ts) + '">' + esc(model.tsLabel[i]) + "</td>" +
      "<td>" + chipHtml(ev.badge, classColorVar(ev.badge)) + "</td>" +
      "<td>" + esc(ev.name) + "</td>" +
      "<td>" + (outcome ? ktextHtml(outcome, outcomeColorVar(outcome)) : '<span class="empty">—</span>') + "</td>" +
      '<td class="summary-cell ellipsis">' + (summary || '<span class="empty">—</span>') + "</td>" +
    "</tr>";
  if (expanded) html += timelineDetailRowHtml(ev);
  return html;
}

function timelineDetailRowHtml(ev) {
  var attrs = ev.attrs || {};
  var keys = Object.keys(attrs).sort();
  var grid = keys.map(function (k) {
    return '<div class="k">' + esc(k) + '</div><div class="v">' + esc(String(attrs[k])) + "</div>";
  }).join("");
  var actions = ['<button type="button" class="btn small" data-act="copy-json" data-seq="' + ev.seq + '">copy JSON</button>'];
  var chainId = ev.action_id || ev.parent_action_id;
  if (chainId) {
    actions.push('<button type="button" class="btn small" data-act="filter-chain" data-value="' + esc(chainId) + '">filter action chain</button>');
  }
  var pid = attrRaw(ev, "process.pid");
  if (pid !== undefined && pid !== null && pid !== "") {
    actions.push('<button type="button" class="btn small" data-act="focus-pid" data-value="' + esc(String(pid)) + '">focus pid ' + esc(String(pid)) + "</button>");
  }
  // A file event's most useful next question is "what else happened to this
  // path", which the Files tab answers in full; this jumps there rather than
  // duplicating the version history inside the detail row.
  var filePath = attrRaw(ev, "file.path");
  if (FILE_VERSION_NAMES.has(ev.name) && filePath) {
    actions.push('<button type="button" class="btn small" data-act="file-history" data-value="' + esc(String(filePath)) + '">file history →</button>');
  }
  return (
    '<tr class="detail-row" data-detail-for="' + ev.seq + '"><td colspan="6">' +
      '<div class="detail-body">' + (ev.body ? esc(ev.body) : '<span class="empty">no body</span>') + "</div>" +
      '<div class="kv-grid">' + (grid || '<div class="empty">no attrs</div>') + "</div>" +
      '<div class="detail-actions">' + actions.join("") + "</div>" +
    "</td></tr>"
  );
}

function renderTimelineRowsFull(ctx, displayIdx) {
  var shownCount = Math.min(ctx.state.timelineShown, displayIdx.length);
  var shown = displayIdx.slice(0, shownCount);
  var html = shown.map(function (i) { return timelineRowHtml(ctx, i); }).join("");
  ctx.els.tlBody.innerHTML = html || '<tr><td colspan="6" class="empty">no matching events</td></tr>';
  ctx.tlRenderedCount = shownCount;
}

// appendTimelineTail is the live-refresh fast path: it only ever appends the
// genuinely-new tail events (never touches already-rendered rows), and only
// when the user had already revealed every previously-filtered row — if
// they were mid-chunk, new arrivals just grow the "N remaining" counter
// until they click "show more". Restricted to ascending sort: in that
// order new (higher-seq) events always belong at the very end, which is a
// pure append; descending sort would need new events at the very front
// while also possibly evicting the chunk cap's oldest visible row, which is
// enough extra bookkeeping for an already-rare combination (live session +
// manually flipped to newest-first) that it just falls back to a full
// rebuild instead (still bounded by the shown-count, so still cheap).
function appendTimelineTail(ctx, filtered, displayIdx) {
  var prevShown = ctx.tlRenderedCount || 0;
  var prevTotal = ctx.prevFilteredTotal || 0;
  if (prevShown < prevTotal) {
    return; // mid-chunk: leave rendered rows alone, just let counts grow
  }
  var newTail = displayIdx.filter(function (i) { return i >= ctx.prevEventCount; });
  if (newTail.length) {
    var html = newTail.map(function (i) { return timelineRowHtml(ctx, i); }).join("");
    ctx.els.tlBody.insertAdjacentHTML("beforeend", html);
  }
  ctx.state.timelineShown = displayIdx.length;
  ctx.tlRenderedCount = displayIdx.length;
}

// appendTimelineChunk implements the "Show N more"/"Show all" buttons: it
// appends only the newly-revealed slice via one insertAdjacentHTML call,
// never rebuilding rows already in the DOM.
function appendTimelineChunk(ctx) {
  var displayIdx = timelineDisplayIndices(ctx.timelineFiltered, ctx.state);
  var prevShown = ctx.tlRenderedCount || 0;
  var newShown = Math.min(ctx.state.timelineShown, displayIdx.length);
  if (newShown > prevShown) {
    var slice = displayIdx.slice(prevShown, newShown);
    var html = slice.map(function (i) { return timelineRowHtml(ctx, i); }).join("");
    ctx.els.tlBody.insertAdjacentHTML("beforeend", html);
  }
  ctx.tlRenderedCount = newShown;
  ctx.els.tlMore.innerHTML = timelineMoreHtml(ctx.state.timelineShown, displayIdx.length);
  ctx.els.tlResults.innerHTML = timelineResultsLineHtml(ctx, ctx.timelineFiltered, ctx.model.events.length);
}

function copyEventJSON(ctx, seq, btnEl) {
  var idx = ctx.model.bySeq.get(seq);
  if (idx === undefined) return;
  copyToClipboard(JSON.stringify(ctx.model.events[idx], null, 2), btnEl);
}

function mountTimelineTab(ctx) {
  var el = ctx.els.tabs.timeline;
  el.innerHTML =
    '<div class="filterbar" data-role="filterbar"></div>' +
    '<div class="results-line" data-role="results"></div>' +
    '<div class="table-wrap"><table><thead><tr>' +
      "<th>Seq</th><th>Time</th><th>Class</th><th>Name</th><th>Outcome</th><th>Summary</th>" +
    '</tr></thead><tbody data-role="body"></tbody></table></div>' +
    '<div class="table-more" data-role="more"></div>';
  ctx.els.tlFilterbar = el.querySelector('[data-role="filterbar"]');
  ctx.els.tlResults = el.querySelector('[data-role="results"]');
  ctx.els.tlBody = el.querySelector('[data-role="body"]');
  ctx.els.tlMore = el.querySelector('[data-role="more"]');
  bindTimelineEvents(ctx, el);
}

// renderTimelineFilterbarOnly re-renders just the filter bar — used to
// open/close the event-types popover, which changes no filter and so needs
// neither the O(n) computeTimelineFilter pass nor a table-row rebuild.
// Reuses ctx.timelineFiltered from the last full update (always populated
// by the time this can fire: the popover toggle only exists inside
// filterbar markup that a prior updateTimelineTab call already rendered).
function renderTimelineFilterbarOnly(ctx) {
  ctx.els.tlFilterbar.innerHTML = timelineFilterBarHtml(ctx, ctx.timelineFiltered);
}

function updateTimelineTab(ctx, appendMode) {
  var filtered = computeTimelineFilter(ctx.model, ctx.state, ctx.agentActivityNames);
  ctx.timelineFiltered = filtered;
  var total = ctx.model.events.length;
  var displayIdx = timelineDisplayIndices(filtered, ctx.state);

  ctx.els.tlFilterbar.innerHTML = timelineFilterBarHtml(ctx, filtered);

  if (appendMode === "tail" && ctx.state.sort === "asc") {
    appendTimelineTail(ctx, filtered, displayIdx);
  } else {
    renderTimelineRowsFull(ctx, displayIdx);
  }
  ctx.els.tlMore.innerHTML = timelineMoreHtml(ctx.state.timelineShown, displayIdx.length);
  ctx.els.tlResults.innerHTML = timelineResultsLineHtml(ctx, filtered, total);
}

function bindTimelineEvents(ctx, container) {
  container.addEventListener("input", function (e) {
    if (e.target.matches('[data-act="search"]')) {
      ctx.state.search = e.target.value;
      ctx.debouncedSearch();
    } else if (e.target.matches('[data-act="pid"]')) {
      ctx.state.pid = e.target.value.trim();
      ctx.debouncedSearch();
    }
  });
  container.addEventListener("change", function (e) {
    var t = e.target;
    if (t.matches('[data-act="hide-noise"]')) {
      ctx.state.hideNoise = t.checked;
    } else if (t.matches('[data-act="agent-activity"]')) {
      ctx.state.agentActivity = t.checked;
      if (t.checked) ctx.state.hideNoise = true; // agent-activity supersedes hide-noise, see computeTimelineFilter
    } else if (t.matches('[data-act="errors-only"]')) {
      ctx.state.errorsOnly = t.checked;
    } else if (t.matches('[data-act="toggle-name"]')) {
      toggleInArray(ctx.state.names, t.dataset.value);
    } else if (t.matches('[data-act="toggle-name-group"]')) {
      var groupNames = [];
      ctx.timelineFiltered.nameCounts.forEach(function (_, name) {
        if (nameGroup(name) === t.dataset.value) groupNames.push(name);
      });
      groupNames.forEach(function (nm) {
        var idx = ctx.state.names.indexOf(nm);
        if (t.checked && idx === -1) ctx.state.names.push(nm);
        if (!t.checked && idx !== -1) ctx.state.names.splice(idx, 1);
      });
    } else {
      return;
    }
    resetTimelineChunk(ctx.state);
    ctx.refreshAll();
  });
  container.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-act]");
    if (btn) {
      var act = btn.dataset.act;
      if (act === "toggle-class") { toggleInArray(ctx.state.classes, btn.dataset.value); resetTimelineChunk(ctx.state); ctx.refreshAll(); return; }
      if (act === "toggle-outcome") { toggleInArray(ctx.state.outcomes, btn.dataset.value); resetTimelineChunk(ctx.state); ctx.refreshAll(); return; }
      if (act === "toggle-producer") { toggleInArray(ctx.state.producers, btn.dataset.value); resetTimelineChunk(ctx.state); ctx.refreshAll(); return; }
      if (act === "toggle-name-popover") { ctx.state.namePopoverOpen = !ctx.state.namePopoverOpen; renderTimelineFilterbarOnly(ctx); return; }
      if (act === "clear-filters") { clearFilters(ctx.state); resetTimelineChunk(ctx.state); ctx.refreshAll(); return; }
      if (act === "tl-sort") { ctx.state.sort = ctx.state.sort === "asc" ? "desc" : "asc"; resetTimelineChunk(ctx.state); updateTimelineTab(ctx); return; }
      if (act === "tl-collapse-all") {
        // Collapse every expanded row without touching filters: only the
        // rendered rows change, so re-render them in place rather than running
        // the O(n) filter/facet pass updateTimelineTab would.
        if (ctx.state.expandedSeqs.size) {
          ctx.state.expandedSeqs.clear();
          renderTimelineRowsFull(ctx, timelineDisplayIndices(ctx.timelineFiltered, ctx.state));
        }
        return;
      }
      if (act === "show-noise") { ctx.state.hideNoise = false; ctx.state.agentActivity = false; resetTimelineChunk(ctx.state); ctx.refreshAll(); return; }
      if (act === "clear-chip") { clearActiveFilter(ctx.state, btn.dataset.kind, btn.dataset.value); resetTimelineChunk(ctx.state); ctx.refreshAll(); return; }
      if (act === "tl-more") {
        var d1 = timelineDisplayIndices(ctx.timelineFiltered, ctx.state);
        ctx.state.timelineShown = Math.min(ctx.state.timelineShown + CHUNK_SIZE, d1.length);
        appendTimelineChunk(ctx);
        return;
      }
      if (act === "tl-more-all") {
        var d2 = timelineDisplayIndices(ctx.timelineFiltered, ctx.state);
        ctx.state.timelineShown = d2.length;
        appendTimelineChunk(ctx);
        return;
      }
      if (act === "copy-json") { copyEventJSON(ctx, Number(btn.dataset.seq), btn); return; }
      if (act === "filter-chain") { ctx.setSearch(btn.dataset.value); return; }
      if (act === "focus-pid") { ctx.focusPid(btn.dataset.value); return; }
      if (act === "file-history") { ctx.showFileHistory(btn.dataset.value); return; }
      return;
    }
    var row = e.target.closest("tr.tl-row");
    if (row) {
      var seq = Number(row.dataset.seq);
      if (ctx.state.expandedSeqs.has(seq)) ctx.state.expandedSeqs.delete(seq);
      else ctx.state.expandedSeqs.add(seq);
      renderTimelineRowsFull(ctx, timelineDisplayIndices(ctx.timelineFiltered, ctx.state));
    }
  });
  document.addEventListener("click", function (e) {
    if (!ctx.state.namePopoverOpen) return;
    if (e.target.closest(".popover-wrap")) return;
    ctx.state.namePopoverOpen = false;
    renderTimelineFilterbarOnly(ctx);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && ctx.state.namePopoverOpen) {
      ctx.state.namePopoverOpen = false;
      renderTimelineFilterbarOnly(ctx);
    }
  });
}

// ---- per-tab renderers: processes (phase-1 hook + fallback) ----
//
// Phase 2 adds internal/view/processes.js, which — if present — sets
// window.BoxedAiProc.render(container, events, api) and takes over this
// tab entirely. This phase only builds the hook point and a graceful
// fallback (the server-rendered ASCII process tree).

function mountProcessesTab(ctx) {
  ctx.els.tabs.processes.innerHTML = '<div class="processes-fallback" data-role="body"></div>';
  ctx.els.procBody = ctx.els.tabs.processes.querySelector('[data-role="body"]');
}

function updateProcessesTab(ctx) {
  var host = ctx.els.procBody;
  var hasHook = window.BoxedAiProc && typeof window.BoxedAiProc.render === "function";
  if (hasHook) {
    var lastSeq = ctx.model.events.length ? ctx.model.events[ctx.model.events.length - 1].seq : 0;
    var api = {
      esc: esc,
      fmtTs: fmtTs,
      focusPid: ctx.focusPid,
      statusColor: statusColor,
      payloadVersion: ctx.model.events.length + ":" + lastSeq,
    };
    host.innerHTML = "";
    window.BoxedAiProc.render(host, ctx.model.events, api);
    return;
  }
  var tree = ctx.payload.process_tree;
  host.innerHTML =
    '<div class="note">process explorer arrives in phase 2</div>' +
    (tree ? "<pre>" + esc(tree) + "</pre>" : '<div class="empty" style="padding:12px 16px;">No process.executed events.</div>');
}

// ---- per-tab renderers: shared compact filter bar (Files/Network/Actions) ----
//
// compactFilterBarHtml is the smaller filter bar for the three domain-scoped
// tabs: search + outcome chips/errors-only only (see domainFilterIndices'
// doc comment for why the class/name/producer facets and pid filter are
// Timeline-only).
function compactFilterBarHtml(ctx, domainFiltered) {
  var s = ctx.state;
  var outcomeChips = sortedFacetEntries(domainFiltered.outcomeCounts, OUTCOMES).filter(function (e) { return e[0] !== ""; }).map(function (e) {
    var on = s.outcomes.indexOf(e[0]) !== -1;
    return '<button type="button" class="chip selectable' + (on ? " on" : "") + '" style="--chip-color:' +
      outcomeColorVar(e[0]) + '" data-act="toggle-outcome" data-value="' + esc(e[0]) + '">' + esc(e[0]) + " " + numFmt(e[1]) + "</button>";
  }).join("");
  return (
    '<input type="search" placeholder="search name, body, attrs…" value="' + esc(s.search) + '" data-act="search">' +
    '<label class="toggle"><input type="checkbox" data-act="errors-only"' + (s.errorsOnly ? " checked" : "") + "> errors only</label>" +
    '<span class="facet-label">outcome</span>' + outcomeChips
  );
}

// digestCellHtml renders a truncated, titled, copyable digest cell, shared
// by the Files and Proof tabs.
function digestCellHtml(digest) {
  if (!digest) return '<span class="empty">—</span>';
  return '<span title="' + esc(digest) + '">' + esc(truncateDigest(digest)) + '</span> ' +
    '<button type="button" class="copy-btn" data-act="copy-text" data-value="' + esc(digest) + '">copy</button>';
}

// bindCommonFilterEvents wires the search box, errors-only toggle and
// outcome chips shared by every compact filter bar; `onChange` re-renders
// the owning tab (each tab keeps its own bind function so listeners stay
// scoped to that tab's container).
function bindCommonFilterEvents(ctx, el, onChange) {
  el.addEventListener("input", function (e) {
    if (e.target.matches('[data-act="search"]')) {
      ctx.state.search = e.target.value;
      ctx.debouncedSearch();
    }
  });
  el.addEventListener("change", function (e) {
    if (e.target.matches('[data-act="errors-only"]')) {
      ctx.state.errorsOnly = e.target.checked;
      ctx.refreshAll();
    }
  });
  el.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-act]");
    if (!btn) return;
    if (btn.dataset.act === "toggle-outcome") { toggleInArray(ctx.state.outcomes, btn.dataset.value); ctx.refreshAll(); return; }
    if (btn.dataset.act === "copy-text") { copyToClipboard(btn.dataset.value, btn); return; }
    onChange(e, btn);
  });
}

// ---- per-tab renderers: files ----

function filesAllRowsHtml(ctx, indices) {
  var model = ctx.model;
  return indices.map(function (i) {
    var ev = model.events[i];
    var digest = attrRaw(ev, "audit.content.digest");
    var path = attrRaw(ev, "file.path");
    var observer = attrRaw(ev, "observer");
    return "<tr>" +
      '<td class="mono-num">' + ev.seq + "</td>" +
      "<td>" + esc(model.tsLabel[i]) + "</td>" +
      "<td>" + esc(ev.name) + "</td>" +
      '<td class="ellipsis">' + esc(path || "") + "</td>" +
      "<td>" + digestCellHtml(digest) + "</td>" +
      "<td>" + esc(observer || "") + "</td>" +
    "</tr>";
  }).join("");
}

// filesLatestGroups reduces the domain-filtered indices (already in
// ascending-seq order) to one entry per file.path, so the last-visited
// index for a path is always its true latest event.
function filesLatestGroups(ctx, indices) {
  var model = ctx.model;
  var byPath = new Map();
  indices.forEach(function (i) {
    var ev = model.events[i];
    var key = attrRaw(ev, "file.path") || "(no path)";
    var entry = byPath.get(key);
    if (!entry) { entry = { count: 0, lastIdx: i }; byPath.set(key, entry); }
    entry.count++;
    entry.lastIdx = i;
  });
  var paths = Array.from(byPath.keys()).sort();
  return { paths: paths, byPath: byPath };
}

function filesLatestRowsHtml(ctx, grouped) {
  var model = ctx.model;
  return grouped.paths.map(function (path) {
    var entry = grouped.byPath.get(path);
    var ev = model.events[entry.lastIdx];
    var expanded = ctx.state.expandedFilePaths.has(path);
    var deleted = ev.name === "file.deleted";
    var kindChip = deleted ? ktextHtml("deleted", statusColor("crit")) : ktextHtml("changed", statusColor("good"));
    var digest = attrRaw(ev, "audit.content.digest");
    var html = '<tr class="clickable file-row" data-act="toggle-file-path" data-path="' + esc(path) + '">' +
      '<td class="ellipsis"><span class="caret">' + (expanded ? "▾" : "▸") + "</span>" + esc(path) + "</td>" +
      "<td>" + kindChip + "</td>" +
      '<td class="mono-num">' + entry.count + "</td>" +
      "<td>" + digestCellHtml(digest) + "</td>" +
      '<td class="mono-num">' + ev.seq + "</td>" +
      "<td>" + esc(model.tsLabel[entry.lastIdx]) + "</td>" +
    "</tr>";
    if (expanded) html += fileHistoryRowHtml(ctx, path);
    return html;
  }).join("");
}

// ---- files tab: per-path version history + inline content diff ----
//
// Expanding a path row shows every version of that file the record contains,
// derived entirely client-side from the events already loaded — no extra
// request. /api/filediff is called only when the reader explicitly opens one
// version's diff, because what comes back is captured workload file content: it
// is fetched on demand, one version at a time, never eagerly.

// CAPTURE_REASON_CHIPS maps file.capture.reason — the host capture path's word
// for why a changed file's bytes were NOT stored — to a chip label and status
// role. Withholding is normal and policy-driven (secret/excluded/too large), so
// those read muted rather than alarming; losing a race with the workload is a
// warn (the digest and the bytes on disk drifted apart); a read/store failure
// is serious, because capture was supposed to happen and didn't.
var CAPTURE_REASON_CHIPS = {
  secret_policy: {
    label: "secret — withheld", role: "muted",
    title: "the capture policy classifies this path as secret; the change is still attested by its digest",
  },
  excluded_by_policy: {
    label: "excluded", role: "muted",
    title: "the path lives under a directory the capture policy excludes",
  },
  size_cap: {
    label: "too large", role: "muted",
    title: "the file is larger than the capture policy's size cap",
  },
  changed_before_capture: {
    label: "not captured (changed mid-scan)", role: "warn",
    title: "the file changed again between the digest scan and the capture read, so no bytes match the recorded digest",
  },
  missing_before_capture: {
    label: "not captured (changed mid-scan)", role: "warn",
    title: "the file was gone by the time capture tried to read it",
  },
  read_error: { label: "capture error", role: "serious", title: "the host could not read the file" },
  store_error: { label: "capture error", role: "serious", title: "the host could not store the content" },
};

// fileCaptureChipHtml renders one version's capture state. capture=="full" is
// the ONLY value that means bytes exist in the blob store (and therefore that a
// diff can be fetched); every other value — including no attribute at all,
// which is the shape of every session recorded before content capture existed —
// means digest-only evidence.
function fileCaptureChipHtml(ev) {
  var capture = attrRaw(ev, "audit.content.capture");
  if (capture === "full") {
    var size = attrRaw(ev, "file.size");
    var known = size !== undefined && size !== null && size !== "";
    return chipHtml(known ? "content · " + fmtBytes(size) : "content", statusColor("good"), null,
      "the content is stored in this session's blob store");
  }
  var reason = attrRaw(ev, "file.capture.reason");
  var mapped = reason ? CAPTURE_REASON_CHIPS[reason] : null;
  if (mapped) return chipHtml(mapped.label, statusColor(mapped.role), null, mapped.title);
  if (reason) {
    // Forward compatibility: a reason this client doesn't know is reported as
    // an unexplained non-capture rather than flattened into "digest only",
    // which would claim content capture was never attempted for it.
    return chipHtml("not captured", statusColor("muted"), null, "file.capture.reason=" + String(reason));
  }
  return chipHtml("digest only", statusColor("muted"), null,
    capture ? "audit.content.capture=" + String(capture) : "this session recorded no content capture");
}

// filePathVersions derives one path's full version history from the loaded
// events: every file.changed/file.deleted carrying that exact file.path, in
// ascending seq order, each annotated with the diff base its "diff" toggle
// should ask the server for.
//
// It deliberately ignores the tab's search/outcome filter. The expansion
// answers "what happened to this file", not "what matches the filter" — and,
// more importantly, `from` resolution must see every version: a filtered-out
// captured version would otherwise be skipped and the diff taken against the
// wrong base while still naming a seq in its header.
//
// from-resolution: the nearest OLDER version of the same path whose content was
// actually captured, else "baseline" (the session-start copy, which the server
// resolves; a file absent at session start yields a new-file diff). Everything
// between that base and this version is by construction uncaptured — the scan
// stops at the first captured predecessor — so `skipped` is exactly how many
// versions the diff jumps over, and the header says so instead of implying a
// change-by-change history.
function filePathVersions(model, path) {
  var out = [];
  for (var i = 0; i < model.events.length; i++) {
    var ev = model.events[i];
    if (!FILE_VERSION_NAMES.has(ev.name)) continue;
    if (attrRaw(ev, "file.path") !== path) continue;
    out.push({
      idx: i,
      ev: ev,
      deleted: ev.name === "file.deleted",
      captured: attrRaw(ev, "audit.content.capture") === "full",
      digest: attrRaw(ev, "audit.content.digest") || "",
      from: "",
      fromSeq: 0,
      skipped: 0,
    });
  }
  out.forEach(function (v, k) {
    if (!v.captured || !v.digest) return;
    for (var j = k - 1; j >= 0; j--) {
      if (out[j].captured && out[j].digest) {
        v.from = out[j].digest;
        v.fromSeq = out[j].ev.seq;
        v.skipped = k - j - 1;
        return;
      }
    }
    v.from = "baseline";
    v.skipped = k; // every earlier version of this path went uncaptured
  });
  return out;
}

// fileDiffBaseLabel names what a version is being diffed against, honestly: the
// exact seq when the base is another recorded version, the session-start copy
// when it is the baseline, and in both cases how many versions were jumped.
function fileDiffBaseLabel(v) {
  var base = v.from === "baseline" ? "vs session start" : "vs seq " + v.fromSeq;
  if (!v.skipped) return base;
  return base + " (" + numFmt(v.skipped) +
    (v.skipped === 1 ? " uncaptured version" : " uncaptured versions") + " in between)";
}

// fileDiffKey identifies one cached diff. path+from+to rather than path+digest:
// `from` is derived from the version list, so keying on it too means a cached
// entry can never be shown under a different base than the one it was fetched
// with. " " occurs in neither a path nor a digest, so it separates
// unambiguously.
function fileDiffKey(path, from, to) {
  return path + " " + from + " " + to;
}

// apiSessionParam is the trailing query parameter the per-session content
// endpoints need on the dashboard, whose one global mux serves every session —
// the same "id=<session>" the sidebar's own /api/session fetch passes. The
// single-session viewer's mux is already bound to one session directory, so
// there it is empty.
function apiSessionParam(ctx) {
  if (ctx.mode !== "embedded") return "";
  var id = ctx.payload && ctx.payload.session_id;
  return id ? "&id=" + encodeURIComponent(id) : "";
}

// fetchFileDiff resolves one /api/filediff request into the per-view cache and
// re-renders the Files tab when it lands. Failures are cached as inline
// messages rather than retried: all three failure modes (403 withheld by
// policy, 404 blob absent, anything else) are durable for a given
// path+from+to, so retrying would only re-ask the same question.
function fetchFileDiff(ctx, key, path, from, to) {
  ctx.diffCache.set(key, { status: "loading" });
  var forSession = ctx.payload && ctx.payload.session_id;
  var url = "/api/filediff?path=" + encodeURIComponent(path) +
    "&from=" + encodeURIComponent(from) + "&to=" + encodeURIComponent(to) + apiSessionParam(ctx);
  fetch(url).then(function (r) {
    if (r.ok) {
      return r.json().then(function (d) {
        return { status: "ok", diff: d && typeof d.diff === "string" ? d.diff : "" };
      });
    }
    if (r.status === 403) return { status: "error", message: "content withheld by policy" };
    if (r.status === 404) return { status: "error", message: "content unavailable" };
    return r.text().then(function (t) {
      return { status: "error", message: t.trim() || "request failed (HTTP " + r.status + ")" };
    });
  }).catch(function (err) {
    return { status: "error", message: String((err && err.message) || err) };
  }).then(function (entry) {
    // The dashboard can switch sessions while this is in flight. A late result
    // must never land in the next session's cache — "from=baseline" resolves
    // against the session's own workspace.orig, so it is genuinely
    // session-specific (same guard fetchDashboardSession applies to its own
    // late payloads).
    if ((ctx.payload && ctx.payload.session_id) !== forSession) return;
    ctx.diffCache.set(key, entry);
    if (ctx.state.tab === "files") updateFilesTab(ctx);
  });
}

// toggleFileDiff opens or closes one version's inline diff, fetching it the
// first time and never again: a sealed session's content is immutable and the
// cache is keyed by path+from+to, so re-expanding is always served from memory.
function toggleFileDiff(ctx, path, from, to) {
  var key = fileDiffKey(path, from, to);
  if (ctx.state.expandedFileDiffs.has(key)) {
    ctx.state.expandedFileDiffs.delete(key);
  } else {
    ctx.state.expandedFileDiffs.add(key);
    if (!ctx.diffCache.has(key)) fetchFileDiff(ctx, key, path, from, to);
  }
  updateFilesTab(ctx);
}

// fileDiffBodyHtml renders one unified diff. EVERY line goes through esc()
// before it reaches the DOM: this block is the one place in the viewer that
// renders captured workload file bytes, so it is also the easiest place to hand
// a workload an injection if a single line ever skipped escaping.
function fileDiffBodyHtml(entry) {
  if (!entry || entry.status === "loading") return '<div class="meta">loading diff…</div>';
  if (entry.status === "error") return '<div class="file-diff-error">' + esc(entry.message) + "</div>";
  if (!entry.diff) return '<div class="meta">no content change (identical bytes)</div>';
  var lines = entry.diff.split("\n");
  if (lines.length && lines[lines.length - 1] === "") lines.pop(); // trailing newline, not a blank line
  // git reports binary content as a "Binary files a/… and b/… differ" line in
  // place of hunks — after the diff/index header lines, not necessarily as the
  // very first line. Rendering it as a diff body would imply the bytes are
  // renderable text, so it is lifted out as a plain note instead.
  for (var b = 0; b < lines.length; b++) {
    if (lines[b].indexOf("@@") === 0) break;
    if (lines[b].indexOf("Binary files ") === 0) {
      return '<div class="file-diff-note">' + esc(lines[b]) + "</div>";
    }
  }
  var shown = lines.slice(0, DIFF_MAX_LINES);
  var seenHunk = false;
  var html = shown.map(function (line) {
    var cls = "diff-line";
    if (line.indexOf("@@") === 0) { seenHunk = true; cls += " diff-meta"; }
    else if (!seenHunk) cls += " diff-meta"; // the diff/index/---/+++ preamble
    else if (line.indexOf("+") === 0) cls += " diff-add";
    else if (line.indexOf("-") === 0) cls += " diff-del";
    else if (line.indexOf("\\") === 0) cls += " diff-meta"; // "\ No newline at end of file"
    return '<div class="' + cls + '">' + (esc(line) || "&nbsp;") + "</div>";
  }).join("");
  if (lines.length > shown.length) {
    html += '<div class="diff-line diff-meta">… ' + numFmt(lines.length - shown.length) + " more lines not shown</div>";
  }
  return '<div class="file-diff">' + html + "</div>";
}

// fileVersionRowHtml renders one version line plus, when its diff is open, the
// diff block beneath it. file.deleted rows carry no content and get no diff
// affordance — a deletion's "before" is the previous version, which is already
// diffable from that version's own row.
function fileVersionRowHtml(ctx, path, v) {
  var ev = v.ev;
  var kindChip = v.deleted ? ktextHtml("deleted", statusColor("crit")) : ktextHtml("changed", statusColor("good"));
  // A capture with no digest to name it can't be fetched (and never resolved a
  // `from` either), so it gets no diff affordance rather than a broken request.
  var diffable = v.captured && !!v.digest;
  var diffKey = fileDiffKey(path, v.from, v.digest);
  var open = diffable && ctx.state.expandedFileDiffs.has(diffKey);
  var diffCell = diffable
    ? '<button type="button" class="btn small' + (open ? " active" : "") + '" data-act="file-diff"' +
      ' data-path="' + esc(path) + '" data-from="' + esc(v.from) + '" data-to="' + esc(v.digest) + '">diff</button>'
    : '<span class="empty">—</span>';
  var html = "<tr>" +
    '<td class="mono-num">' + ev.seq + "</td>" +
    "<td>" + esc(ctx.model.tsLabel[v.idx]) + "</td>" +
    "<td>" + kindChip + "</td>" +
    "<td>" + (v.digest ? digestCellHtml(v.digest) : '<span class="empty">—</span>') + "</td>" +
    "<td>" + (v.deleted ? '<span class="empty">—</span>' : fileCaptureChipHtml(ev)) + "</td>" +
    "<td>" + esc(attrRaw(ev, "observer") || "") + "</td>" +
    "<td>" + diffCell + "</td>" +
  "</tr>";
  if (open) {
    html += '<tr class="file-diff-row"><td colspan="7">' +
      '<div class="file-diff-hdr meta">' + esc(fileDiffBaseLabel(v)) + "</div>" +
      fileDiffBodyHtml(ctx.diffCache.get(diffKey)) +
    "</td></tr>";
  }
  return html;
}

// fileHistoryRowHtml is the expansion under one path row: its versions newest
// first, matching the Timeline's default order.
function fileHistoryRowHtml(ctx, path) {
  var versions = filePathVersions(ctx.model, path);
  if (!versions.length) {
    // Reachable for the "(no path)" bucket filesLatestGroups creates for file
    // events that carry no file.path at all.
    return '<tr class="detail-row"><td colspan="6"><span class="empty">no version history</span></td></tr>';
  }
  var rows = versions.slice().reverse().map(function (v) {
    return fileVersionRowHtml(ctx, path, v);
  }).join("");
  return '<tr class="detail-row"><td colspan="6">' +
    '<table class="file-history"><thead><tr>' +
      "<th>Seq</th><th>Time</th><th>Change</th><th>Digest</th><th>Capture</th><th>Observer</th><th></th>" +
    "</tr></thead><tbody>" + rows + "</tbody></table>" +
  "</td></tr>";
}

// scrollFilesFocusIntoView honours the one-shot focus request the Timeline's
// "file history" action sets. The row is found by comparing dataset values, not
// by building an attribute selector — a workload-controlled path may contain
// quotes — and the request is cleared whether or not the row exists, so a path
// hidden by the active filter can't leave a focus that re-scrolls on every streamed update.
function scrollFilesFocusIntoView(ctx) {
  var want = ctx.state.filesFocusPath;
  if (!want) return;
  ctx.state.filesFocusPath = "";
  var rows = ctx.els.filesTableWrap.querySelectorAll("tr[data-path]");
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].dataset.path === want) {
      rows[i].scrollIntoView({ block: "center" });
      return;
    }
  }
}

function filesToolbarHtml(state, countsText) {
  return (
    '<button type="button" class="btn small' + (state.filesMode === "all" ? " active" : "") + '" data-act="files-mode" data-value="all">all events</button>' +
    '<button type="button" class="btn small' + (state.filesMode === "latest" ? " active" : "") + '" data-act="files-mode" data-value="latest">latest per path</button>' +
    '<span class="meta">' + countsText + "</span>"
  );
}

function mountFilesTab(ctx) {
  var el = ctx.els.tabs.files;
  el.innerHTML =
    '<div class="filterbar" data-role="filterbar"></div>' +
    '<div class="subtoolbar" data-role="toolbar"></div>' +
    '<div class="table-wrap" data-role="tablewrap"></div>';
  ctx.els.filesFilterbar = el.querySelector('[data-role="filterbar"]');
  ctx.els.filesToolbar = el.querySelector('[data-role="toolbar"]');
  ctx.els.filesTableWrap = el.querySelector('[data-role="tablewrap"]');
  bindCommonFilterEvents(ctx, ctx.els.filesFilterbar, function () {});
  ctx.els.filesToolbar.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-act]");
    if (btn && btn.dataset.act === "files-mode") { ctx.state.filesMode = btn.dataset.value; updateFilesTab(ctx); }
  });
  // The table's own actions: path expand/collapse, per-version diff toggle, and
  // the digest copy affordance digestCellHtml renders into every row (the
  // filter-bar listener bindCommonFilterEvents installs never sees clicks in
  // the table, so copy-text has to be handled here).
  ctx.els.filesTableWrap.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-act]");
    if (!btn) return;
    var act = btn.dataset.act;
    if (act === "copy-text") { copyToClipboard(btn.dataset.value, btn); return; }
    if (act === "toggle-file-path") {
      var path = btn.dataset.path;
      if (ctx.state.expandedFilePaths.has(path)) ctx.state.expandedFilePaths.delete(path);
      else ctx.state.expandedFilePaths.add(path);
      updateFilesTab(ctx);
      return;
    }
    if (act === "file-diff") { toggleFileDiff(ctx, btn.dataset.path, btn.dataset.from, btn.dataset.to); return; }
  });
}

function updateFilesTab(ctx) {
  var domainFiltered = domainFilterIndices(ctx.model, ctx.state, FILES_DOMAIN);
  ctx.els.filesFilterbar.innerHTML = compactFilterBarHtml(ctx, domainFiltered);
  if (ctx.state.filesMode === "all") {
    ctx.els.filesToolbar.innerHTML = filesToolbarHtml(ctx.state, numFmt(domainFiltered.indices.length) + " events");
    ctx.els.filesTableWrap.innerHTML =
      "<table><thead><tr><th>Seq</th><th>Time</th><th>Event</th><th>Path</th><th>Digest</th><th>Observer</th></tr></thead><tbody>" +
      (filesAllRowsHtml(ctx, domainFiltered.indices) || '<tr><td colspan="6" class="empty">no matching events</td></tr>') + "</tbody></table>";
  } else {
    var grouped = filesLatestGroups(ctx, domainFiltered.indices);
    ctx.els.filesToolbar.innerHTML = filesToolbarHtml(ctx.state, numFmt(grouped.paths.length) + " paths · " + numFmt(domainFiltered.indices.length) + " events");
    ctx.els.filesTableWrap.innerHTML =
      "<table><thead><tr><th>Path</th><th>Last event</th><th>Changes</th><th>Last digest</th><th>Last seq</th><th>Last time</th></tr></thead><tbody>" +
      (filesLatestRowsHtml(ctx, grouped) || '<tr><td colspan="6" class="empty">no matching events</td></tr>') + "</tbody></table>";
    scrollFilesFocusIntoView(ctx);
  }
}

// ---- per-tab renderers: network ----

function mountNetworkTab(ctx) {
  var el = ctx.els.tabs.network;
  el.innerHTML =
    '<div class="filterbar" data-role="filterbar"></div>' +
    '<div class="summary-strip" data-role="summary"></div>' +
    '<div class="table-wrap" data-role="tablewrap"></div>';
  ctx.els.netFilterbar = el.querySelector('[data-role="filterbar"]');
  ctx.els.netSummary = el.querySelector('[data-role="summary"]');
  ctx.els.netTableWrap = el.querySelector('[data-role="tablewrap"]');
  bindCommonFilterEvents(ctx, ctx.els.netFilterbar, function () {});
}

function updateNetworkTab(ctx) {
  var domainFiltered = domainFilterIndices(ctx.model, ctx.state, NETWORK_DOMAIN);
  ctx.els.netFilterbar.innerHTML = compactFilterBarHtml(ctx, domainFiltered);

  var model = ctx.model;
  var denied = 0, connected = 0;
  var uniqueDest = new Set();
  var rows = domainFiltered.indices.map(function (i) {
    var ev = model.events[i];
    var isDenied = ev.name === "network.denied";
    if (isDenied) denied++; else connected++;
    var ip = attrRaw(ev, "network.dest.ip");
    var port = attrRaw(ev, "network.dest.port");
    var hasIP = ip !== undefined && ip !== null && ip !== "";
    var hasPort = port !== undefined && port !== null && port !== "";
    var dest = hasIP ? (ip + (hasPort ? ":" + port : "")) : "";
    if (dest) uniqueDest.add(dest);
    var proto = attrRaw(ev, "network.proto");
    var observer = attrRaw(ev, "observer");
    var eventChip = ktextHtml(ev.name, isDenied ? statusColor("crit") : statusColor("good"));
    return "<tr>" +
      '<td class="mono-num">' + ev.seq + "</td>" +
      "<td>" + esc(model.tsLabel[i]) + "</td>" +
      "<td>" + eventChip + "</td>" +
      "<td>" + (dest ? esc(dest) : '<span class="empty">—</span>') + "</td>" +
      "<td>" + esc(proto || "") + "</td>" +
      "<td>" + esc(observer || "") + "</td>" +
    "</tr>";
  }).join("");

  ctx.els.netSummary.textContent = numFmt(domainFiltered.indices.length) + " attempts · " + numFmt(denied) +
    " denied · " + numFmt(connected) + " connected · " + numFmt(uniqueDest.size) + " unique destinations";
  ctx.els.netTableWrap.innerHTML =
    "<table><thead><tr><th>Seq</th><th>Time</th><th>Event</th><th>Destination</th><th>Proto</th><th>Observer</th></tr></thead><tbody>" +
    (rows || '<tr><td colspan="6" class="empty">no matching events</td></tr>') + "</tbody></table>";
}

// ---- per-tab renderers: actions ----

function actionRowHtml(ctx, i) {
  var model = ctx.model, ev = model.events[i];
  var outcome = ev.outcome || "";
  var summary = summaryCellHtml(ev);
  return "<tr>" +
    '<td class="mono-num">' + ev.seq + "</td>" +
    "<td>" + esc(model.tsLabel[i]) + "</td>" +
    "<td>" + chipHtml(ev.badge, classColorVar(ev.badge)) + "</td>" +
    "<td>" + esc(ev.name) + "</td>" +
    "<td>" + (outcome ? ktextHtml(outcome, outcomeColorVar(outcome)) : '<span class="empty">—</span>') + "</td>" +
    '<td class="summary-cell ellipsis">' + (summary || '<span class="empty">—</span>') + "</td>" +
  "</tr>";
}

// computeActionGroups links Actions-domain events that share a root action
// id: follow parent_action_id -> action_id links up to the chain's root.
// The ownId map is built from the FULL event list (not just the currently
// filtered/visible indices) so a chain still resolves correctly even when a
// search/outcome filter hides the root event itself; only membership in a
// rendered group is gated by `indices`.
function computeActionGroups(ctx, indices) {
  var model = ctx.model;
  var byOwnId = new Map();
  for (var i = 0; i < model.events.length; i++) {
    var ev = model.events[i];
    if (ev.action_id) byOwnId.set(ev.action_id, i);
  }
  function findRoot(id, guard) {
    var idx = byOwnId.get(id);
    if (idx === undefined) return id;
    var ev = model.events[idx];
    if (!ev.parent_action_id || guard.has(id)) return id; // no parent, or cycle guard
    guard.add(id);
    return findRoot(ev.parent_action_id, guard);
  }

  var groups = new Map();
  var unlinked = [];
  indices.forEach(function (i) {
    var ev = model.events[i];
    var key = null;
    if (ev.action_id) key = findRoot(ev.action_id, new Set());
    else if (ev.parent_action_id) key = findRoot(ev.parent_action_id, new Set());
    if (key === null) { unlinked.push(i); return; }
    var g = groups.get(key);
    if (!g) { g = { rootKey: key, members: [] }; groups.set(key, g); }
    g.members.push(i);
  });

  var groupList = Array.from(groups.values());
  groupList.forEach(function (g) {
    g.members.sort(function (a, b) { return model.events[a].seq - model.events[b].seq; });
  });
  groupList.sort(function (a, b) { return model.events[a.members[0]].seq - model.events[b.members[0]].seq; });
  return { groups: groupList, unlinked: unlinked, byOwnId: byOwnId };
}

function actionGroupHeaderHtml(ctx, g, expanded) {
  var model = ctx.model;
  var rootIdx = ctx.actionsGroupInfo.byOwnId.get(g.rootKey);
  var rootName = rootIdx !== undefined ? model.events[rootIdx].name : "(root not in view)";
  var lastEv = model.events[g.members[g.members.length - 1]];
  var lastOutcome = lastEv.outcome || "";
  return (
    '<button type="button" class="action-group-hdr" data-act="toggle-group" data-key="' + esc(g.rootKey) + '">' +
      '<span class="caret">' + (expanded ? "▾" : "▸") + "</span>" +
      "<strong>" + esc(rootName) + "</strong>" +
      '<span class="meta">' + esc(g.rootKey) + "</span>" +
      (lastOutcome ? ktextHtml(lastOutcome, outcomeColorVar(lastOutcome)) : '<span class="empty">—</span>') +
      '<span class="meta">' + g.members.length + " events</span>" +
    "</button>"
  );
}

function actionsChainHtml(ctx, indices) {
  var info = computeActionGroups(ctx, indices);
  ctx.actionsGroupInfo = info;
  var html = info.groups.map(function (g) {
    var expanded = ctx.state.expandedActionGroups.has(g.rootKey);
    var membersHtml = expanded ? g.members.map(function (i) { return actionRowHtml(ctx, i); }).join("") : "";
    return '<div class="action-group">' + actionGroupHeaderHtml(ctx, g, expanded) +
      (expanded ? '<table class="action-group-members"><tbody>' + membersHtml + "</tbody></table>" : "") +
      "</div>";
  }).join("");
  if (info.unlinked.length) {
    var expanded = ctx.state.expandedActionGroups.has("__unlinked__");
    var unlinkedRows = expanded ? info.unlinked.map(function (i) { return actionRowHtml(ctx, i); }).join("") : "";
    html += '<div class="action-group">' +
      '<button type="button" class="action-group-hdr" data-act="toggle-group" data-key="__unlinked__">' +
        '<span class="caret">' + (expanded ? "▾" : "▸") + '</span><strong>unlinked</strong>' +
        '<span class="meta">' + info.unlinked.length + " events</span>" +
      "</button>" +
      (expanded ? '<table class="action-group-members"><tbody>' + unlinkedRows + "</tbody></table>" : "") +
      "</div>";
  }
  return html || '<div class="empty" style="padding:12px 16px;">no matching events</div>';
}

function actionsFlatHtml(ctx, indices) {
  var rows = indices.map(function (i) { return actionRowHtml(ctx, i); }).join("");
  return "<table><thead><tr><th>Seq</th><th>Time</th><th>Class</th><th>Name</th><th>Outcome</th><th>Summary</th></tr></thead><tbody>" +
    (rows || '<tr><td colspan="6" class="empty">no matching events</td></tr>') + "</tbody></table>";
}

// ---- per-agent grouping (honest presentation) ----
//
// The agent hierarchy is narrated by the DISTRUSTED harness (DESIGN.md "Agent
// hierarchy and attribution"): grouping events under an agent is self-reported
// and must never be shown as authenticated fact. So every agent group carries a
// strength badge (controller/strong for the host-minted Primary, self_reported
// for hook-registered children), and two buckets are ALWAYS rendered even when
// empty: "Unattributed Workload" (workload events with no agent.id — never
// defaulted to any agent) and "BoxedAi Infrastructure" (authenticated
// non-workload channels). Zero agent.started events renders "no agent
// decomposition reported" — never "single agent", which would assert a hierarchy
// the harness never narrated.

var UNATTRIBUTED_KEY = "__unattributed__";
var INFRASTRUCTURE_KEY = "__infrastructure__";

// agentStrengthChip renders the honesty badge for one agent's attribution
// strength: self_reported is painted warn (the harness's word, unverified),
// strong is the host-attested Primary, and an id carrying activity with no
// agent.started registration is called out as unregistered.
function agentStrengthChip(meta) {
  if (!meta) return chipHtml("unregistered", statusColor("crit"), null,
    "activity is attributed to an agent id that has no agent.started registration");
  if (meta.strength === "strong") return chipHtml("controller · strong", statusColor("good"), null,
    "host-minted and controller-attested; not workload-forgeable");
  if (meta.strength === "self_reported") return chipHtml("self-reported", statusColor("warn"), null,
    "the harness claims this grouping; not independently verified");
  return chipHtml(meta.strength || "unattributed", statusColor("muted"), null, null);
}

// computeAgentGroups buckets the visible events by the agent responsible for
// them. Agent metadata (role/strength/native id/type) is read from ALL
// agent.started events in the model, closure state from ALL agent.completed
// events, and nesting from ALL spawn edges (agent.spawned.id on a completed spawn
// call), so a group still labels and nests correctly when a filter hides the
// registration itself. Ordering: Primary first, then agents by registration seq.
function computeAgentGroups(ctx, indices, seedAllAgents) {
  var model = ctx.model;
  var meta = new Map(); // agent.id -> {role, strength, nativeID, parentID, type, seq, completed, outcome, num}
  var completions = new Map(); // agent.id -> agent.outcome, applied after the scan
  var spawnEdges = new Map(); // spawned agent.id -> spawning agent.id, applied after the scan
  // "Has this session ended" decides whether an unclosed agent is still running
  // or was never closed, so it is answered from the server's own lifecycle
  // marker first (webPayload.state, read from session.state: created|running|
  // sealed|incomplete) and from the event stream second. The event-presence
  // check stays as a fallback because the two disagree in both directions: a
  // session killed before it could emit session.stopped carries no such event
  // (and would otherwise look live forever), while a payload from a viewer
  // built before `state` existed carries no state at all.
  var lifecycle = ctx.payload ? ctx.payload.state : "";
  var sessionEnded = lifecycle === "sealed" || lifecycle === "incomplete";
  for (var i = 0; i < model.events.length; i++) {
    var ev = model.events[i];
    if (ev.name === "session.stopped" || ev.name === "session.sealed") { sessionEnded = true; continue; }
    if (ev.name === "agent.completed") {
      var doneID = attrRaw(ev, "agent.id");
      if (doneID && !completions.has(doneID)) completions.set(doneID, attrRaw(ev, "agent.outcome") || "");
      continue;
    }
    // A completed spawn call carries agent.spawned.id — the id of the agent that
    // call created — beside the acting agent's own agent.id. That one event names
    // both ends of a parent→child edge, and it is the ONLY nested-parent signal
    // Claude Code supplies: agent.parent.id on agent.started always names the
    // Primary, because SubagentStart's stdin has no parent field at all (DESIGN.md
    // ownership invariant 4). Collected here, joined set-wise below.
    var spawnedID = attrRaw(ev, "agent.spawned.id");
    if (spawnedID) {
      var spawnerID = attrRaw(ev, "agent.id");
      // First edge wins. Two events naming the same spawned id is a contradiction
      // the record cannot resolve (both are self_reported narration and neither
      // is more authoritative), so the tab picks one deterministically — scan
      // order over a fixed event list — rather than letting the last writer win.
      if (spawnerID && !spawnEdges.has(spawnedID)) spawnEdges.set(spawnedID, spawnerID);
    }
    if (ev.name !== "agent.started") continue;
    var id = attrRaw(ev, "agent.id");
    if (!id || meta.has(id)) continue;
    meta.set(id, {
      role: attrRaw(ev, "agent.role") || "",
      strength: attrRaw(ev, "agent.attribution.strength") || "",
      nativeID: attrRaw(ev, "agent.native_id") || "",
      parentID: attrRaw(ev, "agent.parent.id") || "",
      type: attrRaw(ev, "agent.type") || "",
      seq: ev.seq,
      completed: false,
      outcome: "",
      num: 0, // 1-based child ordinal, assigned below
    });
  }
  // Closure is applied after the scan because audit.sequence is arrival order: a
  // hook-submitted agent.completed can be sequenced before the agent.started it
  // closes (DESIGN.md ownership invariant 8). A completion naming an id that was
  // never registered is the verifier's business (unregistered activity), not the
  // viewer's, and is dropped here rather than inventing an agent.
  completions.forEach(function (outcome, doneID) {
    var m = meta.get(doneID);
    if (!m) return;
    m.completed = true;
    m.outcome = outcome;
  });
  // The spawn edges are joined the same way and for the same reason: arrival
  // order proves nothing in EITHER direction. A synchronous spawn's tool.completed
  // is sequenced after the child's agent.started, while a backgrounded one
  // (tool_response.status "async_launched") returns before its child has
  // registered at all — an edge at seq 1390 whose child registered at 1392 was
  // observed in a live run. So the join is set-wise over the whole scan, never
  // "the agent.started nearest this event" (DESIGN.md ownership invariant 4:
  // pairing a spawn to a child by arrival order or timing is rejected outright).
  //
  // This is derived, not claimed: self_reported spawn narration joined to
  // self_reported registration is still self_reported, so nothing here promotes an
  // agent's attribution strength or earns a new badge — the tree simply stops
  // pretending twelve grandchildren were the Primary's own children. A child with
  // no edge (its PostToolUse hook was dropped — hooks are fail-open) keeps the
  // wire parent and stays flat under the Primary, exactly as before.
  spawnEdges.forEach(function (spawnerID, childID) {
    var m = meta.get(childID);
    // An edge naming an id that never registered invents no agent, the same rule
    // an orphan agent.completed gets above.
    if (!m) return;
    // An unregistered spawner is not better information than the parent the record
    // does carry, and a self-edge is not a parent at all: in both cases the wire
    // parent stands. Every other malformed shape (a cycle through two real agents,
    // a component with no root) is still caught by the walk's own guards below.
    if (!meta.has(spawnerID) || spawnerID === childID) return;
    m.parentID = spawnerID;
  });
  // Number the registered children 1..N in agent.started order so the UI can name
  // them stably. Registration order — not arrival order of their activity — because
  // that is the only ordering the harness itself narrated, and it stays fixed as
  // filters change. Sorting is explicit: agent.started can be sequenced after a
  // sibling's (invariant 8), so Map insertion order is not registration order.
  var childMetas = [];
  meta.forEach(function (m) { if (m.role === "child") childMetas.push(m); });
  childMetas.sort(function (a, b) { return a.seq - b.seq; });
  childMetas.forEach(function (m, i) { m.num = i + 1; });

  var groups = new Map();
  function bucket(key) {
    var g = groups.get(key);
    if (!g) { g = { key: key, members: [] }; groups.set(key, g); }
    return g;
  }
  indices.forEach(function (i) { bucket(ownerAgentOf(model.events[i])).members.push(i); });

  // The Agents tab filters to a single event kind (tool.requested), so an agent
  // that owns none of the filtered events — a child that was registered but never
  // witnessed acting, or a Primary in a recording made before its own direct calls
  // carried its id — would be absent from `groups` and its children would orphan
  // in the forest walk below. Seeding an empty group for every registered
  // agent keeps the full hierarchy walkable; members stay [] so nothing renders
  // as activity for it.
  if (seedAllAgents) {
    meta.forEach(function (m, id) {
      if (!groups.has(id)) groups.set(id, { key: id, members: [] });
    });
  }

  // Order the rendered agent groups as a pre-order walk: Primary root first,
  // each rendered agent immediately followed by its rendered children. Metadata
  // for a filtered-out parent must not orphan a visible child. Malformed cycles
  // and self-parents have no ordinary root, so a final unseen-component pass
  // below keeps every workload-forgeable group visible exactly once.
  function seqOfKey(k) {
    var m = meta.get(k);
    return m ? m.seq : model.events[groups.get(k).members[0]].seq;
  }
  var childrenOf = new Map(); // parentID -> [childID...]
  var roots = [];
  var renderedKeys = [];
  groups.forEach(function (g, key) {
    if (key === UNATTRIBUTED_KEY || key === INFRASTRUCTURE_KEY) return;
    renderedKeys.push(key);
    var m = meta.get(key);
    var parent = m ? m.parentID : "";
    if (parent && groups.has(parent)) {
      if (!childrenOf.has(parent)) childrenOf.set(parent, []);
      childrenOf.get(parent).push(key);
    } else {
      roots.push(key);
    }
  });
  roots.sort(function (a, b) {
    var ma = meta.get(a), mb = meta.get(b);
    var pa = ma && ma.role === "primary" ? 0 : 1;
    var pb = mb && mb.role === "primary" ? 0 : 1;
    if (pa !== pb) return pa - pb;
    return seqOfKey(a) - seqOfKey(b);
  });
  var ordered = [];
  var seen = new Set();
  function visit(key, depth) {
    if (seen.has(key)) return; // cycle guard (workload-forgeable parent links)
    seen.add(key);
    ordered.push({ group: groups.get(key), depth: depth });
    (childrenOf.get(key) || [])
      .slice()
      .sort(function (a, b) { return seqOfKey(a) - seqOfKey(b); })
      .forEach(function (c) { visit(c, depth + 1); });
  }
  roots.forEach(function (r) { visit(r, 0); });
  renderedKeys
    .slice()
    .sort(function (a, b) { return seqOfKey(a) - seqOfKey(b); })
    .forEach(function (key) { if (!seen.has(key)) visit(key, 0); });

  return {
    agentGroups: ordered, // [{group, depth}], pre-order, parents before children
    meta: meta,
    agentCount: meta.size,
    sessionEnded: sessionEnded, // an agent still open at session end never closed
    unattributed: groups.get(UNATTRIBUTED_KEY) || { key: UNATTRIBUTED_KEY, members: [] },
    infrastructure: groups.get(INFRASTRUCTURE_KEY) || { key: INFRASTRUCTURE_KEY, members: [] },
  };
}

// agentStatusChip renders the agent's lifecycle state as the harness narrated it:
// a closed agent shows its outcome, an open one is still running — or, once the
// session itself has ended, was never closed (a crashed harness or a dropped
// SubagentStop, the same shape the verifier counts as an open child).
function agentStatusChip(meta, sessionEnded) {
  if (!meta) return "";
  if (meta.completed) {
    if (meta.outcome && meta.outcome !== "success") {
      return chipHtml(meta.outcome, statusColor("warn"), null,
        "the harness narrated this agent's closure with outcome " + meta.outcome);
    }
    return chipHtml("completed", statusColor("good"), null,
      "the harness narrated this agent's closure" + (meta.outcome ? "" : " (no outcome reported)"));
  }
  if (sessionEnded) {
    return chipHtml("never closed", statusColor("crit"), null,
      "the session ended with no agent.completed for this agent (crashed harness or dropped SubagentStop)");
  }
  return chipHtml("running", statusColor("muted"), null, "no agent.completed recorded yet");
}

// agentTitle names the agent by role: children are numbered in registration order
// ("Child Agent 1"), qualified with the harness-declared subagent type when there is
// one ("Child Agent 1 · general-purpose"). The number is a viewer-assigned ordinal
// over agent.started seq — the harness narrates no name for a subagent, and the
// spawning tool call's description cannot be tied to a specific child by the record.
function agentTitle(meta) {
  var role = meta ? meta.role : "";
  var title = role === "primary" ? "Primary Agent" : role === "child" ? "Child Agent" : "Agent (unregistered)";
  if (role === "child" && meta.num) title += " " + meta.num;
  return meta && meta.type ? title + " · " + meta.type : title;
}

// ownerAgentOf decides which bucket an event belongs to: any event carrying a
// positively-identified agent.id (including agent.started/completed, which carry
// the id they describe) belongs to that agent; a workload event with none is
// Unattributed Workload (NEVER defaulted to an agent); everything else rides an
// authenticated non-workload channel and is Infrastructure.
function ownerAgentOf(ev) {
  var id = attrRaw(ev, "agent.id");
  if (id) return id;
  if (INFRASTRUCTURE_PRODUCERS.has(ev.producer)) return INFRASTRUCTURE_KEY;
  return UNATTRIBUTED_KEY;
}

function agentGroupsHtml(ctx, indices) {
  var info = computeAgentGroups(ctx, indices);
  var html = "";
  if (info.agentCount === 0) {
    html += '<div class="empty" style="padding:10px 16px;">no agent decomposition reported ' +
      '<span class="meta">(the harness narrated no subagents; activity below is shown at session scope)</span></div>';
  }
  info.agentGroups.forEach(function (og) { html += agentGroupHtml(ctx, og.group, info.meta, og.depth, info.sessionEnded); });
  // The two mandatory buckets are ALWAYS rendered, even when empty, so their
  // absence is never mistaken for "no unattributed activity".
  html += bucketGroupHtml(ctx, info.unattributed, "Unattributed Workload",
    "workload events with no positively-identified agent.id (for sessions recorded before primary attribution this includes the Primary's own direct tool calls)", statusColor("warn"));
  html += bucketGroupHtml(ctx, info.infrastructure, "BoxedAi Infrastructure",
    "authenticated non-workload channels (controller, broker, supervisor, recorder); not attributable to a single agent", statusColor("info"));
  return html;
}

function agentGroupHtml(ctx, g, meta, depth, sessionEnded) {
  var expanded = ctx.state.expandedActionGroups.has(g.key);
  var m = meta.get(g.key);
  var members = expanded ? g.members.map(function (i) { return actionRowHtml(ctx, i); }).join("") : "";
  var indent = depth ? ' style="margin-left:' + depth * 18 + 'px"' : "";
  return '<div class="action-group"' + indent + ">" +
    '<button type="button" class="action-group-hdr" data-act="toggle-group" data-key="' + esc(g.key) + '">' +
      '<span class="caret">' + (expanded ? "▾" : "▸") + "</span>" +
      "<strong>" + esc(agentTitle(m)) + "</strong>" +
      agentStrengthChip(m) +
      agentStatusChip(m, sessionEnded) +
      '<span class="meta">' + esc(g.key) + (m && m.nativeID ? " · native " + esc(m.nativeID) : "") + "</span>" +
      '<span class="meta">' + g.members.length + " events</span>" +
    "</button>" +
    (expanded ? '<table class="action-group-members"><tbody>' + members + "</tbody></table>" : "") +
    "</div>";
}

function bucketGroupHtml(ctx, g, title, note, color) {
  var expanded = ctx.state.expandedActionGroups.has(g.key);
  var count = g.members.length;
  var members = expanded && count ? g.members.map(function (i) { return actionRowHtml(ctx, i); }).join("") : "";
  return '<div class="action-group">' +
    '<button type="button" class="action-group-hdr" data-act="toggle-group" data-key="' + esc(g.key) + '">' +
      '<span class="caret">' + (expanded ? "▾" : "▸") + "</span>" +
      "<strong>" + esc(title) + "</strong>" +
      chipHtml(count + (count === 1 ? " event" : " events"), color, null, note) +
      '<span class="meta">' + esc(note) + "</span>" +
    "</button>" +
    (expanded && count ? '<table class="action-group-members"><tbody>' + members + "</tbody></table>" : "") +
    (expanded && !count ? '<div class="empty" style="padding:8px 16px;">(none)</div>' : "") +
    "</div>";
}

function mountActionsTab(ctx) {
  var el = ctx.els.tabs.actions;
  el.innerHTML =
    '<div class="filterbar" data-role="filterbar"></div>' +
    '<div class="subtoolbar" data-role="toolbar"></div>' +
    '<div class="table-wrap" data-role="tablewrap"></div>';
  ctx.els.actionsFilterbar = el.querySelector('[data-role="filterbar"]');
  ctx.els.actionsToolbar = el.querySelector('[data-role="toolbar"]');
  ctx.els.actionsTableWrap = el.querySelector('[data-role="tablewrap"]');
  bindCommonFilterEvents(ctx, ctx.els.actionsFilterbar, function () {});
  ctx.els.actionsToolbar.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-act]");
    if (btn && btn.dataset.act === "actions-mode") { ctx.state.actionsMode = btn.dataset.value; updateActionsTab(ctx); }
  });
  ctx.els.actionsTableWrap.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-act]");
    if (btn && btn.dataset.act === "toggle-group") {
      var key = btn.dataset.key;
      if (ctx.state.expandedActionGroups.has(key)) ctx.state.expandedActionGroups.delete(key);
      else ctx.state.expandedActionGroups.add(key);
      updateActionsTab(ctx);
    }
  });
}

function updateActionsTab(ctx) {
  var domainFiltered = domainFilterIndices(ctx.model, ctx.state, ACTIONS_DOMAIN);
  ctx.els.actionsFilterbar.innerHTML = compactFilterBarHtml(ctx, domainFiltered);
  ctx.els.actionsToolbar.innerHTML =
    '<button type="button" class="btn small' + (ctx.state.actionsMode === "flat" ? " active" : "") + '" data-act="actions-mode" data-value="flat">flat</button>' +
    '<button type="button" class="btn small' + (ctx.state.actionsMode === "chain" ? " active" : "") + '" data-act="actions-mode" data-value="chain">by action chain</button>' +
    '<button type="button" class="btn small' + (ctx.state.actionsMode === "agents" ? " active" : "") + '" data-act="actions-mode" data-value="agents">by agent</button>' +
    '<span class="meta">' + numFmt(domainFiltered.indices.length) + " events</span>";
  ctx.els.actionsTableWrap.innerHTML =
    ctx.state.actionsMode === "chain" ? actionsChainHtml(ctx, domainFiltered.indices) :
    ctx.state.actionsMode === "agents" ? agentGroupsHtml(ctx, domainFiltered.indices) :
    actionsFlatHtml(ctx, domainFiltered.indices);
}

// ---- per-tab renderers: agents ----
//
// The Agents tab is a read-view over the same per-agent grouping the
// Actions tab's "by agent" mode uses (computeAgentGroups/agentStrengthChip,
// see the "per-agent grouping" section above), scoped to ONLY tool.requested
// events — the concise "what did each agent do" activity set. Everything
// else (tool.completed, process.*/file.*/network.*/model.*...) is "more
// info", reachable by expanding a line or via the other tabs, not
// duplicated here. Unlike the Actions tab's by-agent mode (default
// collapsed), agent blocks here default OPEN — glanceability is the point —
// and the Infrastructure bucket is intentionally never shown (locked
// design: agent activity only, not BoxedAi's own plumbing).
//
// The tab has two sub-views over that one grouping: the default List, which
// renders the whole hierarchy split into "Active Agents" (still running) and
// "Past Agents" (closed, or everything once the session ended), and a Graph
// (internal/view/agentgraph.js) that draws only the currently-active agents.
// Both are presentations of the same evidence — neither filters it, neither
// asserts anything the harness did not narrate, and neither is gated on
// verification facets: an INCOMPLETE verdict with agent_hierarchy_valid=false
// is the EXPECTED shape of a real multi-subagent session (dropped hooks at
// scale) and must still render.

// AGENTS_TAB_COLLAPSE_PREFIX namespaces this tab's collapse-tracking within
// the SHARED ctx.state.expandedActionGroups Set. The Actions tab's by-agent
// mode already stores raw agent-id/UNATTRIBUTED_KEY keys in that same Set
// under a "present == expanded, default closed" convention; this tab wants
// the opposite default (open), so it can't safely share the Actions tab's
// raw keys — that would either fight its convention or leak this tab's
// opens into it. Prefixing keeps both tabs' toggle state in the one Set (as
// directed) while keeping the meaning independent: for this tab, presence
// means "explicitly collapsed" and absence — including every agent seen for
// the first time — means "open".
var AGENTS_TAB_COLLAPSE_PREFIX = "agents-tab-collapsed:";
function agentsTabGroupCollapsed(ctx, key) {
  return ctx.state.expandedActionGroups.has(AGENTS_TAB_COLLAPSE_PREFIX + key);
}
function toggleAgentsTabGroup(ctx, key) {
  var k = AGENTS_TAB_COLLAPSE_PREFIX + key;
  if (ctx.state.expandedActionGroups.has(k)) ctx.state.expandedActionGroups.delete(k);
  else ctx.state.expandedActionGroups.add(k);
}

// toolRequestedIndices lists every tool.requested event's index, in seq
// order — the Agents tab's concise activity set (see section comment
// above).
function toolRequestedIndices(model) {
  var indices = [];
  for (var i = 0; i < model.events.length; i++) {
    if (model.events[i].name === "tool.requested") indices.push(i);
  }
  return indices;
}

// toolActivitySummary extracts the one-line concise summary of a
// tool.requested/tool.completed event: the tool name, the salient argument that
// identifies what it acted on (`text`), and the human description shown beside
// it (`desc`) — a Bash call carries both a command and a description, and the
// enriched Timeline summary wants to show both. harness.tool.input is a
// workload-controlled JSON STRING (not an object), so parsing is always
// try/catch guarded; a parse failure (or a shape with none of the known fields)
// just yields empty text/desc, leaving the tool name alone. harness.task
// .description is the spawn narration the hook lifts out of a Task/Agent
// tool_input when the input excerpt is capped (guest/agent/hooks.go), so it
// stands in as the description for a spawn.
function toolActivitySummary(ev) {
  var toolName = attrRaw(ev, "tool.name") || "tool";
  var raw = attrRaw(ev, "harness.tool.input");
  var input = {};
  if (typeof raw === "string") {
    try { input = JSON.parse(raw) || {}; } catch (e) { input = {}; }
  }
  var text = input.command || input.file_path || input.pattern || input.url || "";
  var desc = input.description || attrRaw(ev, "harness.task.description") || "";
  return { tool: toolName, text: text, desc: desc };
}

// agentActivityLineHtml renders one concise activity line for a
// tool.requested event: a dim tool-name label + the salient argument in
// monospace (ellipsis-truncated so long commands never wrap). Clicking the
// line toggles ctx.state.expandedSeqs — the same per-event expand state the
// Timeline tab uses — and, when expanded, appends timelineDetailRowHtml(ev)
// verbatim, so the full body/attrs/copy-JSON/filter-chain/focus-pid detail
// is identical to Timeline's own expand affordance. Wrapped in a <tr><td
// colspan="6"> (matching timelineDetailRowHtml's own colspan) purely so
// both rows share one <table> cleanly; the "6" carries no meaning here.
function agentActivityLineHtml(ctx, i) {
  var model = ctx.model, ev = model.events[i];
  var expanded = ctx.state.expandedSeqs.has(ev.seq);
  var summary = toolActivitySummary(ev);
  // Prefer the salient argument; fall back to the description (a Task spawn has
  // only a description, no command/path/pattern/url) so its line stays labeled.
  var textVal = summary.text || summary.desc;
  // Both branches use the SAME agent-line-text/ellipsis wrapper as the direct
  // flex child, with .empty nested one level deeper for the no-argument case,
  // never handed to the flex row bare: .agent-line-row is a flex container, so
  // a bare .empty span there is blockified and picks up .dash-main .empty's
  // unrelated 24px padding (meant for its own "Select a session." placeholder)
  // in full, roughly doubling this one row's height when the tab is viewed
  // inside the embedded dashboard. Nesting keeps .empty a plain inline span,
  // exactly like the graph ticker/popover already do (agentgraph.js).
  var textHtml = textVal
    ? '<span class="agent-line-text ellipsis">' + esc(textVal) + "</span>"
    : '<span class="agent-line-text ellipsis"><span class="empty">(no argument)</span></span>';
  var html =
    '<tr class="clickable agent-line" data-seq="' + ev.seq + '">' +
      '<td colspan="6">' +
        '<div class="agent-line-row">' +
          '<span class="agent-tool-label">' + esc(summary.tool) + "</span>" +
          textHtml +
          '<span class="meta mono-num">' + esc(model.tsLabel[i]) + "</span>" +
        "</div>" +
      "</td>" +
    "</tr>";
  if (expanded) html += timelineDetailRowHtml(ev);
  return html;
}

// agentActivityTableHtml renders one group's members as the concise
// activity log, in seq order (computeAgentGroups already hands back members
// in seq order — see its own doc comment above).
function agentActivityTableHtml(ctx, members) {
  if (!members.length) return '<div class="empty" style="padding:8px 16px;">(none)</div>';
  var rows = members.map(function (i) { return agentActivityLineHtml(ctx, i); }).join("");
  return '<table class="action-group-members"><tbody>' + rows + "</tbody></table>";
}

// agentBlockHtml renders one hierarchy entry (Primary/Child/unregistered
// agent), indented by its depth in the parent forest exactly like
// agentGroupHtml (style="margin-left:<depth*18>px"), with the same header
// (numbered role title + subagent type + agentStrengthChip + agentStatusChip +
// id/native id + action count) but showing the concise activity log instead of
// a raw event table, and defaulting OPEN (see AGENTS_TAB_COLLAPSE_PREFIX above).
function agentBlockHtml(ctx, g, meta, depth, sessionEnded) {
  var collapsed = agentsTabGroupCollapsed(ctx, g.key);
  var m = meta.get(g.key);
  var cls = "action-group" + (depth ? " agent-block-child" : "");
  var indent = depth ? ' style="margin-left:' + depth * 18 + 'px"' : "";
  return '<div class="' + cls + '"' + indent + ">" +
    '<button type="button" class="action-group-hdr" data-act="toggle-agent-group" data-key="' + esc(g.key) + '">' +
      '<span class="caret">' + (collapsed ? "▸" : "▾") + "</span>" +
      "<strong>" + esc(agentTitle(m)) + "</strong>" +
      agentStrengthChip(m) +
      agentStatusChip(m, sessionEnded) +
      '<span class="meta">' + esc(g.key) + (m && m.nativeID ? " · native " + esc(m.nativeID) : "") + "</span>" +
      '<span class="meta">' + numFmt(g.members.length) + (g.members.length === 1 ? " action" : " actions") + "</span>" +
    "</button>" +
    (collapsed ? "" : agentActivityTableHtml(ctx, g.members)) +
    "</div>";
}

// agentUnattributedBlockHtml renders the mandatory Unattributed Workload
// bucket (mirrors bucketGroupHtml's honest-presentation framing above):
// everything the harness never positively attributed to an agent — sessions
// recorded before the Primary's own direct calls were attributed, hooks that
// ran without a Primary id, and non-hook workload channels. Same
// default-open/collapse mechanics as agentBlockHtml; the Infrastructure
// bucket is intentionally never rendered on this tab.
function agentUnattributedBlockHtml(ctx, g, decompositionUnavailable) {
  var collapsed = agentsTabGroupCollapsed(ctx, g.key);
  var count = g.members.length;
  var note = decompositionUnavailable
    ? "agent decomposition unavailable: no lifecycle registrations recorded"
    : "activity with no positively-identified agent (for sessions recorded before primary attribution this includes the Primary's own direct tool calls)";
  return '<div class="action-group">' +
    '<button type="button" class="action-group-hdr" data-act="toggle-agent-group" data-key="' + esc(g.key) + '">' +
      '<span class="caret">' + (collapsed ? "▸" : "▾") + "</span>" +
      "<strong>Unattributed Workload</strong>" +
      '<span class="meta">' + numFmt(count) + (count === 1 ? " action" : " actions") + "</span>" +
      '<span class="meta">' + esc(note) + "</span>" +
    "</button>" +
    (collapsed ? "" : agentActivityTableHtml(ctx, g.members)) +
    "</div>";
}

// agentIsActive is the single "is this agent live right now" predicate, shared
// by the list view's Active/Past split and by the graph sub-tab (handed over as
// api.agentIsActive) so the two views can never disagree about who is running.
//
// An agent id carrying activity but no registration (meta undefined) counts as
// ACTIVE while the session is live: it is emitting actions and the record
// contains no closure for it, so calling it "past" would assert an ending the
// harness never narrated. It keeps its "unregistered" chip either way. Once the
// session itself has ended nothing is live — including those unregistered ids
// and any child the harness never closed.
function agentIsActive(m, sessionEnded) {
  if (sessionEnded) return false;
  return !m || !m.completed;
}

// partitionAgentGroups splits computeAgentGroups' pre-order forest walk into the
// two rendered sections. Splitting one walk into two lists breaks its
// parent-before-child adjacency, so indentation is recomputed PER SECTION rather
// than carried over from the walk: an agent whose parent landed in the other
// section (or is not rendered above it at all) becomes a root of its own section,
// and everything below it follows, so a re-rooted parent never leaves its own
// subtree floating at an indent level that points at nothing.
//
// The walk is pre-order, so a parent in the same section has always been placed
// before its children and its rendered depth is known; the only entries that miss
// that lookup are the ones the walk itself rescued (a cycle or a rootless
// component visited out of order), which correctly start at depth 0. Now that
// nesting is derived from spawn edges this is N-level generic and routinely
// exercised: a mid-tree agent completing while its children still run puts a
// depth-2 subtree in Active whose parent sits in Past.
function partitionAgentGroups(info) {
  var sectionOf = new Map(); // agent id -> "active" | "past"
  info.agentGroups.forEach(function (og) {
    sectionOf.set(og.group.key, agentIsActive(info.meta.get(og.group.key), info.sessionEnded) ? "active" : "past");
  });
  var active = [], past = [];
  var renderedDepth = new Map(); // agent id -> its indent depth WITHIN its own section
  info.agentGroups.forEach(function (og) {
    var key = og.group.key;
    var section = sectionOf.get(key);
    var m = info.meta.get(key);
    var parentID = m ? m.parentID : "";
    var nested = parentID && sectionOf.get(parentID) === section && renderedDepth.has(parentID);
    var depth = nested ? renderedDepth.get(parentID) + 1 : 0;
    renderedDepth.set(key, depth);
    (section === "active" ? active : past).push({ group: og.group, depth: depth });
  });
  return { active: active, past: past };
}

// agentsSectionHdrHtml renders one section banner, reusing the sidebar's
// group/section header look (.group-hdr/.section-hdr) with an agents-prefixed
// class for this tab's wider gutter.
function agentsSectionHdrHtml(title, count, note) {
  return '<div class="group-hdr section-hdr agents-section-hdr">' +
    '<span class="group-name">' + esc(title) + "</span>" +
    (note ? '<span class="meta agents-section-note">' + esc(note) + "</span>" : "") +
    '<span class="group-count">' + numFmt(count) + "</span>" +
    "</div>";
}

// agentsModeSwitchHtml is the List/Graph sub-view switch, following the same
// mode-button idiom as the Files and Actions toolbars. The choice is
// deliberately NOT persisted in the URL hash, like every other mode toggle
// (see serializeStateForHash).
function agentsModeSwitchHtml(state) {
  return (
    '<button type="button" class="btn small' + (state.agentsMode === "list" ? " active" : "") + '" data-act="agents-mode" data-value="list">list</button>' +
    '<button type="button" class="btn small' + (state.agentsMode === "graph" ? " active" : "") + '" data-act="agents-mode" data-value="graph">graph</button>'
  );
}

function mountAgentsTab(ctx) {
  var el = ctx.els.tabs.agents;
  // Two panes, both mounted once: switching sub-views toggles .hidden instead
  // of replacing the tab's markup, so the list's rendered blocks (and the graph
  // module's own delegated listeners, bound once on a stable container) survive
  // every trip through the switch.
  el.innerHTML =
    '<div class="subtoolbar" data-role="toolbar"></div>' +
    '<div class="table-wrap" data-role="tablewrap"></div>' +
    '<div class="agraph-pane hidden" data-role="graphwrap"></div>';
  ctx.els.agentsToolbar = el.querySelector('[data-role="toolbar"]');
  ctx.els.agentsTableWrap = el.querySelector('[data-role="tablewrap"]');
  ctx.els.agentsGraphWrap = el.querySelector('[data-role="graphwrap"]');
  bindAgentsTabEvents(ctx, el);
}

function updateAgentsTab(ctx) {
  var indices = toolRequestedIndices(ctx.model);
  var info = computeAgentGroups(ctx, indices, true);
  var graphMode = ctx.state.agentsMode === "graph";
  ctx.els.agentsTableWrap.classList.toggle("hidden", graphMode);
  ctx.els.agentsGraphWrap.classList.toggle("hidden", !graphMode);
  // The graph pane must be visible before it renders: a display:none pane
  // measures as zero, and the graph's edges are drawn from measured card
  // positions (see agentgraph.js's own geometry guard).
  if (graphMode) renderAgentGraph(ctx, info);

  if (indices.length === 0) {
    ctx.els.agentsToolbar.innerHTML = agentsModeSwitchHtml(ctx.state) +
      '<span class="meta">no agent activity recorded</span>';
    ctx.els.agentsTableWrap.innerHTML =
      '<div class="empty" style="padding:12px 16px;">no agent activity recorded ' +
      '<span class="meta">(the harness narrated no subagents for this session)</span></div>';
    return;
  }

  if (info.agentCount === 0) {
    ctx.els.agentsToolbar.innerHTML = agentsModeSwitchHtml(ctx.state) +
      (graphMode ? "" : '<button type="button" class="btn small" data-act="agents-collapse-all" title="collapse every agent block and expanded row">collapse all</button>') +
      '<span class="meta">0 agents · ' + numFmt(indices.length) + " actions</span>";
    ctx.els.agentsTableWrap.innerHTML = agentUnattributedBlockHtml(ctx, {
      key: UNATTRIBUTED_KEY,
      members: indices,
    }, true);
    return;
  }

  // Active/Past is a presentation of the same grouping, not a filter over it:
  // every agent in the walk lands in exactly one of the two sections, so the
  // tab still shows the whole hierarchy and the tab's count badge (tabCounts)
  // is unaffected.
  var sections = partitionAgentGroups(info);
  ctx.els.agentsToolbar.innerHTML = agentsModeSwitchHtml(ctx.state) +
    (graphMode ? "" : '<button type="button" class="btn small" data-act="agents-collapse-all" title="collapse every agent block and expanded row">collapse all</button>') +
    '<span class="meta">' + numFmt(info.agentCount) + (info.agentCount === 1 ? " agent" : " agents") +
    " · " + numFmt(sections.active.length) + " active · " + numFmt(indices.length) + " actions</span>";

  var html = "";
  if (sections.active.length) {
    html += agentsSectionHdrHtml("Active Agents", sections.active.length,
      info.sessionEnded ? "" : "no closure recorded yet");
    sections.active.forEach(function (og) {
      html += agentBlockHtml(ctx, og.group, info.meta, og.depth, info.sessionEnded);
    });
  }
  if (sections.past.length) {
    html += agentsSectionHdrHtml("Past Agents", sections.past.length,
      info.sessionEnded ? "the session has ended" : "closed by the harness");
    sections.past.forEach(function (og) {
      html += agentBlockHtml(ctx, og.group, info.meta, og.depth, info.sessionEnded);
    });
  }
  // The Unattributed Workload bucket belongs to no agent and so to neither
  // section: it stays where it has always been, last and outside both.
  html += agentUnattributedBlockHtml(ctx, info.unattributed);
  ctx.els.agentsTableWrap.innerHTML = html;
}

// renderAgentGraph hands the ALREADY-DERIVED grouping to the graph sub-view
// (internal/view/agentgraph.js), the same hook shape updateProcessesTab uses for
// the Processes tab: the caller empties the container, the module rebuilds its
// DOM from scratch, and anything that must survive that lives in the module's
// own state. Passing computeAgentGroups' output rather than raw events is what
// keeps every honesty rule pinned in this file (registrations only, orphan
// completions dropped, missing parents rendered as roots, cycle guard, rootless
// sweep, registered-but-silent agents still present) true of the graph for free.
//
// payloadVersion is session-qualified — unlike the Processes hook's, which
// predates the dashboard being able to swap sessions under a mounted view — so a
// module-level cache can never carry one session's nodes into the next.
function renderAgentGraph(ctx, info) {
  var host = ctx.els.agentsGraphWrap;
  if (!(window.BoxedAiAgentGraph && typeof window.BoxedAiAgentGraph.render === "function")) {
    host.innerHTML = '<div class="empty" style="padding:12px 16px;">graph view unavailable ' +
      '<span class="meta">(/assets/agentgraph.js did not load)</span></div>';
    return;
  }
  var model = ctx.model;
  var lastSeq = model.events.length ? model.events[model.events.length - 1].seq : 0;
  var sessionID = (ctx.payload && ctx.payload.session_id) || "";
  var data = {
    groups: info.agentGroups, // [{group, depth}], pre-order, parents before children
    meta: info.meta,
    unattributed: info.unattributed,
    sessionEnded: info.sessionEnded,
    events: model.events,
    tsLabel: model.tsLabel, // parallel to events, precomputed clock labels
    bySeq: model.bySeq, // seq -> index, for resolving an agent's registration timestamp
    sessionId: sessionID,
  };
  var api = {
    esc: esc,
    numFmt: numFmt,
    chipHtml: chipHtml,
    statusColor: statusColor,
    toolActivitySummary: toolActivitySummary,
    agentTitle: agentTitle,
    agentStrengthChip: agentStrengthChip,
    agentIsActive: agentIsActive,
    fmtTs: fmtTs,
    payloadVersion: sessionID + ":" + model.events.length + ":" + lastSeq,
  };
  host.innerHTML = "";
  window.BoxedAiAgentGraph.render(host, data, api);
}

// collapseAllAgentsTab folds every rendered agent block closed and clears every
// expanded activity-line detail, returning the tab to just its agent headers —
// the Agents-tab counterpart to the Timeline's "collapse all". The block keys
// are recomputed (not scraped from the DOM) so the collapsed set matches exactly
// what updateAgentsTab renders: each hierarchy group plus the always-present
// Unattributed bucket. expandedSeqs is the same per-event detail state the
// Timeline clears, so a full clear here keeps the two buttons' behaviour aligned.
function collapseAllAgentsTab(ctx) {
  var info = computeAgentGroups(ctx, toolRequestedIndices(ctx.model), true);
  info.agentGroups.forEach(function (og) {
    ctx.state.expandedActionGroups.add(AGENTS_TAB_COLLAPSE_PREFIX + og.group.key);
  });
  ctx.state.expandedActionGroups.add(AGENTS_TAB_COLLAPSE_PREFIX + UNATTRIBUTED_KEY);
  ctx.state.expandedSeqs.clear();
}

// bindAgentsTabEvents mirrors the relevant parts of bindTimelineEvents: a
// row click toggles ctx.state.expandedSeqs and the detail row's copy-JSON/
// filter-chain/focus-pid buttons behave identically to Timeline's;
// toggle-agent-group additionally collapses/expands one hierarchy block.
function bindAgentsTabEvents(ctx, container) {
  container.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-act]");
    if (btn) {
      var act = btn.dataset.act;
      // The sub-view switch is dispatched here, not through ctx.switchTab:
      // switchTab early-returns on the tab that is already active, and this
      // moves between two panes INSIDE the Agents tab.
      if (act === "agents-mode") { ctx.state.agentsMode = btn.dataset.value; updateAgentsTab(ctx); return; }
      if (act === "toggle-agent-group") { toggleAgentsTabGroup(ctx, btn.dataset.key); updateAgentsTab(ctx); return; }
      if (act === "agents-collapse-all") { collapseAllAgentsTab(ctx); updateAgentsTab(ctx); return; }
      if (act === "copy-json") { copyEventJSON(ctx, Number(btn.dataset.seq), btn); return; }
      if (act === "filter-chain") { ctx.setSearch(btn.dataset.value); return; }
      if (act === "focus-pid") { ctx.focusPid(btn.dataset.value); return; }
      return;
    }
    var row = e.target.closest("tr.agent-line");
    if (row) {
      var seq = Number(row.dataset.seq);
      if (ctx.state.expandedSeqs.has(seq)) ctx.state.expandedSeqs.delete(seq);
      else ctx.state.expandedSeqs.add(seq);
      updateAgentsTab(ctx);
    }
  });
}

// ---- per-tab renderers: proof ----
//
// This is the audit tool's full evidence view — everything the old
// overview/verify/dashboard-proof sections showed, restyled, dropping
// nothing. Bounded by segment/check counts (never event counts), so it is
// always a single cheap innerHTML render with no chunking needed.

function boolTextHtml(b) {
  return ktextHtml(b ? "true" : "false", boolColorVar(b));
}

// The trust-record booleans only carry meaning once a record exists: a legacy
// session that has none still reports them as false, and painting that red
// reads as a signature failure next to a passing session-trust-record check.
// The CLI report gates the same two lines on a non-empty profile, so an
// absent record renders as the same em dash the other optional rows use.
function trustBoolTextHtml(present, b) {
  return present ? boolTextHtml(!!b) : '<span class="empty">—</span>';
}

function proofVerdictBannerHtml(payload) {
  var proof = payload.proof || {};
  var verdict = proof.verdict || "no verdict";
  var verdictColor = proof.verdict ? verdictColorVar(proof.verdict) : statusColor("muted");
  var html = '<div class="proof-banner">' +
    chipHtml(verdict, verdictColor, "big") +
    chipHtml(proof.status || "unknown", proofStatusColorVar(proof.status)) +
    "</div>";
  // The server always explains the current proof status in proof.message (the
  // old page showed it as a "Message" row for every status, not just the
  // provisional one), so it is rendered whenever present.
  if (proof.message) {
    html += '<div class="proof-message">' + esc(proof.message) + "</div>";
  }
  return html;
}

function proofFactsGridHtml(payload) {
  var proof = payload.proof || {};
  var verify = payload.verify;
  var rows = [];
  rows.push(["digest / chain", esc(proof.digest_algorithm || "") + "; chain valid " + boolTextHtml(!!proof.chain_valid)]);
  rows.push(["signature", esc(proof.signature_format || "") + "; " + esc(proof.signature_algorithm || "")]);
  rows.push(["recorder fingerprint", proof.recorder_key_fingerprint ? digestCellHtml(proof.recorder_key_fingerprint) : '<span class="empty">—</span>']);
  if (verify) {
    var f = verify.facets || {};
    rows.push(["signature valid", boolTextHtml(!!f.signature_valid)]);
    rows.push(["sequence continuous", boolTextHtml(!!f.sequence_continuous)]);
    rows.push(["close status", esc(f.close_status || "")]);
    rows.push(["sensor loss count", numFmt(f.sensor_loss_count)]);
    rows.push(["ungated activity count", numFmt(f.ungated_activity_count)]);
    rows.push(["verified unreachable", esc(f.verified_unreachable || "")]);
    if (f.messages && f.messages.length) {
      rows.push(["messages", "<ul>" + f.messages.map(function (m) { return "<li>" + esc(m) + "</li>"; }).join("") + "</ul>"]);
    }
    rows.push(["trust record status", esc(proof.trust_record_status || "—")]);
    rows.push(["trust record profile", esc(proof.trust_record_profile || "—")]);
    var haveTrustRecord = !!proof.trust_record_profile;
    rows.push(["trust record signature valid", trustBoolTextHtml(haveTrustRecord, proof.trust_record_signature_valid)]);
    rows.push(["trust record cross-derived", trustBoolTextHtml(haveTrustRecord, proof.trust_record_cross_derived)]);
    rows.push(["trust record assurance", esc(proof.trust_record_assurance || "—")]);
  }
  return '<div class="facts-grid">' + rows.map(function (r) {
    return '<div class="k">' + esc(r[0]) + '</div><div class="v">' + r[1] + "</div>";
  }).join("") + "</div>";
}

function proofChecksTableHtml(payload) {
  var checks = (payload.proof && payload.proof.checks) || [];
  if (!checks.length) {
    return '<table><tbody><tr><td class="empty">No verifier checks available.</td></tr></tbody></table>';
  }
  var rows = checks.map(function (c) {
    var resultHtml = c.passed ? ktextHtml("PASS ✓", statusColor("good")) : ktextHtml("FAIL ✕", statusColor("crit"));
    return "<tr><td>" + esc(c.name) + "</td><td>" + resultHtml + "</td><td>" + esc(c.detail || "") + "</td></tr>";
  }).join("");
  return "<table><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>" + rows + "</tbody></table>";
}

// proofSegmentChainStripHtml renders the #1 → #2 → ... chip strip; a
// connector is good-colored only when segment i's prev_segment_digest
// exactly matches segment i-1's declared_segment_digest and both are
// non-empty, per spec.
function proofSegmentChainStripHtml(segments) {
  if (!segments.length) return "";
  var parts = segments.map(function (seg, idx) {
    var color = seg.sealed ? statusColor("good") : statusColor("warn");
    var chip = '<span class="segment-chip" style="--chip-color:' + color + '">#' + seg.number + "</span>";
    if (idx === 0) return chip;
    var prev = segments[idx - 1];
    var linked = !!(seg.prev_segment_digest && prev.declared_segment_digest && seg.prev_segment_digest === prev.declared_segment_digest);
    var title = "prev=" + (seg.prev_segment_digest || "(none)") + " prevDeclared=" + (prev.declared_segment_digest || "(none)");
    return '<span class="segment-connector' + (linked ? " linked" : "") + '" title="' + esc(title) + '"> → </span>' + chip;
  });
  return '<div class="segment-strip">' + parts.join("") + "</div>";
}

function proofSegmentsTableHtml(segments) {
  if (!segments.length) {
    return '<table><tbody><tr><td class="empty">No segments.</td></tr></tbody></table>';
  }
  var rows = segments.map(function (seg) {
    var digest = seg.otlp_digest || seg.declared_segment_digest || "";
    var digestKind = seg.otlp_digest ? "otlp_digest (recomputed)" : "declared_segment_digest (manifest)";
    var hasFirst = seg.first_sequence !== undefined && seg.first_sequence !== null;
    var hasLast = seg.last_sequence !== undefined && seg.last_sequence !== null;
    var seqRange = (hasFirst ? seg.first_sequence : "?") + "–" + (hasLast ? seg.last_sequence : "?");
    var digestCell = digest
      ? '<span title="' + esc(digestKind + ": " + digest) + '">' + esc(truncateDigest(digest)) + "</span> " +
        '<button type="button" class="copy-btn" data-act="copy-text" data-value="' + esc(digest) + '">copy</button>'
      : '<span class="empty">—</span>';
    var prevCell = seg.prev_segment_digest
      ? '<span title="' + esc(seg.prev_segment_digest) + '">' + esc(truncateDigest(seg.prev_segment_digest)) + "</span>"
      : '<span class="empty">—</span>';
    return "<tr>" +
      "<td>" + seg.number + "</td>" +
      "<td>" + boolTextHtml(!!seg.sealed) + "</td>" +
      "<td>" + numFmt(seg.record_count || 0) + "</td>" +
      "<td>" + esc(seqRange) + "</td>" +
      "<td>" + esc(seg.sealed_at || "") + "</td>" +
      "<td>" + digestCell + "</td>" +
      "<td>" + prevCell + "</td>" +
      "<td>" + (seg.cose_sign1 ? ktextHtml("✓", statusColor("good")) : ktextHtml("—", statusColor("muted"))) + "</td>" +
    "</tr>";
  }).join("");
  return "<table><thead><tr><th>#</th><th>Sealed</th><th>Records</th><th>Seq range</th><th>Sealed at</th>" +
    "<th>Digest</th><th>Prev digest</th><th>COSE</th></tr></thead><tbody>" + rows + "</tbody></table>";
}

function mountProofTab(ctx) {
  // Unlike the other tabs the proof pane has no .table-wrap to scroll: its
  // whole stack of sections is one body, so that body is the scroller (see
  // .proof-body in app.css, and activeScrollEl which saves its position).
  ctx.els.tabs.proof.innerHTML = '<div class="proof-body" data-role="body"></div>';
  ctx.els.proofBody = ctx.els.tabs.proof.querySelector('[data-role="body"]');
  ctx.els.proofBody.addEventListener("click", function (e) {
    var btn = e.target.closest('[data-act="copy-text"]');
    if (btn) copyToClipboard(btn.dataset.value, btn);
  });
}

function updateProofTab(ctx) {
  var payload = ctx.payload;
  var segments = (payload.proof && payload.proof.segments) || [];
  ctx.els.proofBody.innerHTML =
    proofVerdictBannerHtml(payload) +
    proofFactsGridHtml(payload) +
    '<div class="proof-section-title">Verifier checks</div>' +
    proofChecksTableHtml(payload) +
    '<div class="proof-section-title">Segments</div>' +
    proofSegmentChainStripHtml(segments) +
    proofSegmentsTableHtml(segments);
}

// ---- header/tabs ----

var TAB_DEFS = [
  { key: "timeline", label: "Timeline" },
  { key: "agents", label: "Agents" },
  { key: "processes", label: "Processes" },
  { key: "files", label: "Files" },
  { key: "network", label: "Network" },
  { key: "actions", label: "Actions" },
  { key: "proof", label: "Proof" },
];

function headerHtml(ctx) {
  var payload = ctx.payload;
  var proof = payload.proof || {};
  var events = payload.events || [];
  var lastEv = events.length ? events[events.length - 1] : null;
  var statusSuffix = proof.provisional ? '<span class="pulse-text"> · live</span>' : "";
  var statusChip = '<span class="chip" style="--chip-color:' + proofStatusColorVar(proof.status) + '">' +
    esc(proof.status || "unknown") + statusSuffix + "</span>";
  var updated = ctx.lastUpdatedAt ? fmtClockShort(ctx.lastUpdatedAt) : "—";

  return (
    '<span class="wordmark">BoxedAi</span>' +
    '<button type="button" class="copy-btn" data-act="copy-value" data-value="' + esc(payload.session_id || "") +
      '" title="click to copy">' + esc(payload.session_id || "(unknown session)") + "</button>" +
    chipHtml(payload.state || "unknown", sessionStateColorVar(payload.state)) +
    chipHtml(proof.verdict || "NO VERDICT", proof.verdict ? verdictColorVar(proof.verdict) : statusColor("muted")) +
    statusChip +
    '<span class="meta mono-num">' + numFmt(events.length) + " events</span>" +
    '<span class="meta mono-num">last ' + (lastEv ? esc(fmtClockShort(lastEv.ts)) : "—") + "</span>" +
    '<button type="button" class="copy-btn" data-act="copy-value" data-value="' + esc(payload.policy_digest || "") +
      '" title="click to copy full digest">' + esc(truncateDigest(payload.policy_digest || "") || "(no digest)") + "</button>" +
    '<span class="spacer"></span>' +
    chipHtml(ctx.connectionState, connectionStateColorVar(ctx.connectionState), "connection-state") +
    '<label class="toggle"><input type="checkbox" data-act="live-toggle"' + (ctx.state.liveOn ? " checked" : "") + "> live</label>" +
    '<span class="meta mono-num">updated ' + esc(updated) + "</span>" +
    '<button type="button" class="btn small" data-act="manual-refresh" title="refresh now">⟳</button>'
  );
}

function renderHeader(ctx) {
  ctx.els.hdr.innerHTML = headerHtml(ctx);
  // textContent (not innerHTML) below: the browser escapes it for us, so no
  // separate esc() call is needed for this one assignment.
  if (ctx.payload.verify_error) {
    ctx.els.banner.textContent = "verify failed: " + ctx.payload.verify_error;
    ctx.els.banner.classList.remove("hidden");
  } else {
    ctx.els.banner.textContent = "";
    ctx.els.banner.classList.add("hidden");
  }
}

function bindHeaderEvents(ctx) {
  ctx.els.hdr.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-act]");
    if (!btn) return;
    if (btn.dataset.act === "copy-value") { copyToClipboard(btn.dataset.value, btn); return; }
    if (btn.dataset.act === "manual-refresh") { ctx.manualRefresh(); return; }
  });
  ctx.els.hdr.addEventListener("change", function (e) {
    if (e.target.matches('[data-act="live-toggle"]')) {
      ctx.state.liveOn = e.target.checked;
      ctx.onLiveToggle();
    }
  });
  ctx.els.tabsBar.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-tab-btn]");
    if (btn) ctx.switchTab(btn.dataset.tabBtn);
  });
}

function tabsBarHtml(ctx) {
  var counts = tabCounts(ctx.payload);
  return TAB_DEFS.map(function (t) {
    var active = ctx.state.tab === t.key;
    return '<button type="button" class="tab-btn' + (active ? " active" : "") + '" data-tab-btn="' + t.key + '">' +
      esc(t.label) + ' <span class="tab-count">' + numFmt(counts[t.key]) + "</span></button>";
  }).join("");
}
function renderTabsBar(ctx) {
  ctx.els.tabsBar.innerHTML = tabsBarHtml(ctx);
}

function renderActiveTab(ctx, appendMode) {
  switch (ctx.state.tab) {
    case "timeline": updateTimelineTab(ctx, appendMode); break;
    case "agents": updateAgentsTab(ctx); break;
    case "processes": updateProcessesTab(ctx); break;
    case "files": updateFilesTab(ctx); break;
    case "network": updateNetworkTab(ctx); break;
    case "actions": updateActionsTab(ctx); break;
    case "proof": updateProofTab(ctx); break;
  }
}

// activeScrollEl finds the scrollable area of whichever tab is currently
// visible, so callers can save/restore scrollTop around a rebuild (spec:
// re-renders must preserve scroll position). Every tab but Proof scrolls in a
// .table-wrap; Proof has no table to wrap, so its own body is the scroller.
// Both are direct children of the pane, so the first match is the right one.
function activeScrollEl(ctx) {
  var container = ctx.els.tabs[ctx.state.tab];
  return container ? container.querySelector(".table-wrap, .proof-body") : null;
}

function switchTab(ctx, tab) {
  if (ctx.state.tab === tab) return;
  ctx.state.tab = tab;
  TAB_DEFS.forEach(function (t) { ctx.els.tabs[t.key].classList.toggle("hidden", t.key !== tab); });
  renderTabsBar(ctx);
  renderActiveTab(ctx);
  ctx.scheduleHash();
}

function mountShell(ctx) {
  ctx.root.innerHTML =
    '<div class="topbar">' +
      '<div class="hdr" data-role="hdr"></div>' +
      '<div class="hdr-banner hidden" data-role="banner"></div>' +
      '<div class="tabs" data-role="tabs"></div>' +
    "</div>" +
    '<div class="tab-content" data-tab="timeline"></div>' +
    '<div class="tab-content hidden" data-tab="agents"></div>' +
    '<div class="tab-content hidden" data-tab="processes"></div>' +
    '<div class="tab-content hidden" data-tab="files"></div>' +
    '<div class="tab-content hidden" data-tab="network"></div>' +
    '<div class="tab-content hidden" data-tab="actions"></div>' +
    '<div class="tab-content hidden" data-tab="proof"></div>';
  ctx.els.hdr = ctx.root.querySelector('[data-role="hdr"]');
  ctx.els.banner = ctx.root.querySelector('[data-role="banner"]');
  ctx.els.tabsBar = ctx.root.querySelector('[data-role="tabs"]');
  ctx.els.tabs = {};
  TAB_DEFS.forEach(function (t) {
    ctx.els.tabs[t.key] = ctx.root.querySelector('.tab-content[data-tab="' + t.key + '"]');
    // The markup above hardcodes Timeline as the visible pane; state.tab may
    // already be something else (restored from the hash), and switchTab never
    // runs for that restore, so reconcile visibility with state here.
    ctx.els.tabs[t.key].classList.toggle("hidden", t.key !== ctx.state.tab);
  });
  bindHeaderEvents(ctx);
  mountTimelineTab(ctx);
  mountAgentsTab(ctx);
  mountProcessesTab(ctx);
  mountFilesTab(ctx);
  mountNetworkTab(ctx);
  mountActionsTab(ctx);
  mountProofTab(ctx);
}

// ---- session view orchestrator ----

// createSessionView mounts the one shared component both pages use. Transport
// stays page-owned: the standalone and dashboard hosts call setPayload() from
// their shared EventSource lifecycle, while Live and manual refresh notify the
// host through opts.onLiveToggle/onManualRefresh.
function createSessionView(rootEl, opts) {
  opts = opts || {};
  var ctx = {
    state: defaultState(),
    payload: null,
    model: null,
    agentActivityNames: new Set(), // repopulated per payload in setSessionViewPayload from payload.agent_activity_names
    // Per-view /api/filediff cache, keyed by fileDiffKey. Lives on the view (not
    // in state) because it holds fetched content rather than UI intent, and is
    // dropped whenever the view switches sessions — blobs are session-scoped.
    diffCache: new Map(),
    root: rootEl,
    els: {},
    mode: opts.mode || "standalone",
    connectionState: "connecting",
    prevSummary: null,
    prevEventCount: 0,
    prevFilteredTotal: 0,
    tlRenderedCount: 0,
    lastUpdatedAt: null,
  };

  restoreStateFromHash(ctx.state);

  ctx.scheduleHash = function () {
    writeHashDebounced(ctx.state);
  };
  ctx.debouncedSearch = debounce(function () {
    resetTimelineChunk(ctx.state);
    ctx.refreshAll();
  }, SEARCH_DEBOUNCE_MS);
  ctx.refreshAll = function () {
    renderHeader(ctx);
    renderTabsBar(ctx);
    renderActiveTab(ctx);
    ctx.scheduleHash();
  };
  ctx.switchTab = function (tab) { switchTab(ctx, tab); };
  ctx.setSearch = function (value) {
    ctx.state.search = value;
    resetTimelineChunk(ctx.state);
    if (ctx.state.tab !== "timeline") ctx.switchTab("timeline");
    else ctx.refreshAll();
  };
  ctx.focusPid = function (pid) {
    ctx.state.pid = String(pid);
    resetTimelineChunk(ctx.state);
    if (ctx.state.tab !== "timeline") ctx.switchTab("timeline");
    else ctx.refreshAll();
  };
  // showFileHistory is the Timeline's "file history" jump: the Files tab in
  // latest-per-path mode, with that path already expanded and scrolled to.
  // switchTab renders the tab itself, so it only re-renders directly when the
  // reader is already on Files.
  ctx.showFileHistory = function (path) {
    ctx.state.filesMode = "latest";
    ctx.state.expandedFilePaths.add(path);
    ctx.state.filesFocusPath = path;
    if (ctx.state.tab !== "files") ctx.switchTab("files");
    else updateFilesTab(ctx);
  };
  ctx.manualRefresh = function () {
    if (opts.onManualRefresh) opts.onManualRefresh();
  };
  ctx.onLiveToggle = function () {
    if (opts.onLiveToggle) opts.onLiveToggle(ctx.state.liveOn);
  };

  mountShell(ctx);

  return {
    setPayload: function (payload) { setSessionViewPayload(ctx, payload); },
    getPayload: function () { return ctx.payload; },
    setConnectionState: function (state) {
      ctx.connectionState = state;
      if (ctx.payload) renderHeader(ctx);
    },
    isLive: function () { return ctx.state.liveOn; },
    setLive: function (on) {
      if (ctx.state.liveOn === on) return;
      ctx.state.liveOn = on;
      if (ctx.payload) renderHeader(ctx);
      ctx.onLiveToggle();
    },
    focusPid: ctx.focusPid,
    destroy: function () {},
  };
}

// setSessionViewPayload is the single entry point every new snapshot or merged
// delta flows through.
// It implements the spec's change-detection/append-only/full-rerender
// decision and preserves active tab, filters, expanded rows, sort, mode
// toggles and scroll position across whichever path it takes.
function setSessionViewPayload(ctx, payload) {
  var isNewSession = !ctx.payload || ctx.payload.session_id !== payload.session_id;
  var newEvents = payload.events || [];
  var newSummary = {
    len: newEvents.length,
    lastSeq: newEvents.length ? newEvents[newEvents.length - 1].seq : 0,
    state: payload.state || "",
    status: payload.proof && payload.proof.status,
    verifyError: payload.verify_error || "",
  };

  if (!isNewSession && ctx.prevSummary &&
      ctx.prevSummary.len === newSummary.len &&
      ctx.prevSummary.lastSeq === newSummary.lastSeq &&
      ctx.prevSummary.state === newSummary.state &&
      ctx.prevSummary.status === newSummary.status &&
      ctx.prevSummary.verifyError === newSummary.verifyError) {
    ctx.lastUpdatedAt = new Date().toISOString();
    renderHeader(ctx); // keep the "updated HH:MM:SS" clock current even when the payload is unchanged
    return;
  }

  var appendMode = null;
  if (isNewSession || !ctx.model) {
    ctx.model = buildModel(newEvents);
    ctx.state.expandedSeqs = new Set(); // seqs from a different session are meaningless here
    ctx.state.expandedActionGroups = new Set();
    ctx.state.expandedFilePaths = new Set();
    ctx.state.expandedFileDiffs = new Set();
    ctx.state.filesFocusPath = "";
    ctx.diffCache = new Map(); // blob content is session-scoped: never show one session's bytes under another
    ctx.tlRenderedCount = 0;
    resetTimelineChunk(ctx.state);
    if (isNewSession && payload.proof) {
      // Re-derive the Live default per session (spec: ON iff provisional);
      // a manual choice made on the SAME session is never overridden. The page
      // owner reconciles its single source after the initial snapshot.
      ctx.state.liveOn = !!payload.proof.provisional;
      ctx.onLiveToggle();
    }
  } else {
    var oldEvents = ctx.model.events;
    var isPrefix = newEvents.length > oldEvents.length && oldEvents.length > 0 &&
      newEvents[0].seq === oldEvents[0].seq &&
      newEvents[oldEvents.length - 1].seq === oldEvents[oldEvents.length - 1].seq;
    ctx.prevEventCount = oldEvents.length;
    ctx.prevFilteredTotal = ctx.timelineFiltered ? timelineDisplayIndices(ctx.timelineFiltered, ctx.state).length : 0;
    if (isPrefix) {
      extendModel(ctx.model, newEvents);
      appendMode = "tail";
    } else {
      ctx.model = buildModel(newEvents); // not a clean prefix: rebuild, but keep filters/tab/sort/expansion
    }
  }

  ctx.payload = payload;
  ctx.agentActivityNames = new Set(payload.agent_activity_names || []);
  ctx.lastUpdatedAt = new Date().toISOString();
  ctx.prevSummary = newSummary;

  var scrollEl = activeScrollEl(ctx);
  var savedScrollTop = scrollEl ? scrollEl.scrollTop : 0;

  renderHeader(ctx);
  renderTabsBar(ctx);
  renderActiveTab(ctx, appendMode);

  if (scrollEl) scrollEl.scrollTop = savedScrollTop;
}

function terminalSessionState(state) {
  return state === "sealed" || state === "incomplete";
}

function fetchStandaloneSnapshot(view) {
  fetch("/api/events").then(function (r) { return r.json(); }).then(function (payload) {
    var result = reduceSessionSnapshot(payload, "");
    if (result.kind !== "applied") {
      view.setConnectionState("stale");
      return;
    }
    view.setPayload(result.payload);
    if (terminalSessionState(result.payload.state)) view.setConnectionState("complete");
  }).catch(function () {
    // Network hiccup: keep showing the last good payload and surface that it
    // could not be refreshed instead of clearing the view.
    view.setConnectionState("stale");
  });
}

function mountStandalone(appEl) {
  var view;
  var owner = createEventSourceOwner({
    eventTypes: STREAM_EVENT_TYPES,
    onState: function (state) {
      if (view) view.setConnectionState(state);
    },
    onMalformed: function () {
      if (view) view.setConnectionState("stale");
      owner.restart();
    },
    onEvent: function (type, payload) {
      if (type === "session.snapshot") {
        var snapshot = reduceSessionSnapshot(payload, "");
        if (snapshot.kind !== "applied") {
          view.setConnectionState("stale");
          owner.restart();
          return;
        }
        view.setPayload(snapshot.payload);
        if (terminalSessionState(snapshot.payload.state)) {
          view.setLive(false);
          owner.close("complete");
        }
        return;
      }
      if (type !== "session.delta") return;
      var delta = reduceSessionDelta(view.getPayload(), payload);
      if (delta.kind !== "applied") {
        view.setConnectionState("stale");
        owner.restart();
        return;
      }
      view.setPayload(delta.payload);
    },
  });

  view = createSessionView(appEl, {
    mode: "standalone",
    onManualRefresh: function () {
      if (view.isLive()) owner.restart();
      else fetchStandaloneSnapshot(view);
    },
    onLiveToggle: function (on) {
      if (on) owner.ensure("/api/stream");
      else owner.close("paused");
    },
  });
  owner.open("/api/stream");
  window.addEventListener("beforeunload", function () { owner.close(); }, { once: true });
}

// ---- dashboard ----
//
// The dashboard is a ~300px session-list sidebar plus one embedded
// SessionView in the main pane. Its page-owned EventSource always carries
// dashboard discovery and carries selected-session detail only while Live is
// enabled; the embedded SessionView still owns DOM change detection.

// repoLabel shortens a repository reference (a clone URL or an owner/name) to a
// compact "owner/name" for the group header, falling back to a stable label
// for sessions that were run against a local checkout with no remote origin.
function repoLabel(repo) {
  if (!repo) return "local (no remote)";
  var s = repo.replace(/\.git$/, "");
  // scp-like (git@host:owner/name, org-123@github.com:owner/name) or URL.
  var scp = s.match(/^[^/]*@[^:]+:(.+)$/);
  if (scp) s = scp[1];
  else {
    var m = s.match(/^[a-z]+:\/\/[^/]+\/(.+)$/i);
    if (m) s = m[1];
  }
  var parts = s.split("/").filter(Boolean);
  if (parts.length >= 2) return parts.slice(-2).join("/");
  return parts.join("/") || repo;
}

function branchLabel(branch) {
  return branch || "(detached)";
}

// groupKey is the stable identity of a repo group, used for collapse state and
// group-level select-all so it survives re-renders across streamed updates.
function groupKey(repo) {
  return "repo:" + (repo || "");
}

// sessionMatchesFilter tests the free-text sidebar filter against a session's
// id, harness, profile, repo and branch so filtering works after grouping too.
function sessionMatchesFilter(s, q) {
  if (!q) return true;
  var hay = (s.session_id + " " + (s.harness || "") + " " + (s.profile || "") + " " +
    (s.repository || "") + " " + repoLabel(s.repository) + " " + (s.branch || "")).toLowerCase();
  return hay.indexOf(q) !== -1;
}

// groupPrevious buckets finished sessions by repository, then branch, so the
// sidebar can render them under "<owner/name>" › "<branch>" headers. Repos are
// sorted alphabetically with the no-remote bucket last; branches alphabetically;
// sessions newest-first (ids carry a UTC timestamp prefix).
function groupPrevious(sessions) {
  var byRepo = {};
  sessions.forEach(function (s) {
    var rk = groupKey(s.repository);
    if (!byRepo[rk]) byRepo[rk] = { key: rk, repo: s.repository || "", label: repoLabel(s.repository), branches: {} };
    var bk = s.branch || "";
    if (!byRepo[rk].branches[bk]) byRepo[rk].branches[bk] = { branch: bk, label: branchLabel(bk), sessions: [] };
    byRepo[rk].branches[bk].sessions.push(s);
  });
  return Object.keys(byRepo).map(function (rk) {
    var g = byRepo[rk];
    var branches = Object.keys(g.branches).map(function (bk) { return g.branches[bk]; });
    branches.sort(function (a, b) { return a.label.localeCompare(b.label); });
    branches.forEach(function (b) {
      b.sessions.sort(function (x, y) { return x.session_id < y.session_id ? 1 : -1; });
    });
    var count = branches.reduce(function (n, b) { return n + b.sessions.length; }, 0);
    return { key: g.key, repo: g.repo, label: g.label, branches: branches, count: count };
  }).sort(function (a, b) {
    if (!a.repo !== !b.repo) return a.repo ? -1 : 1; // no-remote bucket last
    return a.label.localeCompare(b.label);
  });
}

function sessionCardHtml(s, selected, opts) {
  opts = opts || {};
  var stateChip = chipHtml(s.state, sessionStateColorVar(s.state));
  var pulse = s.state === "running" ? ' <span class="pulse-dot" title="running"></span>' : "";
  var statusChip = s.proof && s.proof.status ? chipHtml(s.proof.status, proofStatusColorVar(s.proof.status)) : "";
  var verdictChip = s.proof && s.proof.verdict ? chipHtml(s.proof.verdict, verdictColorVar(s.proof.verdict)) : "";
  var metaLine = [s.harness || "", s.profile || ""].filter(Boolean).join(" · ");
  // Running cards surface repo/branch inline (they aren't grouped under a repo
  // header the way finished sessions are).
  var repoLine = "";
  if (opts.showRepo) {
    var rb = [repoLabel(s.repository), s.branch ? branchLabel(s.branch) : ""].filter(Boolean).join(" · ");
    repoLine = '<div class="row-repo">' + esc(rb) + "</div>";
  } else if (opts.showBranch) {
    // Branch only: previous-session cards already sit under a repo › branch
    // header pair, but a card is read on its own (and copied, and linked), so
    // it names its own branch. branchLabel supplies "(detached)" for a session
    // recorded off any branch, so this line is never blank.
    repoLine = '<div class="row-branch">⎇ ' + esc(branchLabel(s.branch)) + "</div>";
  }
  var check = opts.selectable
    ? '<input type="checkbox" class="session-check" data-select-id="' + esc(s.session_id) + '"' + (opts.checked ? " checked" : "") + ' aria-label="select session">'
    : "";
  var card =
    '<button type="button" class="session-card' + (selected ? " selected" : "") + '" data-session-id="' + esc(s.session_id) + '">' +
      '<div class="row1"><span>' + esc(s.session_id) + "</span>" + stateChip + pulse + "</div>" +
      repoLine +
      '<div class="row2">' + esc(metaLine || "—") + " · " + numFmt(s.event_count) + " events · seq " + numFmt(s.last_event_seq || 0) +
        (s.last_event_ts ? " · " + esc(relTime(s.last_event_ts)) : "") + "</div>" +
      '<div class="row3">' + statusChip + verdictChip + "</div>" +
    "</button>";
  if (!opts.selectable) return card;
  return '<div class="session-row' + (opts.checked ? " checked" : "") + '">' + check + card + "</div>";
}

function renderSidebarList(dash) {
  var q = dash.filterText;
  var visible = dash.sessions.filter(function (s) { return sessionMatchesFilter(s, q); });
  dash.els.counts.textContent = numFmt(dash.sessions.length) + " total" + (q ? " · " + numFmt(visible.length) + " shown" : "") +
    (dash.lastUpdatedAt ? " · updated " + fmtClockShort(dash.lastUpdatedAt) : "");

  renderDeleteBar(dash);

  if (!dash.sessions.length) {
    dash.els.list.innerHTML = '<div class="empty" style="padding:1rem;">No sessions recorded.</div>';
    return;
  }

  var running = visible.filter(function (s) { return s.state === "running"; })
    .sort(function (x, y) { return x.session_id < y.session_id ? 1 : -1; });
  var previous = visible.filter(function (s) { return s.state !== "running"; });

  var html = "";
  if (running.length) {
    html += '<div class="group-hdr running-hdr"><span class="group-name">Running</span>' +
      '<span class="group-count">' + numFmt(running.length) + "</span></div>";
    html += running.map(function (s) {
      return sessionCardHtml(s, s.session_id === dash.selectedId, { showRepo: true });
    }).join("");
  }

  var groups = groupPrevious(previous);
  if (groups.length) {
    html += '<div class="group-hdr section-hdr"><span class="group-name">Previous</span>' +
      '<span class="group-count">' + numFmt(previous.length) + "</span></div>";
    groups.forEach(function (g) {
      var collapsed = dash.collapsed[g.key];
      var groupIds = [];
      g.branches.forEach(function (b) { b.sessions.forEach(function (s) { groupIds.push(s.session_id); }); });
      var allSelected = dash.selectMode && groupIds.length > 0 && groupIds.every(function (id) { return dash.selected[id]; });
      var groupCheck = dash.selectMode
        ? '<input type="checkbox" class="group-check" data-group-key="' + esc(g.key) + '"' + (allSelected ? " checked" : "") + ' aria-label="select all in repo">'
        : "";
      html += '<div class="group-hdr repo-hdr" data-collapse-key="' + esc(g.key) + '">' + groupCheck +
        '<span class="caret">' + (collapsed ? "▸" : "▾") + "</span>" +
        '<span class="group-name" title="' + esc(g.repo || g.label) + '">' + esc(g.label) + "</span>" +
        '<span class="group-count">' + numFmt(g.count) + "</span></div>";
      if (collapsed) return;
      g.branches.forEach(function (b) {
        html += '<div class="branch-hdr"><span class="branch-name">' + esc(b.label) + "</span>" +
          '<span class="group-count">' + numFmt(b.sessions.length) + "</span></div>";
        html += b.sessions.map(function (s) {
          return sessionCardHtml(s, s.session_id === dash.selectedId, {
            selectable: dash.selectMode,
            checked: !!dash.selected[s.session_id],
            showBranch: true,
          });
        }).join("");
      });
    });
  }

  dash.els.list.innerHTML = html || '<div class="empty" style="padding:1rem;">no sessions match filter</div>';
}

// selectedCount / renderDeleteBar drive the bulk-delete action bar shown while
// select mode is on: it reflects how many finished sessions are checked and
// gates the destructive button.
function selectedCount(dash) {
  return Object.keys(dash.selected).filter(function (id) { return dash.selected[id]; }).length;
}

function renderDeleteBar(dash) {
  var bar = dash.els.deleteBar;
  if (!bar) return;
  if (!dash.selectMode) {
    bar.hidden = true;
    return;
  }
  bar.hidden = false;
  var n = selectedCount(dash);
  dash.els.deleteBtn.disabled = n === 0 || dash.deleting;
  dash.els.deleteBtn.textContent = dash.deleting ? "Deleting…" : "Delete" + (n ? " (" + n + ")" : "");
}

function ensureDashboardView(dash) {
  if (dash.view) return;
  dash.els.main.innerHTML = "";
  dash.view = createSessionView(dash.els.main, {
    mode: "embedded",
    onManualRefresh: function () {
      if (!dash.selectedId) return;
      if (dash.view.isLive()) dash.owner.restart();
      else fetchDashboardSession(dash, dash.selectedId);
    },
    onLiveToggle: function (on) {
      dash.detailLive = on;
      if (on) dash.detailComplete = false;
      dash.owner.ensure(dashboardStreamURL(dash.selectedId, dash.detailLive));
      updateDashboardConnectionState(dash, dash.streamState);
    },
  });
}

function fetchDashboardSession(dash, id) {
  fetch("/api/session?id=" + encodeURIComponent(id)).then(function (r) { return r.json(); }).then(function (data) {
    if (dash.selectedId !== id) return; // user selected something else before this resolved
    var snapshot = reduceSessionSnapshot(data, id);
    if (snapshot.kind !== "applied") {
      if (dash.view) dash.view.setConnectionState("stale");
      return;
    }
    ensureDashboardView(dash);
    dash.view.setPayload(snapshot.payload);
    if (terminalSessionState(snapshot.payload.state)) {
      dash.detailComplete = true;
      dash.view.setConnectionState("complete");
    }
  }).catch(function () {
    if (dash.view) dash.view.setConnectionState("stale");
  });
}

function selectDashboardSession(dash, id) {
  if (dash.selectedId === id) return;
  dash.selectedId = id;
  dash.detailLive = !!id;
  dash.detailComplete = false;
  writeHashObjectMerged({ sess: id || undefined });
  renderSidebarList(dash);
  dash.owner.open(dashboardStreamURL(id, dash.detailLive));
}

function updateDashboardConnectionState(dash, state) {
  dash.streamState = state;
  if (!dash.view) return;
  if (dash.detailComplete) dash.view.setConnectionState("complete");
  else dash.view.setConnectionState(dash.detailLive ? state : "paused");
}

function resetDashboardStream(dash) {
  updateDashboardConnectionState(dash, "stale");
  dash.owner.restart();
}

function clearDashboardSelection(dash) {
  dash.selectedId = "";
  dash.detailLive = false;
  dash.detailComplete = false;
  writeHashObjectMerged({ sess: undefined });
  if (dash.view) dash.view.destroy();
  dash.view = null;
  dash.els.main.innerHTML = '<div class="empty">Select a session.</div>';
  dash.owner.ensure("/api/stream");
}

function applyDashboardRemoval(dash, removal) {
  var reduced = reduceSessionsRemove(dash.sessions, removal);
  if (!reduced) return false;
  dash.sessions = reduced.sessions;
  delete dash.selected[reduced.removedId];
  if (dash.selectedId === reduced.removedId) clearDashboardSelection(dash);
  dash.lastUpdatedAt = new Date().toISOString();
  renderSidebarList(dash);
  return true;
}

function handleDashboardStreamEvent(dash, type, payload) {
  if (type === "sessions.snapshot") {
    var sessions = reduceSessionsSnapshot(payload);
    if (!sessions) { resetDashboardStream(dash); return; }
    dash.sessions = sessions;
    dash.lastUpdatedAt = new Date().toISOString();
    if (dash.selectedId && !sessions.some(function (session) { return session.session_id === dash.selectedId; })) {
      clearDashboardSelection(dash);
      renderSidebarList(dash);
      return;
    }
    if (!dash.selectedId && sessions.length) {
      selectDashboardSession(dash, sessions[0].session_id);
      return;
    }
    renderSidebarList(dash);
    return;
  }
  if (type === "sessions.upsert") {
    var upserted = reduceSessionsUpsert(dash.sessions, payload);
    if (!upserted) { resetDashboardStream(dash); return; }
    dash.sessions = upserted;
    dash.lastUpdatedAt = new Date().toISOString();
    if (!dash.selectedId) {
      selectDashboardSession(dash, upserted[0].session_id);
      return;
    }
    renderSidebarList(dash);
    return;
  }
  if (type === "sessions.remove") {
    if (!applyDashboardRemoval(dash, payload)) resetDashboardStream(dash);
    return;
  }
  if (type === "session.snapshot") {
    if (!dash.selectedId || !dash.detailLive) return;
    var snapshot = reduceSessionSnapshot(payload, dash.selectedId);
    if (snapshot.kind !== "applied") { resetDashboardStream(dash); return; }
    ensureDashboardView(dash);
    dash.view.setPayload(snapshot.payload);
    if (terminalSessionState(snapshot.payload.state)) {
      dash.detailComplete = true;
      dash.view.setLive(false);
      dash.owner.ensure("/api/stream");
      dash.view.setConnectionState("complete");
    }
    return;
  }
  if (type !== "session.delta" || !dash.selectedId || !dash.detailLive || !dash.view) return;
  var delta = reduceSessionDelta(dash.view.getPayload(), payload);
  if (delta.kind !== "applied") { resetDashboardStream(dash); return; }
  dash.view.setPayload(delta.payload);
}

function mountDashboard(appEl) {
  appEl.innerHTML =
    '<div class="dash-layout">' +
      '<aside class="dash-sidebar">' +
        '<div class="dash-sidebar-hdr">' +
          '<div class="hdr-top"><h1>sessions</h1>' +
            '<button type="button" class="btn small" data-role="select-toggle">Select</button></div>' +
          '<div class="counts" data-role="counts"></div>' +
          '<input type="search" placeholder="filter sessions…" data-role="filter">' +
          '<div class="delete-bar" data-role="delete-bar" hidden>' +
            '<button type="button" class="btn small danger" data-role="delete-btn" disabled>Delete</button>' +
            '<button type="button" class="btn small link" data-role="cancel-btn">Cancel</button>' +
          "</div>" +
        "</div>" +
        '<div class="session-list" data-role="list"></div>' +
      "</aside>" +
      '<main class="dash-main" data-role="main"><div class="empty">Select a session.</div></main>' +
    "</div>";

  var dash = {
    sessions: [],
    filterText: "",
    selectedId: readHashObject().sess || "",
    detailLive: false,
    detailComplete: false,
    lastUpdatedAt: null,
    streamState: "connecting",
    owner: null,
    view: null,
    selectMode: false,
    selected: {},   // id -> true for bulk-delete selection
    collapsed: {},  // repo groupKey -> true when collapsed
    deleting: false,
    els: {
      counts: appEl.querySelector('[data-role="counts"]'),
      filter: appEl.querySelector('[data-role="filter"]'),
      list: appEl.querySelector('[data-role="list"]'),
      main: appEl.querySelector('[data-role="main"]'),
      selectToggle: appEl.querySelector('[data-role="select-toggle"]'),
      deleteBar: appEl.querySelector('[data-role="delete-bar"]'),
      deleteBtn: appEl.querySelector('[data-role="delete-btn"]'),
      cancelBtn: appEl.querySelector('[data-role="cancel-btn"]'),
    },
  };
  dash.detailLive = !!dash.selectedId;
  dash.owner = createEventSourceOwner({
    eventTypes: STREAM_EVENT_TYPES,
    onState: function (state) { updateDashboardConnectionState(dash, state); },
    onMalformed: function () { resetDashboardStream(dash); },
    onEvent: function (type, payload) { handleDashboardStreamEvent(dash, type, payload); },
  });

  dash.els.filter.addEventListener("input", debounce(function (e) {
    dash.filterText = e.target.value.trim().toLowerCase();
    renderSidebarList(dash);
  }, SEARCH_DEBOUNCE_MS));

  dash.els.selectToggle.addEventListener("click", function () {
    setSelectMode(dash, !dash.selectMode);
  });
  dash.els.cancelBtn.addEventListener("click", function () { setSelectMode(dash, false); });
  dash.els.deleteBtn.addEventListener("click", function () { deleteSelectedSessions(dash); });

  dash.els.list.addEventListener("click", function (e) {
    var chk = e.target.closest(".session-check");
    if (chk) { dash.selected[chk.dataset.selectId] = chk.checked; renderSidebarList(dash); return; }
    var gchk = e.target.closest(".group-check");
    if (gchk) { toggleGroupSelect(dash, gchk.dataset.groupKey, gchk.checked); return; }
    var collapseHdr = e.target.closest("[data-collapse-key]");
    if (collapseHdr) {
      var k = collapseHdr.dataset.collapseKey;
      dash.collapsed[k] = !dash.collapsed[k];
      renderSidebarList(dash);
      return;
    }
    var card = e.target.closest("[data-session-id]");
    if (card) selectDashboardSession(dash, card.dataset.sessionId);
  });

  dash.owner.open(dashboardStreamURL(dash.selectedId, dash.detailLive));
  window.addEventListener("beforeunload", function () { dash.owner.close(); }, { once: true });
}

function setSelectMode(dash, on) {
  dash.selectMode = on;
  if (!on) dash.selected = {};
  dash.els.selectToggle.textContent = on ? "Done" : "Select";
  dash.els.selectToggle.classList.toggle("active", on);
  renderSidebarList(dash);
}

// toggleGroupSelect checks or clears every finished session under one repo group
// at once, respecting the active text filter so it only touches visible rows.
function toggleGroupSelect(dash, key, checked) {
  var q = dash.filterText;
  dash.sessions.forEach(function (s) {
    if (s.state === "running") return;
    if (groupKey(s.repository) !== key) return;
    if (!sessionMatchesFilter(s, q)) return;
    dash.selected[s.session_id] = checked;
  });
  renderSidebarList(dash);
}

// deleteSelectedSessions posts the checked ids to the bulk-delete endpoint,
// which removes each session's entire on-disk directory. On return it clears
// selection and immediately applies the same removal reducer as the stream, so
// the list does not wait for the matching filesystem notification.
function deleteSelectedSessions(dash) {
  var ids = Object.keys(dash.selected).filter(function (id) { return dash.selected[id]; });
  if (!ids.length || dash.deleting) return;
  if (!window.confirm("Delete " + ids.length + " session" + (ids.length === 1 ? "" : "s") +
    " and all of their evidence files? This cannot be undone.")) return;
  dash.deleting = true;
  renderDeleteBar(dash);
  fetch("/api/sessions/delete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ids: ids }),
  }).then(function (r) { return r.json(); }).then(function (resp) {
    var deleted = (resp && resp.deleted) || [];
    var errors = (resp && resp.errors) || {};
    deleted.forEach(function (id) {
      applyDashboardRemoval(dash, { session_id: id });
    });
    var failed = Object.keys(errors);
    if (failed.length) window.alert("Could not delete " + failed.length + " session(s):\n" +
      failed.map(function (id) { return id + ": " + errors[id]; }).join("\n"));
  }).catch(function () {
    window.alert("Delete request failed.");
  }).then(function () {
    dash.deleting = false;
    if (!selectedCount(dash)) setSelectMode(dash, false);
    else renderDeleteBar(dash);
  });
}

// ---- boot ----

document.addEventListener("DOMContentLoaded", function () {
  var page = document.body.dataset.page;
  var app = document.getElementById("app");
  if (!app) return;
  if (page === "dashboard") {
    mountDashboard(app);
  } else {
    mountStandalone(app);
  }
});
