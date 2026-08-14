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
var NETWORK_DOMAIN = new Set(["network.connected", "network.denied"]);
var ACTIONS_DOMAIN = new Set([
  "authorization.decided", "tool.requested", "tool.completed",
  "internal_tool.dispatched", "internal_tool.completed", "internal_tool.failed",
  "effect.requested", "effect.approved", "effect.denied", "effect.dispatched", "effect.completed", "effect.failed",
  "credential.issued", "credential.revoked",
  "model.requested", "model.completed",
]);

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

var HASH_DEBOUNCE_MS = 200;
var SEARCH_DEBOUNCE_MS = 150;
var POLL_MS = 3000;
var DASH_POLL_MS = 2500;
var CHUNK_SIZE = 1000;
var CHUNK_ALL_THRESHOLD = 5000;

// ---- state ----

// defaultState is the single state object described in the spec: filters,
// tab, sort, per-tab toggles, expanded rows and (dashboard-only) the
// selected session id. A fresh object is created per SessionView instance.
function defaultState() {
  return {
    tab: "timeline",
    sort: "asc", // "asc" (oldest first, default) | "desc"
    search: "",
    classes: [], // selected badge strings; [] = unconstrained
    names: [], // selected event names; [] = unconstrained
    outcomes: [], // selected outcome strings; [] = unconstrained
    producers: [], // selected producer strings; [] = unconstrained
    pid: "",
    hideNoise: true, // "Hide process noise" preset, default ON
    agentActivity: false, // "Agent activity" preset, opt-in; implies hideNoise (see computeTimelineFilter)
    errorsOnly: false,
    filesMode: "latest", // "all" | "latest"
    actionsMode: "chain", // "flat" | "chain"
    expandedSeqs: new Set(),
    expandedActionGroups: new Set(), // Actions-tab chain groups expanded (in-memory only, not URL-persisted)
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
  state.agentActivity = false;
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

// buildModel precomputes, once per payload load, everything the filter
// engine and renderers need per event so no render pass re-derives them:
// a lowercased search corpus, the non-bookkeeping "k=v" summary tail, and a
// formatted clock label. All are parallel arrays indexed like payload.events.
function buildModel(events) {
  var n = events.length;
  var corpus = new Array(n);
  var kv = new Array(n);
  var tsLabel = new Array(n);
  var bySeq = new Map();
  for (var i = 0; i < n; i++) {
    var ev = events[i];
    var kvStr = summarizeAttrs(ev.attrs);
    kv[i] = kvStr;
    corpus[i] = corpusOf(ev, kvStr);
    tsLabel[i] = fmtClock(ev.ts);
    bySeq.set(ev.seq, i);
  }
  return { events: events, corpus: corpus, kv: kv, tsLabel: tsLabel, bySeq: bySeq };
}

// extendModel appends derived fields for newly-arrived tail events onto an
// existing model in place (the live-refresh append-only path), avoiding a
// full O(n) recompute of unchanged rows.
function extendModel(model, events) {
  for (var i = model.events.length; i < events.length; i++) {
    var ev = events[i];
    var kvStr = summarizeAttrs(ev.attrs);
    model.kv.push(kvStr);
    model.corpus.push(corpusOf(ev, kvStr));
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
  var processes = 0, files = 0, network = 0, actions = 0;
  for (var i = 0; i < events.length; i++) {
    var name = events[i].name;
    if (name.indexOf("process.") === 0) processes++;
    if (FILES_DOMAIN.has(name)) files++;
    if (NETWORK_DOMAIN.has(name)) network++;
    if (ACTIONS_DOMAIN.has(name)) actions++;
  }
  return {
    timeline: events.length,
    processes: processes,
    files: files,
    network: network,
    actions: actions,
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

function timelineRowHtml(ctx, i) {
  var model = ctx.model, ev = model.events[i];
  var expanded = ctx.state.expandedSeqs.has(ev.seq);
  var outcome = ev.outcome || "";
  var kvStr = model.kv[i];
  var summary = esc(ev.body || "") + (kvStr ? ' <span class="kv">' + esc(kvStr) + "</span>" : "");
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
    var deleted = ev.name === "file.deleted";
    var kindChip = deleted ? ktextHtml("deleted", statusColor("crit")) : ktextHtml("changed", statusColor("good"));
    var digest = attrRaw(ev, "audit.content.digest");
    return "<tr>" +
      '<td class="ellipsis">' + esc(path) + "</td>" +
      "<td>" + kindChip + "</td>" +
      '<td class="mono-num">' + entry.count + "</td>" +
      "<td>" + digestCellHtml(digest) + "</td>" +
      '<td class="mono-num">' + ev.seq + "</td>" +
      "<td>" + esc(model.tsLabel[entry.lastIdx]) + "</td>" +
    "</tr>";
  }).join("");
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
  var kvStr = model.kv[i];
  var summary = esc(ev.body || "") + (kvStr ? ' <span class="kv">' + esc(kvStr) + "</span>" : "");
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
    '<span class="meta">' + numFmt(domainFiltered.indices.length) + " events</span>";
  ctx.els.actionsTableWrap.innerHTML = ctx.state.actionsMode === "chain" ?
    actionsChainHtml(ctx, domainFiltered.indices) : actionsFlatHtml(ctx, domainFiltered.indices);
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
  ctx.els.tabs.proof.innerHTML = '<div data-role="body"></div>';
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
    chipHtml(proof.verdict || "NO VERDICT", proof.verdict ? verdictColorVar(proof.verdict) : statusColor("muted")) +
    statusChip +
    '<span class="meta mono-num">' + numFmt(events.length) + " events</span>" +
    '<span class="meta mono-num">last ' + (lastEv ? esc(fmtClockShort(lastEv.ts)) : "—") + "</span>" +
    '<button type="button" class="copy-btn" data-act="copy-value" data-value="' + esc(payload.policy_digest || "") +
      '" title="click to copy full digest">' + esc(truncateDigest(payload.policy_digest || "") || "(no digest)") + "</button>" +
    '<span class="spacer"></span>' +
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
    case "processes": updateProcessesTab(ctx); break;
    case "files": updateFilesTab(ctx); break;
    case "network": updateNetworkTab(ctx); break;
    case "actions": updateActionsTab(ctx); break;
    case "proof": updateProofTab(ctx); break;
  }
}

// activeScrollEl finds the scrollable table area of whichever tab is
// currently visible, so callers can save/restore scrollTop around a
// rebuild (spec: re-renders must preserve scroll position).
function activeScrollEl(ctx) {
  var container = ctx.els.tabs[ctx.state.tab];
  return container ? container.querySelector(".table-wrap") : null;
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
  mountProcessesTab(ctx);
  mountFilesTab(ctx);
  mountNetworkTab(ctx);
  mountActionsTab(ctx);
  mountProofTab(ctx);
}

// ---- session view orchestrator ----

// createSessionView mounts the one shared component both pages use. In
// "standalone" mode it owns its own 3s /api/events poll loop gated by the
// Live toggle; in "embedded" mode (the dashboard) it never polls itself —
// the host calls setPayload() on its own schedule and the toggle just
// notifies the host via opts.onLiveToggle/onManualRefresh, since the
// dashboard's own sidebar poll already decides when a refetch is worthwhile
// (see the dashboard section's refetch policy).
function createSessionView(rootEl, opts) {
  opts = opts || {};
  var ctx = {
    state: defaultState(),
    payload: null,
    model: null,
    agentActivityNames: new Set(), // repopulated per payload in setSessionViewPayload from payload.agent_activity_names
    root: rootEl,
    els: {},
    mode: opts.mode || "standalone",
    fetchUrl: opts.fetchUrl,
    liveTimer: null,
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
  ctx.manualRefresh = function () {
    if (ctx.mode === "standalone") fetchStandalone(ctx);
    else if (opts.onManualRefresh) opts.onManualRefresh();
  };
  ctx.onLiveToggle = function () {
    if (ctx.mode === "standalone") {
      if (ctx.state.liveOn) startPolling(ctx); else stopPolling(ctx);
    } else if (opts.onLiveToggle) {
      opts.onLiveToggle(ctx.state.liveOn);
    }
  };

  mountShell(ctx);
  if (ctx.mode === "standalone") fetchStandalone(ctx);

  return {
    setPayload: function (payload) { setSessionViewPayload(ctx, payload); },
    focusPid: ctx.focusPid,
    destroy: function () { stopPolling(ctx); },
  };
}

function fetchStandalone(ctx) {
  fetch(ctx.fetchUrl).then(function (r) { return r.json(); }).then(function (data) {
    setSessionViewPayload(ctx, data);
  }).catch(function () {
    // Network hiccup: keep showing the last good payload and try again on
    // the next tick (or manual click) rather than clearing the view.
  });
}
function startPolling(ctx) {
  stopPolling(ctx);
  ctx.liveTimer = setInterval(function () { fetchStandalone(ctx); }, POLL_MS);
}
function stopPolling(ctx) {
  if (ctx.liveTimer) { clearInterval(ctx.liveTimer); ctx.liveTimer = null; }
}

// setSessionViewPayload is the single entry point every new payload (first
// load, standalone poll tick, or a dashboard-driven refetch) flows through.
// It implements the spec's change-detection/append-only/full-rerender
// decision and preserves active tab, filters, expanded rows, sort, mode
// toggles and scroll position across whichever path it takes.
function setSessionViewPayload(ctx, payload) {
  var isNewSession = !ctx.payload || ctx.payload.session_id !== payload.session_id;
  var newEvents = payload.events || [];
  var newSummary = {
    len: newEvents.length,
    lastSeq: newEvents.length ? newEvents[newEvents.length - 1].seq : 0,
    status: payload.proof && payload.proof.status,
    verifyError: payload.verify_error || "",
  };

  if (!isNewSession && ctx.prevSummary &&
      ctx.prevSummary.len === newSummary.len &&
      ctx.prevSummary.lastSeq === newSummary.lastSeq &&
      ctx.prevSummary.status === newSummary.status &&
      ctx.prevSummary.verifyError === newSummary.verifyError) {
    ctx.lastUpdatedAt = new Date().toISOString();
    renderHeader(ctx); // keep the "updated HH:MM:SS" clock live even on a no-op poll
    return;
  }

  var appendMode = null;
  if (isNewSession || !ctx.model) {
    ctx.model = buildModel(newEvents);
    ctx.state.expandedSeqs = new Set(); // seqs from a different session are meaningless here
    ctx.state.expandedActionGroups = new Set();
    ctx.tlRenderedCount = 0;
    resetTimelineChunk(ctx.state);
    if (isNewSession && payload.proof) {
      // Re-derive the Live default per session (spec: ON iff provisional);
      // a manual choice made on the SAME session is never overridden. Only
      // standalone mode acts on it immediately (starts/stops its own poll
      // timer) — in embedded/dashboard mode this is just the checkbox's
      // initial state; the dashboard's own poll cadence is unaffected by it
      // (see the dashboard section's refetch policy).
      ctx.state.liveOn = !!payload.proof.provisional;
      if (ctx.mode === "standalone") ctx.onLiveToggle();
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

// ---- dashboard ----
//
// The dashboard is a ~300px session-list sidebar plus one embedded
// SessionView in the main pane. It owns the /api/sessions poll loop and
// decides, per the spec's refetch policy, when the selected session's
// detail actually needs refetching — the embedded SessionView's own
// change-detection then decides how much of the DOM that refetch touches.

function summaryKey(s) {
  return s.state + ":" + s.event_count + ":" + s.last_event_seq + ":" + (s.proof && s.proof.status);
}

function sessionCardHtml(s, selected) {
  var stateChip = chipHtml(s.state, sessionStateColorVar(s.state));
  var pulse = s.state === "running" ? ' <span class="pulse-dot" title="running"></span>' : "";
  var statusChip = s.proof && s.proof.status ? chipHtml(s.proof.status, proofStatusColorVar(s.proof.status)) : "";
  var verdictChip = s.proof && s.proof.verdict ? chipHtml(s.proof.verdict, verdictColorVar(s.proof.verdict)) : "";
  var metaLine = [s.harness || "", s.profile || ""].filter(Boolean).join(" · ");
  return (
    '<button type="button" class="session-card' + (selected ? " selected" : "") + '" data-session-id="' + esc(s.session_id) + '">' +
      '<div class="row1"><span>' + esc(s.session_id) + "</span>" + stateChip + pulse + "</div>" +
      '<div class="row2">' + esc(metaLine || "—") + " · " + numFmt(s.event_count) + " events · seq " + numFmt(s.last_event_seq || 0) +
        (s.last_event_ts ? " · " + esc(relTime(s.last_event_ts)) : "") + "</div>" +
      '<div class="row3">' + statusChip + verdictChip + "</div>" +
    "</button>"
  );
}

function renderSidebarList(dash) {
  var q = dash.filterText;
  var filtered = dash.sessions.filter(function (s) {
    if (!q) return true;
    var hay = (s.session_id + " " + (s.harness || "") + " " + (s.profile || "")).toLowerCase();
    return hay.indexOf(q) !== -1;
  });
  dash.els.counts.textContent = numFmt(dash.sessions.length) + " total" + (q ? " · " + numFmt(filtered.length) + " shown" : "") +
    (dash.lastPollAt ? " · updated " + fmtClockShort(dash.lastPollAt) : "");
  if (!dash.sessions.length) {
    dash.els.list.innerHTML = '<div class="empty" style="padding:1rem;">No sessions recorded.</div>';
    return;
  }
  dash.els.list.innerHTML = filtered.map(function (s) { return sessionCardHtml(s, s.session_id === dash.selectedId); }).join("") ||
    '<div class="empty" style="padding:1rem;">no sessions match filter</div>';
}

function ensureDashboardView(dash) {
  if (dash.view) return;
  dash.els.main.innerHTML = "";
  dash.view = createSessionView(dash.els.main, {
    mode: "embedded",
    onManualRefresh: function () { if (dash.selectedId) fetchDashboardSession(dash, dash.selectedId); },
    onLiveToggle: function () { if (dash.selectedId) fetchDashboardSession(dash, dash.selectedId); },
  });
}

function fetchDashboardSession(dash, id) {
  fetch("/api/session?id=" + encodeURIComponent(id)).then(function (r) { return r.json(); }).then(function (data) {
    if (dash.selectedId !== id) return; // user selected something else before this resolved
    ensureDashboardView(dash);
    dash.view.setPayload(data);
  }).catch(function () {});
}

function selectDashboardSession(dash, id) {
  if (dash.selectedId === id) return;
  dash.selectedId = id;
  writeHashObjectMerged({ sess: id || undefined });
  renderSidebarList(dash);
  fetchDashboardSession(dash, id);
}

// pollDashboardSessions runs every 2.5s unconditionally; it refetches the
// selected session's full detail only when that session's sidebar summary
// changed since the previous tick (state/event_count/last_event_seq/proof
// .status), when nothing has been fetched for it yet (first selection), or
// when the embedded view's Live toggle asks for it directly (see
// onLiveToggle above) — not on every tick, per the spec's refetch policy.
function pollDashboardSessions(dash) {
  fetch("/api/sessions").then(function (r) { return r.json(); }).then(function (data) {
    var sessions = data.sessions || [];
    var prevSummaries = dash.summaries || {};
    var nextSummaries = {};
    sessions.forEach(function (s) { nextSummaries[s.session_id] = summaryKey(s); });
    dash.sessions = sessions;
    dash.summaries = nextSummaries;
    dash.lastPollAt = new Date().toISOString();

    if (!dash.selectedId && sessions.length) {
      selectDashboardSession(dash, sessions[0].session_id);
      return;
    }
    renderSidebarList(dash);

    var id = dash.selectedId;
    if (!id || !Object.prototype.hasOwnProperty.call(nextSummaries, id)) return;
    if (prevSummaries[id] !== nextSummaries[id] || !dash.view) {
      fetchDashboardSession(dash, id);
    }
  }).catch(function () {});
}

function mountDashboard(appEl) {
  appEl.innerHTML =
    '<div class="dash-layout">' +
      '<aside class="dash-sidebar">' +
        '<div class="dash-sidebar-hdr">' +
          "<h1>sessions</h1>" +
          '<div class="counts" data-role="counts"></div>' +
          '<input type="search" placeholder="filter sessions…" data-role="filter">' +
        "</div>" +
        '<div class="session-list" data-role="list"></div>' +
      "</aside>" +
      '<main class="dash-main" data-role="main"><div class="empty">Select a session.</div></main>' +
    "</div>";

  var dash = {
    sessions: [],
    summaries: {},
    filterText: "",
    selectedId: readHashObject().sess || "",
    lastPollAt: null,
    view: null,
    els: {
      counts: appEl.querySelector('[data-role="counts"]'),
      filter: appEl.querySelector('[data-role="filter"]'),
      list: appEl.querySelector('[data-role="list"]'),
      main: appEl.querySelector('[data-role="main"]'),
    },
  };

  dash.els.filter.addEventListener("input", debounce(function (e) {
    dash.filterText = e.target.value.trim().toLowerCase();
    renderSidebarList(dash);
  }, SEARCH_DEBOUNCE_MS));

  dash.els.list.addEventListener("click", function (e) {
    var card = e.target.closest("[data-session-id]");
    if (card) selectDashboardSession(dash, card.dataset.sessionId);
  });

  pollDashboardSessions(dash);
  setInterval(function () { pollDashboardSessions(dash); }, DASH_POLL_MS);
}

// ---- boot ----

document.addEventListener("DOMContentLoaded", function () {
  var page = document.body.dataset.page;
  var app = document.getElementById("app");
  if (!app) return;
  if (page === "dashboard") {
    mountDashboard(app);
  } else {
    createSessionView(app, { mode: "standalone", fetchUrl: "/api/events" });
  }
});
