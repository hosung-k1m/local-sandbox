// BoxedAi Processes tab (phase 2): the fork/exec process explorer. Plain
// script (see app.js's top comment — same "no modules, no build step"
// contract; DESIGN.md "Viewer": "embedded HTML pages (no build step,
// vanilla JS)"). app.js's Processes-tab hook (updateProcessesTab) calls
// window.BoxedAiProc.render(container, events, api) with the FULL ascending
// event list every time the tab is active — on tab switch and on every
// streamed detail update — and it empties `container` itself immediately before
// calling render(), so this file always rebuilds its DOM from scratch on
// every call. UI state that must survive that (selection, expanded rows,
// view mode, pan/zoom, search) therefore lives in module-level state below,
// not in the DOM, and is keyed by stable node identity so it survives a
// full rebuild. `api` is { esc, fmtTs, focusPid, statusColor, payloadVersion
// } — see internal/view/app.js's updateProcessesTab for the exact shape.
//
// Wrapped in an IIFE (unlike app.js, which predates having a second script
// on the page) so none of the many small helpers below collide with app.js's
// own same-named globals (esc, numFmt, debounce, ...); the only thing this
// file adds to the global scope is window.BoxedAiProc itself.
(function () {

// ---- wire contract: event/attr names (see guest/agent/events.go comments
// and internal/evidence for the authoritative key strings) ----
var EVENT_CREATED = "process.created";
var EVENT_EXECUTED = "process.executed";
var EVENT_EXITED = "process.exited";

var ATTR_PID = "process.pid";
var ATTR_PPID = "process.parent_pid";
var ATTR_UID = "process.uid";
var ATTR_BINARY = "process.binary";
var ATTR_ARGV = "process.argv";
var ATTR_EXEC_ID = "process.exec.id";
var ATTR_PARENT_EXEC_ID = "process.parent_exec_id";
var ATTR_CGROUP_ID = "process.cgroup.id";
var ATTR_OBSERVER = "observer";
var ATTR_EXIT_CODE = "process.exit_code";
var ATTR_EXIT_SIGNAL = "process.exit_signal";
var ATTR_EXIT_STATUS = "process.exit_status";

// ---- constants ----
var TASK_CHIP_CAP = 200; // inline task sub-list cap before "...and K more"
var GRAPH_NODE_CAP = 400; // graph render guard
var DEFAULT_EXPAND_DEPTH = 3; // tree: depth < this is expanded by default
var SEARCH_DEBOUNCE_MS = 150;
var GRAPH_NODE_W = 200;
var GRAPH_NODE_H = 34;
var GRAPH_DEPTH_DX = 220;
var GRAPH_LEAF_DY = 44;
var ZOOM_MIN = 0.25;
var ZOOM_MAX = 3;
var GRAPH_PAD = 24;
var GRAPH_TOP_PAD = 16;
var GRAPH_READABLE_MIN = 0.5; // below this the node labels stop being legible
var ZOOM_WHEEL_FACTOR = 1.1;
var DRAG_THRESHOLD_PX = 3;
var ARGV_ROW_TRUNC = 70;
var EXEC_CHAIN_ARGV_TRUNC = 60;
var BIN_LABEL_TRUNC = 18;

// ---- small pure utils ----

function hasVal(v) {
  return v !== undefined && v !== null && v !== "";
}
function readAttr(ev, key) {
  return ev && ev.attrs ? ev.attrs[key] : undefined;
}
function pidOf(ev) {
  var v = readAttr(ev, ATTR_PID);
  return hasVal(v) ? String(v) : null;
}
function ppidOf(ev) {
  var v = readAttr(ev, ATTR_PPID);
  return hasVal(v) ? String(v) : null;
}
function numFmt(n) {
  return Number(n || 0).toLocaleString("en-US");
}
function clamp(v, lo, hi) {
  return Math.max(lo, Math.min(hi, v));
}
function debounce(fn, ms) {
  var t = null;
  return function () {
    var args = arguments, ctx = this;
    clearTimeout(t);
    t = setTimeout(function () { fn.apply(ctx, args); }, ms);
  };
}
function baseName(path) {
  if (!path) return "";
  var i = path.lastIndexOf("/");
  return i === -1 ? path : path.slice(i + 1);
}
function truncateEnd(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function truncateMiddle(s, keep) {
  keep = keep || 4;
  if (!s || s.length <= keep * 2 + 1) return s || "";
  return s.slice(0, keep) + "…" + s.slice(-keep);
}
function humanizeDuration(ms) {
  if (ms === null || ms === undefined || ms < 0 || isNaN(ms)) return "";
  if (ms < 1000) return Math.round(ms) + "ms";
  var s = ms / 1000;
  if (s < 60) return (Math.round(s * 100) / 100) + "s";
  var m = Math.floor(s / 60);
  var rem = Math.round(s - m * 60);
  return m + "m" + rem + "s";
}
function nodeLifespanMs(node) {
  if (node.exitSeq === null) return null;
  var start = Date.parse(node.firstTs), end = Date.parse(node.exitTs);
  if (isNaN(start) || isNaN(end)) return null;
  return end - start;
}

// copyText mirrors app.js's copyToClipboard (same classes/timing) — not
// exposed via `api`, so duplicated here rather than reached into app.js.
function copyText(text, el) {
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

// ---- pure model builder (window.BoxedAiProc._buildModel) ----
//
// Single ascending pass over process.* events. Nodes are keyed by pid
// *incarnation* (pid + ":" + firstSeq) so pid reuse produces two distinct
// nodes rather than one node with contradictory history: `live` tracks the
// currently-open incarnation per pid string and is deleted on
// process.exited. A changed nonempty exec id also starts a fresh node even
// without an observed exit, so PID reuse cannot overwrite a live node's
// identity or redirect the eventual exit to the older incarnation.

function makeNode(pid, seq, ts) {
  return {
    pid: pid,
    ppid: null,
    uid: null,
    binary: "",
    execs: [], // {binary, argv, seq, ts}, oldest first
    execId: "",
    parentExecId: "",
    cgroupId: "",
    observer: "",
    producer: "", // audit.producer of the process evidence (last non-empty wins)
    forged: false, // any contributing event came from a channel other than guest_supervisor
    firstSeq: seq,
    firstTs: ts,
    exitSeq: null,
    exitTs: null,
    exitCode: null,
    exitSignal: null,
    exitStatus: null,
    events: [], // {seq, name, ts} raw events this node was built from
    hasExec: false,
    key: pid + ":" + seq,
    parentKey: null,
    childKeys: [],
    procChildKeys: [], // hasExec, or itself has children (rendered normally)
    taskChildKeys: [], // never exec'd AND childless — the noise, foldable
    status: "task",
  };
}

// applyCommonFields updates fields any of the three process.* events may
// carry (Tetragon's correlation ids are attached uniformly by
// guest/agent/events.go's procCorrelation to created/executed/exited
// alike), keeping "last non-empty wins" semantics per the field.
function applyCommonFields(node, ev) {
  var uid = readAttr(ev, ATTR_UID);
  if (hasVal(uid)) node.uid = uid;
  var observer = readAttr(ev, ATTR_OBSERVER);
  if (hasVal(observer)) node.observer = String(observer);
  // Trust provenance: legitimate process evidence is stamped guest_supervisor by
  // the recorder (kernel sensor, authenticated supervisor channel). A process.*
  // event on any other channel is workload-forgeable — the process tree used to
  // render it as an indistinguishable real node. Flag it (sticky) so the row can
  // badge it as not kernel-verified. See DESIGN.md channel-derived producer.
  if (hasVal(ev.producer)) {
    node.producer = String(ev.producer);
    if (ev.producer !== "guest_supervisor") node.forged = true;
  }
  var execId = readAttr(ev, ATTR_EXEC_ID);
  if (hasVal(execId)) node.execId = String(execId);
  var parentExecId = readAttr(ev, ATTR_PARENT_EXEC_ID);
  if (hasVal(parentExecId)) node.parentExecId = String(parentExecId);
  var cgroupId = readAttr(ev, ATTR_CGROUP_ID);
  if (hasVal(cgroupId)) node.cgroupId = String(cgroupId);
}

function applyCreated(node, ev) {
  applyCommonFields(node, ev);
  var ppid = ppidOf(ev);
  // Prefer an exec event's parent_pid (spec); a created event only sets
  // ppid while no exec has claimed it yet (guards a created event that
  // arrives, out of the ordinary order, after this incarnation already
  // exec'd).
  if (ppid !== null && !node.hasExec) node.ppid = ppid;
}

function applyExecuted(node, ev) {
  applyCommonFields(node, ev);
  var ppid = ppidOf(ev);
  if (ppid !== null) node.ppid = ppid;
  var binary = readAttr(ev, ATTR_BINARY);
  var argv = readAttr(ev, ATTR_ARGV);
  node.execs.push({
    binary: hasVal(binary) ? String(binary) : "",
    argv: hasVal(argv) ? String(argv) : "",
    seq: ev.seq,
    ts: ev.ts,
  });
  if (hasVal(binary)) node.binary = String(binary); // later execs re-exec the image; show the last
  node.hasExec = true;
}

function applyExited(node, ev) {
  applyCommonFields(node, ev);
  node.exitSeq = ev.seq;
  node.exitTs = ev.ts;
  var status = readAttr(ev, ATTR_EXIT_STATUS);
  node.exitStatus = hasVal(status) ? String(status) : null;
  var code = readAttr(ev, ATTR_EXIT_CODE);
  node.exitCode = hasVal(code) ? Number(code) : null;
  var sig = readAttr(ev, ATTR_EXIT_SIGNAL);
  node.exitSignal = hasVal(sig) ? String(sig) : null;
}

// linkParents resolves each node's parentKey: prefer process.parent_exec_id
// -> the node with that process.exec.id (stronger than pid math — kernel-
// observed lineage rather than a heuristic); otherwise fall back to the
// ppid's incarnation whose lifetime window [firstSeq, exitSeq-or-Infinity]
// contains this node's firstSeq, or (if none contains it) the latest
// same-pid incarnation created at or before this node.
function linkParents(nodes, byKey) {
  var byPid = new Map();
  nodes.forEach(function (n) {
    if (!byPid.has(n.pid)) byPid.set(n.pid, []);
    byPid.get(n.pid).push(n);
  });
  byPid.forEach(function (arr) { arr.sort(function (a, b) { return a.firstSeq - b.firstSeq; }); });

  var byExecId = new Map();
  nodes.forEach(function (n) { if (n.execId) byExecId.set(n.execId, n); });

  nodes.forEach(function (child) {
    var parent = null;
    if (child.parentExecId && byExecId.has(child.parentExecId)) {
      var candidate = byExecId.get(child.parentExecId);
      if (candidate !== child) parent = candidate;
    }
    if (!parent && child.ppid !== null) {
      var candidates = byPid.get(child.ppid) || [];
      for (var i = 0; i < candidates.length; i++) {
        var c = candidates[i];
        if (c === child) continue;
        var end = c.exitSeq === null ? Infinity : c.exitSeq;
        if (c.firstSeq <= child.firstSeq && child.firstSeq <= end) { parent = c; break; }
      }
      if (!parent) {
        for (var j = candidates.length - 1; j >= 0; j--) {
          if (candidates[j] !== child && candidates[j].firstSeq <= child.firstSeq) { parent = candidates[j]; break; }
        }
      }
    }
    child.parentKey = parent ? parent.key : null;
  });
}

// attachChildren builds childKeys/roots (sorted by firstSeq) then splits
// each node's children into procChildKeys (rendered normally) and
// taskChildKeys (never exec'd AND childless — pure noise, foldable); a task
// that itself later has children is never foldable, per spec.
function attachChildren(nodes, byKey) {
  var roots = [];
  nodes.forEach(function (n) {
    if (n.parentKey && byKey.has(n.parentKey)) {
      byKey.get(n.parentKey).childKeys.push(n.key);
    } else {
      roots.push(n.key);
    }
  });
  function byFirstSeq(aKey, bKey) { return byKey.get(aKey).firstSeq - byKey.get(bKey).firstSeq; }
  nodes.forEach(function (n) { n.childKeys.sort(byFirstSeq); });
  roots.sort(byFirstSeq);
  nodes.forEach(function (n) {
    n.childKeys.forEach(function (k) {
      var c = byKey.get(k);
      var isPureTask = !c.hasExec && c.childKeys.length === 0;
      if (isPureTask) n.taskChildKeys.push(k); else n.procChildKeys.push(k);
    });
  });
  return roots;
}

// computeStatus: hasExec is the primary gate (task vs. process); only
// exec'd nodes get running/ok/failed/signaled, so the thousands of
// thread-clone exits that never exec don't reintroduce noise as spurious
// "failed"/"signaled" chips — they stay "task" regardless of their own
// exit event, which the task mini-row still shows verbatim if present.
function computeStatus(node) {
  if (!node.hasExec) return "task";
  if (node.exitSeq === null) return "running";
  if (node.exitSignal) return "signaled";
  if (node.exitCode === 0) return "ok";
  if (node.exitCode !== null) return "failed";
  // exit_status "unknown" (procfs fallback gap: exited but neither code nor
  // signal recorded). Bucketed as failed since a clean exit can't be
  // confirmed; the literal exitStatus is still shown verbatim in the detail
  // panel, nothing is hidden.
  return "failed";
}

function computeStats(nodes) {
  var stats = { processes: 0, tasks: 0, running: 0, failed: 0, total: nodes.length };
  nodes.forEach(function (n) {
    if (n.status === "task") { stats.tasks++; return; }
    stats.processes++;
    if (n.status === "running") stats.running++;
    else if (n.status === "failed" || n.status === "signaled") stats.failed++;
  });
  return stats;
}

function buildModel(events) {
  var live = new Map(); // pid string -> currently-open node
  var nodes = [];

  for (var i = 0; i < events.length; i++) {
    var ev = events[i];
    if (!ev || typeof ev.name !== "string" || ev.name.indexOf("process.") !== 0) continue;
    var pid = pidOf(ev);
    if (pid === null) continue;

    if (ev.name === EVENT_EXITED) {
      var exitNode = live.get(pid);
      if (!exitNode) {
        // No live node: the exit arrived with nothing prior seen (dropped
        // created/executed, or a process that predates this session's
        // window) — stub a node so the event is never dropped.
        exitNode = makeNode(pid, ev.seq, ev.ts);
        nodes.push(exitNode);
      }
      applyExited(exitNode, ev);
      exitNode.events.push({ seq: ev.seq, name: ev.name, ts: ev.ts });
      live.delete(pid); // retire: a later created/executed for this pid starts fresh (pid reuse)
      continue;
    }

    var node = live.get(pid);
    if (node && ev.name === EVENT_EXECUTED) {
      var nextExecId = readAttr(ev, ATTR_EXEC_ID);
      if (hasVal(nextExecId) && node.execId && String(nextExecId) !== node.execId) {
        node = null;
        live.delete(pid);
      }
    }
    if (!node) {
      node = makeNode(pid, ev.seq, ev.ts);
      nodes.push(node);
      live.set(pid, node);
    }
    if (ev.name === EVENT_EXECUTED) applyExecuted(node, ev);
    else if (ev.name === EVENT_CREATED) applyCreated(node, ev);
    else applyCommonFields(node, ev); // forward-compatible: unknown process.* event name
    node.events.push({ seq: ev.seq, name: ev.name, ts: ev.ts });
  }

  var byKey = new Map();
  nodes.forEach(function (n) { byKey.set(n.key, n); });

  linkParents(nodes, byKey);
  var roots = attachChildren(nodes, byKey);
  nodes.forEach(function (n) { n.status = computeStatus(n); });
  var stats = computeStats(nodes);

  return { nodes: nodes, byKey: byKey, roots: roots, stats: stats };
}

// ---- module state ----
//
// The container app.js hands render() is emptied by the CALLER before every
// call (see updateProcessesTab), so nothing here can live in the DOM across
// calls. All of it is keyed by stable node identity (node.key = pid +
// firstSeq) so it survives a full rebuild, including a rebuild triggered by
// a brand-new payload.

var uiState = {
  view: "tree", // "tree" | "graph"
  search: "",
  showTasks: false,
  selectedKey: null,
  expandOverrides: new Map(), // node key -> explicit expanded(true)/collapsed(false); absent = depth default
  preSearchExpanded: null, // snapshot of expandOverrides taken when search started; restored when search clears
  expandedTaskChips: new Set(), // node keys whose inline "+N tasks" sub-list is open
  graphTransform: { x: 0, y: 0, k: 1 },
  graphViewVersion: null, // payloadVersion the opening view was computed for; null until the graph has been drawn once
  graphUserAdjusted: false, // once the user pans/zooms, their framing wins over any recomputed opening view
  graphRenderAnyway: false,
  treeScrollTop: 0,
  suppressNextClick: false, // set on drag-release so the same pointerup doesn't also select/deselect
};

// modelCache memoizes the whole model on api.payloadVersion (spec: events
// can arrive mid-lifecycle; a full rebuild is O(n) and simplest-correct).
var modelCache = { version: null, model: null };
var lastApi = null;
var boundContainers = new WeakSet(); // ensureEventsBound guard — container is stable, only its children are rebuilt
var searchDebounceTimer = null;

// ---- shared small render helpers ----

function statusRole(status) {
  switch (status) {
    case "task": return "muted";
    case "running": return "info";
    case "ok": return "good";
    case "failed": return "serious";
    case "signaled": return "crit";
    default: return "muted";
  }
}
function statusDotHtml(api, status) {
  if (status === "running") return '<span class="pulse-dot" title="running"></span>';
  var color = api.statusColor(statusRole(status));
  return '<span class="proc-dot" style="--chip-color:' + color + '" title="' + api.esc(status) + '"></span>';
}
function statusBadgeHtml(api, status) {
  var color = api.statusColor(statusRole(status));
  return statusDotHtml(api, status) + ' <span class="ktext" style="--chip-color:' + color + '">' + api.esc(status) + "</span>";
}
function chipLocal(api, label, color) {
  return '<span class="chip" style="--chip-color:' + color + '">' + api.esc(label) + "</span>";
}
function exitChipHtml(api, node) {
  if (node.status === "running") return chipLocal(api, "running", api.statusColor("info"));
  if (node.status === "ok") return chipLocal(api, "exit 0", api.statusColor("good"));
  if (node.status === "failed") {
    var label = node.exitCode !== null ? "exit " + node.exitCode : "exit " + (node.exitStatus || "?");
    return chipLocal(api, label, api.statusColor("serious"));
  }
  if (node.status === "signaled") return chipLocal(api, node.exitSignal || "signaled", api.statusColor("crit"));
  return ""; // task: no exit chip
}
function describeTaskExit(node) {
  if (node.exitSignal) return node.exitSignal;
  if (node.exitCode !== null) return "exit " + node.exitCode;
  return node.exitStatus || "exited";
}

// ---- tree view ----

function visibleChildCount(node, showTasks) {
  return node.procChildKeys.length + (showTasks ? node.taskChildKeys.length : 0);
}
function isExpanded(node, depth, ui) {
  if (ui.expandOverrides.has(node.key)) return ui.expandOverrides.get(node.key);
  return depth < DEFAULT_EXPAND_DEPTH;
}

// computeSearchMatches: case-insensitive substring over pid/binary/argv.
// Deliberately simple (per the tree search spec bullet): while `showTasks`
// is off, folded task nodes are outside the search corpus entirely — search
// doesn't reach inside a collapsed "+N tasks" chip. A task is always a leaf
// (childless by construction), so this can never hide an ancestor path.
function computeSearchMatches(model, query, showTasks) {
  var q = query.trim().toLowerCase();
  var matched = new Set();
  if (!q) return matched;
  model.nodes.forEach(function (n) {
    if (!n.hasExec && !showTasks) return;
    var hay = n.pid;
    if (n.binary) hay += " " + n.binary;
    for (var i = 0; i < n.execs.length; i++) hay += " " + n.execs[i].binary + " " + n.execs[i].argv;
    if (hay.toLowerCase().indexOf(q) !== -1) matched.add(n.key);
  });
  return matched;
}
function computeKeepSet(model, matched) {
  var keep = new Set(matched);
  matched.forEach(function (key) {
    var p = model.byKey.get(key).parentKey;
    while (p && model.byKey.has(p) && !keep.has(p)) {
      keep.add(p);
      p = model.byKey.get(p).parentKey;
    }
  });
  return keep;
}

// buildVisibleRows walks roots -> children producing the flat, depth-
// indexed row list the tree actually renders (only expanded/kept subtrees
// are walked at all, so this stays cheap even at thousands of task nodes).
function buildVisibleRows(model, ui) {
  var rows = [];
  var searching = !!ui.search.trim();
  var matched = searching ? computeSearchMatches(model, ui.search, ui.showTasks) : null;
  var keep = searching ? computeKeepSet(model, matched) : null;

  function walk(key, depth) {
    if (searching && !keep.has(key)) return;
    var node = model.byKey.get(key);
    var expanded;
    if (searching) {
      // Force-expand any node on the path to a match so the match is visible.
      expanded = node.procChildKeys.some(function (k) { return keep.has(k); }) ||
        node.taskChildKeys.some(function (k) { return keep.has(k); });
    } else {
      expanded = isExpanded(node, depth, ui);
    }
    rows.push({ kind: "node", key: key, node: node, depth: depth, isMatch: !!(searching && matched.has(key)), expanded: expanded });
    if (!expanded) return;

    node.procChildKeys.forEach(function (k) { walk(k, depth + 1); });
    if (ui.showTasks) {
      node.taskChildKeys.forEach(function (k) { walk(k, depth + 1); });
    } else if (node.taskChildKeys.length && !searching) {
      rows.push({ kind: "task-chip", key: key + "#tasks", node: node, depth: depth + 1, taskCount: node.taskChildKeys.length });
      if (ui.expandedTaskChips.has(key)) {
        var capped = node.taskChildKeys.slice(0, TASK_CHIP_CAP);
        capped.forEach(function (k) {
          rows.push({ kind: "task-mini", key: k, node: model.byKey.get(k), depth: depth + 2 });
        });
        if (node.taskChildKeys.length > TASK_CHIP_CAP) {
          rows.push({ kind: "task-more", key: key + "#more", depth: depth + 2, more: node.taskChildKeys.length - TASK_CHIP_CAP });
        }
      }
    }
  }

  model.roots.forEach(function (k) { walk(k, 0); });
  return rows;
}

function treeNodeRowHtml(api, ui, row) {
  var node = row.node, depth = row.depth;
  var hasCaret = visibleChildCount(node, ui.showTasks) > 0;
  var caretHtml = hasCaret
    ? '<button type="button" class="proc-caret-btn" data-act="toggle" data-key="' + api.esc(node.key) + '" data-depth="' + depth + '">' +
      (row.expanded ? "▾" : "▸") + "</button>"
    : '<span class="proc-caret-spacer"></span>';
  var binaryHtml = node.hasExec
    ? '<span class="proc-bin" title="' + api.esc(node.binary) + '">' + api.esc(baseName(node.binary) || "(exec)") + "</span>"
    : '<span class="proc-bin proc-bin-task">task</span>';
  var lastArgv = node.hasExec && node.execs.length ? node.execs[node.execs.length - 1].argv : "";
  var argvHtml = lastArgv
    ? '<span class="proc-argv ellipsis" title="' + api.esc(lastArgv) + '">' + api.esc(truncateEnd(lastArgv, ARGV_ROW_TRUNC)) + "</span>"
    : "";
  var metaBits = [];
  var exitHtml = exitChipHtml(api, node);
  if (exitHtml) metaBits.push(exitHtml);
  var lifespan = nodeLifespanMs(node);
  if (lifespan !== null) metaBits.push('<span class="meta">' + humanizeDuration(lifespan) + "</span>");
  if (!ui.showTasks && node.taskChildKeys.length) {
    metaBits.push(chipLocal(api, "+" + node.taskChildKeys.length + " tasks", "var(--ink-3)"));
  }
  var classes = "proc-row" + (row.isMatch ? " proc-row-match" : "") + (ui.selectedKey === node.key ? " proc-row-selected" : "");
  var forgedHtml = node.forged
    ? '<span class="chip" style="--chip-color:' + api.statusColor("crit") +
      '" title="reported on the ' + api.esc(node.producer || "unknown") +
      ' channel, not the trusted guest_supervisor kernel sensor — this process is NOT kernel-verified and may be workload-forged">unverified</span>'
    : "";
  return (
    '<div class="' + classes + '" data-key="' + api.esc(node.key) + '" style="--depth:' + depth + '">' +
      caretHtml +
      statusBadgeHtml(api, node.status) +
      forgedHtml +
      '<span class="mono-num proc-pid">' + api.esc(node.pid) + "</span>" +
      binaryHtml + argvHtml +
      '<span class="proc-meta">' + metaBits.join("") + "</span>" +
    "</div>"
  );
}
function taskChipRowHtml(api, ui, row) {
  var node = row.node;
  var expanded = ui.expandedTaskChips.has(node.key);
  return (
    '<div class="proc-row proc-row-taskchip" style="--depth:' + row.depth + '">' +
      '<button type="button" class="proc-caret-btn" data-act="toggle-taskchip" data-key="' + api.esc(node.key) + '">' +
        (expanded ? "▾" : "▸") +
      "</button>" +
      '<span class="meta">+' + row.taskCount + " tasks</span>" +
    "</div>"
  );
}
function taskMiniRowHtml(api, row) {
  var n = row.node;
  var exitBit = n.exitSeq !== null ? describeTaskExit(n) : "running";
  return (
    '<div class="proc-row proc-row-taskmini" data-key="' + api.esc(n.key) + '" style="--depth:' + row.depth + '">' +
      '<span class="proc-caret-spacer"></span>' +
      '<span class="mono-num proc-pid">' + api.esc(n.pid) + "</span>" +
      '<span class="meta">' + api.esc(api.fmtTs(n.firstTs)) + " · " + api.esc(exitBit) + "</span>" +
    "</div>"
  );
}
function taskMoreRowHtml(row) {
  return '<div class="proc-row proc-row-taskmore" style="--depth:' + row.depth + '">…and ' + row.more + " more</div>";
}

function treeBodyHtml(api, ui, model) {
  var rows = buildVisibleRows(model, ui);
  if (!rows.length) {
    return '<div class="empty proc-empty">' + (ui.search.trim() ? "no matching processes" : "no processes to show") + "</div>";
  }
  return rows.map(function (row) {
    if (row.kind === "task-chip") return taskChipRowHtml(api, ui, row);
    if (row.kind === "task-mini") return taskMiniRowHtml(api, row);
    if (row.kind === "task-more") return taskMoreRowHtml(row);
    return treeNodeRowHtml(api, ui, row);
  }).join("");
}
function treeMainHtml(api, ui, model) {
  return '<div class="proc-tree-scroll" data-role="tree-scroll">' + treeBodyHtml(api, ui, model) + "</div>";
}

// ---- graph view ----

function nodeVisibleInGraph(node, showTasks) {
  return node.hasExec || showTasks;
}
// resolveGraphParent walks up parentKey past any node the current filter
// hides (a task node, when showTasks is off) so an exec'd descendant of a
// task still connects to its nearest exec'd ancestor instead of becoming a
// spurious extra root.
function resolveGraphParent(node, byKey, showTasks) {
  var p = node.parentKey ? byKey.get(node.parentKey) : null;
  while (p && !nodeVisibleInGraph(p, showTasks)) {
    p = p.parentKey ? byKey.get(p.parentKey) : null;
  }
  return p || null;
}

// layoutCache memoizes the graph layout on the same payloadVersion (plus
// showTasks, which changes the visible node set) — per spec, re-layout
// only when the visible node set changes.
var layoutCache = { version: null, pos: null, roots: null, childrenOf: null, nodes: null, edges: null };

function computeGraphLayout(model, api, showTasks) {
  var version = api.payloadVersion + ":" + showTasks;
  if (layoutCache.version === version) return layoutCache;

  var nodes = model.nodes.filter(function (n) { return nodeVisibleInGraph(n, showTasks); });
  var childrenOf = new Map();
  nodes.forEach(function (n) { childrenOf.set(n.key, []); });
  var roots = [];
  var edges = []; // {parentKey, childKey, childStatus}
  nodes.forEach(function (n) {
    var parent = resolveGraphParent(n, model.byKey, showTasks);
    if (parent && childrenOf.has(parent.key)) {
      childrenOf.get(parent.key).push(n.key);
      edges.push({ parentKey: parent.key, childKey: n.key, childStatus: n.status });
    } else {
      roots.push(n.key);
    }
  });
  function byFirstSeq(aKey, bKey) { return model.byKey.get(aKey).firstSeq - model.byKey.get(bKey).firstSeq; }
  childrenOf.forEach(function (arr) { arr.sort(byFirstSeq); });
  roots.sort(byFirstSeq);

  // Leaf-indexed tidy-ish layout: x = depth * dx; leaves get successive y
  // slots in visible-node order, parents center on their children's midpoint.
  var pos = new Map();
  var leafCount = 0;
  function place(key, depth) {
    var kids = childrenOf.get(key) || [];
    if (!kids.length) {
      var y = leafCount * GRAPH_LEAF_DY;
      leafCount++;
      pos.set(key, { x: depth * GRAPH_DEPTH_DX, y: y });
      return y;
    }
    var ys = kids.map(function (k) { return place(k, depth + 1); });
    var mid = (Math.min.apply(null, ys) + Math.max.apply(null, ys)) / 2;
    pos.set(key, { x: depth * GRAPH_DEPTH_DX, y: mid });
    return mid;
  }
  roots.forEach(function (r) { place(r, 0); });

  layoutCache = { version: version, pos: pos, roots: roots, childrenOf: childrenOf, nodes: nodes, edges: edges };
  return layoutCache;
}

function graphNodeGlyphHtml(api, ui, node, p) {
  var selected = ui.selectedKey === node.key;
  var color = api.statusColor(statusRole(node.status));
  var stroke = selected ? "var(--info)" : "var(--border)";
  var strokeWidth = selected ? 2 : 1;
  var label = node.hasExec ? (baseName(node.binary) || "?") : "task";
  var exitLabel = "";
  if (node.status === "ok") exitLabel = "0";
  else if (node.status === "failed") exitLabel = node.exitCode !== null ? String(node.exitCode) : (node.exitStatus || "?");
  else if (node.status === "signaled") exitLabel = node.exitSignal || "";
  var dotHtml = node.status === "running"
    ? '<circle class="pulse-dot" cx="14" cy="0" r="4" fill="var(--info)"></circle>'
    : '<circle class="proc-dot" cx="14" cy="0" r="4" style="--chip-color:' + color + '"></circle>';
  return (
    '<g class="proc-gnode" data-key="' + api.esc(node.key) + '" transform="translate(' + p.x + "," + p.y + ')">' +
      '<rect class="proc-gnode-rect" x="0" y="' + (-GRAPH_NODE_H / 2) + '" width="' + GRAPH_NODE_W + '" height="' + GRAPH_NODE_H +
        '" rx="6" stroke="' + stroke + '" stroke-width="' + strokeWidth + '"></rect>' +
      dotHtml +
      '<text class="proc-gtext" x="26" y="4">' + api.esc(truncateEnd(String(node.pid), 6)) + " " + api.esc(truncateEnd(label, BIN_LABEL_TRUNC)) + "</text>" +
      (exitLabel ? '<text class="proc-gtext-exit" x="' + (GRAPH_NODE_W - 8) + '" y="4" text-anchor="end">' + api.esc(exitLabel) + "</text>" : "") +
    "</g>"
  );
}
function graphEdgeHtml(api, p1, p2, childStatus) {
  var x1 = p1.x + GRAPH_NODE_W, y1 = p1.y, x2 = p2.x, y2 = p2.y;
  var mx = (x1 + x2) / 2;
  var d = "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2;
  var special = childStatus === "failed" || childStatus === "signaled";
  var stroke = special ? api.statusColor(statusRole(childStatus)) : "var(--grid)";
  var opacityAttr = special ? ' stroke-opacity="0.6"' : "";
  return '<path class="proc-gedge" d="' + d + '" stroke="' + stroke + '"' + opacityAttr + "></path>";
}
function graphTooManyHtml(count) {
  return (
    '<div class="proc-graph-toomany">' +
      "<p>" + numFmt(count) + " nodes — too many to draw; filter or keep tasks hidden</p>" +
      '<button type="button" class="btn small" data-act="graph-render-anyway">Render anyway</button>' +
    "</div>"
  );
}
function graphSvgOrMessageHtml(api, ui, model) {
  var layout = computeGraphLayout(model, api, ui.showTasks);
  if (!layout.nodes.length) {
    return '<div class="empty proc-empty">no exec’d processes to graph' + (ui.showTasks ? "" : " — try “show tasks”") + "</div>";
  }
  if (layout.nodes.length > GRAPH_NODE_CAP && !ui.graphRenderAnyway) {
    return graphTooManyHtml(layout.nodes.length);
  }
  var edgesHtml = layout.edges.map(function (e) {
    return graphEdgeHtml(api, layout.pos.get(e.parentKey), layout.pos.get(e.childKey), e.childStatus);
  }).join("");
  var nodesHtml = layout.nodes.map(function (n) {
    return graphNodeGlyphHtml(api, ui, n, layout.pos.get(n.key));
  }).join("");
  var t = ui.graphTransform;
  var label = layout.nodes.length + " processes, " + layout.edges.length + " connections";
  return (
    '<div class="proc-graph-wrap">' +
      '<svg class="proc-graph-svg" role="img" aria-label="' + api.esc("process fork/exec graph: " + label) + '" data-role="graph-svg">' +
        '<g data-role="graph-viewport" transform="translate(' + t.x + "," + t.y + ") scale(" + t.k + ')">' +
          edgesHtml + nodesHtml +
        "</g>" +
      "</svg>" +
      '<div class="proc-graph-controls"><button type="button" class="btn small" data-act="graph-fit">fit</button></div>' +
    "</div>"
  );
}

function applyGraphTransform(container) {
  var g = container.querySelector('[data-role="graph-viewport"]');
  if (g) g.setAttribute("transform", "translate(" + uiState.graphTransform.x + "," + uiState.graphTransform.y + ") scale(" + uiState.graphTransform.k + ")");
}
// graphGeometry measures the drawn content and the pane it is drawn in, or
// returns null when either is not measurable yet (hidden pane, empty graph).
function graphGeometry(container) {
  var svg = container.querySelector('[data-role="graph-svg"]');
  var g = container.querySelector('[data-role="graph-viewport"]');
  if (!svg || !g) return null;
  var bbox;
  try { bbox = g.getBBox(); } catch (e) { return null; }
  if (!bbox || bbox.width <= 0 || bbox.height <= 0) return null;
  var rect = svg.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return null;
  return { bbox: bbox, rect: rect };
}
function graphFitAllScale(rect, bbox) {
  return clamp(Math.min((rect.width - GRAPH_PAD * 2) / bbox.width, (rect.height - GRAPH_PAD * 2) / bbox.height), ZOOM_MIN, ZOOM_MAX);
}
// fitGraphView is the explicit "fit" button: everything on screen at once,
// centered, however small that has to be.
function fitGraphView(container) {
  var geo = graphGeometry(container);
  if (!geo) return;
  var scale = graphFitAllScale(geo.rect, geo.bbox);
  var cx = geo.bbox.x + geo.bbox.width / 2, cy = geo.bbox.y + geo.bbox.height / 2;
  uiState.graphTransform = { x: geo.rect.width / 2 - cx * scale, y: geo.rect.height / 2 - cy * scale, k: scale };
  applyGraphTransform(container);
}
// initialGraphView is the transform the graph OPENS with. Fit-everything is
// the right opening move for a small tree, but a deep run (dozens of leaves
// stacked vertically) only fits by shrinking the pid/binary labels into an
// unreadable smear. So below GRAPH_READABLE_MIN the opening view instead
// fits the content WIDTH at a readable scale and parks the top of the tree
// near the top of the pane; the vertical overflow is what panning is for.
// Returns whether a view could actually be computed.
function initialGraphView(container) {
  var geo = graphGeometry(container);
  if (!geo) return false;
  if (graphFitAllScale(geo.rect, geo.bbox) >= GRAPH_READABLE_MIN) {
    fitGraphView(container);
    return true;
  }
  var scale = clamp((geo.rect.width - GRAPH_PAD * 2) / geo.bbox.width, GRAPH_READABLE_MIN, 1);
  var cx = geo.bbox.x + geo.bbox.width / 2;
  uiState.graphTransform = { x: geo.rect.width / 2 - cx * scale, y: GRAPH_TOP_PAD - geo.bbox.y * scale, k: scale };
  applyGraphTransform(container);
  return true;
}
function handleGraphWheel(e, container) {
  var svg = e.target.closest('[data-role="graph-svg"]');
  if (!svg) return;
  e.preventDefault();
  var rect = svg.getBoundingClientRect();
  var mx = e.clientX - rect.left, my = e.clientY - rect.top;
  var t = uiState.graphTransform;
  var factor = e.deltaY < 0 ? ZOOM_WHEEL_FACTOR : 1 / ZOOM_WHEEL_FACTOR;
  var newK = clamp(t.k * factor, ZOOM_MIN, ZOOM_MAX);
  var wx = (mx - t.x) / t.k, wy = (my - t.y) / t.k; // point under cursor, in content space, held fixed across the zoom
  uiState.graphTransform = { x: mx - wx * newK, y: my - wy * newK, k: newK };
  uiState.graphUserAdjusted = true;
  applyGraphTransform(container);
}
function handleGraphPointerDown(e, container) {
  var svg = e.target.closest('[data-role="graph-svg"]');
  if (!svg || e.button !== 0) return;
  var startX = e.clientX, startY = e.clientY;
  var startT = { x: uiState.graphTransform.x, y: uiState.graphTransform.y, k: uiState.graphTransform.k };
  var dragging = false;
  svg.classList.add("proc-graph-grabbing");
  function onMove(ev) {
    var dx = ev.clientX - startX, dy = ev.clientY - startY;
    if (!dragging && (Math.abs(dx) > DRAG_THRESHOLD_PX || Math.abs(dy) > DRAG_THRESHOLD_PX)) dragging = true;
    if (!dragging) return;
    uiState.graphTransform = { x: startT.x + dx, y: startT.y + dy, k: startT.k };
    uiState.graphUserAdjusted = true;
    applyGraphTransform(container);
  }
  function onUp() {
    window.removeEventListener("pointermove", onMove);
    window.removeEventListener("pointerup", onUp);
    svg.classList.remove("proc-graph-grabbing");
    if (dragging) uiState.suppressNextClick = true; // the drag-release's click shouldn't also select/deselect a node
  }
  window.addEventListener("pointermove", onMove);
  window.addEventListener("pointerup", onUp);
}

// ---- detail panel ----

function exitDetailText(api, node) {
  if (node.exitSeq === null) return '<span class="empty">—</span>';
  var bits = [];
  if (node.exitCode !== null) bits.push("code " + node.exitCode);
  if (node.exitSignal) bits.push("signal " + api.esc(node.exitSignal));
  if (!bits.length) bits.push(api.esc(node.exitStatus || "unknown"));
  return bits.join(" · ");
}
function copyableMiddleTruncated(api, value) {
  return '<span title="' + api.esc(value) + '">' + api.esc(truncateMiddle(value, 6)) + "</span> " +
    '<button type="button" class="copy-btn" data-act="copy" data-value="' + api.esc(value) + '">copy</button>';
}
function detailPanelHtml(api, model, key) {
  var node = model.byKey.get(key);
  if (!node) return "";
  var lifespan = nodeLifespanMs(node);
  var lastArgv = node.hasExec && node.execs.length ? node.execs[node.execs.length - 1].argv : "";

  var rows = [];
  rows.push(["binary", node.hasExec
    ? '<span title="' + api.esc(node.binary) + '">' + api.esc(node.binary || "") + "</span>"
    : '<span class="empty">never exec’d</span>']);
  rows.push(["argv", lastArgv
    ? '<div class="proc-argv-block"><span class="proc-argv-wrap">' + api.esc(lastArgv) + '</span> ' +
      '<button type="button" class="copy-btn" data-act="copy" data-value="' + api.esc(lastArgv) + '">copy</button></div>'
    : '<span class="empty">—</span>']);
  rows.push(["uid", hasVal(node.uid) ? api.esc(String(node.uid)) : '<span class="empty">—</span>']);
  rows.push(["observer", node.observer ? api.esc(node.observer) : '<span class="empty">—</span>']);
  rows.push(["exec id", node.execId ? copyableMiddleTruncated(api, node.execId) : '<span class="empty">—</span>']);
  rows.push(["parent exec id", node.parentExecId ? copyableMiddleTruncated(api, node.parentExecId) : '<span class="empty">—</span>']);
  rows.push(["started", api.esc(api.fmtTs(node.firstTs)) + ' <span class="meta">seq ' + node.firstSeq + "</span>"]);
  rows.push(["exited", node.exitSeq !== null
    ? api.esc(api.fmtTs(node.exitTs)) + ' <span class="meta">seq ' + node.exitSeq + (lifespan !== null ? " · " + humanizeDuration(lifespan) : "") + "</span>"
    : '<span class="empty">—</span>']);
  rows.push(["exit code / signal", exitDetailText(api, node)]);
  rows.push(["children", numFmt(node.procChildKeys.length) + " children · " + numFmt(node.taskChildKeys.length) + " tasks"]);

  var execChainHtml = "";
  if (node.execs.length > 1) {
    execChainHtml = '<div class="proc-section-title">Exec chain</div><ol class="proc-execchain">' +
      node.execs.map(function (e) {
        return "<li>" + e.seq + " · " + api.esc(e.binary) + " — " + api.esc(truncateEnd(e.argv, EXEC_CHAIN_ARGV_TRUNC)) + "</li>";
      }).join("") + "</ol>";
  }
  var eventsHtml = '<div class="proc-section-title">Raw events</div><div class="proc-rawevents">' +
    node.events.map(function (ev) {
      return '<div class="proc-rawevent-row">' + ev.seq + " · " + api.esc(ev.name) + " · " + api.esc(api.fmtTs(ev.ts)) + "</div>";
    }).join("") + "</div>";

  return (
    '<div class="proc-detail">' +
      '<div class="proc-detail-hdr">' + statusBadgeHtml(api, node.status) +
        '<span class="proc-detail-pid">pid ' + api.esc(node.pid) + "</span>" +
        '<span class="proc-detail-bin">' + api.esc(node.hasExec ? (baseName(node.binary) || "") : "task") + "</span>" +
        '<button type="button" class="btn small proc-detail-close" data-act="close-detail" title="close">×</button>' +
      "</div>" +
      '<div class="kv-grid proc-detail-grid">' + rows.map(function (r) {
        return '<div class="k">' + api.esc(r[0]) + '</div><div class="v">' + r[1] + "</div>";
      }).join("") + "</div>" +
      execChainHtml + eventsHtml +
      '<div class="detail-actions">' +
        '<button type="button" class="btn small" data-act="focus-pid" data-value="' + api.esc(node.pid) + '">show events in timeline</button>' +
        (lastArgv ? '<button type="button" class="btn small" data-act="copy" data-value="' + api.esc(lastArgv) + '">copy argv</button>' : "") +
      "</div>" +
    "</div>"
  );
}

// ---- top control row + overall layout ----

function controlRowHtml(api, ui, model) {
  var stats = model.stats;
  var statsText = numFmt(stats.processes) + " processes · " + numFmt(stats.tasks) + " tasks · " +
    numFmt(stats.running) + " running · " + numFmt(stats.failed) + " failed";
  var expandButtons = ui.view === "tree"
    ? '<span class="spacer"></span>' +
      '<button type="button" class="btn small" data-act="expand-all">expand all</button>' +
      '<button type="button" class="btn small" data-act="collapse-all">collapse all</button>'
    : "";
  return (
    '<div class="proc-toolbar">' +
      '<div class="proc-viewswitch">' +
        '<button type="button" class="btn small' + (ui.view === "tree" ? " active" : "") + '" data-act="view" data-value="tree">Tree</button>' +
        '<button type="button" class="btn small' + (ui.view === "graph" ? " active" : "") + '" data-act="view" data-value="graph">Graph</button>' +
      "</div>" +
      '<input type="search" class="proc-search" placeholder="pid, binary or argv…" value="' + api.esc(ui.search) + '" data-act="search">' +
      '<label class="toggle"><input type="checkbox" data-act="show-tasks"' + (ui.showTasks ? " checked" : "") + "> show tasks</label>" +
      '<span class="meta">' + statsText + "</span>" +
      expandButtons +
    "</div>"
  );
}
function bodyLayoutHtml(mainHtml, detailHtml) {
  return (
    '<div class="proc-layout">' +
      '<div class="proc-main">' + mainHtml + "</div>" +
      (detailHtml ? '<div class="proc-side">' + detailHtml + "</div>" : "") +
    "</div>"
  );
}

// renderShell rebuilds the whole tab body into `container` (already emptied
// by the caller) and reapplies whatever of uiState is still visually live
// (scroll position via a fresh listener, graph pan/zoom via the transform
// attribute) since none of it can have survived in the DOM.
function renderShell(container, model, api) {
  if (uiState.selectedKey && !model.byKey.has(uiState.selectedKey)) uiState.selectedKey = null;

  if (!model.nodes.length) {
    container.innerHTML = '<div class="empty proc-empty-root">No process events recorded.</div>';
    return;
  }

  var hint = model.stats.processes === 0
    ? '<div class="proc-hint">No processes have exec’d yet — everything below is task/thread creation.</div>'
    : "";
  var mainHtml = uiState.view === "tree" ? treeMainHtml(api, uiState, model) : graphSvgOrMessageHtml(api, uiState, model);
  var detailHtml = uiState.selectedKey ? detailPanelHtml(api, model, uiState.selectedKey) : "";

  container.innerHTML = controlRowHtml(api, uiState, model) + hint + bodyLayoutHtml(mainHtml, detailHtml);

  var scroller = container.querySelector('[data-role="tree-scroll"]');
  if (scroller) {
    scroller.scrollTop = uiState.treeScrollTop;
    scroller.addEventListener("scroll", function () { uiState.treeScrollTop = scroller.scrollTop; });
  }
  applyGraphTransform(container);
  // The opening view is computed on the first graph draw and recomputed for a
  // brand-new payload, but only while the user has not panned/zoomed — once
  // they have framed the graph themselves, that framing survives re-renders.
  if (uiState.view === "graph" && uiState.graphViewVersion !== api.payloadVersion && !uiState.graphUserAdjusted) {
    if (initialGraphView(container)) uiState.graphViewVersion = api.payloadVersion;
  }
}

function rerenderNow(container) {
  renderShell(container, modelCache.model, lastApi);
}
function scheduleSearchRerender(container) {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(function () { rerenderNow(container); }, SEARCH_DEBOUNCE_MS);
}

// ---- event binding (delegated on the stable container; bound exactly once
// since app.js reuses the same container across every render() call) ----

function handleSearchChange(value, container) {
  var wasEmpty = !uiState.search.trim();
  var willBeEmpty = !value.trim();
  if (wasEmpty && !willBeEmpty) uiState.preSearchExpanded = new Map(uiState.expandOverrides);
  uiState.search = value;
  if (willBeEmpty && uiState.preSearchExpanded) {
    uiState.expandOverrides = uiState.preSearchExpanded;
    uiState.preSearchExpanded = null;
  }
  scheduleSearchRerender(container);
}

function handleActionClick(btn, container) {
  var act = btn.dataset.act;
  if (act === "view") { uiState.view = btn.dataset.value; rerenderNow(container); return; }
  if (act === "show-tasks") return; // handled by the "change" listener below; click fires first and is a no-op here
  if (act === "toggle") {
    var key = btn.dataset.key;
    var node = modelCache.model.byKey.get(key);
    var depth = Number(btn.dataset.depth) || 0;
    uiState.expandOverrides.set(key, !isExpanded(node, depth, uiState));
    rerenderNow(container);
    return;
  }
  if (act === "toggle-taskchip") {
    var k = btn.dataset.key;
    if (uiState.expandedTaskChips.has(k)) uiState.expandedTaskChips.delete(k); else uiState.expandedTaskChips.add(k);
    rerenderNow(container);
    return;
  }
  if (act === "expand-all") {
    modelCache.model.nodes.forEach(function (n) { uiState.expandOverrides.set(n.key, true); });
    rerenderNow(container);
    return;
  }
  if (act === "collapse-all") {
    modelCache.model.nodes.forEach(function (n) { uiState.expandOverrides.set(n.key, false); });
    rerenderNow(container);
    return;
  }
  if (act === "close-detail") { uiState.selectedKey = null; rerenderNow(container); return; }
  if (act === "focus-pid") { lastApi.focusPid(btn.dataset.value); return; }
  if (act === "copy") { copyText(btn.dataset.value, btn); return; }
  if (act === "graph-fit") { fitGraphView(container); return; }
  if (act === "graph-render-anyway") { uiState.graphRenderAnyway = true; rerenderNow(container); return; }
}

function ensureEventsBound(container) {
  if (boundContainers.has(container)) return;
  boundContainers.add(container);

  container.addEventListener("input", function (e) {
    if (e.target.matches('[data-act="search"]')) handleSearchChange(e.target.value, container);
  });
  container.addEventListener("change", function (e) {
    if (e.target.matches('[data-act="show-tasks"]')) {
      uiState.showTasks = e.target.checked;
      rerenderNow(container);
    }
  });
  container.addEventListener("click", function (e) {
    if (uiState.suppressNextClick) { uiState.suppressNextClick = false; return; }
    var btn = e.target.closest("[data-act]");
    if (btn) { handleActionClick(btn, container); return; }
    var gnode = e.target.closest(".proc-gnode");
    if (gnode && gnode.dataset.key) { uiState.selectedKey = gnode.dataset.key; rerenderNow(container); return; }
    var row = e.target.closest(".proc-row[data-key]");
    if (row && row.dataset.key) { uiState.selectedKey = row.dataset.key; rerenderNow(container); }
  });
  container.addEventListener("wheel", function (e) { handleGraphWheel(e, container); }, { passive: false });
  container.addEventListener("pointerdown", function (e) { handleGraphPointerDown(e, container); });
}

// ---- render entry point ----

function render(container, events, api) {
  lastApi = api;
  if (modelCache.version !== api.payloadVersion) {
    modelCache.model = buildModel(events);
    modelCache.version = api.payloadVersion;
  }
  ensureEventsBound(container);
  renderShell(container, modelCache.model, api);
}

window.BoxedAiProc = {
  render: render,
  _buildModel: buildModel,
};

})();
