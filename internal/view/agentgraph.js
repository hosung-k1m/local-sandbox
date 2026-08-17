// BoxedAi Agents-tab graph view: a live picture of the agents that are working
// RIGHT NOW. Plain script (same "no modules, no build step" contract as
// app.js/processes.js; DESIGN.md "Viewer": "embedded HTML pages (no build step,
// vanilla JS)"). app.js's Agents tab calls
// window.BoxedAiAgentGraph.render(container, data, api) whenever the tab is
// active in graph mode — on tab switch, on the sub-view toggle and on every
// live-poll tick — and, exactly like the Processes hook, it empties `container`
// itself immediately before calling render(). So this file rebuilds its DOM from
// scratch on every call, and everything that must survive that (which nodes have
// already been seen, which have just disappeared, how far each ticker had got)
// lives in the module-level state below, keyed by agent id.
//
// This view is a PRESENTATION of the grouping app.js already computed
// (computeAgentGroups) and hands over pre-derived: it never re-reads raw
// lifecycle events, so every honesty rule pinned there holds here for free —
// agents come only from registrations, a closure naming an unregistered id is
// dropped rather than promoted into an agent, an agent whose parent is missing
// renders as a root, forged parent cycles are guarded, and a registered agent
// that was never witnessed acting still appears. Self-reported attribution is
// never promoted: every node carries the same strength chip the list view shows.
//
// Nothing here is ever gated on verification facets. `agent_hierarchy_valid=false`
// and an INCOMPLETE verdict are the EXPECTED shape of a real multi-subagent
// session (hooks are fail-open and get dropped at scale), and the graph must
// draw happily through that.
//
// The pane is navigable: wheel pans, ctrl/cmd+wheel (and trackpad pinch) zooms
// around the cursor, dragging empty background pans, and "fit" restores the
// framed view. All of it moves ONE shared inner layer — the canvas holding both
// the cards and the SVG edge underlay — so nodes and edges can never desync.
//
// Wrapped in an IIFE (like processes.js) so its helpers can't collide with
// app.js's own same-named globals; the only global it adds is
// window.BoxedAiAgentGraph.
(function () {

// ---- constants ----
var TICKER_LINES = 8; // most recent actions shown inside a node card
var POPOVER_LINES = 100; // most recent actions the hover popover shows (it scrolls)
var EXIT_LINGER_MS = 600; // how long a just-finished agent lingers as a fading card
var TICK_MS = 1000; // elapsed-clock cadence
var NODE_CAP = 60; // live-node render guard: agent registrations are workload-narrated, so their count is not bounded by anything trustworthy
var DENSE_LEVEL = 8; // a band wider than this switches the whole canvas to compact cards
var POPOVER_TEXT_TRUNC = 140; // one row per action, so its lines stay one-line and the panel scrolls
var POPOVER_W = 460; // keep in sync with .agraph-popover's width in app.css
var POPOVER_MARGIN = 10;
var POPOVER_GAP = 4; // gap between a card and its panel: small enough to cross, big enough to read as separate
var HOVER_GRACE_MS = 200; // how long the panel survives the pointer leaving, so it can be moved INTO
var RESIZE_DEBOUNCE_MS = 120;

// Pan/zoom. FIT_READABLE_MIN is the floor the opening view will shrink to: a
// tall tree that only fits by shrinking its tickers into a smear is worse than
// a readable tree the user pans through, which is what the vertical overflow is
// for. ZOOM_MIN is lower because the USER may deliberately zoom out for a map.
var ZOOM_MIN = 0.3;
var ZOOM_MAX = 2.5;
var ZOOM_WHEEL_FACTOR = 1.12;
var FIT_READABLE_MIN = 0.55;
var FIT_PAD = 20;
var DRAG_THRESHOLD_PX = 3; // below this a pointerdown/up is a click, not a pan

// AGENT_AVATARS maps the harness-declared subagent type to a glyph. The type is
// workload-controlled, so it is only ever a LOOKUP KEY (lowercased) into this
// fixed table — an unknown type gets the default, never anything derived from
// the string itself — and the type text rendered beside it still goes through
// esc(). The avatar is decoration only: every node keeps its text title, its
// attribution chip and its status text, so no meaning here rides on a glyph (or
// a color) alone.
var AGENT_AVATARS = {
  explore: "🔎",
  plan: "🗺️",
  "general-purpose": "🛠️",
  review: "👓",
  code: "🧩",
  build: "🏗️",
  test: "🧪",
  research: "📚",
  docs: "📝",
};
var AVATAR_DEFAULT = "🤖";
var AVATAR_PRIMARY = "🧠"; // the Primary is the one host-minted agent; it gets its own face
var AVATAR_UNATTRIBUTED = "🌫️";

// ---- small pure utils ----

function truncateEnd(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

// elapsedLabel renders "how long has this been going" from an RFC3339
// timestamp. Coarse on purpose: this is a glance-value, not a measurement.
function elapsedLabel(startTs) {
  if (!startTs) return "";
  var t = Date.parse(startTs);
  if (isNaN(t)) return "";
  var s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return s + "s";
  var m = Math.floor(s / 60);
  if (m < 60) return m + "m " + (s % 60) + "s";
  var h = Math.floor(m / 60);
  return h + "h " + (m % 60) + "m";
}

function clamp(v, lo, hi) {
  return Math.min(hi, Math.max(lo, v));
}

function debounce(fn, ms) {
  var t = null;
  return function () {
    var args = arguments, self = this;
    clearTimeout(t);
    t = setTimeout(function () { fn.apply(self, args); }, ms);
  };
}

// ---- module state ----
//
// The container is emptied by the CALLER before every render (see app.js's
// renderAgentGraph), so none of this can live in the DOM. It is keyed by agent
// id — stable across rebuilds — and dropped wholesale when the session changes,
// because ids, event indices and sequence numbers all mean something different
// in the next session (the dashboard can swap sessions under a mounted view).

var uiState = {
  sessionId: null, // session the caches below belong to
  version: null, // api.payloadVersion the ticker watermark was last advanced for
  seen: new Set(), // agent ids already drawn once: they don't replay the enter animation
  exiting: new Map(), // agent id -> Date.now() when it was first seen absent
  lastTopSeq: new Map(), // agent id -> newest action seq already shown (drives the new-line highlight)
  lastCards: new Map(), // agent id -> frozen card snapshot, so an exiting node can still be drawn
  // Where the user has navigated to. This is the reason the transform lives in
  // module state at all: the tab re-renders on every live poll (~3s), and a
  // viewport that snapped back to the fit view three times a minute would be
  // unusable. It belongs to ONE session — the id above is the session-qualifying
  // half of api.payloadVersion — so switching sessions in the dashboard drops it
  // with everything else, while a new payload for the SAME session keeps it.
  transform: null, // {x, y, k} applied to the canvas layer, or null until first fitted
  userAdjusted: false, // once the user pans/zooms, their framing outranks any recomputed fit
};

var lastContainer = null;
var lastData = null;
var lastApi = null;
var lastEdges = []; // [{parentId, childId, live}] from the most recent build, redrawn on resize
var boundContainers = new WeakSet(); // ensureBound guard — the container is stable, only its children are rebuilt
var tickTimer = null;
var exitTimer = null;
var popoverEl = null;
var popoverAgentId = null;
var popoverHideTimer = null; // hover-intent grace: see scheduleHidePopover
var popoverScroll = 0; // how far the reader had scrolled the open panel, so a rebuild can restore it
var panning = false; // a background drag is in progress, so hover must stay out of the way
var resizeBound = false;

// resetForSession drops every per-agent cache when the view moves to another
// session. api.payloadVersion is session-qualified for the same reason.
function resetForSession(sessionId) {
  if (uiState.sessionId === sessionId) return;
  uiState.sessionId = sessionId;
  uiState.version = null;
  uiState.seen = new Set();
  uiState.exiting = new Map();
  uiState.lastTopSeq = new Map();
  uiState.lastCards = new Map();
  uiState.transform = null;
  uiState.userAdjusted = false;
  hidePopover();
}

// ---- node model (built from the pre-derived grouping, never from raw events) ----

function avatarFor(m) {
  if (m && m.role === "primary") return AVATAR_PRIMARY;
  var type = m && m.type ? String(m.type).toLowerCase() : "";
  return AGENT_AVATARS[type] || AVATAR_DEFAULT;
}

// agentStartTs answers "running since when". meta.seq is the agent's own
// registration sequence and data.bySeq maps a sequence to its index in the same
// event list, so this reads the timestamp the record actually carries rather
// than inventing one.
function agentStartTs(data, m, members) {
  if (m && data.bySeq && data.bySeq.has(m.seq)) {
    var ev = data.events[data.bySeq.get(m.seq)];
    if (ev) return ev.ts;
  }
  // An id with activity but no registration has no start to read: fall back to
  // its first observed action, which is the earliest moment the record proves
  // it existed.
  if (members && members.length) {
    var first = data.events[members[0]];
    if (first) return first.ts;
  }
  return "";
}

// buildNodes turns the pre-order forest walk into the levels the canvas draws:
// depth 0 on top, each deeper level a band below it. Only live agents are
// nodes (same predicate as the list view's Active section, handed over as
// api.agentIsActive), plus the ghosts and re-rootings described below.
function buildNodes(data, api) {
  var walk = data.groups || [];
  var meta = data.meta;
  var entryByKey = new Map();
  walk.forEach(function (og) { entryByKey.set(og.group.key, og); });

  var keep = new Map(); // agent id -> {entry, ghost}
  walk.forEach(function (og) {
    if (api.agentIsActive(meta.get(og.group.key), data.sessionEnded)) {
      keep.set(og.group.key, { entry: og, ghost: false });
    }
  });
  // An agent that is NOT live but still has live descendants is drawn as a
  // dimmed ghost, so its subtree's edges stay anchored to something instead of
  // scattering into extra roots. Today's evidence makes this nearly
  // unreachable — every child parents to the Primary, so a live child implies a
  // live Primary — but the walk is N-level generic and the cost here is a loop.
  var liveIds = [];
  keep.forEach(function (_, id) { liveIds.push(id); });
  liveIds.forEach(function (id) {
    var m = meta.get(id);
    var parentID = m ? m.parentID : "";
    var guard = 0;
    while (parentID && entryByKey.has(parentID) && !keep.has(parentID) && guard++ < 64) {
      keep.set(parentID, { entry: entryByKey.get(parentID), ghost: true });
      var pm = meta.get(parentID);
      parentID = pm ? pm.parentID : "";
    }
  });

  var nodes = [];
  var byId = new Map();
  var edges = [];
  walk.forEach(function (og) {
    var id = og.group.key;
    var kept = keep.get(id);
    if (!kept) return;
    if (nodes.length >= NODE_CAP) return; // the walk is pre-order, so a dropped tail never orphans a drawn parent
    var m = meta.get(id);
    var parentID = m ? m.parentID : "";
    var parentNode = parentID ? byId.get(parentID) : null;
    // Re-rooting: an agent whose parent isn't drawn (finished with no live
    // descendants, never registered, or cut by the node cap) has no visible
    // anchor, so it becomes a root of its own rather than sitting at an indent
    // level that points at nothing.
    var node = {
      id: id,
      meta: m,
      ghost: kept.ghost,
      depth: parentNode ? parentNode.depth + 1 : 0,
      members: og.group.members || [],
      title: api.agentTitle(m),
      avatar: avatarFor(m),
      strengthChip: api.agentStrengthChip(m),
      startTs: agentStartTs(data, m, og.group.members),
      nativeID: m && m.nativeID ? m.nativeID : "",
      satellite: false,
    };
    nodes.push(node);
    byId.set(id, node);
    if (parentNode) edges.push({ parentId: parentNode.id, childId: id, live: !kept.ghost });
  });

  var levels = [];
  nodes.forEach(function (n) {
    if (!levels[n.depth]) levels[n.depth] = [];
    levels[n.depth].push(n);
  });
  var widest = 0;
  levels.forEach(function (band) { if (band && band.length > widest) widest = band.length; });

  var live = 0;
  nodes.forEach(function (n) { if (!n.ghost) live++; });
  return {
    nodes: nodes,
    byId: byId,
    levels: levels,
    edges: edges,
    live: live,
    dense: widest > DENSE_LEVEL,
    dropped: Math.max(0, keep.size - nodes.length),
  };
}

// unattributedNode builds the dashed satellite for workload activity the record
// never attributed to any agent (app.js's UNATTRIBUTED bucket). It rides in the
// TOP band beside the Primary — same level, dashed, and never connected by an
// edge, because it belongs to no agent and giving it a parent would be exactly
// the "default it to the Primary" claim the whole attribution model refuses to
// make. It returns null when there is no such activity, and then nothing extra
// renders at all: no row, no divider, no placeholder.
function unattributedNode(data) {
  var g = data.unattributed;
  if (!g || !g.members || !g.members.length) return null;
  return {
    id: "__unattributed__",
    meta: null,
    ghost: false,
    depth: 0,
    members: g.members,
    title: "unattributed activity",
    avatar: AVATAR_UNATTRIBUTED,
    strengthChip: "",
    startTs: "",
    nativeID: "",
    satellite: true,
  };
}

// ---- card rendering ----

// tickerHtml renders a node's rolling activity: its most recent actions,
// oldest first so the newest sits at the bottom where the eye lands. Lines that
// arrived since the previous render slide in; the watermark only advances when
// the payload itself did, so a re-render triggered by the exit timer or the
// sub-view switch doesn't silently clear the highlight.
//
// Each line shows the WHOLE summary — a command, a path or a search pattern cut
// mid-token tells you nothing, so the text wraps over as many lines as it needs
// and the card grows downward (the card's width is fixed; .agraph-tick-text in
// app.css carries the wrap rules and the pathological-input clamp). Nothing here
// carries a timestamp: the ticker answers "what is this agent doing", and the
// hover popover remains the surface that answers "when".
function tickerHtml(node, data, api, advanceWatermark) {
  var members = node.members || [];
  if (!members.length) {
    return '<div class="agraph-tick agraph-tick-idle">no actions recorded yet</div>';
  }
  var prevTop = uiState.lastTopSeq.get(node.id);
  var start = Math.max(0, members.length - TICKER_LINES);
  var out = [];
  var newest = 0;
  for (var i = start; i < members.length; i++) {
    var idx = members[i];
    var ev = data.events[idx];
    if (!ev) continue;
    if (ev.seq > newest) newest = ev.seq;
    var summary = api.toolActivitySummary(ev);
    var text = summary.text || summary.desc || "";
    var fresh = prevTop !== undefined && ev.seq > prevTop;
    out.push(
      '<div class="agraph-tick' + (fresh ? " agraph-tick-new" : "") + '">' +
        '<span class="agraph-tick-tool">' + api.esc(summary.tool) + "</span>" +
        '<span class="agraph-tick-text">' +
          (text ? api.esc(text) : '<span class="empty">(no argument)</span>') +
        "</span>" +
      "</div>"
    );
  }
  // The last member is the newest action for this node, so its seq is the
  // watermark the next render compares against.
  if (advanceWatermark && newest) uiState.lastTopSeq.set(node.id, newest);
  return out.join("");
}

// statusHtml is the node's live state: a pulsing dot plus a ticking elapsed
// clock for a running agent, a plain label for a ghost or the satellite. The
// elapsed span carries its own start timestamp so the interval below can
// refresh it without a re-render.
function statusHtml(node, api) {
  var count = (node.members || []).length;
  var actions = api.numFmt(count) + (count === 1 ? " action" : " actions");
  if (node.satellite) {
    return '<span class="agraph-status"><span class="meta">' + api.esc(actions) + "</span></span>";
  }
  if (node.ghost) {
    return '<span class="agraph-status"><span class="meta">not running · ' + api.esc(actions) + "</span></span>";
  }
  return (
    '<span class="agraph-status">' +
      '<span class="pulse-dot" title="running"></span>' +
      '<span class="agraph-elapsed mono-num" data-role="elapsed" data-since="' + api.esc(node.startTs) + '">' +
        api.esc(elapsedLabel(node.startTs)) +
      "</span>" +
      '<span class="meta">' + api.esc(actions) + "</span>" +
    "</span>"
  );
}

function cardClasses(node, isNew) {
  var cls = "agraph-card";
  if (node.satellite) cls += " agraph-card-satellite";
  if (node.ghost) cls += " agraph-card-ghost";
  if (!node.ghost && !node.satellite) cls += " agraph-card-live";
  if (isNew) cls += " agraph-card-enter";
  return cls;
}

// cardHtml renders one node. Every workload-controlled value on it — the agent
// id, the harness-declared type, tool names and their arguments — goes through
// api.esc(), including the ones that land in data-* attributes.
function cardHtml(node, data, api, advanceWatermark) {
  var isNew = !node.satellite && !uiState.seen.has(node.id);
  var typeText = node.meta && node.meta.type ? String(node.meta.type) : "";
  var subBits = [];
  if (node.satellite) subBits.push("no agent.id on these actions");
  else subBits.push(node.id);
  if (node.nativeID) subBits.push("native " + node.nativeID);
  return (
    '<div class="' + cardClasses(node, isNew) + '" data-agent-id="' + api.esc(node.id) + '">' +
      '<div class="agraph-card-hd">' +
        '<span class="agraph-avatar" aria-hidden="true">' + api.esc(node.avatar) + "</span>" +
        '<span class="agraph-title ellipsis" title="' + api.esc(node.title) + '">' + api.esc(node.title) + "</span>" +
      "</div>" +
      '<div class="agraph-chips">' +
        node.strengthChip +
        (typeText ? '<span class="meta agraph-type ellipsis">' + api.esc(typeText) + "</span>" : "") +
      "</div>" +
      '<div class="agraph-sub meta ellipsis" title="' + api.esc(subBits.join(" · ")) + '">' + api.esc(subBits.join(" · ")) + "</div>" +
      statusHtml(node, api) +
      '<div class="agraph-ticker">' + tickerHtml(node, data, api, advanceWatermark) + "</div>" +
    "</div>"
  );
}

// exitCardHtml redraws a node that has just left the live set from its frozen
// snapshot. The DOM is rebuilt every render, so an agent that completes between
// two ticks would otherwise blink out with no transition at all; instead it
// fades and shrinks for EXIT_LINGER_MS and is then dropped (a timer schedules
// the render that removes it).
function exitCardHtml(snap) {
  return '<div class="agraph-card agraph-card-exit">' + snap.body + "</div>";
}

// ---- canvas ----

function levelsHtml(model, data, api, advanceWatermark, lingering) {
  var bands = [];
  for (var depth = 0; depth < model.levels.length; depth++) {
    var band = model.levels[depth] || [];
    var cards = band.map(function (n) { return cardHtml(n, data, api, advanceWatermark); });
    // Exiting nodes rejoin the band they were last drawn in, so the row doesn't
    // reflow around the gap while they fade.
    lingering.forEach(function (snap) {
      if (snap.depth === depth) cards.push(exitCardHtml(snap));
    });
    if (!cards.length) continue;
    bands.push('<div class="agraph-level" data-depth="' + depth + '">' + cards.join("") + "</div>");
  }
  // A node that exited from a band that no longer exists still gets to finish
  // its animation rather than vanishing mid-fade.
  var orphanExits = lingering.filter(function (snap) { return snap.depth >= model.levels.length; });
  if (orphanExits.length) {
    bands.push('<div class="agraph-level">' + orphanExits.map(exitCardHtml).join("") + "</div>");
  }
  return bands.join("");
}

function emptyStateHtml(data) {
  if (data.sessionEnded) {
    return '<div class="agraph-empty">' +
      '<div class="agraph-empty-title">session ended — no live agents</div>' +
      '<div class="meta">the list view has the full history, including every agent that ran</div>' +
      "</div>";
  }
  return '<div class="agraph-empty">' +
    '<div class="agraph-empty-title">waiting for the first agent…</div>' +
    '<div class="meta">this fills in as the harness narrates agents; nothing has been reported yet</div>' +
    "</div>";
}

function headerHtml(model, api) {
  var bits = [api.numFmt(model.live) + (model.live === 1 ? " live agent" : " live agents")];
  if (model.dropped) bits.push(api.numFmt(model.dropped) + " more not drawn (node cap)");
  bits.push("active agents only — the list view shows every agent");
  return '<div class="agraph-hdr">' +
    '<span class="meta">' + api.esc(bits.join(" · ")) + "</span>" +
    '<span class="agraph-controls">' +
      // The navigation is discoverable from the pane itself: nothing else in the
      // viewer pans, so a first-time reader has no reason to try.
      '<span class="meta agraph-hint">wheel pans · ⌘/ctrl+wheel zooms · drag the background</span>' +
      '<button type="button" class="btn small" data-act="graph-fit" title="refit the whole graph in view (or double-click the background)">fit</button>' +
    "</span>" +
    "</div>";
}

// renderShell rebuilds the whole pane. It always ASSIGNS innerHTML rather than
// appending, so it behaves identically whether app.js emptied the container for
// us or one of this module's own timers triggered the render.
function renderShell(container, data, api) {
  var advanceWatermark = uiState.version !== api.payloadVersion;
  var model = buildNodes(data, api);
  var satellite = data.sessionEnded ? null : unattributedNode(data);

  // Exit bookkeeping: anything drawn last time and absent now starts fading;
  // anything past its linger window is dropped for good.
  var liveIds = new Set();
  model.nodes.forEach(function (n) { liveIds.add(n.id); });
  var now = Date.now();
  uiState.lastCards.forEach(function (snap, id) {
    if (!liveIds.has(id) && !uiState.exiting.has(id)) uiState.exiting.set(id, now);
  });
  var lingering = [];
  var soonest = null;
  uiState.exiting.forEach(function (since, id) {
    if (liveIds.has(id)) { uiState.exiting.delete(id); return; } // it came back before the fade finished
    var remaining = EXIT_LINGER_MS - (now - since);
    var snap = uiState.lastCards.get(id);
    if (remaining <= 0 || !snap) {
      uiState.exiting.delete(id);
      uiState.lastCards.delete(id);
      uiState.seen.delete(id);
      uiState.lastTopSeq.delete(id);
      return;
    }
    lingering.push(snap);
    if (soonest === null || remaining < soonest) soonest = remaining;
  });

  // The satellite joins the top band rather than getting a row of its own: it is
  // a peer of the Primary in the sense that matters here (nobody's child), and a
  // separator below the tree rendered as a stray empty box whenever there was no
  // unattributed activity to put in it. It is appended to the band, never to
  // model.nodes, so it can never acquire an edge or an exit animation.
  if (satellite) {
    if (!model.levels[0]) model.levels[0] = [];
    model.levels[0].push(satellite);
  }

  var body;
  if (!model.nodes.length && !lingering.length && !satellite) {
    body = emptyStateHtml(data);
  } else {
    // The viewport clips; the canvas inside it is the ONE layer the pan/zoom
    // transform moves, so the SVG underlay and the cards it connects are
    // transformed together and can never drift apart.
    body =
      headerHtml(model, api) +
      '<div class="agraph-viewport" data-role="viewport">' +
        '<div class="agraph-canvas' + (model.dense ? " agraph-dense" : "") + '" data-role="canvas">' +
          '<svg class="agraph-edges" data-role="edges" aria-hidden="true"></svg>' +
          levelsHtml(model, data, api, advanceWatermark, lingering) +
        "</div>" +
      "</div>";
  }
  container.innerHTML = body;

  // Snapshot what is on screen now: the exit path redraws from these, so it can
  // never depend on event indices that a later payload may have moved.
  var nextCards = new Map();
  var cardEls = container.querySelectorAll(".agraph-card");
  for (var i = 0; i < cardEls.length; i++) {
    var id = cardEls[i].dataset.agentId;
    if (!id || !liveIds.has(id)) continue;
    var node = model.byId.get(id);
    nextCards.set(id, { id: id, depth: node ? node.depth : 0, body: cardEls[i].innerHTML });
    uiState.seen.add(id);
  }
  lingering.forEach(function (snap) { nextCards.set(snap.id, snap); });
  uiState.lastCards = nextCards;
  uiState.version = api.payloadVersion;

  lastEdges = model.edges;
  if (!drawEdges(container) || !applyViewTransform(container)) {
    // A hidden pane measures as zero. Try once more after layout; the tab's own
    // activation re-renders anyway, so this is only for the transient case.
    window.requestAnimationFrame(function () {
      drawEdges(container);
      applyViewTransform(container);
    });
  }
  if (popoverAgentId) reopenPopover(container);
  scheduleExitSweep(soonest);
  ensureTicking(container);
}

// drawEdges measures the drawn cards and connects each parent to its children
// with a soft curve. Positions are MEASURED rather than computed: the bands are
// laid out (and wrapped) by flexbox, so measuring is the only way the edges can
// track where the cards actually landed. Returns false when nothing is
// measurable yet (hidden pane), so the caller can retry.
//
// The measurement is taken from LAYOUT OFFSETS, not client rects: the canvas is
// the layer the pan/zoom transform is applied to, so a client rect reports
// scaled screen pixels while the SVG underlay inside that same layer draws in
// unscaled canvas pixels. offsetLeft/offsetTop are relative to the canvas (its
// position:relative makes it the offsetParent) and are transform-free, so one
// set of numbers is correct at every zoom level and no edge has to be redrawn
// when the user navigates.
function drawEdges(container) {
  var canvas = container.querySelector('[data-role="canvas"]');
  var svg = container.querySelector('[data-role="edges"]');
  if (!canvas || !svg) return true; // empty state: nothing to draw
  if (canvas.offsetWidth <= 0 || canvas.offsetHeight <= 0) return false;

  var pos = new Map();
  var cards = canvas.querySelectorAll(".agraph-card");
  for (var i = 0; i < cards.length; i++) {
    var id = cards[i].dataset.agentId;
    if (!id) continue;
    pos.set(id, {
      cx: cards[i].offsetLeft + cards[i].offsetWidth / 2,
      top: cards[i].offsetTop,
      bottom: cards[i].offsetTop + cards[i].offsetHeight,
    });
  }
  var paths = lastEdges.map(function (e) {
    var p = pos.get(e.parentId), c = pos.get(e.childId);
    if (!p || !c) return "";
    var midY = (p.bottom + c.top) / 2;
    var d = "M" + p.cx + "," + p.bottom +
      " C" + p.cx + "," + midY + " " + c.cx + "," + midY + " " + c.cx + "," + c.top;
    return '<path class="agraph-edge' + (e.live ? " agraph-edge-live" : "") + '" d="' + d + '"></path>';
  }).join("");
  // No viewBox: the SVG fills the canvas box, so one user unit is one CSS pixel
  // and the measured coordinates above can be used verbatim.
  svg.innerHTML = paths;
  return true;
}

// ---- pan / zoom ----
//
// Same shape as the Processes tab's process graph (processes.js): a {x, y, k}
// transform in module state, applied to one viewport layer, with the cursor
// held fixed across a zoom. The difference is what gets transformed — there an
// SVG <g>, here the HTML canvas that carries both the cards and their SVG
// underlay — so the two never disagree about where a node is.

// viewGeometry measures the canvas content and the viewport it is framed in, or
// returns null while neither can be measured (the pane is display:none until the
// Agents tab is on screen in graph mode).
function viewGeometry(container) {
  var viewport = container.querySelector('[data-role="viewport"]');
  var canvas = container.querySelector('[data-role="canvas"]');
  if (!viewport || !canvas) return null;
  var vw = viewport.clientWidth, vh = viewport.clientHeight;
  var cw = canvas.offsetWidth, ch = canvas.offsetHeight;
  if (vw <= 0 || vh <= 0 || cw <= 0 || ch <= 0) return null;
  return { vw: vw, vh: vh, cw: cw, ch: ch };
}

// fitView computes the framed view: the whole graph centered and scaled to fit,
// but never shrunk past FIT_READABLE_MIN (a tall run would otherwise open as an
// unreadable smear — panning is the answer to vertical overflow) and never
// magnified past 1 (a two-node graph should not fill the pane with balloons).
//
// Fitting is a VERTICAL question only: the bands wrap (.agraph-level is a
// wrapping flex row) so the content is never wider than the canvas box, and the
// canvas box is as wide as the viewport. The horizontal term below is therefore
// pure centering of the scaled layer, not a fit.
function fitView(container) {
  var geo = viewGeometry(container);
  if (!geo) return false;
  var k = clamp((geo.vh - FIT_PAD * 2) / geo.ch, FIT_READABLE_MIN, 1);
  uiState.transform = { x: (geo.vw - geo.cw * k) / 2, y: FIT_PAD, k: k };
  return true;
}

function applyTransform(container) {
  var canvas = container.querySelector('[data-role="canvas"]');
  if (!canvas || !uiState.transform) return;
  var t = uiState.transform;
  canvas.style.transform = "translate(" + t.x + "px, " + t.y + "px) scale(" + t.k + ")";
}

// applyViewTransform is what every render calls: it re-fits only while the user
// has not navigated, so a live poll keeps a growing graph framed but never yanks
// the viewport away from someone reading it.
function applyViewTransform(container) {
  if (!container.querySelector('[data-role="canvas"]')) return true; // empty state
  if (!uiState.transform || !uiState.userAdjusted) {
    if (!fitView(container)) return false;
  }
  applyTransform(container);
  return true;
}

// resetView is the "fit" button and the background double-click: it hands
// framing back to the code.
function resetView(container) {
  uiState.userAdjusted = false;
  hidePopover();
  if (fitView(container)) applyTransform(container);
}

function panBy(container, dx, dy) {
  if (!uiState.transform) return;
  var t = uiState.transform;
  uiState.transform = { x: t.x + dx, y: t.y + dy, k: t.k };
  uiState.userAdjusted = true;
  applyTransform(container);
}

// zoomAt scales around a point in VIEWPORT coordinates, so whatever is under the
// cursor stays under the cursor — the behaviour every map has trained people to
// expect, and the reason the point is converted into content space first.
function zoomAt(container, factor, vx, vy) {
  if (!uiState.transform) return;
  var t = uiState.transform;
  var k = clamp(t.k * factor, ZOOM_MIN, ZOOM_MAX);
  if (k === t.k) return;
  var cx = (vx - t.x) / t.k, cy = (vy - t.y) / t.k;
  uiState.transform = { x: vx - cx * k, y: vy - cy * k, k: k };
  uiState.userAdjusted = true;
  applyTransform(container);
}

// handleWheel maps the two gestures every trackpad and mouse already produces:
// a plain wheel/two-finger scroll pans, and ctrl/cmd+wheel — which is also what
// a trackpad PINCH is delivered as — zooms. It preventDefaults inside the pane
// so the page underneath never scrolls out from under the graph, but leaves the
// popover alone: that panel has its own scrollback and must keep it.
//
// The WHOLE pane is the gesture surface, header strip included. This listener is
// delegated on the pane itself, so anything reaching it is already inside; an
// earlier version also required the target to be inside the viewport, which let
// a wheel that happened to land on the header bubble out and scroll the page out
// from under the graph — the exact thing this handler exists to prevent. The one
// thing still worth testing is that there is a graph to move at all: the empty
// state has no viewport, and swallowing scroll over a screenful of "waiting for
// the first agent…" would just trap the reader.
function handleWheel(e, container) {
  if (popoverEl && popoverEl.contains(e.target)) return;
  var viewport = container.querySelector('[data-role="viewport"]');
  if (!viewport) return;
  e.preventDefault();
  hidePopover();
  if (e.ctrlKey || e.metaKey) {
    var rect = viewport.getBoundingClientRect();
    zoomAt(container, e.deltaY < 0 ? ZOOM_WHEEL_FACTOR : 1 / ZOOM_WHEEL_FACTOR,
      e.clientX - rect.left, e.clientY - rect.top);
    return;
  }
  panBy(container, -e.deltaX, -e.deltaY);
}

// handlePointerDown starts a background pan. A press that lands on a card is
// left alone: cards are the hover surface, and a graph where brushing a node
// dragged the whole view would be miserable.
function handlePointerDown(e, container) {
  if (e.button !== 0) return;
  var viewport = e.target.closest('[data-role="viewport"]');
  if (!viewport || e.target.closest(".agraph-card")) return;
  var startX = e.clientX, startY = e.clientY;
  var startT = uiState.transform ? { x: uiState.transform.x, y: uiState.transform.y, k: uiState.transform.k } : null;
  if (!startT) return;
  var moved = false;
  function onMove(ev) {
    var dx = ev.clientX - startX, dy = ev.clientY - startY;
    if (!moved && Math.abs(dx) < DRAG_THRESHOLD_PX && Math.abs(dy) < DRAG_THRESHOLD_PX) return;
    if (!moved) {
      moved = true;
      panning = true;
      viewport.classList.add("agraph-grabbing");
      hidePopover();
    }
    uiState.transform = { x: startT.x + dx, y: startT.y + dy, k: startT.k };
    uiState.userAdjusted = true;
    applyTransform(container);
  }
  function onUp() {
    window.removeEventListener("pointermove", onMove);
    window.removeEventListener("pointerup", onUp);
    viewport.classList.remove("agraph-grabbing");
    panning = false;
  }
  window.addEventListener("pointermove", onMove);
  window.addEventListener("pointerup", onUp);
}

// ---- timers ----

// ensureTicking keeps the elapsed clocks moving without re-rendering anything.
// It stops itself as soon as there is nobody to see it: the tab was switched
// away (the pane is display:none, so it has no offsetParent), or the whole view
// was torn down. The next render starts it again.
function ensureTicking(container) {
  if (tickTimer) return;
  tickTimer = setInterval(function () {
    if (!lastContainer || !lastContainer.isConnected || lastContainer.offsetParent === null) {
      clearInterval(tickTimer);
      tickTimer = null;
      return;
    }
    var els = lastContainer.querySelectorAll('[data-role="elapsed"]');
    for (var i = 0; i < els.length; i++) {
      els[i].textContent = elapsedLabel(els[i].dataset.since);
    }
  }, TICK_MS);
}

// scheduleExitSweep re-renders once the oldest fading card has served its time,
// which is what actually removes it from the DOM.
function scheduleExitSweep(remaining) {
  clearTimeout(exitTimer);
  exitTimer = null;
  if (remaining === null || remaining === undefined) return;
  exitTimer = setTimeout(function () {
    if (!lastContainer || !lastContainer.isConnected) return;
    renderShell(lastContainer, lastData, lastApi);
  }, Math.max(50, remaining + 20));
}

// ---- hover popover ----
//
// One shared element, built lazily on first hover: pre-rendering a hundred rows
// for every node would mean thousands nobody asked for. Nodes are resolved by
// comparing dataset values, NEVER by building an attribute selector out of an
// agent id — ids are workload-controlled and may contain quotes.
//
// The panel is REACHABLE: it stays open while the pointer is over its node or
// over the panel itself, with a short grace timer covering the gap between them,
// so its scrollback can actually be read and scrolled. That is why it takes
// pointer events (see app.css) — the hover bookkeeping below is what stops it
// from stealing hover from the card it describes.

function ensurePopover(container) {
  if (popoverEl && popoverEl.isConnected) return popoverEl;
  popoverEl = document.createElement("div");
  popoverEl.className = "agraph-popover hidden";
  container.appendChild(popoverEl); // re-appended after each rebuild, since the caller empties the container
  return popoverEl;
}

function findCard(container, agentId) {
  var cards = container.querySelectorAll(".agraph-card");
  for (var i = 0; i < cards.length; i++) {
    if (cards[i].dataset.agentId === agentId) return cards[i];
  }
  return null;
}

function findNode(agentId) {
  if (!lastData) return null;
  var model = buildNodes(lastData, lastApi);
  var node = model.byId.get(agentId);
  if (node) return node;
  var sat = lastData.sessionEnded ? null : unattributedNode(lastData);
  return sat && sat.id === agentId ? sat : null;
}

function popoverBodyHtml(node, data, api) {
  var members = node.members || [];
  var start = Math.max(0, members.length - POPOVER_LINES);
  var rows = [];
  for (var i = start; i < members.length; i++) {
    var idx = members[i];
    var ev = data.events[idx];
    if (!ev) continue;
    var s = api.toolActivitySummary(ev);
    var text = s.text || "";
    var desc = s.desc || "";
    rows.push(
      '<div class="agraph-pop-row">' +
        '<span class="agraph-pop-ts mono-num">' + api.esc(data.tsLabel[idx] || "") + "</span>" +
        '<span class="agraph-tick-tool">' + api.esc(s.tool) + "</span>" +
        '<span class="agraph-pop-text">' +
          (text ? api.esc(truncateEnd(text, POPOVER_TEXT_TRUNC)) : '<span class="empty">(no argument)</span>') +
          (desc ? ' <span class="meta">' + api.esc(truncateEnd(desc, POPOVER_TEXT_TRUNC)) + "</span>" : "") +
        "</span>" +
      "</div>"
    );
  }
  var shown = members.length - start;
  var head = '<div class="agraph-pop-hdr">' +
    '<span class="agraph-avatar" aria-hidden="true">' + api.esc(node.avatar) + "</span>" +
    "<strong>" + api.esc(node.title) + "</strong>" +
    node.strengthChip +
    "</div>" +
    '<div class="meta agraph-pop-sub">' + api.esc(node.id) +
      (members.length > shown ? " · showing the last " + api.numFmt(shown) + " of " + api.numFmt(members.length) : "") +
    "</div>";
  return head + (rows.length ? rows.join("") : '<div class="empty">no actions recorded yet</div>');
}

// positionPopover parks the panel beside its card and clamps it into the
// viewport, so a node near an edge never opens off screen. The gap is deliberately
// tiny: the pointer has to be able to cross it before the grace timer expires.
// The card is measured with a client rect on purpose — unlike the edges, this
// panel is positioned in SCREEN coordinates, so it must follow the card to
// wherever the current pan/zoom actually put it.
function positionPopover(el, card) {
  var r = card.getBoundingClientRect();
  var w = Math.min(POPOVER_W, window.innerWidth - POPOVER_MARGIN * 2);
  var left = Math.min(Math.max(POPOVER_MARGIN, r.left + r.width / 2 - w / 2), window.innerWidth - w - POPOVER_MARGIN);
  el.style.width = w + "px";
  el.style.left = left + "px";
  var below = window.innerHeight - r.bottom;
  if (below > 220 || below > r.top) {
    el.style.top = (r.bottom + POPOVER_GAP) + "px";
    el.style.bottom = "auto";
  } else {
    el.style.top = "auto";
    el.style.bottom = (window.innerHeight - r.top + POPOVER_GAP) + "px";
  }
}

function showPopover(container, card) {
  var agentId = card.dataset.agentId;
  if (!agentId) return;
  var node = findNode(agentId);
  if (!node) return;
  cancelHidePopover();
  var el = ensurePopover(container);
  // Re-anchoring the SAME agent (a live poll rebuilt the pane under the pointer)
  // keeps the reader's place in the scrollback; a different agent starts at the
  // top of its own history. The offset is read from popoverScroll rather than
  // from the element, because the rebuild detached the old panel — and a detached
  // element reports a scrollTop of zero.
  var keepScroll = agentId === popoverAgentId ? popoverScroll : 0;
  el.innerHTML = popoverBodyHtml(node, lastData, lastApi);
  el.classList.remove("hidden");
  positionPopover(el, card);
  el.scrollTop = keepScroll;
  popoverScroll = el.scrollTop; // clamped by the browser if the new body is shorter
  popoverAgentId = agentId;
}

// reopenPopover re-anchors an open popover after a rebuild, so a live poll tick
// doesn't yank the panel out from under the pointer; if the agent it described
// is gone, it closes instead of describing a card that no longer exists.
function reopenPopover(container) {
  var card = findCard(container, popoverAgentId);
  if (!card) { hidePopover(); return; }
  showPopover(container, card);
}

function hidePopover() {
  cancelHidePopover();
  popoverAgentId = null;
  popoverScroll = 0;
  if (popoverEl) popoverEl.classList.add("hidden");
}

// scheduleHidePopover is the hover-intent grace window: leaving the card does
// not close the panel immediately, because the most common reason to leave a
// card is to move INTO the panel and scroll it. Entering either end cancels it.
function scheduleHidePopover() {
  cancelHidePopover();
  popoverHideTimer = setTimeout(function () {
    popoverHideTimer = null;
    hidePopover();
  }, HOVER_GRACE_MS);
}

function cancelHidePopover() {
  if (popoverHideTimer === null) return;
  clearTimeout(popoverHideTimer);
  popoverHideTimer = null;
}

// stillWithinPopoverPair reports whether the pointer merely moved between the
// card and its panel (or around inside either), which must not close anything.
function stillWithinPopoverPair(container, from, to) {
  if (!to) return false;
  if (popoverEl && popoverEl.contains(to)) return true;
  var card = findCard(container, popoverAgentId);
  if (card && card.contains(to)) return true;
  return !!(from && from.contains && from.contains(to));
}

// ---- event binding (delegated on the stable container, bound exactly once,
// since app.js reuses the same container across every render() call) ----

function ensureBound(container) {
  if (boundContainers.has(container)) return;
  boundContainers.add(container);

  // mouseenter doesn't bubble, so hover is delegated through mouseover/mouseout
  // with a relatedTarget check — one listener for every card, now and after
  // every rebuild. The panel is inside this same container, so its own hover
  // arrives here too, which is exactly what keeps it open while it is read.
  container.addEventListener("mouseover", function (e) {
    if (panning) return; // a background drag is not a hover
    if (popoverEl && popoverEl.contains(e.target)) { cancelHidePopover(); return; }
    var card = e.target.closest(".agraph-card");
    if (!card || !card.dataset.agentId) return;
    if (card.dataset.agentId === popoverAgentId) { cancelHidePopover(); return; }
    showPopover(container, card);
  });
  container.addEventListener("mouseout", function (e) {
    var inPopover = popoverEl && popoverEl.contains(e.target);
    var card = e.target.closest(".agraph-card");
    if (!inPopover && !card) return;
    if (stillWithinPopoverPair(container, inPopover ? popoverEl : card, e.relatedTarget)) return;
    scheduleHidePopover();
  });
  // scroll doesn't bubble, so this is a capture listener. The panel scrolling
  // ITSELF is not a dismissal — it is the whole point of making it reachable —
  // so that case only records where the reader has got to.
  container.addEventListener("scroll", function (e) {
    if (popoverEl && popoverEl.contains(e.target)) {
      popoverScroll = popoverEl.scrollTop;
      return;
    }
    hidePopover();
  }, true);

  // Navigation. The wheel listener is explicitly non-passive because it calls
  // preventDefault: inside the pane the wheel drives the graph, not the page.
  container.addEventListener("wheel", function (e) { handleWheel(e, container); }, { passive: false });
  container.addEventListener("pointerdown", function (e) { handlePointerDown(e, container); });
  container.addEventListener("dblclick", function (e) {
    if (e.target.closest(".agraph-card") || !e.target.closest('[data-role="viewport"]')) return;
    resetView(container);
  });
  container.addEventListener("click", function (e) {
    var btn = e.target.closest('[data-act="graph-fit"]');
    if (btn) resetView(container);
  });

  if (!resizeBound) {
    resizeBound = true;
    // Card positions are measured, so a resize (or a sidebar/pane reflow) has to
    // re-measure them; the cards themselves are laid out by flexbox and need no
    // re-render. The framing is recomputed too, unless the user has navigated —
    // their view survives a window resize like it survives a poll.
    window.addEventListener("resize", debounce(function () {
      if (!lastContainer || !lastContainer.isConnected) return;
      hidePopover();
      drawEdges(lastContainer);
      applyViewTransform(lastContainer);
    }, RESIZE_DEBOUNCE_MS));
  }
}

// ---- render entry point ----

function render(container, data, api) {
  lastContainer = container;
  lastData = data;
  lastApi = api;
  resetForSession(data.sessionId);
  ensureBound(container);
  renderShell(container, data, api);
}

window.BoxedAiAgentGraph = {
  render: render,
  _buildNodes: buildNodes,
};

})();
