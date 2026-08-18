const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");

function loadClient() {
  class FakeEventSource {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSED = 2;
    static instances = [];

    constructor(url) {
      this.url = url;
      this.readyState = FakeEventSource.CONNECTING;
      this.listeners = {};
      this.closed = false;
      FakeEventSource.instances.push(this);
    }

    addEventListener(type, listener) {
      this.listeners[type] = listener;
    }

    close() {
      this.closed = true;
      this.readyState = FakeEventSource.CLOSED;
    }

    open() {
      this.readyState = FakeEventSource.OPEN;
      this.onopen();
    }

    fail() {
      this.readyState = FakeEventSource.CONNECTING;
      this.onerror();
    }

    emit(type, data, lastEventId) {
      this.listeners[type]({ data: data, lastEventId: lastEventId || "" });
    }
  }

  const context = {
    Date: Date,
    EventSource: FakeEventSource,
    JSON: JSON,
    Map: Map,
    Set: Set,
    clearTimeout: clearTimeout,
    console: console,
    document: { addEventListener: function () {} },
    location: { hash: "" },
    navigator: {},
    setTimeout: setTimeout,
    window: {},
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  return { client: context, FakeEventSource: FakeEventSource };
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

function event(seq, body) {
  return {
    seq: seq,
    ts: "2026-08-17T12:00:0" + seq + "Z",
    name: "tool.requested",
    class: "BROKER_MEDIATED",
    badge: "BROKER",
    producer: "broker",
    body: body,
    attrs: { "tool.name": "example" },
  };
}

test("event source owner fences superseded callbacks and closes every source", function () {
  const loaded = loadClient();
  const states = [];
  const delivered = [];
  const malformed = [];
  const owner = loaded.client.createEventSourceOwner({
    eventTypes: ["session.snapshot", "session.delta"],
    onState: function (state) { states.push(state); },
    onEvent: function (type, payload) { delivered.push([type, payload]); },
    onMalformed: function (type) { malformed.push(type); },
  });

  owner.open("/api/stream");
  const first = loaded.FakeEventSource.instances[0];
  assert.deepEqual(states, ["connecting"]);
  first.open();
  first.emit("session.snapshot", JSON.stringify({ session_id: "one", events: [] }));
  assert.equal(states.at(-1), "live");
  assert.deepEqual(plain(delivered), [["session.snapshot", { session_id: "one", events: [] }]]);

  first.emit("session.delta", "{");
  assert.deepEqual(malformed, ["session.delta"]);
  assert.equal(states.at(-1), "stale");

  owner.restart();
  const second = loaded.FakeEventSource.instances[1];
  assert.equal(first.closed, true);
  first.emit("session.delta", JSON.stringify({ session_id: "one", events: [event(1, "late")] }));
  assert.equal(delivered.length, 1);

  owner.open("/api/stream?session=two");
  const third = loaded.FakeEventSource.instances[2];
  assert.equal(second.closed, true);
  second.open();
  assert.notEqual(states.at(-1), "live");

  third.fail();
  assert.equal(states.at(-1), "reconnecting");
  assert.equal(loaded.FakeEventSource.instances.length, 3);

  owner.close("paused");
  assert.equal(third.closed, true);
  assert.equal(states.at(-1), "paused");
});

test("event source restart and ensure never create competing live connections", function () {
  const loaded = loadClient();
  const owner = loaded.client.createEventSourceOwner({
    eventTypes: [],
    onState: function () {},
    onEvent: function () {},
    onMalformed: function () {},
  });

  owner.open("/api/stream?session=one");
  owner.ensure("/api/stream?session=one");
  assert.equal(loaded.FakeEventSource.instances.length, 1);

  owner.restart();
  assert.equal(loaded.FakeEventSource.instances.length, 2);
  assert.equal(loaded.FakeEventSource.instances[0].closed, true);

  owner.ensure("/api/stream");
  assert.equal(loaded.FakeEventSource.instances.length, 3);
  assert.equal(loaded.FakeEventSource.instances[1].closed, true);
  assert.equal(loaded.client.dashboardStreamURL("one", true), "/api/stream?session=one");
  assert.equal(loaded.client.dashboardStreamURL("one", false), "/api/stream");
});

test("standalone Live and manual refresh retain data and keep one source", async function () {
  const loaded = loadClient();
  const states = [];
  const fetches = [];
  let viewOptions;
  let payload = null;
  let live = false;
  let view;

  loaded.client.window.addEventListener = function () {};
  loaded.client.fetch = function (url) {
    fetches.push(url);
    return Promise.resolve({
      json: function () {
        return Promise.resolve({
          session_id: "one",
          state: "running",
          proof: { status: "provisional", provisional: true },
          events: [event(1, "one"), event(2, "manual")],
        });
      },
    });
  };
  loaded.client.createSessionView = function (_root, options) {
    viewOptions = options;
    view = {
      setPayload: function (next) {
        const initial = payload === null;
        payload = next;
        if (initial && next.proof && next.proof.provisional) {
          live = true;
          options.onLiveToggle(true);
        }
      },
      getPayload: function () { return payload; },
      setConnectionState: function (state) { states.push(state); },
      isLive: function () { return live; },
      setLive: function (on) {
        if (live === on) return;
        live = on;
        options.onLiveToggle(on);
      },
    };
    return view;
  };

  loaded.client.mountStandalone({});
  const first = loaded.FakeEventSource.instances[0];
  first.open();
  first.emit("session.snapshot", JSON.stringify({
    session_id: "one",
    state: "running",
    proof: { status: "provisional", provisional: true },
    events: [event(1, "one")],
  }));
  assert.equal(loaded.FakeEventSource.instances.length, 1);
  assert.equal(payload.events.length, 1);

  view.setLive(false);
  assert.equal(first.closed, true);
  first.emit("session.delta", JSON.stringify({
    session_id: "one",
    state: "running",
    events: [event(2, "late")],
    event_count: 2,
    last_event_seq: 2,
  }));
  assert.equal(payload.events.length, 1);

  viewOptions.onManualRefresh();
  await new Promise(function (resolve) { setImmediate(resolve); });
  assert.deepEqual(fetches, ["/api/events"]);
  assert.equal(payload.events.at(-1).body, "manual");

  view.setLive(true);
  const second = loaded.FakeEventSource.instances[1];
  viewOptions.onManualRefresh();
  const third = loaded.FakeEventSource.instances[2];
  assert.equal(second.closed, true);
  assert.deepEqual(fetches, ["/api/events"]);

  third.emit("session.delta", "{");
  const fourth = loaded.FakeEventSource.instances[3];
  assert.equal(third.closed, true);
  assert.equal(payload.events.at(-1).body, "manual");
  assert.equal(states.includes("stale"), true);

  fourth.emit("session.snapshot", JSON.stringify({
    session_id: "one",
    state: "sealed",
    proof: { status: "sealed", provisional: false },
    events: [event(1, "one"), event(2, "manual")],
  }));
  assert.equal(fourth.closed, true);
  assert.equal(states.at(-1), "complete");
});

test("dashboard selection and Live changes replace the page source", function () {
  const loaded = loadClient();
  const delivered = [];
  loaded.client.writeHashObjectMerged = function () {};
  loaded.client.renderSidebarList = function () {};
  const dash = {
    selectedId: "",
    detailLive: false,
    detailComplete: false,
    owner: loaded.client.createEventSourceOwner({
      eventTypes: ["session.snapshot"],
      onState: function () {},
      onEvent: function (type, payload) { delivered.push([type, payload]); },
      onMalformed: function () {},
    }),
  };

  loaded.client.selectDashboardSession(dash, "one");
  const first = loaded.FakeEventSource.instances[0];
  loaded.client.selectDashboardSession(dash, "two");
  const second = loaded.FakeEventSource.instances[1];
  assert.equal(first.closed, true);
  assert.equal(first.url, "/api/stream?session=one");
  assert.equal(second.url, "/api/stream?session=two");

  first.emit("session.snapshot", JSON.stringify({ session_id: "one", events: [] }));
  assert.equal(delivered.length, 0);
  dash.detailLive = false;
  dash.owner.ensure(loaded.client.dashboardStreamURL(dash.selectedId, false));
  const globalOnly = loaded.FakeEventSource.instances[2];
  assert.equal(second.closed, true);
  assert.equal(globalOnly.url, "/api/stream");
});

test("dashboard Live and manual refresh exercise embedded callbacks", async function () {
  const loaded = loadClient();
  const fetches = [];
  const states = [];
  let live = true;
  let payload = null;
  let viewOptions;

  loaded.client.fetch = function (url) {
    fetches.push(url);
    return Promise.resolve({
      json: function () {
        return Promise.resolve({
          session_id: "one",
          state: "running",
          proof: { status: "provisional", provisional: true },
          events: [event(1, "one"), event(2, "manual dashboard")],
        });
      },
    });
  };
  loaded.client.createSessionView = function (_root, options) {
    viewOptions = options;
    return {
      setPayload: function (next) { payload = next; },
      getPayload: function () { return payload; },
      setConnectionState: function (state) { states.push(state); },
      isLive: function () { return live; },
      setLive: function (on) {
        if (live === on) return;
        live = on;
        options.onLiveToggle(on);
      },
      destroy: function () {},
    };
  };

  const dash = {
    selectedId: "one",
    detailLive: true,
    detailComplete: false,
    streamState: "connecting",
    owner: null,
    view: null,
    els: { main: { innerHTML: "" } },
  };
  dash.owner = loaded.client.createEventSourceOwner({
    eventTypes: [],
    onState: function (state) { loaded.client.updateDashboardConnectionState(dash, state); },
    onEvent: function () {},
    onMalformed: function () {},
  });
  dash.owner.open("/api/stream?session=one");
  loaded.client.ensureDashboardView(dash);

  const first = loaded.FakeEventSource.instances[0];
  dash.view.setLive(false);
  const globalOnly = loaded.FakeEventSource.instances[1];
  assert.equal(dash.detailLive, false);
  assert.equal(first.closed, true);
  assert.equal(globalOnly.url, "/api/stream");
  assert.equal(states.at(-1), "paused");

  viewOptions.onManualRefresh();
  await new Promise(function (resolve) { setImmediate(resolve); });
  assert.deepEqual(fetches, ["/api/session?id=one"]);
  assert.equal(payload.events.at(-1).body, "manual dashboard");
  assert.equal(loaded.FakeEventSource.instances.length, 2);

  dash.view.setLive(true);
  const selected = loaded.FakeEventSource.instances[2];
  assert.equal(dash.detailLive, true);
  assert.equal(dash.detailComplete, false);
  assert.equal(globalOnly.closed, true);
  assert.equal(selected.url, "/api/stream?session=one");

  viewOptions.onManualRefresh();
  const restarted = loaded.FakeEventSource.instances[3];
  assert.equal(selected.closed, true);
  assert.equal(restarted.url, "/api/stream?session=one");
  assert.deepEqual(fetches, ["/api/session?id=one"]);
  dash.owner.close();
});

test("session delta reducer appends ordered records and suppresses harmless overlap", function () {
  const loaded = loadClient();
  const current = {
    session_id: "one",
    state: "running",
    proof: { status: "provisional", provisional: true },
    events: [event(1, "one"), event(2, "two")],
  };
  const result = loaded.client.reduceSessionDelta(current, {
    session_id: "one",
    state: "running",
    events: [event(2, "two"), event(3, "three")],
    event_count: 3,
    last_event_seq: 3,
    last_event_ts: "2026-08-17T12:00:03Z",
  });

  assert.equal(result.kind, "applied");
  assert.deepEqual(plain(result.payload.events), [event(1, "one"), event(2, "two"), event(3, "three")]);
  assert.equal(result.payload.proof.status, "provisional");
  assert.equal(current.events.length, 2);

  const lifecycleOnly = loaded.client.reduceSessionDelta(result.payload, {
    session_id: "one",
    state: "sealed",
    events: [],
    event_count: 3,
    last_event_seq: 3,
    last_event_ts: "2026-08-17T12:00:03Z",
  });
  assert.equal(lifecycleOnly.kind, "applied");
  assert.equal(lifecycleOnly.payload.state, "sealed");
  assert.deepEqual(plain(lifecycleOnly.payload.events), plain(result.payload.events));
});

test("session snapshot reducer accepts ordered initial state and rejects stale sessions", function () {
  const loaded = loadClient();
  const snapshot = {
    session_id: "one",
    state: "running",
    proof: { status: "provisional", provisional: true },
    events: [event(1, "one"), event(2, "two")],
  };

  assert.equal(loaded.client.reduceSessionSnapshot(snapshot, "one").kind, "applied");
  assert.equal(loaded.client.reduceSessionSnapshot(snapshot, "two").kind, "reset");
  assert.equal(loaded.client.reduceSessionSnapshot({
    session_id: "one",
    events: [event(2, "two"), event(1, "one")],
  }, "one").kind, "reset");
});

test("session delta reducer resets on gaps conflicts and malformed order", function () {
  const loaded = loadClient();
  const current = {
    session_id: "one",
    state: "running",
    proof: { status: "provisional", provisional: true },
    events: [event(1, "one"), event(2, "two")],
  };

  assert.equal(loaded.client.reduceSessionDelta(current, {
    session_id: "one",
    events: [event(4, "four")],
    event_count: 4,
    last_event_seq: 4,
  }).kind, "reset");
  assert.equal(loaded.client.reduceSessionDelta(current, {
    session_id: "one",
    events: [event(2, "changed")],
    event_count: 2,
    last_event_seq: 2,
  }).kind, "reset");
  assert.equal(loaded.client.reduceSessionDelta(current, {
    session_id: "one",
    events: [event(3, "three"), event(2, "two")],
    event_count: 3,
    last_event_seq: 3,
  }).kind, "reset");
  assert.equal(loaded.client.reduceSessionDelta(current, {
    session_id: "two",
    events: [],
    event_count: 0,
    last_event_seq: 0,
  }).kind, "reset");
});

test("dashboard reducers preserve running-first ordering and remove only the target", function () {
  const loaded = loadClient();
  const history = { session_id: "bx-3", state: "sealed" };
  const runningOld = { session_id: "bx-1", state: "running" };
  const runningNew = { session_id: "bx-2", state: "running" };

  let sessions = loaded.client.reduceSessionsSnapshot({ sessions: [history, runningOld, runningNew] });
  assert.deepEqual(plain(sessions).map(function (item) { return item.session_id; }), ["bx-2", "bx-1", "bx-3"]);

  sessions = loaded.client.reduceSessionsUpsert(sessions, { session_id: "bx-2", state: "sealed" });
  assert.deepEqual(plain(sessions).map(function (item) { return item.session_id; }), ["bx-1", "bx-3", "bx-2"]);

  const removed = loaded.client.reduceSessionsRemove(sessions, { session_id: "bx-3" });
  assert.equal(removed.removedId, "bx-3");
  assert.deepEqual(plain(removed.sessions).map(function (item) { return item.session_id; }), ["bx-1", "bx-2"]);
  assert.equal(loaded.client.reduceSessionsSnapshot({ sessions: "bad" }), null);
});

test("streamed payloads preserve interaction state and escape adversarial content", function () {
  const loaded = loadClient();
  loaded.client.buildModel = function (events) { return { events: events.slice() }; };
  loaded.client.extendModel = function (model, events) { model.events = events.slice(); };
  loaded.client.renderHeader = function () {};
  loaded.client.renderTabsBar = function () {};
  loaded.client.renderActiveTab = function () {};
  loaded.client.resetTimelineChunk = function () {};
  loaded.client.timelineDisplayIndices = function () { return []; };
  const scroll = { scrollTop: 73 };
  loaded.client.activeScrollEl = function () { return scroll; };

  const firstEvent = event(1, "one");
  const state = loaded.client.defaultState();
  state.tab = "agents";
  state.sort = "asc";
  state.search = "needle";
  state.liveOn = true;
  state.expandedSeqs.add(1);
  state.expandedActionGroups.add("action-one");
  state.expandedFilePaths.add("one.txt");
  state.expandedFileDiffs.add("one.txt:1:2");
  const ctx = {
    state: state,
    payload: {
      session_id: "one",
      state: "running",
      proof: { status: "provisional", provisional: true },
      events: [firstEvent],
    },
    model: { events: [firstEvent] },
    agentActivityNames: new loaded.client.Set(),
    diffCache: new loaded.client.Map([["one.txt:1:2", "cached"]]),
    els: {},
    prevSummary: { len: 1, lastSeq: 1, state: "running", status: "provisional", verifyError: "" },
    timelineFiltered: null,
    onLiveToggle: function () {},
  };

  loaded.client.setSessionViewPayload(ctx, {
    session_id: "one",
    state: "running",
    proof: { status: "provisional", provisional: true },
    events: [firstEvent, event(2, `<img src=x onerror="boom">`)],
  });
  assert.equal(ctx.state.tab, "agents");
  assert.equal(ctx.state.sort, "asc");
  assert.equal(ctx.state.search, "needle");
  assert.equal(ctx.state.expandedSeqs.has(1), true);
  assert.equal(ctx.state.expandedActionGroups.has("action-one"), true);
  assert.equal(ctx.state.expandedFilePaths.has("one.txt"), true);
  assert.equal(ctx.state.expandedFileDiffs.has("one.txt:1:2"), true);
  assert.equal(ctx.diffCache.get("one.txt:1:2"), "cached");
  assert.equal(scroll.scrollTop, 73);
  assert.equal(ctx.payload.events.length, 2);

  const header = loaded.client.headerHtml({
    payload: {
      session_id: `<img src=x onerror="session">`,
      state: "running",
      policy_digest: `"><svg onload="digest">`,
      proof: { status: "provisional", provisional: true },
      events: [firstEvent, event(2, "two")],
    },
    state: ctx.state,
    connectionState: "live",
    lastUpdatedAt: "2026-08-17T12:00:02Z",
  });
  assert.match(header, /2 events/);
  assert.equal(header.includes("last " + loaded.client.fmtClockShort("2026-08-17T12:00:02Z")), true);
  assert.match(header, /provisional<span class="pulse-text"> · live<\/span>/);
  assert.match(header, /class="chip connection-state"[^>]*>live<\/span>/);
  assert.match(header, /data-act="live-toggle" checked/);
  assert.equal(header.includes("updated " + loaded.client.fmtClockShort("2026-08-17T12:00:02Z")), true);
  assert.doesNotMatch(header, /<img src=x/);
  assert.doesNotMatch(header, /<svg onload/);
  assert.match(header, /&lt;img src=x/);

  loaded.client.setSessionViewPayload(ctx, {
    session_id: "two",
    state: "running",
    proof: { status: "provisional", provisional: true },
    events: [event(1, "new session")],
  });
  assert.equal(ctx.state.tab, "agents");
  assert.equal(ctx.state.sort, "asc");
  assert.equal(ctx.state.search, "needle");
  assert.equal(ctx.state.expandedSeqs.size, 0);
  assert.equal(ctx.state.expandedActionGroups.size, 0);
  assert.equal(ctx.state.expandedFilePaths.size, 0);
  assert.equal(ctx.state.expandedFileDiffs.size, 0);
  assert.equal(ctx.diffCache.size, 0);

  const detail = loaded.client.timelineDetailRowHtml({
    seq: 2,
    name: "tool.requested",
    body: `<img src=x onerror="boom">`,
    attrs: { "bad<key>": `<script>alert("x")</script>` },
  });
  assert.doesNotMatch(detail, /<img src=x/);
  assert.doesNotMatch(detail, /<script>alert/);
  assert.match(detail, /&lt;img src=x/);
  assert.match(detail, /&lt;script&gt;/);
});

test("browser delivery path contains no summary or detail polling machinery", function () {
  assert.doesNotMatch(source, /\bPOLL_MS\b/);
  assert.doesNotMatch(source, /\bDASH_POLL_MS\b/);
  assert.doesNotMatch(source, /\bstartPolling\b/);
  assert.doesNotMatch(source, /\bpollDashboardSessions\b/);
});
