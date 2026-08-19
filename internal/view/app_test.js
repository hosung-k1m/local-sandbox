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

function bashRequest(seq, command, parentPID, parentExecID) {
  return {
    seq: seq,
    ts: "2026-08-19T12:00:0" + seq + "Z",
    name: "tool.requested",
    class: "harness_observed",
    badge: "HARNESS",
    producer: "workload",
    attrs: {
      "tool.name": "Bash",
      "harness.tool.input": JSON.stringify({ command: command }),
      "process.parent_pid": parentPID,
      "process.parent_exec_id": parentExecID || "parent-exec-" + parentPID,
    },
  };
}

function kernelExecution(seq, argv, parentPID, parentExecID, execID) {
  return {
    seq: seq,
    ts: "2026-08-19T12:00:" + seq + "Z",
    name: "process.executed",
    class: "kernel_observed",
    badge: "KERNEL",
    producer: "guest_supervisor",
    attrs: {
      "process.argv": argv,
      "process.parent_pid": parentPID,
      "process.parent_exec_id": parentExecID || "parent-exec-" + parentPID,
      "process.exec.id": execID || "exec-" + seq,
    },
  };
}

function kernelCreation(seq, pid, parentPID, parentExecID) {
  return {
    seq: seq,
    ts: "2026-08-19T12:00:" + seq + "Z",
    name: "process.created",
    class: "kernel_observed",
    badge: "KERNEL",
    producer: "guest_supervisor",
    attrs: {
      "process.pid": pid,
      "process.parent_pid": parentPID,
      "process.parent_exec_id": parentExecID,
    },
  };
}

function claudeEvalWrapperArgv(command) {
  return "-c \"source /home/agent/.claude/shell-snapshots/snapshot-bash-1787084693475-00k93e.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval '" +
    command.replace(/'/g, "'\"'\"'") +
    "' < /dev/null && pwd -P >| /tmp/claude-e0e7-cwd\"";
}

function authenticatedBashLineage(rootSeq, requestSeq, wrapperSeq, command) {
  const claudePID = 10000 + rootSeq;
  const hookWrapperPID = claudePID + 1;
  const hookPID = claudePID + 2;
  const wrapperPID = claudePID + 3;
  const claudeExecID = "claude-exec-" + rootSeq;
  const hookWrapperExecID = "hook-wrapper-exec-" + rootSeq;
  const hookExecID = "hook-exec-" + rootSeq;
  const claude = kernelExecution(rootSeq, "--debug-file /home/agent/.claude/debug/claude-code.log", claudePID, "session-exec-" + rootSeq, claudeExecID);
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = claudePID;
  const hookWrapper = kernelExecution(rootSeq + 1, "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"", claudePID, claudeExecID, hookWrapperExecID);
  hookWrapper.attrs["process.binary"] = "/bin/sh";
  hookWrapper.attrs["process.pid"] = hookWrapperPID;
  const hook = kernelExecution(rootSeq + 2, "lefthook", hookWrapperPID, hookWrapperExecID, hookExecID);
  hook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  hook.attrs["process.pid"] = hookPID;
  const request = bashRequest(requestSeq, command, hookWrapperPID);
  request.attrs["process.pid"] = hookPID;
  const wrapper = kernelExecution(wrapperSeq, claudeEvalWrapperArgv(command), claudePID, claudeExecID, "bash-wrapper-exec-" + rootSeq);
  wrapper.attrs["process.binary"] = "/bin/bash";
  wrapper.attrs["process.pid"] = wrapperPID;
  return { claude: claude, hookWrapper: hookWrapper, hook: hook, request: request, wrapper: wrapper,
    events: [claude, hookWrapper, hook, request, wrapper] };
}

function authenticatedHookCycle(claude, seed, requestSeq, wrapperSeq, command) {
  const claudePID = claude.attrs["process.pid"];
  const claudeExecID = claude.attrs["process.exec.id"];
  const hookWrapperPID = 20000 + seed;
  const hookPID = hookWrapperPID + 1;
  const hookWrapperExecID = "hook-wrapper-exec-" + seed;
  const hookWrapper = kernelExecution(seed, "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"", claudePID, claudeExecID, hookWrapperExecID);
  hookWrapper.attrs["process.binary"] = "/bin/sh";
  hookWrapper.attrs["process.pid"] = hookWrapperPID;
  const hook = kernelExecution(seed + 1, "lefthook", hookWrapperPID, hookWrapperExecID, "hook-exec-" + seed);
  hook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  hook.attrs["process.pid"] = hookPID;
  const request = bashRequest(requestSeq, command, hookWrapperPID);
  request.attrs["process.pid"] = hookPID;
  const wrapper = kernelExecution(wrapperSeq, claudeEvalWrapperArgv(command), claudePID, claudeExecID, "bash-wrapper-exec-" + seed);
  wrapper.attrs["process.binary"] = "/bin/bash";
  wrapper.attrs["process.pid"] = hookPID + 1;
  return { hookWrapper: hookWrapper, hook: hook, request: request, wrapper: wrapper,
    events: [hookWrapper, hook, request, wrapper] };
}

test("Bash derivation rejects a forged direct request without kernel hook lineage", function () {
  const loaded = loadClient();
  const events = [
    bashRequest(10, "pwd", 41),
    kernelExecution(11, "pwd", 41),
  ];
  const result = loaded.client.deriveBashProcessLinks(events);

  assert.equal(result.requestLinks.has(10), false);
  assert.equal(result.executionClassification.get(11), "unmatched");
});

test("Bash derivation links the faithful captured 2237 request through Claude's wrapper", function () {
  const loaded = loadClient();
  const claude = kernelExecution(
    9,
    "--debug-file /home/agent/.claude/debug/claude-code.log",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNTMyMzA5MjQ6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
  );
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = 1881;
  const hookWrapper = kernelExecution(
    2231,
    "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTIxOTc3MTU5NDc0OjMxMTI=",
  );
  hookWrapper.attrs["process.binary"] = "/bin/sh";
  hookWrapper.attrs["process.pid"] = 3112;
  const hook = kernelExecution(
    2233,
    "lefthook",
    3112,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTIxOTc3MTU5NDc0OjMxMTI=",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTIxOTc3ODU3NTk5OjMxMTM=",
  );
  hook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  hook.attrs["process.pid"] = 3113;
  const request = {
    seq: 2237,
    ts: "2026-08-18T20:25:34.409283Z",
    name: "tool.requested",
    class: "harness_observed",
    badge: "HARNESS",
    producer: "workload",
    attrs: {
      "tool.name": "Bash",
      "harness.tool.input": "{\"command\":\"echo waiting\"}",
      "process.parent_pid": 3112,
      "process.pid": 3113,
    },
  };
  const execution = {
    seq: 2241,
    ts: "2026-08-18T20:25:34.4257701Z",
    name: "process.executed",
    class: "kernel_observed",
    badge: "KERNEL",
    producer: "guest_supervisor",
    attrs: {
      "process.argv": "-c \"source /home/agent/.claude/shell-snapshots/snapshot-bash-1787084693475-00k93e.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'echo waiting' < /dev/null && pwd -P >| /tmp/claude-a600-cwd\"",
      "process.binary": "/bin/bash",
      "process.parent_pid": 1881,
      "process.parent_exec_id": "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
      "process.exec.id": "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTIxOTg5NTg0NzI0OjMxMTg=",
      "process.pid": 3118,
    },
  };

  const result = loaded.client.deriveBashProcessLinks([claude, hookWrapper, hook, request, execution]);

  assert.equal(result.requestLinks.get(2237).executionSeq, 2241);
  assert.equal(result.requestLinks.get(2237).argv, "echo waiting");
  assert.equal(result.requestLinks.get(2237).matchBasis, "guest_hook_lineage+claude_parent_exec_id+exact_claude_eval_command");
  assert.equal(result.executionClassification.get(2241), "matched");
  assert.equal(result.executionExemptions.get(2231), "boxedai_guest_agent_lefthook_shell_wrapper");
  assert.equal(result.executionExemptions.get(2233), "boxedai_guest_agent_lefthook");
});

test("Bash derivation keeps the faithful captured 266 Claude child with request 110", function () {
  const loaded = loadClient();
  const claude = kernelExecution(
    9,
    "--debug-file /home/agent/.claude/debug/claude-code.log",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNTMyMzA5MjQ6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
  );
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = 1881;
  const hookWrapper = kernelExecution(
    104,
    "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwMTEyODkwMzc6MTk2OQ==",
  );
  hookWrapper.attrs["process.binary"] = "/bin/sh";
  hookWrapper.attrs["process.pid"] = 1969;
  const hook = kernelExecution(
    106,
    "lefthook",
    1969,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwMTEyODkwMzc6MTk2OQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwMTE4NTQwMzc6MTk3MA==",
  );
  hook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  hook.attrs["process.pid"] = 1970;
  const request = {
    seq: 110,
    ts: "2026-08-18T20:24:53.445412Z",
    name: "tool.requested",
    class: "harness_observed",
    badge: "HARNESS",
    producer: "workload",
    attrs: {
      "tool.name": "Bash",
      "harness.tool.input": "{\"command\":\"find . -type d -iname \\\"*subagent*\\\" -not -path \\\"*/node_modules/*\\\" -not -path \\\"*/.git/*\\\"\"}",
      "process.parent_pid": 1969,
      "process.pid": 1970,
    },
  };
  const wrapper = kernelExecution(
    220,
    "-c \"source /home/agent/.claude/shell-snapshots/snapshot-bash-1787084693475-00k93e.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'find . -type d -iname \"*subagent*\" -not -path \"*/node_modules/*\" -not -path \"*/.git/*\"' < /dev/null && pwd -P >| /tmp/claude-e02b-cwd\"",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwODc3NDkxNjI6MjAxNg==",
  );
  wrapper.attrs["process.binary"] = "/bin/bash";
  wrapper.attrs["process.pid"] = 2016;
  const helperProcess = kernelCreation(
    221,
    2017,
    2016,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwODc3NDkxNjI6MjAxNg==",
  );
  const helperChildProcess = kernelCreation(
    224,
    2019,
    2017,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwODg2Njg5NTQ6MjAxNw==",
  );
  const helper = kernelExecution(
    225,
    "-d",
    2017,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwODg2Njg5NTQ6MjAxNw==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwODkyNTc0NTQ6MjAxOQ==",
  );
  helper.attrs["process.binary"] = "/usr/bin/base64";
  helper.attrs["process.pid"] = 2019;
  const child = kernelExecution(
    266,
    "-S dfs -regextype findutils-default . -type d -iname *subagent* -not -path */node_modules/* -not -path */.git/*",
    2016,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwODc3NDkxNjI6MjAxNg==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6ODEwOTY4OTUwMzc6MjAzNg==",
  );
  child.attrs["process.binary"] = "/usr/local/bin/claude";
  child.attrs["process.pid"] = 2036;
  const nearMiss = kernelExecution(267, "-d", 9999, "unrelated-parent-exec", "unrelated-base64-exec");
  nearMiss.attrs["process.binary"] = "/usr/bin/base64";

  const events = [
    claude,
    hookWrapper,
    hook,
    request,
    wrapper,
    helperProcess,
    helperChildProcess,
    helper,
    child,
    nearMiss,
  ];
  const result = loaded.client.deriveBashProcessLinks(events);

  assert.equal(result.requestLinks.get(110).executionSeq, 220);
  assert.equal(result.executionLinks.get(220), 110);
  assert.equal(result.executionLinks.get(225), 110);
  assert.equal(result.executionLinks.get(266), 110);
  assert.equal(result.executionClassification.get(225), "matched");
  assert.equal(result.executionClassification.get(266), "matched");
  assert.equal(result.executionClassification.get(267), "unmatched");
});

test("Bash derivation accepts the faithful 641 request when its direct hook arrives later", function () {
  const loaded = loadClient();
  const claude = kernelExecution(
    9,
    "--debug-file /home/agent/.claude/debug/claude-code.log",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNTMyMzA5MjQ6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
  );
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = 1881;
  const hookWrapper = kernelExecution(
    639,
    "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDAyNzMzOTIzOjIyNDA=",
  );
  hookWrapper.attrs["process.binary"] = "/bin/sh";
  hookWrapper.attrs["process.pid"] = 2240;
  const request = {
    seq: 641,
    ts: "2026-08-18T20:25:00.006341Z",
    name: "tool.requested",
    class: "harness_observed",
    badge: "HARNESS",
    producer: "workload",
    attrs: {
      "tool.name": "Bash",
      "harness.tool.input": "{\"command\":\"find /workspace/tiles/daily-summary -type f -not -path '*/node_modules/*' | sort\"}",
      "process.parent_pid": 2240,
      "process.pid": 2241,
    },
  };
  const hook = kernelExecution(
    642,
    "lefthook",
    2240,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDAyNzMzOTIzOjIyNDA=",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDAzMDg5NTkwOjIyNDE=",
  );
  hook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  hook.attrs["process.pid"] = 2241;
  const execution = kernelExecution(
    649,
    "-c \"source /home/agent/.claude/shell-snapshots/snapshot-bash-1787084693475-00k93e.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'find /workspace/tiles/daily-summary -type f -not -path '\"'\"'*/node_modules/*'\"'\"' | sort' < /dev/null && pwd -P >| /tmp/claude-e0e7-cwd\"",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDEyNjAxMjk4OjIyNDY=",
  );
  execution.attrs["process.binary"] = "/bin/bash";
  execution.attrs["process.pid"] = 2246;
  const bfsParent = kernelCreation(
    692,
    2266,
    2246,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDEyNjAxMjk4OjIyNDY=",
  );
  const sort = kernelExecution(
    694,
    "",
    2246,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDEyNjAxMjk4OjIyNDY=",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDIzMDQzMjk4OjIyNjc=",
  );
  sort.attrs["process.binary"] = "/usr/bin/sort";
  sort.attrs["process.pid"] = 2267;
  const bfs = kernelExecution(
    696,
    "-S dfs -regextype findutils-default /workspace/tiles/daily-summary -type f -not -path */node_modules/*",
    2266,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDIyNjUwNzU2OjIyNjY=",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDIzMzQ1Mjk4OjIyNjg=",
  );
  bfs.attrs["process.binary"] = "/usr/local/bin/claude";
  bfs.attrs["process.pid"] = 2268;
  const bfsChild = kernelCreation(
    695,
    2268,
    2266,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAzNDIyNjUwNzU2OjIyNjY=",
  );
  const unrelatedEmptyArgv = kernelExecution(697, "", 9999, "unrelated-parent-exec", "unrelated-empty-exec");
  unrelatedEmptyArgv.attrs["process.binary"] = "/usr/bin/sort";
  unrelatedEmptyArgv.attrs["process.pid"] = 9998;

  const events = [
    claude,
    hookWrapper,
    request,
    hook,
    execution,
    bfsParent,
    sort,
    bfsChild,
    bfs,
    unrelatedEmptyArgv,
  ];
  const result = loaded.client.deriveBashProcessLinks(events);

  assert.equal(result.requestLinks.get(641).executionSeq, 649);
  assert.equal(result.requestLinks.get(641).argv, "find /workspace/tiles/daily-summary -type f -not -path '*/node_modules/*' | sort");
  assert.equal(result.executionLinks.get(694), 641);
  assert.equal(result.executionLinks.get(696), 641);
  assert.equal(result.executionClassification.get(697), "unmatched");
  const model = loaded.client.buildModel(events);
  assert.match(loaded.client.timelineRowHtml({ model: model, state: { expandedSeqs: new loaded.client.Set() } }, 6), /linked Bash request · request seq 641/);
  const duplicateHook = plain(hook);
  duplicateHook.seq = 650;
  duplicateHook.attrs["process.exec.id"] = "duplicate-hook-exec";
  const ambiguous = loaded.client.deriveBashProcessLinks([claude, hookWrapper, request, hook, duplicateHook, execution]);
  assert.equal(ambiguous.requestLinks.has(641), false);
});

test("Bash derivation links the faithful 800 sort descendant for request 748", function () {
  const loaded = loadClient();
  const claude = kernelExecution(
    9,
    "--debug-file /home/agent/.claude/debug/claude-code.log",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNTMyMzA5MjQ6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
  );
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = 1881;
  const hookWrapper = kernelExecution(
    742,
    "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTM0MTg4MjU3OjIyOTI=",
  );
  hookWrapper.attrs["process.binary"] = "/bin/sh";
  hookWrapper.attrs["process.pid"] = 2292;
  const hook = kernelExecution(
    744,
    "lefthook",
    2292,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTM0MTg4MjU3OjIyOTI=",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTM0NzQ0OTI0OjIyOTM=",
  );
  hook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  hook.attrs["process.pid"] = 2293;
  const request = {
    seq: 748,
    ts: "2026-08-18T20:25:17.966286Z",
    name: "tool.requested",
    class: "harness_observed",
    badge: "HARNESS",
    producer: "workload",
    attrs: {
      "tool.name": "Bash",
      "harness.tool.input": "{\"command\":\"find /workspace/tiles/prompt-manager -type f -not -path '*/node_modules/*' | sort\"}",
      "process.parent_pid": 2292,
      "process.pid": 2293,
    },
  };
  const wrapper = kernelExecution(
    753,
    "-c \"source /home/agent/.claude/shell-snapshots/snapshot-bash-1787084693475-00k93e.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'find /workspace/tiles/prompt-manager -type f -not -path '\"'\"'*/node_modules/*'\"'\"' | sort' < /dev/null && pwd -P >| /tmp/claude-dd3a-cwd\"",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTU2MjMzOTI0OjIyOTg=",
  );
  wrapper.attrs["process.binary"] = "/bin/bash";
  wrapper.attrs["process.pid"] = 2298;
  const bfsParent = kernelCreation(
    798,
    2318,
    2298,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTU2MjMzOTI0OjIyOTg=",
  );
  const sort = kernelExecution(
    800,
    "",
    2298,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTU2MjMzOTI0OjIyOTg=",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTY3MzU5MDQ5OjIzMTk=",
  );
  sort.attrs["process.binary"] = "/usr/bin/sort";
  sort.attrs["process.pid"] = 2319;
  const bfs = kernelExecution(
    802,
    "-S dfs -regextype findutils-default /workspace/tiles/prompt-manager -type f -not -path */node_modules/*",
    2318,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTY2OTY4Nzk5OjIzMTg=",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTY3NzAwMDA3OjIzMjA=",
  );
  bfs.attrs["process.binary"] = "/usr/local/bin/claude";
  bfs.attrs["process.pid"] = 2320;
  const bfsChild = kernelCreation(
    801,
    2320,
    2318,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTA1NTY2OTY4Nzk5OjIzMTg=",
  );

  const events = [
    claude,
    hookWrapper,
    hook,
    request,
    wrapper,
    bfsParent,
    sort,
    bfsChild,
    bfs,
  ];
  const result = loaded.client.deriveBashProcessLinks(events);

  assert.equal(result.requestLinks.get(748).executionSeq, 753);
  assert.equal(result.executionLinks.get(800), 748);
  assert.equal(result.executionLinks.get(802), 748);
  const model = loaded.client.buildModel(events);
  assert.match(loaded.client.timelineRowHtml({ model: model, state: { expandedSeqs: new loaded.client.Set() } }, 6), /linked Bash request · request seq 748/);
});

test("Bash derivation leaves an ambiguous request unlinked", function () {
  const loaded = loadClient();
  const lineage = authenticatedBashLineage(1, 10, 11, "pwd");
  const secondWrapper = plain(lineage.wrapper);
  secondWrapper.seq = 12;
  secondWrapper.attrs["process.exec.id"] = "second-bash-wrapper-exec";
  const result = loaded.client.deriveBashProcessLinks([
    lineage.claude,
    lineage.hookWrapper,
    lineage.hook,
    lineage.request,
    lineage.wrapper,
    secondWrapper,
  ]);

  assert.equal(result.requestLinks.has(10), false);
  assert.equal(result.executionClassification.get(11), "unmatched");
  assert.equal(result.executionClassification.get(12), "unmatched");
});

test("Bash derivation requires matching execution lineage", function () {
  const loaded = loadClient();
  const lineage = authenticatedBashLineage(1, 10, 11, "pwd");
  lineage.wrapper.attrs["process.parent_exec_id"] = "wrong-claude-exec";
  const result = loaded.client.deriveBashProcessLinks([
    lineage.claude,
    lineage.hookWrapper,
    lineage.hook,
    lineage.request,
    lineage.wrapper,
  ]);

  assert.equal(result.requestLinks.has(10), false);
  assert.equal(result.executionClassification.get(11), "unmatched");
});

test("Bash derivation leaves an unknown eligible execution unmatched", function () {
  const loaded = loadClient();
  const result = loaded.client.deriveBashProcessLinks([
    kernelExecution(11, "unrecognized command", 41),
  ]);

  assert.equal(result.executionClassification.get(11), "unmatched");
  assert.equal(result.executionExemptions.has(11), false);
});

test("Bash derivation labels only exact guest-hook executions with Claude lineage as noise-exempt", function () {
  const loaded = loadClient();
  const claudeParent = kernelExecution(8, "--debug-file /home/agent/.claude/debug/claude-code.log", 1, "session-exec", "claude-parent-exec");
  claudeParent.attrs["process.binary"] = "/usr/local/bin/claude";
  claudeParent.attrs["process.pid"] = 1;
  const claude = kernelExecution(9, "--debug-file /home/agent/.claude/debug/claude-code.log", 1, "claude-parent-exec", "claude-exec");
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = 1;
  const wrapper = kernelExecution(10, "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"", 1, "claude-exec", "hook-wrapper-exec");
  wrapper.attrs["process.binary"] = "/bin/sh";
  wrapper.attrs["process.pid"] = 42;
  const execution = kernelExecution(11, "lefthook", 42, "hook-wrapper-exec");
  execution.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";

  const result = loaded.client.deriveBashProcessLinks([claudeParent, claude, wrapper, execution]);

  assert.equal(result.executionClassification.get(11), "noise-exempt");
  assert.equal(result.executionExemptions.get(11), "boxedai_guest_agent_lefthook");
  assert.equal(result.executionClassification.get(10), "noise-exempt");
  assert.equal(result.executionExemptions.get(10), "boxedai_guest_agent_lefthook_shell_wrapper");
  assert.equal(result.executionClassification.get(9), "unmatched");
  assert.equal(result.executionExemptions.has(9), false);
});

test("Bash derivation exempts the faithful captured agenthook pair", function () {
  const loaded = loadClient();
  const claude = kernelExecution(
    9,
    "--debug-file /home/agent/.claude/debug/claude-code.log",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNTMyMzA5MjQ6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
  );
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = 1881;
  const wrapper = kernelExecution(
    595,
    "-c \"/usr/local/bin/boxedai-guest-agent agenthook\"",
    1881,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTczNjc5NjE0NjU6MTg4MQ==",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAwOTcxMzMwNzE0OjIyMTU=",
  );
  wrapper.attrs["process.binary"] = "/bin/sh";
  wrapper.attrs["process.pid"] = 2215;
  const hook = kernelExecution(
    597,
    "agenthook",
    2215,
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAwOTcxMzMwNzE0OjIyMTU=",
    "bGltYS1ieC0yMDI2MDgxOC0yMDIzMjYtNjE1NjkwNTA6MTAwOTcyMDI0OTIyOjIyMTY=",
  );
  hook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  hook.attrs["process.pid"] = 2216;
  const userNearMiss = kernelExecution(598, "agenthook --user-command", 2215, "unrelated-parent-exec", "user-agenthook-exec");
  userNearMiss.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";

  const result = loaded.client.deriveBashProcessLinks([claude, wrapper, hook, userNearMiss]);

  assert.equal(result.executionExemptions.get(595), "boxedai_guest_agent_agenthook_shell_wrapper");
  assert.equal(result.executionExemptions.get(597), "boxedai_guest_agent_agenthook");
  assert.equal(result.executionClassification.get(598), "unmatched");
  assert.equal(result.executionExemptions.has(598), false);
});

test("Bash derivation leaves Claude startup with wrong lineage unmatched", function () {
  const loaded = loadClient();
  const execution = kernelExecution(9, "--debug-file /home/agent/.claude/debug/claude-code.log", 1, "unrelated-exec");
  execution.attrs["process.binary"] = "/usr/local/bin/claude";

  const result = loaded.client.deriveBashProcessLinks([execution]);

  assert.equal(result.executionClassification.get(9), "unmatched");
  assert.equal(result.executionExemptions.has(9), false);
});

test("Bash derivation rejects a startup snapshot builder with an appended command", function () {
  const loaded = loadClient();
  const appendedBuilder = {
    binary: "/bin/bash",
    argv: "-c -l \"SNAPSHOT_FILE=/home/agent/.claude/shell-snapshots/snapshot-bash-1787084693475-00k93e.sh\n      source \"/home/agent/.bashrc\" < /dev/null\n# Shadow find/grep with embedded bfs/ugrep\n# Exit silently on success, only report errors\n    \"; id",
  };

  assert.equal(loaded.client.isStartupSnapshotBuilder(appendedBuilder), false);
});

test("Bash derivation exempts only the exact Claude startup taxonomy before the first linked wrapper", function () {
  const loaded = loadClient();
  const startup = kernelExecution(9, "--debug-file /home/agent/.claude/debug/claude-code.log", 1881, "session-parent", "startup-exec");
  startup.attrs["process.binary"] = "/usr/local/bin/claude";
  startup.attrs["process.pid"] = 1881;
  const directProbe = kernelExecution(10, "--version", 1881, "startup-exec", "startup-probe-exec");
  directProbe.attrs["process.binary"] = "/usr/local/bin/claude";
  directProbe.attrs["process.pid"] = 1890;
  const envProbe = kernelExecution(11, "-c env", 1881, "startup-exec", "startup-env-exec");
  envProbe.attrs["process.binary"] = "/bin/bash";
  envProbe.attrs["process.pid"] = 1891;
  const createdChild = kernelCreation(12, 1892, 1891, "startup-env-exec");
  const emptyDescendant = kernelExecution(13, "", 1891, "startup-env-exec", "startup-empty-exec");
  emptyDescendant.attrs["process.binary"] = "/usr/bin/env";
  emptyDescendant.attrs["process.pid"] = 1892;
  const unknownChild = kernelExecution(14, "-a", 1881, "startup-exec", "startup-unknown-exec");
  unknownChild.attrs["process.binary"] = "/usr/bin/uname";
  unknownChild.attrs["process.pid"] = 1893;
  const wrongLineage = kernelExecution(15, "--debug-file /home/agent/.claude/debug/claude-code.log", 1881, "wrong-parent", "wrong-lineage-exec");
  wrongLineage.attrs["process.binary"] = "/usr/local/bin/claude";
  wrongLineage.attrs["process.pid"] = 1894;
  const hookWrapper = kernelExecution(16, "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"", 1881, "startup-exec", "startup-hook-wrapper-exec");
  hookWrapper.attrs["process.binary"] = "/bin/sh";
  hookWrapper.attrs["process.pid"] = 41;
  const hook = kernelExecution(17, "lefthook", 41, "startup-hook-wrapper-exec", "startup-hook-exec");
  hook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  hook.attrs["process.pid"] = 42;
  const request = bashRequest(20, "pwd", 41, "request-parent");
  request.attrs["process.pid"] = 42;
  const wrapper = kernelExecution(21, "-c \"source /home/agent/.claude/shell-snapshots/snapshot-bash-1787084693475-00k93e.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'pwd' < /dev/null && pwd -P >| /tmp/claude-e0e7-cwd\"", 1881, "startup-exec", "matched-wrapper-exec");
  wrapper.attrs["process.binary"] = "/bin/bash";
  wrapper.attrs["process.pid"] = 43;
  const laterSameArgv = kernelExecution(22, "--debug-file /home/agent/.claude/debug/claude-code.log", 1881, "startup-exec", "later-startup-shaped-exec");
  laterSameArgv.attrs["process.binary"] = "/usr/local/bin/claude";
  laterSameArgv.attrs["process.pid"] = 1894;

  const result = loaded.client.deriveBashProcessLinks([
    startup,
    directProbe,
    envProbe,
    createdChild,
    emptyDescendant,
    unknownChild,
    wrongLineage,
    hookWrapper,
    hook,
    request,
    wrapper,
    laterSameArgv,
  ]);

  assert.equal(result.requestLinks.get(20).executionSeq, 21);
  assert.equal(result.executionExemptions.get(9), "claude_startup_root");
  assert.equal(result.executionExemptions.get(10), "claude_startup_claude_probe");
  assert.equal(result.executionExemptions.get(11), "claude_startup_env_probe");
  assert.equal(result.executionExemptions.get(13), "claude_startup_env_child");
  assert.equal(result.executionClassification.get(14), "unmatched");
  assert.equal(result.executionClassification.get(15), "unmatched");
  assert.equal(result.executionClassification.get(22), "unmatched");
});

test("Bash derivation leaves exact guest-hook shapes with wrong lineage unmatched", function () {
  const loaded = loadClient();
  const wrapper = kernelExecution(10, "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"", 41, "not-claude", "hook-wrapper-exec");
  wrapper.attrs["process.binary"] = "/bin/sh";
  const execution = kernelExecution(11, "lefthook", 42, "hook-wrapper-exec");
  execution.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";

  const result = loaded.client.deriveBashProcessLinks([wrapper, execution]);

  assert.equal(result.executionClassification.get(10), "unmatched");
  assert.equal(result.executionClassification.get(11), "unmatched");
});

test("Bash derivation rejects wrong-PID and duplicate-ID hook lineage", function () {
  const loaded = loadClient();
  const claude = kernelExecution(1, "--debug-file /home/agent/.claude/debug/claude-code.log", 100, "session-exec", "claude-exec");
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = 100;
  const wrongPIDWrapper = kernelExecution(2, "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"", 999, "claude-exec", "wrong-wrapper-exec");
  wrongPIDWrapper.attrs["process.binary"] = "/bin/sh";
  wrongPIDWrapper.attrs["process.pid"] = 101;
  const wrongPIDHook = kernelExecution(3, "lefthook", 101, "wrong-wrapper-exec", "wrong-hook-exec");
  wrongPIDHook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  wrongPIDHook.attrs["process.pid"] = 102;
  const duplicateWrapper = kernelExecution(4, "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"", 100, "claude-exec", "duplicate-exec");
  duplicateWrapper.attrs["process.binary"] = "/bin/sh";
  duplicateWrapper.attrs["process.pid"] = 103;
  const duplicateExecution = kernelExecution(5, "unrelated", 100, "claude-exec", "duplicate-exec");
  duplicateExecution.attrs["process.binary"] = "/usr/bin/true";
  duplicateExecution.attrs["process.pid"] = 104;
  const duplicateHook = kernelExecution(6, "lefthook", 103, "duplicate-exec", "duplicate-hook-exec");
  duplicateHook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  duplicateHook.attrs["process.pid"] = 105;

  const result = loaded.client.deriveBashProcessLinks([
    claude,
    wrongPIDWrapper,
    wrongPIDHook,
    duplicateWrapper,
    duplicateExecution,
    duplicateHook,
  ]);

  [2, 3, 4, 5, 6].forEach(function (seq) {
    assert.equal(result.executionClassification.get(seq), "unmatched");
    assert.equal(result.executionExemptions.has(seq), false);
  });
});

test("Bash descendant traversal rejects a duplicate child exec ID and its descendants", function () {
  const loaded = loadClient();
  const lineage = authenticatedBashLineage(1, 10, 11, "pwd");
  const duplicateChild = kernelExecution(12, "-d", lineage.wrapper.attrs["process.pid"], lineage.wrapper.attrs["process.exec.id"], "duplicate-child-exec");
  duplicateChild.attrs["process.binary"] = "/usr/bin/base64";
  duplicateChild.attrs["process.pid"] = 500;
  const duplicateIncarnation = kernelExecution(13, "unrelated", 999, "wrong-parent", "duplicate-child-exec");
  duplicateIncarnation.attrs["process.binary"] = "/usr/bin/true";
  duplicateIncarnation.attrs["process.pid"] = 501;
  const unreachableDescendant = kernelExecution(14, "-d", 500, "duplicate-child-exec", "unreachable-descendant-exec");
  unreachableDescendant.attrs["process.binary"] = "/usr/bin/base64";
  unreachableDescendant.attrs["process.pid"] = 502;

  const result = loaded.client.deriveBashProcessLinks(lineage.events.concat([
    duplicateChild,
    duplicateIncarnation,
    unreachableDescendant,
  ]));

  assert.equal(result.requestLinks.get(10).executionSeq, 11);
  [12, 13, 14].forEach(function (seq) {
    assert.equal(result.executionClassification.get(seq), "unmatched");
    assert.equal(result.executionExemptions.has(seq), false);
    assert.equal(result.executionLinks.has(seq), false);
  });
});

test("Bash descendant links reject a reused parent PID without its exact creation lineage", function () {
  const loaded = loadClient();
  const lineage = authenticatedBashLineage(1, 10, 11, "pwd");
  const request = lineage.request;
  const wrapper = lineage.wrapper;
  wrapper.attrs["process.pid"] = 500;
  const originalCreation = kernelCreation(12, 501, 500, wrapper.attrs["process.exec.id"]);
  const originalChildCreation = kernelCreation(13, 502, 501, "fork-one");
  const originalChild = kernelExecution(14, "", 501, "fork-one", "original-child-exec");
  originalChild.attrs["process.binary"] = "/usr/bin/sort";
  originalChild.attrs["process.pid"] = 502;
  const reusedCreation = kernelCreation(15, 501, 999, "unrelated-exec");
  const reusedChildCreation = kernelCreation(16, 503, 501, "fork-two");
  const reusedChild = kernelExecution(17, "", 501, "fork-two", "reused-child-exec");
  reusedChild.attrs["process.binary"] = "/usr/bin/sort";
  reusedChild.attrs["process.pid"] = 503;
  const mismatchedChildCreation = kernelCreation(18, 504, 501, "mismatched-fork");
  const mismatchedChild = kernelExecution(19, "", 501, "fork-three", "mismatched-child-exec");
  mismatchedChild.attrs["process.binary"] = "/usr/bin/sort";
  mismatchedChild.attrs["process.pid"] = 504;

  const result = loaded.client.deriveBashProcessLinks([
    lineage.claude,
    lineage.hookWrapper,
    lineage.hook,
    request,
    wrapper,
    originalCreation,
    originalChildCreation,
    originalChild,
    reusedCreation,
    reusedChildCreation,
    reusedChild,
    mismatchedChildCreation,
    mismatchedChild,
  ]);

  assert.equal(result.executionLinks.get(14), 10);
  assert.equal(result.executionClassification.get(17), "unmatched");
  assert.equal(result.executionClassification.get(19), "unmatched");
});

test("Bash derivation classifies incomplete kernel anchors as unmatched", function () {
  const loaded = loadClient();
  const execution = kernelExecution(11, "pwd", 41);
  delete execution.attrs["process.parent_exec_id"];

  const result = loaded.client.deriveBashProcessLinks([execution]);

  assert.equal(result.executionClassification.get(11), "unmatched");
});

test("Bash derivation links exact quoted, wrapper, and multiline argv shapes deterministically", function () {
  const loaded = loadClient();
  const cases = [
    [10, "printf '%s\\n' \"quoted value\""],
    [20, "printf '%s\\n' \\\"quoted value\\\""],
    [30, "printf '%s\\n' first\\nsecond"],
    [40, "bash -c 'printf wrapped'"],
  ];
  const events = [];
  cases.forEach(function (entry, index) {
    const lineage = authenticatedBashLineage(100 + index * 10, entry[0], entry[0] + 1, entry[1]);
    events.push.apply(events, lineage.events);
  });

  const first = loaded.client.deriveBashProcessLinks(events);
  const second = loaded.client.deriveBashProcessLinks(plain(events));
  assert.deepEqual(Array.from(first.requestLinks.entries()), Array.from(second.requestLinks.entries()));
  assert.deepEqual(Array.from(first.executionLinks.entries()), Array.from(second.executionLinks.entries()));
  cases.forEach(function (entry) {
    assert.equal(first.requestLinks.get(entry[0]).executionSeq, entry[0] + 1);
  });
});

test("Bash derivation keeps repeated and interleaved commands one-to-one", function () {
  const loaded = loadClient();
  const root = authenticatedBashLineage(1, 100, 101, "unused").claude;
  const firstEcho = authenticatedHookCycle(root, 10, 20, 21, "echo waiting");
  const firstPwd = authenticatedHookCycle(root, 30, 40, 41, "pwd");
  const secondEcho = authenticatedHookCycle(root, 50, 60, 61, "echo waiting");
  const secondPwd = authenticatedHookCycle(root, 70, 80, 81, "pwd");
  const events = [root].concat(firstEcho.events, firstPwd.events, secondEcho.events, secondPwd.events);
  const result = loaded.client.deriveBashProcessLinks(events);

  assert.deepEqual(Array.from(result.requestLinks.entries()).map(function (entry) { return entry[0] + ":" + entry[1].executionSeq; }), [
    "20:21", "40:41", "60:61", "80:81",
  ]);
  assert.deepEqual(Array.from(result.executionLinks.entries()), [[21, 20], [41, 40], [61, 60], [81, 80]]);
});

test("Bash derivation leaves overlapping identical requests unlinked", function () {
  const loaded = loadClient();
  const root = authenticatedBashLineage(1, 100, 101, "unused").claude;
  const first = authenticatedHookCycle(root, 10, 20, 30, "echo waiting");
  const second = authenticatedHookCycle(root, 40, 21, 31, "echo waiting");
  const result = loaded.client.deriveBashProcessLinks([
    root,
    first.hookWrapper,
    first.hook,
    first.request,
    second.hookWrapper,
    second.hook,
    second.request,
    first.wrapper,
  ]);

  assert.equal(result.requestLinks.size, 0);
  assert.equal(result.executionClassification.get(30), "unmatched");
});

test("Bash derivation rejects malformed, truncated, missing, and ambiguous evidence", function () {
  const loaded = loadClient();
  const malformed = bashRequest(10, "pwd", 41);
  malformed.attrs["harness.tool.input"] = "{\"command\":";
  const truncated = bashRequest(11, "echo truncated", 42);
  truncated.attrs["harness.tool.input"] = JSON.stringify({ command: "echo truncated" }).slice(0, -2);
  const missingCommand = bashRequest(12, "echo missing", 43);
  missingCommand.attrs["harness.tool.input"] = JSON.stringify({});
  const missingLineage = kernelExecution(13, "echo missing-lineage", 44);
  delete missingLineage.attrs["process.parent_exec_id"];
  const missingArgv = kernelExecution(14, "ignored", 45);
  delete missingArgv.attrs["process.argv"];
  const ambiguousRequest = bashRequest(15, "same command", 46);
  const ambiguousExecutionA = kernelExecution(16, "same command", 46);
  const ambiguousExecutionB = kernelExecution(17, "same command", 46);

  const result = loaded.client.deriveBashProcessLinks([
    malformed,
    truncated,
    missingCommand,
    missingLineage,
    missingArgv,
    ambiguousRequest,
    ambiguousExecutionA,
    ambiguousExecutionB,
  ]);

  assert.equal(result.requestLinks.size, 0);
  assert.equal(result.executionClassification.get(13), "unmatched");
  assert.equal(result.executionClassification.get(16), "unmatched");
  assert.equal(result.executionClassification.get(17), "unmatched");
  assert.equal(result.executionClassification.has(14), false);
});

test("Bash derivation requires trusted producers, badges, and event classes", function () {
  const loaded = loadClient();
  const request = bashRequest(10, "pwd", 41);
  const forgedRequestBadge = bashRequest(11, "echo forged badge", 42);
  forgedRequestBadge.badge = "KERNEL";
  const forgedRequestProducer = bashRequest(12, "echo forged producer", 43);
  forgedRequestProducer.producer = "guest_supervisor";
  const forgedExecution = kernelExecution(13, "pwd", 41);
  forgedExecution.badge = "HARNESS";
  const wrongProducer = kernelExecution(14, "echo forged producer", 43);
  wrongProducer.producer = "workload";
  const wrongEvent = kernelExecution(15, "echo wrong event", 44);
  wrongEvent.name = "tool.requested";
  const trustedExecution = kernelExecution(16, "pwd", 41);
  const forgedRequestClass = bashRequest(17, "echo forged class", 45);
  forgedRequestClass.class = "kernel_observed";
  const forgedExecutionClass = kernelExecution(18, "echo forged class", 45);
  forgedExecutionClass.class = "harness_observed";
  const authenticatedUnmatchedExecution = kernelExecution(19, "echo unrequested", 46);
  const noncanonicalRequestClass = bashRequest(20, "echo uppercase class", 47);
  noncanonicalRequestClass.class = "HARNESS_OBSERVED";
  const noncanonicalExecutionClass = kernelExecution(21, "echo uppercase class", 47);
  noncanonicalExecutionClass.class = "KERNEL_OBSERVED";

  const result = loaded.client.deriveBashProcessLinks([
    request,
    forgedRequestBadge,
    forgedRequestProducer,
    forgedExecution,
    wrongProducer,
    wrongEvent,
    trustedExecution,
    forgedRequestClass,
    forgedExecutionClass,
    authenticatedUnmatchedExecution,
    noncanonicalRequestClass,
    noncanonicalExecutionClass,
  ]);

  assert.equal(result.requestLinks.has(10), false);
  assert.equal(result.requestLinks.has(11), false);
  assert.equal(result.requestLinks.has(12), false);
  assert.equal(result.executionClassification.has(13), false);
  assert.equal(result.executionClassification.has(14), false);
  assert.equal(result.executionClassification.has(15), false);
  assert.equal(result.requestLinks.has(17), false);
  assert.equal(result.executionClassification.has(18), false);
  assert.equal(result.executionClassification.get(19), "unmatched");
  assert.equal(result.requestLinks.has(20), false);
  assert.equal(result.executionClassification.has(21), false);
});

test("Bash derivation exempts only exact noise shapes and keeps user near misses unmatched", function () {
  const loaded = loadClient();
  const claudeParent = kernelExecution(8, "--debug-file /home/agent/.claude/debug/claude-code.log", 1, "session-exec", "claude-parent-exec");
  claudeParent.attrs["process.binary"] = "/usr/local/bin/claude";
  claudeParent.attrs["process.pid"] = 1;
  const claude = kernelExecution(9, "--debug-file /home/agent/.claude/debug/claude-code.log", 1, "claude-parent-exec", "claude-exec");
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = 1;
  const exactWrapper = kernelExecution(10, "-c \"/usr/local/bin/boxedai-guest-agent righthook\"", 1, "claude-exec", "wrapper-exec");
  exactWrapper.attrs["process.binary"] = "/bin/sh";
  exactWrapper.attrs["process.pid"] = 42;
  const exactHook = kernelExecution(11, "righthook", 42, "wrapper-exec");
  exactHook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  const agentHookWrapper = kernelExecution(17, "-c \"/usr/local/bin/boxedai-guest-agent agenthook\"", 1, "claude-exec", "agenthook-wrapper-exec");
  agentHookWrapper.attrs["process.binary"] = "/bin/sh";
  agentHookWrapper.attrs["process.pid"] = 42;
  const agentHook = kernelExecution(18, "agenthook", 42, "agenthook-wrapper-exec");
  agentHook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  const alteredAgentHook = kernelExecution(19, "agenthook --user-command", 42, "agenthook-wrapper-exec");
  alteredAgentHook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  const genericShell = kernelExecution(12, "echo waiting", 43);
  genericShell.attrs["process.binary"] = "/bin/sh";
  const pathMention = kernelExecution(13, "echo /usr/local/bin/boxedai-guest-agent lefthook", 44);
  pathMention.attrs["process.binary"] = "/bin/bash";
  const alteredHook = kernelExecution(14, "lefthook --user-command", 45);
  alteredHook.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  const alteredWrapper = kernelExecution(15, "-c /usr/local/bin/boxedai-guest-agent lefthook", 46, "claude-exec", "altered-wrapper");
  alteredWrapper.attrs["process.binary"] = "/bin/sh";
  const wrongStartupLineage = kernelExecution(16, "--debug-file /home/agent/.claude/debug/claude-code.log", 47, "unrelated-exec");
  wrongStartupLineage.attrs["process.binary"] = "/usr/local/bin/claude";

  const result = loaded.client.deriveBashProcessLinks([
    claudeParent,
    claude,
    exactWrapper,
    exactHook,
    agentHookWrapper,
    agentHook,
    alteredAgentHook,
    genericShell,
    pathMention,
    alteredHook,
    alteredWrapper,
    wrongStartupLineage,
  ]);

  assert.equal(result.executionClassification.get(9), "unmatched");
  assert.equal(result.executionExemptions.has(9), false);
  assert.equal(result.executionExemptions.get(10), "boxedai_guest_agent_righthook_shell_wrapper");
  assert.equal(result.executionExemptions.get(11), "boxedai_guest_agent_righthook");
  assert.equal(result.executionExemptions.get(17), "boxedai_guest_agent_agenthook_shell_wrapper");
  assert.equal(result.executionExemptions.get(18), "boxedai_guest_agent_agenthook");
  [12, 13, 14, 15, 16, 19].forEach(function (seq) {
    assert.equal(result.executionClassification.get(seq), "unmatched");
    assert.equal(result.executionExemptions.has(seq), false);
  });
});

test("Bash derived state stays stable across filtering, sorting, chunking, rebuilds, and live execution deltas", function () {
  const loaded = loadClient();
  const lineage = authenticatedBashLineage(1, 10, 12, "pwd");
  const request = lineage.request;
  const unrelated = event(11, { note: "outside visible slice" });
  const initialEvents = [lineage.claude, lineage.hookWrapper, lineage.hook, request, unrelated];
  const model = loaded.client.buildModel(initialEvents);
  const state = loaded.client.defaultState();
  state.agentActivity = true;
  state.search = "pwd";
  const filtered = loaded.client.computeTimelineFilter(model, state, new loaded.client.Set(["tool.requested"]));

  assert.deepEqual(Array.from(filtered.indices), [3]);
  assert.equal(model.requestLinks.has(10), false);

  const execution = lineage.wrapper;
  loaded.client.extendModel(model, initialEvents.concat([execution]));

  assert.equal(model.requestLinks.get(10).executionSeq, 12);
  assert.equal(model.executionLinks.get(12), 10);
  assert.equal(model.events.length, 6);
  assert.equal(model.corpus.length, 6);

  const rebuilt = loaded.client.buildModel(initialEvents.concat([execution]));
  assert.deepEqual(Array.from(model.requestLinks.entries()), Array.from(rebuilt.requestLinks.entries()));
  assert.deepEqual(Array.from(model.executionLinks.entries()), Array.from(rebuilt.executionLinks.entries()));
  assert.deepEqual(Array.from(model.executionClassification.entries()), Array.from(rebuilt.executionClassification.entries()));

  const postDelta = loaded.client.computeTimelineFilter(model, state, new loaded.client.Set(["tool.requested", "process.executed"]));
  assert.deepEqual(Array.from(postDelta.indices), [3, 5]);
  state.search = "";
  state.agentActivity = false;
  state.hideNoise = false;
  state.sort = "desc";
  state.timelineShown = 1;
  const allPostDelta = loaded.client.computeTimelineFilter(model, state, new loaded.client.Set(["tool.requested", "process.executed"]));
  const display = loaded.client.timelineDisplayIndices(allPostDelta, state);
  assert.deepEqual(Array.from(display.slice(0, state.timelineShown)), [5]);
  assert.equal(model.requestLinks.get(10).executionSeq, 12);
});

test("Bash derivation rebuilds without mutating raw events after a live delta", function () {
  const loaded = loadClient();
  const lineage = authenticatedBashLineage(1, 10, 11, "pwd");
  const request = lineage.request;
  const execution = lineage.wrapper;
  const originalRequest = plain(request);
  const originalExecution = plain(execution);
  const initialEvents = [lineage.claude, lineage.hookWrapper, lineage.hook, request];
  const model = loaded.client.buildModel(initialEvents);

  loaded.client.extendModel(model, initialEvents.concat([execution]));

  assert.equal(model.requestLinks.get(10).executionSeq, 11);
  assert.equal(model.executionClassification.get(11), "matched");
  assert.deepEqual(plain(request), originalRequest);
  assert.deepEqual(plain(execution), originalExecution);
});

test("live links replace earlier timeline rows and Actions rows use the derived summary", function () {
  const loaded = loadClient();
  const lineage = authenticatedBashLineage(1, 10, 11, "pwd");
  const request = lineage.request;
  const execution = lineage.wrapper;
  const initialEvents = [lineage.claude, lineage.hookWrapper, lineage.hook, request];
  const body = {
    innerHTML: "",
    insertAdjacentHTML: function (_position, html) { this.innerHTML += html; },
  };
  const ctx = {
    state: loaded.client.defaultState(),
    payload: {
      session_id: "one",
      state: "running",
      proof: { status: "provisional", provisional: true },
      events: initialEvents,
    },
    model: loaded.client.buildModel(initialEvents),
    agentActivityNames: new loaded.client.Set(["tool.requested", "process.executed"]),
    els: {
      tlFilterbar: { innerHTML: "" },
      tlBody: body,
      tlMore: { innerHTML: "" },
      tlResults: { innerHTML: "" },
    },
    prevSummary: {
      len: 4,
      lastSeq: 10,
      state: "running",
      status: "provisional",
      verifyError: "",
    },
    prevEventCount: 0,
    prevFilteredTotal: 0,
    tlRenderedCount: 0,
  };
  ctx.state.sort = "asc";
  loaded.client.renderHeader = function () {};
  loaded.client.renderTabsBar = function () {};
  loaded.client.activeScrollEl = function () { return null; };

  loaded.client.updateTimelineTab(ctx);
  assert.match(body.innerHTML, /no matching process execution/);

  loaded.client.setSessionViewPayload(ctx, {
    session_id: "one",
    state: "running",
    proof: { status: "provisional", provisional: true },
    agent_activity_names: ["tool.requested", "process.executed"],
    events: initialEvents.concat([execution]),
  });

  assert.match(body.innerHTML, /kernel-observed: pwd/);
  assert.match(loaded.client.actionRowHtml(ctx, 3), /kernel-observed: pwd/);
});

test("timeline renders Bash link states and preserves exact noise exemptions for show everything", function () {
  const loaded = loadClient();
  const lineage = authenticatedBashLineage(1, 10, 11, "pwd");
  const linkedRequest = lineage.request;
  const linkedExecution = lineage.wrapper;
  linkedExecution.attrs["process.pid"] = 77;
  const unlinkedRequest = bashRequest(12, "echo missing", 42);
  const unmatchedExecution = kernelExecution(13, "unrequested command", 43);
  const claudeParent = kernelExecution(14, "--debug-file /home/agent/.claude/debug/claude-code.log", 1, "session-exec", "claude-parent-exec");
  claudeParent.attrs["process.binary"] = "/usr/local/bin/claude";
  claudeParent.attrs["process.pid"] = 1;
  const claude = kernelExecution(15, "--debug-file /home/agent/.claude/debug/claude-code.log", 1, "claude-parent-exec", "claude-exec");
  claude.attrs["process.binary"] = "/usr/local/bin/claude";
  claude.attrs["process.pid"] = 1;
  const hookWrapper = kernelExecution(16, "-c \"/usr/local/bin/boxedai-guest-agent lefthook\"", 1, "claude-exec", "hook-wrapper-exec");
  hookWrapper.attrs["process.binary"] = "/bin/sh";
  hookWrapper.attrs["process.pid"] = 42;
  const exemptExecution = kernelExecution(17, "lefthook", 42, "hook-wrapper-exec");
  exemptExecution.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  const nearMissExecution = kernelExecution(18, "lefthook", 42, "unrelated-exec");
  nearMissExecution.attrs["process.binary"] = "/usr/local/bin/boxedai-guest-agent";
  const model = loaded.client.buildModel([
    lineage.claude,
    lineage.hookWrapper,
    lineage.hook,
    linkedRequest,
    linkedExecution,
    unlinkedRequest,
    unmatchedExecution,
    claudeParent,
    claude,
    hookWrapper,
    exemptExecution,
    nearMissExecution,
  ]);
  const ctx = {
    model: model,
    state: { expandedSeqs: new loaded.client.Set() },
  };

  const linkedRow = loaded.client.timelineRowHtml(ctx, 3);
  assert.match(linkedRow, /kernel-observed: pwd/);
  assert.match(linkedRow, /source seq 11/);
  assert.match(linkedRow, /pid 77/);

  const unlinkedRow = loaded.client.timelineRowHtml(ctx, 5);
  assert.match(unlinkedRow, /no matching process execution/);
  assert.doesNotMatch(unlinkedRow, /kernel-observed/);

  const unmatchedRow = loaded.client.timelineRowHtml(ctx, 6);
  assert.match(unmatchedRow, /no linked Bash request/);

  const exemptRow = loaded.client.timelineRowHtml(ctx, 10);
  assert.match(exemptRow, /noise-exempt: boxedai_guest_agent_lefthook/);
  const activityState = loaded.client.defaultState();
  const activityFiltered = loaded.client.computeTimelineFilter(model, activityState, new loaded.client.Set(["process.executed"]));
  assert.equal(activityFiltered.indices.includes(10), false);
  assert.equal(activityFiltered.indices.includes(11), true);
  activityState.agentActivity = false;
  activityState.hideNoise = false;
  const everythingFiltered = loaded.client.computeTimelineFilter(model, activityState, new loaded.client.Set(["process.executed"]));
  assert.equal(everythingFiltered.indices.includes(10), true);
});

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
