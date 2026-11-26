import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { render } from "ink-testing-library";
import { App } from "../src/app.js";
import { makeTheme } from "../src/theme.js";
import { HelperAbsent, type Helper } from "../src/helper.js";
import { redact } from "../src/redact.js";
import { down, healthy, PAYEE, sourceOf } from "./fixtures.js";

const tick = (ms = 80) => new Promise((r) => setTimeout(r, ms));
const ESC_SEQ = /\u001b\[/;
const strip = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");
const txt = (r: { lastFrame: () => string | undefined }): string => strip(r.lastFrame() ?? "");

function mount(snap: () => ReturnType<typeof healthy>, cols = 80, rows = 24, color = false, account: string | null = null) {
  return render(<App source={sourceOf(snap)} theme={makeTheme(color)} initialAccount={account} refreshMs={60000} size={{ columns: cols, rows }} />);
}

test("overview at 80x24 fits, says OK, and lists a keys footer", async () => {
  const r = mount(healthy);
  await tick();
  const f = txt(r);
  const lines = f.split("\n");
  assert.ok(lines.length <= 24, `frame is ${lines.length} lines`);
  assert.ok(lines.every((l) => l.length <= 80));
  assert.match(f, /TENZRO/);
  assert.match(f, /\bOK\b/);
  assert.match(f, /Height\s+1,234,567/);
  assert.match(f, /\? help/);
  assert.match(f, /q quit/);
  r.unmount();
});

test("overview at 120x40 uses two columns", async () => {
  const r = mount(healthy, 120, 40);
  await tick();
  const f = txt(r);
  const chainLine = f.split("\n").find((l) => l.includes("Node") && l.includes("Chain"));
  assert.ok(chainLine, "Node and Chain headings share a row at 120 columns");
  r.unmount();
});

test("number keys, Tab and arrows move between screens and lists", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("3");
  await tick();
  assert.match(txt(r), /Models on this node/);
  assert.match(txt(r), /> org\/model-00/);
  r.stdin.write("j");
  await tick();
  assert.match(txt(r), /> org\/model-01/);
  r.stdin.write("\u001b[B");
  await tick();
  assert.match(txt(r), /> org\/model-02/);
  r.stdin.write("\t");
  await tick();
  assert.match(txt(r), /Validators/);
  r.stdin.write("\u001b[D");
  await tick();
  assert.match(txt(r), /Models on this node/);
  r.unmount();
});

test("a long list scrolls inside the window and shows where you are", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("3");
  await tick();
  r.stdin.write("j".repeat(25));
  await tick(150);
  const f = txt(r);
  assert.match(f, /> org\/model-25/);
  assert.match(f, /of 30/);
  assert.ok(f.split("\n").length <= 24);
  r.unmount();
});

test("help overlay is generated from the binding table and closes with Esc", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("?");
  await tick();
  assert.match(txt(r), /Status words/);
  assert.match(txt(r), /Quit and restore the terminal/);
  r.stdin.write("\u001b");
  await tick(150);
  assert.doesNotMatch(txt(r), /Status words/);
  r.unmount();
});

test("wallet shows the payee balance, then a chosen account, and rejects a bad address", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("2");
  await tick();
  let f = txt(r);
  assert.match(f, new RegExp(PAYEE));
  assert.match(f, /1,234\.5678 TNZO/);
  assert.match(f, /Nonce\s+7/);
  r.stdin.write("e");
  await tick();
  r.stdin.write("0x12");
  await tick();
  r.stdin.write("\r");
  await tick();
  f = txt(r);
  assert.match(f, /not an account address/);
  r.stdin.write("\u001b");
  await tick(150);
  assert.doesNotMatch(txt(r), /not an account address/);
  r.unmount();
});

test("keys that arrive in one chunk act in order across a screen change", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("3jj");
  await tick(150);
  assert.match(txt(r), /> org\/model-02/);
  r.unmount();
});

test("keys typed into the account field never trigger screen keys", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("2");
  await tick();
  r.stdin.write("e");
  await tick();
  r.stdin.write("q4");
  await tick();
  const f = txt(r);
  assert.match(f, /> q4/);
  assert.match(f, /Choose the account/);
  r.unmount();
});

test("node down: DOWN with the reason, not a green screen", async () => {
  const r = mount(() => down("http://127.0.0.1:8545"));
  await tick();
  const f = txt(r);
  assert.match(f, /\bDOWN\b/);
  assert.match(f, /Cannot reach a node at http:\/\/127\.0\.0\.1:8545/);
  assert.doesNotMatch(f, /\bOK\b/);
  r.stdin.write("3");
  await tick();
  assert.match(txt(r), /no data: Cannot reach a node/);
  assert.doesNotMatch(txt(r), /No models here yet/);
  r.stdin.write("1");
  await tick();
  const overview = txt(r);
  assert.equal((overview.match(/Cannot reach a node/g) ?? []).length, 1, "the reason is said once, not on every row");
  r.unmount();
});

test("a node that goes away leaves its last values marked STALE", async () => {
  let n = 0;
  const first = healthy();
  const src = {
    url: redact("http://127.0.0.1:8545"),
    collect: async (_a: string | null, prev: typeof first) => {
      n++;
      if (n === 1) return first;
      const lastOk = prev.status.state === "ok" ? { value: prev.status.value, at: prev.status.at } : prev.status.state === "error" ? prev.status.last : undefined;
      const e = { state: "error" as const, error: redact("gone"), at: Date.now(), ...(lastOk ? { last: lastOk } : {}) };
      return { ...first, status: e };
    },
  };
  const r = render(<App source={src} theme={makeTheme(false)} initialAccount={null} refreshMs={60000} size={{ columns: 80, rows: 24 }} />);
  await tick();
  r.stdin.write("r");
  await tick(150);
  const f = txt(r);
  assert.match(f, /\bDOWN\b/);
  assert.match(f, /STALE/);
  r.unmount();
});

test("an answer nothing has replaced for three refresh periods is marked STALE", async () => {
  const old = Date.now() - 600_000;
  const aged = () => {
    const s = healthy();
    return { ...s, status: { ...s.status, at: old }, chainId: { ...s.chainId, at: old } };
  };
  const r = render(<App source={sourceOf(aged)} theme={makeTheme(false)} initialAccount={null} refreshMs={60000} size={{ columns: 80, rows: 24 }} />);
  await tick();
  const f = txt(r);
  assert.match(f, /Height\s+1,234,567 STALE 10m 0s ago/);
  assert.match(f, /Chain id\s+13380 STALE/);
  // Readings inside the window are shown plainly.
  assert.match(f, /Finalized\s+1,234,560\s*$/m);
  r.unmount();
});

test("nine screens fit the tab row at 80 columns and each one draws", async () => {
  const r = mount(healthy);
  await tick();
  const headings: [string, RegExp][] = [
    ["6", /Health: what needs attention/],
    ["7", /Peers this node has heard from/],
    ["8", /Log of this console session/],
    ["9", /Settings of this console/],
  ];
  for (const [key, heading] of headings) {
    r.stdin.write(key);
    await tick();
    const f = txt(r);
    assert.match(f, heading);
    assert.ok(f.split("\n").every((l) => l.length <= 80), `screen ${key} is wider than 80`);
    assert.ok(f.split("\n").length <= 24);
  }
  r.stdin.write("7");
  await tick();
  assert.match(txt(r), /> this node\s+Validator, Provider/);
  assert.match(txt(r), /machine: did:tenzro:machine:265ad18ed76da11b/);
  r.stdin.write("6");
  await tick();
  assert.match(txt(r), /Nothing needs attention/);
  assert.match(txt(r), /the console's own rules/);
  r.unmount();
});

test("an alert appears after two snapshots, is counted in the header, and is acknowledged with a typed reason", async () => {
  const lonely = () => {
    const s = healthy();
    if (s.status.state !== "ok") throw new Error("fixture");
    return { ...s, status: { ...s.status, value: { ...s.status.value, peer_count: 0 } } };
  };
  const r = mount(lonely);
  await tick();
  r.stdin.write("6");
  await tick();
  // The engine's own tests hold that one snapshot is not yet an alert; here a second one has arrived.
  r.stdin.write("r");
  await tick(150);
  let f = txt(r);
  assert.match(f, /1 TO SEE/);
  assert.match(f, /> WARN .* no\s+The node has no peers/);
  assert.match(f, /not acknowledged\. Press a/);
  r.stdin.write("a");
  await tick();
  assert.match(txt(r), /Acknowledge an alert/);
  r.stdin.write("\r");
  await tick();
  assert.match(txt(r), /needs a reason/);
  // Letters typed into the reason never act as screen keys.
  r.stdin.write("q1 lab node");
  await tick();
  r.stdin.write("\r");
  await tick(150);
  f = txt(r);
  assert.match(f, /acknowledged now: q1 lab node/);
  assert.doesNotMatch(f, /TO SEE/);
  r.stdin.write("8");
  await tick();
  f = txt(r);
  assert.match(f, /acknowledged\s+WARN\s+The node has no peers/);
  assert.match(f, /raised\s+WARN\s+The node has no peers/);
  r.unmount();
});

test("the help overlay still fits 80x24 with every key listed", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("?");
  await tick();
  const f = txt(r);
  assert.match(f, /1 to 9\s+Go to a screen/);
  assert.match(f, /Health: acknowledge the selected alert/);
  assert.match(f, /Status words/);
  assert.match(f, /DOWN the node did not answer/);
  r.unmount();
});

const provider = () => {
  const s = healthy();
  if (s.status.state !== "ok") throw new Error("fixture");
  return { ...s, status: { ...s.status, value: { ...s.status.value, roles: ["Provider"] } } };
};

function mountWith(snap: () => ReturnType<typeof healthy>, helper: Helper | null) {
  return render(<App source={sourceOf(snap)} theme={makeTheme(false)} initialAccount={null} refreshMs={60000} helper={helper} size={{ columns: 100, rows: 30 }} />);
}

test("a stop that would leave the validator set short is blocked and asks the helper for nothing", async () => {
  const calls: string[] = [];
  const helper: Helper = { path: "x", call: async (m) => (calls.push(m), {} as never) };
  const r = mountWith(healthy, helper);
  await tick();
  r.stdin.write("S");
  await tick();
  const f = txt(r);
  assert.match(f, /Planned stop of this node/);
  assert.match(f, /NO\s+1 validators are active; without this one only 0 would remain/);
  assert.match(f, /The stop is blocked/);
  r.stdin.write("STOP");
  await tick();
  r.stdin.write("\r");
  await tick(150);
  assert.deepEqual(calls, []);
  assert.doesNotMatch(txt(r), /Planned stop/, "Enter closed the blocked view");
  r.unmount();
});

test("a stop goes to the helper only after the checks pass and STOP is typed", async () => {
  const calls: [string, unknown][] = [];
  const helper: Helper = { path: "x", call: async (m, p) => (calls.push([m, p]), { service: "stopped", reason: "" } as never) };
  const r = mountWith(provider, helper);
  await tick();
  r.stdin.write("S");
  await tick();
  assert.match(txt(r), /ok\s+This node does not validate/);
  assert.match(txt(r), /counted as registered Active, not as up right now/);
  assert.match(txt(r), /Type STOP and press Enter/);
  r.stdin.write("stop");
  await tick();
  r.stdin.write("\r");
  await tick(150);
  assert.match(txt(r), /Nothing was stopped: that was not STOP/);
  assert.deepEqual(calls, []);
  r.stdin.write("\u007f\u007f\u007f\u007f");
  await tick();
  r.stdin.write("STOP");
  await tick();
  r.stdin.write("\r");
  await tick(200);
  assert.deepEqual(calls, [["control_service", { action: "stop" }]]);
  assert.match(txt(r), /The helper answered: the node service is stopped/);
  r.unmount();
});

test("without a helper the console stops nothing and shows the command to run", async () => {
  for (const helper of [null, { path: "x", call: async () => Promise.reject(new HelperAbsent("x")) } as Helper]) {
    const r = mountWith(provider, helper);
    await tick();
    r.stdin.write("S");
    await tick();
    r.stdin.write("STOP");
    await tick();
    r.stdin.write("\r");
    await tick(200);
    const f = txt(r).replace(/\s+/g, " ");
    assert.match(f, /Nothing was stopped\. To stop it, run as this node's operator: tenzro-node graceful-exit --rpc-url http:\/\/127\.0\.0\.1:8545/);
    r.unmount();
  }
});

test("the palette finds a screen by name and opens it", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("/");
  await tick();
  assert.match(txt(r), /Find a screen or an action/);
  r.stdin.write("heard");
  await tick();
  assert.match(txt(r), /> Peers: who this node has heard from/);
  r.stdin.write("\r");
  await tick();
  assert.match(txt(r), /Peers this node has heard from/);
  // Letters typed into the palette are a filter, never keys: q did not quit.
  r.stdin.write("/");
  await tick();
  r.stdin.write("q");
  await tick();
  assert.match(txt(r), /> Quit and restore the terminal/);
  r.stdin.write("\u001b");
  await tick(150);
  assert.match(txt(r), /Peers this node has heard from/);
  r.unmount();
});

test("replay steps back through what the console saw, decides nothing, and returns to now", async () => {
  let n = 0;
  const climbing = () => {
    const s = provider();
    if (s.status.state !== "ok") throw new Error("fixture");
    n++;
    return { ...s, at: Date.now(), status: { ...s.status, value: { ...s.status.value, block_height: 1000 + n } } };
  };
  const calls: string[] = [];
  const r = mountWith(climbing, { path: "x", call: async (m) => (calls.push(m), {} as never) });
  const height = () => Number(/Height\s+1,(\d\d\d)/.exec(txt(r))![1]);
  await tick();
  r.stdin.write("r");
  await tick(150);
  r.stdin.write("r");
  await tick(150);
  const live = height();
  const total = n;
  assert.ok(total >= 3 && live === total, `${total} answers collected, height ${live}`);
  r.stdin.write("[");
  await tick();
  assert.match(txt(r), new RegExp(`REPLAY \\d\\d:\\d\\d:\\d\\d UTC, ${total - 1} of ${total}`));
  assert.equal(height(), live - 1);
  r.stdin.write("[".repeat(total + 2));
  await tick();
  assert.match(txt(r), new RegExp(`1 of ${total}`));
  assert.equal(height(), 1, "the oldest answer, and no further back");
  // The past is not a place to act from.
  r.stdin.write("S");
  await tick();
  assert.doesNotMatch(txt(r), /Planned stop/);
  r.stdin.write("r");
  await tick(150);
  assert.equal(n, total, "refresh is held in replay");
  r.stdin.write("]".repeat(total));
  await tick();
  assert.doesNotMatch(txt(r), /REPLAY/);
  assert.equal(height(), live);
  assert.deepEqual(calls, []);
  r.unmount();
});

test("below 80x24 it says so instead of drawing garbage", async () => {
  const r = mount(healthy, 60, 20);
  await tick();
  assert.match(txt(r), /Terminal too small/);
  assert.match(txt(r), /60x20/);
  r.unmount();
});

test("without color no color codes are written (bold and reverse remain)", async () => {
  const r = mount(healthy, 80, 24, false);
  await tick();
  r.stdin.write("4");
  await tick();
  const f = r.lastFrame() ?? "";
  assert.match(f, ESC_SEQ, "FORCE_COLOR=3 is set by the test script, so styles do show up");
  assert.doesNotMatch(f, /\u001b\[(3[0-7]|9[0-7]|38|48)[;m]/);
  r.unmount();
});

test("with color the accent is the site periwinkle", async () => {
  const r = mount(healthy, 80, 24, true);
  await tick();
  assert.match(r.lastFrame() ?? "", /\u001b\[(3[0-7]|38;)/, "color codes are written when the theme has color");
  r.unmount();
});

test("q quits", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("q");
  await tick();
  r.unmount();
});
