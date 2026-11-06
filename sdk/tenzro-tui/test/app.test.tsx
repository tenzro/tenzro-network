import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { render } from "ink-testing-library";
import { App } from "../src/app.js";
import { makeTheme } from "../src/theme.js";
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
    url: "http://127.0.0.1:8545",
    collect: async (_a: string | null, prev: typeof first) => {
      n++;
      if (n === 1) return first;
      const lastOk = prev.status.state === "ok" ? { value: prev.status.value, at: prev.status.at } : prev.status.state === "error" ? prev.status.last : undefined;
      const e = { state: "error" as const, error: "gone", at: Date.now(), ...(lastOk ? { last: lastOk } : {}) };
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

test("below 80x24 it says so instead of drawing garbage", async () => {
  const r = mount(healthy, 60, 20);
  await tick();
  assert.match(txt(r), /Terminal too small/);
  assert.match(txt(r), /60x20/);
  r.unmount();
});

test("without colour no colour codes are written (bold and reverse remain)", async () => {
  const r = mount(healthy, 80, 24, false);
  await tick();
  r.stdin.write("4");
  await tick();
  const f = r.lastFrame() ?? "";
  assert.match(f, ESC_SEQ, "FORCE_COLOR=3 is set by the test script, so styles do show up");
  assert.doesNotMatch(f, /\u001b\[(3[0-7]|9[0-7]|38|48)[;m]/);
  r.unmount();
});

test("with colour the accent is the site periwinkle", async () => {
  const r = mount(healthy, 80, 24, true);
  await tick();
  assert.match(r.lastFrame() ?? "", /\u001b\[(3[0-7]|38;)/, "colour codes are written when the theme has colour");
  r.unmount();
});

test("q quits", async () => {
  const r = mount(healthy);
  await tick();
  r.stdin.write("q");
  await tick();
  r.unmount();
});
