import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { render } from "ink-testing-library";
import { App } from "../src/app.js";
import { emptySnapshot } from "../src/data.js";
import { runbooks } from "../src/guides.js";
import { makeTheme } from "../src/theme.js";
import { healthy, sourceOf } from "./fixtures.js";

const STEP_FIELDS = ["caution", "gate", "id", "progress", "result", "skippable", "state", "title", "what", "why"];

test("every step has exactly the fields of a Control setup-plan step, and ids are unique", () => {
  const books = runbooks(emptySnapshot, []);
  assert.deepEqual(books.map((b) => b.id), ["genesis", "validator", "upgrade"]);
  const ids = books.flatMap((b) => b.steps.map((s) => s.id));
  assert.equal(new Set(ids).size, ids.length);
  for (const s of books.flatMap((b) => b.steps)) {
    assert.deepEqual(Object.keys(s).sort(), STEP_FIELDS, s.id);
    assert.ok(["free", "os_permission", "passkey"].includes(s.gate), s.id);
    assert.ok(s.title && s.what && s.why, s.id);
  }
});

test("a step is pending unless the console read its state from the node", () => {
  const blind = runbooks(emptySnapshot, []).flatMap((b) => b.steps);
  assert.ok(blind.every((s) => s.state === "pending" && s.result === null));

  const seen = Object.fromEntries(runbooks(healthy(), []).flatMap((b) => b.steps).map((s) => [s.id, s]));
  assert.equal(seen["genesis.start"]!.state, "done");
  assert.match(seen["genesis.start"]!.result!, /Running, Healthy, at height 1234567/);
  assert.equal(seen["validator.replay"]!.state, "done");
  // One active validator: the set cannot lose it.
  assert.equal(seen["upgrade.headroom"]!.state, "failed");
  assert.match(seen["upgrade.headroom"]!.result!, /only 0 would remain/);
  assert.equal(seen["genesis.collect"]!.state, "pending");

  const replaying = { ...healthy(), syncing: { state: "ok" as const, value: true, at: 0 } };
  assert.equal(runbooks(replaying, [])[1]!.steps[1]!.state, "running");
});

test("a runbook opens from the finder, moves by step and shows what, why and what was seen", async () => {
  const r = render(<App source={sourceOf(healthy)} theme={makeTheme(false)} initialAccount={null} refreshMs={60000} size={{ columns: 120, rows: 40 }} />);
  const tick = (ms = 80) => new Promise((res) => setTimeout(res, ms));
  const txt = () => (r.lastFrame() ?? "").replace(/\u001b\[[0-9;]*m/g, "");
  await tick();
  r.stdin.write("/");
  await tick();
  r.stdin.write("upgrade");
  await tick();
  r.stdin.write("\r");
  await tick();
  let f = txt();
  assert.match(f, /Runbook: Upgrade window/);
  assert.match(f, /> 1\. FAILED\s+Check the set can lose one validator/);
  assert.match(f, /Seen: 1 validators are active/);
  r.stdin.write("j");
  await tick();
  f = txt();
  assert.match(f, /> 2\. PENDING\s+Update one validator/);
  assert.match(f, /Care: Do not use systemctl restart/);
  assert.match(f, /Needs: the machine's own permissions/);
  // Keys do nothing else here: q is not quit, 3 is not a screen.
  r.stdin.write("q3");
  await tick();
  assert.match(txt(), /Runbook: Upgrade window/);
  r.stdin.write("\u001b");
  await tick(150);
  assert.doesNotMatch(txt(), /Runbook:/);
  r.unmount();
});
