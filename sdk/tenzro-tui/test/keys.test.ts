import test from "node:test";
import assert from "node:assert/strict";
import { BINDINGS, SCREENS, actionFor, bindingProblems, paletteMatches } from "../src/keys.js";

test("no key is bound twice and no label is reused", () => {
  assert.deepEqual(bindingProblems(), []);
});

test("the checker does catch a duplicate", () => {
  const bad = [...BINDINGS, { action: "refresh" as const, keys: ["q"], label: "Other" }];
  assert.ok(bindingProblems(bad).some((p) => p.includes("key q")));
});

test("every screen has exactly one number key and one binding", () => {
  for (const s of SCREENS) assert.equal(actionFor(s.key), s.action);
  assert.equal(new Set(SCREENS.map((s) => s.key)).size, SCREENS.length);
});

test("every footer hint belongs to a binding in the table", () => {
  for (const b of BINDINGS) if (b.hint) assert.ok(b.keys.length > 0);
});

test("the palette offers what the key table holds, filtered by every word typed", () => {
  const all = paletteMatches("");
  assert.equal(all.length, BINDINGS.length - 2, "everything but the palette itself and close");
  assert.deepEqual(paletteMatches("heard from").map((b) => b.action), ["screen:peers"]);
  assert.deepEqual(paletteMatches("STOP planned").map((b) => b.action), ["stop"]);
  assert.deepEqual(paletteMatches("screen next").map((b) => b.action), ["next"]);
  assert.deepEqual(paletteMatches("runbook").map((b) => b.action), ["runbook:genesis", "runbook:validator", "runbook:upgrade"]);
  assert.deepEqual(paletteMatches("no such thing"), []);
});
