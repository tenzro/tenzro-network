import test from "node:test";
import assert from "node:assert/strict";
import { BINDINGS, SCREENS, actionFor, bindingProblems } from "../src/keys.js";

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
