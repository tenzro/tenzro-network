// Runs against the compiled package in dist/ (npm test builds first).
// The OpenShell vectors shared with the Rust and Python SDKs: grants to
// Terms, session ids, and sessions the tenzro-openshell extensions signed,
// verified offline, with every tampering refused.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const dir = path.join(__dirname, "../../fixtures/openshell");
const V = JSON.parse(fs.readFileSync(path.join(dir, "vectors.json"), "utf8"));
const P = JSON.parse(fs.readFileSync(path.join(dir, "policy_terms.json"), "utf8"));

const opts = (c) => {
  const o = { identity: c.identity };
  if (c.hybrid_records_from_ms !== null && c.hybrid_records_from_ms !== undefined) o.hybridRecordsFromMs = c.hybrid_records_from_ms;
  return o;
};

test("every grant maps to the Terms the vectors state", () => {
  assert.ok(P.cases.length >= 4);
  for (const c of P.cases) {
    assert.deepEqual(sdk.openShellTerms(c.policy, c.grant, P.options), c.terms, c.name);
  }
});

test("every grant or policy the mapping must refuse is refused with its reason", () => {
  assert.ok(P.refusals.length >= 15);
  for (const c of P.refusals) {
    assert.throws(() => sdk.openShellTerms(c.policy, c.grant, P.options), (e) => e.message.includes(c.error), c.name);
  }
});

test("session ids are the extensions' layout", async () => {
  for (const c of V.session_ids) {
    assert.equal(await sdk.openShellSessionId(c.gateway, c.session), c.session_id);
  }
});

test("sessions the extensions signed verify, with their root, kinds and payments", async () => {
  assert.equal(V.sessions.length, 3);
  for (const s of V.sessions) {
    const v = await sdk.verifyOpenShellSession(s.entries, { ...opts(s), sessionId: s.expect.session_id });
    assert.equal(v.session_id, s.expect.session_id, s.name);
    assert.equal(v.agent, s.expect.agent);
    assert.equal(v.count, s.expect.count);
    assert.equal(v.root, s.expect.root);
    assert.deepEqual(v.entries.map((e) => e.kind), s.expect.kinds);
    assert.ok(v.entries.every((e) => e.image === s.expect.image));
    assert.deepEqual(sdk.openShellPayments(v), s.expect.payments);
    for (const e of v.entries.filter((e) => e.kind === "tool_call")) assert.equal(e.call.surface, "openshell");
  }
  const hybrid = await sdk.verifyOpenShellSession(V.sessions[1].entries, opts(V.sessions[1]));
  assert.ok(hybrid.entries.every((e) => e.hybrid));
});

test("entries parse from JSON Lines and from an array", async () => {
  const s = V.sessions[0];
  const lines = s.entries.map((e) => JSON.stringify(e)).join("\n");
  assert.deepEqual(sdk.parseOpenShellEntries(lines), s.entries);
  assert.deepEqual(sdk.parseOpenShellEntries(JSON.stringify(s.entries)), s.entries);
});

test("a model call's receipt header verifies", async () => {
  const r = await sdk.verifyOpenShellReceipt(V.receipt.header, opts(V.receipt));
  assert.equal(r.kind, V.receipt.expect.kind);
  assert.equal(r.action, V.receipt.expect.action);
  assert.equal(r.linked_tx, V.receipt.expect.linked_tx);
});

test("every tampering is refused with its reason", async () => {
  assert.ok(V.refusals.length >= 6);
  for (const c of V.refusals) {
    await assert.rejects(sdk.verifyOpenShellSession(c.entries, opts(c)), (e) => e.message.includes(c.error), c.name);
  }
});
