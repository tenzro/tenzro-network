// Replays the shared light-client fixture (sdk/fixtures/light-client) through
// the WebAssembly build: the node's replies the Rust core recorded, answered
// by a transport over the recording. Run after ./build.sh.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { LightClient } = require("../pkg/tenzro_light_wasm.js");
const f = JSON.parse(readFileSync(new URL("../../fixtures/light-client/fixture.json", import.meta.url)));
const expect = f.expect;
const clock = [BigInt(f.clock.now_ms), BigInt(f.clock.max_age_ms), BigInt(f.clock.max_ahead_ms)];

async function replay(method, paramsJson) {
  const c = f.calls.find((c) => c.method === method && c.params === paramsJson);
  if (!c) throw new Error(`no recorded reply to ${method} ${paramsJson}`);
  return c.result;
}

const client = (transport = replay) =>
  new LightClient(transport, BigInt(f.chain_id), f.genesis_hash, BigInt(f.epoch), f.committee_root, f.committee_reply);

test("syncs and proves an identity's keys", async () => {
  const lc = client();
  const cp = JSON.parse(await lc.sync(...clock));
  assert.equal(cp.index, expect.checkpoint.index);
  assert.equal(Buffer.from(cp.state_root).toString("hex"), expect.checkpoint.state_root);

  const id = JSON.parse(await lc.resolve_identity(expect.identity.did, ...clock));
  for (const k of ["controller_key", "ml_dsa_key", "key_digest", "revoked", "key_type", "identity_type"]) {
    assert.equal(id[k], expect.identity[k], k);
  }
  assert.equal(await lc.resolve_identity(expect.absent_did, ...clock), null);
});

test("proves an identity's key history", async () => {
  const lc = client();
  await lc.sync(...clock);
  const want = expect.key_history;
  const h = JSON.parse(await lc.key_history(expect.identity.did, ...clock));
  assert.equal(h.epochs.length, want.keys);
  assert.equal(h.head.sequence, want.sequence);
  assert.equal(h.head.head, want.head);
  const key = h.epochs.at(-1);
  assert.equal(key.version, want.version);
  assert.equal(key.ed25519, want.ed25519);
  assert.equal(key.effective_from_ms, want.effective_from_ms);
});

test("saved state restores and refuses a rollback", async () => {
  const lc = client();
  const cp = JSON.parse(await lc.sync(...clock));
  const saved = lc.save();
  const back = LightClient.restore(replay, saved, BigInt(f.chain_id), f.genesis_hash, BigInt(cp.index));
  assert.equal(JSON.parse(back.latest()).index, cp.index);
  assert.throws(() => LightClient.restore(replay, saved, BigInt(f.chain_id), f.genesis_hash, BigInt(cp.index + 1)));
});

test("nothing is read before a checkpoint is certified", () => {
  assert.throws(() => client().resolve_identity(expect.identity.did, ...clock));
});

test("members that do not hash to the root are refused", () => {
  assert.throws(
    () => new LightClient(replay, BigInt(f.chain_id), f.genesis_hash, BigInt(f.epoch), "07".repeat(32), f.committee_reply),
  );
});

test("a transport failure is reported and nothing is taken", async () => {
  const lc = client(async () => {
    throw new Error("connection refused");
  });
  await assert.rejects(lc.sync(...clock));
  assert.equal(lc.latest(), undefined);
});

test("an old checkpoint is refused against the caller's clock", async () => {
  const late = [clock[0] + 3_600_000n, clock[1], clock[2]];
  await assert.rejects(client().sync(...late));
});
