import test from "node:test";
import assert from "node:assert/strict";
import { noAlerts, openAlerts, step } from "../src/alerts.js";
import type { Snapshot } from "../src/data.js";
import { quorum, stopAllowed, stopChecks, stopConsequence } from "../src/stop.js";
import { down, healthy } from "./fixtures.js";

function withValidators(active: number, others: string[] = [], roles: unknown = ["Validator"]): Snapshot {
  const s = healthy();
  if (s.status.state !== "ok" || s.validators.state !== "ok") throw new Error("fixture");
  const one = s.validators.value[0]!;
  const set = [...Array.from({ length: active }, () => "Active"), ...others].map((status, i) => ({ ...one, address: `v${i}`, status }));
  return { ...s, status: { ...s.status, value: { ...s.status.value, roles } as never }, validators: { ...s.validators, value: set as never } };
}

const verdict = (snap: Snapshot) => Object.fromEntries(stopChecks(snap, []).map((c) => [c.id, c.ok]));

test("quorum is n - floor((n - 1) / 3)", () => {
  assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 10, 13].map(quorum), [1, 2, 3, 3, 4, 5, 5, 7, 9]);
});

test("a validator may stop only when quorum plus one remain without it", () => {
  for (const [n, ok] of [[1, false], [3, false], [4, false], [5, false], [6, false], [7, true], [8, true], [10, true]] as const) {
    const checks = stopChecks(withValidators(n), []);
    assert.equal(checks.find((c) => c.id === "quorum")!.ok, ok, `${n} active`);
    assert.equal(stopAllowed(checks), ok, `${n} active`);
  }
  assert.match(stopChecks(withValidators(4), []).find((c) => c.id === "quorum")!.text, /4 validators are active; without this one only 3 would remain, and 4 \(quorum plus one\) are needed/);
});

test("only Active registrations count, and a node that does not validate takes nothing from the set", () => {
  assert.equal(verdict(withValidators(6, ["Jailed", "Exited", "Pending"])).quorum, false);
  assert.equal(verdict(withValidators(1, [], ["Provider"])).quorum, true);
  assert.ok(stopAllowed(stopChecks(withValidators(1, [], ["Provider"]), [])));
});

test("a node that is catching up, unreadable, or has an open page-level alert is not stopped", () => {
  const ok = withValidators(7);
  assert.equal(verdict({ ...ok, syncing: { state: "ok", value: true, at: 0 } }).syncing, false);
  const gone = down("http://x:1");
  assert.deepEqual(verdict(gone), { fresh: false, alerts: true, syncing: true, quorum: false });
  assert.ok(!stopAllowed(stopChecks(gone, [])));

  let state = noAlerts;
  const t = Date.now();
  for (const at of [t, t + 5000]) state = step(state, gone, at, 15000).state;
  const alerts = openAlerts(state, t + 5000, t + 5000, 15000);
  const blocked = stopChecks(ok, alerts);
  assert.equal(blocked.find((c) => c.id === "alerts")!.ok, false);
  assert.match(blocked.find((c) => c.id === "alerts")!.text, /The node does not answer/);
  const acked = alerts.map((a) => ({ ...a, ack: { reason: a.title, at: t } }));
  assert.ok(stopAllowed(stopChecks(ok, acked)), "an acknowledged alert no longer blocks");
});

test("the consequence of a stop is said in one sentence before it is confirmed", () => {
  assert.match(stopConsequence(withValidators(7)), /this validator stops signing, leaving 6 of 7, 1 over quorum\. The node first waits until it leads none of the coming rounds/);
  assert.match(stopConsequence(withValidators(10)), /leaving 9 of 10, 2 over quorum/);
  assert.match(stopConsequence(withValidators(3, [], ["Provider"])), /stops answering its callers.*The validator set is not affected/);
  assert.match(stopConsequence(down("http://x:1")), /could not be read/);
});
