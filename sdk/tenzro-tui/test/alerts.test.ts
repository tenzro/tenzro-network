import test from "node:test";
import assert from "node:assert/strict";
import { acknowledge, alertSource, findings, levelOf, noAlerts, openAlerts, step, worstUnacknowledged, type AlertEvent, type AlertState, type Condition } from "../src/alerts.js";
import type { Snapshot } from "../src/data.js";
import { down, healthy } from "./fixtures.js";

const STALE = 15_000;
const T0 = Date.now();

function withStatus(patch: Record<string, unknown>): Snapshot {
  const s = healthy();
  if (s.status.state !== "ok") throw new Error("fixture");
  return { ...s, status: { ...s.status, value: { ...s.status.value, ...patch } as never } };
}

function run(snaps: Snapshot[], start: AlertState = noAlerts, t0 = T0) {
  let state = start;
  const events: AlertEvent[] = [];
  let t = t0;
  for (const s of snaps) {
    const r = step(state, s, t, STALE);
    state = r.state;
    events.push(...r.events);
    t += 5000;
  }
  return { state, events, at: t - 5000 };
}

const keys = (state: AlertState, now: number) => openAlerts(state, now, now, STALE).map((a) => a.key);

test("a healthy node raises nothing", () => {
  const { state, events, at } = run([healthy(), healthy(), healthy()]);
  assert.deepEqual(keys(state, at), []);
  assert.deepEqual(events, []);
});

test("a finding is raised only when it holds for two snapshots, and once", () => {
  const bad = withStatus({ peer_count: 0 });
  const one = run([bad]);
  assert.deepEqual(keys(one.state, one.at), []);
  const flicker = run([bad, healthy(), bad, healthy()]);
  assert.deepEqual(keys(flicker.state, flicker.at), []);
  assert.deepEqual(flicker.events, []);
  const held = run([bad, bad, bad, bad]);
  assert.deepEqual(keys(held.state, held.at), ["no-peers"]);
  assert.deepEqual(held.events.map((e) => `${e.what} ${e.key}`), ["raised no-peers"]);
});

test("a raised alert clears only after two clear snapshots", () => {
  const bad = withStatus({ peer_count: 0 });
  const blip = run([bad, bad, healthy(), bad, healthy()]);
  assert.deepEqual(keys(blip.state, blip.at), ["no-peers"]);
  assert.equal(blip.events.filter((e) => e.what === "raised").length, 1, "one alert, not two");
  const gone = run([bad, bad, healthy(), healthy()]);
  assert.deepEqual(keys(gone.state, gone.at), []);
  assert.deepEqual(gone.events.map((e) => e.what), ["raised", "cleared"]);
});

test("the three levels sort worst first", () => {
  const s = withStatus({ peer_count: 0, health_status: "Degraded" });
  const all = { ...down("http://x:1"), syncing: { state: "ok" as const, value: true, at: T0 } };
  const { state, at } = run([all, all]);
  const open = openAlerts(state, at, at, STALE);
  assert.deepEqual(open.map((a) => a.level), ["page", "info"]);
  assert.equal(worstUnacknowledged(open), "page");
  const warn = run([s, s]);
  assert.deepEqual(openAlerts(warn.state, warn.at, warn.at, STALE).map((a) => a.level), ["warn", "warn"]);
});

test("finality that stops advancing is a page-level alert; while catching up it is not", () => {
  const stuck = healthy();
  const many = Array.from({ length: 8 }, () => stuck);
  const { state, at } = run(many);
  assert.deepEqual(keys(state, at), ["finality-stalled"]);
  const syncing = { ...stuck, syncing: { state: "ok" as const, value: true, at: T0 } };
  const quiet = run(Array.from({ length: 8 }, () => syncing));
  assert.deepEqual(keys(quiet.state, quiet.at), ["syncing"]);
  let h = 100;
  const moving = Array.from({ length: 8 }, () => ({ ...stuck, finalized: { state: "ok" as const, value: h++, at: T0 } }));
  const fine = run(moving);
  assert.deepEqual(keys(fine.state, fine.at), []);
});

test("an acknowledgement needs a reason, stays until the alert clears, and does not cover a worse level", () => {
  const bad = withStatus({ peer_count: 0 });
  const { state, at } = run([bad, bad]);
  assert.match(acknowledge(state, "no-peers", "   ", at) as string, /needs a reason/);
  assert.match(acknowledge(state, "nothing", "why", at) as string, /no longer open/);
  const done = acknowledge(state, "no-peers", "isolated on purpose for the drill, token=planted-ack-secret", at);
  assert.ok(typeof done !== "string");
  assert.equal(done.event.what, "acknowledged");
  const acked = openAlerts(done.state, at, at, STALE);
  assert.equal(acked[0]!.ack!.reason, "isolated on purpose for the drill, token=***");
  assert.equal(worstUnacknowledged(acked), null);
  const kept = run([bad, bad], done.state, at + 5000);
  assert.ok(openAlerts(kept.state, kept.at, kept.at, STALE).find((a) => a.key === "no-peers")!.ack, "kept while the alert holds");
  const back = run([healthy(), healthy(), bad, bad], done.state, at + 5000);
  const again = openAlerts(back.state, back.at, back.at, STALE).find((a) => a.key === "no-peers");
  assert.ok(again, "raised again");
  assert.equal(again.ack, null, "a new occurrence is not pre-acknowledged");
});

const SINCE = "2027-01-15T07:58:30Z";
const condition = (id: string, severity: string, since = SINCE): Condition => ({ id, kind: "node", title: `Condition ${id}`, detail: "detail", since, code: id, severity });

test("the node's conditions list replaces the console's rules when the node serves one", () => {
  const rules = withStatus({ peer_count: 0 });
  assert.equal(alertSource(rules), "rules");
  const listed = [condition("requirement:disk", "warning"), condition("key_grant", "critical"), condition("update:0.2.9", "info")];
  const served = { ...withStatus({ peer_count: 0, health_status: "Degraded" }), conditions: { state: "ok" as const, value: listed, at: T0 } };
  assert.equal(alertSource(served), "conditions");
  // Peers and disk are the node's to judge once it lists conditions; health is on no list and stays the console's.
  assert.deepEqual(findings(served, noAlerts, T0, STALE).map((f) => `${f.level} ${f.key}`), [
    "warn node-health",
    `warn condition:requirement:disk@${SINCE}`,
    `page condition:key_grant@${SINCE}`,
    `info condition:update:0.2.9@${SINCE}`,
  ]);
  const { state, at } = run([served, served]);
  assert.deepEqual(keys(state, at), [`condition:key_grant@${SINCE}`, `condition:requirement:disk@${SINCE}`, "node-health", `condition:update:0.2.9@${SINCE}`]);
  // A node that answers nothing cannot list its conditions: the console still says so itself.
  const gone = down("http://x:1");
  assert.deepEqual(findings({ ...gone, conditions: served.conditions }, noAlerts, T0, STALE).map((f) => f.key)[0], "node-unreachable");
  assert.equal(levelOf("critical"), "page");
  assert.equal(levelOf("warning"), "warn");
  assert.equal(levelOf("info"), "info");
  assert.equal(levelOf("something-new"), "warn");
});

test("a condition that opens again is a new occurrence: an old acknowledgement does not cover it", () => {
  const open = (since: string) => ({ ...healthy(), conditions: { state: "ok" as const, value: [condition("follow", "critical", since)], at: T0 } });
  const first = run([open(SINCE), open(SINCE)]);
  const key = `condition:follow@${SINCE}`;
  const acked = acknowledge(first.state, key, "known: the uplink is being moved", first.at);
  assert.ok(typeof acked !== "string");
  // Its code or detail may change while it stays open; the acknowledgement stays.
  const worse = { ...open(SINCE), conditions: { state: "ok" as const, value: [{ ...condition("follow", "critical", SINCE), code: "stalled", detail: "no block for an hour" }], at: T0 } };
  const same = run([worse], acked.state, first.at + 5000);
  assert.ok(openAlerts(same.state, same.at, same.at, STALE)[0]!.ack);
  const later = "2027-01-15T09:10:00Z";
  const again = run([open(later), open(later)], same.state, same.at + 5000);
  const now = openAlerts(again.state, again.at, again.at, STALE);
  assert.deepEqual(now.map((a) => a.key), [`condition:follow@${later}`]);
  assert.equal(now[0]!.ack, null);
});

test("with no fresh answer for three periods the console raises its own alert without a snapshot", () => {
  const { state, at } = run([healthy(), healthy()]);
  assert.deepEqual(openAlerts(state, at, at + STALE, STALE), []);
  const blind = openAlerts(state, at, at + STALE + 1, STALE);
  assert.deepEqual(blind.map((a) => `${a.level} ${a.key}`), ["page console-blind"]);
  assert.match(acknowledge(state, "console-blind", "fine", at) as string, /no longer open/);
});
