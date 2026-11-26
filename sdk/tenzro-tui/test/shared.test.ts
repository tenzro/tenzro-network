import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { acknowledge, adopt, noAlerts, openAlerts, step, type AlertState } from "../src/alerts.js";
import { MAX_SHARED_BYTES, readShared, writeShared } from "../src/shared.js";
import { down } from "./fixtures.js";

const STALE = 15000;

function raised(at: number): { state: AlertState; key: string } {
  const snap = down("http://127.0.0.1:8545");
  const state = step(step(noAlerts, snap, at, STALE).state, snap, at + 1, STALE).state;
  const key = Object.keys(state.tracks).find((k) => state.tracks[k]!.raised);
  assert.ok(key, "the down node raises an alert");
  return { state, key };
}

function tempFile(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "tui-shared-")), "acks.json");
}

test("an acknowledgement one console shares shows in another that names the file", () => {
  const file = tempFile();
  const { state, key } = raised(1000);
  const done = acknowledge(state, key, "known: maintenance window", 2000);
  assert.ok(typeof done !== "string");
  const ack = done.state.tracks[key]!.ack!;
  assert.equal(writeShared(file, key, { level: done.event.level, reason: ack.reason, at: ack.at }), null);

  const other = raised(1000).state;
  const shown = openAlerts(adopt(other, readShared(file)), 1001, 1001, STALE).find((a) => a.key === key);
  assert.equal(shown?.ack?.reason, "known: maintenance window");
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test("a shared acknowledgement older than the alert, or given at a milder level, does not carry", () => {
  const { state, key } = raised(5000);
  const level = state.tracks[key]!.finding.level;
  assert.equal(adopt(state, { [key]: { level, reason: "old", at: 4000 } }).tracks[key]!.ack, null);
  if (level !== "info") assert.equal(adopt(state, { [key]: { level: "info", reason: "milder", at: 6000 } }).tracks[key]!.ack, null);
  assert.equal(adopt(state, { [key]: { level, reason: "now", at: 6000 } }).tracks[key]!.ack?.reason, "now");
});

test("a reason planted in the shared file is redacted before it is shown", () => {
  const { state, key } = raised(1000);
  const level = state.tracks[key]!.finding.level;
  const planted = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2lnbmF0dXJlc2ln";
  const ack = adopt(state, { [key]: { level, reason: `see token=${planted}`, at: 2000 } }).tracks[key]!.ack;
  assert.ok(ack && !ack.reason.includes(planted), String(ack?.reason));
});

test("a malformed or oversized shared file reads as no acknowledgements", () => {
  const file = tempFile();
  assert.deepEqual(readShared(file), {});
  fs.writeFileSync(file, "{not json");
  assert.deepEqual(readShared(file), {});
  fs.writeFileSync(file, JSON.stringify({ a: { level: "loud", reason: "x", at: 1 }, b: { level: "warn", reason: "ok", at: 2 } }));
  assert.deepEqual(readShared(file), { b: { level: "warn", reason: "ok", at: 2 } });
  fs.writeFileSync(file, JSON.stringify({ b: { level: "warn", reason: "x".repeat(MAX_SHARED_BYTES), at: 2 } }));
  assert.deepEqual(readShared(file), {});
});

test("writing one acknowledgement keeps the others", () => {
  const file = tempFile();
  assert.equal(writeShared(file, "a", { level: "warn", reason: "first", at: 1 }), null);
  assert.equal(writeShared(file, "b", { level: "page", reason: "second", at: 2 }), null);
  assert.deepEqual(Object.keys(readShared(file)).sort(), ["a", "b"]);
  assert.match(writeShared(file, "c", { level: "warn", reason: "x".repeat(501), at: 3 }) ?? "", /too long/);
});
