import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { render } from "ink-testing-library";
import { noAlerts, openAlerts, step } from "../src/alerts.js";
import { App } from "../src/app.js";
import { rehearsalHelper, rehearsalSource, scripted, SCRIPT_LENGTH } from "../src/rehearsal.js";
import { stopAllowed, stopChecks } from "../src/stop.js";
import { makeTheme } from "../src/theme.js";

const tick = (ms = 80) => new Promise((res) => setTimeout(res, ms));

test("the script runs healthy, loses the network for four steps, recovers, and repeats", () => {
  const t = Date.now();
  const stalled = Array.from({ length: SCRIPT_LENGTH * 2 }, (_, n) => {
    const s = scripted(n, t);
    return s.conditions.state === "ok" && s.conditions.value !== null && s.conditions.value.length > 0;
  });
  assert.deepEqual(stalled.slice(0, SCRIPT_LENGTH), [false, false, false, true, true, true, true, false, false, false, false, false]);
  assert.deepEqual(stalled.slice(SCRIPT_LENGTH), stalled.slice(0, SCRIPT_LENGTH));
  const heights = Array.from({ length: SCRIPT_LENGTH * 2 }, (_, n) => {
    const s = scripted(n, t);
    return s.status.state === "ok" ? s.status.value.block_height : -1;
  });
  assert.ok(heights.every((h, i) => i === 0 || h >= heights[i - 1]!), `height never goes back: ${heights}`);
  assert.equal(new Set(heights.slice(3, 7)).size, 1, "frozen while stalled");
});

test("the scripted stall raises one page-level alert, blocks a stop, and clears", () => {
  let state = noAlerts;
  const seen: string[][] = [];
  const allowed: boolean[] = [];
  const t = Date.now();
  for (let n = 0; n < SCRIPT_LENGTH; n++) {
    const snap = scripted(n, t + n * 5000);
    state = step(state, snap, t + n * 5000, 15000).state;
    const alerts = openAlerts(state, t + n * 5000, t + n * 5000, 15000);
    seen.push(alerts.map((a) => a.level));
    allowed.push(stopAllowed(stopChecks(snap, alerts)));
  }
  assert.deepEqual(seen.map((l) => l.join()), ["", "", "", "", "page", "page", "page", "page", "", "", "", ""]);
  assert.deepEqual(allowed, [true, true, true, true, false, false, false, false, true, true, true, true]);
});

test("a rehearsed stop reaches only the rehearsal helper and says nothing was stopped", async () => {
  const asked: { method: string; params: unknown }[] = [];
  const r = render(<App source={rehearsalSource()} helper={rehearsalHelper(asked)} banner="REHEARSAL" theme={makeTheme(false)} initialAccount={null} refreshMs={60000} size={{ columns: 100, rows: 30 }} />);
  const txt = () => (r.lastFrame() ?? "").replace(/\u001b\[[0-9;]*m/g, "");
  await tick();
  assert.match(txt(), /REHEARSAL/);
  assert.match(txt(), /rehearsal \(no node is contacted\)/);
  r.stdin.write("S");
  await tick();
  assert.match(txt(), /ok\s+7 validators are active; without this one 6 remain, and 6 \(quorum plus one\) are needed/);
  assert.match(txt().replace(/\s+/g, " "), /If you go on: this validator stops signing, leaving 6 of 7, 1 over quorum/);
  r.stdin.write("STOP");
  await tick();
  r.stdin.write("\r");
  await tick(200);
  assert.match(txt().replace(/\s+/g, " "), /the node service is running \(rehearsal: nothing was stopped\)/);
  assert.deepEqual(asked, [{ method: "control_service", params: { action: "stop" } }]);
  r.unmount();
});
