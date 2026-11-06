import { describe, expect, it } from "vitest";
import { describeHeld, heldLevers, type LeversRead } from "./governance";

const read: LeversRead = {
  epoch: 100,
  levers: [
    { key: "bridge.status", kind: "status", status: "enabled" },
    { key: "zk.groth16.status", kind: "status", status: "paused", guardian_pause_until_epoch: 120 },
    { key: "roles.ai.status", kind: "status", status: "paused", guardian_pause_until_epoch: null,
      pending: { value: "0", status: "enabled", activates_epoch: 105 } },
    { key: "records.old.status", kind: "status", status: "retired" },
    { key: "fees.settlement_fee_bps", kind: "value", status: null },
  ],
};

describe("held levers", () => {
  it("lists only paused and retired levers, by key", () => {
    expect(heldLevers(read).map((h) => h.key)).toEqual(["records.old.status", "roles.ai.status", "zk.groth16.status"]);
  });

  it("tells a guardian pause from a vote", () => {
    const held = heldLevers(read);
    expect(describeHeld(held[2])).toBe("Paused by the protocol guardians until epoch 120.");
    expect(describeHeld(held[1])).toBe("Paused by a vote. enabled from epoch 105.");
    expect(describeHeld(held[0])).toBe("Retired by a vote; it does not come back.");
  });

  it("treats a guardian pause that has lapsed as a vote's state", () => {
    const lapsed = heldLevers({ epoch: 130, levers: [read.levers[1]] });
    expect(lapsed[0].cause).toBe("vote");
  });
});
