import { describe, expect, it } from "vitest";
import fixtures from "./onboarding-fixtures.json";
import {
  currentEnv,
  ladderLine,
  resolveState,
  stakeGap,
  type ApplicationState,
  type Line,
  type MsgEnv,
  type Phase,
} from "./onboarding";

describe("onboarding message matches the CLI's", () => {
  it("replays every case the Rust builder produced", () => {
    expect(fixtures.cases.length).toBeGreaterThan(100);
    for (const c of fixtures.cases) {
      const env: MsgEnv = {
        phase: c.phase as Phase,
        join_link: fixtures.env.join_link,
        contacts: fixtures.env.contacts,
        reply_time: fixtures.env.reply_time,
      };
      const got = stakeGap(
        {
          roleLabel: c.role_label,
          requiredWei: BigInt(c.required_wei),
          balanceWei: c.balance_wei === null ? null : BigInt(c.balance_wei),
          account: c.account,
          state: c.state as ApplicationState,
        },
        env,
      );
      expect(got as Line[] | null, JSON.stringify(c)).toEqual(c.lines);
    }
  });
});

describe("state", () => {
  it("serving without a stake is not believed; a report is capped at funded", () => {
    expect(resolveState({ reported: "applied", balanceMeetsMinimum: null, chainStaked: null, chainServing: true })).toBe("applied");
    expect(resolveState({ reported: "serving", balanceMeetsMinimum: null, chainStaked: null, chainServing: null })).toBe("funded");
    expect(resolveState({ reported: "approved", balanceMeetsMinimum: true, chainStaked: null, chainServing: null })).toBe("funded");
    expect(resolveState({ reported: null, balanceMeetsMinimum: null, chainStaked: null, chainServing: null })).toBe("not_applied");
  });
  it("brackets the current rung", () => {
    expect(ladderLine("approved")).toContain("[approved]");
  });
  it("the shipped config names real channels and defaults to the initial phase", () => {
    const env = currentEnv();
    expect(env.contacts.length).toBeGreaterThan(0);
    expect(env.contacts.some((c) => c.includes("PLACEHOLDER") || c.includes(".invalid"))).toBe(false);
    expect(env.reply_time.includes("PLACEHOLDER")).toBe(false);
    expect(env.phase).toBe("foundation");
  });
});
