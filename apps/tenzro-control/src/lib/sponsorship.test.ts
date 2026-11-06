import { describe, expect, it } from "vitest";
import {
  assess,
  platformOf,
  proposalsFor,
  readSponsorship,
  type Read,
  type SponsorshipInputs,
} from "./sponsorship";

const ACCOUNT = `0x${"ab".repeat(32)}`;

function base(): SponsorshipInputs {
  return {
    account: ACCOUNT,
    machineDid: "did:tenzro:machine:abc",
    nodeReachable: true,
    platform: "tpm",
    windowHours: 168,
    verifiedEpochs: [100, 101, 105],
    approval: null,
    receivedWei: "0",
    sponsoredBondedWei: "0",
    caps: {
      sponsorshipYearlyMaxTnzo: "0",
      runningCostPerVerifiedEpochWei: "0",
      perGranteeYearlyMaxTnzo: "0",
      combinedYearlyMaxTnzo: "0",
    },
    proposals: [],
  };
}

const level = (a: ReturnType<typeof assess>, label: string) =>
  a.criteria.find((c) => c.label === label)?.level;

describe("sponsorship assessment", () => {
  it("a TPM machine with hours and no proposal is ready to apply", () => {
    const a = assess(base());
    expect(a.readyToApply).toBe(true);
    expect(level(a, "Verified-available hours")).toBe("pass");
    expect(level(a, "Governance approval")).toBe("todo");
  });

  it("zero caps are called out as paying nothing", () => {
    const caps = assess(base()).criteria.find((c) => c.label === "Sponsorship caps");
    expect(caps?.level).toBe("warn");
    expect(caps?.detail).toContain("pays nothing");
  });

  it("no verified hour blocks, an unreadable one does not", () => {
    const none = { ...base(), verifiedEpochs: [] };
    expect(assess(none).readyToApply).toBe(false);
    expect(level(assess(none), "Verified-available hours")).toBe("fail");
    const unread = { ...base(), verifiedEpochs: null };
    expect(level(assess(unread), "Verified-available hours")).toBe("warn");
    expect(assess(unread).readyToApply).toBe(true);
  });

  it("a Mac is told it cannot be approved", () => {
    const a = assess({ ...base(), platform: "secure-enclave" });
    expect(level(a, "Hardware endorsement")).toBe("fail");
    expect(a.readyToApply).toBe(false);
  });

  it("an approval is reported and a revoked one blocks", () => {
    const ok = assess({ ...base(), approval: { class: "validator", proposal_id: "p1", revoked: false } });
    expect(ok.approved).toBe(true);
    expect(ok.readyToApply).toBe(false);
    const revoked = assess({ ...base(), approval: { class: "validator", proposal_id: "p1", revoked: true } });
    expect(revoked.approved).toBe(false);
    expect(level(revoked, "Governance approval")).toBe("fail");
  });

  it("a proposal in flight is named and stops a second application", () => {
    const a = assess({ ...base(), proposals: [{ id: "p9", status: "Voting" }] });
    expect(a.readyToApply).toBe(false);
    expect(a.criteria.find((c) => c.label === "Governance approval")?.detail).toContain("p9");
  });

  it("platforms map from the operating system", () => {
    expect(platformOf("macos")).toBe("secure-enclave");
    expect(platformOf("linux")).toBe("tpm");
    expect(platformOf("freebsd")).toBe("unknown");
  });
});

describe("sponsorship reads", () => {
  it("matches proposals by operator whether bytes or hex", () => {
    const bytes = Array.from({ length: 32 }, () => 0xab);
    const list = {
      proposals: [
        { proposal: { id: "a", status: "Voting", action: { operator: bytes } } },
        { proposal: { id: "b", status: "Passed", action: { operator: `0x${"cd".repeat(32)}` } } },
        { proposal: { id: "c", status: "Queued", action: { operator: "ab".repeat(32) } } },
      ],
    };
    expect(proposalsFor(list, ACCOUNT).map((p) => p.id)).toEqual(["a", "c"]);
  });

  it("reads the node the way the CLI does and leaves failed reads empty", async () => {
    const now = 1_000 * 3_600_000;
    const read: Read = async (method, params) => {
      const p = params as Record<string, unknown>;
      if (method === "tenzro_getNodeStatus") return { payee: ACCOUNT, machine_did: "did:tenzro:machine:abc" };
      if (method === "tenzro_slaVerdict") return p.epoch === 999 ? { available: true } : null;
      if (method === "tenzro_getTreasuryPayouts") {
        return {
          caps: { sponsorship_yearly_max_tnzo: "50000", running_cost_per_verified_epoch_wei: "0" },
          address: { total_received: "7", operator: null },
        };
      }
      return null;
    };
    const i = await readSponsorship(read, { platform: "tpm", hours: 24, nowMs: now });
    expect(i.account).toBe(ACCOUNT);
    expect(i.verifiedEpochs).toEqual([999]);
    expect(i.receivedWei).toBe("7");
    expect(i.caps?.sponsorshipYearlyMaxTnzo).toBe("50000");
    expect(i.approval).toBeNull();
    expect(i.proposals).toEqual([]);
  });

  it("an unreachable node yields an identity failure", async () => {
    const i = await readSponsorship(async () => null, { platform: "tpm", nowMs: 0 });
    expect(i.nodeReachable).toBe(false);
    expect(assess(i).criteria[0].level).toBe("fail");
  });
});
