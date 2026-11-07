// Sponsorship standing of this operator, read from the embedded node.
//
// This reads the same node methods as `tenzro sponsor check` and judges them
// by the same criteria (crates/tenzro-cli/src/commands/sponsor.rs): the
// machine DID and account from `tenzro_getNodeStatus`, verified-available
// hours from `tenzro_slaVerdict`, the approval record and governed caps from
// `tenzro_getTreasuryPayouts`, governance-sponsored stake from
// `tenzro_getSponsoredBond`, and an approval proposal in flight from
// `tenzro_listProposals`. The node exposes no read for the TPM endorsement
// chain, which the chain checks when a proposal is enacted, so that criterion
// states what the platform makes of it.

export type Level = "pass" | "fail" | "warn" | "todo";

export interface Criterion {
  label: string;
  level: Level;
  detail: string;
}

export interface Caps {
  sponsorshipYearlyMaxTnzo: string;
  runningCostPerVerifiedEpochWei: string;
  perGranteeYearlyMaxTnzo: string;
  combinedYearlyMaxTnzo: string;
}

export interface ProposalLine {
  id: string;
  status: string;
}

export type Platform = "tpm" | "secure-enclave" | "unknown";

export interface SponsorshipInputs {
  account: string | null;
  machineDid: string | null;
  nodeReachable: boolean;
  platform: Platform;
  windowHours: number;
  /** Epochs with a verified-available verdict; null when the reads failed. */
  verifiedEpochs: number[] | null;
  approval: { class?: string; proposal_id?: string; revoked?: boolean; verified_epochs?: number } | null;
  receivedWei: string;
  sponsoredBondedWei: string;
  caps: Caps | null;
  proposals: ProposalLine[];
}

export interface Assessment {
  criteria: Criterion[];
  approved: boolean;
  /** A proposer can file the approval for this operator now. */
  readyToApply: boolean;
}

/** One node read: the result, or null when the call failed. */
export type Read = (method: string, params: unknown) => Promise<unknown | null>;

const EPOCH_MS = 3_600_000;
const BATCH = 12;

export function platformOf(os: string): Platform {
  if (os === "macos" || os === "ios") return "secure-enclave";
  if (os === "linux" || os === "windows") return "tpm";
  return "unknown";
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function capsOf(payouts: Record<string, unknown>): Caps | null {
  const c = asRecord(payouts.caps);
  if (!c) return null;
  const s = (k: string) => (c[k] === undefined || c[k] === null ? "0" : String(c[k]));
  return {
    sponsorshipYearlyMaxTnzo: s("sponsorship_yearly_max_tnzo"),
    runningCostPerVerifiedEpochWei: s("running_cost_per_verified_epoch_wei"),
    perGranteeYearlyMaxTnzo: s("per_grantee_yearly_max_tnzo"),
    combinedYearlyMaxTnzo: s("combined_yearly_max_tnzo"),
  };
}

function capsOpen(c: Caps): boolean {
  return [c.sponsorshipYearlyMaxTnzo, c.runningCostPerVerifiedEpochWei, c.combinedYearlyMaxTnzo].some(
    (v) => /^\d+$/.test(v) && BigInt(v) > 0n,
  );
}

/** The operator hex an approve_operator proposal names, from bytes or hex. */
function proposalOperator(action: unknown): string | null {
  const op = asRecord(action)?.operator;
  if (typeof op === "string") return op.replace(/^0x/, "").toLowerCase();
  if (Array.isArray(op) && op.every((b) => Number.isInteger(b) && b >= 0 && b < 256)) {
    return op.map((b: number) => b.toString(16).padStart(2, "0")).join("");
  }
  return null;
}

export function proposalsFor(list: unknown, account: string): ProposalLine[] {
  const want = account.replace(/^0x/, "").toLowerCase();
  const entries = asRecord(list)?.proposals;
  if (!Array.isArray(entries)) return [];
  const out: ProposalLine[] = [];
  for (const entry of entries) {
    const p = asRecord(asRecord(entry)?.proposal);
    if (!p || proposalOperator(p.action) !== want) continue;
    const id = str(p.id);
    if (!id) continue;
    out.push({ id, status: typeof p.status === "string" ? p.status : JSON.stringify(p.status) });
  }
  return out;
}

async function verifiedEpochs(read: Read, did: string, from: number, to: number): Promise<number[] | null> {
  const epochs: number[] = [];
  for (let e = from; e <= to; e++) epochs.push(e);
  const verified: number[] = [];
  let anyRead = false;
  for (let i = 0; i < epochs.length; i += BATCH) {
    const batch = epochs.slice(i, i + BATCH);
    const answers = await Promise.all(
      batch.map((epoch) => read("tenzro_slaVerdict", { provider_did: did, epoch })),
    );
    answers.forEach((v, k) => {
      if (v === null) return;
      anyRead = true;
      if (asRecord(v)?.available === true) verified.push(batch[k]);
    });
  }
  verified.sort((a, b) => a - b);
  return anyRead ? verified : null;
}

/** Read everything the verdict needs; a read that fails is left empty. */
export async function readSponsorship(
  read: Read,
  opts: { platform: Platform; hours?: number; nowMs?: number },
): Promise<SponsorshipInputs> {
  const hours = opts.hours ?? 168;
  const status = asRecord(await read("tenzro_getNodeStatus", []));
  const account = str(status?.payee);
  const machineDid = str(status?.machine_did);

  const to = Math.floor((opts.nowMs ?? Date.now()) / EPOCH_MS);
  const from = Math.max(0, to - (hours - 1));
  const verified = machineDid ? await verifiedEpochs(read, machineDid, from, to) : null;

  let approval: SponsorshipInputs["approval"] = null;
  let receivedWei = "0";
  let caps: Caps | null = null;
  let sponsoredBondedWei = "0";
  let proposals: ProposalLine[] = [];
  if (account) {
    const payouts = asRecord(await read("tenzro_getTreasuryPayouts", { address: account, limit: 1 }));
    if (payouts) {
      caps = capsOf(payouts);
      const a = asRecord(payouts.address);
      receivedWei = str(a?.total_received) ?? "0";
      const op = asRecord(a?.operator);
      approval = op ? (op as SponsorshipInputs["approval"]) : null;
    }
    const bond = asRecord(await read("tenzro_getSponsoredBond", { address: account }));
    sponsoredBondedWei = str(bond?.sponsored_bonded) ?? "0";
    proposals = proposalsFor(await read("tenzro_listProposals", { kind: "approve_operator", limit: 50 }), account);
  }

  return {
    account,
    machineDid,
    nodeReachable: status !== null,
    platform: opts.platform,
    windowHours: hours,
    verifiedEpochs: verified,
    approval,
    receivedWei,
    sponsoredBondedWei,
    caps,
    proposals,
  };
}

/** Judge the inputs against what an operator approval is enacted on. */
export function assess(i: SponsorshipInputs): Assessment {
  const criteria: Criterion[] = [];
  const add = (label: string, level: Level, detail: string) => criteria.push({ label, level, detail });

  if (i.machineDid && i.account) {
    add("Identity", "pass", `${i.machineDid}, account ${i.account}`);
  } else if (!i.nodeReachable) {
    add("Identity", "fail", "The node did not answer; it is still starting or has stopped.");
  } else {
    add("Identity", "fail", "The node reports no machine identity or account.");
  }

  if (i.platform === "secure-enclave") {
    add(
      "Hardware endorsement",
      "fail",
      "A Secure Enclave has no TPM endorsement certificate, and operator approval requires one that chains to a recognized root. A Mac cannot be approved today.",
    );
  } else if (i.platform === "tpm") {
    add(
      "Hardware endorsement",
      "warn",
      "Checked by the chain when the proposal is enacted; the node exposes no read for it. Recognised roots: Infineon, STMicroelectronics, Nuvoton, Intel PTT, AMD fTPM.",
    );
  } else {
    add("Hardware endorsement", "warn", "This platform's endorsement is checked by the chain when the proposal is enacted.");
  }

  if (i.verifiedEpochs === null) {
    add("Verified-available hours", "warn", "Could not be read; the requirement is at least one verified hour.");
  } else if (i.verifiedEpochs.length === 0) {
    add(
      "Verified-available hours",
      "fail",
      `None in the last ${i.windowHours} hours. Keep the node running and reachable; validators attest each hour.`,
    );
  } else {
    const e = i.verifiedEpochs;
    add(
      "Verified-available hours",
      "pass",
      `${e.length} in the last ${i.windowHours} hours (epochs ${Math.min(...e)} to ${Math.max(...e)})`,
    );
  }

  const approved = i.approval !== null && i.approval.revoked !== true;
  if (approved) {
    add("Governance approval", "pass", `Approved as ${i.approval?.class ?? "operator"} by proposal ${i.approval?.proposal_id ?? "?"}`);
  } else if (i.approval !== null) {
    add("Governance approval", "fail", "Was approved and then revoked by governance.");
  } else if (i.proposals.length > 0) {
    add("Governance approval", "todo", `Proposal ${i.proposals[0].id} is ${i.proposals[0].status}`);
  } else {
    add(
      "Governance approval",
      "todo",
      "Not approved, and no approval proposal names this account. A proposer with stake files it; `tenzro sponsor apply` prepares the command.",
    );
  }

  if (i.caps === null) {
    add("Sponsorship caps", "warn", "Could not be read.");
  } else if (capsOpen(i.caps)) {
    add(
      "Sponsorship caps",
      "pass",
      `Open: ${i.caps.sponsorshipYearlyMaxTnzo} TNZO a year, ${i.caps.runningCostPerVerifiedEpochWei} wei per verified hour`,
    );
  } else {
    add(
      "Sponsorship caps",
      "warn",
      "All zero. Approval pays nothing until governance sets the sponsorship caps.",
    );
  }

  const blocked = criteria.some((c) => c.level === "fail");
  return {
    criteria,
    approved,
    readyToApply: !blocked && !approved && i.proposals.length === 0,
  };
}
