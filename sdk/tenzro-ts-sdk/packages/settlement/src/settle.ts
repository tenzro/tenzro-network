import { RpcClient } from "@tenzro/core";
import { TypedTxClient, type SignedTransactionJson } from "@tenzro/core";
import type { HybridSigner } from "@tenzro/core";

/**
 * Settlement plans: several value legs, one Commit-or-Abort decision, the
 * division fixed by the quote.
 *
 * `previewSplit` is the network's split engine computed locally: the protocol
 * fee once on the gross (burn, treasury, insurance), payee-borne network fees,
 * then the rule's lines by largest remainder. It is checked against the shared
 * vectors in `sdk/fixtures/split`, so a payer sees exactly the division the
 * chain will make.
 */

export type SplitRole =
  | "payee" | "publisher" | "licensor" | "referrer" | "facilitator"
  | "relayer" | "solver" | "prover" | "refund";

const ROLES: SplitRole[] = [
  "payee", "publisher", "licensor", "referrer", "facilitator", "relayer", "solver", "prover", "refund",
];

/** Who a line pays: a 32-byte hex account, a registered DID's account, or the decider. */
export type SplitRecipient = { address: string } | { did_derived: string } | "leg_submitter";

/** How much a line takes. Amounts are decimal strings of wei. */
export type SplitBasis = { bps: number } | { fixed: string } | "remainder";

export interface SplitLine {
  role: SplitRole;
  recipient: SplitRecipient;
  basis: SplitBasis;
  cap?: string | null;
}

export interface SplitRule {
  version: number;
  lines: SplitLine[];
}

export interface FeeParams {
  fee_bps: number;
  min_fee: string;
  burn_bps: number;
  insurance_bps: number;
}

export interface Allocation {
  gross: string;
  fee: { fee: string; burn: string; treasury: string; insurance: string };
  network_fees: string;
  net: string;
  credits: string[];
}

const BPS = 10_000n;
const bpsOf = (v: bigint, b: bigint) => (v / BPS) * b + ((v % BPS) * b) / BPS;
const min = (a: bigint, b: bigint) => (a < b ? a : b);
const max = (a: bigint, b: bigint) => (a > b ? a : b);

/** The checks the chain applies to a rule. Throws on a malformed rule. */
export function validateSplitRule(rule: SplitRule): void {
  if (rule.version !== 1) throw new Error("unknown split rule version");
  if (rule.lines.length < 1 || rule.lines.length > 16) throw new Error("a split rule has 1 to 16 lines");
  let remainders = 0;
  let bps = 0;
  for (const l of rule.lines) {
    if (l.basis === "remainder") {
      remainders++;
      if (l.cap != null) throw new Error("the remainder line has no cap");
    } else if ("bps" in l.basis) {
      if (l.basis.bps <= 0) throw new Error("a basis-point line takes a positive share");
      bps += l.basis.bps;
    } else if (BigInt(l.basis.fixed) === 0n) {
      throw new Error("a fixed line takes a positive amount");
    }
    if (typeof l.recipient === "object" && "address" in l.recipient
      && l.recipient.address.replace(/^0x/, "").length !== 64) {
      throw new Error("an address is 32 bytes of hex");
    }
  }
  if (remainders !== 1) throw new Error("a split rule has exactly one remainder line");
  if (bps > 10_000) throw new Error("basis-point lines sum to at most 10000");
}

/** The protocol fee on `gross` and its parts. */
/**
 * Refuse a rule whose facilitator and relayer lines can take more than
 * `maxBps` of `gross`, as the network checks an agent's plan against its
 * Terms (`max_split_fee_bps`): each line at the most it can take (a
 * basis-point line its exact share, a fixed line its amount, the remainder
 * the whole gross), each bounded by its cap and the gross.
 */
export function checkIntermediaryShare(rule: SplitRule, gross: bigint, maxBps: number): void {
  const min = (a: bigint, b: bigint) => (a < b ? a : b);
  let most = 0n;
  for (const l of rule.lines) {
    if (l.role !== "facilitator" && l.role !== "relayer") continue;
    let share =
      l.basis === "remainder"
        ? gross * 10_000n
        : "bps" in l.basis
          ? gross * BigInt(l.basis.bps)
          : min(BigInt(l.basis.fixed), gross) * 10_000n;
    if (l.cap != null) share = min(share, min(BigInt(l.cap), gross) * 10_000n);
    most += share;
  }
  if (most > gross * BigInt(maxBps)) {
    throw new Error(`facilitator and relayer lines can take more than ${maxBps} bps of the gross`);
  }
}

export function feeAllocation(gross: bigint, p: FeeParams) {
  const fee = min(max(bpsOf(gross, BigInt(Math.min(p.fee_bps, 10_000))), BigInt(p.min_fee)), gross);
  const burn = bpsOf(fee, BigInt(Math.min(p.burn_bps, 10_000)));
  const insurance = bpsOf(fee - burn, BigInt(Math.min(p.insurance_bps, 10_000)));
  return { fee, burn, treasury: fee - burn - insurance, insurance };
}

/** The division the chain makes of `gross` under `rule`. */
export function previewSplit(gross: bigint, rule: SplitRule, params: FeeParams, networkFees = 0n): Allocation {
  validateSplitRule(rule);
  const f = feeAllocation(gross, params);
  if (f.fee + networkFees > gross) throw new Error("fees exceed the gross");
  const net = gross - f.fee - networkFees;
  const credits = rule.lines.map(() => 0n);
  let left = net;
  rule.lines.forEach((l, i) => {
    if (typeof l.basis === "object" && "fixed" in l.basis) {
      const cap = l.cap != null ? BigInt(l.cap) : null;
      let take = BigInt(l.basis.fixed);
      if (cap !== null) take = min(take, cap);
      take = min(take, left);
      credits[i] = take;
      left -= take;
    }
  });
  const pool = left;
  let sumBps = 0n;
  let floors = 0n;
  const fractions: Array<[bigint, number]> = [];
  rule.lines.forEach((l, i) => {
    if (typeof l.basis === "object" && "bps" in l.basis) {
      const b = BigInt(l.basis.bps);
      sumBps += b;
      credits[i] = bpsOf(pool, b);
      floors += credits[i];
      fractions.push([((pool % BPS) * b) % BPS, i]);
    }
  });
  fractions.sort((a, b) => (a[0] === b[0] ? a[1] - b[1] : a[0] > b[0] ? -1 : 1));
  let extra = bpsOf(pool, sumBps) - floors;
  for (const [, i] of fractions) {
    if (extra === 0n) break;
    credits[i] += 1n;
    extra -= 1n;
  }
  rule.lines.forEach((l, i) => {
    if (typeof l.basis === "object" && "bps" in l.basis && l.cap != null) credits[i] = min(credits[i], BigInt(l.cap));
  });
  const paid = credits.reduce((a, c) => a + c, 0n);
  credits[rule.lines.findIndex((l) => l.basis === "remainder")] = net - paid;
  const s = (v: bigint) => v.toString();
  return {
    gross: s(gross),
    fee: { fee: s(f.fee), burn: s(f.burn), treasury: s(f.treasury), insurance: s(f.insurance) },
    network_fees: s(networkFees),
    net: s(net),
    credits: credits.map(s),
  };
}

const be = (v: bigint, bytes: number) => {
  const out = new Uint8Array(bytes);
  for (let i = bytes - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};
const fromHex = (h: string) => Uint8Array.from((h.replace(/^0x/, "").match(/../g) ?? []).map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** The hash a quote signs and a plan binds, hex. */
export async function splitRuleHash(rule: SplitRule): Promise<string> {
  const parts: number[] = [...new TextEncoder().encode("tenzro/split-rule/v1"), ...be(BigInt(rule.version), 2), rule.lines.length];
  for (const l of rule.lines) {
    parts.push(ROLES.indexOf(l.role));
    if (l.recipient === "leg_submitter") parts.push(2);
    else if ("address" in l.recipient) parts.push(0, ...fromHex(l.recipient.address));
    else {
      const d = new TextEncoder().encode(l.recipient.did_derived);
      parts.push(1, ...be(BigInt(d.length), 2), ...d);
    }
    if (l.basis === "remainder") parts.push(2);
    else if ("bps" in l.basis) parts.push(0, ...be(BigInt(l.basis.bps), 2));
    else parts.push(1, ...be(BigInt(l.basis.fixed), 16));
    if (l.cap != null) parts.push(1, ...be(BigInt(l.cap), 16));
    else parts.push(0);
  }
  const digest = await globalThis.crypto.subtle.digest("SHA-256", Uint8Array.from(parts));
  return toHex(new Uint8Array(digest));
}

/** One leg of a plan. */
export type PlanLeg = {
  kind: { native_transfer: { amount: string; escrow_id: string | null } };
  class_required: "native";
};

/** One way an x402 seller accepts payment, as its 402 lists it. */
export interface X402PaymentRequirement {
  scheme: string;
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>;
}

/** The x402 wire version this network speaks. */
export const X402_VERSION = 2;

/**
 * The x402 payment payload for a `plan` requirement: the payer's signed
 * `SettlementPlan` open transaction (`TypedTxClient.sign` of
 * `SettleClient.openPlanTx`), which the facilitator checks and submits.
 */
export function planPaymentPayload(
  accepted: X402PaymentRequirement,
  signedTx: SignedTransactionJson,
  resource?: { url: string; description?: string; mimeType?: string },
) {
  if (accepted.scheme !== "plan") throw new Error(`requirement scheme is ${accepted.scheme}, not plan`);
  const op = (signedTx.transaction.tx_type as { SettlementPlan?: { op?: { open?: unknown } } })?.SettlementPlan?.op;
  if (!op || !("open" in op)) throw new Error("the transaction does not open a settlement plan");
  return {
    x402Version: X402_VERSION,
    ...(resource ? { resource } : {}),
    accepted,
    payload: { signed_tx: signedTx },
  };
}

/** `planPaymentPayload` encoded for the `PAYMENT-SIGNATURE` header (base64 JSON). */
export function planPaymentHeader(payload: ReturnType<typeof planPaymentPayload>): string {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** Builds the `open` operation a payer signs. */
export class PlanBuilder {
  private legs: PlanLeg[] = [];

  constructor(
    private nonce: number,
    private quoteDigest: string,
    private split: SplitRule,
    private decideDeadlineMs: number,
  ) {}

  /** A Tenzro leg paid from the payer's balance, or from its funded escrow. */
  native(amount: bigint, escrowId?: string): this {
    this.legs.push({
      kind: { native_transfer: { amount: amount.toString(), escrow_id: escrowId ? escrowId.replace(/^0x/, "") : null } },
      class_required: "native",
    });
    return this;
  }

  /** The `open` operation's fields. */
  async build() {
    validateSplitRule(this.split);
    if (this.legs.length < 1 || this.legs.length > 16) throw new Error("a plan has 1 to 16 legs");
    return {
      nonce: this.nonce,
      quote_digest: this.quoteDigest.replace(/^0x/, ""),
      split_hash: await splitRuleHash(this.split),
      split: this.split,
      legs: this.legs,
      decide_deadline_ms: this.decideDeadlineMs,
    };
  }
}

/**
 * Settlement plan client. Opening a plan and proving a leg are
 * `SettlementPlan` transactions the caller signs with its own key; every read
 * carries the record's state-proof key.
 */
export class SettleClient {
  constructor(private rpc: RpcClient) {}

  /** The division under the node's live fee parameters. */
  previewSplit(gross: bigint, split: SplitRule, networkFees = 0n) {
    return this.rpc.call("tenzro_previewSplit", { gross: gross.toString(), split, network_fees: networkFees.toString() });
  }

  /** The transaction type that opens `plan` (`PlanBuilder.build()`'s output), for the payer's signer. */
  static openPlanTx(plan: Record<string, unknown>) {
    return { SettlementPlan: { op: { open: plan } } };
  }

  /**
   * Pay an x402 `plan` requirement: sign the transaction opening `plan` with
   * the payer's key, locally, and wrap it as the payment payload. Returns the
   * payload and its `PAYMENT-SIGNATURE` header value; nothing is submitted
   * here, the facilitator opens the plan when it settles the payment.
   */
  async signPlanPayment(
    signer: HybridSigner,
    plan: Record<string, unknown>,
    accepted: X402PaymentRequirement,
    resource?: { url: string; description?: string; mimeType?: string },
  ) {
    const signed = await new TypedTxClient(this.rpc).sign(signer, {
      kind: "SettlementPlan",
      fields: SettleClient.openPlanTx(plan).SettlementPlan,
    });
    const payload = planPaymentPayload(accepted, signed, resource);
    return { payload, header: planPaymentHeader(payload) };
  }

  /**
   * The transaction type recording that leg `index` reached its evidence class, for any signer. `evidence` (hex) is
   * a lock leg's `Locked` event proof, a hash-locked leg's funding proof or, once funded, its preimage; omit it for
   * legs Tenzro reads from its own state. `networkFee` is the wei the sender paid on the leg's network to carry the
   * proof; the commit repays it up to the leg's `max_network_fee`.
   */
  static proveLegTx(planId: string, index: number, evidence?: string, networkFee: bigint = 0n) {
    const prove: Record<string, unknown> = { plan_id: planId.replace(/^0x/, ""), index, network_fee: networkFee.toString() };
    if (evidence) prove.evidence = evidence.replace(/^0x/, "");
    return { SettlementPlan: { op: { prove_leg: prove } } };
  }

  /**
   * The transaction type a rail leg's payee sends to dispute the leg its attestor confirmed, inside the compensation
   * window: the payee is paid the leg's reserve and the attestor's bond is slashed. `evidence` (hex) is the payee's
   * proof that the payment did not arrive.
   */
  static disputeRailTx(planId: string, index: number, evidence: string) {
    const dispute = { plan_id: planId.replace(/^0x/, ""), index, evidence: evidence.replace(/^0x/, "") };
    return { SettlementPlan: { op: { dispute_rail: dispute } } };
  }

  /**
   * The transaction type that posts (`post: true`) or withdraws collateral for netted plans. `asset` is the token id
   * (32-byte hex); a withdrawal keeps what the asset's open batch's net debit needs. `agent` is a delegated agent's
   * signed action (`{ action, signature }`) when the collateral is the agent's: a post names the asset (`0x` token
   * id, absent for TNZO), states the amount and, off TNZO, its USD value, and counts against the asset's limits and
   * the wei limits in its terms; a withdrawal states none and returns to its wallet.
   */
  static collateralTx(asset: string, amount: bigint, post: boolean, agent?: { action: unknown; signature: unknown }) {
    const body = { asset: asset.replace(/^0x/, ""), amount: amount.toString(), ...(agent ? { agent } : {}) };
    return { SettlementPlan: { op: post ? { post_collateral: body } : { withdraw_collateral: body } } };
  }

  /**
   * An asset's netting batch (the latest when `seq` is omitted) with its state-proof key; with a participant, its
   * collateral, defaults and, once settled, its gross-to-net statement (obligations with Merkle paths to the root).
   */
  getNettingBatch(asset: string, opts: { seq?: number; participant?: string } = {}) {
    return this.rpc.call("tenzro_getNettingBatch", { asset, ...opts });
  }

  /**
   * Check a reconciliation of a route's settlement lock against the route's stored one. `entries` are what the lock
   * recorded since the last reconciliation, in order; `checkpoint` is the route's proof of the lock's checkpoint, hex.
   * Returns `tx_type`, the `SettlementPlan` transaction to sign and send, with the `count` and running hash `acc`
   * the checkpoint must prove.
   */
  submitReconciliation(
    adapter: string,
    chain: string,
    entries: { plan_id: string; leg_id: string; kind: "locked" | "released" | "refunded"; amount: string }[],
    checkpoint: string,
  ) {
    return this.rpc.call("tenzro_submitReconciliation", { adapter, chain, entries, checkpoint: checkpoint.replace(/^0x/, "") });
  }

  /** How far a route's settlement lock is reconciled, with its state-proof key. */
  getReconciliation(adapter: string, chain: string) {
    return this.rpc.call("tenzro_getReconciliation", { adapter, chain });
  }

  /**
   * The reconciliation mismatches stored for a route's settlement lock, each with the account it cost, the loss an
   * insurance claim can pay and its state-proof key.
   */
  listMismatches(adapter: string, chain: string) {
    return this.rpc.call("tenzro_listMismatches", { adapter, chain });
  }

  getPlan(planId: string) {
    return this.rpc.call("tenzro_getPlan", { plan_id: planId });
  }

  getDecision(planId: string) {
    return this.rpc.call("tenzro_getPlanDecision", { plan_id: planId });
  }

  /**
   * One leg's receipt and its recorded evidence (`ple:`): class, evidence digest, a hash-locked leg's funding txid and,
   * once the plan commits, the preimage its recipient claims with; each with its state-proof key.
   */
  getLegReceipt(planId: string, index: number) {
    return this.rpc.call("tenzro_getLegReceipt", { plan_id: planId, index });
  }

  listPlans(opts: { payer?: string; status?: "open" | "committed" | "aborted"; limit?: number } = {}) {
    return this.rpc.call("tenzro_listPlans", opts);
  }
}
