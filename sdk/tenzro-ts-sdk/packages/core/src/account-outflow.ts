/**
 * Requests to an account's opt-in outflow policy (a cap per window, a hold and
 * an optional guardian), and a plain-language preview of each to show before
 * signing. The same wire form and wording as the node's
 * `tenzro_types::account_outflow_ui` and the Rust and Python SDKs; the rules
 * are the chain's, in its `account_outflow` module.
 *
 * Send a request with `TypedTxClient.send(signer, outflowTransaction(...))`; a
 * guardian sends from its own account, naming the guarded account.
 */
import type { RpcClient } from "./rpc";
import type { TypedTransaction } from "./typed-tx";

const ONE_TNZO = 10n ** 18n;

export type OutflowRequest =
  | { op: "set"; windowMs: number; cap: bigint; holdMs: number; guardian?: string }
  | { op: "remove" }
  | { op: "cancel_pending"; approval?: unknown }
  | { op: "request_release"; to: Uint8Array; amount: bigint }
  | { op: "cancel_release"; id: number; approval?: unknown }
  | { op: "claim_release"; id: number; approval?: unknown };

export interface OutflowPolicy {
  windowMs: number;
  cap: bigint;
  holdMs: number;
  guardian?: string;
  pending?: { windowMs: number; cap: bigint; holdMs: number; guardian?: string; remove: boolean; effectiveMs: number };
}

/** Read the `policy` of a `tenzro_getAccountOutflow` answer. */
export function outflowPolicyFromRpc(v: any): OutflowPolicy | undefined {
  if (!v) return undefined;
  const p = v.pending
    ? {
        windowMs: v.pending.window_ms,
        cap: BigInt(v.pending.cap),
        holdMs: v.pending.hold_ms,
        guardian: v.pending.guardian ?? undefined,
        remove: !!v.pending.remove,
        effectiveMs: v.pending.effective_ms,
      }
    : undefined;
  return { windowMs: v.window_ms, cap: BigInt(v.cap), holdMs: v.hold_ms, guardian: v.guardian ?? undefined, pending: p };
}

const arr = (b: Uint8Array) => Array.from(b);

/** The operation as the VM reads it, for `account`. */
export function outflowOpJson(r: OutflowRequest, account: Uint8Array): Uint8Array {
  // The chain's operation is externally tagged: {"set": {...fields}}.
  const a = arr(account);
  let v: Record<string, unknown>;
  switch (r.op) {
    case "set":
      v = { set: { account: a, window_ms: r.windowMs, cap: r.cap.toString(), hold_ms: r.holdMs, guardian: r.guardian ?? null } };
      break;
    case "request_release":
      v = { request_release: { account: a, to: arr(r.to), amount: r.amount.toString() } };
      break;
    case "cancel_release":
    case "claim_release":
      v = { [r.op]: { account: a, id: r.id, approval: r.approval ?? null } };
      break;
    case "cancel_pending":
      v = { cancel_pending: { account: a, approval: r.approval ?? null } };
      break;
    default:
      v = { remove: { account: a } };
  }
  return new TextEncoder().encode(JSON.stringify(v));
}

/** The transaction carrying the request, for `TypedTxClient.send`. */
export function outflowTransaction(r: OutflowRequest, account: Uint8Array): TypedTransaction {
  return { kind: "AccountOutflow", fields: { op: arr(outflowOpJson(r, account)) } };
}

const hex = (b: Uint8Array | string) =>
  typeof b === "string" ? b : Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

function tnzo(wei: bigint): string {
  const whole = wei / ONE_TNZO;
  const frac = wei % ONE_TNZO;
  if (frac === 0n) return `${whole} TNZO`;
  return `${whole}.${frac.toString().padStart(18, "0").replace(/0+$/, "")} TNZO`;
}

function span(ms: number): string {
  const m = Math.floor(ms / 60000);
  if (m >= 2 * 24 * 60) return `${Math.floor(m / 1440)} days`;
  if (m >= 120) return `${Math.floor(m / 60)} hours`;
  if (m >= 1) return `${m} minutes`;
  return "under a minute";
}

const at = (ms: number) => new Date(ms).toISOString().slice(0, 16).replace("T", " ") + " UTC";

/** Whether `next` loosens `cur` (the chain queues those for the hold). */
export function outflowLoosens(cur: OutflowPolicy, next: { windowMs: number; cap: bigint; holdMs: number; guardian?: string }): boolean {
  return (
    next.cap * BigInt(cur.windowMs) > cur.cap * BigInt(next.windowMs) ||
    next.holdMs < cur.holdMs ||
    (cur.guardian !== undefined && next.guardian !== cur.guardian)
  );
}

/** Plain-language lines to show before signing `r`. */
export function describeOutflow(r: OutflowRequest, current: OutflowPolicy | undefined, nowMs: number): string[] {
  const who = (p?: OutflowPolicy) => (p?.guardian ? " or your guardian" : "");
  switch (r.op) {
    case "set": {
      const out = [
        `Cap: this account can send at most ${tnzo(r.cap)} per ${span(r.windowMs)}.`,
        `Hold: a larger payment is queued and waits ${span(r.holdMs)} before it can be paid. You${r.guardian ? " or your guardian" : ""} can cancel it meanwhile.`,
        r.guardian
          ? `Guardian: ${r.guardian} can cancel a queued payment and can approve one at once, each with their own passkey. Choose a person whose passkey is on different hardware from this account's.`
          : "No guardian: only this account can cancel or approve. A thief holding its key could also approve a queued payment once the hold ends, so the hold is your only protection.",
      ];
      if (!current) out.push("A first policy takes effect at once.");
      else if (outflowLoosens(current, { windowMs: r.windowMs, cap: r.cap, holdMs: r.holdMs, guardian: r.guardian }))
        out.push(`This loosens the policy, so it is queued for the current hold (${span(current.holdMs)}) and takes effect at ${at(nowMs + current.holdMs)}. You${who(current)} can cancel it until then.`);
      else out.push("This tightens the policy, so it takes effect at once.");
      return out;
    }
    case "remove":
      return [`Remove the outflow policy. This is queued for the current hold (${span(current?.holdMs ?? 0)}) and takes effect at ${at(nowMs + (current?.holdMs ?? 0))}; until then the cap still applies. You${who(current)} can cancel it.`];
    case "cancel_pending":
      return ["Cancel the queued change to this account's outflow policy. The policy stays as it is now."];
    case "request_release":
      return [
        `Queue a payment of ${tnzo(r.amount)} to 0x${hex(r.to)}.`,
        current
          ? `It can be paid at ${at(nowMs + current.holdMs)} (after the ${span(current.holdMs)} hold). You${who(current)} can cancel it until it is paid.`
          : "This account has no outflow policy, so a queued payment is refused.",
      ];
    case "cancel_release":
      return [`Cancel queued payment #${r.id}. Nothing is sent; it leaves the queue.`];
    case "claim_release":
      return [`Pay queued payment #${r.id}. The account pays it once its hold has ended; its guardian may pay it at once, with their passkey approval.`];
  }
}

/** The bytes a guardian's passkey signs for one action; `step` is `approval_step` from the node's answer. */
export function outflowApprovalTarget(account: Uint8Array, action: string, id: number, step: number): Uint8Array {
  const enc = new TextEncoder().encode(action);
  const out = new Uint8Array(4 + account.length + 4 + enc.length + 16);
  const dv = new DataView(out.buffer);
  let o = 0;
  dv.setUint32(o, account.length); o += 4;
  out.set(account, o); o += account.length;
  dv.setUint32(o, enc.length); o += 4;
  out.set(enc, o); o += enc.length;
  dv.setBigUint64(o, BigInt(id)); o += 8;
  dv.setBigUint64(o, BigInt(step));
  return out;
}

/** What a wallet offers when it creates an account. Nothing is set unless the holder chooses to. */
export function outflowCreationOffer(): string[] {
  return [
    "Optional: protect this account with an outflow limit.",
    "You choose a cap per window and a hold. A payment above the cap is queued and waits the hold, and you can cancel it meanwhile.",
    "For the strongest protection name a guardian: a person whose passkey is on different hardware from this account's. The guardian can cancel, and can approve a payment at once.",
    "Nothing is set unless you set it: tenzro wallet outflow set --cap <TNZO> --guardian <did>",
  ];
}

/** The node queries behind the outflow policy. */
export class AccountOutflowClient {
  constructor(private rpc: RpcClient) {}

  /** `tenzro_getAccountOutflow`: the policy of `account` (hex), its pending change and its releases. */
  async get(account: string): Promise<Record<string, unknown>> {
    return this.rpc.call("tenzro_getAccountOutflow", { account: account.replace(/^0x/, "") });
  }

  /** `tenzro_checkDelegateTarget`: whether the code at `address` is on the governed list of delegate code hashes. */
  async checkDelegateTarget(address: string): Promise<Record<string, unknown>> {
    return this.rpc.call("tenzro_checkDelegateTarget", { address });
  }
}
