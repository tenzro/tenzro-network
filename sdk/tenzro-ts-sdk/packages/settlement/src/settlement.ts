import { RpcClient } from "@tenzro/core";
import { TypedTxClient } from "@tenzro/core";
import {
  ACCOUNT_OWNER_SIGNATURE_CONTEXT,
  compositeMessageRepresentative,
  compositeSignatureJson,
} from "@tenzro/core";
import type { HybridSigner } from "@tenzro/core";
import { validateSplitRule, type SplitRule } from "./settle";
import { LedgerSettlement, SettlementParams } from "@tenzro/core";

/**
 * Client for payment settlement operations.
 * Supports immediate settlement, escrow, and micropayment channels.
 */
export class SettlementClient {
  constructor(private rpc: RpcClient) {}

  /**
   * Settle a payment on the ledger: a `PayerSettle` transaction carrying the
   * payer's own signed authorization (`request.payment`), which names the
   * payee and a ceiling. The node relays it and pays the gas; it can move
   * nothing the payer did not sign for.
   */
  async settle(request: SettlementParams): Promise<LedgerSettlement> {
    return this.rpc.call<LedgerSettlement>("tenzro_settle", { ...request });
  }

  /**
   * One payment's consensus record (native, proven or attested), by its
   * reference or by the payment id it settled under. `null` when none.
   */
  async getPayment(ref: { pay_ref?: string; payment_id?: string }): Promise<any> {
    return this.rpc.call("tenzro_getPayment", ref);
  }

  /**
   * Consensus payment records in chain order, read from the event index.
   * Each entry is `{ cursor, tx_hash, record, proof? }`; pass the returned
   * `cursor` back as `from_cursor` to continue with no gap.
   */
  async listPayments(query: {
    payee?: string;
    payer?: string;
    agent_did?: string;
    class?: "native" | "proven" | "attested";
    asset?: string;
    from_cursor?: string;
    from_height?: number;
    to_cursor?: string;
    limit?: number;
    proofs?: boolean;
  } = {}): Promise<{ payments: any[]; cursor: string | null }> {
    return this.rpc.call("tenzro_listPayments", query);
  }

  /**
   * The standing split rule every payment a payee receives is divided by
   * after the fee, from consensus state: `{ rule }` in the split engine's
   * form, `rule: null` when it set none.
   */
  async getPayeeSplit(payee: string): Promise<{ rule: Record<string, unknown> | null }> {
    return this.rpc.call("tenzro_getPayeeSplit", { payee });
  }

  /**
   * As the payee, return `amount` (smallest unit, in the asset it was paid
   * in) of the native payment `payRef` (32-byte hex) to its payer, as a
   * `Payment` transaction `signer` signs locally. Refunds on one record never
   * exceed what it paid.
   */
  async refundPayment(signer: HybridSigner, payRef: string, amount: bigint): Promise<unknown> {
    return this.sendPaymentOp(signer, refundOp(payRef, amount));
  }

  /**
   * As the payee, set the standing split rule every payment it receives is
   * divided by after the fee; `null` clears it. A `Payment` transaction
   * `signer` signs locally.
   */
  async setPayeeSplit(signer: HybridSigner, rule: SplitRule | null): Promise<unknown> {
    if (rule) validateSplitRule(rule);
    return this.sendPaymentOp(signer, { set_split: { rule } });
  }

  private sendPaymentOp(signer: HybridSigner, op: Record<string, unknown>): Promise<unknown> {
    return new TypedTxClient(this.rpc).send(signer, { kind: "Payment", fields: { op } });
  }

  /** Inspect an escrow record by its 32-byte id. */
  async getEscrow(escrowId: string): Promise<any> {
    const escrowIdBytes = parseEscrowId(escrowId);
    const escrowIdHex = "0x" + bytesToHex(escrowIdBytes);
    return this.rpc.call("tenzro_getEscrow", { escrow_id: escrowIdHex });
  }

  /**
   * List every escrow funded by `payer`. Returns
   * `{payer, escrows: [...], cursor}` in creation order, from the
   * `EscrowCreated` event log; pass `cursor` back to continue.
   *
   * @param payer - Payer address (the wallet that created the escrow)
   */
  async listEscrowsByPayer(payer: string, fromCursor?: string): Promise<any> {
    return this.rpc.call("tenzro_listEscrowsByPayer", { payer, from_cursor: fromCursor });
  }

  /**
   * List every escrow held for `payee`. Returns
   * `{payee, escrows: [...], cursor}` in creation order, from the
   * `EscrowCreated` event log; pass `cursor` back to continue.
   *
   * @param payee - Payee address (the recipient on successful release)
   */
  async listEscrowsByPayee(payee: string, fromCursor?: string): Promise<any> {
    return this.rpc.call("tenzro_listEscrowsByPayee", { payee, from_cursor: fromCursor });
  }

  /**
   * Open a payment channel over an escrow the payer already funded on the
   * ledger with its own signed `CreateEscrow` transaction naming this node's
   * payee. `channelId` is that escrow's id (32 bytes, hex). The node checks
   * the escrow on consensus state and returns the channel session.
   */
  async openPaymentChannel(channelId: string): Promise<Record<string, unknown>> {
    return this.rpc.call("tenzro_openPaymentChannel", { channel_id: channelId });
  }

  /**
   * Close a payment channel as its payer. `signer` holds the payer account's
   * key and signs the close request once, for now; the node claims the
   * highest voucher on chain and reports what is due.
   */
  async closePaymentChannel(signer: HybridSigner, channelId: string): Promise<ChannelClose> {
    const id = parseEscrowId(channelId);
    const timestampMs = Date.now();
    const message = ownerRequestMessage("tenzro_closePaymentChannel", id, timestampMs);
    const mPrime = await compositeMessageRepresentative(ACCOUNT_OWNER_SIGNATURE_CONTEXT, message);
    const [p256, pq] = await signer.signComposite(mPrime);
    return this.rpc.call<ChannelClose>("tenzro_closePaymentChannel", {
      channel_id: channelId,
      timestamp_ms: timestampMs,
      public_key: bytesToHex(signer.p256PublicKey()),
      signature: compositeSignatureJson(p256, pq),
    });
  }
}

/** `tenzro_closePaymentChannel`. */
export interface ChannelClose {
  channel_id: string;
  status: "open" | "closing" | "closed";
  /** What the node claims on chain (wei, decimal), when anything is due. */
  claim_due: string | null;
}

/**
 * The message an account owner signs for an owner-signed RPC request:
 * `tenzro/rpc-owner/v1`, 0, the method, 0, then the canonical bytes and the
 * request's `timestamp_ms` (i64 little-endian).
 */
export function ownerRequestMessage(method: string, canonical: Uint8Array, timestampMs: number): Uint8Array {
  const enc = new TextEncoder();
  const tag = enc.encode("tenzro/rpc-owner/v1");
  const m = enc.encode(method);
  const out = new Uint8Array(tag.length + 1 + m.length + 1 + canonical.length + 8);
  let o = 0;
  out.set(tag, o); o += tag.length;
  out[o++] = 0;
  out.set(m, o); o += m.length;
  out[o++] = 0;
  out.set(canonical, o); o += canonical.length;
  new DataView(out.buffer).setBigInt64(o, BigInt(timestampMs), true);
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  if (clean.length % 2 !== 0) {
    throw new Error(`invalid hex string (odd length): ${hex}`);
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function parseEscrowId(s: string): Uint8Array {
  const bytes = hexToBytes(s);
  if (bytes.length !== 32) {
    throw new Error(`escrow_id must be 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

/** The `Payment` operation by which a payee refunds `amount` of the record `payRef` (32-byte hex). */
export function refundOp(payRef: string, amount: bigint) {
  const ref = payRef.replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(ref)) throw new Error("payRef must be 32 bytes of hex");
  if (amount <= 0n) throw new Error("amount must be positive");
  return { refund: { pay_ref: ref, amount: amount.toString() } };
}
