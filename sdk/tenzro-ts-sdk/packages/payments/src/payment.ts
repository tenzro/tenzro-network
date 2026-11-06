import { RpcClient } from "@tenzro/core";
import type { HybridSigner } from "@tenzro/core";
import {
  ACCOUNT_OWNER_SIGNATURE_CONTEXT,
  compositeMessageRepresentative,
  compositeSignatureJson,
} from "@tenzro/core";
import {
  PaymentChallenge,
  PaymentReceipt,
  PayerPayment,
} from "@tenzro/core";

/**
 * Client for payment challenges, credential checks and ledger settlement.
 */
export class PaymentClient {
  constructor(private rpc: RpcClient) {}

  /**
   * Create a payment challenge for a resource (payee side). The node stamps it
   * with its chain id; the payer signs a credential for it.
   * @param resource - Resource identifier (e.g., URL or model ID)
   * @param amount - Payment amount, in the asset's smallest unit
   * @param asset - Asset identifier (default: "TNZO")
   * @param protocol - Payment protocol: "mpp" or "x402" (default: "mpp")
   * @param recipient - Payee address (default: the node's payee)
   * @returns The challenge, as the node issued it
   */
  async createChallenge(
    resource: string,
    amount: bigint | number,
    asset: string = "TNZO",
    protocol: string = "mpp",
    recipient?: string,
  ): Promise<PaymentChallenge> {
    const params: Record<string, unknown> = { resource, amount: BigInt(amount).toString(), asset, protocol };
    if (recipient !== undefined) params.recipient = recipient;
    return this.rpc.call<PaymentChallenge>("tenzro_createPaymentChallenge", params);
  }

  /**
   * What a price costs in each accepted asset now (TNZO when none is named),
   * with the settlement fee each pays in kind, or a coded reason an asset
   * cannot settle now. Give the price as USD micro-units or as a decimal.
   */
  async quote(q: {
    usdE6?: number | bigint;
    price?: { amount: string; unit: "USD" };
    accept?: string[];
  }): Promise<{
    usd_e6: number | bigint;
    unit: { basket: string; version: number };
    rate_epoch: number | null;
    assets: Record<string, unknown>[];
  }> {
    const params: Record<string, unknown> = q.price ? { price: q.price } : { usd_e6: q.usdE6 };
    if (q.accept) params.accept = q.accept;
    return this.rpc.call("tenzro_quotePayment", params);
  }

  /** `tenzro_getSettlementPreference`. */
  getSettlementPreference<T = unknown>(params: { payee_did?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getSettlementPreference", params);
  }

  /** `tenzro_getTerritoryPolicy`. */
  getTerritoryPolicy<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_getTerritoryPolicy");
  }

  /** `tenzro_updatePaymentChannel`. */
  updatePaymentChannel<T = unknown>(params: { charge?: unknown; voucher?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_updatePaymentChannel", params);
  }

  /**
   * Check a payment credential against its challenge without settling:
   * whether it verifies, and the amount and account it would debit.
   */
  verifyPayment<T = unknown>(credential: Record<string, unknown>): Promise<T> {
    return this.rpc.call<T>("tenzro_verifyPayment", { credential });
  }

  /**
   * Set the asset `payeeDid` is paid in: `keep_inbound` (whatever arrives)
   * or `tnzo`. `signer` holds a key the DID declares for authentication; it
   * signs the preference change under the account-owner context.
   */
  async setSettlementPreference<T = unknown>(
    signer: HybridSigner,
    payeeDid: string,
    asset: "tnzo" | "keep_inbound",
  ): Promise<T> {
    const timestampMs = Date.now();
    const preimage = settlementPreferencePreimage(payeeDid, asset, timestampMs);
    const mPrime = await compositeMessageRepresentative(ACCOUNT_OWNER_SIGNATURE_CONTEXT, preimage);
    const [p256, pq] = await signer.signComposite(mPrime);
    return this.rpc.call<T>("tenzro_setSettlementPreference", {
      payee_did: payeeDid,
      asset,
      timestamp_ms: timestampMs,
      public_key: Array.from(signer.p256PublicKey(), (b) => b.toString(16).padStart(2, "0")).join(""),
      signature: compositeSignatureJson(p256, pq),
    });
  }
}

/** A settlement on Tenzro, as `tenzro_settle` reports it. */
export interface SettledPayment {
  tx_hash: string;
  status: string;
  payer: string;
  payee: string;
  payment_id: string;
  /** Amount the payer was debited, in the smallest unit. */
  amount: bigint;
  network_fee: string;
  payee_credit: string;
}

/** The bytes a settlement preference change is signed over: a domain tag, then each field length-prefixed (u64 LE). */
export function settlementPreferencePreimage(payeeDid: string, asset: string, timestampMs: number): Uint8Array {
  const enc = new TextEncoder();
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigInt64(0, BigInt(timestampMs), true);
  const parts: Uint8Array[] = [enc.encode("tenzro/settlement-preference/v1")];
  for (const field of [enc.encode(payeeDid), enc.encode(asset), ts]) {
    const len = new Uint8Array(8);
    new DataView(len.buffer).setBigUint64(0, BigInt(field.length), true);
    parts.push(len, field);
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
