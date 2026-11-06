/**
 * Paying on the Tenzro ledger in whatever asset the payer holds: a price in
 * the unit of account, a quote per accepted asset with its fee in kind, an
 * idempotent payment, and a receipt checked against the chain on two
 * endpoints.
 *
 * ```ts
 * const pay = new LedgerPayments([rpcA, rpcB]);
 * const q = await pay.quote({ payee, price: { amount: "0.25", unit: "USD" }, request, accept: ["0x..usdc", "TNZO"] });
 * const r = await pay.pay(q, { signer, idempotencyKey });
 * await pay.verifyReceipt(r);
 * ```
 *
 * Nothing is rerouted silently: an asset that cannot settle now is reported
 * with its code, a quote none of whose accepted assets can settle is
 * refused, and a receipt the two endpoints disagree on is refused.
 */
import type { RpcClient, HybridSigner } from "@tenzro/core";
import { accountAddress, compositeMessageRepresentative, compositeSignatureJson, stringifyExact } from "@tenzro/core";
import { PAYMENT_AUTHORIZATION_CONTEXT } from "./web/fetch";

/** Why a payment step was refused. */
export type PaymentErrorCode =
  | "invalid_price"
  | "asset_unpermitted"
  | "asset_disabled"
  | "rate_held"
  | "asset_suspended"
  | "asset_off_peg"
  | "asset_inflow_full"
  | "invalid_asset"
  | "no_accepted_asset"
  | "settlement_failed"
  | "receipt_missing"
  | "receipt_mismatch"
  | "receipt_unverified";

/** A payment step refused, with its code. */
export class PaymentError extends Error {
  constructor(
    readonly code: PaymentErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PaymentError";
  }
}

/** A price in the unit of account. */
export interface Price {
  /** Decimal, at most six places: `"0.25"`. */
  amount: string;
  /** The unit of account: `"USD"`. */
  unit: "USD";
}

/** A reseller's commission on top of the operator's price: its own leg, signed by the payer. */
export interface ResellerCommission {
  /** The reseller's account, 32 bytes of hex. */
  reseller: string;
  /** Basis points of the operator's price. */
  commission_bps: number;
}

/** One commission a quote discloses, as the chain carves it from the signed amount. */
export interface QuotedLeg {
  reseller: string;
  commission_bps: number;
  amount: bigint;
  fee: bigint;
}

/** One accepted asset's price now, with the fee it pays in kind. */
export interface AssetQuote {
  asset: string;
  /** Smallest units to authorize: the operator's price and every commission. */
  amount: bigint;
  /** Settlement fee taken out of `amount`, every leg's together, in `fee_asset`. */
  fee: bigint;
  fee_asset: string;
  rate_epoch: number | null;
  /** The operator's price inside `amount`. */
  operator_amount: bigint;
  /** Each commission inside `amount`; empty for a direct payment. */
  legs: QuotedLeg[];
}

/** An accepted asset the payment cannot settle in now. */
export interface AssetRefusal {
  asset: string;
  error: { code: PaymentErrorCode; reason: string };
}

/** What `quote` returns: the price, every accepted asset's answer, and the one chosen. */
export interface LedgerQuote {
  payee: string;
  request: string;
  requestDigest: Uint8Array;
  usdE6: bigint;
  unit: { basket: string; version: number };
  rateEpoch: number | null;
  assets: (AssetQuote | AssetRefusal)[];
  chosen: AssetQuote;
  /** The commissions the payment carries, signed with it. */
  resellers: ResellerCommission[];
}

/** What a settled payment left on chain, checked. */
export interface LedgerReceipt {
  paymentId: string;
  /** The one request the payment pays for. */
  request: string;
  /** The commissions the payment carries. */
  resellers?: ResellerCommission[];
  payee: string;
  asset: string;
  amount: bigint;
  /** The chain's record, as both endpoints returned it. */
  record: Record<string, unknown>;
}

const enc = new TextEncoder();

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function le(v: bigint, bytes: number): Uint8Array {
  const out = new Uint8Array(bytes);
  let x = v;
  for (let i = 0; i < bytes; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error(`${v} does not fit in ${bytes} bytes`);
  return out;
}

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function bytes32(value: string, what: string): Uint8Array {
  const h = value.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64}$/.test(h)) throw new Error(`${what} is 32 bytes of hex`);
  return Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", data as BufferSource));
}

/** Micro-units of a decimal price: `"0.25"` is 250000n. Refuses more than six places, signs and exponents. */
export function parsePriceE6(amount: string): bigint {
  const m = /^(\d+)(?:\.(\d{1,6}))?$/.exec(amount);
  if (!m) throw new PaymentError("invalid_price", `price ${JSON.stringify(amount)} is not a decimal with at most six places`);
  const e6 = BigInt(m[1]) * 1_000_000n + BigInt((m[2] ?? "").padEnd(6, "0"));
  if (e6 === 0n) throw new PaymentError("invalid_price", "a price is greater than zero");
  if (e6 > 0xffffffffffffffffn) throw new PaymentError("invalid_price", `price ${amount} is too large`);
  return e6;
}

/** The digest of what a payment buys: SHA-256 of `tenzro/request` and the request. */
export function requestDigest(request: string): Promise<Uint8Array> {
  return sha256(concat([enc.encode("tenzro/request"), enc.encode(request)]));
}

/**
 * The payment id every retry of one payment settles under: SHA-256 of
 * `tenzro/payment-id`, the idempotency key (u32 LE length prefixed), payer,
 * payee and request digest, as hex. The chain settles an id once.
 */
export async function paymentId(
  idempotencyKey: string,
  payer: Uint8Array,
  payee: Uint8Array,
  digest: Uint8Array,
): Promise<string> {
  const key = enc.encode(idempotencyKey);
  return hex(await sha256(concat([enc.encode("tenzro/payment-id"), le(BigInt(key.length), 4), key, payer, payee, digest])));
}

/** The fields a ledger payment authorization signs. */
export interface LedgerAuthorizationFields {
  chainId: bigint;
  paymentId: string;
  payer: Uint8Array;
  payee: Uint8Array;
  maxAmount: bigint;
  asset: string;
  requestDigest: Uint8Array;
  quoteDigest?: Uint8Array;
  usdE6: bigint;
  /** Reseller commissions the payer agrees to. */
  resellers?: ResellerCommission[];
}

/**
 * The authorization preimage a `PayerSettle` checks, exactly as the chain
 * builds it (no developer margin): with resellers, a `0x02` tag, their count
 * and each reseller and commission follow, so none can change after signing.
 */
export function ledgerAuthorizationMessage(f: LedgerAuthorizationFields): Uint8Array {
  const id = enc.encode(f.paymentId);
  const asset = enc.encode(f.asset);
  const resellers = f.resellers ?? [];
  const legs =
    resellers.length === 0
      ? []
      : [
          new Uint8Array([2]),
          le(BigInt(resellers.length), 4),
          ...resellers.flatMap((r) => [bytes32(r.reseller, "reseller"), le(BigInt(r.commission_bps), 4)]),
        ];
  return concat([
    enc.encode("tenzro/payment-authorization"),
    le(f.chainId, 8),
    le(BigInt(id.length), 4),
    id,
    f.payer,
    f.payee,
    le(f.maxAmount, 16),
    le(BigInt(asset.length), 4),
    asset,
    f.requestDigest,
    f.quoteDigest ?? new Uint8Array(32),
    le(f.usdE6, 8),
    new Uint8Array([0]),
    ...legs,
  ]);
}

function isRefusal(a: AssetQuote | AssetRefusal): a is AssetRefusal {
  return (a as AssetRefusal).error !== undefined;
}

/** Reseller commissions as the chain reads them: each account as its 32 bytes. */
function resellerJson(resellers: ResellerCommission[]): { reseller: number[]; commission_bps: number }[] {
  return resellers.map((r) => ({ reseller: Array.from(bytes32(r.reseller, "reseller")), commission_bps: r.commission_bps }));
}

/**
 * An amount as the node writes it, exactly: an integer literal (a bigint
 * past 2^53) or a decimal string. A number that is not a safe integer was
 * already rounded and is refused rather than paid.
 */
export function readAmount(v: unknown, what: string, code: PaymentErrorCode = "receipt_mismatch"): bigint {
  if (typeof v === "bigint" && v >= 0n) return v;
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === "string" && /^\d+$/.test(v)) return BigInt(v);
  throw new PaymentError(code, `${what} ${String(v)} is not an exact amount`);
}

/** Reads a `tenzro_quotePayment` answer. */
export function readQuoteAssets(response: { assets: unknown[] }): (AssetQuote | AssetRefusal)[] {
  return response.assets.map((raw) => {
    const a = raw as Record<string, unknown>;
    if (a.error) return a as unknown as AssetRefusal;
    const amount = readAmount(a.amount, "the quoted amount", "invalid_asset");
    return {
      asset: String(a.asset),
      amount,
      fee: readAmount(a.fee, "the quoted fee", "invalid_asset"),
      fee_asset: String(a.fee_asset),
      rate_epoch: (a.rate_epoch as number | null) ?? null,
      operator_amount: a.operator_amount === undefined ? amount : readAmount(a.operator_amount, "the operator amount", "invalid_asset"),
      legs: ((a.legs as Record<string, unknown>[] | undefined) ?? []).map((l) => ({
        reseller: String(l.reseller),
        commission_bps: Number(l.commission_bps),
        amount: readAmount(l.amount, "a leg amount", "invalid_asset"),
        fee: readAmount(l.fee, "a leg fee", "invalid_asset"),
      })),
    };
  });
}

/** The first asset in `accept` order the payment can settle in; refused with every reason when none can. */
export function chooseAsset(assets: (AssetQuote | AssetRefusal)[], accept: string[]): AssetQuote {
  const reasons: string[] = [];
  let only: PaymentErrorCode | undefined;
  for (const want of accept) {
    const a = assets.find((x) => x.asset.toLowerCase() === want.toLowerCase());
    if (!a) {
      reasons.push(`${want}: not quoted`);
      continue;
    }
    if (!isRefusal(a)) return a;
    reasons.push(`${want}: ${a.error.code} (${a.error.reason})`);
    only = only === undefined || only === a.error.code ? a.error.code : "no_accepted_asset";
  }
  throw new PaymentError(only ?? "no_accepted_asset", `no accepted asset can settle now: ${reasons.join("; ")}`);
}

function payeeHex(v: unknown): string {
  if (Array.isArray(v)) return hex(Uint8Array.from(v as number[]));
  return String(v).replace(/^0x/, "").toLowerCase();
}

/**
 * Checks the record two endpoints returned for a payment: both present and
 * identical, a native record under the payment id, to the payee, in the
 * asset and amount paid, for exactly `expected.request`, with every receipt
 * field filled. A receipt for one request never verifies for another.
 */
export async function checkReceipt(
  expected: {
    paymentId: string;
    request: string;
    payee: string;
    asset: string;
    amount: bigint;
    /** The commissions the payment carries; their legs must all be on the record. */
    resellers?: ResellerCommission[];
  },
  a: unknown,
  b: unknown,
): Promise<LedgerReceipt> {
  if (a == null || b == null) throw new PaymentError("receipt_missing", `no record settled under ${expected.paymentId}`);
  if (stringifyExact(a) !== stringifyExact(b)) {
    throw new PaymentError("receipt_mismatch", "the two endpoints return different records");
  }
  const r = a as Record<string, unknown>;
  const fail = (what: string) => new PaymentError("receipt_mismatch", `the record's ${what} is not what was paid`);
  if (r.class !== "native") throw fail("class");
  if (r.nonce !== expected.paymentId) throw fail("payment id");
  if (payeeHex(r.payee) !== payeeHex(expected.payee)) throw fail("payee");
  if (String(r.asset).toLowerCase() !== expected.asset.toLowerCase()) throw fail("asset");
  if (readAmount(r.amount, "the record's amount") !== expected.amount) throw fail("amount");
  for (const f of ["fee_asset", "payout_asset", "value_units"]) {
    if (typeof r[f] !== "string" || r[f] === "") throw fail(f);
  }
  readAmount(r.value_units, "the record's value units");
  const unit = r.unit as { basket?: string } | undefined;
  if (!unit?.basket) throw fail("unit");
  const binding = r.binding as { request_digest?: string } | undefined;
  if (binding?.request_digest !== hex(await requestDigest(expected.request))) throw fail("request");
  // Every record names its legs: the operator first, then each commission.
  const legs = (r.legs as { role?: string; account?: string; commission_bps?: number }[] | undefined) ?? [];
  if (legs[0]?.role !== "operator" || payeeHex(legs[0]?.account) !== payeeHex(expected.payee)) throw fail("operator leg");
  const resold = legs.filter((l) => l.role === "reseller");
  const want = expected.resellers ?? [];
  if (
    resold.length !== want.length ||
    want.some((w) => !resold.some((l) => payeeHex(l.account) === payeeHex(w.reseller) && l.commission_bps === w.commission_bps))
  ) {
    throw fail("reseller legs");
  }
  return {
    paymentId: expected.paymentId,
    request: expected.request,
    payee: expected.payee,
    asset: expected.asset,
    amount: expected.amount,
    record: r,
  };
}

/**
 * Where a seller records the payments it has served, so each unlocks one
 * request once. A store shared by every server of a seller makes that hold
 * across them.
 */
export interface ChargeStore {
  /** `true` the first time `paymentId` is claimed, `false` ever after. */
  claim(paymentId: string, request: string): boolean | Promise<boolean>;
}

/** A {@link ChargeStore} in this process's memory. */
export class MemoryChargeStore implements ChargeStore {
  private readonly used = new Map<string, string>();
  claim(paymentId: string, request: string): boolean {
    if (this.used.has(paymentId)) return false;
    this.used.set(paymentId, request);
    return true;
  }
}

/** Options for {@link LedgerPayments.pay}. */
export interface PayOptions {
  /** The payer's hardware or passkey signer; the SDK never takes a raw key. */
  signer: HybridSigner;
  /** The caller's key for this payment; every retry with it settles once. */
  idempotencyKey: string;
  /** The account paid from (32 bytes of hex), when not the one the signer's key names. */
  account?: string;
  /** Attempts across the endpoints before giving up. Default 4. */
  attempts?: number;
  /** Lookups for the record once submitted. Default 30. */
  waitLookups?: number;
  /** Milliseconds between the first retries, doubled each time. Default 250. */
  backoffMs?: number;
}

/** A u64 the node reads as a JSON integer: a number while exact, a bigint (written as a literal) past 2^53. */
function wireInt(v: bigint): number | bigint {
  return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Quote, pay and verify ledger payments over one or more node endpoints. */
export class LedgerPayments {
  /** @param rpcs node endpoints; receipts are checked on the first two. */
  constructor(private readonly rpcs: Pick<RpcClient, "call">[]) {
    if (rpcs.length === 0) throw new Error("at least one endpoint");
  }

  /**
   * What `price` costs in each of `accept` now, with the fee each pays in
   * kind and, through `resellers`, the operator's price and each commission
   * disclosed apart; chooses the first that can settle.
   */
  async quote(q: { payee: string; price: Price; request: string; accept: string[]; resellers?: ResellerCommission[] }): Promise<LedgerQuote> {
    if (q.price.unit !== "USD") throw new PaymentError("invalid_price", "prices are in USD");
    const usdE6 = parsePriceE6(q.price.amount);
    const response = await this.rpcs[0].call<{ usd_e6: number | bigint; unit: { basket: string; version: number }; rate_epoch: number | null; assets: unknown[] }>(
      "tenzro_quotePayment",
      q.resellers?.length
        ? { usd_e6: wireInt(usdE6), accept: q.accept, resellers: resellerJson(q.resellers) }
        : { usd_e6: wireInt(usdE6), accept: q.accept },
    );
    const assets = readQuoteAssets(response);
    return {
      payee: q.payee,
      request: q.request,
      requestDigest: await requestDigest(q.request),
      usdE6,
      unit: response.unit,
      rateEpoch: response.rate_epoch,
      assets,
      chosen: chooseAsset(assets, q.accept),
      resellers: q.resellers ?? [],
    };
  }

  private async lookup(i: number, id: string): Promise<unknown> {
    return this.rpcs[i % this.rpcs.length].call("tenzro_getPayment", { payment_id: id, exact: true });
  }

  /**
   * Pays a quote: signs the authorization for the chosen asset and amount,
   * has a node relay it, and waits for the record. A retry with the same
   * idempotency key looks the payment up first and never pays twice.
   */
  async pay(q: LedgerQuote, o: PayOptions): Promise<LedgerReceipt> {
    const payer = o.account ? bytes32(o.account, "account") : await accountAddress(o.signer.p256PublicKey());
    const payee = bytes32(q.payee, "payee");
    const id = await paymentId(o.idempotencyKey, payer, payee, q.requestDigest);
    const expected = {
      paymentId: id,
      request: q.request,
      payee: q.payee,
      asset: q.chosen.asset,
      amount: q.chosen.amount,
      resellers: q.resellers,
    };
    const done = (record: unknown): LedgerReceipt => ({ ...expected, record: record as Record<string, unknown> });
    const existing = await this.lookup(0, id);
    if (existing) return done(existing);
    const chainId = BigInt(await this.rpcs[0].call<string>("eth_chainId"));
    const message = ledgerAuthorizationMessage({
      chainId,
      paymentId: id,
      payer,
      payee,
      maxAmount: q.chosen.amount,
      asset: q.chosen.asset,
      requestDigest: q.requestDigest,
      usdE6: q.usdE6,
      resellers: q.resellers,
    });
    const [p256, pq] = await o.signer.signComposite(await compositeMessageRepresentative(PAYMENT_AUTHORIZATION_CONTEXT, message));
    const params = {
      payee: hex(payee),
      amount: q.chosen.amount.toString(),
      payment: {
        payer: hex(payer),
        payment_id: id,
        authorization: {
          public_key: hex(o.signer.p256PublicKey()),
          signature: compositeSignatureJson(p256, pq),
          max_amount: q.chosen.amount.toString(),
          asset: q.chosen.asset,
          binding: {
            request_digest: hex(q.requestDigest),
            quote_digest: hex(new Uint8Array(32)),
            usd_e6: wireInt(q.usdE6),
            app_margin: null,
          },
          resellers: resellerJson(q.resellers),
        },
      },
    };
    const attempts = o.attempts ?? 4;
    let backoff = o.backoffMs ?? 250;
    let last: unknown;
    for (let i = 0; i < attempts; i++) {
      try {
        await this.rpcs[i % this.rpcs.length].call("tenzro_settle", params);
        last = undefined;
        break;
      } catch (e) {
        last = e;
        const settled = await this.lookup(i, id).catch(() => null);
        if (settled) return done(settled);
        await sleep(backoff);
        backoff *= 2;
      }
    }
    if (last !== undefined) {
      throw new PaymentError("settlement_failed", `the payment was not settled: ${(last as Error)?.message ?? String(last)}`);
    }
    for (let i = 0; i < (o.waitLookups ?? 30); i++) {
      const record = await this.lookup(i, id).catch(() => null);
      if (record) return done(record);
      await sleep(o.backoffMs ?? 250);
    }
    throw new PaymentError("receipt_missing", `payment ${id} was submitted and is not yet recorded`);
  }

  /** Checks a payment's record on two endpoints. */
  async verifyReceipt(r: Omit<LedgerReceipt, "record"> & { record?: unknown }): Promise<LedgerReceipt> {
    if (this.rpcs.length < 2) throw new PaymentError("receipt_unverified", "a receipt is checked on two endpoints");
    const [a, b] = await Promise.all([this.lookup(0, r.paymentId), this.lookup(1, r.paymentId)]);
    return checkReceipt(r, a, b);
  }

  /** Quote, pay and verify in one call, through `resellers` when given. */
  async payFor(
    request: string,
    o: PayOptions & { payee: string; price: Price; accept: string[]; resellers?: ResellerCommission[] },
  ): Promise<LedgerReceipt> {
    const q = await this.quote({ payee: o.payee, price: o.price, request, accept: o.accept, resellers: o.resellers });
    const paid = await this.pay(q, o);
    return this.rpcs.length >= 2 ? this.verifyReceipt(paid) : paid;
  }

  /**
   * Seller side: serves `handler` only for a request whose payment id names
   * a payment on chain to `payee` worth at least `price` for that request,
   * checked on two endpoints, and only the first time that payment is
   * presented (`store`, by default this wrapper's memory); otherwise
   * answers 402 with what to pay.
   */
  charge<Req extends { request: string; paymentId?: string }, Res>(
    handler: (req: Req, receipt: Record<string, unknown>) => Promise<Res>,
    o: {
      payee: string;
      price: Price;
      accept: string[];
      store?: ChargeStore;
      /** A reseller app's own commission, which the payment must carry as its leg. */
      reseller?: ResellerCommission;
    },
  ): (req: Req) => Promise<
    Res | { status: 402; reason?: "payment_consumed"; payment: { payee: string; price: Price; accept: string[]; request: string } }
  > {
    const owed = parsePriceE6(o.price.amount);
    const store = o.store ?? new MemoryChargeStore();
    return async (req) => {
      const required = { status: 402 as const, payment: { payee: o.payee, price: o.price, accept: o.accept, request: req.request } };
      if (!req.paymentId) return required;
      if (this.rpcs.length < 2) throw new PaymentError("receipt_unverified", "a charge checks payments on two endpoints");
      const [a, b] = await Promise.all([this.lookup(0, req.paymentId), this.lookup(1, req.paymentId)]);
      if (a == null || b == null) return required;
      if (stringifyExact(a) !== stringifyExact(b)) throw new PaymentError("receipt_mismatch", "the two endpoints return different records");
      const r = a as Record<string, unknown>;
      const binding = r.binding as { request_digest?: string } | undefined;
      const paidFor = hex(await requestDigest(req.request));
      if (
        payeeHex(r.payee) !== payeeHex(o.payee) ||
        binding?.request_digest !== paidFor ||
        readAmount(r.value_units ?? "0", "the record's value units") < owed
      ) {
        return required;
      }
      if (o.reseller) {
        const legs = (r.legs as { role?: string; account?: string; commission_bps?: number }[] | undefined) ?? [];
        const own = legs.some(
          (l) => l.role === "reseller" && payeeHex(l.account) === payeeHex(o.reseller!.reseller) && l.commission_bps === o.reseller!.commission_bps,
        );
        if (!own) return required;
      }
      if (!(await store.claim(req.paymentId, req.request))) return { ...required, reason: "payment_consumed" as const };
      return handler(req, r);
    };
  }
}
