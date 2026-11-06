/**
 * Metered work, price cards and the generic registry.
 *
 * - {@link BillableUnits}: what a call consumed, meter key to quantity.
 * - {@link chargeWei}: the pricing rule the node charges with, so a caller can
 *   quote and check a charge itself.
 * - {@link RegistryClient}: the generic registry, where units, service types,
 *   price cards and applications are published as entries, listed by kind.
 * - {@link receiptChainNext} and {@link escrowVoucherPreimage}: what a
 *   streaming payer binds and signs.
 */
import { createHash } from "node:crypto";
import { RpcClient } from "@tenzro/core";

/**
 * What one call consumed: meter key (a unit id, optionally `@tier`) to
 * quantity. A quantity is a number below 2^53 and a decimal string above it;
 * zero quantities are absent.
 */
export type BillableUnits = Record<string, number | string>;

/** A price: `price` per `10^per_exp` units. */
export interface Rate {
  price: string | number;
  per_exp?: number;
}

/** A price list: a price per meter key and a per-call minimum. */
export interface RateCard {
  denom?: "nano_usd" | "wei";
  lines: Record<string, Rate>;
  min_charge?: string | number;
}

/** A provider's card for one model, as its registry entry carries it. */
export interface PriceCard {
  model_id: string;
  model_hash: string;
  rates: RateCard;
}

/** Units the network records but never charges. */
export const RECORDED_ONLY_UNITS = ["ttft_ms", "decode_ms"];

/** Billable by default: every unit but the recorded-only ones. */
export function defaultBillable(unit: string): boolean | undefined {
  return !RECORDED_ONLY_UNITS.includes(unit);
}

const ceilDiv = (a: bigint, b: bigint): bigint => (a + b - 1n) / b;

/**
 * The charge for `units` in the card's denomination: each priced key
 * `ceil(q × price / 10^per_exp)`, an unpriced key nothing, at least the
 * minimum. Throws when billable work exists and the card prices none of it,
 * or a unit is unknown to `billable`.
 */
export function chargeInDenom(
  card: RateCard,
  units: BillableUnits,
  billable: (unit: string) => boolean | undefined = defaultBillable,
): bigint {
  let total = 0n;
  let priced = false;
  const unpriced: string[] = [];
  for (const key of Object.keys(units).sort()) {
    const q = BigInt(units[key]);
    if (q === 0n) continue;
    const unit = key.split("@")[0];
    const b = billable(unit);
    if (b === undefined) throw new Error(`unit '${unit}' is not registered`);
    if (!b) continue;
    const line = card.lines[key];
    if (!line) {
      unpriced.push(key);
      continue;
    }
    priced = true;
    total += ceilDiv(q * BigInt(line.price), 10n ** BigInt(line.per_exp ?? 0));
  }
  if (!priced && unpriced.length > 0) {
    throw new Error(`the card prices none of the billable work metered (${unpriced.join(", ")})`);
  }
  const min = BigInt(card.min_charge ?? 0);
  return total > min ? total : min;
}

/**
 * The charge in TNZO base units. A USD card converts at `tnzoUsdNano`
 * (billionths of a dollar per TNZO, from `tenzro_getFeeRate`), rounding up.
 */
export function chargeWei(
  card: RateCard,
  units: BillableUnits,
  tnzoUsdNano: bigint,
  billable: (unit: string) => boolean | undefined = defaultBillable,
): bigint {
  const amount = chargeInDenom(card, units, billable);
  if (amount === 0n || card.denom === "wei") return amount;
  if (tnzoUsdNano === 0n) throw new Error("no TNZO/USD rate");
  return ceilDiv(amount * 10n ** 18n, tnzoUsdNano);
}

const sha256 = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};

/** The next head of a voucher's receipt chain. */
export function receiptChainNext(previous: Uint8Array, receiptDigest: Uint8Array): Uint8Array {
  return sha256(new TextEncoder().encode("tenzro/receipt-chain"), previous, receiptDigest);
}

const le = (v: bigint, bytes: number): Uint8Array => {
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) out[i] = Number((v >> BigInt(8 * i)) & 0xffn);
  return out;
};

/**
 * The bytes a payer signs for an escrow voucher: the domain, the chain, the
 * escrow, the cumulative amount and the receipt-chain binding (all zero for
 * a voucher signed ahead of delivery).
 */
export function escrowVoucherPreimage(
  chainId: bigint,
  escrowId: Uint8Array,
  cumulative: bigint,
  binding: Uint8Array = new Uint8Array(32),
): Uint8Array {
  const domain = new TextEncoder().encode("tenzro/escrow-voucher");
  const out = new Uint8Array(domain.length + 8 + 32 + 16 + 32);
  out.set(domain, 0);
  out.set(le(chainId, 8), domain.length);
  out.set(escrowId, domain.length + 8);
  out.set(le(cumulative, 16), domain.length + 40);
  out.set(binding, domain.length + 56);
  return out;
}

/** Registry kind of a standard: the anchor is the digest of its bundle. */
export const REGISTRY_KIND_STANDARD = "standard";
/** Registry kind of a conformance claim: the anchor is the implementation's digest, the data the 32-byte bundle digests of the standards it passes. */
export const REGISTRY_KIND_CONFORMANCE = "conformance";
/** Registry kind of a name: first come, bonded, retired by governance only. */
export const REGISTRY_KIND_NAME = "name";
/** The registry kinds whose rules the chain enforces. */
export const RESERVED_REGISTRY_KINDS = [REGISTRY_KIND_STANDARD, REGISTRY_KIND_CONFORMANCE, REGISTRY_KIND_NAME] as const;

/** One registry entry, as the node returns it. */
export interface RegistryEntry {
  id: string;
  kind: string;
  owner: string;
  version: number;
  anchor: string;
  /** The entry's data, hex. */
  data: string;
  digest: string;
  put_at_ms: number;
  retired_at_ms: number | null;
  standing: boolean;
}

/** The registry id of `provider`'s card for `modelId`. */
export function cardEntryId(provider: string, modelId: string): string {
  return `${provider.replace(/^0x/, "")}/card/${modelId}`;
}

/** The transaction type that puts a registry entry. */
export function registryPutTx(id: string, kind: string, anchorHex: string, data: Uint8Array) {
  return { Registry: { op: { put: { id, kind, anchor: anchorHex, data: Buffer.from(data).toString("hex") } } } };
}

/** The transaction type that retires a registry entry. */
export function registryRetireTx(id: string) {
  return { Registry: { op: { retire: { id } } } };
}

/** Client for the generic registry and price cards. */
export class RegistryClient {
  private rpc: RpcClient;

  constructor(rpc: RpcClient) {
    this.rpc = rpc;
  }

  /** Standing entries of `kind`, in id order, after `after`. */
  async list(kind: string, after?: string, limit?: number): Promise<{ kind: string; entries: RegistryEntry[]; next: string | null }> {
    return await this.rpc.call("tenzro_listRegistry", { kind, after, limit });
  }

  /** An entry, the latest version or `version`. */
  async get(id: string, version?: number): Promise<RegistryEntry | null> {
    return await this.rpc.call("tenzro_getRegistryEntry", { id, version });
  }

  /** The card `provider` publishes for `modelId`, with its entry. */
  async priceCard(provider: string, modelId: string): Promise<(RegistryEntry & { card: PriceCard }) | null> {
    return await this.rpc.call("tenzro_getPriceCard", { provider, model_id: modelId });
  }

  /** The entry `provider` would put to publish the node's card for a model. */
  async priceCardToPublish(provider: string, modelId: string): Promise<{ entry: { id: string; kind: string; data: string } | null }> {
    return await this.rpc.call("tenzro_priceCardToPublish", { provider, model_id: modelId });
  }

  /** The TNZO/USD rate, billionths of a dollar per TNZO. */
  async tnzoUsdNano(): Promise<bigint> {
    const r = await this.rpc.call<{ rate_nano_usd: string }>("tenzro_getFeeRate", {});
    return BigInt(r.rate_nano_usd);
  }

  /** What `units` cost at `provider` for `modelId`, in TNZO base units. */
  async quote(provider: string, modelId: string, units: BillableUnits): Promise<bigint> {
    const found = await this.priceCard(provider, modelId);
    if (!found) throw new Error(`${provider} publishes no card for ${modelId}`);
    return chargeWei(found.card.rates, units, await this.tnzoUsdNano());
  }
}
