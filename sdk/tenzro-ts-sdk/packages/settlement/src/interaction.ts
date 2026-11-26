/**
 * The digest of a Tenzro interaction record, implemented from
 * `docs/standards/interaction-receipt.md`. It runs wherever WebCrypto does,
 * so a browser page can check a receipt without a node.
 */
import { parseExact } from "@tenzro/core";

/** Domain tag the preimage starts with. */
export const INTERACTION_DOMAIN = "tenzro/interaction-attestation/v2";

const KINDS = [
  "inference",
  "rental",
  "storage",
  "database",
  "hosting",
  "security",
  "marketplace",
  "rpc_brokerage",
  "access",
];
const U64_MAX = 2n ** 64n - 1n;
const U128_MAX = 2n ** 128n - 1n;
const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;

/**
 * Why a record has no digest: `malformed` when a field is missing, has the
 * wrong JSON type or an unknown value; `not_attestable` when the record is
 * well formed but names no payer, attester or interaction, or its charge
 * contradicts its amount.
 */
export class InteractionError extends Error {
  constructor(
    readonly reason: "malformed" | "not_attestable",
    message: string,
  ) {
    super(reason === "malformed" ? `not an interaction record: ${message}` : `the record has no digest: ${message}`);
  }
}

const malformed = (why: string) => new InteractionError("malformed", why);
type Json = Record<string, unknown>;

function text(record: Json, path: string): string {
  let at: unknown = record;
  for (const key of path.split(".")) {
    if (typeof at !== "object" || at === null || !(key in at)) throw malformed(`\`${path}\` is missing`);
    at = (at as Json)[key];
  }
  if (typeof at !== "string") throw malformed(`\`${path}\` is not a string`);
  return at;
}

/** A JSON integer as `parseExact` returns it: a safe number or a bigint. */
function integer(value: unknown): bigint | undefined {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  return undefined;
}

/** The amount in wei: a JSON number up to 2^64 - 1, or a string of decimal digits for any value. */
function amount(record: Json): bigint {
  if (!("amount_charged" in record)) throw malformed("`amount_charged` is missing");
  const value = record.amount_charged;
  if (typeof value === "string") {
    if (!/^[0-9]+$/.test(value)) throw malformed("`amount_charged` is not a number or a decimal string");
    const wei = BigInt(value);
    if (wei > U128_MAX) throw malformed("`amount_charged` does not fit 128 bits");
    return wei;
  }
  const wei = integer(value);
  if (wei === undefined || wei < 0n || wei > U64_MAX) throw malformed("`amount_charged` is not a whole number");
  return wei;
}

function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

/**
 * The bytes the digest is taken over. `record` is the record's JSON text, or
 * the value `parseExact` made of it; a value from `JSON.parse` has already
 * rounded any integer past 2^53.
 */
export function interactionPreimage(record: unknown): Uint8Array {
  const parsed = typeof record === "string" ? parseExact(record) : record;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw malformed("not a JSON object");
  const r = parsed as Json;
  const kind = text(r, "kind");
  if (!KINDS.includes(kind)) throw malformed(`\`${kind}\` is not an interaction kind`);
  let onBehalfOf = "";
  if (r.on_behalf_of !== undefined && r.on_behalf_of !== null) {
    if (typeof r.on_behalf_of !== "string") throw malformed("`on_behalf_of` is not a string");
    onBehalfOf = r.on_behalf_of;
  }
  const authorityKind = text(r, "authority.kind");
  const authorityValue = (() => {
    switch (authorityKind) {
      case "delegation":
        return text(r, "authority.controller_did");
      case "x402_payment":
        return text(r, "authority.scheme");
      case "credential":
        return text(r, "authority.digest");
      case "open":
        return "";
      default:
        throw malformed(`\`${authorityKind}\` is not an authority kind`);
    }
  })();
  const chargeKind = text(r, "charge.kind");
  const chargeValue = (() => {
    switch (chargeKind) {
      case "settlement":
        return text(r, "charge.settlement_id");
      case "channel": {
        const nonce = integer((r.charge as Json).nonce);
        if (nonce === undefined || nonce < 0n || nonce > U64_MAX) throw malformed("`charge.nonce` is not a whole number");
        return `${text(r, "charge.channel_id")}:${nonce}`;
      }
      case "accrued":
        return text(r, "charge.accrued_wei");
      case "free":
        return "";
      default:
        throw malformed(`\`${chargeKind}\` is not a charge kind`);
    }
  })();
  const wei = amount(r);
  const occurredAt = integer(r.occurred_at);
  if (occurredAt === undefined || occurredAt < I64_MIN || occurredAt > I64_MAX) {
    throw malformed("`occurred_at` is not an integer");
  }
  const interactionId = text(r, "interaction_id");
  const payerDid = text(r, "payer_did");
  const attesterDid = text(r, "attester_did");
  for (const [name, value] of [
    ["payer_did", payerDid],
    ["attester_did", attesterDid],
    ["interaction_id", interactionId],
  ]) {
    if (value === "") throw new InteractionError("not_attestable", `\`${name}\` is empty`);
  }
  if ((chargeKind === "free") !== (wei === 0n)) {
    throw new InteractionError("not_attestable", `a \`${chargeKind}\` charge of ${wei} wei`);
  }
  const when = new Uint8Array(8);
  new DataView(when.buffer).setBigInt64(0, occurredAt, true);
  const utf8 = (s: string) => new TextEncoder().encode(s);
  const fields = [
    utf8(interactionId),
    utf8(kind),
    utf8(payerDid),
    utf8(onBehalfOf),
    utf8(attesterDid),
    utf8(text(r, "resource_id")),
    utf8(authorityKind),
    utf8(authorityValue),
    utf8(chargeKind),
    utf8(chargeValue),
    utf8(wei.toString()),
    utf8(text(r, "settled_asset")),
    when,
  ];
  const parts = [utf8(INTERACTION_DOMAIN), ...fields.flatMap((f) => [u32le(f.length), f])];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** The record's digest, lowercase hex, as the node attests it. */
export async function interactionDigest(record: unknown): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(interactionPreimage(record))));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}
