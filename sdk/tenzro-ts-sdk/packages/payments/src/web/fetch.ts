/**
 * The payer side: a fetch that answers 402 by paying one of the offered
 * requirements and retrying, and keeps paying a path it has paid before
 * without another 402 round trip. A delegated agent pays from a channel its
 * wallet funded; its serving node signs each voucher with its hardware key
 * for the agent, and the ledger honors it only within the agent's Terms.
 */
import type { RpcClient } from "@tenzro/core";
import {
  type HybridSigner,
  accountAddress,
  compositeMessageRepresentative,
  compositeSignatureJson,
} from "@tenzro/core";
import type { PaymentChallenge } from "@tenzro/core";
import {
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  X402_VERSION,
  challengeIdOf,
  decodeHeaderText,
  encodeHeaderText,
  stringifyExact,
  tenzroNetwork,
  type PaymentRequired,
  type PaymentRequirement,
  type ResourceInfo,
} from "./x402";

/** A composite signature in the network's JSON form: the P-256 leg, and the ML-DSA-65 leg when present. */
type CompositeSignatureJson = { classical: { form: string; signature: string }; pq?: string };

/** Pays requirements it supports, returning the payload's `payload` field. */
export interface Payer {
  supports(r: PaymentRequirement): boolean;
  pay(r: PaymentRequirement, resource: ResourceInfo): Promise<unknown>;
}

export interface PayingFetchOptions {
  /** The most one request may cost, in the requirement's smallest unit. */
  maxAmount: bigint;
  fetch?: typeof fetch;
}

/** The `PAYMENT-SIGNATURE` value for `requirement`, paid by `payer`. */
export async function paymentHeader(payer: Payer, required: PaymentRequired, requirement: PaymentRequirement): Promise<string> {
  const payload = await payer.pay(requirement, required.resource);
  const body = { x402Version: X402_VERSION, resource: required.resource, accepted: requirement, payload };
  return encodeHeaderText(stringifyExact(body));
}

/** A fetch that pays. Returns the paid response, or the 402 when nothing offered is payable within `maxAmount`. */
export function payingFetch(payer: Payer, opts: PayingFetchOptions): (input: string | URL, init?: RequestInit) => Promise<Response> {
  const send = opts.fetch ?? fetch;
  const known = new Map<string, { required: PaymentRequired; requirement: PaymentRequirement }>();
  const keyOf = (u: URL) => `${u.origin}${u.pathname}`;
  const withHeader = (init: RequestInit | undefined, value: string): RequestInit => {
    const headers = new Headers(init?.headers);
    headers.set(PAYMENT_SIGNATURE_HEADER, value);
    return { ...init, headers };
  };
  const fresh = (r: PaymentRequirement): PaymentRequirement => ({ ...r, extra: { ...(r.extra ?? {}), challengeId: globalThis.crypto.randomUUID() } });

  return async (input, init) => {
    const url = new URL(String(input));
    const prior = known.get(keyOf(url));
    if (prior) {
      // A path paid before is paid up front under a fresh challenge id; a
      // voucher only ever moves forward, so a replay pays nothing twice.
      const requirement = fresh(prior.requirement);
      const res = await send(url, withHeader(init, await paymentHeader(payer, prior.required, requirement)));
      if (res.status !== 402) return res;
      known.delete(keyOf(url));
    }
    const first = await send(url, init);
    if (first.status !== 402) return first;
    const header = first.headers.get(PAYMENT_REQUIRED_HEADER);
    if (!header) return first;
    const required = JSON.parse(decodeHeaderText(header)) as PaymentRequired;
    const requirement = required.accepts.find((r) => payer.supports(r) && BigInt(r.amount) <= opts.maxAmount);
    if (!requirement) return first;
    const paid = await send(url, withHeader(init, await paymentHeader(payer, required, requirement)));
    if (paid.status !== 402) known.set(keyOf(url), { required, requirement });
    return paid;
  };
}

/** A delegated agent paying from its channel (an escrow its wallet funded) to one payee. */
export class AgentChannelPayer implements Payer {
  private cumulative: bigint;

  /**
   * @param rpc a client on one of the agent's serving nodes, carrying the agent's credential
   * @param chainId the Tenzro chain
   * @param channelId the escrow id (hex)
   * @param payTo the payee the channel pays
   * @param spent what earlier vouchers on the channel already cover
   */
  constructor(
    private readonly rpc: RpcClient,
    private readonly chainId: number,
    private readonly channelId: string,
    private readonly payTo: string,
    spent: bigint = 0n,
  ) {
    this.cumulative = spent;
  }

  supports(r: PaymentRequirement): boolean {
    return (
      r.scheme === "batch-settlement" &&
      r.network === tenzroNetwork(this.chainId) &&
      r.payTo.replace(/^0x/, "").toLowerCase() === this.payTo.replace(/^0x/, "").toLowerCase()
    );
  }

  async pay(r: PaymentRequirement): Promise<unknown> {
    const charge = BigInt(r.amount);
    const next = this.cumulative + charge;
    const signed = (await this.rpc.call("tenzro_agentVoucher", {
      channel_id: this.channelId,
      cumulative_amount: next.toString(),
    })) as { voucher: { signature: CompositeSignatureJson; agent: { agent_did: string; machine_did: string; as_of_ms: number } } };
    this.cumulative = next;
    return agentVoucherCredential(r, this.channelId, next, charge, signed.voucher, globalThis.crypto.randomUUID());
  }
}

/** The credential a facilitator takes for an agent's voucher, as `PaymentCredential` serializes. */
export function agentVoucherCredential(
  r: PaymentRequirement,
  channelId: string,
  cumulative: bigint,
  charge: bigint,
  voucher: { signature: CompositeSignatureJson; agent: { agent_did: string; machine_did: string; as_of_ms: number } },
  credentialId: string,
): Record<string, unknown> {
  return {
    credential_id: credentialId,
    challenge_id: challengeIdOf(r) ?? "",
    protocol: "x402",
    payer_did: voucher.agent.agent_did,
    payer_address: "",
    amount: charge,
    asset: r.asset,
    signature: voucher.signature,
    extra: {
      escrow_id: channelId.replace(/^0x/, ""),
      cumulative_amount: cumulative.toString(),
      agent_did: voucher.agent.agent_did,
      machine_did: voucher.agent.machine_did,
      as_of_ms: String(voucher.agent.as_of_ms),
    },
  };
}

/** Context of the composite signature over a payment authorization. */
export const PAYMENT_AUTHORIZATION_CONTEXT = new TextEncoder().encode("tenzro/payment/authorization");

const hexOf = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

function fromHex(value: string): Uint8Array {
  const clean = value.trim().replace(/^0x/, "");
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) throw new Error(`${value} is not hex`);
  return Uint8Array.from(clean.match(/../g) ?? [], (h) => parseInt(h, 16));
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function u64le(v: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, true);
  return b;
}

function u128le(v: bigint): Uint8Array {
  if (v < 0n || v >= 1n << 128n) throw new Error("amount out of range");
  return concat([u64le(v & ((1n << 64n) - 1n)), u64le(v >> 64n)]);
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

/** A Tenzro address from 20 or 32 bytes of hex; 20 bytes fill the leading bytes. */
function tenzroAddress(value: string): Uint8Array {
  const bytes = fromHex(value);
  if (bytes.length === 32) return bytes;
  if (bytes.length === 20) return concat([bytes, new Uint8Array(12)]);
  throw new Error(`address ${value} is ${bytes.length} bytes; a Tenzro address is 20 or 32 bytes`);
}

/**
 * The account a payer pays from: `account` (20 or 32 bytes of hex) when the
 * caller names one, such as the shared account a wallet's linked passkeys
 * act for, otherwise the account the signer's P-256 key names.
 */
async function payingAccount(signer: HybridSigner, account?: string): Promise<Uint8Array> {
  return account === undefined ? accountAddress(signer.p256PublicKey()) : tenzroAddress(account);
}

/** The fields a payment authorization covers. */
interface AuthorizationFields {
  chainId: bigint;
  challengeId: string;
  payer: Uint8Array;
  payTo: string;
  maxAmount: bigint;
  asset: string;
  resource: string;
  quoteDigest?: Uint8Array;
  usdE6?: bigint;
  appMargin?: AppMargin;
}

/** An application's developer margin on a payment, as the payer signs it. */
interface AppMargin {
  appWallet: Uint8Array;
  marginBps: number;
}

/** `0x00` for no margin, or `0x01 || app_wallet(32) || margin_bps(u32 LE)`. */
function appMarginBytes(m?: AppMargin): Uint8Array {
  if (m === undefined) return new Uint8Array([0]);
  return concat([new Uint8Array([1]), m.appWallet, u32le(m.marginBps)]);
}

/**
 * The developer margin a challenge asks the payer to sign: `app_wallet` and a
 * non-zero `margin_bps` together, or neither.
 */
function challengeAppMargin(extra: Record<string, unknown>): AppMargin | undefined {
  const bps = extra["margin_bps"];
  const wallet = extra["app_wallet"];
  if (bps !== undefined && (typeof bps !== "number" || !Number.isInteger(bps) || bps < 0 || bps > 0xffffffff)) {
    throw new Error("margin_bps must be a u32");
  }
  if (wallet !== undefined && typeof wallet !== "string") throw new Error("app_wallet must be a hex string");
  const marginBps = (bps as number | undefined) ?? 0;
  if (wallet === undefined && marginBps === 0) return undefined;
  if (wallet === undefined || marginBps === 0) {
    throw new Error("a developer margin names both a non-zero margin_bps and an app_wallet");
  }
  return { appWallet: tenzroAddress(wallet), marginBps };
}

/**
 * The payment authorization preimage, exactly as the node rebuilds it: the
 * chain, the challenge id, payer and payee, the ceiling, the asset, and what
 * is paid for (the request digest of the resource, the quote digest and the
 * USD price, zero when unquoted, and the application margin, if any).
 */
async function authorizationPreimage(f: AuthorizationFields): Promise<Uint8Array> {
  const id = utf8(f.challengeId);
  const asset = utf8(f.asset);
  const requestDigest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", concat([utf8("tenzro/request"), utf8(f.resource)]) as BufferSource),
  );
  const quoteDigest = f.quoteDigest ?? new Uint8Array(32);
  if (quoteDigest.length !== 32) throw new Error("quote_digest is 32 bytes of hex");
  return concat([
      utf8("tenzro/payment-authorization"),
      u64le(f.chainId),
      u32le(id.length),
      id,
      f.payer,
      tenzroAddress(f.payTo),
      u128le(f.maxAmount),
      u32le(asset.length),
      asset,
      requestDigest,
      quoteDigest,
      u64le(f.usdE6 ?? 0n),
      appMarginBytes(f.appMargin),
    ]);
}

/**
 * The message a payer signs to authorize `maxAmount` against a
 * `tenzro-hybrid` requirement for `resourceUrl`, exactly as the facilitator
 * rebuilds it: the chain, the challenge id, payer and payee, the ceiling, the
 * asset, and the request digest of the resource.
 */
export async function hybridAuthorizationMessage(
  r: PaymentRequirement,
  resourceUrl: string,
  payer: Uint8Array,
  maxAmount: bigint,
): Promise<Uint8Array> {
  const chain = /^tenzro:(\d+)$/.exec(r.network);
  if (!chain) throw new Error(`${r.network} is not a Tenzro network`);
  const challengeId = challengeIdOf(r);
  if (challengeId === undefined) throw new Error("the requirement names no challengeId");
  return authorizationPreimage({
    chainId: BigInt(chain[1]),
    challengeId,
    payer,
    payTo: r.payTo,
    maxAmount,
    asset: r.asset,
    resource: resourceUrl,
  });
}

/**
 * The message a payer signs to authorize `maxAmount` against a challenge the
 * node issued (`tenzro_createPaymentChallenge`), exactly as the node rebuilds
 * it, including the quote digest and USD price a quoted challenge carries
 * and the developer margin it asks the payer to sign.
 */
export async function challengeAuthorizationMessage(
  challenge: PaymentChallenge,
  payer: Uint8Array,
  maxAmount: bigint,
): Promise<Uint8Array> {
  const extra = challenge.extra ?? {};
  const chainId = extra["chain_id"];
  if (typeof chainId !== "number" && typeof chainId !== "bigint") {
    throw new Error(`challenge ${challenge.challenge_id} carries no chain_id; it was not issued by a node`);
  }
  const quote = extra["quote_digest"];
  const usd = extra["usd_e6"];
  return authorizationPreimage({
    chainId: BigInt(chainId),
    challengeId: challenge.challenge_id,
    payer,
    payTo: challenge.recipient,
    maxAmount,
    asset: challenge.asset,
    resource: challenge.resource,
    quoteDigest: quote === undefined ? undefined : fromHex(String(quote)),
    usdE6: usd === undefined ? undefined : BigInt(usd as number),
    appMargin: challengeAppMargin(extra),
  });
}

/** A payer's signed answer to a node-issued challenge, as the pay endpoints parse it. */
export interface PaymentCredential {
  credential_id: string;
  challenge_id: string;
  protocol: string;
  payer_did: string;
  payer_address: string;
  amount: bigint;
  asset: string;
  signature: ReturnType<typeof compositeSignatureJson>;
  extra: Record<string, string>;
}

/**
 * Sign a credential for `challenge` with the payer's hardware key. The charge
 * is the challenge amount; `maxAmount` is the ceiling signed (defaults to the
 * charge), recorded as `upto_max` when above it (a metered credential).
 */
export async function signChallengeCredential(
  challenge: PaymentChallenge,
  signer: HybridSigner,
  payerDid: string = "",
  maxAmount?: bigint,
  account?: string,
): Promise<PaymentCredential> {
  const amount = BigInt(challenge.amount);
  const ceiling = maxAmount ?? amount;
  if (ceiling < amount) throw new Error(`maxAmount ${ceiling} is below the challenge amount ${amount}`);
  const publicKey = signer.p256PublicKey();
  const payer = await payingAccount(signer, account);
  const message = await challengeAuthorizationMessage(challenge, payer, ceiling);
  const mPrime = await compositeMessageRepresentative(PAYMENT_AUTHORIZATION_CONTEXT, message);
  const [signature, pqSignature] = await signer.signComposite(mPrime);
  const extra: Record<string, string> = { public_key: hexOf(publicKey) };
  if (ceiling !== amount) extra["upto_max"] = ceiling.toString();
  return {
    credential_id: globalThis.crypto.randomUUID(),
    challenge_id: challenge.challenge_id,
    protocol: challenge.protocol.toLowerCase(),
    payer_did: payerDid,
    payer_address: hexOf(payer),
    amount,
    asset: challenge.asset,
    signature: compositeSignatureJson(signature, pqSignature),
    extra,
  };
}

/** A payer paying `tenzro-hybrid` requirements with its hardware key. */
export class HybridPayer implements Payer {
  /**
   * @param signer the payer's hardware signer
   * @param payerDid the payer's DID, when one stands behind the key
   * @param account the account paid from, 20 or 32 bytes of hex: a passkey
   *   account whose keystore links the signer's passkey; by default the
   *   account the signer's P-256 key names
   */
  constructor(
    private readonly signer: HybridSigner,
    private readonly payerDid: string = "",
    private readonly account?: string,
  ) {}

  supports(r: PaymentRequirement): boolean {
    return r.scheme === "tenzro-hybrid" && /^tenzro:\d+$/.test(r.network);
  }

  async pay(r: PaymentRequirement, resource: ResourceInfo): Promise<unknown> {
    const publicKey = this.signer.p256PublicKey();
    const payer = await payingAccount(this.signer, this.account);
    const amount = BigInt(r.amount);
    const message = await hybridAuthorizationMessage(r, resource.url, payer, amount);
    const mPrime = await compositeMessageRepresentative(PAYMENT_AUTHORIZATION_CONTEXT, message);
    const [signature, pqSignature] = await this.signer.signComposite(mPrime);
    return {
      credential_id: globalThis.crypto.randomUUID(),
      challenge_id: challengeIdOf(r) ?? "",
      protocol: "x402",
      payer_did: this.payerDid,
      payer_address: hexOf(payer),
      amount,
      asset: r.asset,
      signature: compositeSignatureJson(signature, pqSignature),
      extra: { public_key: hexOf(publicKey) },
    };
  }
}
