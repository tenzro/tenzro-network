/**
 * OpenShell sandboxes on Tenzro: the Terms a sandbox's agent is delegated
 * under, the provider credential the gateway attaches, and the signed records
 * of what the Tenzro extensions decided, verified offline.
 *
 * Terms are held by Tenzro and approved by the controller's passkey. The
 * policy's `tenzro` network middleware takes no config: it only routes the
 * sandbox's traffic through the extensions, which read the agent's Terms from
 * Tenzro on every decision.
 *
 * Every decision is a tenzro-types agent audit entry, signed by a session key
 * that the serving node's hardware identity certified. An entry is
 * `{"body": <hex of the entry JSON>, "signature": <hex of the SessionSignature
 * JSON>}`; entries of one session are numbered from 0, each chained to the
 * leaf hash of the one before, and the session's root is the MMR root of
 * their leaf hashes. A session is named by SHA-256("tenzro/openshell/session/v1"
 * || 0x00 || gateway || 0x00 || name), the name being a sandbox, or the agent's
 * DID for its model calls.
 */
import type { AgentTerms, AuthClient, DelegatedAgent, ServingNodeRef } from "@tenzro/core";
import { COMPOSITE_LABEL_MLDSA65_P256, compositeMessageRepresentative } from "@tenzro/core";
import { bagPeaks, fromHex, nodeHash, sha256, strip0x, toHex, u64le } from "./agent";

const SESSION_DOMAIN = "tenzro/openshell/session/v1\0";
const CERTIFICATE_CONTEXT = "tenzro/session/certificate";
const HYBRID_SESSION_CONTEXT = "tenzro/session/ml-dsa-65";
const ML_DSA_65_VK_LEN = 1952;
const ML_DSA_65_SIG_LEN = 3309;
const KEY_TYPE_TAGS: Record<string, number> = { Ed25519: 0, Secp256k1: 1, Ed25519MlDsa65: 2 };

/** The payment rails a sandbox may use, as Terms name them. */
export const OPENSHELL_PAYMENT_PROTOCOLS = ["x402", "mpp", "ap2"] as const;

/** The middleware name the Tenzro supervisor middleware registers under. */
export const OPENSHELL_TENZRO_MIDDLEWARE = "tenzro";

/** The sandbox annotation that names the agent a sandbox runs. */
export const OPENSHELL_AGENT_ANNOTATION = "tenzro.agent";

/** The response header that carries the signed record of a model call. */
export const OPENSHELL_RECEIPT_HEADER = "x-tenzro-receipt";

/** The parts of an OpenShell sandbox policy the checks read. */
export interface OpenShellPolicy {
  network_policies?: Record<string, { name?: string; endpoints?: { host: string; port?: number }[] }>;
  network_middlewares?: Record<string, { name?: string; middleware: string; config?: unknown; on_error?: string }>;
}

/** What the controller grants the sandbox's agent, approved on Tenzro. */
export interface OpenShellGrant {
  /** Models the agent may call through the Tenzro provider. */
  models?: string[];
  /** The agent may change its sandbox's policy. */
  policy_changes?: boolean;
  /** The agent may make MCP tool calls through the sandbox. */
  tools?: boolean;
  /** Most one payment or inference charge may move, wei, canonical decimal. */
  max_transaction_value: string;
  /** Most the agent may spend in a day, wei, canonical decimal. */
  max_daily_spend: string;
  /** Chains the agent may act on; Tenzro alone when omitted. */
  chains?: string[];
  payments?: {
    protocols?: string[];
    /** Addresses (hex) the agent may pay. */
    payees?: string[];
    /** Pay any payee; the grant must say so, an empty list is refused. */
    any_payee?: boolean;
    /** Hosts of the services the agent pays; each must be a network policy endpoint. */
    services?: string[];
  };
  expires_in_secs: number;
}

/** Who the Terms are for and where the agent is served. */
export interface OpenShellTermsOptions {
  controller_did: string;
  agent_name: string;
  serving_nodes: ServingNodeRef[];
  capabilities?: string[];
  min_distinct_operators?: number;
  /** Clock for the expiry, ms; now when omitted. */
  now_ms?: number;
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/**
 * The Terms to ask Tenzro for, from an explicit grant, checked against the
 * sandbox policy: the policy routes through exactly one `tenzro` middleware,
 * which carries no config and does not fail open, and every payment service
 * is an endpoint of its network policy. Refuses open limits or payees, rails
 * Terms do not know and wildcard models. Every sandbox may be created and
 * reach its endpoints; policy changes, tool calls, inference and payments are
 * granted only when asked for.
 */
export function openShellTerms(policy: OpenShellPolicy, grant: OpenShellGrant, opts: OpenShellTermsOptions): AgentTerms {
  const mws = Object.values(policy.network_middlewares ?? {}).filter((m) => m?.middleware === OPENSHELL_TENZRO_MIDDLEWARE);
  if (mws.length === 0) throw new Error("the policy has no tenzro middleware");
  if (mws.length > 1) throw new Error("the policy names the tenzro middleware twice");
  if (mws[0].config !== undefined) throw new Error("the tenzro middleware takes no config: Terms stay on Tenzro");
  if (mws[0].on_error !== undefined && mws[0].on_error !== "fail_closed") throw new Error("the tenzro middleware must fail closed");
  const models = grant.models ?? [];
  if (models.some((m) => !m || m.includes("*"))) throw new Error("models must be named");
  const pay = grant.payments ?? {};
  const protocols = (pay.protocols ?? []).map((p) => p.toLowerCase());
  for (const p of protocols) {
    if (!(OPENSHELL_PAYMENT_PROTOCOLS as readonly string[]).includes(p)) {
      throw new Error(`payment protocol ${p} is not one of ${OPENSHELL_PAYMENT_PROTOCOLS.join(", ")}`);
    }
  }
  let payees: string[] = [];
  if (protocols.length > 0 && pay.any_payee !== true) {
    payees = pay.payees ?? [];
    if (payees.length === 0) throw new Error("name the payees or set any_payee");
    for (const a of payees) if (!ADDRESS.test(a)) throw new Error(`payee ${a} is not a 20-byte hex address`);
    payees = payees.map((a) => a.toLowerCase());
  }
  const services = pay.services ?? [];
  if (services.length > 0 && protocols.length === 0) throw new Error("payment services need a payment rail");
  const hosts = new Set<string>();
  for (const np of Object.values(policy.network_policies ?? {})) {
    for (const ep of np.endpoints ?? []) hosts.add(ep.host.toLowerCase());
  }
  for (const s of services) {
    if (!hosts.has(s.toLowerCase())) throw new Error(`payment service ${s} is not an endpoint of the network policy`);
  }
  for (const k of ["max_transaction_value", "max_daily_spend"] as const) {
    const v = grant[k];
    if (typeof v !== "string" || !DECIMAL.test(v)) throw new Error(`${k} is not a canonical decimal`);
  }
  if (BigInt(grant.max_transaction_value) > BigInt(grant.max_daily_spend)) {
    throw new Error("max_transaction_value is above max_daily_spend");
  }
  const secs = grant.expires_in_secs;
  if (typeof secs !== "number" || !Number.isInteger(secs) || secs <= 0) {
    throw new Error("expires_in_secs must be a positive whole number");
  }
  const operations = ["sandbox", "fetch"];
  if (grant.policy_changes === true) operations.push("sandbox.policy");
  if (grant.tools === true) operations.push("tool");
  if (models.length > 0) operations.push("inference");
  if (protocols.length > 0) operations.push("pay");
  const terms: AgentTerms = {
    controller_did: opts.controller_did,
    agent_name: opts.agent_name,
    delegation_scope: {
      max_transaction_value: grant.max_transaction_value,
      max_daily_spend: grant.max_daily_spend,
      allowed_operations: operations,
      allowed_payment_protocols: protocols,
      allowed_chains: grant.chains ?? ["tenzro"],
      allowed_models: models,
      allowed_counterparties: payees,
    },
    capabilities: opts.capabilities ?? [],
    serving_nodes: opts.serving_nodes,
    expires_at_ms: (opts.now_ms ?? Date.now()) + secs * 1000,
  };
  if (opts.min_distinct_operators !== undefined) terms.min_distinct_operators = opts.min_distinct_operators;
  return terms;
}

const utf8 = (s: string) => new TextEncoder().encode(s);

/** The session id of `name` (a sandbox, or an agent DID) on `gateway`, hex. */
export async function openShellSessionId(gateway: string, name: string): Promise<string> {
  return toHex(await sha256(utf8(SESSION_DOMAIN), utf8(gateway), Uint8Array.of(0), utf8(name)));
}

/** The provider record and annotation a sandbox for the agent is created with. */
export interface OpenShellCredential {
  agent_did: string;
  /**
   * The provider record: its one credential is the agent's DID. The Tenzro
   * credential driver mints a short-lived token from it on every resolve;
   * neither the DID nor the token reaches the sandbox's environment.
   */
  provider: { name: "tenzro"; type: "tenzro"; credentials: { TENZRO_AGENT_TOKEN: string } };
  /** The sandbox annotation naming the agent (`--annotation tenzro.agent=<did>`). */
  annotation: { [OPENSHELL_AGENT_ANNOTATION]: string };
  delegated: DelegatedAgent;
}

/**
 * Delegate the sandbox's agent under the Terms `grant` asks for, approved by
 * the controller's passkey (`authorize`), and return the provider record and
 * annotation its sandbox is created with.
 */
export async function mintOpenShellCredential(
  auth: AuthClient,
  p: {
    accountAddress: string;
    policy: OpenShellPolicy;
    grant: OpenShellGrant;
    options: OpenShellTermsOptions;
    /** Signs the custody challenge with a passkey enrolled on the controller's account. */
    authorize: Parameters<AuthClient["delegateAgent"]>[2];
  },
): Promise<OpenShellCredential> {
  const terms = openShellTerms(p.policy, p.grant, p.options);
  const delegated = await auth.delegateAgent(p.accountAddress, terms, p.authorize);
  const did = delegated?.identity?.did;
  if (!did) throw new Error("the node returned no agent DID");
  return {
    agent_did: did,
    provider: { name: "tenzro", type: "tenzro", credentials: { TENZRO_AGENT_TOKEN: did } },
    annotation: { [OPENSHELL_AGENT_ANNOTATION]: did },
    delegated,
  };
}

/** A signed agent audit entry as stored and disclosed: hex of the signed JSON and of its session signature. */
export interface OpenShellSignedEntry {
  body: string;
  signature: string;
}

/** The hardware identity that certifies the session keys: P-256 `x || y` hex, and its ML-DSA-65 key when it has one. */
export interface OpenShellIdentity {
  p256: string;
  pq?: string;
}

/** Entries from JSON Lines (one signed entry per line) or a JSON array. */
export function parseOpenShellEntries(text: string): OpenShellSignedEntry[] {
  const t = text.trim();
  const rows: unknown[] = t.startsWith("[") ? JSON.parse(t) : t.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  return rows.map((r, i) => {
    const e = r as Partial<OpenShellSignedEntry>;
    if (typeof e?.body !== "string" || typeof e?.signature !== "string") throw new Error(`entry ${i} is not a signed entry`);
    return { body: e.body, signature: e.signature };
  });
}

/** One verified entry. */
export interface OpenShellRecord {
  session_id: string;
  seq: number;
  at_ms: number;
  agent: string;
  /** `egress`, `tool_call`, `spend`, `model_call`, `grant_use`, `violation`, ... */
  kind: string;
  action: string;
  outcome: { status: string; reason?: string };
  /** SHA-256 of the action's arguments, hex. */
  detail: string;
  linked_tx?: string;
  /** The host binding the serving node verified. */
  image?: string;
  /** For a tool call: the serving node and the surface (`openshell`). */
  call?: { node: string; surface: string; [k: string]: unknown };
  /** Its leaf hash in the session's MMR, hex. */
  leaf: string;
  /** Whether a hybrid (Ed25519 + ML-DSA-65) session key signed it. */
  hybrid: boolean;
}

/** A session every entry of which verified. */
export interface VerifiedOpenShellSession {
  session_id: string;
  agent: string;
  count: number;
  /** The MMR root over every entry, hex. */
  root: string;
  entries: OpenShellRecord[];
}

/** Verifier options. */
export interface OpenShellVerifyOptions {
  /** The serving node's hardware identity. */
  identity: OpenShellIdentity;
  /**
   * The moment hybrid records are in force, ms (chain state); an entry made at
   * or after it must carry a hybrid session signature. Not in force when omitted.
   */
  hybridRecordsFromMs?: number;
  /** The session the entries must belong to, hex. */
  sessionId?: string;
}

type KeyJson = { key_type: string; bytes: number[] };
type SigJson = { key_type: string; bytes: number[] };
type CompositeJson = { classical: { form: string; signature?: string }; pq?: string };
type SessionSignatureJson = {
  certificate: { session_key: KeyJson; not_after_ms: number; signature: CompositeJson };
  signature: SigJson;
};

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const u32le = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const buf = (b: Uint8Array) => Uint8Array.from(b).buffer;

function bytesOf(v: unknown, what: string): Uint8Array {
  if (!Array.isArray(v) || v.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) throw new Error(`${what} is not a byte array`);
  return Uint8Array.from(v as number[]);
}

/** A DER ECDSA signature, or raw r || s, as raw r || s. */
function rawP256(sig: Uint8Array): Uint8Array {
  if (sig.length === 64) return sig;
  const fail = () => {
    throw new Error("the P-256 leg is neither raw r || s nor DER");
  };
  if (sig[0] !== 0x30 || sig[1] !== sig.length - 2) fail();
  let o = 2;
  const int = () => {
    if (sig[o] !== 0x02) fail();
    const len = sig[o + 1];
    let v = sig.subarray(o + 2, o + 2 + len);
    o += 2 + len;
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) fail();
    return concat(new Uint8Array(32 - v.length), v);
  };
  const r = int();
  const s = int();
  if (o !== sig.length) fail();
  return concat(r, s);
}

let mlDsa: Promise<{ verify: (sig: Uint8Array, msg: Uint8Array, pk: Uint8Array, opts?: { context?: Uint8Array }) => boolean }> | undefined;
function mlDsa65() {
  mlDsa ??= import("@noble/post-quantum/ml-dsa.js").then((m) => m.ml_dsa65);
  return mlDsa;
}

async function mlDsaVerify(vk: Uint8Array, ctx: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  if (vk.length !== ML_DSA_65_VK_LEN || sig.length !== ML_DSA_65_SIG_LEN) return false;
  return (await mlDsa65()).verify(sig, msg, vk, { context: ctx });
}

/** The identity's composite signature under the session-certificate context. */
async function verifyComposite(identity: OpenShellIdentity, message: Uint8Array, sig: CompositeJson): Promise<boolean> {
  if (sig?.classical?.form !== "raw" || typeof sig.classical.signature !== "string") {
    throw new Error("the certificate's P-256 leg is not a raw hardware signature");
  }
  const m = await compositeMessageRepresentative(utf8(CERTIFICATE_CONTEXT), message);
  const xy = fromHex(identity.p256);
  if (xy.length !== 64) throw new Error("the identity's P-256 key is not x || y");
  const key = await crypto.subtle.importKey("raw", buf(concat(Uint8Array.of(4), xy)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const p256ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, buf(rawP256(fromHex(sig.classical.signature))), buf(m));
  if (!p256ok) return false;
  const pq = sig.pq !== undefined && sig.pq !== null ? fromHex(sig.pq) : undefined;
  const enrolled = identity.pq ? fromHex(identity.pq) : undefined;
  if (pq && !enrolled) throw new Error("ML-DSA-65 leg present for an identity with no ML-DSA-65 key");
  if (enrolled && !pq) return false;
  if (pq && enrolled) return mlDsaVerify(enrolled, COMPOSITE_LABEL_MLDSA65_P256, m, pq);
  return true;
}

async function verifySessionKey(key: KeyJson, message: Uint8Array, sig: SigJson): Promise<boolean> {
  const k = bytesOf(key.bytes, "the session key");
  const s = bytesOf(sig.bytes, "the session signature");
  const ed25519 = async (pk: Uint8Array, sg: Uint8Array) => {
    if (pk.length !== 32 || sg.length !== 64) return false;
    const ck = await crypto.subtle.importKey("raw", buf(pk), { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "Ed25519" }, ck, buf(sg), buf(message));
  };
  if (key.key_type === "Ed25519") return sig.key_type === "Ed25519" && ed25519(k, s);
  if (key.key_type === "Ed25519MlDsa65") {
    if (sig.key_type !== "Ed25519MlDsa65" || k.length !== 32 + ML_DSA_65_VK_LEN || s.length <= 64) return false;
    return (await ed25519(k.subarray(0, 32), s.subarray(0, 64))) && mlDsaVerify(k.subarray(32), utf8(HYBRID_SESSION_CONTEXT), message, s.subarray(64));
  }
  return false;
}

/**
 * Check one session signature over `body` made at `atMs`: the identity
 * certified the session key, the certificate was valid at `atMs`, the session
 * key signed `body`, and a record made once hybrid records are in force
 * carries a hybrid session key. Returns whether the session key is hybrid.
 */
export async function verifyOpenShellSignature(
  body: Uint8Array,
  signature: Uint8Array,
  atMs: number,
  opts: Pick<OpenShellVerifyOptions, "identity" | "hybridRecordsFromMs">,
): Promise<boolean> {
  let s: SessionSignatureJson;
  try {
    s = JSON.parse(new TextDecoder().decode(signature));
  } catch {
    throw new Error("the signature is not a session signature");
  }
  const cert = s?.certificate;
  const keyType = cert?.session_key?.key_type;
  if (keyType !== "Ed25519" && keyType !== "Ed25519MlDsa65") throw new Error("a session key must be Ed25519 or Ed25519 with ML-DSA-65");
  const hybrid = keyType === "Ed25519MlDsa65";
  if (opts.hybridRecordsFromMs !== undefined && atMs >= opts.hybridRecordsFromMs && !hybrid) {
    throw new Error(`a record made at ${atMs} ms needs a hybrid session signature`);
  }
  if (!Number.isSafeInteger(cert.not_after_ms)) throw new Error("the certificate names no expiry");
  if (atMs > cert.not_after_ms) throw new Error(`the session certificate expired at ${cert.not_after_ms} ms, before ${atMs} ms`);
  const idp256 = fromHex(opts.identity.p256);
  const idpq = opts.identity.pq ? fromHex(opts.identity.pq) : undefined;
  const sk = bytesOf(cert.session_key.bytes, "the session key");
  const notAfter = new Uint8Array(8);
  new DataView(notAfter.buffer).setBigUint64(0, BigInt(cert.not_after_ms), true);
  const certMessage = concat(
    u32le(idp256.length),
    idp256,
    idpq ? concat(Uint8Array.of(1), u32le(idpq.length), idpq) : Uint8Array.of(0),
    Uint8Array.of(KEY_TYPE_TAGS[keyType]),
    u32le(sk.length),
    sk,
    notAfter,
  );
  if (!(await verifyComposite(opts.identity, certMessage, cert.signature))) throw new Error("the session certificate does not verify under the identity");
  if (!(await verifySessionKey(cert.session_key, body, s.signature))) throw new Error("the session signature does not verify");
  return hybrid;
}

async function leafHash(body: Uint8Array, signature: Uint8Array): Promise<Uint8Array> {
  return sha256(Uint8Array.of(0x00), u64le(body.length), body, signature);
}

function decode(body: Uint8Array, i: number) {
  try {
    return JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new Error(`entry ${i} is not an agent audit entry`);
  }
}

function record(e: any, leaf: string, hybrid: boolean): OpenShellRecord {
  const r: OpenShellRecord = {
    session_id: strip0x(String(e.session_id)).toLowerCase(),
    seq: e.seq,
    at_ms: e.at_ms,
    agent: e.agent,
    kind: e.kind,
    action: e.action,
    outcome: e.outcome,
    detail: e.detail,
    leaf,
    hybrid,
  };
  if (e.linked_tx !== undefined) r.linked_tx = e.linked_tx;
  if (e.image !== undefined) r.image = e.image;
  if (e.call !== undefined) r.call = e.call;
  return r;
}

/**
 * Verify a session from its entries alone, as the extensions' own verifier
 * does: every entry signed under a session key the identity certified,
 * numbered from 0 with no gap, of one session and one agent, each chained to
 * the leaf hash of the entry before it. Returns the entries and the MMR root.
 */
export async function verifyOpenShellSession(
  entries: OpenShellSignedEntry[],
  opts: OpenShellVerifyOptions,
): Promise<VerifiedOpenShellSession> {
  if (entries.length === 0) throw new Error("the session has no entries");
  let session = opts.sessionId ? strip0x(opts.sessionId).toLowerCase() : undefined;
  let agent: string | undefined;
  let prev = "00".repeat(32);
  const peaks: { h: number; hash: Uint8Array }[] = [];
  const out: OpenShellRecord[] = [];
  for (let i = 0; i < entries.length; i++) {
    const body = fromHex(entries[i].body);
    const signature = fromHex(entries[i].signature);
    const e = decode(body, i);
    let hybrid: boolean;
    try {
      hybrid = await verifyOpenShellSignature(body, signature, e.at_ms, opts);
    } catch (err) {
      throw new Error(`entry ${i}: ${(err as Error).message}`);
    }
    if (e.seq !== i) throw new Error(`entry ${i} is numbered ${e.seq}`);
    if (strip0x(String(e.prev)).toLowerCase() !== prev) throw new Error(`entry ${i} does not chain to the entry before it`);
    const sid = strip0x(String(e.session_id)).toLowerCase();
    session ??= sid;
    if (sid !== session) throw new Error(`entry ${i} names another session`);
    agent ??= e.agent;
    if (e.agent !== agent) throw new Error(`entry ${i} names another agent`);
    const leaf = await leafHash(body, signature);
    prev = toHex(leaf);
    let hash = leaf;
    let h = 0;
    while (peaks.length > 0 && peaks[peaks.length - 1].h === h) {
      hash = await nodeHash(peaks.pop()!.hash, hash);
      h++;
    }
    peaks.push({ h, hash });
    out.push(record(e, prev, hybrid));
  }
  return {
    session_id: session!,
    agent: agent!,
    count: out.length,
    root: toHex(await bagPeaks(peaks.map((p) => p.hash))),
    entries: out,
  };
}

/**
 * Verify the signed record a model call returns in `x-tenzro-receipt`
 * (base64url of the signed entry's JSON): its signature only, as one entry of
 * the agent's session.
 */
export async function verifyOpenShellReceipt(header: string, opts: Omit<OpenShellVerifyOptions, "sessionId">): Promise<OpenShellRecord> {
  const b64 = header.trim().replace(/-/g, "+").replace(/_/g, "/");
  const json = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0))));
  const [entry] = parseOpenShellEntries(JSON.stringify([json]));
  const body = fromHex(entry.body);
  const signature = fromHex(entry.signature);
  const e = decode(body, 0);
  const hybrid = await verifyOpenShellSignature(body, signature, e.at_ms, opts);
  return record(e, toHex(await leafHash(body, signature)), hybrid);
}

/** A payment the agent made, or was refused, in a session. */
export interface OpenShellPayment {
  seq: number;
  at_ms: number;
  /** `x402`, `mpp`, `ap2`, or `inference` for a model call's charge. */
  rail: string;
  /** The service URL for a payment, the model for an inference charge. */
  target: string;
  outcome: { status: string; reason?: string };
  /** The payment or settlement it is linked to; null when it was refused. */
  linked_tx: string | null;
}

/**
 * The payments of a verified session, in order: every `spend` entry (action
 * "<rail> <url>") and every model call that names the settlement of its charge.
 */
export function openShellPayments(session: VerifiedOpenShellSession): OpenShellPayment[] {
  const out: OpenShellPayment[] = [];
  for (const e of session.entries) {
    let rail: string;
    let target: string;
    if (e.kind === "spend") {
      const sp = e.action.indexOf(" ");
      if (sp <= 0) throw new Error(`entry ${e.seq} names no payment rail`);
      rail = e.action.slice(0, sp);
      target = e.action.slice(sp + 1);
    } else if (e.kind === "model_call" && e.linked_tx) {
      rail = "inference";
      target = e.action;
    } else {
      continue;
    }
    out.push({ seq: e.seq, at_ms: e.at_ms, rail, target, outcome: e.outcome, linked_tx: e.linked_tx ?? null });
  }
  return out;
}
