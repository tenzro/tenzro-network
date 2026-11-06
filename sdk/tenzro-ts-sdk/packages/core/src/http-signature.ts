/**
 * Verify the RFC 9421 HTTP message signature a Tenzro agent puts on the
 * requests it sends.
 *
 * The node serving an agent signs each outbound request with the agent's
 * hardware-held P-256 key in the Web Bot Auth profile
 * (`alg="ecdsa-p256-sha256"`, label `tenzro`, tag `web-bot-auth`). The
 * signature covers the request line, the body's `Content-Digest`, the
 * `Signature-Agent` header (the agent's key directory, which every node
 * derives from the agent's terms in consensus state), the `Tenzro-Agent`
 * header (the agent's DID) and the `Tenzro-Mandate` header (the approval
 * digest of the terms it acts under).
 *
 * A server checks a request in two steps: read the `keyid` and agent with
 * {@link agentKeyOf}, resolve them from chain state with
 * `AgentClient.resolveAgentKey` (or read the directory
 * `Signature-Agent` names), then call {@link verifyAgentRequest}.
 */

/** What chain state says about an agent's signing key (`tenzro_resolveAgentKey`). */
export interface AgentKeyResolution {
  agent_did: string;
  root: string;
  keyid: string;
  /** P-256 `x || y`, hex. */
  public_key: string;
  machine_did: string;
  key_certification: string;
  /** Approval digest of the terms in force, hex. */
  mandate: string;
  terms_version: number;
  expires_at_ms: number | null;
  revoked: boolean;
  quarantined: boolean;
}

/** An HTTP request as the verifier received it. Header names are case-insensitive. */
export interface SignedHttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array | string;
}

export interface VerifiedAgentRequest {
  agent_did: string;
  root: string;
  mandate: string;
  created: number;
}

export const AGENT_SIGNATURE_LABEL = "tenzro";
export const AGENT_SIGNATURE_TAG = "web-bot-auth";
export const SIGNATURE_AGENT_HEADER = "signature-agent";
export const MAX_SIGNATURE_LIFETIME_SECS = 300;
const CLOCK_SKEW_SECS = 30;
const REQUIRED = ["@method", "@authority", "@path", "signature-agent", "tenzro-agent", "tenzro-mandate"];

interface ParsedInput {
  components: string[];
  params: Record<string, string>;
  raw: string;
}

function lower(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

function parseInput(header: string): ParsedInput {
  const prefix = `${AGENT_SIGNATURE_LABEL}=`;
  if (!header.startsWith(prefix)) throw new Error("not a Tenzro agent signature");
  const raw = header.slice(prefix.length);
  const close = raw.indexOf(")");
  if (!raw.startsWith("(") || close < 0) throw new Error("malformed Signature-Input");
  const components = raw
    .slice(1, close)
    .split(" ")
    .filter((c) => c.length > 0)
    .map((c) => c.replace(/^"|"$/g, ""));
  const params: Record<string, string> = {};
  for (const part of raw.slice(close + 1).split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0) params[part.slice(0, eq).trim()] = part.slice(eq + 1).trim().replace(/^"|"$/g, "");
  }
  return { components, params, raw };
}

function toBytes(body: Uint8Array | string): Uint8Array {
  return typeof body === "string" ? new TextEncoder().encode(body) : body;
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new Error("not hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** `Content-Digest` value of a body (RFC 9530, SHA-256). */
export async function contentDigest(body: Uint8Array | string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toBytes(body) as BufferSource));
  return `sha-256=:${b64(digest)}:`;
}

function canonical(value: string): string {
  return value.replace(/[\r\n\t ]+/g, " ").trim();
}

function componentValue(name: string, url: URL, method: string, headers: Record<string, string>): string {
  switch (name) {
    case "@method":
      return method.toUpperCase();
    case "@authority":
      return url.host.toLowerCase();
    case "@path":
      return url.pathname;
    case "@query":
      return url.search.length > 1 ? url.search : "?";
    case "@scheme":
      return url.protocol.replace(":", "").toLowerCase();
    default: {
      const v = headers[name];
      if (v === undefined) throw new Error(`missing header: ${name}`);
      return canonical(v);
    }
  }
}

/** The `keyid` and agent DID a signed request names, to resolve before verifying. */
export function agentKeyOf(request: SignedHttpRequest): { keyid: string; agent_did: string } {
  const headers = lower(request.headers);
  const input = headers["signature-input"];
  const agent = headers["tenzro-agent"];
  if (!input || !agent) throw new Error("not a Tenzro agent request");
  const keyid = parseInput(input).params.keyid;
  if (!keyid) throw new Error("no keyid");
  return { keyid, agent_did: agent };
}

/**
 * Check a request a Tenzro agent signed against what chain state says about
 * its key. `now` is the verifier's clock, unix seconds. Replay protection
 * beyond the signature's short lifetime is the caller's: remember the
 * nonce until `expires`. Throws on any failure.
 */
export async function verifyAgentRequest(
  request: SignedHttpRequest,
  resolution: AgentKeyResolution,
  now: number = Math.floor(Date.now() / 1000),
): Promise<VerifiedAgentRequest> {
  const headers = lower(request.headers);
  const need = (name: string): string => {
    const v = headers[name];
    if (v === undefined) throw new Error(`no ${name} header`);
    return v;
  };
  const input = parseInput(need("signature-input"));
  if (input.params.tag !== AGENT_SIGNATURE_TAG) throw new Error("not a web-bot-auth agent signature");
  const directory = need(SIGNATURE_AGENT_HEADER);
  if (!directory.startsWith('"https://') || !directory.endsWith('"')) {
    throw new Error("Signature-Agent does not name an https directory");
  }
  if (input.params.alg !== "ecdsa-p256-sha256") throw new Error("an agent signature is ecdsa-p256-sha256");
  for (const c of REQUIRED) {
    if (!input.components.includes(c)) throw new Error(`the signature does not cover ${c}`);
  }
  const url = new URL(request.url);
  if (url.search.length > 1 && !input.components.includes("@query")) {
    throw new Error("the signature does not cover the query");
  }
  const body = request.body === undefined ? undefined : toBytes(request.body);
  if (body && body.length > 0) {
    if (!input.components.includes("content-digest")) throw new Error("the signature does not cover the body");
    if (need("content-digest") !== (await contentDigest(body))) {
      throw new Error("the body does not match its Content-Digest");
    }
  }
  const created = Number(input.params.created);
  const expires = Number(input.params.expires);
  if (!Number.isInteger(created) || !Number.isInteger(expires)) throw new Error("no created or expires");
  if (expires < created || expires - created > MAX_SIGNATURE_LIFETIME_SECS) {
    throw new Error("the signature's lifetime is too long");
  }
  if (created > now + CLOCK_SKEW_SECS || now > expires) throw new Error("the signature is not valid now");
  if (input.params.keyid !== resolution.keyid) throw new Error("the key the signature names is not the resolved key");
  if (need("tenzro-agent") !== resolution.agent_did) {
    throw new Error("the key does not belong to the agent the request names");
  }
  if (resolution.revoked) throw new Error("the agent's controller revoked it");
  if (resolution.quarantined) throw new Error("the agent is quarantined");
  if (resolution.expires_at_ms !== null && now * 1000 > resolution.expires_at_ms) {
    throw new Error("the agent's terms have expired");
  }
  if (need("tenzro-mandate").toLowerCase() !== resolution.mandate.toLowerCase()) {
    throw new Error("the request was made under terms no longer in force");
  }

  const lines = input.components.map(
    (c) => `"${c}": ${componentValue(c, url, request.method, headers)}`,
  );
  lines.push(`"@signature-params": ${input.raw}`);
  const base = new TextEncoder().encode(lines.join("\n"));

  const sigHeader = need("signature");
  const m = sigHeader.match(/^tenzro=:([A-Za-z0-9+/=]+):$/);
  if (!m) throw new Error("malformed Signature header");
  const xy = fromHex(resolution.public_key);
  const sec1 = new Uint8Array(65);
  sec1[0] = 0x04;
  sec1.set(xy, 1);
  const key = await crypto.subtle.importKey(
    "raw",
    sec1 as BufferSource,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    fromB64(m[1]) as BufferSource,
    base as BufferSource,
  );
  if (!ok) throw new Error("the signature does not verify");
  return { agent_did: resolution.agent_did, root: resolution.root, mandate: resolution.mandate, created };
}
