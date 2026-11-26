/**
 * The tools a Tenzro node's MCP server lists, checked against the node's
 * signature.
 *
 * A Tenzro node signs every `tools/list` answer with its machine identity
 * key: an ES256 JWS in the answer's `_meta` under
 * {@link TOOLS_SIGNATURE_META_KEY}, over the time it was signed, the node
 * release that listed the tools, and each tool's name, title, description,
 * input and output schema and annotations ordered by name, as RFC 8785
 * canonical JSON. The JWS `kid` is
 * `<machine DID>#hardware-key`, and the machine DID derives from the key the
 * protected header carries, so the check needs no lookup. A client that pins
 * tools (Tenzro Terms pin each tool by the digest of exactly those three
 * fields) learns here that the descriptions it pins came from that machine,
 * not from a relay that rewrote them.
 *
 * {@link listTools} refuses an unsigned list, a list whose signature fails,
 * a list signed by another machine than the one asked for, a list signed
 * longer ago than `maxAgeMs` and one from an older release than the caller
 * has seen, so a list signed before a description changed cannot be
 * replayed; `check: "unchecked"` is for MCP servers that are not Tenzro
 * nodes.
 */

/** The `_meta` key of a tool list's signature. */
export const TOOLS_SIGNATURE_META_KEY = "tenzro/tools-signature";

const PROTOCOL_VERSION = "2026-07-28";

/** How {@link listTools} checks what the server returns. */
export type ToolListCheck =
  /** A valid signature by a Tenzro machine identity key (the default). */
  | "tenzro-signed"
  /** No check: for MCP servers that are not Tenzro nodes. */
  | "unchecked"
  /** A valid signature by this machine DID. */
  | { signedBy: string };

/** A node signs its list again every hour; a day is the default limit. */
export const DEFAULT_TOOL_LIST_MAX_AGE_MS = 24 * 3600 * 1000;

/** How recent a signed list must be. */
export interface ToolListFreshness {
  /** Now, ms since the Unix epoch (default: the clock). */
  nowMs?: number;
  /** The oldest signature accepted, ms before now (default a day). */
  maxAgeMs?: number;
  /** The newest node release seen; a list from an older one is refused. Keep {@link ToolList.listVersion}. */
  seenVersion?: string;
}

/** A server's tools. */
export interface ToolList {
  /** The tools as the server listed them. */
  tools: Record<string, unknown>[];
  /** The machine DID whose key signed the list; null when it was not checked. */
  signedBy: string | null;
  /** When the list was signed, ms since the Unix epoch; null unchecked. */
  issuedAtMs: number | null;
  /** The node release that listed the tools; null unchecked. */
  listVersion: string | null;
}

/** What a valid signature says. */
export interface SignedToolList {
  machineDid: string;
  issuedAtMs: number;
  listVersion: string;
}

function olderRelease(a: string, b: string): boolean {
  const pa = a.split(".").map((p) => Number(p) || 0);
  const pb = b.split(".").map((p) => Number(p) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}

const enc = new TextEncoder();

function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  return Uint8Array.from(atob(pad), (c) => c.charCodeAt(0));
}

/** RFC 8785 canonical JSON: members ordered by key at every level, no whitespace. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** What a tool list's signature covers (see the module documentation). */
export function toolListSignedPayload(
  tools: Record<string, unknown>[],
  issuedAtMs: number,
  listVersion: string,
): string {
  const entries = tools.map((t) => {
    if (typeof t.name !== "string") throw new Error("a listed tool has no name");
    return {
      name: t.name,
      title: t.title ?? null,
      description: typeof t.description === "string" ? t.description : "",
      inputSchema: t.inputSchema ?? {},
      outputSchema: t.outputSchema ?? null,
      annotations: t.annotations ?? null,
    };
  });
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return canonical({ issuedAtMs, listVersion, tools: entries });
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

/** The machine DID of the uncompressed P-256 key `sec1`. */
export async function machineDidOfKey(sec1: Uint8Array): Promise<string> {
  const domain = enc.encode("tenzro/machine-did/device-key");
  const input = new Uint8Array(domain.length + 4 + sec1.length);
  input.set(domain, 0);
  new DataView(input.buffer).setUint32(domain.length, sec1.length, false);
  input.set(sec1, domain.length + 4);
  const digest = await sha256(input);
  return `did:tenzro:machine:${Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/**
 * Checks that `signed` (the `_meta` value `{protected, signature,
 * issuedAtMs, listVersion}`) verifies over `tools` and that its `kid` names
 * the machine DID its key derives.
 * @throws when the signature is malformed, does not verify, or names another machine
 */
export async function verifyToolList(
  tools: Record<string, unknown>[],
  signed: unknown,
): Promise<SignedToolList> {
  const s = signed as { protected?: unknown; signature?: unknown; issuedAtMs?: unknown; listVersion?: unknown };
  if (typeof s?.protected !== "string" || typeof s?.signature !== "string") {
    throw new Error("tool list signature: no protected header or signature");
  }
  if (!Number.isSafeInteger(s.issuedAtMs) || typeof s.listVersion !== "string") {
    throw new Error("tool list signature: no issuedAtMs or listVersion");
  }
  const issuedAtMs = s.issuedAtMs as number;
  const listVersion = s.listVersion;
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(s.protected)));
  if (header.alg !== "ES256" || header.jwk?.kty !== "EC" || header.jwk?.crv !== "P-256") {
    throw new Error("tool list signature: not an ES256 signature by a P-256 key");
  }
  const x = b64urlDecode(header.jwk.x);
  const y = b64urlDecode(header.jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new Error("tool list signature: jwk coordinates are not 32 bytes");
  const sec1 = new Uint8Array(65);
  sec1[0] = 0x04;
  sec1.set(x, 1);
  sec1.set(y, 33);
  const key = await crypto.subtle.importKey(
    "raw",
    sec1 as BufferSource,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const input = enc.encode(
    `${s.protected}.${b64urlEncode(enc.encode(toolListSignedPayload(tools, issuedAtMs, listVersion)))}`,
  );
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    b64urlDecode(s.signature) as BufferSource,
    input as BufferSource,
  );
  if (!ok) throw new Error("tool list signature: it does not verify over the listed tools");
  const did = await machineDidOfKey(sec1);
  if (header.kid !== `${did}#hardware-key`) {
    throw new Error(`tool list signature: its kid ${header.kid} is not the machine DID its key derives`);
  }
  return { machineDid: did, issuedAtMs, listVersion };
}

/**
 * `result`, a `tools/list` result, checked as `check` and `freshness` say.
 * @throws when the check fails
 */
export async function checkToolList(
  result: unknown,
  check: ToolListCheck = "tenzro-signed",
  freshness: ToolListFreshness = {},
): Promise<ToolList> {
  const r = result as { tools?: unknown; _meta?: Record<string, unknown> };
  if (!Array.isArray(r?.tools)) throw new Error("the tools/list result has no tools");
  const tools = r.tools as Record<string, unknown>[];
  if (check === "unchecked") return { tools, signedBy: null, issuedAtMs: null, listVersion: null };
  const signature = r._meta?.[TOOLS_SIGNATURE_META_KEY];
  if (signature === undefined) {
    throw new Error(
      'the tool list carries no Tenzro signature (pass check: "unchecked" for a server that is not a Tenzro node)',
    );
  }
  const signed = await verifyToolList(tools, signature);
  if (typeof check === "object" && check.signedBy !== signed.machineDid) {
    throw new Error(`the tool list is signed by ${signed.machineDid}, not ${check.signedBy}`);
  }
  const now = freshness.nowMs ?? Date.now();
  const maxAge = freshness.maxAgeMs ?? DEFAULT_TOOL_LIST_MAX_AGE_MS;
  if (now - signed.issuedAtMs > maxAge) {
    throw new Error(`the tool list was signed at ${signed.issuedAtMs} ms, longer ago than ${maxAge} ms`);
  }
  if (freshness.seenVersion !== undefined && olderRelease(signed.listVersion, freshness.seenVersion)) {
    throw new Error(
      `the tool list is from release ${signed.listVersion}, older than ${freshness.seenVersion} already seen`,
    );
  }
  return { tools, signedBy: signed.machineDid, issuedAtMs: signed.issuedAtMs, listVersion: signed.listVersion };
}

/**
 * The tools the MCP server at `mcpUrl` (its Streamable HTTP endpoint, such as
 * `https://mcp.tenzro.com/mcp`) lists, checked as `check` says.
 * @param mcpUrl - The server's MCP endpoint
 * @param check - How the list is checked; a Tenzro signature by default
 * @param freshness - How recent the signature must be, and the newest release seen
 * @returns `{ tools, signedBy, issuedAtMs, listVersion }`
 * @throws when the request fails or the check fails
 */
export async function listTools(
  mcpUrl: string,
  check: ToolListCheck = "tenzro-signed",
  freshness: ToolListFreshness = {},
): Promise<ToolList> {
  const response = await fetch(mcpUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": PROTOCOL_VERSION,
      "Mcp-Method": "tools/list",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
          "io.modelcontextprotocol/clientInfo": { name: "tenzro-ts-sdk", version: "0" },
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
  if (!response.ok) throw new Error(`${mcpUrl}: HTTP ${response.status}`);
  const answer = (await response.json()) as { result?: unknown; error?: unknown };
  if (answer.error !== undefined) throw new Error(`${mcpUrl}: ${JSON.stringify(answer.error)}`);
  return checkToolList(answer.result, check, freshness);
}
