import { ApiError } from "./errors";
import type { AccessCredential, DpopProver } from "./access";
import { parseExact, stringifyExact } from "./exact-json";

export interface RpcResponse<T = unknown> {
  jsonrpc: "2.0";
  result?: T;
  error?: RpcError;
  id: number;
}

export interface RpcError {
  code: number;
  message: string;
  data?: unknown;
}

/** Header carrying the A2A protocol version on every A2A request. */
export const A2A_VERSION_HEADER = "A2A-Version";
/** A2A protocol version this SDK speaks (`Major.Minor`). */
export const A2A_PROTOCOL_VERSION = "1.0";
/** Well-known path of a public A2A agent card. */
export const A2A_AGENT_CARD_PATH = "/.well-known/agent-card.json";

/** Unwrap an A2A JSON-RPC response envelope into its `result`. */
export function decodeA2aEnvelope<T>(envelope: unknown): T {
  const env = envelope as { result?: unknown; error?: RpcError | null };
  if (env.error) {
    throw new Error(`A2A error ${env.error.code}: ${env.error.message}`);
  }
  if (env.result === undefined) {
    throw new Error("A2A response carries no result");
  }
  return env.result as T;
}

/**
 * Pluggable transport for JSON-RPC calls.
 *
 * The default transport `fetch`es the configured endpoint with the
 * usual `Content-Type: application/json` body. Browser-extension dApps
 * can supply an EIP-1193 provider instead — `provider.request({method,
 * params})` then handles auth (DPoP, session), routing, and user
 * confirmation, and the SDK never touches a private key or token.
 */
export interface RpcTransport {
  call<T>(method: string, params: unknown[] | Record<string, unknown>): Promise<T>;
}

/**
 * Adapter that turns an EIP-1193 provider into an `RpcTransport`. Used
 * by `TenzroClient.fromInjected()` and any direct consumer that wants
 * to route SDK calls through `window.tenzro` rather than a network
 * endpoint.
 */
export class Eip1193Transport implements RpcTransport {
  constructor(
    private readonly provider: {
      request<T = unknown>(args: {
        method: string;
        params?: readonly unknown[] | Record<string, unknown>;
      }): Promise<T>;
    },
  ) {}

  async call<T>(method: string, params: unknown[] | Record<string, unknown> = []): Promise<T> {
    return this.provider.request<T>({ method, params });
  }
}

/**
 * JSON-RPC and HTTP client for one node.
 *
 * A client carries at most one access credential, presented with a fresh DPoP
 * proof on every request it makes. A caller signed in as several DIDs builds
 * one client per DID. Without one, `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF`
 * are forwarded where a process environment exists.
 */
export class RpcClient {
  private endpoint: string;
  private apiEndpoint: string;
  private timeout: number;
  private requestId: number = 0;
  private readonly transport: RpcTransport | undefined;
  private readonly credential: AccessCredential | undefined;

  constructor(
    endpoint: string,
    apiEndpoint?: string,
    timeout: number = 30000,
    transport?: RpcTransport,
    credential?: AccessCredential,
  ) {
    this.endpoint = endpoint;
    this.timeout = timeout;
    this.transport = transport;
    this.credential = credential;

    // Derive API endpoint from RPC endpoint if not provided
    if (apiEndpoint) {
      this.apiEndpoint = apiEndpoint;
    } else if (endpoint.includes("localhost:8545") || endpoint.includes("127.0.0.1:8545")) {
      this.apiEndpoint = endpoint.replace("8545", "8080");
    } else {
      // Default: assume API endpoint is the same as RPC endpoint
      this.apiEndpoint = endpoint;
    }
  }

  async call<T>(method: string, params: unknown[] | Record<string, unknown> = []): Promise<T> {
    // Injected-provider path: the extension owns auth + routing.
    if (this.transport) {
      return this.transport.call<T>(method, params);
    }
    return this.send<T>(method, params, await this.authHeaders("POST", this.endpoint));
  }

  /**
   * Call `method` proving possession of `prover`'s key with a DPoP proof and
   * no access token, as a token endpoint is called (`tenzro_refreshToken`).
   */
  async callWithProof<T>(
    method: string,
    params: Record<string, unknown>,
    prover: DpopProver,
  ): Promise<T> {
    if (this.transport) {
      throw new Error(`${method} needs a DPoP proof the injected provider cannot carry`);
    }
    return this.send<T>(method, params, {
      DPoP: await prover.proof("POST", dpopHtu(this.endpoint), ""),
    });
  }

  private async send<T>(
    method: string,
    params: unknown[] | Record<string, unknown>,
    auth: Record<string, string>,
  ): Promise<T> {

    // Use modular arithmetic to prevent overflow beyond Number.MAX_SAFE_INTEGER
    this.requestId = (this.requestId + 1) % Number.MAX_SAFE_INTEGER;
    const id = this.requestId;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...auth,
    };

    try {
      const response = await fetch(this.endpoint, {
        method: "POST",
        headers,
        // Exact: a bigint (an amount above 2^53) is written as an integer literal.
        body: stringifyExact({ jsonrpc: "2.0", method, params, id }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`RPC HTTP error: ${response.status} ${response.statusText}`);
      }

      const json = parseExact(await response.text()) as RpcResponse<T>;

      if (json.error) {
        throw new RpcCallError(json.error.code, json.error.message, json.error.data);
      }

      return json.result as T;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`RPC request timed out after ${this.timeout}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * POST a streamed body to a realtime route on the RPC listener and yield the server-sent events it answers with,
   * as they arrive. The body is sent while it is produced (HTTP/2 or a runtime that streams request bodies).
   */
  async *streamRoute(
    path: string,
    body: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
  ): AsyncGenerator<{ event: string; data: unknown }> {
    const url = `${this.endpoint.replace(/\/$/, "")}${path}`;
    const source = body;
    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        for await (const chunk of source) controller.enqueue(chunk);
        controller.close();
      },
    });
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-ndjson", ...(await this.authHeaders("POST", url)) },
      body: stream,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    if (!response.ok || !response.body) {
      throw new Error(`${path}: HTTP ${response.status} ${response.statusText}`);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let pending = "";
    let event = "message";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      pending += decoder.decode(value, { stream: true });
      let nl: number;
      while ((nl = pending.indexOf("\n")) >= 0) {
        const line = pending.slice(0, nl).replace(/\r$/, "");
        pending = pending.slice(nl + 1);
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) yield { event, data: parseExact(line.slice(5).trim()) };
      }
    }
  }

  async get<T>(path: string): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.apiEndpoint}${path}`, {
        method: "GET",
        headers: { Accept: "application/json", ...(await this.authHeaders("GET", `${this.apiEndpoint}${path}`)) },
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return parseExact(await response.text()) as T;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Request timed out after ${this.timeout}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    return this.postWithHeaders<T>(path, body, {});
  }

  /**
   * Call an A2A v1.0 JSON-RPC method on the node's `/a2a` endpoint.
   * Sends the `A2A-Version` header the protocol requires on every request
   * and unwraps the JSON-RPC envelope (an `error` member throws).
   */
  async a2aCall<T>(method: string, params: Record<string, unknown>): Promise<T> {
    const envelope = await this.postWithHeaders<unknown>(
      "/a2a",
      { jsonrpc: "2.0", id: 1, method, params },
      { [A2A_VERSION_HEADER]: A2A_PROTOCOL_VERSION },
    );
    return decodeA2aEnvelope<T>(envelope);
  }

  private async postWithHeaders<T>(
    path: string,
    body: unknown,
    extraHeaders: Record<string, string>,
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.apiEndpoint}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...(await this.authHeaders("POST", `${this.apiEndpoint}${path}`)),
          ...extraHeaders,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return parseExact(await response.text()) as T;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Request timed out after ${this.timeout}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * POST to the Web API where the node replies `204 No Content` (empty
   * body). Parsing `response.json()` on an empty body would throw, so
   * this variant only checks the status.
   */
  async postNoContent(path: string, body: unknown): Promise<void> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.apiEndpoint}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...(await this.authHeaders("POST", `${this.apiEndpoint}${path}`)),
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Request timed out after ${this.timeout}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Authenticated POST to the Web API. The `/wallet/*` endpoints
   * require a fresh DPoP proof per request that signs over the exact
   * `(method, htu)` pair — only the wallet kernel can produce that
   * proof, so the SDK accepts both the bearer JWT and the proof as
   * explicit arguments instead of reading them from ambient env.
   */
  async postWithAuth<T>(
    path: string,
    body: unknown,
    bearerJwt: string,
    dpopProof: string,
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.apiEndpoint}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `DPoP ${bearerJwt}`,
          DPoP: dpopProof,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return parseExact(await response.text()) as T;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Request timed out after ${this.timeout}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** Authenticated GET counterpart to {@link postWithAuth}. */
  async getWithAuth<T>(
    path: string,
    bearerJwt: string,
    dpopProof: string,
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.apiEndpoint}${path}`, {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: `DPoP ${bearerJwt}`,
          DPoP: dpopProof,
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return parseExact(await response.text()) as T;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Request timed out after ${this.timeout}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * POST a JSON body to `path` on the node's RPC origin and hand back the
   * response unread, for callers that consume a streamed body. A non-2xx
   * status throws the node's `{"error":{..}}` as {@link ApiError} when the
   * body carries one. No timeout applies: a stream legitimately outlives it,
   * so cancellation is the caller's `signal`.
   */
  async postStream(path: string, body: unknown, signal?: AbortSignal): Promise<Response> {
    const response = await fetch(`${this.endpoint.replace(/\/$/, "")}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "text/event-stream",
        ...(await this.authHeaders("POST", `${this.endpoint.replace(/\/$/, "")}${path}`)),
      },
      body: JSON.stringify(body),
      signal,
    });
    if (response.ok) return response;
    const payload: unknown = await response.text().then(parseExact).catch(() => undefined);
    throw ApiError.fromBody(payload) ?? new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  /**
   * The access token and a DPoP proof for one request: the client's
   * credential, else `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF`.
   */
  private async authHeaders(htm: string, htu: string): Promise<Record<string, string>> {
    const headers: Record<string, string> = {};
    if (this.credential) {
      const { token, prover } = this.credential;
      headers["Authorization"] = `DPoP ${token}`;
      headers["DPoP"] = await prover.proof(htm, dpopHtu(htu), token);
      return headers;
    }
    const env = processEnv();
    const bearer = env?.TENZRO_BEARER_JWT;
    if (bearer && bearer.length > 0) headers["Authorization"] = `DPoP ${bearer}`;
    const dpop = env?.TENZRO_DPOP_PROOF;
    if (dpop && dpop.length > 0) headers["DPoP"] = dpop;
    return headers;
  }

  getEndpoint(): string {
    return this.endpoint;
  }

  getApiEndpoint(): string {
    return this.apiEndpoint;
  }
}

/**
 * A JSON-RPC error the node answered with: its `code`, message and `data`.
 * -32602 is invalid params, -32601 an unknown method, -32004 a resource or
 * capability this node does not have.
 */
export class RpcCallError extends Error {
  constructor(public code: number, message: string, public data?: unknown) {
    super(`RPC Error ${code}: ${message}`);
    this.name = "RpcCallError";
  }

  /**
   * True when the node is the light build of tenzro-node, which runs no
   * model: it refuses a call that needs a local model with code -32004 and
   * `data.build === "light"`. Send such a call to a provider node instead.
   */
  get isLightBuild(): boolean {
    const d = this.data as { build?: unknown } | null | undefined;
    return this.code === -32004 && typeof d === "object" && d !== null && d.build === "light";
  }
}

/** The process environment where one exists (Node), else `undefined`. */
function processEnv(): Record<string, string | undefined> | undefined {
  const proc = (globalThis as unknown as {
    process?: { env?: Record<string, string | undefined> };
  }).process;
  return proc && proc.env ? proc.env : undefined;
}

/**
 * The `htu` a DPoP proof names for `url` (RFC 9449 section 4.3): scheme, authority and path, without query or
 * fragment, normalized as RFC 3986 section 6.2.3 does, so an endpoint given as `http://host:port` proves the same
 * URI as `http://host:port/`, the one the node checks against.
 */
export function dpopHtu(url: string): string {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
}

/**
 * Parse a hex quantity, `0x`-prefixed or bare. Anything else, or a value past
 * `Number.MAX_SAFE_INTEGER`, throws.
 */
export function parseQuantity(value: unknown): number {
  if (typeof value !== "string" || !/^(0x)?[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`${JSON.stringify(value)} is not a hex quantity`);
  }
  const n = BigInt(value.startsWith("0x") ? value : "0x" + value);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${value} is past the largest exact number`);
  }
  return Number(n);
}

/**
 * Read a hex quantity (a nonce, the chain id) from the node. An RPC failure or
 * an answer that is not a hex quantity throws, naming the endpoint; no default
 * stands in for it.
 */
export async function readQuantity(
  rpc: RpcClient,
  method: string,
  params: unknown[],
  what: string,
): Promise<number> {
  try {
    return parseQuantity(await rpc.call<unknown>(method, params));
  } catch (e) {
    const at = typeof rpc.getEndpoint === "function" ? rpc.getEndpoint() : "the RPC endpoint";
    const cause = e instanceof Error ? e.message : String(e);
    throw new Error(`could not read the ${what} from ${at}: ${cause}`);
  }
}
