import { TenzroClient } from "./client";
import type { RpcTransport } from "@tenzro/core";
import { NETWORK_SEEDS, PREVIEW_NETWORK, parseExact } from "@tenzro/core";
import { RpcCallError } from "@tenzro/core";
import type { RoleEndpoints } from "@tenzro/chain";

/** How to find and check the network's RPC operators. */
export interface NetworkOptions {
  /**
   * URLs to ask for the operator list first. Any node of the network will do:
   * every node answers the same list from consensus state, so a seed is only
   * a way in, never an authority.
   */
  seeds: string[];
  /** The chain every endpoint must report (`eth_chainId`). */
  chainId: number;
  /** Role whose operators to use. Default `rpc`. */
  role?: string;
  /** Per-request timeout, ms. Default 10000. */
  timeout?: number;
}

/** The preview network's seeds and chain id, the default for {@link connectToNetwork}. */
export const DEFAULT_NETWORK: NetworkOptions = { seeds: [...NETWORK_SEEDS], chainId: PREVIEW_NETWORK.chainId };

/** An endpoint that passed the checks, with the checkpoint it agreed on. */
export interface CheckedEndpoint {
  url: string;
  /** The staking account, when the endpoint came from the on-chain list. */
  account?: string;
  /** The checkpoint index the endpoints were compared at. */
  checkpointIndex?: number;
  /** That checkpoint's digest, as this endpoint reported it. */
  checkpointDigest?: string;
}

async function post<T>(url: string, method: string, params: unknown, timeout: number): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`${url}: HTTP ${response.status}`);
    }
    const json = parseExact(await response.text()) as { result?: T; error?: { code: number; message: string; data?: unknown } };
    if (json.error) {
      throw new RpcCallError(json.error.code, json.error.message, json.error.data);
    }
    return json.result as T;
  } finally {
    clearTimeout(timer);
  }
}

function majority<T>(items: T[], key: (t: T) => string): T[] {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    groups.set(k, [...(groups.get(k) ?? []), item]);
  }
  let best: T[] = [];
  for (const group of groups.values()) {
    if (group.length > best.length) best = group;
  }
  return best;
}

/**
 * Find the network's staked operators of a role and keep those that answer
 * for the expected chain and agree on its history.
 *
 * 1. Every seed is asked for `tenzro_listRoleEndpoints`; the lists are merged.
 * 2. Each candidate (and each seed) must report `chainId`.
 * 3. Each reports its latest checkpoint; all are compared at the lowest
 *    index they all hold, and only those reporting the most common digest
 *    there are kept. An endpoint serving a different history is dropped
 *    instead of trusted.
 *
 * Returns the endpoints most bonded first, seeds last. Throws when none passes.
 */
export async function discoverEndpoints(options: NetworkOptions = DEFAULT_NETWORK): Promise<CheckedEndpoint[]> {
  const timeout = options.timeout ?? 10000;
  const role = options.role ?? "rpc";
  const candidates = new Map<string, CheckedEndpoint>();
  for (const seed of options.seeds) {
    try {
      const list = await post<RoleEndpoints>(seed, "tenzro_listRoleEndpoints", { role }, timeout);
      for (const e of list.endpoints) {
        if (!candidates.has(e.url)) candidates.set(e.url, { url: e.url, account: e.account });
      }
    } catch {
      // An unreachable seed is skipped; another seed or the list itself covers it.
    }
  }
  for (const seed of options.seeds) {
    if (!candidates.has(seed)) candidates.set(seed, { url: seed });
  }

  const expected = `0x${options.chainId.toString(16)}`;
  const onChain: Array<CheckedEndpoint & { latest: number }> = [];
  await Promise.all(
    [...candidates.values()].map(async (c) => {
      try {
        const chain = await post<string>(c.url, "eth_chainId", [], timeout);
        if (chain.toLowerCase() !== expected) return;
        const latest = await post<{ index: number }>(c.url, "tenzro_getCheckpointCertificate", {}, timeout);
        onChain.push({ ...c, latest: Number(latest.index) });
      } catch {
        // Unreachable or not serving the chain: not a candidate.
      }
    }),
  );
  if (onChain.length === 0) {
    throw new Error(`no endpoint answered for chain ${options.chainId}`);
  }

  const index = Math.min(...onChain.map((c) => c.latest));
  const compared: CheckedEndpoint[] = [];
  await Promise.all(
    onChain.map(async (c) => {
      try {
        const cert = await post<{ digest: string }>(c.url, "tenzro_getCheckpointCertificate", { index }, timeout);
        compared.push({ url: c.url, account: c.account, checkpointIndex: index, checkpointDigest: cert.digest });
      } catch {
        // No certificate at the shared index: it cannot be compared, so it is not kept.
      }
    }),
  );
  const agreed = majority(compared, (c) => c.checkpointDigest ?? "");
  if (agreed.length === 0) {
    throw new Error(`no endpoint could be compared at checkpoint ${index}`);
  }
  const order = [...candidates.keys()];
  return agreed.sort((a, b) => order.indexOf(a.url) - order.indexOf(b.url));
}

/**
 * A transport over several endpoints: each call goes to the current one and
 * moves to the next when it cannot be reached, times out or answers with an
 * HTTP error. A JSON-RPC error is the node's answer and is returned as is.
 * It carries no access credential, so it serves open methods and signed
 * transactions, which every operator accepts on their own signature.
 */
export class FailoverTransport implements RpcTransport {
  private current = 0;

  constructor(
    private readonly endpoints: string[],
    private readonly timeout: number = 30000,
  ) {
    if (endpoints.length === 0) {
      throw new Error("FailoverTransport needs at least one endpoint");
    }
  }

  /** The endpoint calls go to now. */
  get endpoint(): string {
    return this.endpoints[this.current];
  }

  async call<T>(method: string, params: unknown[] | Record<string, unknown> = []): Promise<T> {
    let lastError: unknown;
    for (let tried = 0; tried < this.endpoints.length; tried++) {
      const url = this.endpoints[this.current];
      try {
        return await post<T>(url, method, params, this.timeout);
      } catch (error) {
        if (error instanceof RpcCallError) throw error;
        lastError = error;
        this.current = (this.current + 1) % this.endpoints.length;
      }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError));
  }
}

/**
 * A client for the network rather than for one node: it discovers the staked
 * RPC operators on chain, keeps those that agree on the chain's history, and
 * fails over between them.
 */
export async function connectToNetwork(options: NetworkOptions = DEFAULT_NETWORK): Promise<TenzroClient> {
  const endpoints = await discoverEndpoints(options);
  const transport = new FailoverTransport(
    endpoints.map((e) => e.url),
    options.timeout ?? 30000,
  );
  return new TenzroClient({ endpoint: transport.endpoint, chainId: options.chainId, timeout: options.timeout }, transport);
}
