/**
 * Discover and call any method a Tenzro node serves.
 *
 * The typed clients elsewhere in this SDK cover the surfaces worth a dedicated,
 * documented signature — wallets, inference, storage, databases. This covers
 * everything else.
 *
 * It exists because the alternative does not work. A node serves several hundred JSON-RPC
 * methods and gains more with each release; an SDK that hand-wraps them is
 * always some months behind the node it is talking to, and the developer who
 * hits that gap discovers it at the moment they need the method. Here the
 * method list comes *from the node*, so a newer node simply reports more.
 *
 * Authorization is unchanged. A call through this gateway runs behind the same
 * access policy and default-deny classification as any other call — it
 * reaches exactly what your access token already allows.
 */

import { RpcClient } from "./rpc";

/** How a method is gated. */
export type GateClass = "admin" | "owner" | "open" | "reserved";

/** One method in the node's directory. */
export interface MethodEntry {
  /** The JSON-RPC method name. */
  method: string;
  /** How the dispatcher classifies it. */
  gate: GateClass;
  /** The method class the node's access policy decides it under. */
  class: string;
  /** The method's namespace, for grouping. */
  namespace: string;
}

/** The node's method directory. */
export interface MethodDirectory {
  /** Matching methods. */
  methods: MethodEntry[];
  /** How many matched. */
  count: number;
  /** How many the node serves in total, before filtering. */
  total: number;
  /** Every namespace the node has, so a caller can narrow a second query. */
  namespaces: string[];
}

/** Options for {@link GatewayClient.methods}. */
export interface MethodQuery {
  /** Restrict to one namespace. */
  namespace?: string;
  /** Case-insensitive substring of the method name. */
  contains?: string;
}

/** Discover and call any method. */
export class GatewayClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Every method this node serves, with how each is gated.
   *
   * @example
   * ```ts
   * const dir = await client.gateway.methods({ contains: "forecast" });
   * for (const m of dir.methods) console.log(m.method, m.gate);
   * ```
   */
  async methods(query: MethodQuery = {}): Promise<MethodDirectory> {
    return this.rpc.call("tenzro_listRpcMethods", [query]);
  }

  /**
   * Whether this node serves `method`.
   *
   * Asks the node rather than consulting a list compiled into this package, so
   * it stays correct against a node newer than the SDK.
   */
  async supports(method: string): Promise<boolean> {
    const dir = await this.methods({ contains: method });
    return dir.methods.some((m) => m.method === method);
  }

  /**
   * Call any method by name.
   *
   * @example
   * ```ts
   * const plan = await client.gateway.call("tenzro_previewServe", {
   *   model_id: "qwen3-0.6b",
   * });
   * ```
   */
  async call<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
  ): Promise<T> {
    // Wrapped in the positional array the node normalizes back to named
    // params, matching every other call in this package.
    return this.rpc.call<T>(method, [params]);
  }
}
