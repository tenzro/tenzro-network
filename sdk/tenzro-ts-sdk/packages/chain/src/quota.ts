import { RpcClient } from "@tenzro/core";

/**
 * Client for node-level quota and resource-pressure queries.
 *
 * Surfaces the prioritised mempool
 * lanes, per-account contention from the hot-state subsystem,
 * and the data-availability backend registry. All endpoints are
 * read-only.
 */
export class QuotaClient {
  constructor(private rpc: RpcClient) {}

  /**
   * Returns aggregate mempool statistics across all lanes.
   * @returns Mempool stats snapshot
   */
  async getMempoolStats(): Promise<any> {
    return this.rpc.call("tenzro_getMempoolStats", []);
  }

  /**
   * The admission lane an account's transactions enter and its rate-limit
   * bucket: lane, fee floor multiplier, capacity, refill rate and tokens left.
   * @param address - Account address, hex
   * @returns Lane snapshot
   */
  async getMempoolLane(address: string): Promise<any> {
    return this.rpc.call("tenzro_getMempoolLane", { address });
  }

  /**
   * Returns the hot-state contention score for a single account.
   * Used by parallel-execution scheduling and
   * fee-market congestion signals.
   * @param address - Account address
   * @returns Contention metrics
   */
  async getAccountContention(address: string): Promise<any> {
    return this.rpc.call("tenzro_getAccountContention", { address });
  }

  /**
   * List the registered data-availability backends (EigenDA, Celestia,
   * Avail, inline) and their current health.
   * @returns Array of DA backend descriptors
   */
  async getDaBackends(): Promise<any[]> {
    return this.rpc.call<any[]>("tenzro_getDaBackends", []);
  }

  /**
   * Verify that the payload referenced by a `DaPointer` is currently
   * available on its backing DA backend.
   * @param pointer - The `DaPointer` (backend, namespace, locator,
   *   commitment_kzg, attestation_root)
   * @returns Verification result
   */
  async verifyDaPointer(pointer: Record<string, unknown>): Promise<any> {
    return this.rpc.call("tenzro_verifyDaPointer", { pointer });
  }
}
