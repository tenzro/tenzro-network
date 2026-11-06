import type { RpcClient } from "./rpc";

/**
 * Node operation: lifecycle, model residency, telemetry, aliases and
 * visibility. Methods marked operator only need the operator's access token
 * on the RPC client.
 */
export class NodeClient {
  constructor(private rpc: RpcClient) {}

  /** `tenzro_acceptClusterMembership` (operator only). */
  acceptClusterMembership<T = unknown>(params: { cluster_did?: unknown; seq?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_acceptClusterMembership", params);
  }

  /** `tenzro_autotuneDecisions`. */
  autotuneDecisions<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_autotuneDecisions");
  }

  /** `tenzro_cleanupIdleLocalModelServices` (operator only). */
  cleanupIdleLocalModelServices<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_cleanupIdleLocalModelServices");
  }

  /** `tenzro_layerPipelineStatus` (operator only): this machine's part in a model served across the operator's machines. */
  layerPipelineStatus<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_layerPipelineStatus");
  }

  /** `tenzro_fabricProfile`. */
  fabricProfile<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_fabricProfile");
  }

  /** `tenzro_gossipStats` (operator only). */
  gossipStats<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_gossipStats");
  }

  /** `tenzro_gracefulExit` (operator only). */
  gracefulExit<T = unknown>(params: { force?: unknown; max_wait_secs?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_gracefulExit", params);
  }

  /** `tenzro_livenessStats`. */
  livenessStats<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_livenessStats");
  }

  /** `tenzro_loadMediaModel` (operator only). */
  loadMediaModel<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_loadMediaModel", params);
  }

  /** `tenzro_memoryBudget`. */
  memoryBudget<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_memoryBudget");
  }

  /**
   * `tenzro_moeExecute` (operator only): run one expert on the given tokens.
   * `hidden_states` is the little-endian f32 activations, base64; `hidden_q8`
   * the int8-compressed form instead.
   */
  moeExecute<T = unknown>(params: { model_id: string; layer: number; expert: number; token_indices: number[]; d_model: number; hidden_states?: string; hidden_q8?: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_moeExecute", params);
  }

  /**
   * `tenzro_moeExpertLoad` (operator only): load one expert's weights, given
   * inline (`blob_base64`) or as a `tenzro://` blob `uri`.
   */
  moeExpertLoad<T = unknown>(params: { model_id: string; layer: number; expert: number; uri?: string; blob_base64?: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_moeExpertLoad", params);
  }

  /** `tenzro_moeExpertUnload` (operator only): `{ model_id, layer, expert, removed }`. */
  moeExpertUnload<T = { model_id: string; layer: number; expert: number; removed: boolean }>(params: { model_id: string; layer: number; expert: number }): Promise<T> {
    return this.rpc.call<T>("tenzro_moeExpertUnload", params);
  }

  /**
   * `tenzro_moeGateLoad` (operator only): load one layer's router, given
   * inline (`blob_base64`) or as a `tenzro://` blob `uri`.
   */
  moeGateLoad<T = unknown>(params: { model_id: string; layer: number; uri?: string; blob_base64?: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_moeGateLoad", params);
  }

  /** `tenzro_moeGateUnload` (operator only): `{ model_id, layer, removed }`. */
  moeGateUnload<T = { model_id: string; layer: number; removed: boolean }>(params: { model_id: string; layer: number }): Promise<T> {
    return this.rpc.call<T>("tenzro_moeGateUnload", params);
  }

  /**
   * `tenzro_previewServe`: whether a model would fit on this node before it is
   * served: weights, KV cache and headroom at the given quantization, context
   * length and concurrency, with the advice to make it fit when it does not.
   */
  previewServe<T = unknown>(params: { model_id: string; quant?: string; context_length?: number; max_concurrent?: number }): Promise<T> {
    return this.rpc.call<T>("tenzro_previewServe", params);
  }
  /** `tenzro_nodeVisibility`. */
  nodeVisibility<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_nodeVisibility");
  }

  /** `tenzro_pinModel` (operator only). */
  pinModel<T = unknown>(params: { model_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_pinModel", params);
  }

  /** `tenzro_produceSnapshot` (operator only). */
  produceSnapshot<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_produceSnapshot");
  }

  /** `tenzro_pruneModelRegistry` (operator only). */
  pruneModelRegistry<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_pruneModelRegistry");
  }

  /** `tenzro_setDraining` (operator only). */
  setDraining<T = unknown>(params: { draining?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_setDraining", params);
  }

  /** `tenzro_setNodeVisibility` (operator only). */
  setNodeVisibility<T = unknown>(params: { visibility?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_setNodeVisibility", params);
  }


  /** `tenzro_shutdown` (operator only). */
  shutdown<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_shutdown");
  }

  /**
   * `tenzro_standbyQuote`: live operators holding `model_id` on standby in
   * `jurisdiction`, cheapest first, with the account a reservation escrow
   * must pay and the hourly fee each one advertises.
   */
  standbyQuote<T = unknown>(params: { model_id: string; jurisdiction: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_standbyQuote", params);
  }

  /** `tenzro_trafficStats`. */
  trafficStats<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_trafficStats");
  }

  /** `tenzro_unloadMediaModel` (operator only). */
  unloadMediaModel<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_unloadMediaModel", params);
  }

  /** `tenzro_unpinModel` (operator only). */
  unpinModel<T = unknown>(params: { model_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_unpinModel", params);
  }
}
