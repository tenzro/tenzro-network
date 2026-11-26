import { RpcClient } from "@tenzro/core";
import {
  ModelInfo,
  InferenceResult,
  ModelEndpoint,
} from "@tenzro/core";

/** One model a node holds, from `listLoadedModels`. */
export interface LoadedModel {
  /** Catalog model id */
  model_id: string;
  /** `chat`, `vision`, `embedding`, `forecast`, `segmentation`,
   * `text-segmentation`, `detection`, `audio`, `video`, `media` or `speech` */
  type: string;
  /** The engine holding it; `null` when it is served but not resident */
  engine: string | null;
  /** Effective visibility */
  visibility: "public" | "gated" | "private";
  /** `model` when the model carries its own override, `node` when it follows
   * the node's visibility */
  visibility_source: "model" | "node";
  /** The access that visibility grants */
  access:
    | { mode: "public"; price_per_request: string }
    | { mode: "gated" }
    | { mode: "private" };
  /** Resident in memory */
  loaded: boolean;
  /** Offered by this node */
  serving: boolean;
}

/** Every model a node holds. */
export interface LoadedModels {
  models: LoadedModel[];
}

/**
 * What one finished generation consumed and cost, as recorded by the node.
 *
 * The dimensions past prompt and completion appear only when the call actually
 * consumed them, so a chat completion carries none of the media fields. Read it
 * back with {@link InferenceClient.getGeneration}.
 */
export interface GenerationStats {
  /** The id the read was keyed on — a `chatcmpl-…` or a `request_id`. */
  id: string;
  model: string;
  /** Payee address of the node that served it. */
  provider: string;
  /** The whole prompt, including anything served from cache. */
  input_tokens: number;
  output_tokens: number;
  /** Every token-denominated dimension summed, image tokens included. */
  total_tokens: number;
  bytes_in: number;
  bytes_out: number;
  /** Smallest TNZO unit, decimal string — a u128 exceeds JavaScript's safe integer range. */
  cost_wei: string;
  latency_ms: number;
  /** Omitted when the recorded latency is zero. */
  tokens_per_second?: number | null;
  created: number;
  /** Every unit the call was metered on, as the receipt states it. */
  units?: BillableUnits;
}

import type { BillableUnits } from "./pricing";
export type { BillableUnits } from "./pricing";

/**
 * One recorded generation, as it sits in the node's ring of recent records.
 *
 * This is the raw record rather than the reshaped {@link GenerationStats}:
 * `provider_id` is the raw 32-byte address, durations stay in milliseconds, and
 * every dimension is present rather than conditional.
 */
export interface UsageRecord {
  record_id: string;
  model_id: string;
  /** The serving provider's address, as 32 bytes. */
  provider_id: number[];
  units: BillableUnits;
  bytes_in: number;
  bytes_out: number;
  /** Smallest TNZO unit; a decimal string above 2^53. */
  cost: number | string;
  latency_ms: number;
  /** Unix milliseconds. */
  timestamp: number;
}


/** Usage rolled up for one model. */
export interface ModelUsageStats {
  model_id: string;
  inference_count: number;
  total_units: BillableUnits;
  /** Smallest TNZO unit. */
  total_cost: number;
  total_latency_ms: number;
  total_bytes_in: number;
  total_bytes_out: number;
  first_inference?: number | null;
  last_inference?: number | null;
}

/** Usage rolled up for one provider — the same shape, counted as earnings. */
export interface ProviderUsageStats {
  /** The provider's address, as 32 bytes. */
  provider_id: number[];
  inference_count: number;
  total_units: BillableUnits;
  /** Smallest TNZO unit. */
  total_revenue: number;
  total_latency_ms: number;
  total_bytes_in: number;
  total_bytes_out: number;
  first_inference?: number | null;
  last_inference?: number | null;
}

/** Usage rolled up across everything this node has served or routed. */
export interface GlobalUsageStats {
  total_inference_count: number;
  total_units: BillableUnits;
  /** Smallest TNZO unit. */
  total_cost: number;
  total_latency_ms: number;
  total_bytes_in: number;
  total_bytes_out: number;
  unique_models: number;
  unique_providers: number;
  first_inference?: number | null;
  last_inference?: number | null;
}

/**
 * What {@link InferenceClient.listInferenceUsage} returns. Which key is present
 * follows the filters given: both filters returns the matching `records`, one
 * returns that model's or provider's rollup, neither returns all three tiers.
 */
export interface InferenceUsage {
  records?: UsageRecord[];
  model_stats?: ModelUsageStats | null;
  provider_stats?: ProviderUsageStats | null;
  global?: GlobalUsageStats;
  models?: ModelUsageStats[];
  providers?: ProviderUsageStats[];
}

/**
 * Client for AI inference operations.
 * Supports model discovery and inference requests.
 */
export class InferenceClient {
  constructor(private rpc: RpcClient) {}

  /**
   * List all available models on the network.
   */
  async listModels(): Promise<ModelInfo[]> {
    return this.rpc.call<ModelInfo[]>("tenzro_listModels");
  }

  /**
   * List every model the node holds, of every type (chat, vision, embedding,
   * forecast, segmentation, detection, audio, video, media, speech), with its
   * engine, visibility, access and state.
   */
  async listLoadedModels(): Promise<LoadedModels> {
    return this.rpc.call<LoadedModels>("tenzro_listModels", [{ loaded: true }]);
  }

  /**
   * Request inference from a specific model.
   * @param modelId - The model identifier
   * @param input - The input text/data
   * @param maxTokens - Optional maximum tokens to generate (default: 1024)
   * @returns Inference result with output, cost, and metadata
   */
  async request(
    modelId: string,
    input: string,
    maxTokens?: number
  ): Promise<InferenceResult> {
    return this.rpc.call<InferenceResult>("tenzro_inferenceRequest", {
      model_id: modelId,
      input,
      max_tokens: maxTokens ?? 1024,
    });
  }

  /**
   * List all model service endpoints with load information.
   */
  async listModelEndpoints(): Promise<ModelEndpoint[]> {
    return this.rpc.call<ModelEndpoint[]>("tenzro_listModelEndpoints");
  }

  /**
   * Check a jurisdiction receipt on the node: its signature in either form,
   * the identity-key form against the node's chain state, and whether the
   * hardware key it names is the one registered for its machine.
   */
  async verifyJurisdictionReceipt(receipt: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>("tenzro_verifyJurisdictionReceipt", { receipt });
  }

  /**
   * Read the inference router's live metrics snapshot: total requests routed,
   * hedges dispatched, hedges won, and requests abandoned on the whole-request
   * deadline.
   */
  async routerMetrics(): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>("tenzro_getRouterMetrics");
  }

  /**
   * Look up the cached provenance manifest for generated content by its
   * 32-byte hex `contentHash` (with or without `0x` prefix). This is the
   * machine-readable synthetic-content marker per EU AI Act Art. 50(2).
   * Throws JSON-RPC `-32004` when no manifest is cached for the hash.
   */
  async getProvenance(contentHash: string): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>("tenzro_getContentProvenance", [
      { content_hash: contentHash },
    ]);
  }

  /**
   * Read back what one finished generation consumed and cost, by the id you
   * already hold — a `chatcmpl-…` from a chat completion, or the `request_id`
   * of a routed inference.
   *
   * Useful when a stream was consumed and the terminal chunk went by, or when
   * reconciling a billing period against your own request log. Throws JSON-RPC
   * `-32004` when the id is unknown to this node, which also covers a
   * generation still running or one that failed before it could be recorded.
   */
  async getGeneration(id: string): Promise<GenerationStats> {
    return this.rpc.call<GenerationStats>("tenzro_getGeneration", [{ id }]);
  }

  /**
   * Read usage. Which tier comes back follows the filters given: pass both a
   * model and a provider for the matching records, one for that model's or
   * provider's rollup, neither for the global rollup plus the per-model and
   * per-provider breakdowns.
   *
   * Records are the node's bounded ring of recent generations; the rollups are
   * lifetime totals that survive restart.
   */
  async listInferenceUsage(filters?: {
    modelId?: string;
    provider?: string;
  }): Promise<InferenceUsage> {
    const body: Record<string, unknown> = {};
    if (filters?.modelId !== undefined) body.model_id = filters.modelId;
    if (filters?.provider !== undefined) body.provider = filters.provider;
    return this.rpc.call<InferenceUsage>("tenzro_listInferenceUsage", [body]);
  }




  /** `tenzro_listTtsCatalog`. */
  listTtsCatalog<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_listTtsCatalog");
  }

  /** `tenzro_modelLifecycle`. */
  modelLifecycle<T = unknown>(params: { model_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_modelLifecycle", params);
  }

  /** `tenzro_moeDisputeReceipt`: re-check the stored expert receipt at `key`. */
  moeDisputeReceipt<T = unknown>(params: { key: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_moeDisputeReceipt", params);
  }

  /** `tenzro_moeListReceipts`. */
  moeListReceipts<T = { receipts: unknown[]; count: number }>(params: { limit?: number; model_id?: string } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_moeListReceipts", params);
  }

  /** `tenzro_moePrepareStatus`. */
  moePrepareStatus<T = unknown>(params: { job_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_moePrepareStatus", params);
  }

  /**
   * `tenzro_moeRoute`: route tokens through one layer's gate. `hidden_states`
   * is the little-endian f32 activations, base64, `d_model` wide; `top_k`
   * defaults to the catalog's experts per token.
   */
  moeRoute<T = { model_id: string; layer: number; top_k: number; tokens: number; routed: unknown }>(params: { model_id: string; layer: number; d_model: number; hidden_states: string; top_k?: number }): Promise<T> {
    return this.rpc.call<T>("tenzro_moeRoute", params);
  }

  /** `tenzro_prefixProbe`. */
  prefixProbe<T = unknown>(params: { digests?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_prefixProbe", params);
  }




}
