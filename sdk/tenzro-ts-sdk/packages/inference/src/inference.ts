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
 * A use-case hint that biases model selection toward the right modality and
 * quality tier. Mirrors `UseCase::ALL` on the node.
 */
export type UseCase =
  | "chat"
  | "code"
  | "reasoning"
  | "research"
  | "summarize"
  | "extract"
  | "embed";

/**
 * The shared intent fields consumed by `routeIntent` and `chatByIntent`.
 * `budget` is the smallest TNZO unit as a decimal string (a u128 exceeds
 * JavaScript's safe integer range).
 */
export interface IntentParams {
  useCase: UseCase;
  budget?: string;
  /** Cost-quality knob in [0.0, 1.0]: 0.0 = cheapest acceptable, 1.0 = strongest. */
  optimize?: number;
  /** Reject any model below this tier. */
  qualityFloor?: "cheap" | "strong";
  estInputTokens?: number;
  estOutputTokens?: number;
  /** Payer DID — enables the per-DID rolling-window budget gate. */
  payerDid?: string;
  /** Payer wallet address (hex) — enables the wallet-balance hard ceiling. */
  payerAddress?: string;
  /**
   * Text the model will answer, used only to place the request in a difficulty
   * cluster. It is not sent to any provider by `routeIntent`. On `chatByIntent`
   * the node derives it from the chat turns, so it only needs setting when
   * routing without dispatching.
   */
  prompt?: string;
  /** Where the request may be served (ISO 3166-1 codes and bloc tokens, comma-separated). Unmet pins are refused. */
  jurisdiction?: string;
  /** p95 latency target in ms; providers observed slower are skipped. */
  maxP95Ms?: number;
  /**
   * Continuity level. Above `none` the network assigns a successor that holds
   * the session's KV cache; needs `jurisdiction` and `sessionId`.
   */
  continuity?: "none" | "standby" | "hot_successor";
  /** The session the turns belong to, when continuity is above `none`. */
  sessionId?: string;
}

/** How a routed call turned out, reported through `recordRouteOutcome`. */
export type RouteOutcome = "resolved" | "escalated" | "failed";

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

/** The model-selection decision returned by `routeIntent`. */
export interface RouteDecision {
  model_id: string;
  tier: string;
  /** Estimated cost, smallest TNZO unit, decimal string. */
  estimated_cost: string;
  alternates: string[];
  /**
   * Difficulty cluster the prompt landed in. Null when no prompt was supplied
   * or the node has no embedding model loaded. Echo it back to
   * `recordRouteOutcome` so the observation lands on the right cluster.
   */
  cluster?: number | null;
  /**
   * The chosen model's observed adverse-outcome rate in that cluster. Null when
   * the cluster has no observations, meaning the decision was made on declared
   * metadata alone.
   */
  expected_error?: number | null;
  /**
   * Wallet address (hex) of the provider whose announced offer won. Absent when
   * the winner came from this node's own catalog, where the serving operator is
   * resolved at dispatch time.
   */
  provider?: string | null;
  /** The winning offer's endpoint, present alongside `provider`. */
  endpoint?: string | null;
  reason: string;
}

/** Serializes {@link IntentParams} into the node's snake_case RPC param shape. */
function intentToParams(p: IntentParams): Record<string, unknown> {
  const out: Record<string, unknown> = { use_case: p.useCase };
  if (p.budget !== undefined) out.budget = p.budget;
  if (p.optimize !== undefined) out.optimize = p.optimize;
  if (p.qualityFloor !== undefined) out.quality_floor = p.qualityFloor;
  if (p.estInputTokens !== undefined) out.est_input_tokens = p.estInputTokens;
  if (p.estOutputTokens !== undefined) out.est_output_tokens = p.estOutputTokens;
  if (p.payerDid !== undefined) out.payer_did = p.payerDid;
  if (p.payerAddress !== undefined) out.payer_address = p.payerAddress;
  if (p.prompt !== undefined) out.prompt = p.prompt;
  if (p.jurisdiction !== undefined) out.jurisdiction = p.jurisdiction;
  if (p.maxP95Ms !== undefined) out.max_p95_ms = p.maxP95Ms;
  if (p.continuity !== undefined) out.continuity = p.continuity;
  if (p.sessionId !== undefined) out.session_id = p.sessionId;
  return out;
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
   * Resolve an intent to the best model without naming one. Discovery only:
   * no provider is dialed and no spend is recorded, but the per-DID budget
   * gate and the wallet-balance ceiling are still consulted, so an
   * unaffordable request is rejected at discovery time. Feed the returned
   * `model_id` into {@link request} or the chat surface to run it.
   */
  async routeIntent(params: IntentParams): Promise<RouteDecision> {
    return this.rpc.call<RouteDecision>("tenzro_routeIntent", [
      intentToParams(params),
    ]);
  }

  /**
   * Report how a routed call turned out, so per-cluster error rates reflect what
   * happened rather than only what the catalog declares. `cluster` is the
   * `cluster` from the routing decision.
   *
   * In practice this carries `escalated` — the outcome only the caller knows,
   * because it means the caller took the answer to a stronger model. `resolved`
   * and `failed` are already recorded by {@link chatByIntent} from the dispatch
   * itself. Reporting is advisory: `retained: false` in the response means the
   * node has no difficulty index wired, so the feedback was accepted and
   * discarded.
   */
  async recordRouteOutcome(
    modelId: string,
    cluster: number,
    outcome: RouteOutcome
  ): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>("tenzro_recordRouteOutcome", [
      { model_id: modelId, cluster, outcome },
    ]);
  }

  /**
   * Read the node's difficulty index: how many clusters it has discovered and
   * how many prompts landed in each. With `modelId`, also returns that model's
   * per-cluster outcome counters and error rate. An operator diagnostic —
   * routing does not depend on it.
   */
  async routeDifficultyStats(
    modelId?: string
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = {};
    if (modelId !== undefined) body.model_id = modelId;
    return this.rpc.call<Record<string, unknown>>(
      "tenzro_routeDifficultyStats",
      [body]
    );
  }

  /**
   * Resolve an intent to a model and run a chat completion through the same
   * path a named-model request takes. `messages` is the rich chat shape;
   * `message` is the simple single-turn shape. The chosen `RouteDecision`
   * is attached to the response under `route`.
   */
  async chatByIntent(
    params: IntentParams & {
      message?: string;
      messages?: Array<{ role: string; content: string }>;
    }
  ): Promise<Record<string, unknown>> {
    const body: Record<string, unknown> = intentToParams(params);
    if (params.message !== undefined) body.message = params.message;
    if (params.messages !== undefined) body.messages = params.messages;
    return this.rpc.call<Record<string, unknown>>("tenzro_chatByIntent", [body]);
  }

  /**
   * List all model service endpoints with load information.
   */
  async listModelEndpoints(): Promise<ModelEndpoint[]> {
    return this.rpc.call<ModelEndpoint[]>("tenzro_listModelEndpoints");
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
