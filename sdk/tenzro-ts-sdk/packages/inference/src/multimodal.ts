import { RpcClient } from "@tenzro/core";

/**
 * Parameters for every catalog model load. The node fetches and verifies the
 * files the signed catalog entry names; every shape comes from the entry.
 */
/**
 * How a modality call is verified and which provider serves it. A call for a model the node does not serve is
 * forwarded to a provider offering it; an `optimistic` answer may be re-executed on another provider, and a
 * mismatch is filed as a fault refunding the caller.
 */
export interface TaskRouting {
  verification?: "none" | "receipt" | "optimistic" | "tee";
  /** Serve on this provider's offer (its payee address, hex). */
  provider?: string;
}

export interface LoadModelParams {
  /** Catalog model id */
  model_id: string;
  /** Omit to follow the node's visibility */
  visibility?: "public" | "gated" | "private";
}

// ─── Forecast (timeseries) ───────────────────────────────────────────────

/** Curated forecast (timeseries) catalog entry returned by `listForecastCatalog`. */
export interface ForecastCatalogEntry {
  id: string;
  name: string;
  context_length: number;
  max_horizon: number;
  license_tier: string;
  license_conditions?: string | null;
  paid_serving: boolean;
  [k: string]: unknown;
}

export interface ForecastParams extends TaskRouting {
  model_id: string;
  history: number[];
  horizon: number;
  quantiles?: number[];
  frequency_seconds?: number;
}

// ─── Vision encoders (CLIP / SigLIP2 / DINOv3) ───────────────────────────

export interface VisionCatalogEntry {
  id: string;
  name: string;
  input_size: number;
  embedding_dim: number;
  normalization: string;
  license_tier: string;
  license_conditions?: string | null;
  paid_serving: boolean;
  [k: string]: unknown;
}

export interface ImageEmbedParams extends TaskRouting {
  model_id: string;
  /** Base64-encoded PNG/JPEG/WebP bytes */
  image_base64: string;
  normalize?: boolean;
}

export interface ImageEmbedResult {
  embedding: number[];
  dim: number;
  [k: string]: unknown;
}

export interface ImageTextSimilarityResult {
  similarity: number;
  dim: number;
}

// ─── Text embeddings (Qwen3-Embedding, EmbeddingGemma, BGE-M3, ModernBERT) ─

export interface TextEmbeddingCatalogEntry {
  id: string;
  name: string;
  embedding_dim: number;
  supports_matryoshka: boolean;
  license_tier: string;
  license_conditions?: string | null;
  paid_serving: boolean;
  [k: string]: unknown;
}

/**
 * One input to embed: text, or an object whose text, picture (base64
 * PNG/JPEG/WebP) and video (base64 frames, in order) are embedded together as
 * one item. Pictures and video need a vision-language embedder; their visual
 * tokens are billed as input tokens.
 */
export type EmbedInput = string | { text?: string; image?: string; video?: string[] };

/** One option of a choice question: a key and what it means (text or any JSON value). */
export interface DecisionOption {
  key: string;
  description?: unknown;
}

/**
 * A typed question for a decision model. `choice`: `criteria` lists the options (at most 255) in the
 * order the prompt gives them. `score`: `criteria` is 2 to 10 level descriptions, level 0 first.
 * `noul` (yes or no): `criteria` optionally describes the two answers as `{ false, true }`.
 */
export interface DecisionQuestion {
  id: string;
  type: "choice" | "score" | "noul";
  /** What is asked: text, or any JSON value. */
  instructions: unknown;
  criteria?: DecisionOption[] | unknown[] | { false?: unknown; true?: unknown };
}

/** The answer to one question; only the fields of its type are present. */
export interface DecisionAnswer {
  id: string;
  type: "choice" | "score" | "noul";
  /** Choice: the most probable key. */
  choice?: string;
  /** Score: the expected level. */
  score?: number;
  /** Yes or no: the probability of yes. */
  noul?: number;
  /** Choice and score: the probability of every key. */
  probabilities?: Record<string, number>;
  /** Choice and score: how decided the model is, 0 to 1. */
  confidence?: number;
  /** Score: what each level means. */
  legend?: Record<string, unknown>;
}

export interface TextEmbedParams extends TaskRouting {
  model_id: string;
  inputs: EmbedInput[];
  /** Optional Matryoshka truncation dim (Qwen3-Embedding, EmbeddingGemma) */
  requested_dim?: number;
  normalize?: boolean;
}

// ─── Segmentation (SAM 2 / EdgeSAM / MobileSAM) ─────────────────────────

export interface SegmentationCatalogEntry {
  id: string;
  name: string;
  family: string;
  license_tier: string;
  license_conditions?: string | null;
  paid_serving: boolean;
  [k: string]: unknown;
}

/** A point anchoring the mask to a pixel. `is_foreground` distinguishes
 * "this is the object" from "this is background". */
export interface PointPrompt {
  x: number;
  y: number;
  is_foreground: boolean;
}

/**
 * Prompt for `segment`. Coordinates are original-image pixels — the runtime
 * scales them into encoder space itself.
 */
export type SegmentPrompt =
  | ({ type: "point" } & PointPrompt)
  | { type: "box"; x0: number; y0: number; x1: number; y1: number }
  | { type: "points"; points: PointPrompt[] };

export interface SegmentParams extends TaskRouting {
  model_id: string;
  image_base64: string;
  prompts: SegmentPrompt[];
}

// ─── Text-promptable segmentation (SAM 3 / SAM 3.1) ─────────────────────

export interface TextSegmentationCatalogEntry {
  id: string;
  name: string;
  license_tier: string;
  license_conditions?: string | null;
  paid_serving: boolean;
  [k: string]: unknown;
}

/** Box prompt for `textSegment` — centre plus extent, unlike the corner
 * pairs the click-driven `segment` surface takes. */
export interface TextSegmentBoxPrompt {
  cx: number;
  cy: number;
  w: number;
  h: number;
}

export interface TextSegmentParams extends TaskRouting {
  model_id: string;
  image_base64: string;
  /** Free-text label, e.g. `"dog"`. Pass `""` together with `box_prompt` to
   * run box-only mode. */
  text_prompt: string;
  box_prompt?: TextSegmentBoxPrompt;
  /** Default 0.5 */
  score_threshold?: number;
}

// ─── Detection (RF-DETR, D-FINE) ─────────────────────────────────────────

export interface DetectionCatalogEntry {
  id: string;
  name: string;
  family: string;
  num_classes: number;
  input_size: number;
  license_tier: string;
  license_conditions?: string | null;
  paid_serving: boolean;
  [k: string]: unknown;
}

export interface DetectParams extends TaskRouting {
  model_id: string;
  image_base64: string;
  /** Default 0.25 */
  score_threshold?: number;
}

export interface Detection {
  /** Box in input-image pixels: x0, y0, x1, y1. */
  bbox: [number, number, number, number];
  label_id: number;
  /** Class label, when the model was loaded with a labels file. */
  label?: string;
  score: number;
}

// ─── Audio ASR (Moonshine, Whisper, Distil-Whisper, Parakeet, Canary) ────

export interface AudioCatalogEntry {
  id: string;
  name: string;
  family: string;
  max_audio_seconds: number;
  license_tier: string;
  license_conditions?: string | null;
  paid_serving: boolean;
  [k: string]: unknown;
}

export interface TranscribeParams extends TaskRouting {
  model_id: string;
  /** Base64-encoded WAV/FLAC/MP3 bytes */
  audio_base64: string;
  language?: string;
  timestamps?: boolean;
  temperature?: number;
}

// ─── Video (clip-level embeddings over an image encoder) ─────────────────

export interface VideoCatalogEntry {
  id: string;
  name: string;
  license_tier: string;
  license_conditions?: string | null;
  paid_serving: boolean;
  [k: string]: unknown;
}

export interface LoadVideoModelParams {
  /** Id to register the clip encoder under */
  model_id: string;
  /** Id of an image encoder already brought online with `loadVisionModel` */
  vision_model_id: string;
  /** Frames to sample per clip. Default 8, clamped to 1..128 */
  num_frames?: number;
  /** Omit to follow the node's visibility */
  visibility?: "public" | "gated" | "private";
}

export interface VideoEmbedParams extends TaskRouting {
  model_id: string;
  /** Base64-encoded video container bytes */
  video_base64: string;
  normalize?: boolean;
  /** Keep every `frame_stride`-th decoded frame instead of spreading the
   * samples evenly across the clip. Still capped at the `num_frames` the clip
   * encoder was registered with, so a tight stride surveys the opening of the
   * clip rather than the whole of it. */
  frame_stride?: number;
}

// ─── Generic shapes ──────────────────────────────────────────────────────

export interface LoadModelResult {
  model_id: string;
  loaded: boolean;
  [k: string]: unknown;
}

export interface UnloadModelResult {
  model_id: string;
  removed: boolean;
}

/**
 * Multi-modal AI client — covers the ONNX-backed runtimes on a Tenzro node:
 * forecast (timeseries), vision encoders, text embeddings, click-driven
 * segmentation, text-promptable segmentation, detection, audio (ASR), and
 * video.
 *
 * Each modality has the same surface shape: `list{Modality}Catalog()` to
 * browse curated models, `load{Modality}Model()` to bring a model online,
 * `unload{Modality}Model()` to drop it, and one inference verb.
 * `InferenceClient.listLoadedModels()` lists what is loaded, of every type.
 *
 * Every catalog loader takes the same `LoadModelParams`: the catalog model id
 * and an optional visibility. The node fetches and verifies the files the
 * signed catalog entry names, and enforces the entry's licence tier: it
 * refuses with JSON-RPC `-32010` when the operator has not accepted that
 * entry's terms. Those are node-operator startup flags, never client
 * parameters.
 *
 * The runtimes are feature-gated. A node built without the `onnx` feature
 * answers every load and inference call with JSON-RPC `-32011`.
 */
export class MultimodalClient {
  constructor(private rpc: RpcClient) {}

  // ── Forecast ──

  async listForecastCatalog(): Promise<{ models: ForecastCatalogEntry[] }> {
    return this.rpc.call("tenzro_listForecastCatalog");
  }

  async loadForecastModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadForecastModel", [params]);
  }

  async unloadForecastModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadForecastModel", [{ model_id: modelId }]);
  }

  async forecast(params: ForecastParams): Promise<unknown> {
    return this.rpc.call("tenzro_forecast", [params]);
  }

  // ── Vision encoders ──

  async listVisionCatalog(): Promise<{ models: VisionCatalogEntry[] }> {
    return this.rpc.call("tenzro_listVisionCatalog");
  }

  async loadVisionModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadVisionModel", [params]);
  }

  async unloadVisionModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadVisionModel", [{ model_id: modelId }]);
  }

  /** Embed a single image. Note: the node RPC is `tenzro_imageEmbed`. */
  async imageEmbed(params: ImageEmbedParams): Promise<ImageEmbedResult> {
    return this.rpc.call("tenzro_imageEmbed", [params]);
  }

  /**
   * Pure cosine similarity between two embeddings of identical dimension.
   * Pair an image embedding from `imageEmbed` with a text-tower embedding
   * (CLIP / SigLIP). Node RPC: `tenzro_imageTextSimilarity`.
   */
  async imageTextSimilarity(
    imageEmbedding: number[],
    textEmbedding: number[],
  ): Promise<ImageTextSimilarityResult> {
    return this.rpc.call("tenzro_imageTextSimilarity", [
      { image_embedding: imageEmbedding, text_embedding: textEmbedding },
    ]);
  }

  // ── Text embeddings ──

  async listTextEmbeddingCatalog(): Promise<{ models: TextEmbeddingCatalogEntry[] }> {
    return this.rpc.call("tenzro_listTextEmbeddingCatalog");
  }

  async loadTextEmbeddingModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadTextEmbeddingModel", [params]);
  }

  async unloadTextEmbeddingModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadTextEmbeddingModel", [{ model_id: modelId }]);
  }

  async textEmbed(params: TextEmbedParams): Promise<unknown> {
    return this.rpc.call("tenzro_textEmbed", [params]);
  }

  // ── Segmentation ──

  async listSegmentationCatalog(): Promise<{ models: SegmentationCatalogEntry[] }> {
    return this.rpc.call("tenzro_listSegmentationCatalog");
  }

  async loadSegmentationModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadSegmentationModel", [params]);
  }

  async unloadSegmentationModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadSegmentationModel", [{ model_id: modelId }]);
  }

  /** Segment from clicks or boxes. The encoder pass is cached per image, so
   * each additional prompt costs one more decoder pass. */
  async segment(params: SegmentParams): Promise<unknown> {
    return this.rpc.call("tenzro_segment", [params]);
  }

  // ── Text-promptable segmentation ──

  async listTextSegmentationCatalog(): Promise<{ models: TextSegmentationCatalogEntry[] }> {
    return this.rpc.call("tenzro_listTextSegmentationCatalog");
  }

  async loadTextSegmentationModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadTextSegmentationModel", [params]);
  }

  async unloadTextSegmentationModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadTextSegmentationModel", [{ model_id: modelId }]);
  }

  /** Segment by free-text label, no click needed. */
  async textSegment(params: TextSegmentParams): Promise<unknown> {
    return this.rpc.call("tenzro_textSegment", [params]);
  }

  // ── Detection ──

  async listDetectionCatalog(): Promise<{ models: DetectionCatalogEntry[] }> {
    return this.rpc.call("tenzro_listDetectionCatalog");
  }

  async loadDetectionModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadDetectionModel", [params]);
  }

  async unloadDetectionModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadDetectionModel", [{ model_id: modelId }]);
  }

  async detect(params: DetectParams): Promise<{ detections: Detection[]; generation_time_ms: number; cost_wei?: string; units?: unknown; settlement?: unknown }> {
    return this.rpc.call("tenzro_detect", [params]);
  }

  // ── Rerank ──

  async listRerankCatalog(): Promise<{ models: unknown[] }> {
    return this.rpc.call("tenzro_listRerankCatalog");
  }

  async loadRerankModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadRerankModel", [params]);
  }

  async unloadRerankModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadRerankModel", [{ model_id: modelId }]);
  }

  /**
   * Score documents against a query, best first, with the units billed and a signed receipt at the requested
   * verification level. The query and every document take the embedding input shape; pictures and video need a
   * vision-language reranker. Billed per (query, document) pair.
   */
  async rerank(params: {
    model_id: string;
    query: EmbedInput;
    documents: EmbedInput[];
    top_n?: number;
    return_documents?: boolean;
  } & TaskRouting): Promise<{
    model_id: string;
    results: { index: number; relevance_score: number; document?: EmbedInput }[];
    units: Record<string, number | string>;
    cost_wei: string;
    tenzro_receipt?: unknown;
  }> {
    return this.rpc.call("tenzro_rerank", [params]);
  }

  // ── Decision ──

  async listDecisionCatalog(): Promise<{ models: unknown[] }> {
    return this.rpc.call("tenzro_listDecisionCatalog");
  }

  async loadDecisionModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadDecisionModel", [params]);
  }

  async unloadDecisionModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadDecisionModel", [{ model_id: modelId }]);
  }

  /**
   * Answer typed questions (1 to 64) about a state with a decision model, in one forward pass and without
   * generating text. Each answer is in request order and carries only the fields of its question type.
   * Billed per question answered.
   */
  async decide(params: {
    model_id: string;
    /** Text, or any JSON value (an email, a ticket, a record). */
    state: unknown;
    questions: DecisionQuestion[];
  } & TaskRouting): Promise<{
    model_id: string;
    answers: DecisionAnswer[];
    usage: { questions: number; input_tokens: number };
    units: Record<string, number | string>;
    cost_wei: string;
    tenzro_receipt?: unknown;
  }> {
    return this.rpc.call("tenzro_decide", [params]);
  }

  // ── Training ──

  /** Load a downloaded catalog language model for LoRA training on the node's CUDA device. Operator only. */
  async loadTrainingModel(modelId: string): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadTrainingModel", { model_id: modelId });
  }

  /** Drop a model loaded for training. Operator only. */
  async unloadTrainingModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadTrainingModel", { model_id: modelId });
  }

  /**
   * Run one supervised LoRA round: the round's commitment and roots, each step's loss, the adapter's SHA-256 and
   * URI, `result_digest` with the machine's attestation, the units billed and the signed receipt. Operator only.
   */
  async trainRound(params: {
    model_id: string;
    recipe: Record<string, unknown>;
    records: { prompt: string; completion: string }[];
    sample_seed: number;
    steps: number;
    adapter_seed: number;
    start?: { state_uri: string; start_root: string; steps_taken: number };
  } & TaskRouting): Promise<Record<string, unknown>> {
    return this.rpc.call("tenzro_trainRound", params as unknown as Record<string, unknown>);
  }

  // ── Speech synthesis ──

  async loadSpeechModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadSpeechModel", [params]);
  }

  async unloadSpeechModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadSpeechModel", [{ model_id: modelId }]);
  }

  /** Speak text: base64 WAV with its hash and length, the units billed and a signed receipt at the requested verification level. */
  async speak(params: {
    model_id: string;
    input: string;
    language?: string;
    ref_audio?: string;
    seed?: number;
  } & TaskRouting): Promise<{
    audio_base64: string;
    audio_sha256: string;
    /** RMS sample value of each 20 ms window, committed to by the receipt. */
    envelope: number[];
    sample_rate: number;
    duration_ms: number;
    units: Record<string, number | string>;
    cost_wei: string;
    tenzro_receipt?: unknown;
  }> {
    return this.rpc.call("tenzro_speak", [params]);
  }

  // ── Audio ASR ──

  async listAudioCatalog(): Promise<{ models: AudioCatalogEntry[] }> {
    return this.rpc.call("tenzro_listAudioCatalog");
  }

  async loadAudioModel(params: LoadModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadAudioModel", [params]);
  }

  async unloadAudioModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadAudioModel", [{ model_id: modelId }]);
  }

  async transcribe(params: TranscribeParams): Promise<unknown> {
    return this.rpc.call("tenzro_transcribe", [params]);
  }

  // ── Video ──

  /** The V-JEPA 2 entries the node knows about. They describe the reference
   * clip encoders; the loader below composes over an image encoder instead. */
  async listVideoCatalog(): Promise<{ models: VideoCatalogEntry[] }> {
    return this.rpc.call("tenzro_listVideoCatalog");
  }

  /**
   * Register a clip encoder over an image encoder that `loadVisionModel` has
   * already brought online. Each call samples `num_frames` evenly-spaced
   * frames, embeds them through that encoder, and mean-pools. The node answers
   * `-32004` when `vision_model_id` names an encoder it has not loaded.
   */
  async loadVideoModel(params: LoadVideoModelParams): Promise<LoadModelResult> {
    return this.rpc.call("tenzro_loadVideoModel", [params]);
  }

  async unloadVideoModel(modelId: string): Promise<UnloadModelResult> {
    return this.rpc.call("tenzro_unloadVideoModel", [{ model_id: modelId }]);
  }

  /**
   * Transcribe live audio as it is captured, over the realtime transport. `chunks` yields mono 16-bit little-endian
   * PCM. Yields `partial` transcripts of the open segment, `final` segments committed at pauses (each billed by the
   * second of audio and receipted), then `done`. The node must serve the model.
   */
  async *transcribeStream(
    params: { model_id: string; sample_rate?: number; language?: string; verification?: TaskRouting["verification"] },
    chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
  ): AsyncGenerator<{ event: string; data: unknown }> {
    const encoder = new TextEncoder();
    async function* lines(): AsyncGenerator<Uint8Array> {
      yield encoder.encode(JSON.stringify(params) + "\n");
      for await (const chunk of chunks) {
        let binary = "";
        for (const b of chunk) binary += String.fromCharCode(b);
        yield encoder.encode(JSON.stringify({ pcm_s16le_base64: btoa(binary) }) + "\n");
      }
    }
    yield* this.rpc.streamRoute("/tenzro/realtime/transcribe", lines());
  }

  async videoEmbed(params: VideoEmbedParams): Promise<unknown> {
    return this.rpc.call("tenzro_videoEmbed", [params]);
  }
}
