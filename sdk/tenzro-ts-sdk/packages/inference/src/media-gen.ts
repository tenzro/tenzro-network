import { RpcClient } from "@tenzro/core";

/**
 * Media kind a render asks for. Mirrors the Rust
 * `tenzro_types::media_gen::MediaGenKind` wire spellings.
 */
export type MediaGenKind =
  | "text2image"
  | "image2image"
  | "text2video"
  | "image2video"
  | "text2audio"
  | "image23d"
  | "text23d"
  | "action_policy"
  | "world_model";

/**
 * Which half of a split denoising schedule a pass runs. Pipelines whose
 * schedule crosses a timestep boundary run the high-noise expert first and
 * the low-noise expert second, with one latent handed over between them.
 */
export type MediaGenExpertRole = "high_noise" | "low_noise";

/** What one input is to the pipeline that renders it. */
export type MediaGenInputRole =
  | "first_frame"
  | "last_frame"
  | "reference"
  | "edit_source"
  | "mask"
  | "observation";

/**
 * One render input (`params.inputs[]`): bytes named by their SHA-256
 * `hash` (the 32 digest bytes) and the `role` they play, sent alongside in
 * `inputsBase64`. The list is read in order (a multi-image edit reads its
 * sources in that order). Accepted roles per kind: image2image edit_source, reference,
 * mask; image2video first_frame, last_frame, reference; image23d reference;
 * action_policy one observation; world_model an optional first_frame.
 */
export interface MediaGenInput {
  role: MediaGenInputRole;
  hash: number[];
}

/**
 * Result of `tenzro_mediaGen_listCatalog`. Entries pass through as
 * `unknown` so a catalog refresh doesn't break compiled callers.
 */
export interface MediaGenCatalog {
  models: unknown[];
  count: number;
}

/**
 * Result of `tenzro_mediaGen_render`: what the signed receipt commits to,
 * the receipt, the price, and where the output is.
 */
export interface MediaGenRender {
  mime: string;
  output_sha256: string;
  output_bytes: number;
  /**
   * Perceptual fingerprint: luma grid cells, sound envelope windows, and for
   * a 3D asset (`model/gltf-binary`) the surface-area share of each cell of
   * an 8x8x8 grid over its bounding cube.
   */
  fingerprint: { luma: number[]; envelope: number[]; geometry: number[] };
  /** Relative L2 distance two renders of it may differ by, in basis points. */
  tolerance_bps: number;
  /** BLAKE3 of the output, fetched with `tenzro_iroh_fetchBlob`. */
  output_blake3: string;
  tenzro_receipt?: unknown;
  units?: unknown;
  /** attoTNZO, decimal string. */
  cost_wei: string;
  settlement?: unknown;
  /** The provider that rendered it, when forwarded. */
  provider?: string;
}

/**
 * Generative media client: the media catalog, and renders on a node or a
 * provider serving the model.
 *
 * @example
 * ```ts
 * const client = await connectToNetwork();
 * const media = client.mediaGen();
 * const { count } = await media.listCatalog();
 * const out = await media.render("z-image-turbo", "text2image", {
 *   prompt: "a lighthouse in fog",
 *   width: 1024,
 *   height: 1024,
 *   steps: 8,
 *   seed: 7,
 * });
 * console.log(count, out.output_blake3);
 * ```
 */
export class MediaGenClient {
  constructor(private rpc: RpcClient) {}

  /**
   * The curated generative-media catalog: ungated, diffusers-loadable
   * models, each carrying its default resolution, step count, frame
   * count, VRAM floor, license tier, and — where the schedule splits —
   * the expert pair and the timestep boundary between them.
   */
  async listCatalog(): Promise<MediaGenCatalog> {
    return this.rpc.call("tenzro_mediaGen_listCatalog", []);
  }

  /**
   * Render one output now, on the node or on a provider serving the model.
   * `params` carries the seed; `inputsBase64` the bytes of each input
   * `params.inputs` names, in order. The answer carries what its signed
   * receipt commits to (`mime`, `output_sha256`, `output_bytes`,
   * `fingerprint`, `tolerance_bps`), the receipt, the price, and
   * `output_blake3`, fetched with `tenzro_iroh_fetchBlob`.
   */
  async render(
    modelId: string,
    kind: MediaGenKind,
    params: Record<string, unknown>,
    options: { inputsBase64?: string[]; verification?: string; provider?: string } = {},
  ): Promise<MediaGenRender> {
    const req: Record<string, unknown> = {
      model_id: modelId,
      kind,
      params,
      inputs_base64: options.inputsBase64 ?? [],
    };
    if (options.verification) req.verification = options.verification;
    if (options.provider) req.provider = options.provider;
    return this.rpc.call("tenzro_mediaGen_render", [req]);
  }
}
