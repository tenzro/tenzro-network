import { RpcClient } from "@tenzro/core";

/** Licence tier of a model's weights. */
export type LicenseTier =
  | "permissive"
  | "attribution"
  | "commercial_custom"
  | "non_commercial";

/** One file a model downloads and the SHA-256 its bytes must have. */
export interface CatalogComponent {
  repo: string;
  path: string;
  revision: string;
  size: number;
  sha256: string;
}

/** A model as its publisher describes it. */
export interface CatalogEntry {
  /** Engine family (`gguf`, `onnx-vision`, `media-gen`, ...) and its description of the model. */
  model: { engine: string; spec: Record<string, unknown> & { id: string; name: string } };
  licence: { name: string; id?: string; tier: LicenseTier };
  /** The operator's own Hugging Face token is needed; the weights are never redistributed. */
  gated: boolean;
  components: CatalogComponent[];
  capabilities: string[];
  capability_priors: Record<string, number>;
  moe_source?: { repo: string; revision: string };
}

/** A published model the node does not serve, and why. */
export interface RefusedEntry {
  model: string;
  publishers: string[];
  reason: string;
}

/** What the node's catalog is assembled from. */
export interface CatalogStatus {
  named_publishers: string[];
  publishers: string[];
  entries: number;
  refused: RefusedEntry[];
  note?: string;
}

/**
 * The model catalog a node serves: the signed entries of the publishers its
 * operator names (or every bonded publisher). Entries are published with
 * `TrustClient.submit`.
 */
export class CatalogClient {
  constructor(private rpc: RpcClient) {}

  /** Every entry the node serves, optionally of one engine family. */
  async list(engine?: string): Promise<{ status: CatalogStatus; count: number; entries: CatalogEntry[] }> {
    return this.rpc.call("tenzro_listCatalog", engine ? { engine } : {});
  }

  /** One model's entry and its publishers. */
  async entry(model: string): Promise<{
    model: string;
    served: boolean;
    publishers: string[];
    entry: CatalogEntry;
  }> {
    return this.rpc.call("tenzro_getCatalogEntry", { model });
  }

  /**
   * The engine releases from the publishers the node's operator trusts for
   * releases, newest first, each marked `newer` than the running build. The
   * node installs nothing; its operator applies a release.
   */
  async engineReleases(): Promise<{
    running: string;
    platform: string;
    publishers: string[];
    available: string | null;
    releases: Array<{
      version: string;
      publisher: string;
      newer: boolean;
      artifacts: Array<{ platform: string; size: number; sha256: string; blake3: string }>;
      record: unknown;
    }>;
    note: string | null;
  }> {
    return this.rpc.call("tenzro_getEngineReleases", {});
  }
}
