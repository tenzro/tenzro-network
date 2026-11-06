import type { RpcClient } from "@tenzro/core";

// ── Types ──

/** One snapshot, as `tenzro_listSnapshots` lists it. */
export interface SnapshotSummary {
  /** Height of the committed state. */
  height: number;
  /** State root at that height. */
  state_root: string;
  /** BLAKE3 hash (hex) of the manifest blob. */
  manifest_blob: string;
  /** Number of state buckets. */
  buckets: number;
}

/** Result of `tenzro_listSnapshots`. */
export interface SnapshotList {
  snapshots: SnapshotSummary[];
  /** The iroh endpoint the snapshot data is served from, when the node runs one. */
  endpoint_id: string | null;
}

/**
 * A snapshot manifest, as `tenzro_getSnapshotManifest` returns it. A joining
 * node checks that the bucket summaries fold to `state_root`, that
 * `state_root` is the one a trusted block commits to, and every fetched
 * bucket against its summary before applying it.
 */
export interface SnapshotManifest {
  /** Height of the committed state. */
  height: number;
  /** The state root at `height`. */
  state_root: unknown;
  /** BLAKE3 hash of the blob holding the anchor chain of blocks. */
  anchor_chain: unknown;
  /** Every non-empty bucket, in index order: its summary, blob hash and entry count. */
  buckets: unknown[];
}

// ── Client ──

/**
 * State-sync snapshot client for `tenzro_listSnapshots` and
 * `tenzro_getSnapshotManifest`. Both are reads. The snapshot data itself (the
 * anchor chain and the state buckets) is fetched over the node's iroh
 * state-sync protocol from the listed `endpoint_id` and verified against the
 * manifest.
 */
export class SnapshotClient {
  constructor(private readonly rpc: RpcClient) {}

  /** The snapshots this node holds, and the iroh endpoint it serves them from. */
  async listSnapshots(): Promise<SnapshotList> {
    return this.rpc.call<SnapshotList>('tenzro_listSnapshots', []);
  }

  /**
   * The full manifest for the snapshot at `height`. Returns the node's
   * `-32004 no snapshot at height` error if it holds none there.
   */
  async getSnapshotManifest(height: number): Promise<SnapshotManifest> {
    return this.rpc.call<SnapshotManifest>('tenzro_getSnapshotManifest', [
      { height },
    ]);
  }
}
