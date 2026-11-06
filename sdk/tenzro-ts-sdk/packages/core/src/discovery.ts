import type { RpcClient } from './rpc';

/**
 * Discovery + helper RPCs for the Universal Resolver, SIWT, KERI,
 * PKR, and Institution-identity modules.
 *
 * State-bearing dispatch (party allocation, mint apply)
 * lives on the individual adapter clients; this class gives wallets and
 * SDK consumers read access to the new modules.
 */
export class DiscoveryClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Decentralized MoE shard map for `model_id`: providers holding each
   * `(layer, expert)`, per-expert replication, under-replicated experts,
   * hot experts, and role counts.
   */
  async moeShardMap(modelId: string): Promise<unknown> {
    return this.rpc.call('tenzro_moeShardMap', { model_id: modelId });
  }

  /**
   * Build a dispatch plan from per-token top-k routing decisions.
   * `routings` is `[{token_index, experts: [{layer, expert}]}]`.
   */
  async moePlanDispatch(
    modelId: string,
    routings: Array<{ token_index: number; experts: Array<{ layer: number; expert: number }> }>,
    allowCold = false,
  ): Promise<unknown> {
    return this.rpc.call('tenzro_moePlanDispatch', {
      model_id: modelId,
      routings,
      allow_cold: allowCold,
    });
  }

  /** Current governance-tuned replication policy. */
  async moeReplicationPolicy(): Promise<unknown> {
    return this.rpc.call('tenzro_moeReplicationPolicy', []);
  }

  /** Catalog-side MoE topology for `model_id`. */
  async moeCatalogShape(modelId: string): Promise<unknown> {
    return this.rpc.call('tenzro_moeCatalogShape', { model_id: modelId });
  }

  /**
   * Resident experts and gates on this node's expert runtime, each with its
   * residency tier (`Warm` in memory / `Cold` on disk) and byte footprint,
   * plus the memory budget and whether GPU compute is active.
   */
  async moeExpertStatus(): Promise<unknown> {
    return this.rpc.call('tenzro_moeExpertStatus', []);
  }

  /**
   * Slice a catalog checkpoint into per-expert blobs, optionally
   * block-quantizing each projection, and publish them for holders to load.
   * `quant` is a preset (`q4_k_m` / `q8_0` / `q4_k` / `q6_k`) or a
   * per-projection object like `{ gate: 'q4_k', up: 'q4_k', down: 'q6_k' }`;
   * omit for dense f32 blobs. Empty `experts` prepares every expert in the
   * layer.
   */
  async moePrepareExperts(
    modelId: string,
    layer: number,
    opts: { experts?: number[]; includeGate?: boolean; quant?: string | Record<string, string> } = {},
  ): Promise<unknown> {
    const params: Record<string, unknown> = {
      model_id: modelId,
      layer,
      include_gate: opts.includeGate ?? true,
    };
    if (opts.experts && opts.experts.length > 0) params.experts = opts.experts;
    if (opts.quant !== undefined) params.quant = opts.quant;
    return this.rpc.call('tenzro_moePrepareExperts', params);
  }

  /**
   * Run one distributed MoE layer forward: gate `hidden` locally, fan the
   * selected experts out to holders over the `tenzro/moe` transport, and
   * combine the gate-weighted outputs. `hidden` is the row-major
   * `[numTokens, dModel]` activation, sent as `hidden_states` (little-endian
   * f32, base64); `outputs` in the result uses the same encoding (see
   * {@link decodeF32Base64}).
   */
  async moeForward(
    modelId: string,
    layer: number,
    dModel: number,
    hidden: ArrayLike<number>,
  ): Promise<unknown> {
    return this.rpc.call('tenzro_moeForward', {
      model_id: modelId,
      layer,
      d_model: dModel,
      hidden_states: encodeF32Base64(hidden),
    });
  }

  /**
   * This node's hardware self-profile from the ggml device API: build commit,
   * CPU arch, OS, devices, and the derived serving VRAM / backend / capability
   * key.
   */
  async nodeProfile(): Promise<unknown> {
    return this.rpc.call('tenzro_nodeProfile', []);
  }

  /**
   * Create a cluster or change its members: derives the cluster DID from the
   * operator DID and name, and returns the custody challenge request the
   * operator's passkey answers and the digest each member machine accepts.
   * `seq` is 1 for a new cluster and higher for every change.
   */
  async deriveClusterMembership(
    operatorDid: string,
    name: string,
    seq: number,
    members: string[],
  ): Promise<unknown> {
    return this.rpc.call('tenzro_deriveClusterMembership', {
      operator_did: operatorDid,
      name,
      seq,
      members,
    });
  }

  /**
   * Submit a membership list the operator approved (through the custody
   * challenge `challengeId`) and every member accepted.
   */
  async setClusterMembership(membership: unknown, challengeId: string): Promise<unknown> {
    return this.rpc.call('tenzro_setClusterMembership', {
      membership,
      challenge_id: challengeId,
    });
  }

  /**
   * The verified members of `clusterDid` (this node's own cluster when
   * omitted) and the cluster's aggregated reputation record.
   */
  async clusterMembers(clusterDid?: string): Promise<unknown> {
    return this.rpc.call('tenzro_clusterMembers', { entry: clusterDid ?? null });
  }
}

/** Little-endian f32 values as base64, the encoding `tenzro_moeForward` takes `hidden_states` in. */
export function encodeF32Base64(values: ArrayLike<number>): string {
  const view = new DataView(new ArrayBuffer(values.length * 4));
  for (let i = 0; i < values.length; i++) view.setFloat32(i * 4, values[i], true);
  const bytes = new Uint8Array(view.buffer);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

/** The f32 values a base64 string of little-endian f32s carries, as `tenzro_moeForward` returns `outputs`. */
export function decodeF32Base64(b64: string): Float32Array {
  const bin = atob(b64);
  if (bin.length % 4 !== 0) throw new Error("f32 payload length is not a multiple of 4 bytes");
  const view = new DataView(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) view.setUint8(i, bin.charCodeAt(i));
  const out = new Float32Array(bin.length / 4);
  for (let i = 0; i < out.length; i++) out[i] = view.getFloat32(i * 4, true);
  return out;
}
