import { RpcClient, withRequestEnvelope } from "@tenzro/core";
import type { HybridSigner } from "@tenzro/core";

/** Result of {@link StorageClient.storeObject}. */
export interface StoredObject {
  object_id: string;
  size_bytes: number;
  data_shards: number;
  parity_shards: number;
  /** Hex SHA-256 of the object descriptor: what a storage compute claim commits to pay for keeping the object. */
  descriptor_digest: string | null;
}

/** Storage-provider status snapshot. */
export interface StorageStatus {
  is_storage_provider: boolean;
  /** Effective byte-epoch rate in wei (string-encoded). */
  effective_rate_wei: string;
  /** Number of objects this provider holds. */
  object_count: number;
}

function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function toBase64(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  // `btoa` in browsers and modern Node (≥16); fall back to a Buffer path on
  // older runtimes, reached through `globalThis` so it isn't a bare global.
  if (typeof btoa === "function") {
    return btoa(binary);
  }
  return (globalThis as unknown as {
    Buffer: { from(s: string, e: string): { toString(e: string): string } };
  }).Buffer.from(binary, "binary").toString("base64");
}

/**
 * Decentralized storage client.
 *
 * A node started with the `storage` role spawns a storage-provider runtime:
 * it erasure-codes objects, publishes their shards over the content-addressed
 * transport. A renter pays for keeping an object through a storage compute
 * claim that commits the object's descriptor digest; each hour the claim pays
 * the provider only if validators found its bond available, which requires a
 * possession proof of the object.
 *
 * These calls target the provider node directly; they succeed only when that
 * node is serving the storage role.
 */
export class StorageClient {
  private rpc: RpcClient;

  constructor(rpc: RpcClient) {
    this.rpc = rpc;
  }

  /**
   * Stores an object owned by `ownerDid`: erasure-codes `data` and publishes
   * its shards over the transport. Only `ownerDid` may retrieve it. `signer`
   * holds the key `ownerDid` resolves to and signs the request's envelope.
   *
   * @example
   * ```typescript
   * const stored = await client.storage.storeObject(
   *   "photo-1",
   *   "0xowner",
   *   new TextEncoder().encode("hello"),
   *   4,
   *   2,
   *   "did:tenzro:human:alice",
   *   signer,
   * );
   * console.log(`stored ${stored.size_bytes} bytes`);
   * ```
   */
  async storeObject(
    objectId: string,
    owner: string,
    data: Uint8Array,
    dataShards: number,
    parityShards: number,
    ownerDid: string,
    signer: HybridSigner,
  ): Promise<StoredObject> {
    const params = await withRequestEnvelope(signer, ownerDid, "tenzro_storageStoreObject", {
      object_id: objectId,
      owner,
      data: toBase64(data),
      data_shards: dataShards,
      parity_shards: parityShards,
      owner_did: ownerDid,
    });
    return this.rpc.call<StoredObject>("tenzro_storageStoreObject", params);
  }

  /**
   * Rebuilds an object from its shards for `readerDid` and returns its bytes.
   * The object's access policy must admit `readerDid`; `signer` holds the key
   * it resolves to and signs the request's envelope.
   */
  async retrieveObject(objectId: string, readerDid: string, signer: HybridSigner): Promise<Uint8Array> {
    const params = await withRequestEnvelope(signer, readerDid, "tenzro_storageRetrieveObject", {
      object_id: objectId,
    });
    const out = await this.rpc.call<{ data: string }>("tenzro_storageRetrieveObject", params);
    return fromBase64(out.data);
  }

  /**
   * Sets the provider's fixed byte-epoch rate, in wei, what deals opened from
   * now on pay.
   */
  async setFixedRate(rate: bigint | string): Promise<Record<string, unknown>> {
    return this.rpc.call("tenzro_storageSetPricing", [{ mode: "fixed", rate: rate.toString() }]);
  }

  /** Returns this node's storage-provider status (rate, object count). */
  async status(): Promise<StorageStatus> {
    return this.rpc.call<StorageStatus>("tenzro_storageStatus", []);
  }

  /** `tenzro_daAvailability`. */
  daAvailability<T = unknown>(params: { address?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_daAvailability", params);
  }

  /** `tenzro_daChallenge` (operator only). */
  daChallenge<T = unknown>(params: { commitment?: unknown; target_index?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_daChallenge", params);
  }

  /** `tenzro_daCommittee`. */
  daCommittee<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_daCommittee");
  }

  /** `tenzro_daListBlobs`. */
  daListBlobs<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_daListBlobs");
  }

  /** `tenzro_daListChallenges`. */
  daListChallenges<T = unknown>(params: { limit?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_daListChallenges", params);
  }
}
