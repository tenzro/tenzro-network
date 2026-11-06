import type { RpcClient } from "@tenzro/core";

/**
 * Result of `tenzro_iroh_getInfo`.
 */
export interface IrohInfo {
  /** z-base-32 iroh `EndpointId` (byte-identical to the TDIP Ed25519 key). */
  endpoint_id: string;
  /** 32-byte endpoint id, hex-encoded. */
  endpoint_id_hex: string;
  /** This machine's DID. */
  machine_did: string | null;
  /** The relays this node's identity transport uses. */
  relays: Array<{ did: string; url: string }>;
  /** The peers it dials at start. */
  boot_peers: Array<{ did: string; endpoint_id: string; relays: string[] }>;
  /** Identity records the transport holds. */
  known_identities: number;
  /** Whether iroh-docs collaborative replicas are enabled on this node. */
  docs_enabled: boolean;
  /** All ALPNs bound on the shared iroh router. */
  bound_alpns: string[];
}

/**
 * Result of `tenzro_iroh_getEndpointId`.
 */
export interface IrohEndpointId {
  endpoint_id: string;
  endpoint_id_hex: string;
}

/**
 * A single ALPN binding on the shared iroh router.
 */
export interface IrohAlpnEntry {
  /** ALPN identifier (e.g. `iroh-blobs`, `tenzro/a2a`). */
  alpn: string;
  /** Short description of the protocol handler bound to this ALPN. */
  description: string;
}

/**
 * Result of `tenzro_iroh_listAlpns`.
 */
export interface IrohAlpnList {
  alpns: IrohAlpnEntry[];
}

/**
 * Result of `tenzro_iroh_publishBlob`.
 */
export interface IrohPublishResult {
  /** `tenzro://blob/<blake3-hex>` URI for the published payload. */
  tenzro_uri: string;
  /** Raw BLAKE3 hash, hex-encoded. */
  blake3_hex: string;
  /** Byte length of the published payload. */
  size_bytes: number;
}

interface IrohFetchResponse {
  bytes_b64: string;
}

/**
 * Base64 helpers — browser + Node ≥18 portable (`btoa`/`atob` are global
 * in both; matches the convention in custody.ts / passkey.ts).
 */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Iroh consumer surface client for the `tenzro_iroh_*` JSON-RPC namespace.
 *
 * Wraps the shared `IrohBackedResolver` on a `tenzro-node`. The same
 * QUIC + Pkarr + iroh-blobs substrate backs the storage DA backend,
 * model-weight peer fetch, and A2A JSON-RPC over the `tenzro/a2a` ALPN.
 *
 * @example
 * ```ts
 * const client = await connectToNetwork();
 * const iroh = client.iroh();
 *
 * const info = await iroh.getInfo();
 * console.log('endpoint:', info.endpoint_id);
 * console.log('alpns:   ', info.alpns);
 *
 * const { tenzro_uri } = await iroh.publishBlob(new TextEncoder().encode('hello'));
 * const bytes = await iroh.fetchBlob(tenzro_uri);
 * console.log(new TextDecoder().decode(bytes)); // "hello"
 * ```
 */
export class IrohClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Endpoint id, Pkarr relay, and bound ALPNs for this node.
   */
  async getInfo(): Promise<IrohInfo> {
    return this.rpc.call<IrohInfo>('tenzro_iroh_getInfo', [{}]);
  }

  /**
   * Just the iroh `EndpointId` (z-base-32 + 32-byte hex).
   */
  async getEndpointId(): Promise<IrohEndpointId> {
    return this.rpc.call<IrohEndpointId>('tenzro_iroh_getEndpointId', [{}]);
  }

  /**
   * ALPNs registered on the shared iroh router.
   */
  async listAlpns(): Promise<IrohAlpnList> {
    return this.rpc.call<IrohAlpnList>('tenzro_iroh_listAlpns', [{}]);
  }

  /**
   * Publish raw bytes as a `tenzro://blob/<blake3-hex>` URI.
   */
  async publishBlob(bytes: Uint8Array): Promise<IrohPublishResult> {
    const bytes_b64 = bytesToBase64(bytes);
    return this.rpc.call<IrohPublishResult>('tenzro_iroh_publishBlob', [
      { bytes_b64 },
    ]);
  }

  /**
   * Fetch a `tenzro://{blob,model,receipt}/...` URI to
   * raw bytes. The dispatcher resolves the variant to the underlying
   * iroh-blobs hash via the shared `IrohBackedResolver`.
   */
  async fetchBlob(tenzroUri: string): Promise<Uint8Array> {
    const resp = await this.rpc.call<IrohFetchResponse>(
      'tenzro_iroh_fetchBlob',
      [{ tenzro_uri: tenzroUri }]
    );
    return base64ToBytes(resp.bytes_b64);
  }

  /**
   * Alias for {@link fetchBlob} for code that thinks of the URI as a
   * name rather than a blob handle.
   */
  async resolve(tenzroUri: string): Promise<Uint8Array> {
    return this.fetchBlob(tenzroUri);
  }

  /** `tenzro_iroh_resolveTenzroUri`. */
  resolveTenzroUri<T = unknown>(params: { tenzro_uri?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_iroh_resolveTenzroUri", params);
  }
}
