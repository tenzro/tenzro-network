import type { AccessCredential } from "./access";

export interface TenzroConfig {
  endpoint: string;
  apiEndpoint?: string;
  chainId?: number;
  timeout?: number;
  /**
   * The access token and DPoP key every call is signed with. Unset,
   * `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` are forwarded where a
   * process environment exists.
   */
  access?: AccessCredential;
}

/** A named Tenzro network: its chain id and the public endpoints it serves. */
export interface NetworkPreset {
  /** The network's name. */
  name: string;
  /** The chain id every endpoint reports (`eth_chainId`). */
  chainId: number;
  /** JSON-RPC. */
  rpc: string;
  /** REST API. */
  api: string;
  /** MCP server. */
  mcp: string;
  /** A2A, with its Agent Card. */
  a2a: string;
  /** Relay for node-to-node connections. */
  relay: string;
}

/** The Tenzro preview network. */
export const PREVIEW_NETWORK: Readonly<NetworkPreset> = Object.freeze({
  name: "preview",
  chainId: 133801,
  rpc: "https://rpc.tenzro.com",
  api: "https://api.tenzro.com",
  mcp: "https://mcp.tenzro.com/mcp",
  a2a: "https://a2a.tenzro.com",
  relay: "https://relay.tenzro.com",
});

/** The chain id the SDK expects by default: {@link PREVIEW_NETWORK}'s. */
export const NETWORK_CHAIN_ID = PREVIEW_NETWORK.chainId;

/**
 * Bootstrap hints for finding the network's staked RPC operators. A seed is a
 * way in, never an authority: the client asks every seed for the on-chain
 * operator list, keeps the endpoints that report {@link NETWORK_CHAIN_ID} and
 * agree on a checkpoint digest, and from then on talks to those operators.
 * Pass your own seeds in `NetworkOptions` to start from any node you trust as
 * a way in.
 */
export const NETWORK_SEEDS: readonly string[] = [PREVIEW_NETWORK.rpc];

/** The preview network's RPC and REST endpoints with its chain id. */
export const PREVIEW_CONFIG: TenzroConfig = {
  endpoint: PREVIEW_NETWORK.rpc,
  apiEndpoint: PREVIEW_NETWORK.api,
  chainId: PREVIEW_NETWORK.chainId,
  timeout: 10000,
};

/** A node on this machine, for development. */
export const LOCAL_CONFIG: TenzroConfig = {
  endpoint: "http://localhost:8545",
  apiEndpoint: "http://localhost:8080",
  chainId: 1337,
  timeout: 10000,
};
