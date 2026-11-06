import { AgentAccountsClient } from "@tenzro/bridge";
import { TenzroConfig, LOCAL_CONFIG, NETWORK_CHAIN_ID, PREVIEW_CONFIG } from "@tenzro/core";
import { discoverEip6963Provider } from "@tenzro/core";
import { Eip1193Transport, RpcClient, RpcTransport } from "@tenzro/core";
import { WalletClient } from "@tenzro/core";
import { PasskeyRpcClient } from "@tenzro/core";
import { TenzroAgentWallet } from "@tenzro/agents";
import { InferenceClient } from "@tenzro/inference";
import { SettlementClient } from "@tenzro/settlement";
import { SettleClient } from "@tenzro/settlement";
import { AgentClient } from "@tenzro/agents";
import { GovernanceClient } from "@tenzro/chain";
import { FundingClient } from "@tenzro/payments";
import { IdentityClient } from "@tenzro/core";
import { PaymentClient } from "@tenzro/payments";
import { ProviderClient, RegistryClient } from "@tenzro/inference";
import { StorageClient } from "@tenzro/chain";
import { TrustClient } from "@tenzro/chain";
import { CatalogClient } from "@tenzro/inference";

import { GatewayClient } from "@tenzro/core";

import { AccountKeysClient } from "@tenzro/core";
import { BeaconClient, DaRetentionClient, getFeeMarket } from "@tenzro/agents";
import { StakingClient } from "@tenzro/chain";
import { TokenClient } from "@tenzro/chain";
import { ContractClient } from "@tenzro/chain";
import { CryptoClient } from "@tenzro/core";
import { TeeClient } from "@tenzro/chain";
import { ZkClient } from "@tenzro/chain";
import { StreamingClient } from "@tenzro/inference";

import { BridgeClient } from "@tenzro/bridge";
import { AgentPaymentClient } from "@tenzro/agents";
import { IrohClient } from "@tenzro/chain";

import { AccessClient } from "@tenzro/core";
import { TypedTxClient } from "@tenzro/core";
import { NodeClient } from "@tenzro/core";
import { AuthClient } from "@tenzro/core";
import { BondClient } from "@tenzro/agents";
import { DutyClient, InsuranceClient } from "@tenzro/chain";
import { AdaptiveBurnClient } from "@tenzro/chain";
import { DeviceClient } from "@tenzro/core";
import { MachineAccessClient } from "@tenzro/chain";
import { QuotaClient } from "@tenzro/chain";
import { LifecycleClient } from "@tenzro/agents";
import { MultimodalClient } from "@tenzro/inference";

import { ValidatorClient } from "@tenzro/chain";

import { MediaGenClient } from "@tenzro/inference";
import { SlaClient } from "@tenzro/chain";
import { SnapshotClient } from "@tenzro/chain";
import { ReserveClient } from "@tenzro/chain";

import { Permit2Client } from "@tenzro/payments";
import { UrwaClient } from "@tenzro/chain";
import { BridgeFeeClient } from "@tenzro/bridge";
import { DiscoveryClient } from "@tenzro/core";
import {
  Block,
  BlockSummary,
  BlockRange,
  FeeHistory,
  Transaction,
  NodeStatus,
  NodeStatusReport,
  HealthResponse,
  NetworkStats,
} from "@tenzro/core";

/**
 * Main client for interacting with Tenzro Network.
 * Provides access to all network functionality through specialized sub-clients.
 */
export class TenzroClient {
  public readonly auth: AuthClient;
  public readonly access: AccessClient;
  /** Every consensus transaction type, signed with the caller's own hybrid key. */
  public readonly transactions: TypedTxClient;
  public readonly node: NodeClient;
  public readonly wallet: WalletClient;
  public readonly passkeyRpc: PasskeyRpcClient;
  /** Composite agent-wallet surface — passkey + bond
   *  in one named class. The substrate sub-clients
   *  (`passkey`/`bond`) hang off `agentWallet` for drop-down
   *  access; most callers use the composite methods (`spawn`,
   *  `getRisk`). */
  public readonly agentWallet: TenzroAgentWallet;
  public readonly inference: InferenceClient;
  public readonly settlement: SettlementClient;
  public readonly settle: SettleClient;
  public readonly agent: AgentClient;
  public readonly governance: GovernanceClient;
  public readonly funding: FundingClient;
  public readonly identity: IdentityClient;
  public readonly payment: PaymentClient;
  public readonly provider: ProviderClient;
  /** The generic registry: units, service types, price cards, apps. */
  public readonly registry: RegistryClient;
  public readonly storage: StorageClient;
  /** Certifications, operator policies and model provenance. */
  public readonly trust: TrustClient;
  /** The model catalog the node serves. */
  public readonly catalog: CatalogClient;
  /** Discover and call any method this node serves — everything the typed clients above do not cover. */
  public readonly gateway: GatewayClient;
  public readonly staking: StakingClient;
  public readonly token: TokenClient;
  public readonly contract: ContractClient;
  public readonly crypto: CryptoClient;
  public readonly tee: TeeClient;
  public readonly zk: ZkClient;
  public readonly streaming: StreamingClient;
  public readonly reserve: ReserveClient;
  public readonly permit2: Permit2Client;
  public readonly agentAccounts: AgentAccountsClient;
  public readonly discovery: DiscoveryClient;
  public readonly urwa: UrwaClient;
  public readonly bridgeFee: BridgeFeeClient;

  private readonly rpc: RpcClient;
  private readonly config: TenzroConfig;

  constructor(config: TenzroConfig, transport?: RpcTransport) {
    this.config = config;
    this.rpc = new RpcClient(
      config.endpoint,
      config.apiEndpoint,
      config.timeout,
      transport,
      config.access,
    );
    this.auth = new AuthClient(this.rpc);
    this.access = new AccessClient(this.rpc);
    this.transactions = new TypedTxClient(this.rpc);
    this.node = new NodeClient(this.rpc);
    this.wallet = new WalletClient(this.rpc);
    this.passkeyRpc = new PasskeyRpcClient(this.rpc);
    this.agentWallet = new TenzroAgentWallet(this.rpc);
    this.inference = new InferenceClient(this.rpc);
    this.settlement = new SettlementClient(this.rpc);
    this.settle = new SettleClient(this.rpc);
    this.agent = new AgentClient(this.rpc);
    this.governance = new GovernanceClient(this.rpc);
    this.funding = new FundingClient(this.rpc);
    this.identity = new IdentityClient(this.rpc);
    this.payment = new PaymentClient(this.rpc);
    this.provider = new ProviderClient(this.rpc);
    this.registry = new RegistryClient(this.rpc);
    this.storage = new StorageClient(this.rpc);
    this.trust = new TrustClient(this.rpc);
    this.catalog = new CatalogClient(this.rpc);
    this.gateway = new GatewayClient(this.rpc);
    this.staking = new StakingClient(this.rpc);
    this.token = new TokenClient(this.rpc);
    this.contract = new ContractClient(this.rpc);
    this.crypto = new CryptoClient(this.rpc);
    this.tee = new TeeClient(this.rpc);
    this.zk = new ZkClient(this.rpc);
    this.streaming = new StreamingClient(this.rpc);
    this.reserve = new ReserveClient(this.rpc);
    this.permit2 = new Permit2Client(this.rpc);
    this.agentAccounts = new AgentAccountsClient(this.rpc);
    this.discovery = new DiscoveryClient(this.rpc);
    this.urwa = new UrwaClient(this.rpc);
    this.bridgeFee = new BridgeFeeClient(this.rpc);
  }

  /** The keys of the signer's own account: enroll or replace its hardware ML-DSA-65 key. */
  accountKeys(): AccountKeysClient {
    return new AccountKeysClient(this.rpc);
  }

  beacon(): BeaconClient {
    return new BeaconClient(this.rpc);
  }

  daRetention(): DaRetentionClient {
    return new DaRetentionClient(this.rpc);
  }

  /** The base fee of every resource market the next block charges. */
  feeMarket() {
    return getFeeMarket(this.rpc);
  }

  /** Access the cross-chain bridge client. */
  bridge(): BridgeClient {
    return new BridgeClient(this.rpc);
  }

  /** Access the agent payment executor client. */
  agentPayments(): AgentPaymentClient {
    return new AgentPaymentClient(this.rpc);
  }

  /**
   * Access the Iroh consumer surface client for the `tenzro_iroh_*`
   * namespace — endpoint id / ALPNs / publish / fetch over the shared
   * `IrohBackedResolver` (QUIC + Pkarr + iroh-blobs substrate that
   * also backs DA, model fetch, and A2A-over-iroh).
   */
  iroh(): IrohClient {
    return new IrohClient(this.rpc);
  }

  /** Access the AgentBond client. */
  bond(): BondClient {
    return new BondClient(this.rpc);
  }

  /** Network duties and evidence checks against chain state. */
  duty(): DutyClient {
    return new DutyClient(this.rpc);
  }

  /** Access the network insurance pool. */
  insurance(): InsuranceClient {
    return new InsuranceClient(this.rpc);
  }

  /** Access the adaptive-burn governance dial client. */
  adaptiveBurn(): AdaptiveBurnClient {
    return new AdaptiveBurnClient(this.rpc);
  }

  /** Access the device-binding and machine-ownership client. */
  device(): DeviceClient {
    return new DeviceClient(this.rpc);
  }

  /** Access the owner-signed machine-access client. */
  machineAccess(): MachineAccessClient {
    return new MachineAccessClient(this.rpc);
  }

  /** Access the node quota / mempool / DA client. */
  quota(): QuotaClient {
    return new QuotaClient(this.rpc);
  }

  /** Access the agent lifecycle / kill-switch client. */
  lifecycle(): LifecycleClient {
    return new LifecycleClient(this.rpc);
  }

  /**
   * Access the multi-modal AI client — forecast (timeseries), vision
   * encoders, text embeddings, click-driven segmentation, text-promptable
   * segmentation, detection, audio (ASR), and video. Each modality exposes
   * catalog browse, list-loaded, load, unload, and one inference verb.
   *
   * The runtimes are feature-gated: a node built without `onnx` answers
   * every load and inference call with JSON-RPC `-32011`.
   */
  multimodal(): MultimodalClient {
    return new MultimodalClient(this.rpc);
  }

  /**
   * Access the generative media client: the media catalog and renders.
   */
  mediaGen(): MediaGenClient {
    return new MediaGenClient(this.rpc);
  }

  /**
   * Access the validator-side SLA fault-detector inspection client.
   * Wraps `tenzro_slaIssueProbe`, `tenzro_slaListOutstandingProbes`,
   * and `tenzro_slaGetParams`. The probe-issuing call is
   * validator-only; on a non-validator node it returns
   * `-32000 SlaManager not initialized`.
   */
  sla(): SlaClient {
    return new SlaClient(this.rpc);
  }

  /**
   * State-sync snapshot client for `tenzro_listSnapshots` and
   * `tenzro_getSnapshotManifest`. A manifest's `state_root` must match the
   * root a trusted block commits to before any bucket from it is applied.
   */
  snapshot(): SnapshotClient {
    return new SnapshotClient(this.rpc);
  }

  static local(): TenzroClient {
    return new TenzroClient(LOCAL_CONFIG);
  }

  /**
   * A client for the preview network's public RPC endpoint. To move between
   * the staked RPC operators instead of one endpoint, use `connectToNetwork()`.
   */
  static preview(): TenzroClient {
    return new TenzroClient(PREVIEW_CONFIG);
  }

  /**
   * Construct a client that routes RPCs through a browser-extension
   * provider (`window.tenzro`) discovered via EIP-6963.
   *
   * The Tenzro provider handles auth (DPoP-bound JWT) and CAIP-25
   * sessions on its own — the SDK never sees the user's keys or tokens
   * and never opens a direct fetch to a node. All
   * `client.rpc.call(...)` calls become `provider.request(...)` calls.
   *
   * Every call goes through the provider; `options.config` sets the chain
   * id (the preview network's by default) and any REST endpoint to fetch
   * directly.
   *
   * Throws if no Tenzro provider is announced within `timeoutMs`
   * (default 3000) — wrap the call in a try/catch and render an
   * "Install Tenzro" CTA on `TenzroNotInstalledError`.
   *
   * @example
   * ```ts
   * try {
   *   const client = await TenzroClient.fromInjected();
   *   const block = await client.getLatestBlock();
   * } catch (err) {
   *   if (err instanceof TenzroNotInstalledError) showInstallCta();
   *   else throw err;
   * }
   * ```
   */
  static async fromInjected(options?: {
    config?: TenzroConfig;
    timeoutMs?: number;
    rdns?: string;
  }): Promise<TenzroClient> {
    const detail = await discoverEip6963Provider({
      timeoutMs: options?.timeoutMs,
      rdns: options?.rdns,
    });
    const transport = new Eip1193Transport(detail.provider);
    const config = options?.config ?? { endpoint: "", chainId: NETWORK_CHAIN_ID };
    return new TenzroClient(config, transport);
  }

  // Core blockchain queries

  async getBlockNumber(): Promise<number> {
    const hex = await this.rpc.call<string>("tenzro_blockNumber");
    return parseHex(hex);
  }

  /** The block at `height`, or null when the node holds none there. */
  async getBlock(height: number): Promise<BlockSummary | null> {
    return this.rpc.call<BlockSummary | null>("tenzro_getBlock", [{ block_number: height }]);
  }

  async getLatestBlock(): Promise<BlockSummary | null> {
    return this.rpc.call<BlockSummary | null>("tenzro_getBlock", [{ height: "latest" }]);
  }

  /**
   * Fetch a contiguous range of blocks for catch-up sync.
   *
   * Returns up to `maxResults` blocks (default 64, capped at 256). Use
   * `nextHeight` and `moreAvailable` to drive pagination. `moreAvailable`
   * reflects whether the chain has further blocks beyond `nextHeight`,
   * independent of the requested `endHeight`, so a sync loop can step over
   * pruning gaps:
   *
   * ```ts
   * let cur = 0;
   * while (true) {
   *   const r = await client.getBlockRange(cur, cur + 255, 256);
   *   for (const b of r.blocks) { /* ... *\/ }
   *   if (!r.moreAvailable) break;
   *   cur = r.nextHeight;
   * }
   * ```
   */
  async getBlockRange(
    startHeight: number,
    endHeight: number,
    maxResults?: number,
  ): Promise<BlockRange> {
    const params: Record<string, number> = {
      startHeight,
      endHeight,
    };
    if (maxResults !== undefined) {
      params.maxResults = maxResults;
    }
    return this.rpc.call<BlockRange>("tenzro_getBlockRange", params);
  }

  /**
   * Get a transaction by hash.
   *
   * Resolves from finalized storage first, then falls back to the consensus
   * mempool. The returned object's `status` field is `"pending"` while the
   * transaction is in-mempool and `"finalized"` once it has been included in
   * a block — callers polling immediately after broadcast can therefore
   * distinguish "not yet finalized" from "unknown hash" (the RPC returns
   * `null` only when the hash is unknown to both storage and mempool).
   */
  async getTransaction(txHash: string): Promise<Transaction | null> {
    return this.rpc.call<Transaction | null>("tenzro_getTransaction", [txHash]);
  }

  async getBalance(address: string): Promise<bigint> {
    const hex = await this.rpc.call<string>("tenzro_getBalance", [address]);
    return BigInt(hex);
  }

  async getNonce(address: string): Promise<number> {
    const hex = await this.rpc.call<string>("tenzro_getNonce", [address]);
    return parseHex(hex);
  }

  async getChainId(): Promise<number> {
    const hex = await this.rpc.call<string>("eth_chainId");
    return parseHex(hex);
  }

  /**
   * Returns the current effective gas price in wei (base fee + suggested
   * priority tip). Tracks the EIP-1559 fee market — the value adjusts ±12.5%
   * per block based on parent gas usage vs. the 15M target.
   */
  async getGasPrice(): Promise<bigint> {
    const hex = await this.rpc.call<string>("eth_gasPrice");
    return BigInt(hex);
  }

  /**
   * Returns a suggested EIP-1559 priority fee (tip) in wei. Use this to fill
   * `maxPriorityFeePerGas` on a Type-2 transaction; derive the base-fee
   * portion from `getFeeHistory()` or the parent block's `baseFeePerGas`.
   */
  async getMaxPriorityFeePerGas(): Promise<bigint> {
    const hex = await this.rpc.call<string>("eth_maxPriorityFeePerGas");
    return BigInt(hex);
  }

  /**
   * Returns base-fee history and gas-usage ratios for the last `blockCount`
   * blocks. `newestBlock` is a hex height or `"latest"`. `rewardPercentiles`
   * requests per-block tip percentiles (e.g. `[25, 50, 75]`); pass `undefined`
   * to omit. `baseFeePerGas` returns `blockCount + 1` entries — the trailing
   * entry is the predicted base fee for the next block. Used by wallets to
   * model `maxFeePerGas` and `maxPriorityFeePerGas`.
   */
  async getFeeHistory(
    blockCount: number,
    newestBlock: string = "latest",
    rewardPercentiles?: number[],
  ): Promise<FeeHistory> {
    const params: unknown[] = [
      `0x${blockCount.toString(16)}`,
      newestBlock,
      rewardPercentiles ?? [],
    ];
    return this.rpc.call<FeeHistory>("eth_feeHistory", params);
  }

  // Node status and network info

  /** The node's own report: state, roles, health, height, peers, TEE and iroh, and the DIDs it runs as. */
  async nodeInfo(): Promise<NodeStatusReport> {
    return this.rpc.call<NodeStatusReport>("tenzro_getNodeStatus");
  }

  async getStatus(): Promise<NodeStatus> {
    return this.rpc.get<NodeStatus>("/status");
  }

  async totalSupply(): Promise<string> {
    return this.rpc.call<string>("tenzro_totalSupply");
  }

  async peerCount(): Promise<number> {
    const hex = await this.rpc.call<string>("tenzro_peerCount");
    return parseHex(hex);
  }

  /**
   * Gets the network metrics snapshot.
   *
   * Returns the gossip counters from `tenzro_network::NetworkMetrics` and
   * the number of peers the node gossips with directly.
   */
  async getNetworkStats(): Promise<NetworkStats> {
    return this.rpc.call<NetworkStats>("tenzro_getNetworkStats");
  }

  /**
   * Whether the node is behind the network tip. The node answers `false`, or
   * `{syncing: true, startingBlock, currentBlock, highestBlock}` while it
   * catches up.
   */
  async isSyncing(): Promise<boolean> {
    const r = await this.rpc.call<false | { syncing: boolean }>("tenzro_syncing");
    return r !== false && r !== null && typeof r === "object" && r.syncing === true;
  }

  async isConnected(): Promise<boolean> {
    try {
      await this.rpc.call<string>("eth_chainId");
      return true;
    } catch {
      return false;
    }
  }

  async health(): Promise<HealthResponse> {
    return this.rpc.get<HealthResponse>("/health");
  }

  /**
   * Gets the finalized block height.
   * @returns Finalized block number
   */
  async getFinalizedBlock(): Promise<number> {
    const hex = await this.rpc.call<string>("tenzro_getFinalizedBlock");
    return parseHex(hex);
  }

  /**
   * Exports the node configuration.
   * @returns Node configuration object
   */
  async exportConfig(): Promise<any> {
    return this.rpc.call("tenzro_exportConfig");
  }

  /**
   * Gets transaction history for an address.
   * @param address - The address to query
   * @param limit - Optional maximum number of transactions to return (at most 100)
   * @param cursor - The previous page's `cursor`, to continue
   * @returns `{ address, transactions, cursor, total, kept, indexed_from_height }`, newest first
   */
  async getTransactionHistory(address: string, limit?: number, cursor?: string): Promise<any> {
    return this.rpc.call("tenzro_getTransactionHistory", [{ address, limit, cursor }]);
  }

  /**
   * Lists the paid calls the node served or routed, newest first: the work
   * as the node recorded it (model, units, serving node, hardware tier,
   * latency) and, for a ledger settlement, its fee, burn and treasury leg
   * from the chain.
   * @param query - Optional filters and paging: `work_class`, `provider`, `payer`, `from_ms`, `to_ms`, `cursor`, `limit`
   * @returns `{ settlements, cursor, recorded, kept, scope }`
   */
  async listSettlements(query: {
    work_class?: string;
    provider?: string;
    payer?: string;
    from_ms?: number;
    to_ms?: number;
    cursor?: string;
    limit?: number;
  } = {}): Promise<any> {
    return this.rpc.call("tenzro_listSettlements", [query]);
  }

  /**
   * The provider legs this node owes for calls it forwarded, each queued,
   * pending, settled or failed with its attempts.
   * @returns `{ legs, cursor }`
   */
  async listNetworkLegs(query: { status?: string; provider?: string; limit?: number; cursor?: string } = {}): Promise<any> {
    return this.rpc.call("tenzro_listNetworkLegs", query);
  }

  /** Drives a failed provider leg again under the same payment id, so it never pays twice (the node's operator). */
  async retryNetworkLeg(paymentId: string): Promise<any> {
    return this.rpc.call("tenzro_retryNetworkLeg", { payment_id: paymentId });
  }

  /**
   * Lists this node and every peer whose signed announcement it holds.
   * @returns `{ peers: [{ peer_id, account, machine_did, roles, hardware_tier, identity_anchor, region, region_source, version }] }`
   */
  async listPeers(): Promise<any> {
    return this.rpc.call("tenzro_listPeers");
  }

  /**
   * A provider's standing on chain, its announced price cards, and its
   * settled count, value and p50/p95 latency over 24 hours and 7 days.
   * @param provider - The provider's account address
   * @returns `{ provider, standing, reputation, price_cards, settled }`
   */
  async getProviderScorecard(provider: string): Promise<any> {
    return this.rpc.call("tenzro_getProviderScorecard", [{ provider }]);
  }

  /**
   * Settlement activity on the chain by reward epoch, newest first.
   * @param epochs - How many of the latest epochs (default 24, at most 168)
   * @returns `{ current_epoch, kept_from_epoch, epochs, totals }`
   */
  async getNetworkActivity(epochs?: number): Promise<any> {
    return this.rpc.call("tenzro_getNetworkActivity", [{ epochs }]);
  }

  /**
   * A short inference a sponsoring agent pays for, on a node that offers it.
   * @param request - `model`, `input`, `sponsor` (the agent's DID) and optional `max_tokens`
   * @returns `{ provider, model, output, units, cost, sponsor, tx_hash, pay_ref }`
   */
  async sponsoredInference(request: {
    model: string;
    input: string;
    sponsor: string;
    max_tokens?: number;
  }): Promise<any> {
    return this.rpc.call("tenzro_sponsoredInference", [request]);
  }

  // Getters

  get endpoint(): string {
    return this.config.endpoint;
  }

  get apiEndpoint(): string {
    return this.rpc.getApiEndpoint();
  }

  get chainId(): number | undefined {
    return this.config.chainId;
  }
}

/**
 * Parse a hex string (with or without 0x prefix) to a number. Anything that
 * is not a hex quantity throws.
 */
function parseHex(hex: string): number {
  if (typeof hex !== "string" || !/^(0x)?[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`${JSON.stringify(hex)} is not a hex quantity`);
  }
  return parseInt(hex.startsWith("0x") ? hex.slice(2) : hex, 16);
}
