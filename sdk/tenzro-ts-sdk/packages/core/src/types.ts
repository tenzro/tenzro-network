

// Primitive types
export type Hash = string; // Hex-encoded hash
export type Address = string; // Base58-encoded address
export type Signature = string; // Hex-encoded signature
export type BlockHeight = number;
export type Nonce = number;
export type Timestamp = number;
export type ChainId = number;

// Wallet types
export interface WalletInfo {
  wallet_id: string;
  address: Address;
  public_key: string;
  key_type: "ed25519" | "secp256k1";
  threshold: number;
  total_shares: number;
}

export enum WalletType {
  Standard = "Standard",
  MultiSig = "MultiSig",
  Agent = "Agent",
  Contract = "Contract",
}

// Model availability — where the model can be used from
export type ModelAvailability = "local" | "downloaded" | "downloadable" | "network";

// Model pricing info (TNZO per token)
export interface ModelPricing {
  inputPerToken: number;
  outputPerToken: number;
  currency: string;
}

// Model types
export interface ModelInfo {
  id: string;
  name: string;
  version: string;
  modality: ModelModality;
  parameters: ModelParameters;
  provider: string;
  status: ModelStatus;
  availability?: ModelAvailability;
  pricing?: ModelPricing;
  pricingConfig: PricingConfig;
  metadata?: Record<string, string>;
  /**
   * Whether the model accepts image input (vision-language). When true,
   * `mmproj` carries the projector loaded via llama.cpp `--mmproj`.
   */
  multimodal?: boolean;
  /** Multimodal projector for vision-capable models; absent for text-only. */
  mmproj?: MmprojSpec;
  /**
   * Catalog-recommended serving profile (sampler defaults, chat-template
   * requirement, reasoning default). Returned by `tenzro_modelMetadata`.
   */
  serving?: ServingProfile;
  /**
   * BLAKE3 content address of the artifact bytes (32-byte array), when known.
   * This is the key iroh-blobs indexes by, so it is what a neighbour uses to
   * fetch the weights over the peer network. Absent for models with no local
   * downloadable artifact.
   */
  blake3_hash?: number[];
  /**
   * `tenzro://model/<id>@<blake3>` URI for this artifact when it has a content
   * address. Lets clients request the model by content hash over the peer
   * network instead of by HuggingFace repo path.
   */
  tenzro_uri?: string;
  /** Peers that can serve this artifact over `tenzro://`, freshest last. */
  peer_hints?: PeerHintRecord[];
}

/**
 * A peer-fetch hint carried on {@link ModelInfo}. Names a `tenzro://` blob a
 * neighbour can fetch the artifact from, plus the canonical SHA-256 for a
 * transport-independent integrity check.
 */
export interface PeerHintRecord {
  /** `tenzro://blob/<blake3>` or `tenzro://model/<id>@<blake3>` URI. */
  tenzro_uri: string;
  /** Canonical SHA-256 of the artifact bytes (hex), verified after transfer. */
  sha256_hex?: string;
}

/** Multimodal projector descriptor for a vision-capable model. */
export interface MmprojSpec {
  /** Projector filename within the model's HF repo (e.g. `mmproj-F16.gguf`). */
  filename: string;
}

/**
 * Catalog-recommended serving configuration. Mirrors the `serving` object
 * from `tenzro_modelMetadata`. These are the model author's recommended
 * defaults; per-request parameters override them.
 */
export interface ServingProfile {
  temperature: number;
  top_p: number;
  top_k: number;
  min_p: number;
  presence_penalty: number;
  jinja_required: boolean;
  reasoning_default: boolean;
}

export interface ModelLoadInfo {
  active_requests: number;
  max_concurrent: number;
  utilization_percent: number;
  load_level: string;
}

export interface ModelEndpoint {
  model_name: string;
  model_id: string;
  instance_id: string;
  mcp_endpoint: string;
  location: string;
  /** iroh EndpointId of the serving node (hex-encoded); the address it is reached by */
  iroh_endpoint_id?: string;
  provider_name: string;
  status: string;
  availability?: ModelAvailability;
  pricing?: ModelPricing;
  load?: ModelLoadInfo;
}

export enum ModelModality {
  Text = "Text",
  Image = "Image",
  Audio = "Audio",
  Video = "Video",
  Multimodal = "Multimodal",
}

export interface ModelParameters {
  maxTokens: number;
  contextWindow: number;
  temperature: number;
  topP: number;
  topK?: number;
  frequencyPenalty?: number;
  presencePenalty?: number;
}

export enum ModelStatus {
  Pending = "Pending",
  Active = "Active",
  Inactive = "Inactive",
}

// Inference types
export interface InferenceRequest {
  id: string;
  modelId: string;
  input: string;
  parameters: InferenceParameters;
  requester: Address;
  maxPrice: string;
  /** The verification the answer must carry. */
  verification: 'none' | 'receipt' | 'optimistic' | 'tee';
  metadata?: InferenceMetadata;
  createdAt: Timestamp;
}

export interface InferenceResponse {
  id: string;
  requestId: string;
  output: string;
  provider: string;
  model: string;
  tokensUsed: number;
  cost: string;
  latencyMs: number;
  metadata?: InferenceMetadata;
  completedAt: Timestamp;
}

/** `tenzro_inferenceRequest`: one completion run on the node, with its bill and receipt. */
export interface InferenceResult {
  model_id: string;
  output: string;
  /** The model's reasoning text, when it produced any. */
  thinking: string | null;
  input_tokens: number;
  output_tokens: number;
  generation_time_ms: number;
  tokens_per_second: number;
  /** What the call cost, wei, decimal string. */
  cost_wei: string;
  /** How the cost settled. */
  settlement: unknown;
  /** `local` when this node served it. */
  provider: string;
  /** The signed inference receipt, when the node signs one. */
  tenzro_receipt: unknown;
  /** The verification commitment, when one was asked for. */
  commitment: unknown;
}

export interface InferenceParameters {
  maxTokens?: number;
  temperature?: number;
  topP?: number;
  topK?: number;
  stopSequences?: string[];
  stream?: boolean;
}

export interface InferenceMetadata {
  teeAttestation?: string;
  proofOfInference?: string;
  zkProof?: string;
  [key: string]: string | undefined;
}

// Pricing types
export interface PricingConfig {
  model: PricingModel;
  basePrice: string;
  pricePerToken: string;
  currency: string;
  discounts?: Record<string, string>;
}

export enum PricingModel {
  PerToken = "PerToken",
  PerRequest = "PerRequest",
  Subscription = "Subscription",
  PayAsYouGo = "PayAsYouGo",
}

// Provider types
export interface InferenceProvider {
  id: string;
  address: Address;
  name: string;
  models: string[];
  capacity: ProviderCapacity;
  status: ProviderStatus;
  reputation: number;
  totalInferences: number;
  pricingConfig: PricingConfig;
  teeEnabled: boolean;
  metadata?: Record<string, string>;
}

export interface ProviderCapacity {
  totalGpu: number;
  availableGpu: number;
  maxConcurrentRequests: number;
  currentLoad: number;
}

export enum ProviderStatus {
  Online = "Online",
  Offline = "Offline",
  Busy = "Busy",
  Maintenance = "Maintenance",
}

// Settlement types
/** A payer's signature over one payment, as the ledger checks it on `PayerSettle`. */
export interface PaymentAuthorization {
  /** The payer's P-256 key `x || y`, hex. */
  public_key: string;
  /** The composite signature: the P-256 leg (raw or a passkey's WebAuthn form), plus the ML-DSA-65 leg when enrolled. */
  signature: unknown;
  /** Ceiling the payer signed, in the smallest unit (decimal string). */
  max_amount: string;
  asset: string;
  /**
   * What the payment pays for: the request digest, the payee's quote digest and USD price (zero when unquoted),
   * and the application margin the payer agrees to, if any.
   */
  binding: {
    request_digest: string;
    quote_digest: string;
    usd_e6: number | bigint;
    app_margin?: { app_wallet: string; margin_bps: number } | null;
  };
}

/** A payer's signed consent to one payment, as payment-taking calls carry it under `payment`. */
export interface PayerPayment {
  payer: Address;
  /** Idempotency key the payer signed; each settles once. */
  payment_id: string;
  authorization: PaymentAuthorization;
}

/** `tenzro_settle`: settle `amount` to `payee` with the payer's signed `payment`. */
export interface SettlementParams {
  payee: Address;
  /** Wei, decimal string. */
  amount: string;
  payment: PayerPayment;
}

/** A settlement submitted to the ledger as a `PayerSettle` transaction. */
export interface LedgerSettlement {
  tx_hash: string;
  /** `settled` once it executed, `pending` while it has not. */
  status: "settled" | "pending";
  /** What the payer was debited (wei, decimal). */
  amount: string;
  network_fee: string;
  payee_credit: string;
  payer: Address;
  payee: Address;
  payment_id: string;
}

export interface SettlementRequest {
  id: string;
  serviceType: ServiceType;
  payer: Address;
  payee: Address;
  amount: string;
  assetId: string;
  paymentIntent: PaymentIntent;
  serviceProof?: string;
  escrowId?: string;
  metadata?: Record<string, string>;
  createdAt: Timestamp;
}

export enum SettlementStatus {
  Pending = "Pending",
  Confirmed = "Confirmed",
  Finalized = "Finalized",
  Failed = "Failed",
  Refunded = "Refunded",
}

export enum ServiceType {
  Inference = "Inference",
  Storage = "Storage",
  Compute = "Compute",
  DataAccess = "DataAccess",
  AgentService = "AgentService",
}

export enum PaymentIntent {
  Immediate = "Immediate",
  Escrow = "Escrow",
  Streaming = "Streaming",
  Deferred = "Deferred",
}

export interface ServiceProof {
  proofType: string;
  proofData: string;
  signature: Signature;
  timestamp: Timestamp;
}

export interface AgentConfig {
  maxConcurrentTasks: number;
  allowedServices: ServiceType[];
  budget: string;
  trustThreshold: number;
  metadata?: Record<string, string>;
}

export interface Capability {
  name: string;
  version: string;
  description: string;
  parameters?: Record<string, string>;
}

/** A2A v1.0 task state, e.g. `TASK_STATE_COMPLETED`. */
export type A2aTaskState =
  | "TASK_STATE_SUBMITTED"
  | "TASK_STATE_WORKING"
  | "TASK_STATE_COMPLETED"
  | "TASK_STATE_FAILED"
  | "TASK_STATE_CANCELED"
  | "TASK_STATE_INPUT_REQUIRED"
  | "TASK_STATE_REJECTED"
  | "TASK_STATE_AUTH_REQUIRED";

/** A2A v1.0 task. */
export interface A2aTask {
  id: string;
  contextId?: string;
  status: { state: A2aTaskState; message?: unknown; timestamp?: string };
  artifacts?: unknown[];
  history?: unknown[];
  metadata?: Record<string, unknown>;
}

/** A2A v1.0 `SendMessage` result: exactly one of `task` or `message`. */
export interface A2aSendMessageResponse {
  task?: A2aTask;
  message?: Record<string, unknown>;
}

/** Build A2A v1.0 `SendMessage` params carrying one user text part. */
export function a2aTextMessage(text: string, messageId: string): Record<string, unknown> {
  return {
    message: {
      messageId,
      role: "ROLE_USER",
      parts: [{ text }],
    },
  };
}

/** A signed audit record: the exact JSON bytes signed, and the signature. */
export interface SignedAuditBlob {
  /** Hex of the JSON body, exactly as signed. */
  body: string;
  /** Hex of the node's session signature (JSON). */
  signature: string;
}

/** Inclusion of one leaf in a session's Merkle Mountain Range. */
export interface AgentAuditMmrProof {
  index: number;
  size: number;
  siblings: string[];
  peaks: string[];
}

/** One session's line in an epoch commitment. */
export interface AgentAuditSessionLeaf {
  session_id: string;
  mmr_root: string;
  count: number;
}

/** Inclusion of one session in an epoch tree. */
export interface AgentAuditEpochProof {
  leaf: AgentAuditSessionLeaf;
  index: number;
  count: number;
  siblings: string[];
}

/** An audit entry with its proof to the committed epoch root. */
export interface AgentAuditProof {
  entry: SignedAuditBlob;
  mmr: AgentAuditMmrProof;
  epoch_proof: AgentAuditEpochProof;
  epoch: number;
  committer: string;
}

/** `tenzro_getAgentAuditCommit` response: the root recorded on chain. */
export interface AgentAuditCommitResponse {
  committer: string;
  epoch: number | null;
  record: {
    root: string;
    sessions: number;
    entries_ref: string;
    recorded_at_ms: number;
  } | null;
  last_epoch: number | null;
}

/** `tenzro_verifyAgentAuditAttestation` response. */
export interface AgentAuditAttestation {
  committer: string;
  epoch: number;
  root: string;
  sessions: number;
  attestation: {
    attested: boolean;
    /** Why there is no attestation, when `attested` is false. */
    reason?: string;
    machine_did?: string;
    ek_name?: string;
    pcr_digest?: string;
    reset_count?: number;
    firmware_version?: number;
  };
}

/** `tenzro_getAgentQuarantine` response. */
export interface AgentQuarantineStatus {
  agent_did: string;
  quarantined: boolean;
  on_chain: {
    controller_did: string;
    by: string;
    reason_code: number;
    evidence_hash: string | null;
    at_ms: number;
  } | null;
}

/** The result of checking an audit entry against chain state. */
export interface AgentAuditVerification {
  /** The decoded entry. */
  entry: Record<string, unknown>;
  /** The epoch root the entry reaches. */
  epochRoot: string;
  /** The root recorded on chain for the committer and epoch. */
  onchainRoot: string;
  epoch: number;
  committer: string;
}

// Governance types

/** Where a proposal is in its life. */
export type ProposalStatus = "voting" | "passed" | "queued" | "vetoed" | "rejected" | "executed" | "contested";

/** Standard; expedited (a shorter window at a higher threshold); ratify
 * (a contested proposal's second vote: three quarters, thirty-day timelock);
 * or security_fix (a protocol upgrade resting on an upheld fault or a
 * vulnerability commitment, on the expedited timetable). */
export type ProposalTrack = "standard" | "expedited" | "ratify" | "security_fix";

/** The typed preimage a privileged transaction is signed over. */
export interface DecodedAction {
  class: "governance" | "guardian" | "issuer" | "terms" | "step_up";
  /** Hex SHA-256 of `preimage_hex`: the digest signed. */
  digest: string;
  preimage_hex: string;
  preimage: Record<string, unknown>;
  /** What the action does, generated from the preimage. */
  description: string[];
}

/**
 * What a transaction would do, executed by a node on a copy of its state
 * after one block (`tenzro_decodeAction` with a whole transaction).
 */
export interface TransactionEffects {
  height: number;
  block_hash: string;
  outcome: "applied" | "reverted" | "rejected";
  error: string | null;
  gas_used: number;
  balance_changes: { account: string; before: string; after: string }[];
  logs: { address: string; topics: string[]; data: string }[];
  /** Hex SHA-256 over all of the above; another node reproduces it for the same block. */
  digest: string;
}

/** One validator machine's quote of a binary. */
export interface UpgradeReadySignal {
  validator: string;
  machine_did: string;
  pcr_digest: string;
  height: number;
}

/** A protocol upgrade's activation, as consensus scheduled it. */
export interface UpgradeActivation {
  proposal_id: string;
  version: string;
  code_hash: string;
  readiness_met_height: number;
  activation_height: number;
}

/** How far a binary's readiness has got. Stake amounts are decimal strings. */
export interface UpgradeReadiness {
  code_hash: string;
  ready_stake: string;
  total_bonded: string;
  ready_bps: number;
  required_bps: number;
  met: boolean;
  signals: UpgradeReadySignal[];
  scheduled: UpgradeActivation | null;
  this_node_runs_it: boolean;
}

/** A proposal as consensus holds it. `action` is tagged by `action`. */
export interface OnChainProposal {
  id: string;
  proposer: string;
  track: ProposalTrack;
  eta_ms: number | null;
  action: { action: string; [field: string]: unknown };
  created_ms: number;
  voting_ends_ms: number;
  status: ProposalStatus;
  /** When it entered the timelock. */
  queued_ms: number | null;
  /** How far the holders' veto escrow has stretched its timelock. */
  veto_extension_ms: number;
  /** Distinct aged human roots that raised a concern while it was queued. */
  concerns: number;
  /** Whether the concerns doubled its timelock (once only). */
  concern_doubled: boolean;
}

/** Running vote totals, in units of bonded stake (decimal strings). */
export interface ProposalTally {
  yes: string;
  no: string;
  total_eligible: string;
}

export interface ProposalView {
  proposal: OnChainProposal;
  /** The action's kind, e.g. "policy_update". */
  kind: string;
  tally: ProposalTally;
  /** TNZO holders have locked against it in its veto escrow (decimal string). */
  veto_locked: string;
}

/** One page of proposals, newest first. */
export interface ProposalPage {
  proposals: ProposalView[];
  total: number;
  /** Pass as `before` for the next page; null on the last. */
  next: number | null;
}

/** The weight an account votes with: its bonded stake. */
/** A governed network parameter as `tenzro_getNetworkParams` reports it. */
export interface NetworkParam {
  key: string;
  /** Decimal strings: several values exceed a JavaScript number. */
  value: string;
  genesis: string;
  min: string;
  max: string;
  /** Direction that makes the rule stricter: `up`, `down` or `neither`. */
  tightens: "up" | "down" | "neither" | "retire";
  /**
   * Set on a capture guard: the direction that tightens it. A change the
   * other way moves at most one step and waits
   * `governance.guard_loosening_grace_epochs` before it applies.
   */
  capture_guard: "up" | "down" | null;
  description: string;
  /** An enacted change waiting for its epoch, or null. */
  pending: { value: string; activates_epoch: number; proposal_id: string } | null;
}

/** Every governed network parameter, and the epoch the chain is in. */
export interface NetworkParams {
  epoch: number;
  params: NetworkParam[];
}

/** The state of a feature a status or switch lever governs. */
export type LeverStatus = "enabled" | "paused" | "retired";

/** A governance lever as `tenzro_listLevers` reports it. */
export interface Lever {
  key: string;
  /** The area it governs: the key up to its first dot. */
  area: string;
  /** `status`: enabled, paused or retired; `switch`: on or off; `value`: an amount or cap. */
  kind: "status" | "switch" | "value";
  /** Decimal strings: several values exceed a JavaScript number. */
  value: string;
  /** Null for a `value` lever. */
  status: LeverStatus | null;
  genesis: string;
  min: string;
  max: string;
  tightens: "up" | "down" | "neither" | "retire";
  description: string;
  /** An enacted change waiting for the epoch it activates in, or null. */
  pending: { value: string; status: LeverStatus | null; activates_epoch: number; proposal_id: string } | null;
  /**
   * The epoch a protocol guardian pause on this status lever lasts until, or
   * null when none is running. While it runs `status` reads `paused`.
   */
  guardian_pause_until_epoch: number | null;
}

/** A bridge route's mode after its own record and its transport's lever. */
export interface BridgeRouteLever {
  adapter: string;
  source_chain: string;
  mode: "open" | "disabled" | "paused";
  reason: string | null;
  /** The transport's status lever key, or null when it has none. */
  transport_lever: string | null;
}

/** Every governance lever, and the epoch the chain is in. */
export interface Levers {
  epoch: number;
  total: number;
  levers: Lever[];
  bridge_routes: BridgeRouteLever[];
}

export interface VotingPower {
  address: string;
  voting_power: string;
  /** Network-wide bonded stake a tally is measured against. */
  total_bonded: string;
}

// Blockchain types
export interface Block {
  header: BlockHeader;
  transactions: Transaction[];
  hash: Hash;
}

/** A block as `tenzro_getBlock` and `tenzro_getBlockRange` report it. */
export interface BlockSummary {
  height: number;
  hash: string;
  prev_hash: string;
  state_root: string;
  tx_root: string;
  /** Block time, Unix milliseconds. */
  timestamp: number;
  proposer: string;
  tx_count: number;
  gas_used: number;
  gas_limit: number;
}

/**
 * Paginated block range response from `tenzro_getBlockRange`.
 *
 * Each block summary is a free-form object (height, hash, prev_hash,
 * state_root, tx_root, timestamp millis, proposer, tx_count, gas_used,
 * gas_limit). `nextHeight` and `moreAvailable` drive pagination: a sync
 * loop keeps requesting until `moreAvailable` is false. `moreAvailable`
 * reflects whether the chain has further blocks beyond `nextHeight`,
 * independent of the requested `endHeight`, so it is safe to step over
 * pruning gaps.
 */
export interface BlockRange {
  blocks: Record<string, unknown>[];
  nextHeight: BlockHeight;
  moreAvailable: boolean;
  localTip: BlockHeight;
}

export interface BlockHeader {
  height: BlockHeight;
  timestamp: Timestamp;
  previousHash: Hash;
  stateRoot: Hash;
  txRoot: Hash;
  proposer: Address;
  signature: Signature;
  chainId: ChainId;
  /**
   * EIP-1559 base fee per gas in wei (hex-encoded). `null` for pre-fee-market
   * blocks. Use `eth_feeHistory` for time-series base-fee modeling.
   */
  baseFeePerGas?: string | null;
}

/**
 * EIP-1559 fee-history payload from `eth_feeHistory`.
 *
 * `baseFeePerGas` has length `blockCount + 1` — the trailing entry is the
 * predicted base fee for the next block, suitable as the floor of a Type-2
 * transaction's `maxFeePerGas`. `reward[i][j]` is the j-th requested
 * percentile of priority tips paid in block `oldestBlock + i`; absent when
 * no percentiles were requested.
 */
export interface FeeHistory {
  oldestBlock: string;
  baseFeePerGas: string[];
  gasUsedRatio: number[];
  reward?: string[][];
}

export interface Transaction {
  hash: Hash;
  txType: TransactionType;
  from: Address;
  to?: Address;
  amount: string;
  fee: string;
  nonce: Nonce;
  data?: string;
  signature: Signature;
  blockHeight?: BlockHeight;
  timestamp: Timestamp;
}

export enum TransactionType {
  Transfer = "Transfer",
  InferenceRequest = "InferenceRequest",
  Settlement = "Settlement",
  AgentRegistration = "AgentRegistration",
  GovernanceVote = "GovernanceVote",
  ContractDeploy = "ContractDeploy",
  ContractCall = "ContractCall",
}

// Account types
export interface Account {
  address: Address;
  balance: string;
  nonce: Nonce;
  state: AccountState;
  createdAt: Timestamp;
}

export interface AccountState {
  storageRoot: Hash;
  codeHash?: Hash;
  metadata?: Record<string, string>;
}

// Network types
export interface NetworkInfo {
  chainId: ChainId;
  blockHeight: BlockHeight;
  peers: number;
  version: string;
  networkName: string;
  genesisHash: Hash;
}

export interface PeerInfo {
  id: string;
  address: string;
  version: string;
  connectedAt: Timestamp;
  latency: number;
}

export interface NodeInfo {
  nodeId: string;
  version: string;
  networkInfo: NetworkInfo;
  peers: PeerInfo[];
  uptime: number;
}

export interface NodeStatus {
  node_state: string;
  role: string;
  health: string;
  block_height: number;
  peer_count: number;
  uptime_secs: number;
}

/** What `tenzro_getNodeStatus` reports. */
export interface NodeStatusReport {
  /** `Created`, `Starting`, `Running`, `Stopping` or `Stopped`. */
  state: string;
  roles: unknown;
  /** `Healthy`, `Degraded` or `Unhealthy`. */
  health_status: string;
  uptime_secs: number;
  block_height: number;
  peer_count: number;
  data_dir: string;
  tee_capable: boolean;
  tee_vendor: string | null;
  iroh_enabled: boolean;
  iroh_endpoint_id: string | null;
  iroh_alpns: string[];
  hidden_gpus: string[];
  /** Disk guard status. */
  disk: Record<string, unknown>;
  machine_did: string | null;
  operator_did: string | null;
  /** The wallet this node is paid at, hex. */
  payee: string | null;
}

export interface HealthResponse {
  status: string;
  version: string;
  verification_service: string;
}

/**
 * Snapshot of network metrics exposed by `tenzro_getNetworkStats`.
 *
 * Gossip counters are monotonically-increasing totals since process start;
 * `peers_connected` is an instantaneous value.
 */
export interface NetworkStats {
  /** `false` when the network service has not been initialized. */
  available: boolean;
  /** Set when `available` is `false`. */
  reason?: string;
  gossip_rejected_invalid?: number;
  gossip_rejected_duplicate?: number;
  gossip_published?: number;
  gossip_accepted?: number;
  /** Peers the node gossips with directly. */
  peers_connected?: number;
}

export interface VerificationResponse {
  valid: boolean;
  details?: string;
  verified_at?: Timestamp;
}

// Identity types (TDIP — Tenzro Decentralized Identity Protocol)
// Supports both human and machine identities natively

export enum IdentityType {
  Human = "Human",
  Machine = "Machine",
}

export interface IdentityInfo {
  did: string;
  status: string;
  display_name: string;
  is_human: boolean;
  is_machine: boolean;
  key_count: number;
  service_count: number;
  public_keys: Array<{ key_id: string; key_type: string; public_key: string }>;
  credentials: Array<{ credential_type: string; issuer: string; subject: string; issued_at: string }>;
  services: Array<{ id: string; service_type: string; endpoint: string }>;
  metadata: Record<string, unknown>;
}

export interface DidDocument {
  "@context": string[];
  id: string;
  controller?: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  keyAgreement: string[];
  service: DidService[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: Record<string, unknown>;
}

export interface DidService {
  id: string;
  type: string;
  serviceEndpoint: string;
}

// MicroNode types (zero-install full network participants)

export interface MicroNodeCapabilities {
  inference: boolean;
  payments: boolean;
  agent_collaboration: boolean;
  mcp_tools: boolean;
  task_execution: boolean;
  chain_query: boolean;
  smart_contracts: boolean;
  tee_services: boolean;
  bridge: boolean;
  governance: boolean;
}

export interface MicroNodeNetworkEndpoints {
  rpc: string;
  mcp: string;
  a2a: string;
}

export interface JoinAsMicroNodeResponse {
  identity: {
    did: string;
    identity_type: string;
    display_name: string;
    status: string;
  };
  wallet: {
    wallet_id: string;
    address: string;
    public_key: string;
  };
  capabilities: MicroNodeCapabilities;
  origin: string;
  participant_type: string;
  role: string;
  network: MicroNodeNetworkEndpoints;
  message: string;
}

// Payment types (MPP / x402)

/**
 * A payment challenge as the node issues it (`tenzro_createPaymentChallenge`).
 * `extra` carries the chain id the node stamped, and the payee's quote digest
 * and USD price when the challenge was quoted; the payer's signature covers
 * them.
 */
export interface PaymentChallenge {
  challenge_id: string;
  protocol: string;
  resource: string;
  amount: number | bigint | string;
  asset: string;
  recipient: string;
  chain?: string;
  expires_at?: string;
  extra?: Record<string, unknown>;
}

export interface PaymentReceipt {
  receiptId: string;
  protocol: string;
  amount: number;
  asset: string;
  sessionId?: string;
  payerDid?: string;
  recipientDid?: string;
  timestamp?: Timestamp;
}

// ─── Agent Marketplace ─────────────────────────────────────────────────────────

export type AgentPricingModel =
  | { type: 'free' }
  | { type: 'per_execution'; price: string }
  | { type: 'per_token'; price_per_token: string }
  | { type: 'subscription'; monthly_rate: string }
  | { type: 'revenue_share'; creator_share_bps: number };

export interface AgentCapabilityDef {
  id: string;
  name: string;
  description: string;
  input_schema?: string;
  output_schema?: string;
}

export interface AgentRuntimeRequirements {
  min_model_size?: string;
  preferred_model_id?: string;
  required_mcp_tools: string[];
  required_permissions: string[];
  estimated_cost_per_run?: string;
  requires_tee: boolean;
}

export interface AgentExample {
  description: string;
  user_input: string;
  expected_output: string;
}

// ─── AgentKit (spawn / run / download / update) ──────────────────────────────

// ─── Skills Registry ─────────────────────────────────────────────────────────

// ─── Tool Registry ───────────────────────────────────────────────────────────

// ─── Staking ─────────────────────────────────────────────────────────────────

/** A role that takes a `Stake` bond (the validator role bonds through RegisterValidator). */
export type StakingRole =
  | 'rpc'
  | 'tee'
  | 'ai'
  | 'compute'
  | 'storage'
  | 'attestor'
  | 'wallet'
  | 'catalog';

/** The capacity a bond backs, which sets the role's required stake. A wallet provider declares the passkey domain it serves. */
export type StakeCapacity =
  | 'none'
  | { accelerators: Array<'integrated' | 'consumer' | 'workstation' | 'datacentre'> }
  | { terabytes: number }
  | { domain: string };

/** One account's stake for one role. */
export interface RoleStake {
  role: string;
  /** Wei, decimal string. */
  bonded: string;
  /** The role's required stake for the declared capacity, wei. */
  required: string;
  /**
   * What a new or raised bond for that capacity must meet, wei: `required`,
   * raised when TNZO trades below `stake.bond_floor_rate_nano_usd` at the
   * safety rate so the bond keeps its USD value.
   */
  entry_required: string;
  capacity: StakeCapacity;
  unbonding: string;
  release_at_ms: number;
  /** For a serving role's stake: the SLA subject validators probe it under (`did:tenzro:role:<role>:<account hex>`); an unavailable verdict slashes the stake. A storage stake's storage claims also name it. */
  sla_subject?: string | null;
}

/** Result of `tenzro_getRoleStakes`. */
export interface RoleStakes {
  address: string;
  stakes: RoleStake[];
  totals: Array<{ role: string; bonded: string; stakers: number }>;
}

/** Result of `tenzro_getWalletProvider`. */
export interface WalletProviderStatus {
  rp_id: string;
  /** True when an account bonded for this domain and the validators' latest check found the domain's /.well-known/tenzro-provider naming it. Show a credential from this domain as coming from a staked provider only when true. */
  staked: boolean;
  /** Every account bonded for the domain, verified ones first. */
  providers: Array<{
    account: string;
    /** Wei, decimal string. */
    bonded: string;
    verified: boolean;
    /** The closed epoch of the latest frozen check, if one is recent enough to count. */
    verdict_epoch: number | null;
  }>;
}

// ─── Bridge ────────────────────────────────────────────────────────────────

/** One direction of a CCIP lane's token bucket. */
export interface BridgeLaneBucket {
  /** What the bucket holds now, smallest unit */
  tokens: string;
  /** Most it holds */
  capacity: string;
  /** Refill per second */
  rate: string;
  /** Unix second of the last update */
  last_updated: number;
}

/** A governed bridge route as `tenzro_listBridgeRoutes` publishes it. */
export interface BridgeRouteInfo {
  /** Route key, `bridge_route:<transport>:<chain>` */
  key: string;
  /** Transport: `ccip`, `ibc`, `deposit` or `contract` */
  adapter: string;
  /** Chain family: `evm`, `solana`, `cosmos`, `bitcoin`, `stellar`, `sui`, `aptos` or `ton` */
  family: string;
  /** External chain name */
  source_chain: string;
  /** Per-transfer and per-epoch caps, and this epoch's usage */
  mint_limit: {
    per_mint: string;
    per_epoch: string;
    network_per_mint?: string | null;
    network_per_epoch?: string | null;
    epoch: number;
    minted_this_epoch?: string | null;
    remaining_this_epoch?: string | null;
  };
  /** CCIP lane: the on-ramp version whose message layout the lane reads, and its token buckets per direction as they stand now; null for routes without a lane */
  lane?: {
    version: '2.0.0' | '1.6.0' | '1.5.0';
    outbound: BridgeLaneBucket;
    inbound: BridgeLaneBucket;
  } | null;
  /** TNZO locked on Tenzro for the route, and the representation outstanding on the external chain */
  supply: { locked: string; bridged: string };
  /** IBC routes: the version, Tenzro's client and packet identifiers, and (classic) where its connection and channel handshakes stand */
  ibc?: {
    version: 'classic' | 'v2';
    client_id: string;
    packet_id: string;
    connection?: [string, 'INIT' | 'TRYOPEN' | 'OPEN' | null] | null;
    channel?: [string, 'INIT' | 'TRYOPEN' | 'OPEN' | null] | null;
  } | null;
  /** What the route carries: `open`, `disabled` (winding down) or `paused` */
  mode: 'open' | 'disabled' | 'paused';
  /** Route fields genesis left as placeholders and no vote has filled yet */
  placeholders: string[];
  /** Why governance cannot open the route yet, if it cannot */
  open_refusal?: string | null;
  /** The light client's governed anchor, if the route requires one */
  light_client?: Record<string, unknown> | null;
  /** Where the light client stands; null until it is bootstrapped */
  light_client_head?: LightClientHead | null;
  /** Whether the route passes the route rules */
  enforced: boolean;
  /** Why it does not, if it does not */
  violation?: string | null;
  [field: string]: unknown;
}

/** Where a route's light client stands. */
export interface LightClientHead {
  kind: string;
  /** Latest finalized position of the external chain it verified. */
  finalized: number;
  /** Committee period it verifies signatures for. */
  period: number;
  /** Whether it knows the next period's committee. */
  next_known: boolean;
}

// ─── Agent spend ───────────────────────────────────────────────────────────

/** A delegated agent's consensus Terms and what it has spent against them. */
export interface AgentTermsView {
  /** Agent DID */
  agent_did: string;
  /** What approved the Terms: a person's passkey or a machine's TPM / Secure Enclave key */
  root_kind: 'passkey' | 'machine';
  status: 'active' | 'quarantined' | 'revoked' | 'expired';
  /** Increments with every approved change */
  version: number;
  /** Digest of the custody challenge the root approved, hex */
  approval_digest: string;
  /** Block time of the last change, ms */
  updated_at_ms: number;
  /** The Terms exactly as chain state records them */
  terms: import('./auth').AgentTerms & Record<string, unknown>;
  /** Spend so far; amounts are decimal strings (wei, or the asset's base units) */
  spent: {
    today: string;
    this_hour: string;
    actions_today: number;
    actions_this_hour: number;
    remaining_today: string | null;
    remaining_this_hour: string | null;
    assets: { asset: string; spent_today: string; remaining_today: string | null }[];
  };
}

// ─── JSON Web Keys (RFC 7517 / RFC 9421 keyid resolution) ─────────────────

// ─── Skill Usage ──────────────────────────────────────────────────────────

// ─── Tool Usage ───────────────────────────────────────────────────────────

// ─── Agent Template Stats ─────────────────────────────────────────────────

