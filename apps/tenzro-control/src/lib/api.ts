import { invoke, Channel } from "@tauri-apps/api/core";

/* --------------------------------------------------------------------- */
/* hardware + budget                                                      */
/* --------------------------------------------------------------------- */

export type GpuClass = "None" | "AppleSilicon" | "Cuda" | "Rocm" | "IntelOrIntegrated";

/// Whether the machine can carry one role, and the sentence explaining the
/// verdict. Decided in the Rust probe so the scan screen and the role picker
/// cannot drift apart.
export interface RoleCapability {
  role: string;
  available: boolean;
  detail: string;
}

export interface CapabilityReadout {
  ram_gb: number;
  physical_cores: number;
  gpu: string;
  gpu_class: GpuClass;
  free_disk_gb: number;
  offerable_storage_gb: number;
  roles: RoleCapability[];
}

export type Fit = "fits" | "blocked" | "unsupported";

export interface ModelBudgetEntry {
  id: string;
  name: string;
  family: string;
  parameters: string;
  quantization: string;
  context_length: number;
  license: string | null;
  description: string;
  size_bytes: number;
  min_ram_gb: number;
  downloaded: boolean;
  on_disk_bytes: number;
  vision: boolean;
  moe: boolean;
  selected: boolean;
  fit: Fit;
  reason: string | null;
}

export interface BudgetReadout {
  ram_total_gb: number;
  ram_reserved_gb: number;
  ram_selected_gb: number;
  ram_available_gb: number;
  disk_total_gb: number;
  disk_reserved_gb: number;
  disk_downloads_gb: number;
  disk_storage_gb: number;
  disk_available_gb: number;
  models: ModelBudgetEntry[];
}

/* --------------------------------------------------------------------- */
/* configuration                                                          */
/* --------------------------------------------------------------------- */

/** 0 = Monday … 6 = Sunday. An empty `days` means every day. */
export interface ServingWindow {
  start_hour: number;
  end_hour: number;
  days: number[];
}

export interface Availability {
  always_on: boolean;
  windows: ServingWindow[];
}

export interface AiPricing {
  input_price_per_token_wei: number;
  output_price_per_token_wei: number;
}

export interface StoragePricing {
  capacity_gb: number;
  min_rate_wei: number;
  max_rate_wei: number;
}

export interface ComputePricing {
  rate_per_hour_wei: number;
}

export type Custody = "none" | "hardware";

export interface Identity {
  did: string;
  address: string;
  custody: Custody;
  display_name: string;
}

export interface MemoryOverride {
  reserve_gb: number | null;
  resident_ceiling_gb: number | null;
  on_demand_ceiling_gb: number | null;
}

export interface ControlConfig {
  identity: Identity;
  roles: string[];
  models: string[];
  availability: Availability;
  ai_pricing: AiPricing;
  storage_pricing: StoragePricing;
  compute_pricing: ComputePricing;
  memory: MemoryOverride;
  onboarded: boolean;
}

export interface PricingBracketView {
  id: string;
  bps: string;
  input_price_per_token_wei: string;
  output_price_per_token_wei: string;
  input_display: string;
  output_display: string;
}

/* --------------------------------------------------------------------- */
/* node + wallet                                                          */
/* --------------------------------------------------------------------- */

export interface NodeStatusView {
  state: string;
  roles: string;
  block_height: number;
  peer_count: number;
  uptime_secs: number;
  tee_capable: boolean;
  iroh_enabled: boolean;
  connectivity: string;
}

export interface RoleStakeGate {
  role: string;
  label: string;
  required_wei: string;
  required_display: string;
  /** A bond is posted against this role and covers its minimum. */
  met: boolean;
  staked_wei: string;
  staked_display: string;
  /** A stake call for this role would be accepted right now. */
  can_stake: boolean;
  shortfall_wei: string;
  shortfall_display: string;
}

/// The node's operator account: the ledger account of this machine's
/// hardware wallet key, which signs Control's native transactions.
export interface StakeAccount {
  /** Empty on a machine without a TPM or Secure Enclave. */
  address: string;
  signer: "tpm" | "secure-enclave" | "";
}

export interface WalletStatusView {
  exists: boolean;
  address: string;
  display_address: string;
  did: string;
  custody: Custody;
  balance_wei: string;
  balance_display: string;
  /** Bonded amount, which the balance does not include and a stake does not debit. */
  staked_wei: string;
  staked_display: string;
  /** Role the bond is posted against, empty when nothing is staked. */
  staked_role: string;
  /** Set once unstaking has begun. Funds unlock 7 days after this. */
  unbonding_at_ms: number | null;
  /** Roles with stake unbonding. */
  unbonding_roles: string[];
  /** The account stakes are bonded from; gates read its balance. */
  stake_account: StakeAccount;
  stake_balance_wei: string;
  stake_balance_display: string;
  node_ready: boolean;
  gates: RoleStakeGate[];
}

export interface SendReceipt {
  custody: Custody;
  from: string;
  to: string;
  amount_wei: string;
  amount_display: string;
  /** Transaction hash. */
  reference: string;
}

/* --------------------------------------------------------------------- */
/* models                                                                 */
/* --------------------------------------------------------------------- */

export interface ModelDownloadStatus {
  model_id: string;
  status: "downloading" | "completed" | "failed" | "not_started";
  progress_percent: number;
  downloaded_bytes: number;
  total_bytes: number;
  error?: string;
}

/* --------------------------------------------------------------------- */
/* forecast                                                               */
/* --------------------------------------------------------------------- */

export interface ForecastCatalogEntry {
  id: string;
  name: string;
  family: string;
  hf_repo: string;
  hf_filename: string;
  context_length: number;
  max_horizon: number;
  n_quantiles: number;
  output_name: string | null;
  batch_size: number;
  parameters: string;
  size_bytes: number;
  min_ram_gb: number;
  license: string | null;
  license_tier: string;
  description: string;
}

export interface LoadedForecaster {
  model_id: string;
  context_length: number;
  max_horizon: number;
}

export interface ForecastResult {
  point: number[];
  quantiles: number[][];
  quantile_levels: number[];
  generation_time_ms: number;
}

/* --------------------------------------------------------------------- */
/* media                                                                  */
/* --------------------------------------------------------------------- */

export type MediaGenKind = "text2image" | "image2image" | "text2video" | "image2video" | "text2audio";

export interface MediaCatalogEntry {
  id: string;
  name: string;
  kinds: string[];
  vram_gb: number;
  license: string;
}

export interface MediaOutput {
  data_url: string;
  mime: string;
  /** attoTNZO the render was metered at, decimal string. */
  cost_wei: string | null;
  output_sha256: string | null;
}

/* --------------------------------------------------------------------- */
/* assistant                                                              */
/* --------------------------------------------------------------------- */

export interface AssistantMessage {
  role: string;
  content: string;
}

export interface AssistantRequest {
  requestId?: string;
  modelId?: string;
  messages: AssistantMessage[];
  temperature?: number;
  maxTokens?: number;
}

export type AssistantEvent =
  | { kind: "start"; requestId: string; modelId: string }
  | { kind: "token"; text: string }
  | {
      kind: "done";
      requestId: string;
      inputTokens: number;
      outputTokens: number;
      tokensPerSecond: number;
      cancelled: boolean;
    }
  | { kind: "error"; requestId: string; message: string };

/* --------------------------------------------------------------------- */
/* device keys + cross-device linking                                     */
/* --------------------------------------------------------------------- */

export interface DeviceKeyInfo {
  label: string;
  public_key_hex: string;
  ml_dsa_public_key_hex: string;
  credential_id_hex: string;
}

export interface HybridSignature {
  p256_signature_hex: string;
  ml_dsa_signature_hex: string;
}

export interface CableSessionStart {
  session_id: string;
  qr_url: string;
}

export interface CableCompleteRequest {
  session_id: string;
  challenge_hex: string;
  rp_id: string;
  allow_credential_ids_hex: string[];
}

export interface CableAssertion {
  credential_id_hex: string;
  authenticator_data_hex: string;
  signature_hex: string;
  client_data_json: string;
  user_handle_hex: string | null;
}

/* --------------------------------------------------------------------- */
/* escape hatch                                                           */
/* --------------------------------------------------------------------- */

/** A read-only console call. The window never holds a credential; the
 *  Rust side refuses any method outside its read-only list. */
export interface RpcCallArgs {
  method: string;
  params: unknown;
}

/* --------------------------------------------------------------------- */
/* commands                                                               */
/* --------------------------------------------------------------------- */

export const api = {
  scanHardware: () => invoke<CapabilityReadout>("scan_hardware"),

  modelBudget: (selected: string[], storagePledgeGb: number) =>
    invoke<BudgetReadout>("model_budget", { selected, storagePledgeGb }),

  getConfig: () => invoke<ControlConfig>("get_config"),

  pricingBrackets: () => invoke<PricingBracketView[]>("pricing_brackets"),

  setRoles: (roles: string[]) => invoke<ControlConfig>("set_roles", { roles }),

  setModels: (models: string[]) => invoke<ControlConfig>("set_models", { models }),

  setAvailability: (availability: Availability) =>
    invoke<ControlConfig>("set_availability", { availability }),

  setAiPricing: (inputPricePerTokenWei: string, outputPricePerTokenWei: string) =>
    invoke<ControlConfig>("set_ai_pricing", {
      inputPricePerTokenWei,
      outputPricePerTokenWei,
    }),

  setStoragePricing: (capacityGb: number, minRateWei: string, maxRateWei: string) =>
    invoke<ControlConfig>("set_storage_pricing", { capacityGb, minRateWei, maxRateWei }),

  setComputePricing: (ratePerHourWei: string) =>
    invoke<ControlConfig>("set_compute_pricing", { ratePerHourWei }),

  completeOnboarding: () => invoke<ControlConfig>("complete_onboarding"),

  /** Takes effect on the next restart — pass `null` for a field to fall back to the node's own default. */
  setMemoryConfig: (args: {
    reserveGb: number | null;
    residentCeilingGb: number | null;
    onDemandCeilingGb: number | null;
  }) => invoke<ControlConfig>("set_memory_config", args),

  nodeStatus: () => invoke<NodeStatusView | null>("node_status"),

  restartNode: () => invoke<void>("restart_node"),

  resetLocalChain: () => invoke<void>("reset_local_chain"),

  nodeDataDir: () => invoke<string>("node_data_dir"),

  revealDataDir: () => invoke<void>("reveal_data_dir"),

  walletStatus: () => invoke<WalletStatusView>("wallet_status"),

  stakeBond: (role: string, amountWei: string) =>
    invoke<WalletStatusView>("stake_bond", { role, amountWei }),

  stakeUnbond: (role: string, amountWei: string) =>
    invoke<WalletStatusView>("stake_unbond", { role, amountWei }),

  stakeWithdraw: (role: string) =>
    invoke<WalletStatusView>("stake_withdraw", { role }),

  walletUseHardwareKey: (displayName: string) =>
    invoke<WalletStatusView>("wallet_use_hardware_key", { displayName }),

  walletSend: (to: string, amountWei: string) =>
    invoke<SendReceipt>("wallet_send", { to, amountWei }),

  modelDetails: (id: string) => invoke<unknown>("model_details", { id }),


  downloadProgress: () => invoke<ModelDownloadStatus[]>("download_progress"),

  serveModel: (id: string, visibility?: string) =>
    invoke<unknown>("serve_model", { id, visibility }),

  stopModel: (id: string) => invoke<unknown>("stop_model", { id }),

  offloadModel: (id: string) => invoke<number>("offload_model", { id }),

  forecastCatalog: () => invoke<{ models: ForecastCatalogEntry[] }>("forecast_catalog"),

  forecastList: () => invoke<{ models: { model_id: string }[] }>("forecast_list"),

  forecastLoad: (args: { modelId: string; visibility?: "public" | "gated" | "private" }) =>
    invoke<unknown>("forecast_load", args),

  forecastUnload: (modelId: string) => invoke<unknown>("forecast_unload", { modelId }),

  forecastRun: (args: { modelId: string; history: number[]; horizon: number; quantiles: number[] }) =>
    invoke<ForecastResult>("forecast_run", args),

  mediaCatalog: () => invoke<{ models: MediaCatalogEntry[] }>("media_catalog"),

  mediaRender: (args: {
    kind: MediaGenKind;
    modelId: string;
    prompt: string;
    negativePrompt?: string;
    width: number;
    height: number;
    steps: number;
    guidanceScale: number;
    numFrames?: number;
    fps?: number;
    seed: number;
  }) => invoke<MediaOutput>("media_render", args),

  assistantChat: (request: AssistantRequest, onEvent: Channel<AssistantEvent>) =>
    invoke<void>("assistant_chat", { request, onEvent }),

  assistantCancel: (requestId: string) => invoke<void>("assistant_cancel", { requestId }),

  rpcCall: (args: RpcCallArgs) => invoke<unknown>("rpc_call", { args }),

  deviceCreatePasskey: (label: string) => invoke<DeviceKeyInfo>("device_create_passkey", { label }),

  deviceSignWithPasskey: (label: string, prehashHex: string) =>
    invoke<string>("device_sign_with_passkey", { label, prehashHex }),

  deviceSignHybridWithPasskey: (label: string, prehashHex: string) =>
    invoke<HybridSignature>("device_sign_hybrid_with_passkey", { label, prehashHex }),

  deviceStartCrossDeviceLink: () => invoke<CableSessionStart>("device_start_cross_device_link"),

  deviceCompleteCrossDeviceLink: (request: CableCompleteRequest) =>
    invoke<CableAssertion>("device_complete_cross_device_link", { request }),

  deviceCancelCrossDeviceLink: (sessionId: string) =>
    invoke<void>("device_cancel_cross_device_link", { sessionId }),
};

export { Channel };

/** Tauri rejects with a plain string; anything else is a WebView-side fault. */
export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}
