//! Main SDK client for Tenzro Network
//!
//! This module provides the primary entry point for interacting with Tenzro Network.

use crate::access::AccessClient;
#[cfg(feature = "agents")]
use crate::agent::AgentClient;
#[cfg(feature = "agents")]
use crate::agent_payments::AgentPaymentClient;
use crate::auth::AuthClient;
#[cfg(feature = "bridge")]
use crate::bridge::BridgeClient;
use crate::config::SdkConfig;
#[cfg(feature = "chain")]
use crate::contract::ContractClient;
use crate::crypto::CryptoClient;
use crate::error::{SdkError, SdkResult};
#[cfg(feature = "chain")]
use crate::events::EventClient;
#[cfg(feature = "chain")]
use crate::governance::GovernanceClient;
use crate::identity::IdentityClient;
#[cfg(feature = "inference")]
use crate::inference::InferenceClient;
#[cfg(feature = "payments")]
use crate::payment::PaymentClient;
#[cfg(feature = "inference")]
use crate::provider::ProviderClient;
use crate::rpc::RpcClient;
#[cfg(feature = "settlement")]
use crate::settlement::SettlementClient;
#[cfg(feature = "chain")]
use crate::staking::StakingClient;
#[cfg(feature = "inference")]
use crate::streaming::StreamingClient;
#[cfg(feature = "chain")]
use crate::tee::TeeClient;
#[cfg(feature = "chain")]
use crate::token::TokenClient;
use crate::types::Address;
use crate::wallet::WalletClient;
#[cfg(feature = "chain")]
use crate::zk::ZkClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Main Tenzro Network client
///
/// The primary entry point for developers to interact with Tenzro Network.
///
/// # Example
///
/// ```no_run
/// use tenzro_sdk::TenzroClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
///
///     let block_number = client.block_number().await?;
///     println!("Current block: {}", block_number);
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct TenzroClient {
    config: Arc<SdkConfig>,
    pub(crate) rpc: Arc<RpcClient>,
}

impl TenzroClient {
    /// Creates a new client connected to the given RPC endpoint.
    ///
    /// This is the simplest way to get started. Uses default timeout and settings.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tenzro_sdk::TenzroClient;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    ///     println!("Connected!");
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(endpoint: &str) -> SdkResult<Self> {
        let config = SdkConfig::builder().endpoint(endpoint).build()?;
        Self::connect(config).await
    }

    /// Connects to a Tenzro Network node with full configuration.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tenzro_sdk::{TenzroClient, config::SdkConfig};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn connect(config: SdkConfig) -> SdkResult<Self> {
        tracing::info!("Connecting to Tenzro Network at {}", config.endpoint);

        let timeout = Duration::from_millis(config.timeout_ms);
        let rpc = RpcClient::new(&config.endpoint, timeout, config.access.clone())?;

        let client = Self {
            config: Arc::new(config),
            rpc: Arc::new(rpc),
        };

        tracing::info!("Successfully connected to Tenzro Network");
        Ok(client)
    }

    /// A client over an already-built [`RpcClient`], such as one that moves
    /// between several endpoints ([`RpcClient::with_failover`]).
    pub fn with_rpc(config: SdkConfig, rpc: RpcClient) -> SdkResult<Self> {
        Ok(Self {
            config: Arc::new(config),
            rpc: Arc::new(rpc),
        })
    }

    /// Checks if the node is reachable by calling `eth_chainId`
    pub async fn is_connected(&self) -> bool {
        self.get_chain_id().await.is_ok()
    }

    /// Gets the current block number (height)
    pub async fn block_number(&self) -> SdkResult<u64> {
        let hex: String = self
            .rpc
            .call("tenzro_blockNumber", serde_json::json!([]))
            .await?;
        parse_hex_u64(&hex)
    }

    /// Gets a block by its height
    pub async fn get_block(&self, height: u64) -> SdkResult<BlockInfo> {
        let block: BlockInfo = self
            .rpc
            .call(
                "tenzro_getBlock",
                serde_json::json!([{ "block_number": height }]),
            )
            .await?;
        Ok(block)
    }

    /// Gets the latest block
    pub async fn get_latest_block(&self) -> SdkResult<BlockInfo> {
        let block: BlockInfo = self
            .rpc
            .call(
                "tenzro_getBlock",
                serde_json::json!([{ "height": "latest" }]),
            )
            .await?;
        Ok(block)
    }

    /// Fetch a contiguous range of blocks for catch-up sync.
    ///
    /// Returns up to `max_results` blocks (default 64, capped at 256). The
    /// response includes `next_height` and `more_available` so a lagging
    /// client can paginate forward until caught up. `more_available` reflects
    /// whether the chain has further blocks beyond `next_height`, independent
    /// of the requested `end_height`, so a sync loop can step over pruning
    /// gaps by repeatedly calling with `start_height = response.next_height`.
    pub async fn get_block_range(
        &self,
        start_height: u64,
        end_height: u64,
        max_results: Option<u64>,
    ) -> SdkResult<BlockRange> {
        let mut params = serde_json::json!({
            "startHeight": start_height,
            "endHeight": end_height,
        });
        if let Some(max) = max_results {
            params["maxResults"] = serde_json::json!(max);
        }
        let range: BlockRange = self.rpc.call("tenzro_getBlockRange", params).await?;
        Ok(range)
    }

    /// Gets the balance of an address (in wei)
    pub async fn get_balance(&self, address: Address) -> SdkResult<u128> {
        let hex: String = self
            .rpc
            .call(
                "tenzro_getBalance",
                serde_json::json!([format!("0x{}", hex::encode(address.as_bytes()))]),
            )
            .await?;
        parse_hex_u128(&hex)
    }

    /// Gets the nonce of an address
    pub async fn get_nonce(&self, address: Address) -> SdkResult<u64> {
        let hex: String = self
            .rpc
            .call(
                "tenzro_getNonce",
                serde_json::json!([format!("0x{}", hex::encode(address.as_bytes()))]),
            )
            .await?;
        parse_hex_u64(&hex)
    }

    /// Gets the chain ID
    pub async fn get_chain_id(&self) -> SdkResult<u64> {
        let hex: String = self.rpc.call("eth_chainId", serde_json::json!([])).await?;
        parse_hex_u64(&hex)
    }

    /// Returns the current effective gas price in wei (base fee + suggested
    /// priority tip). Tracks the EIP-1559 fee market — value adjusts ±12.5%
    /// per block based on parent gas usage vs. the 15M target.
    pub async fn gas_price(&self) -> SdkResult<u128> {
        let hex: String = self.rpc.call("eth_gasPrice", serde_json::json!([])).await?;
        parse_hex_u128(&hex)
    }

    /// Returns a suggested EIP-1559 priority fee (tip) in wei. Use this to
    /// fill `maxPriorityFeePerGas` on a Type-2 transaction; derive the base-fee
    /// portion from `fee_history` or the parent block's `base_fee_per_gas`.
    pub async fn max_priority_fee_per_gas(&self) -> SdkResult<u128> {
        let hex: String = self
            .rpc
            .call("eth_maxPriorityFeePerGas", serde_json::json!([]))
            .await?;
        parse_hex_u128(&hex)
    }

    /// Returns base-fee history and gas-usage ratios for the last `block_count`
    /// blocks. `newest_block` is a hex height or `"latest"`. `reward_percentiles`
    /// requests per-block tip percentiles (e.g. `[25.0, 50.0, 75.0]`); pass
    /// `None` to omit. `base_fee_per_gas` returns `block_count + 1` entries —
    /// the last is the predicted base fee for the next block. Used by wallets
    /// to model `maxFeePerGas` and `maxPriorityFeePerGas`.
    pub async fn fee_history(
        &self,
        block_count: u64,
        newest_block: &str,
        reward_percentiles: Option<&[f64]>,
    ) -> SdkResult<FeeHistory> {
        let percentiles = reward_percentiles
            .map(|p| serde_json::json!(p))
            .unwrap_or(serde_json::json!([]));
        let history: FeeHistory = self
            .rpc
            .call(
                "eth_feeHistory",
                serde_json::json!([format!("0x{:x}", block_count), newest_block, percentiles]),
            )
            .await?;
        Ok(history)
    }

    /// Gets information about the connected node
    pub async fn node_info(&self) -> SdkResult<NodeInfo> {
        let status: serde_json::Value = self
            .rpc
            .call("tenzro_getNodeStatus", serde_json::json!([]))
            .await?;
        let version: String = self
            .rpc
            .call("web3_clientVersion", serde_json::json!([]))
            .await?;
        let chain_hex: String = self.rpc.call("eth_chainId", serde_json::json!([])).await?;
        let syncing: serde_json::Value = self
            .rpc
            .call("tenzro_syncing", serde_json::json!([]))
            .await?;
        let field = |key: &str| {
            status[key].as_u64().ok_or_else(|| {
                SdkError::RpcError(format!("tenzro_getNodeStatus answered without {key}"))
            })
        };
        Ok(NodeInfo {
            version,
            chain_id: parse_hex_u64(&chain_hex)?,
            block_height: field("block_height")?,
            peer_count: field("peer_count")? as u32,
            syncing: syncing
                .get("syncing")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        })
    }

    /// Gets the node status via the Web API
    pub async fn get_status(&self) -> SdkResult<NodeStatus> {
        self.rpc.get("/status").await
    }

    /// Gets the TNZO total supply
    pub async fn total_supply(&self) -> SdkResult<String> {
        self.rpc
            .call("tenzro_totalSupply", serde_json::json!([]))
            .await
    }

    /// Gets the peer count
    pub async fn peer_count(&self) -> SdkResult<u64> {
        let hex: String = self
            .rpc
            .call("tenzro_peerCount", serde_json::json!([]))
            .await?;
        parse_hex_u64(&hex)
    }

    /// Gets the network metrics snapshot.
    ///
    /// Returns the gossip counters from `tenzro_network::NetworkMetrics` and
    /// the number of peers the node gossips with directly.
    pub async fn network_stats(&self) -> SdkResult<NetworkStats> {
        let v: serde_json::Value = self
            .rpc
            .call("tenzro_getNetworkStats", serde_json::json!([]))
            .await?;
        serde_json::from_value(v).map_err(SdkError::from)
    }

    /// The randomness beacon's head, or the value at `round`, or the first
    /// at or after `at_ms`.
    pub async fn beacon(
        &self,
        round: Option<u64>,
        at_ms: Option<i64>,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getBeacon",
                serde_json::json!({ "round": round, "at_ms": at_ms }),
            )
            .await
    }

    /// The base fee of every resource market the next block charges:
    /// compute, state growth, bandwidth, proof.
    pub async fn fee_market(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getFeeMarket", serde_json::json!({}))
            .await
    }

    /// Creates a wallet client for wallet operations
    pub fn wallet(&self) -> WalletClient {
        WalletClient::new(self.rpc.clone())
    }

    /// Creates a passkey custody client: enrollment, custody challenges and
    /// browser passkey sessions. Maps 1:1 to the `tenzro_*Passkey*` RPC
    /// surface.
    pub fn passkey_rpc(&self) -> crate::passkey_client::PasskeyClient {
        crate::passkey_client::PasskeyClient::new(self.rpc.clone())
    }

    /// Creates a client for passkey account keystores in consensus state:
    /// read them from any node and send their changes.
    pub fn keystore(&self) -> crate::keystore::KeystoreClient {
        crate::keystore::KeystoreClient::new(self.rpc.clone())
    }

    #[cfg(feature = "inference")]
    /// Creates an inference client for AI model inference
    pub fn inference(&self) -> InferenceClient {
        InferenceClient::new(self.rpc.clone())
    }

    #[cfg(feature = "inference")]
    /// Creates a multi-modal client over the node's ONNX runtimes —
    /// forecast, vision encoders, text embeddings, click-driven and
    /// text-promptable segmentation, detection, audio ASR, and video.
    /// Each modality exposes the curated catalog, the loaded set, load,
    /// unload, and one inference verb.
    pub fn multimodal(&self) -> crate::multimodal::MultimodalClient {
        crate::multimodal::MultimodalClient::new(self.rpc.clone())
    }

    #[cfg(feature = "settlement")]
    /// Creates a settlement client for payment settlement
    pub fn settlement(&self) -> SettlementClient {
        SettlementClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a client for the generic registry and price cards
    pub fn registry(&self) -> crate::pricing::RegistryClient {
        crate::pricing::RegistryClient::new(self.rpc.clone())
    }

    /// Creates a client for the network insurance pool
    #[cfg(feature = "chain")]
    pub fn insurance(&self) -> crate::insurance::InsuranceClient {
        crate::insurance::InsuranceClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a client for network duties and evidence checks
    pub fn duty(&self) -> crate::duty::DutyClient {
        crate::duty::DutyClient::new(self.rpc.clone())
    }

    #[cfg(feature = "agents")]
    /// Creates an agent client for AI agent operations
    pub fn agent(&self) -> AgentClient {
        AgentClient::new(self.rpc.clone())
    }

    /// Creates an identity client for TDIP identity operations
    pub fn identity(&self) -> IdentityClient {
        IdentityClient::new(self.rpc.clone())
    }

    #[cfg(feature = "payments")]
    /// Creates a payment client for MPP/x402 payment operations
    pub fn payment(&self) -> PaymentClient {
        PaymentClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a governance client for governance operations
    pub fn governance(&self) -> GovernanceClient {
        GovernanceClient::new(self.rpc.clone())
    }

    #[cfg(feature = "inference")]
    /// Creates a provider client for network participation and model serving
    pub fn provider(&self) -> ProviderClient {
        ProviderClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a storage client for decentralized object storage and streaming
    /// storage deals (targets a node serving the `storage` role).
    pub fn storage(&self) -> crate::storage::StorageClient {
        crate::storage::StorageClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a client for certifications, operator policies
    /// and model provenance.
    pub fn trust(&self) -> crate::trust::TrustClient {
        crate::trust::TrustClient::new(self.rpc.clone())
    }

    #[cfg(feature = "inference")]
    /// Creates a client for the model catalog the node serves.
    pub fn catalog(&self) -> crate::catalog::CatalogClient {
        crate::catalog::CatalogClient::new(self.rpc.clone())
    }

    /// The keys of the signer's own account: enroll or replace its hardware
    /// ML-DSA-65 key.
    pub fn account_keys(&self) -> crate::account_keys::AccountKeysClient {
        crate::account_keys::AccountKeysClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a staking client for TNZO staking operations
    pub fn staking(&self) -> StakingClient {
        StakingClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a token client for token registry and cross-VM operations
    pub fn token(&self) -> TokenClient {
        TokenClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a contract client for smart contract deployment
    pub fn contract(&self) -> ContractClient {
        ContractClient::new(self.rpc.clone())
    }

    /// The universal gateway: discover and call any method this node serves.
    ///
    /// The typed clients above cover the surfaces worth a dedicated signature.
    /// This covers the rest, so nothing the node can do is unreachable from the
    /// SDK — and, because it enumerates the node's own registry rather than a
    /// list compiled into this crate, it cannot fall behind a node newer than
    /// the SDK.
    pub fn gateway(&self) -> crate::gateway::GatewayClient {
        crate::gateway::GatewayClient::new(self.rpc.clone())
    }

    #[cfg(feature = "payments")]
    /// Creates a funding client: grant and tranche requests
    pub fn funding(&self) -> crate::funding::FundingClient {
        crate::funding::FundingClient::new(self.rpc.clone())
    }

    #[cfg(feature = "bridge")]
    /// Creates a bridge client for cross-chain token transfer operations
    pub fn bridge(&self) -> BridgeClient {
        BridgeClient::new(self.rpc.clone())
    }

    #[cfg(feature = "agents")]
    /// Creates an agent payment client for spending policies and transactions
    pub fn agent_payments(&self) -> AgentPaymentClient {
        AgentPaymentClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates an Iroh client for the `tenzro_iroh_*` namespace —
    /// endpoint id / ALPNs / publish / fetch over the shared
    /// `IrohBackedResolver` (QUIC + Pkarr + iroh-blobs substrate that
    /// also backs DA, model fetch, and A2A-over-iroh).
    pub fn iroh(&self) -> crate::iroh::IrohClient {
        crate::iroh::IrohClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates an adaptive-burn governance dial client — read-only
    /// access to the current `BurnRateConfig`, rolling supply metrics,
    /// recommended burn-rate action, and in-flight adaptive-burn
    /// governance proposals.
    pub fn adaptive_burn(&self) -> crate::adaptive_burn::AdaptiveBurnClient {
        crate::adaptive_burn::AdaptiveBurnClient::new(self.rpc.clone())
    }

    /// Creates a device-binding client — the devices bound to an identity,
    /// what each proved about the hardware holding its key, whether a wallet
    /// may be created yet, and machine ownership transfer.
    pub fn device(&self) -> crate::device::DeviceClient {
        crate::device::DeviceClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a machine-access client — the owner-signed grants that let a
    /// node's agents, tools and models reach parts of its machine.
    pub fn machine_access(&self) -> crate::machine_access::MachineAccessClient {
        crate::machine_access::MachineAccessClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a validator registry read client — `getValidatorState`
    /// / `listValidators` / `listActiveValidators`. Read-only;
    /// validators self-register via the staking transaction path.
    pub fn validators(&self) -> crate::validator::ValidatorClient {
        crate::validator::ValidatorClient::new(self.rpc.clone())
    }

    #[cfg(feature = "inference")]
    /// Creates a generative media client: the media catalog, renders, and
    /// loading media models on the node.
    pub fn media_gen(&self) -> crate::media_gen::MediaGenClient {
        crate::media_gen::MediaGenClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a validator-side SLA fault-detector inspection client.
    /// Wraps `tenzro_slaIssueProbe`, `tenzro_slaListOutstandingProbes`,
    /// and `tenzro_slaGetParams`. The probe-issuing call is
    /// validator-only; on a non-validator node it returns
    /// `-32000 SlaManager not initialized`.
    pub fn sla(&self) -> crate::sla::SlaClient {
        crate::sla::SlaClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a state-sync snapshot client for `tenzro_listSnapshots` and
    /// `tenzro_getSnapshotManifest`. A manifest's `state_root` must match the
    /// root a trusted block commits to before any bucket from it is applied.
    pub fn snapshot(&self) -> crate::snapshot::SnapshotClient {
        crate::snapshot::SnapshotClient::new(self.rpc.clone())
    }

    #[cfg(feature = "settlement")]
    /// Creates a settlement plan client: open plans, prove legs, read
    /// decisions and leg receipts, preview splits.
    pub fn settle(&self) -> crate::settle::SettleClient {
        crate::settle::SettleClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a Proof-of-Reserve client for the 1:1-backed reserve
    /// attestations behind attested mints
    pub fn reserve(&self) -> crate::reserve::ReserveClient {
        crate::reserve::ReserveClient::new(self.rpc.clone())
    }

    #[cfg(feature = "payments")]
    /// Creates a Permit2 `SignatureTransfer` client. Wraps the
    /// `tenzro_permit2*` RPCs (domain separator, digest, atomic
    /// verify + nonce consume, nonce read). Used by gasless flows.
    pub fn permit2(&self) -> crate::permit2::Permit2Client {
        crate::permit2::Permit2Client::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates an ERC-7943 (uRWA) client for the reads
    /// (`tenzro_urwaIsKillSwitched`, `tenzro_urwaGetFrozenTokens`). The
    /// issuer's controls are signed `Token` transactions
    /// ([`crate::typed_tx`]).
    pub fn urwa(&self) -> crate::urwa::UrwaClient {
        crate::urwa::UrwaClient::new(self.rpc.clone())
    }

    #[cfg(feature = "bridge")]
    /// Creates a bridge-fee-in-TNZO client. Quotes destination-native
    /// fees in TNZO and enumerates per-adapter sponsorship pool vault
    /// addresses.
    pub fn bridge_fee(&self) -> crate::bridge_fee::BridgeFeeClient {
        crate::bridge_fee::BridgeFeeClient::new(self.rpc.clone())
    }

    /// Discovery + helper RPCs for the IBC-Eureka, NEAR Chain
    /// Signatures, BitVM2, Hyperbridge, Stargate V2 Hydra, Universal
    /// Resolver, SIWT, KERI, PKR, global supply, and
    /// Institution-identity modules.
    pub fn discovery(&self) -> crate::discovery::DiscoveryClient {
        crate::discovery::DiscoveryClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates an event client for querying and subscribing to on-chain events
    pub fn events(&self) -> EventClient {
        EventClient::new(self.rpc.clone())
    }

    /// Creates a crypto client for cryptographic operations
    pub fn crypto(&self) -> CryptoClient {
        CryptoClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a TEE client for Trusted Execution Environment operations
    pub fn tee(&self) -> TeeClient {
        TeeClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a consensus client: checkpoint and compact certificates,
    /// committees, epoch handovers and mempool lanes
    pub fn consensus(&self) -> crate::consensus::ConsensusClient {
        crate::consensus::ConsensusClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a data-availability client: committee, blobs and challenges
    pub fn da(&self) -> crate::da::DaClient {
        crate::da::DaClient::new(self.rpc.clone())
    }

    /// Creates a node client: operator status, visibility, aliases and shutdown
    pub fn node(&self) -> crate::node::NodeClient {
        crate::node::NodeClient::new(self.rpc.clone())
    }

    #[cfg(feature = "chain")]
    /// Creates a ZK client for zero-knowledge proof operations
    pub fn zk(&self) -> ZkClient {
        ZkClient::new(self.rpc.clone())
    }

    #[cfg(feature = "inference")]
    /// Creates a streaming client for real-time inference and event streaming
    pub fn streaming(&self) -> StreamingClient {
        StreamingClient::new(self.rpc.clone())
    }

    #[cfg(feature = "bridge")]
    /// Creates a client for agents' accounts on other chains and their grants.
    pub fn agent_accounts(&self) -> crate::agent_accounts::AgentAccountsClient {
        crate::agent_accounts::AgentAccountsClient::new(self.rpc.clone())
    }

    /// Creates an auth client for OAuth 2.1 + DPoP onboarding,
    /// JWT/DID revocation, and HITL approval flows.
    pub fn auth(&self) -> AuthClient {
        AuthClient::new(self.rpc.clone())
    }

    /// Creates a node access client: sign in for an access token, and
    /// administer who may use the node.
    pub fn access(&self) -> AccessClient {
        AccessClient::new(self.rpc.clone())
    }

    /// The outflow policy queries: an account's policy and releases, and the governed delegate code list.
    pub fn account_outflow(&self) -> crate::account_outflow::AccountOutflowClient {
        crate::account_outflow::AccountOutflowClient::new(self.rpc.clone())
    }

    /// Creates a typed transaction client: every consensus transaction type,
    /// signed with the caller's own hybrid key.
    pub fn transactions(&self) -> crate::typed_tx::TypedTxClient {
        crate::typed_tx::TypedTxClient::new(self.rpc.clone())
    }

    /// Returns the SDK configuration
    pub fn config(&self) -> &SdkConfig {
        &self.config
    }

    /// Returns the RPC endpoint URL.
    pub fn endpoint(&self) -> Option<&str> {
        self.rpc.endpoint()
    }

    /// Gets a transaction by hash.
    ///
    /// Resolves from finalized storage first, then falls back to the consensus
    /// mempool. The returned object's `status` field is `"pending"` while the
    /// transaction is in-mempool and `"finalized"` once it has been included in
    /// a block — callers polling immediately after broadcast can therefore
    /// distinguish "not yet finalized" from "unknown hash" (the RPC returns
    /// `null` only when the hash is unknown to both storage and mempool).
    pub async fn get_transaction(&self, hash: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getTransaction", serde_json::json!([hash]))
            .await
    }

    /// Checks if the node is syncing
    pub async fn syncing(&self) -> SdkResult<bool> {
        let result: serde_json::Value = self
            .rpc
            .call("tenzro_syncing", serde_json::json!([]))
            .await?;
        Ok(result
            .get("syncing")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    /// Gets the finalized block height
    pub async fn get_finalized_block(&self) -> SdkResult<u64> {
        let hex: String = self
            .rpc
            .call("tenzro_getFinalizedBlock", serde_json::json!([]))
            .await?;
        parse_hex_u64(&hex)
    }

    /// Exports the node configuration
    pub async fn export_config(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_exportConfig", serde_json::json!([]))
            .await
    }

    /// Gets transaction history for an address, newest first; pass the
    /// previous page's `cursor` to continue
    pub async fn get_transaction_history(
        &self,
        address: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getTransactionHistory",
                serde_json::json!([{"address": address, "limit": limit, "cursor": cursor}]),
            )
            .await
    }

    /// The paid calls the node served or routed, newest first. `query`
    /// takes `work_class`, `provider`, `payer`, `from_ms`, `to_ms`,
    /// `cursor` and `limit`, all optional.
    pub async fn list_settlements(&self, query: serde_json::Value) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_listSettlements", serde_json::json!([query]))
            .await
    }

    /// The provider legs this node owes for calls it forwarded. `query`
    /// takes `status`, `provider`, `limit` and `cursor`, all optional.
    pub async fn list_network_legs(
        &self,
        query: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_listNetworkLegs", query).await
    }

    /// Drives a failed provider leg again under the same payment id, so it
    /// never pays twice. The node's operator only.
    pub async fn retry_network_leg(&self, payment_id: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_retryNetworkLeg",
                serde_json::json!({ "payment_id": payment_id }),
            )
            .await
    }

    /// This node and every peer whose signed announcement it holds
    pub async fn list_peers(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_listPeers", serde_json::json!([]))
            .await
    }

    /// A provider's standing, announced price cards, and settled count,
    /// value and latency over 24 hours and 7 days
    pub async fn get_provider_scorecard(&self, provider: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getProviderScorecard",
                serde_json::json!([{ "provider": provider }]),
            )
            .await
    }

    /// Settlement activity on the chain for the latest `epochs` reward
    /// epochs (default 24, at most 168), newest first
    pub async fn get_network_activity(&self, epochs: Option<u64>) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getNetworkActivity",
                serde_json::json!([{ "epochs": epochs }]),
            )
            .await
    }

    /// A short inference the sponsoring agent `sponsor` pays for, on a node
    /// that offers it
    pub async fn sponsored_inference(
        &self,
        model: &str,
        input: &str,
        sponsor: &str,
        max_tokens: Option<u32>,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_sponsoredInference",
                serde_json::json!([{
                    "model": model, "input": input, "sponsor": sponsor, "max_tokens": max_tokens,
                }]),
            )
            .await
    }
}

/// Information about a Tenzro Network node, as the node reports it
/// (`tenzro_getNodeStatus`, `web3_clientVersion`, `eth_chainId`,
/// `tenzro_syncing`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node software version
    pub version: String,
    /// Chain ID the node serves
    pub chain_id: u64,
    /// Current block height
    pub block_height: u64,
    /// Number of connected peers
    pub peer_count: u32,
    /// Whether the node is currently syncing
    pub syncing: bool,
}

/// Snapshot of network metrics exposed by `tenzro_getNetworkStats`.
///
/// Gossip counters are monotonically-increasing totals since process start;
/// `peers_connected` is an instantaneous value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// `false` when the network service has not been initialized.
    pub available: bool,
    /// Set when `available` is `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub gossip_rejected_invalid: u64,
    #[serde(default)]
    pub gossip_rejected_duplicate: u64,
    #[serde(default)]
    pub gossip_published: u64,
    #[serde(default)]
    pub gossip_accepted: u64,
    /// Peers the node gossips with directly.
    #[serde(default)]
    pub peers_connected: u64,
}

/// Block information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: String,
    /// Previous block hash
    #[serde(default)]
    pub prev_hash: String,
    /// State root
    #[serde(default)]
    pub state_root: String,
    /// Transaction root
    #[serde(default)]
    pub tx_root: String,
    /// Block time, Unix milliseconds
    #[serde(default)]
    pub timestamp: u64,
    /// Block proposer
    #[serde(default)]
    pub proposer: String,
    /// Transaction count
    #[serde(default)]
    pub tx_count: u64,
    /// Gas used
    #[serde(default)]
    pub gas_used: u64,
    /// Gas limit
    #[serde(default)]
    pub gas_limit: u64,
    /// EIP-1559 base fee per gas in wei (hex-encoded). `None` for pre-fee-market
    /// blocks. Use `eth_feeHistory` for time-series base-fee modeling.
    #[serde(default, rename = "base_fee_per_gas")]
    pub base_fee_per_gas: Option<String>,
}

/// Paginated block range response from `tenzro_getBlockRange`.
///
/// Each block is a free-form `serde_json::Value` so callers can parse height,
/// hash, timestamp (millis), proposer, and the rest without committing to a
/// fixed schema. Use `next_height` and `more_available` to drive pagination:
///
/// ```ignore
/// let mut cur = 0u64;
/// loop {
///     let r = client.get_block_range(cur, cur + 255, Some(256)).await?;
///     for block in &r.blocks { /* ... */ }
///     if !r.more_available { break; }
///     cur = r.next_height;
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRange {
    /// Returned block summaries (heights between `startHeight` and the
    /// server-clamped end, inclusive). May be empty when the requested
    /// window falls inside a pruning gap.
    #[serde(default)]
    pub blocks: Vec<serde_json::Value>,
    /// Height the client should request next. Always advances, even when
    /// `blocks` is empty (server skips past gaps).
    #[serde(rename = "nextHeight", default)]
    pub next_height: u64,
    /// True if the chain has further blocks beyond `next_height`. Independent
    /// of the requested `endHeight` so a lagging client knows whether to keep
    /// paginating.
    #[serde(rename = "moreAvailable", default)]
    pub more_available: bool,
    /// Local node's tip at the time of the call.
    #[serde(rename = "localTip", default)]
    pub local_tip: u64,
}

/// EIP-1559 fee-history payload from `eth_feeHistory`.
///
/// `base_fee_per_gas` has length `block_count + 1` — the trailing entry is the
/// predicted base fee for the next block, suitable as the floor of a Type-2
/// transaction's `maxFeePerGas`. `reward[i][j]` is the `j`-th requested
/// percentile of priority tips paid in block `oldest_block + i` (empty when no
/// percentiles were requested).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeHistory {
    /// Lowest block height covered by this response (hex-encoded).
    #[serde(rename = "oldestBlock", default)]
    pub oldest_block: String,
    /// Per-block base fees in wei (hex-encoded). Length = `block_count + 1`.
    #[serde(rename = "baseFeePerGas", default)]
    pub base_fee_per_gas: Vec<String>,
    /// Per-block `gas_used / gas_limit` ratio.
    #[serde(rename = "gasUsedRatio", default)]
    pub gas_used_ratio: Vec<f64>,
    /// Per-block tip percentiles (wei, hex-encoded). Empty when
    /// `reward_percentiles` was `None`.
    #[serde(default)]
    pub reward: Option<Vec<Vec<String>>>,
}

/// Node status from Web API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    /// Node state (running, syncing, etc.)
    #[serde(default)]
    pub node_state: String,
    /// Node role (validator, user, etc.)
    #[serde(default)]
    pub role: String,
    /// Health status
    #[serde(default)]
    pub health: String,
    /// Current block height
    #[serde(default)]
    pub block_height: u64,
    /// Number of connected peers
    #[serde(default)]
    pub peer_count: u64,
    /// Uptime in seconds
    #[serde(default)]
    pub uptime_secs: u64,
}

/// Parse a hex string (with or without "0x" prefix) into u64
fn parse_hex_u128(hex_str: &str) -> SdkResult<u128> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    u128::from_str_radix(stripped, 16)
        .map_err(|e| SdkError::RpcError(format!("Failed to parse hex '{}': {}", hex_str, e)))
}

fn parse_hex_u64(hex_str: &str) -> SdkResult<u64> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    u64::from_str_radix(stripped, 16)
        .map_err(|e| SdkError::RpcError(format!("Failed to parse hex '{}': {}", hex_str, e)))
}
