//! Canton Network bridge adapter
//!
//! This module provides a bridge adapter for cross-synchronizer transfers on the
//! Canton Network. Canton operates as a "network of networks" where participant nodes
//! connect to multiple synchronizers (formerly "domains") and contracts can be
//! transferred between them atomically.
//!
//! Tenzro nodes run Canton participant/validator processes natively, so this adapter
//! connects to the co-located participant's JSON API (HTTP) and Ledger API (gRPC)
//! to facilitate cross-synchronizer asset transfers and message passing.
//!
//! # Canton Cross-Synchronizer Transfers
//!
//! Canton provides native cross-synchronizer atomicity through the Global Synchronizer,
//! a public, permissionless coordination layer operated by Super Validators. This
//! eliminates the need for traditional blockchain bridges — transfers between Canton
//! synchronizers use a two-phase commit protocol coordinated by the mediator.
//!
//! # Supported Operations
//!
//! - Cross-synchronizer asset transfers via Daml Exercise commands
//! - Cross-synchronizer message passing via Daml Create commands
//! - Synchronizer discovery and fee estimation
//! - Transfer status tracking
//!
//! # API Integration
//!
//! This adapter uses Canton's JSON Ledger API v2 (HTTP REST) for contract operations:
//! - `POST /v2/commands/submit-and-wait-for-transaction` - Submit create/exercise commands
//! - `POST /v2/state/active-contracts` - Query active contracts
//! - `POST /v2/events/events-by-contract-id` - Fetch contract by ID
//! - `POST /v2/parties` - Party allocation
//!
//! Authentication is handled via JWT tokens in the Authorization header.

use crate::{
    error::{BridgeError, Result},
    traits::{BridgeAdapter, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo, TransferStatus},
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_types::primitives::Hash;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Canton bridge adapter implementing cross-synchronizer transfers.
///
/// Each Tenzro validator runs a Canton participant node. This adapter uses
/// the co-located participant's JSON API (HTTP) and Ledger API (gRPC) to submit
/// Daml commands that initiate cross-synchronizer transfers. The Canton protocol
/// handles atomic multi-synchronizer coordination through the Global Synchronizer.
pub struct CantonAdapter {
    /// Canton configuration
    config: CantonConfig,
    /// HTTP client for JSON API calls
    http_client: reqwest::Client,
    /// Pending transfer status tracking
    pending_transfers: Arc<DashMap<String, CantonTransferState>>,
}

impl CantonAdapter {
    /// Creates a new Canton adapter
    pub fn new(config: CantonConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            pending_transfers: Arc::new(DashMap::new()),
        }
    }

    /// Generates a unique command ID for Canton command deduplication.
    /// Canton uses (application_id, command_id, act_as_parties) as the deduplication key.
    fn generate_command_id(&self) -> String {
        format!("{}-{}", self.config.application_id, Uuid::new_v4())
    }

    /// Computes a transaction hash from request data
    fn compute_tx_hash(&self, data: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result[..32]);
        Hash::new(hash)
    }

    /// Returns supported synchronizer information.
    /// Chain identifiers follow the format "canton-{synchronizer_id}".
    fn get_supported_synchronizers(synchronizer_ids: &[String]) -> Vec<ChainInfo> {
        synchronizer_ids
            .iter()
            .map(|id| {
                ChainInfo::new(
                    format!("canton-{}", id),
                    format!("Canton Synchronizer {}", id),
                    "DAML",
                    5, // Canton has fast finality (~5 seconds via sequencer + mediator)
                )
            })
            .collect()
    }

    /// Constructs the JSON Ledger API base URL.
    ///
    /// Canton 3.x ships the JSON Ledger API at `/v2`. The legacy `/v1` HTTP
    /// JSON API was removed; all command submission, contract query, and
    /// event lookups go through the `/v2` namespace.
    ///
    /// See: https://docs.digitalasset.com/integrate/devel/Json-Ledger-API/
    fn json_api_url(&self) -> String {
        let scheme = if self.config.tls_enabled { "https" } else { "http" };
        format!(
            "{}://{}:{}/v2",
            scheme, self.config.participant_host, self.config.json_api_port
        )
    }

    /// Creates HTTP request with authentication header
    fn build_request(&self, method: reqwest::Method, endpoint: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.json_api_url(), endpoint);
        let mut builder = self.http_client.request(method, url);

        // Add JWT authentication if configured
        if let Some(ref token) = self.config.jwt_token {
            builder = builder.bearer_auth(token);
        }

        builder.header("Content-Type", "application/json")
    }

    /// Submits a CreateCommand via POST /v2/commands/submit-and-wait-for-transaction.
    ///
    /// In Canton 3.x JSON Ledger API v2 there is no dedicated `/create` endpoint
    /// — every command (create / exercise / createAndExercise) is submitted via
    /// the unified `/commands/submit-and-wait-for-transaction` endpoint
    /// inside a `JsCommands` envelope (migrated from deprecated `-transaction-tree`
    /// endpoint removed in Canton 3.5). The `commandId` is required for
    /// idempotency / dedup, and `actAs` carries the submitter's Daml party.
    async fn create_contract(
        &self,
        template_id: &str,
        payload: serde_json::Value,
    ) -> Result<JsonApiCreateResponse> {
        let command_id = self.generate_command_id();

        let request_body = JsonApiSubmitAndWaitRequest {
            commands: vec![JsonApiCommandV2::Create {
                template_id: template_id.to_string(),
                create_arguments: payload,
            }],
            command_id: command_id.clone(),
            user_id: self.config.application_id.clone(),
            act_as: vec![self.config.act_as_party.clone()],
            read_as: Vec::new(),
            workflow_id: None,
        };

        debug!(
            "Canton JSON Ledger API v2: Creating contract with template_id={}, commandId={}",
            template_id, command_id
        );

        let response = self
            .build_request(
                reqwest::Method::POST,
                "/commands/submit-and-wait-for-transaction",
            )
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                error!("Canton JSON Ledger API v2 submit failed: {}", e);
                BridgeError::AdapterError(format!(
                    "Canton JSON Ledger API v2 submit failed: {}",
                    e
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| String::from("(failed to read response)"));
            error!(
                "Canton JSON Ledger API v2 submit error: {} - {}",
                status, error_text
            );
            return Err(BridgeError::AdapterError(format!(
                "Canton JSON Ledger API v2 submit failed: {} - {}",
                status, error_text
            )));
        }

        let tx_tree: JsonApiSubmitAndWaitResponse = response.json().await.map_err(|e| {
            error!("Failed to parse Canton JSON Ledger API v2 response: {}", e);
            BridgeError::AdapterError(format!("Invalid JSON Ledger API v2 response: {}", e))
        })?;

        // Extract the created event's contract id from the transaction tree.
        // The v2 transaction tree exposes events keyed by node id; we look for
        // the first CreatedEvent variant.
        let create_response = tx_tree
            .into_created_response()
            .ok_or_else(|| {
                BridgeError::AdapterError(
                    "Canton v2 submit returned no CreatedEvent in transaction tree"
                        .to_string(),
                )
            })?;

        info!(
            "Canton: Contract created successfully, contract_id={}",
            create_response.contract_id
        );

        Ok(create_response)
    }

    /// Submits an ExerciseCommand via POST /v2/commands/submit-and-wait-for-transaction.
    ///
    /// In Canton 3.x JSON Ledger API v2, exercising a choice goes through the
    /// same unified `commands/submit-and-wait-for-transaction` endpoint
    /// as create (migrated from deprecated `-transaction-tree` endpoint removed
    /// in Canton 3.5). The exercise command is wrapped in `JsCommands` with the
    /// submitter's `actAs` party.
    async fn exercise_choice(
        &self,
        contract_id: &str,
        template_id: &str,
        choice: &str,
        argument: serde_json::Value,
    ) -> Result<JsonApiExerciseResponse> {
        let command_id = self.generate_command_id();

        let request_body = JsonApiSubmitAndWaitRequest {
            commands: vec![JsonApiCommandV2::Exercise {
                template_id: template_id.to_string(),
                contract_id: contract_id.to_string(),
                choice: choice.to_string(),
                choice_argument: argument,
            }],
            command_id: command_id.clone(),
            user_id: self.config.application_id.clone(),
            act_as: vec![self.config.act_as_party.clone()],
            read_as: Vec::new(),
            workflow_id: None,
        };

        debug!(
            "Canton JSON Ledger API v2: Exercising choice {} on contract {}, commandId={}",
            choice, contract_id, command_id
        );

        let response = self
            .build_request(
                reqwest::Method::POST,
                "/commands/submit-and-wait-for-transaction",
            )
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                error!("Canton JSON Ledger API v2 exercise failed: {}", e);
                BridgeError::AdapterError(format!(
                    "Canton JSON Ledger API v2 exercise failed: {}",
                    e
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| String::from("(failed to read response)"));
            error!(
                "Canton JSON Ledger API v2 exercise error: {} - {}",
                status, error_text
            );
            return Err(BridgeError::AdapterError(format!(
                "Canton JSON Ledger API v2 exercise failed: {} - {}",
                status, error_text
            )));
        }

        let tx_tree: JsonApiSubmitAndWaitResponse = response.json().await.map_err(|e| {
            error!(
                "Failed to parse Canton JSON Ledger API v2 exercise response: {}",
                e
            );
            BridgeError::AdapterError(format!("Invalid JSON Ledger API v2 response: {}", e))
        })?;

        let exercise_response = tx_tree.into_exercise_response();

        info!(
            "Canton: Choice {} exercised successfully on contract {}",
            choice, contract_id
        );

        Ok(exercise_response)
    }

    /// Fetches a contract by id via POST /v2/events/events-by-contract-id.
    ///
    /// Canton 3.x JSON Ledger API v2 replaces the legacy `/v1/fetch` endpoint
    /// with `/events/events-by-contract-id`, which returns the CreatedEvent
    /// (and optional ArchivedEvent) for a given contract id under the
    /// requesting party's view. We treat the absence of a CreatedEvent or
    /// the presence of an ArchivedEvent as "not found" for bridge purposes.
    pub async fn fetch_contract(&self, contract_id: &str) -> Result<Option<JsonApiContract>> {
        let request_body = JsonApiFetchRequest {
            contract_id: contract_id.to_string(),
            requesting_parties: vec![self.config.act_as_party.clone()],
        };

        debug!(
            "Canton JSON Ledger API v2: Fetching contract events for {}",
            contract_id
        );

        let response = self
            .build_request(reqwest::Method::POST, "/events/events-by-contract-id")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                warn!("Canton JSON Ledger API v2 fetch failed: {}", e);
                BridgeError::AdapterError(format!(
                    "Canton JSON Ledger API v2 fetch failed: {}",
                    e
                ))
            })?;

        if response.status() == 404 {
            debug!("Contract {} not found (404)", contract_id);
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| String::from("(failed to read response)"));
            warn!(
                "Canton JSON Ledger API v2 fetch error: {} - {}",
                status, error_text
            );
            return Err(BridgeError::AdapterError(format!(
                "Canton JSON Ledger API v2 fetch failed: {} - {}",
                status, error_text
            )));
        }

        let fetch_response: JsonApiFetchResponse = response.json().await.map_err(|e| {
            error!(
                "Failed to parse Canton JSON Ledger API v2 fetch response: {}",
                e
            );
            BridgeError::AdapterError(format!("Invalid JSON Ledger API v2 response: {}", e))
        })?;

        Ok(fetch_response.into_contract())
    }

    /// Queries the active contract set via POST /v2/state/active-contracts.
    ///
    /// The legacy `/v1/query` JSON predicate filter does not exist in v2. The
    /// active-contracts endpoint accepts a `TransactionFilter` that lists the
    /// requesting parties and template ids, and returns the full active set
    /// at the participant's current ledger end. We then apply the structural
    /// filter from `query` (matching JSON object key/value pairs) on the
    /// client side, which preserves the previous adapter contract.
    async fn query_contracts(
        &self,
        template_ids: Vec<String>,
        query: serde_json::Value,
    ) -> Result<Vec<JsonApiContract>> {
        // The v2 ActiveContractsRequest needs a TransactionFilter where every
        // requesting party gets an InclusiveFilters listing the templates the
        // caller is interested in. Canton 3.4+ uses `identifierFilter` wrappers
        // with tagged variants (TemplateFilter, InterfaceFilter, WildcardFilter)
        // and singular `templateId` (plural `templateIds` deprecated since 2.8).
        let mut filters_by_party = serde_json::Map::new();
        let cumulative_filters: Vec<serde_json::Value> = template_ids
            .iter()
            .map(|tid| serde_json::json!({
                "identifierFilter": {
                    "TemplateFilter": {
                        "value": { "templateId": tid }
                    }
                }
            }))
            .collect();
        filters_by_party.insert(
            self.config.act_as_party.clone(),
            serde_json::json!({
                "cumulative": cumulative_filters,
            }),
        );

        let request_body = serde_json::json!({
            "filter": { "filtersByParty": filters_by_party },
            "verbose": true,
            "activeAtOffset": serde_json::Value::Null,
        });

        debug!(
            "Canton JSON Ledger API v2: Querying active contracts for {} template(s)",
            template_ids.len()
        );

        let response = self
            .build_request(reqwest::Method::POST, "/state/active-contracts")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                error!("Canton JSON Ledger API v2 query failed: {}", e);
                BridgeError::AdapterError(format!(
                    "Canton JSON Ledger API v2 query failed: {}",
                    e
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| String::from("(failed to read response)"));
            error!(
                "Canton JSON Ledger API v2 query error: {} - {}",
                status, error_text
            );
            return Err(BridgeError::AdapterError(format!(
                "Canton JSON Ledger API v2 query failed: {} - {}",
                status, error_text
            )));
        }

        let query_response: JsonApiQueryResponse = response.json().await.map_err(|e| {
            error!(
                "Failed to parse Canton JSON Ledger API v2 query response: {}",
                e
            );
            BridgeError::AdapterError(format!("Invalid JSON Ledger API v2 response: {}", e))
        })?;

        // Apply the client-side payload filter — match every (key, value) in
        // `query` against the contract's createArguments.
        let predicate = query.as_object();
        let filtered: Vec<JsonApiContract> = query_response
            .into_contracts()
            .into_iter()
            .filter(|contract| match predicate {
                None => true,
                Some(map) => map.iter().all(|(k, v)| {
                    contract
                        .payload
                        .get(k)
                        .map(|cv| cv == v)
                        .unwrap_or(false)
                }),
            })
            .collect();

        debug!(
            "Canton: Active-contracts query returned {} matching contracts",
            filtered.len()
        );

        Ok(filtered)
    }
}

#[async_trait]
impl BridgeAdapter for CantonAdapter {
    fn protocol_name(&self) -> &str {
        "canton"
    }

    fn supported_chains(&self) -> Vec<ChainInfo> {
        Self::get_supported_synchronizers(&self.config.synchronizer_ids)
    }

    async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String> {
        // Extract synchronizer ID from chain identifier (format: "canton-{synchronizer_id}")
        let synchronizer_id = dest_chain
            .strip_prefix("canton-")
            .ok_or_else(|| BridgeError::ChainNotSupported(dest_chain.to_string()))?;

        // Verify synchronizer is in our configured list
        if !self.config.synchronizer_ids.contains(&synchronizer_id.to_string()) {
            return Err(BridgeError::ChainNotSupported(dest_chain.to_string()));
        }

        // Generate unique command ID
        let command_id = self.generate_command_id();

        info!(
            "Canton: Sending message to synchronizer {} (command_id: {})",
            synchronizer_id, command_id
        );

        debug!(
            "Canton: Message payload size: {} bytes, acting as party: {}",
            payload.len(),
            self.config.act_as_party
        );

        // Create a message contract via JSON API
        // Template: TenzroBridge:Message
        // Arguments: { sender, recipient, synchronizerId, payload, messageId }
        let message_payload = serde_json::json!({
            "sender": self.config.act_as_party,
            "recipient": dest_chain,
            "synchronizerId": synchronizer_id,
            "payload": BASE64.encode(&payload),
            "messageId": command_id.clone(),
        });

        match self
            .create_contract("TenzroBridge:Message", message_payload)
            .await
        {
            Ok(response) => {
                info!(
                    "Canton: Message contract created, contract_id={}",
                    response.contract_id
                );
                Ok(command_id)
            }
            Err(e) => {
                error!("Canton: Failed to create message contract: {}", e);
                Err(e)
            }
        }
    }

    async fn receive_message(&self, source_chain: &str, payload: Vec<u8>) -> Result<()> {
        let synchronizer_id = source_chain
            .strip_prefix("canton-")
            .ok_or_else(|| BridgeError::ChainNotSupported(source_chain.to_string()))?;

        info!(
            "Canton: Receiving message from synchronizer {}, payload_size={}",
            synchronizer_id,
            payload.len()
        );

        // Query for message contracts from the source synchronizer
        // Template: TenzroBridge:Message
        // Filter: { recipient: act_as_party, synchronizerId: synchronizer_id }
        let query_filter = serde_json::json!({
            "recipient": self.config.act_as_party,
            "synchronizerId": synchronizer_id,
        });

        match self
            .query_contracts(vec!["TenzroBridge:Message".to_string()], query_filter)
            .await
        {
            Ok(contracts) => {
                debug!(
                    "Canton: Found {} message contracts from synchronizer {}",
                    contracts.len(),
                    synchronizer_id
                );

                // Process the first matching message (in production, would need more sophisticated matching)
                if let Some(contract) = contracts.first() {
                    info!(
                        "Canton: Processing message contract_id={}",
                        contract.contract_id
                    );
                    // In production, decode payload from contract.payload and process
                    // For now, just acknowledge receipt
                }

                Ok(())
            }
            Err(e) => {
                error!(
                    "Canton: Failed to query message contracts from synchronizer {}: {}",
                    synchronizer_id, e
                );
                Err(e)
            }
        }
    }

    async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt> {
        // Extract source and destination synchronizer IDs
        let _src_synchronizer = request
            .source_chain
            .strip_prefix("canton-")
            .ok_or_else(|| BridgeError::ChainNotSupported(request.source_chain.clone()))?;

        let dest_synchronizer = request
            .dest_chain
            .strip_prefix("canton-")
            .ok_or_else(|| BridgeError::ChainNotSupported(request.dest_chain.clone()))?;

        // Verify destination synchronizer is supported
        if !self.config.synchronizer_ids.contains(&dest_synchronizer.to_string()) {
            return Err(BridgeError::ChainNotSupported(request.dest_chain.clone()));
        }

        info!(
            "Canton: Bridging {} {} from {} to {}",
            request.amount, request.asset_id, request.source_chain, request.dest_chain
        );

        // Generate unique transfer ID
        let transfer_id = Uuid::new_v4().to_string();

        // Compute transaction hash from request data
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(transfer_id.as_bytes());
        hash_input.extend_from_slice(request.source_chain.as_bytes());
        hash_input.extend_from_slice(request.dest_chain.as_bytes());
        hash_input.extend_from_slice(request.asset_id.as_bytes());
        hash_input.extend_from_slice(&request.amount.to_le_bytes());
        hash_input.extend_from_slice(request.sender.as_bytes());
        hash_input.extend_from_slice(request.recipient.as_bytes());

        let tx_hash = self.compute_tx_hash(&hash_input);

        // Estimate fee
        let fee = self.estimate_fee(&request.dest_chain, 256).await?;

        // Canton finality is ~5 seconds (sequencer timestamp + mediator confirmation)
        let estimated_arrival = Utc::now().timestamp_millis() + 5000;

        // Generate command ID
        let command_id = self.generate_command_id();

        // Create transfer state
        let transfer_state = CantonTransferState {
            transfer_id: transfer_id.clone(),
            status: TransferStatus::Pending,
            command_id: command_id.clone(),
            source_synchronizer: request.source_chain.clone(),
            dest_synchronizer: request.dest_chain.clone(),
            asset_id: request.asset_id.clone(),
            amount: request.amount,
            sender: request.sender.clone(),
            recipient: request.recipient.clone(),
            created_at: Utc::now().timestamp_millis(),
            updated_at: Utc::now().timestamp_millis(),
        };

        // Store in pending transfers
        self.pending_transfers
            .insert(transfer_id.clone(), transfer_state);

        info!(
            "Canton: Transfer {} initiated, tx_hash={}, fee={}",
            transfer_id, tx_hash, fee
        );

        // Submit cross-synchronizer transfer via Daml Exercise command on JSON API
        // This exercises the "Transfer" choice on the token contract
        // The Canton multi-synchronizer protocol handles atomic coordination
        // via the Global Synchronizer (2PC across synchronizers)

        // First, query for the token contract owned by the sender
        let token_query = serde_json::json!({
            "owner": request.sender,
            "assetId": request.asset_id,
        });

        let token_contracts = self
            .query_contracts(
                vec![format!("TenzroBridge:{}", request.asset_id)],
                token_query,
            )
            .await
            .unwrap_or_else(|e| {
                warn!(
                    "Canton: Failed to query token contracts for transfer {}: {}",
                    transfer_id, e
                );
                vec![]
            });

        if let Some(token_contract) = token_contracts.first() {
            // Exercise the Transfer choice
            let transfer_args = serde_json::json!({
                "newOwner": request.recipient,
                "amount": request.amount.to_string(),
                "destinationSynchronizer": dest_synchronizer,
                "transferId": transfer_id,
            });

            match self
                .exercise_choice(
                    &token_contract.contract_id,
                    &token_contract.template_id,
                    "Transfer",
                    transfer_args,
                )
                .await
            {
                Ok(response) => {
                    info!(
                        "Canton: Transfer choice exercised successfully for transfer {}",
                        transfer_id
                    );

                    // Update transfer status
                    if let Some(mut state) = self.pending_transfers.get_mut(&transfer_id) {
                        state.status = TransferStatus::Pending; // Will become Delivered when confirmed
                        state.updated_at = Utc::now().timestamp_millis();
                    }

                    debug!("Canton: Exercise response: {:?}", response);
                }
                Err(e) => {
                    error!(
                        "Canton: Failed to exercise Transfer choice for transfer {}: {}",
                        transfer_id, e
                    );

                    // Update transfer status to failed
                    if let Some(mut state) = self.pending_transfers.get_mut(&transfer_id) {
                        state.status = TransferStatus::Failed;
                        state.updated_at = Utc::now().timestamp_millis();
                    }

                    return Err(e);
                }
            }
        } else {
            warn!(
                "Canton: No token contract found for sender {} with asset {}",
                request.sender, request.asset_id
            );
            // Still return receipt but mark as pending (will fail in status check)
        }

        Ok(BridgeTokenReceipt::new(
            transfer_id,
            tx_hash,
            estimated_arrival,
            fee,
            request.source_chain,
            request.dest_chain,
        ))
    }

    async fn get_transfer_status(&self, transfer_id: &str) -> Result<TransferStatus> {
        // First check local cache
        if let Some(entry) = self.pending_transfers.get(transfer_id) {
            let cached_status = entry.status;

            // If status is pending, query Canton to check if transfer completed
            if cached_status == TransferStatus::Pending {
                let dest_sync = entry.dest_synchronizer.clone();
                let recipient = entry.recipient.clone();
                let asset_id = entry.asset_id.clone();
                drop(entry); // Release read lock before making async call

                // Query for contracts on destination synchronizer with recipient as owner
                let query_filter = serde_json::json!({
                    "owner": recipient,
                    "assetId": asset_id,
                });

                match self
                    .query_contracts(
                        vec![format!("TenzroBridge:{}", asset_id)],
                        query_filter,
                    )
                    .await
                {
                    Ok(contracts) => {
                        // Check if any contract matches our transfer
                        let delivered = contracts.iter().any(|c| {
                            c.payload
                                .get("transferId")
                                .and_then(|v| v.as_str())
                                .map(|id| id == transfer_id)
                                .unwrap_or(false)
                        });

                        if delivered {
                            // Update status to delivered
                            if let Some(mut state) = self.pending_transfers.get_mut(transfer_id) {
                                state.status = TransferStatus::Delivered;
                                state.updated_at = Utc::now().timestamp_millis();
                            }
                            info!(
                                "Canton: Transfer {} confirmed as delivered on {}",
                                transfer_id, dest_sync
                            );
                            return Ok(TransferStatus::Delivered);
                        }
                    }
                    Err(e) => {
                        warn!("Canton: Failed to query transfer status: {}", e);
                        // Return cached pending status on error
                    }
                }
            }

            Ok(cached_status)
        } else {
            Err(BridgeError::TransferNotFound(transfer_id.to_string()))
        }
    }

    async fn estimate_fee(&self, dest_chain: &str, payload_size: usize) -> Result<u128> {
        // Extract synchronizer ID and verify it's supported
        let synchronizer_id = dest_chain
            .strip_prefix("canton-")
            .ok_or_else(|| BridgeError::ChainNotSupported(dest_chain.to_string()))?;

        if !self.config.synchronizer_ids.contains(&synchronizer_id.to_string()) {
            return Err(BridgeError::ChainNotSupported(dest_chain.to_string()));
        }

        // Try querying the Canton participant's Admin API for the synchronizer
        // fee schedule. Canton denominates fees in USD paid by burning CC; the
        // Admin API exposes the per-synchronizer schedule at
        // `GET /admin/synchronizer/{id}/fee-schedule`.
        match self.query_synchronizer_fee_schedule(synchronizer_id, payload_size).await {
            Ok(fee) => {
                debug!(
                    "Canton: Live fee schedule for {} bytes to synchronizer {}: {} units",
                    payload_size, synchronizer_id, fee
                );
                Ok(fee)
            }
            Err(e) => {
                let fallback = Self::estimate_fee_static(payload_size);
                warn!(
                    "Canton: Fee schedule query failed ({}), using static fallback = {} units",
                    e, fallback
                );
                Ok(fallback)
            }
        }
    }
}

impl CantonAdapter {
    /// Offline fee estimate used as fallback when the Canton Admin API is unreachable.
    ///
    /// Numbers reflect typical Canton Network synchronizer costs denominated in
    /// the synchronizer's smallest fee unit.
    fn estimate_fee_static(payload_size: usize) -> u128 {
        const BASE_FEE: u128 = 1000;
        const PER_BYTE_FEE: u128 = 10;
        BASE_FEE + (payload_size as u128 * PER_BYTE_FEE)
    }

    /// Queries the Canton participant Admin API for the live fee schedule of
    /// the given synchronizer and computes `base_fee + size * per_byte_fee`.
    async fn query_synchronizer_fee_schedule(
        &self,
        synchronizer_id: &str,
        payload_size: usize,
    ) -> Result<u128> {
        let scheme = if self.config.tls_enabled { "https" } else { "http" };
        let url = format!(
            "{}://{}:{}/admin/synchronizer/{}/fee-schedule",
            scheme,
            self.config.participant_host,
            self.config.admin_api_port,
            synchronizer_id
        );

        let mut builder = self.http_client.get(&url);
        if let Some(ref token) = self.config.jwt_token {
            builder = builder.bearer_auth(token);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| BridgeError::AdapterError(format!("Canton Admin API GET failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(BridgeError::AdapterError(format!(
                "Canton Admin API returned HTTP {}",
                response.status()
            )));
        }

        let json: serde_json::Value = response.json().await.map_err(|e| {
            BridgeError::AdapterError(format!("Canton Admin API returned invalid JSON: {}", e))
        })?;

        // The Admin API fee-schedule is expected to contain a base fee and a
        // per-byte fee, both expressed in the smallest unit (e.g. microUSD).
        let base_fee = json
            .get("base_fee")
            .or_else(|| json.get("baseFee"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                BridgeError::AdapterError(
                    "Canton Admin API fee-schedule missing base_fee".to_string(),
                )
            })? as u128;

        let per_byte_fee = json
            .get("per_byte_fee")
            .or_else(|| json.get("perByteFee"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                BridgeError::AdapterError(
                    "Canton Admin API fee-schedule missing per_byte_fee".to_string(),
                )
            })? as u128;

        Ok(base_fee + (payload_size as u128 * per_byte_fee))
    }
}

/// Canton adapter configuration.
///
/// Configures the bridge adapter's connection to the co-located Canton participant
/// node and the set of synchronizers it can bridge to.
///
/// ## Production Integration Notes
///
/// Real Canton integration requires:
/// - **JSON API**: HTTP REST API for contract operations (default port 7575)
/// - **Ledger API**: gRPC API for transaction streaming (default port 5001)
/// - **Admin API**: HTTP REST API for participant management (default port 5002)
/// - **JWT Authentication**: Configure `jwt_token` for authenticated access
/// - **TLS Configuration**: Enable `tls_enabled` for production deployments
/// - **Global Synchronizer**: Connect to Canton Network's Global Synchronizer for cross-domain transfers
///
/// See: https://docs.daml.com/canton/usermanual/apis.html
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonConfig {
    /// Canton participant host (co-located, typically localhost)
    pub participant_host: String,
    /// Canton participant JSON API port (default: 7575 in Canton 3.x)
    pub json_api_port: u16,
    /// Canton participant Ledger API port (default: 5001 in Canton 3.x)
    pub participant_port: u16,
    /// Canton participant Admin API port (default: 5002 in Canton 3.x)
    pub admin_api_port: u16,
    /// Enable TLS for participant connection
    pub tls_enabled: bool,
    /// JWT token for JSON API authentication (optional)
    pub jwt_token: Option<String>,
    /// List of Canton synchronizer IDs this adapter can bridge to
    pub synchronizer_ids: Vec<String>,
    /// The Daml party identity to act as (format: "name::fingerprint")
    pub act_as_party: String,
    /// Application ID for command deduplication
    pub application_id: String,
}

impl CantonConfig {
    /// Creates a new Canton configuration
    pub fn new(
        participant_host: impl Into<String>,
        participant_port: u16,
        synchronizer_ids: Vec<String>,
        act_as_party: impl Into<String>,
        application_id: impl Into<String>,
    ) -> Self {
        Self {
            participant_host: participant_host.into(),
            json_api_port: 7575,
            participant_port,
            admin_api_port: 5002,
            tls_enabled: false,
            jwt_token: None,
            synchronizer_ids,
            act_as_party: act_as_party.into(),
            application_id: application_id.into(),
        }
    }

    /// Enables TLS for the participant connection
    pub fn with_tls(mut self, enabled: bool) -> Self {
        self.tls_enabled = enabled;
        self
    }

    /// Sets the JWT authentication token
    pub fn with_jwt_token(mut self, token: impl Into<String>) -> Self {
        self.jwt_token = Some(token.into());
        self
    }

    /// Sets the JSON API port
    pub fn with_json_api_port(mut self, port: u16) -> Self {
        self.json_api_port = port;
        self
    }

    /// Sets the Admin API port
    pub fn with_admin_port(mut self, port: u16) -> Self {
        self.admin_api_port = port;
        self
    }
}

impl Default for CantonConfig {
    fn default() -> Self {
        Self {
            participant_host: "localhost".to_string(),
            json_api_port: 7575,
            participant_port: 5001,
            admin_api_port: 5002,
            tls_enabled: false,
            jwt_token: None,
            synchronizer_ids: vec![],
            act_as_party: String::new(),
            application_id: "tenzro-canton-bridge".to_string(),
        }
    }
}

/// Internal state tracking for Canton cross-synchronizer transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonTransferState {
    /// Unique transfer identifier
    pub transfer_id: String,
    /// Current transfer status
    pub status: TransferStatus,
    /// Canton command ID for deduplication
    pub command_id: String,
    /// Source synchronizer identifier (format: "canton-{id}")
    pub source_synchronizer: String,
    /// Destination synchronizer identifier (format: "canton-{id}")
    pub dest_synchronizer: String,
    /// Asset identifier
    pub asset_id: String,
    /// Transfer amount
    pub amount: u128,
    /// Sender party (format: "name::fingerprint")
    pub sender: String,
    /// Recipient party (format: "name::fingerprint")
    pub recipient: String,
    /// Creation timestamp (milliseconds)
    pub created_at: i64,
    /// Last update timestamp (milliseconds)
    pub updated_at: i64,
}

/// Daml command submission request
///
/// Represents a command to be submitted to the Canton Ledger API.
/// In production, this would be converted to the gRPC `SubmitAndWaitRequest` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DamlCommandSubmission {
    /// Application ID for command deduplication
    pub application_id: String,
    /// Unique command ID for deduplication
    pub command_id: String,
    /// List of party IDs that are authorizing this command
    pub act_as: Vec<String>,
    /// Daml commands to execute
    pub commands: Vec<DamlCommand>,
    /// Minimum ledger time bound (optional)
    pub min_ledger_time: Option<i64>,
    /// Maximum ledger time bound (optional)
    pub max_ledger_time: Option<i64>,
}

/// Daml command type
///
/// Represents different types of Daml commands that can be submitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DamlCommand {
    /// Create a new contract instance
    Create {
        /// Template ID (format: "ModuleName:TemplateName")
        template_id: String,
        /// Contract arguments
        arguments: serde_json::Value,
    },
    /// Exercise a choice on an existing contract
    Exercise {
        /// Contract ID to exercise on
        contract_id: String,
        /// Template ID of the contract
        template_id: String,
        /// Choice name
        choice: String,
        /// Choice arguments
        arguments: serde_json::Value,
    },
}

/// Daml transaction response
///
/// Represents the response from a successful command submission.
/// In production, this would be converted from the gRPC `Transaction` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DamlTransactionResponse {
    /// Transaction ID
    pub transaction_id: String,
    /// Command ID that produced this transaction
    pub command_id: String,
    /// Workflow ID (optional)
    pub workflow_id: Option<String>,
    /// Effective ledger time
    pub effective_at: i64,
    /// Offset in the ledger
    pub offset: String,
    /// Events produced by this transaction
    pub events: Vec<DamlEvent>,
}

/// Daml event
///
/// Represents an event produced by a Daml transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DamlEvent {
    /// Contract created event
    Created {
        /// Event ID
        event_id: String,
        /// Contract ID of the created contract
        contract_id: String,
        /// Template ID
        template_id: String,
        /// Contract arguments
        arguments: serde_json::Value,
    },
    /// Contract archived event
    Archived {
        /// Event ID
        event_id: String,
        /// Contract ID of the archived contract
        contract_id: String,
        /// Template ID
        template_id: String,
    },
}

// JSON Ledger API v2 Request/Response Types
//
// Canton 3.x ships the JSON Ledger API at `/v2`, which mirrors the gRPC
// Ledger API rather than the legacy DAML-on-Ledger HTTP JSON API. The types
// below model the subset of v2 that the bridge adapter exercises:
//
//   - POST /v2/commands/submit-and-wait-for-transaction
//   - POST /v2/state/active-contracts
//   - POST /v2/events/events-by-contract-id
//
// See: https://docs.digitalasset.com/integrate/devel/Json-Ledger-API/

/// One Daml command inside a `JsCommands` envelope. The v2 endpoint accepts
/// a tagged enum (`CreateCommand` / `ExerciseCommand` / `CreateAndExerciseCommand`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "commandType", rename_all = "camelCase")]
enum JsonApiCommandV2 {
    #[serde(rename_all = "camelCase")]
    Create {
        #[serde(rename = "templateId")]
        template_id: String,
        #[serde(rename = "createArguments")]
        create_arguments: serde_json::Value,
    },
    #[serde(rename_all = "camelCase")]
    Exercise {
        #[serde(rename = "templateId")]
        template_id: String,
        #[serde(rename = "contractId")]
        contract_id: String,
        choice: String,
        #[serde(rename = "choiceArgument")]
        choice_argument: serde_json::Value,
    },
}

/// `JsCommands` envelope for `/v2/commands/submit-and-wait-for-transaction`.
/// (Migrated from deprecated `/submit-and-wait-for-transaction-tree` removed in Canton 3.5)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiSubmitAndWaitRequest {
    commands: Vec<JsonApiCommandV2>,
    #[serde(rename = "commandId")]
    command_id: String,
    /// Canton 3.x renames `applicationId` to `userId`; both are accepted in
    /// the JSON Ledger API but `userId` is the canonical 3.4+ field name.
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "actAs")]
    act_as: Vec<String>,
    #[serde(rename = "readAs", default)]
    read_as: Vec<String>,
    #[serde(rename = "workflowId", skip_serializing_if = "Option::is_none")]
    workflow_id: Option<String>,
}

/// Response from `submit-and-wait-for-transaction` (Canton 3.5+).
///
/// The current endpoint returns a `JsTransaction` with a flat `events` array.
/// For backward compat with older Canton (3.3/3.4) or the deprecated tree
/// endpoint, we also accept `transactionTree` with `eventsById` map and
/// top-level `eventsById`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiSubmitAndWaitResponse {
    /// Canton 3.5+ flat transaction response
    #[serde(default)]
    transaction: Option<JsonApiTransaction>,
    /// Canton 3.3/3.4 tree response (backward compat)
    #[serde(rename = "transactionTree", default)]
    transaction_tree: Option<JsonApiTransactionTree>,
    /// Top-level eventsById fallback
    #[serde(rename = "eventsById", default)]
    events_by_id: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Flat transaction from `/v2/commands/submit-and-wait-for-transaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiTransaction {
    #[serde(default)]
    events: Vec<serde_json::Value>,
    #[serde(rename = "updateId", default)]
    update_id: Option<String>,
}

/// JsTransactionTree subset.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiTransactionTree {
    #[serde(rename = "eventsById", default)]
    events_by_id: serde_json::Map<String, serde_json::Value>,
    #[serde(rename = "updateId", default)]
    update_id: Option<String>,
}

impl JsonApiSubmitAndWaitResponse {
    /// Extracts a created event from the response.
    ///
    /// Tries three response shapes in priority order:
    /// 1. Canton 3.5+ flat `transaction.events` array (from `/submit-and-wait-for-transaction`)
    /// 2. Canton 3.3/3.4 `transactionTree.eventsById` map (backward compat)
    /// 3. Top-level `eventsById` fallback
    fn into_created_response(self) -> Option<JsonApiCreateResponse> {
        // Helper: extract created event from a JSON value
        fn extract_created(value: &serde_json::Value) -> Option<JsonApiCreateResponse> {
            let created = value
                .get("CreatedEvent")
                .or_else(|| value.get("CreatedTreeEvent"))
                .or_else(|| value.get("Created"))
                .or_else(|| value.get("created"))
                // Flat transaction events may have the fields at top level
                .or_else(|| if value.get("contractId").is_some() { Some(value) } else { None })?;
            let contract_id = created
                .get("contractId")
                .and_then(|v| v.as_str())
                .map(String::from)?;
            let payload = created
                .get("createArguments")
                .or_else(|| created.get("arguments"))
                .or_else(|| created.get("payload"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            Some(JsonApiCreateResponse { contract_id, payload })
        }

        // 1. Try flat transaction (Canton 3.5+)
        if let Some(tx) = &self.transaction {
            for event in &tx.events {
                if let Some(resp) = extract_created(event) {
                    return Some(resp);
                }
            }
        }

        // 2. Try tree (Canton 3.3/3.4 backward compat)
        let events_map = self
            .transaction_tree
            .map(|t| t.events_by_id)
            .or(self.events_by_id);

        if let Some(events) = events_map {
            for (_node_id, value) in events {
                if let Some(resp) = extract_created(&value) {
                    return Some(resp);
                }
            }
        }

        None
    }

    /// Collects exercise results from the response.
    ///
    /// Same priority: flat transaction → tree → top-level eventsById.
    fn into_exercise_response(self) -> JsonApiExerciseResponse {
        let mut events = Vec::new();
        let mut exercise_result = serde_json::Value::Null;

        // Helper: extract exercise result from a JSON value
        fn extract_exercised(value: &serde_json::Value) -> Option<serde_json::Value> {
            let exercised = value
                .get("ExercisedEvent")
                .or_else(|| value.get("ExercisedTreeEvent"))
                .or_else(|| value.get("Exercised"))
                .or_else(|| value.get("exercised"))
                .or_else(|| if value.get("exerciseResult").is_some() { Some(value) } else { None })?;
            exercised.get("exerciseResult").cloned()
        }

        // 1. Try flat transaction (Canton 3.5+)
        if let Some(tx) = self.transaction {
            for event in tx.events {
                if let Some(result) = extract_exercised(&event) {
                    exercise_result = result;
                }
                events.push(event);
            }
            if !events.is_empty() {
                return JsonApiExerciseResponse { exercise_result, events };
            }
        }

        // 2. Try tree (Canton 3.3/3.4 backward compat)
        let events_map = self
            .transaction_tree
            .map(|t| t.events_by_id)
            .or(self.events_by_id)
            .unwrap_or_default();

        for (_node_id, value) in events_map {
            if let Some(result) = extract_exercised(&value) {
                exercise_result = result;
            }
            events.push(value);
        }

        JsonApiExerciseResponse { exercise_result, events }
    }
}

/// Result of a successful create command (extracted from the v2 transaction tree).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiCreateResponse {
    contract_id: String,
    #[serde(default)]
    payload: serde_json::Value,
}

/// Result of a successful exercise command (extracted from the v2 transaction tree).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiExerciseResponse {
    #[serde(rename = "exerciseResult")]
    exercise_result: serde_json::Value,
    #[serde(default)]
    events: Vec<serde_json::Value>,
}

/// Request body for POST /v2/events/events-by-contract-id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonApiFetchRequest {
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "requestingParties")]
    pub requesting_parties: Vec<String>,
}

/// Response body for POST /v2/events/events-by-contract-id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonApiFetchResponse {
    /// The CreatedEvent for the requested contract id, if currently active.
    #[serde(rename = "created", default)]
    pub created: Option<serde_json::Value>,
    /// An ArchivedEvent (present once the contract has been archived).
    #[serde(rename = "archived", default)]
    pub archived: Option<serde_json::Value>,
}

impl JsonApiFetchResponse {
    /// Converts the v2 events response into a `JsonApiContract`.
    /// Returns None if there is no active CreatedEvent (or the contract has
    /// been archived).
    fn into_contract(self) -> Option<JsonApiContract> {
        if self.archived.is_some() {
            return None;
        }
        let created = self.created?;
        let contract_id = created
            .get("contractId")
            .and_then(|v| v.as_str())
            .map(String::from)?;
        let template_id = created
            .get("templateId")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default();
        let payload = created
            .get("createArguments")
            .or_else(|| created.get("arguments"))
            .or_else(|| created.get("payload"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Some(JsonApiContract {
            contract_id,
            template_id,
            payload,
        })
    }
}

/// Response body for POST /v2/state/active-contracts.
///
/// The v2 endpoint streams `JsGetActiveContractsResponse` records, each of
/// which contains a `contractEntry` carrying either a `JsActiveContract`
/// (with the CreatedEvent) or an `IncompleteUnassigned` / `IncompleteAssigned`
/// stub. We accept all of those shapes via untagged deserialization and only
/// surface the active CreatedEvents.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiQueryResponse {
    /// Modern shape: `{ "contractEntries": [ { "JsActiveContract": ... }, ... ] }`
    #[serde(default, rename = "contractEntries")]
    contract_entries: Vec<serde_json::Value>,
    /// Legacy v2-streaming shape: `{ "results": [ ... ] }`
    #[serde(default)]
    results: Vec<serde_json::Value>,
}

impl JsonApiQueryResponse {
    fn into_contracts(self) -> Vec<JsonApiContract> {
        let raw_entries = if !self.contract_entries.is_empty() {
            self.contract_entries
        } else {
            self.results
        };

        raw_entries
            .into_iter()
            .filter_map(|entry| {
                // Try the modern wrapper first.
                let active = entry
                    .get("JsActiveContract")
                    .or_else(|| entry.get("activeContract"))
                    .unwrap_or(&entry);

                let created = active
                    .get("createdEvent")
                    .or_else(|| active.get("CreatedEvent"))
                    .or_else(|| active.get("created"))?;

                let contract_id = created
                    .get("contractId")
                    .and_then(|v| v.as_str())
                    .map(String::from)?;
                let template_id = created
                    .get("templateId")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_default();
                let payload = created
                    .get("createArguments")
                    .or_else(|| created.get("arguments"))
                    .or_else(|| created.get("payload"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                Some(JsonApiContract {
                    contract_id,
                    template_id,
                    payload,
                })
            })
            .collect()
    }
}

/// JSON Ledger API v2 contract representation, normalized for adapter use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonApiContract {
    #[serde(rename = "contractId")]
    pub contract_id: String,
    #[serde(rename = "templateId")]
    pub template_id: String,
    pub payload: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_canton_adapter_creation() {
        let config = CantonConfig::new(
            "localhost",
            5001,
            vec!["sync1".to_string(), "sync2".to_string()],
            "alice::abc123",
            "tenzro-bridge-test",
        );

        let adapter = CantonAdapter::new(config);
        assert_eq!(adapter.protocol_name(), "canton");
        assert_eq!(adapter.supported_chains().len(), 2);
    }

    #[tokio::test]
    async fn test_estimate_fee() {
        let config = CantonConfig::new(
            "localhost",
            5001,
            vec!["sync1".to_string()],
            "alice::abc123",
            "tenzro-bridge-test",
        );

        let adapter = CantonAdapter::new(config);
        let fee = adapter.estimate_fee("canton-sync1", 100).await.unwrap();
        assert_eq!(fee, 1000 + (100 * 10)); // base_fee + (100 * per_byte_fee)
    }

    #[tokio::test]
    async fn test_unsupported_chain() {
        let config = CantonConfig::new(
            "localhost",
            5001,
            vec!["sync1".to_string()],
            "alice::abc123",
            "tenzro-bridge-test",
        );

        let adapter = CantonAdapter::new(config);
        let result = adapter.estimate_fee("canton-sync2", 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_json_api_url_construction() {
        let config = CantonConfig::new(
            "localhost",
            5001,
            vec!["sync1".to_string()],
            "alice::abc123",
            "tenzro-bridge-test",
        );

        let adapter = CantonAdapter::new(config);
        // Canton 3.x JSON Ledger API is mounted at /v2
        assert_eq!(adapter.json_api_url(), "http://localhost:7575/v2");
    }

    #[tokio::test]
    async fn test_json_api_url_with_tls() {
        let config = CantonConfig::new(
            "participant.canton.network",
            5001,
            vec!["sync1".to_string()],
            "alice::abc123",
            "tenzro-bridge-test",
        )
        .with_tls(true);

        let adapter = CantonAdapter::new(config);
        assert_eq!(
            adapter.json_api_url(),
            "https://participant.canton.network:7575/v2"
        );
    }

    #[tokio::test]
    async fn test_transfer_not_found() {
        let config = CantonConfig::default();
        let adapter = CantonAdapter::new(config);

        let result = adapter.get_transfer_status("non-existent-id").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_config_builder() {
        let config = CantonConfig::new(
            "localhost",
            5001,
            vec!["sync1".to_string()],
            "alice::abc123",
            "tenzro-bridge-test",
        )
        .with_tls(true)
        .with_jwt_token("test-token-123")
        .with_json_api_port(8080)
        .with_admin_port(8081);

        assert_eq!(config.participant_host, "localhost");
        assert_eq!(config.json_api_port, 8080);
        assert_eq!(config.admin_api_port, 8081);
        assert!(config.tls_enabled);
        assert_eq!(config.jwt_token, Some("test-token-123".to_string()));
    }
}
