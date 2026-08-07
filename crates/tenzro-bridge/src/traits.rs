//! Core bridge adapter traits and types
//!
//! This module defines the primary trait that all bridge adapters must implement,
//! as well as common types used across bridge implementations.

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tenzro_types::primitives::Hash;

/// Classification of a bridge adapter for routing purposes.
///
/// Adapters declare one or more classes via [`BridgeAdapter::classes`].
/// [`RoutingStrategy::Regulated`] filters available routes to adapters
/// that include [`BridgeAdapterClass::RegulatedRail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BridgeAdapterClass {
    /// Generic adapter (LayerZero, deBridge, LI.FI, etc.).
    Generic,
    /// Adapter that verifies inbound messages against an attested
    /// committee or quorum on top of the underlying transport
    /// (Chainlink CCIP commit-store + RMN ARM, Wormhole NTT Guardian
    /// quorum, etc.).
    RegulatedRail,
}

/// Core bridge adapter trait that all bridge protocols must implement
#[async_trait]
pub trait BridgeAdapter: Send + Sync {
    /// Returns the name of this bridge protocol
    fn protocol_name(&self) -> &str;

    /// Returns the classes this adapter belongs to. Default is
    /// [`BridgeAdapterClass::Generic`]. Regulated rails (CCIP,
    /// Wormhole NTT) override to include
    /// [`BridgeAdapterClass::RegulatedRail`].
    fn classes(&self) -> Vec<BridgeAdapterClass> {
        vec![BridgeAdapterClass::Generic]
    }

    /// Returns the list of chains supported by this adapter
    fn supported_chains(&self) -> Vec<ChainInfo>;

    /// Sends a cross-chain message to the destination chain
    ///
    /// # Arguments
    /// * `dest_chain` - The destination chain identifier
    /// * `payload` - The message payload to send
    ///
    /// # Returns
    /// The message ID for tracking
    async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String>;

    /// Receives and processes a cross-chain message from the source chain
    ///
    /// # Arguments
    /// * `source_chain` - The source chain identifier
    /// * `payload` - The message payload received
    ///
    /// # Returns
    /// The quorum-verified inner [`TenzroMessage`] when the payload
    /// carries one, `None` when the payload is a provider-native
    /// message with no Tenzro envelope. Consumers that mint or release
    /// funds MUST bind their action to the returned message.
    async fn receive_message(
        &self,
        source_chain: &str,
        payload: Vec<u8>,
    ) -> Result<Option<crate::message_format::TenzroMessage>>;

    /// Initiates a token bridge transfer
    ///
    /// # Arguments
    /// * `request` - The bridge transfer request
    ///
    /// # Returns
    /// A receipt with transfer details
    async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt>;

    /// Gets the status of a cross-chain transfer
    ///
    /// # Arguments
    /// * `transfer_id` - The transfer identifier
    ///
    /// # Returns
    /// The current status of the transfer
    async fn get_transfer_status(&self, transfer_id: &str) -> Result<TransferStatus>;

    /// Estimates the fee for sending a message
    ///
    /// # Arguments
    /// * `dest_chain` - The destination chain identifier
    /// * `payload_size` - Size of the payload in bytes
    ///
    /// # Returns
    /// The estimated fee in the smallest unit of the native token
    async fn estimate_fee(&self, dest_chain: &str, payload_size: usize) -> Result<u128>;
}

/// Information about a supported blockchain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainInfo {
    /// Chain identifier (e.g., "ethereum", "arbitrum")
    pub chain_id: String,
    /// Human-readable chain name
    pub name: String,
    /// Native token symbol
    pub native_token: String,
    /// Average finality time in seconds
    pub finality_time_secs: u64,
}

impl ChainInfo {
    /// The CAIP-2 identifier for this chain, where a verified one exists.
    ///
    /// The bridge layer names chains (`"ethereum"`) because that is what the
    /// underlying protocols route on; settlement uses CAIP-2 (`eip155:1`)
    /// because that is what x402 v2 puts on the wire. This resolves across the
    /// two through the single mapping in `tenzro-types`, rather than each
    /// adapter keeping a table that can drift from the settlement registry.
    ///
    /// `None` means no *verified* mapping — Cosmos and Move family chains, and
    /// chains whose mainnet is absent from the EIP-155 registry. Those remain
    /// reachable and mirrorable by name; the alternative, inventing an
    /// identifier, is the only option that could route value to the wrong
    /// chain.
    pub fn caip2(&self) -> Option<&'static str> {
        tenzro_types::settlement_network::caip2_for_chain_name(&self.chain_id)
    }

    /// Creates a new ChainInfo
    pub fn new(
        chain_id: impl Into<String>,
        name: impl Into<String>,
        native_token: impl Into<String>,
        finality_time_secs: u64,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            name: name.into(),
            native_token: native_token.into(),
            finality_time_secs,
        }
    }
}

/// Request to bridge tokens across chains
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeTokenRequest {
    /// Source chain identifier
    pub source_chain: String,
    /// Destination chain identifier
    pub dest_chain: String,
    /// Asset identifier to bridge
    pub asset_id: String,
    /// Amount to bridge (in smallest unit)
    pub amount: u128,
    /// Sender address on source chain
    pub sender: String,
    /// Recipient address on destination chain
    pub recipient: String,
    /// Additional data for the transfer
    pub extra_data: Option<Vec<u8>>,
}

impl BridgeTokenRequest {
    /// Creates a new bridge token request
    pub fn new(
        source_chain: impl Into<String>,
        dest_chain: impl Into<String>,
        asset_id: impl Into<String>,
        amount: u128,
        sender: impl Into<String>,
        recipient: impl Into<String>,
    ) -> Self {
        Self {
            source_chain: source_chain.into(),
            dest_chain: dest_chain.into(),
            asset_id: asset_id.into(),
            amount,
            sender: sender.into(),
            recipient: recipient.into(),
            extra_data: None,
        }
    }

    /// Adds extra data to the request
    pub fn with_extra_data(mut self, data: Vec<u8>) -> Self {
        self.extra_data = Some(data);
        self
    }
}

/// Receipt for a bridge token transfer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeTokenReceipt {
    /// Unique transfer identifier
    pub transfer_id: String,
    /// Transaction hash on source chain
    pub tx_hash: Hash,
    /// Estimated arrival time (Unix timestamp in milliseconds)
    pub estimated_arrival: i64,
    /// Fee paid for the transfer (in smallest unit)
    pub fee_paid: u128,
    /// Source chain identifier
    pub source_chain: String,
    /// Destination chain identifier
    pub dest_chain: String,
}

impl BridgeTokenReceipt {
    /// Creates a new bridge token receipt
    pub fn new(
        transfer_id: impl Into<String>,
        tx_hash: Hash,
        estimated_arrival: i64,
        fee_paid: u128,
        source_chain: impl Into<String>,
        dest_chain: impl Into<String>,
    ) -> Self {
        Self {
            transfer_id: transfer_id.into(),
            tx_hash,
            estimated_arrival,
            fee_paid,
            source_chain: source_chain.into(),
            dest_chain: dest_chain.into(),
        }
    }
}

/// Status of a cross-chain transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferStatus {
    /// Transfer is pending initial confirmation
    Pending,
    /// Transfer confirmed on source chain
    SourceConfirmed,
    /// Transfer is being relayed across chains
    InTransit,
    /// Transfer successfully delivered to destination
    Delivered,
    /// Transfer failed
    Failed,
}

impl TransferStatus {
    /// Returns true if the transfer is in a final state
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Delivered | Self::Failed)
    }

    /// Returns true if the transfer is still in progress
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::SourceConfirmed | Self::InTransit
        )
    }
}

#[cfg(test)]
mod caip2_tests {
    use super::*;

    #[test]
    fn an_adapter_chain_resolves_to_its_settlement_identifier() {
        // The two identifier schemes meeting: the adapter names the chain,
        // settlement needs CAIP-2, and neither layer keeps its own table.
        let base = ChainInfo::new("base", "Base", "ETH", 2);
        assert_eq!(base.caip2(), Some("eip155:8453"));
        let xrpl = ChainInfo::new("xrpl", "XRP Ledger", "XRP", 4);
        assert_eq!(xrpl.caip2(), Some("xrpl:0"));
    }

    #[test]
    fn a_chain_with_no_verified_identifier_resolves_to_none_not_a_guess() {
        // Still fully reachable through its adapter — it just mirrors by name.
        let osmosis = ChainInfo::new("osmosis", "Osmosis", "OSMO", 6);
        assert_eq!(osmosis.caip2(), None);
    }

    #[test]
    fn resolution_does_not_depend_on_how_the_adapter_cased_the_name() {
        assert_eq!(
            ChainInfo::new("Ethereum", "Ethereum", "ETH", 780).caip2(),
            Some("eip155:1")
        );
    }
}
