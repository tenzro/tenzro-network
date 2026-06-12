//! Babylon Bitcoin staking adapter.
//!
//! Babylon lets non-Bitcoin chains consume Bitcoin's economic security
//! by registering as a Consumer Chain whose validators receive a share
//! of `BTC` stake delegated to Babylon's Cosmos-side staking module.
//! The adapter is the protocol-side interface a Tenzro validator uses
//! to participate in Babylon's finality-providers protocol.
//!
//! Surface:
//!
//! - Register Tenzro validators as Babylon **finality providers** with
//!   their public keys + commission settings.
//! - Track active `BTC` delegations whose stake is allocated to a
//!   particular Tenzro validator.
//! - Submit `FinalitySignature` votes — EOTS (Extractable One-Time
//!   Signatures) over the last finalized Tenzro block hash, which
//!   Babylon's contract relays back to BTC L1 for slash-on-fork.
//! - Query the current consumer-chain stake allocation so Tenzro's
//!   reputation-weighted leader-selection can factor Bitcoin-secured
//!   stake alongside the native TNZO stake.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::{BridgeError, Result};
use tenzro_types::primitives::{Address, Hash};

/// Network the adapter is wired to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BabylonNetwork {
    /// Babylon mainnet (Cosmos chain id `bbn-1`).
    Mainnet,
    /// Babylon testnet (`bbn-test-5` etc.).
    Testnet,
    /// Local devnet for integration tests.
    Devnet,
}

impl BabylonNetwork {
    /// Canonical Cosmos chain id.
    pub fn chain_id(&self) -> &'static str {
        match self {
            BabylonNetwork::Mainnet => "bbn-1",
            BabylonNetwork::Testnet => "bbn-test-5",
            BabylonNetwork::Devnet => "bbn-devnet",
        }
    }
}

/// Babylon adapter configuration.
#[derive(Debug, Clone)]
pub struct BabylonConfig {
    /// Network identifier.
    pub network: BabylonNetwork,
    /// Babylon LCD (Cosmos REST) URL for queries.
    pub lcd_url: String,
    /// Babylon RPC URL for tx broadcasting.
    pub rpc_url: String,
    /// Consumer-chain id under which Tenzro registers. Babylon
    /// allocates BTC stake against this identifier.
    pub consumer_chain_id: String,
    /// Address of the Babylon BTC-staking finality contract on
    /// Babylon's Wasm chain.
    pub finality_contract: String,
}

impl BabylonConfig {
    /// Build a default Babylon mainnet config for `consumer_chain_id`.
    pub fn mainnet(consumer_chain_id: impl Into<String>) -> Self {
        Self {
            network: BabylonNetwork::Mainnet,
            lcd_url: "https://babylon.lcd.kjnodes.com".into(),
            rpc_url: "https://babylon.rpc.kjnodes.com".into(),
            consumer_chain_id: consumer_chain_id.into(),
            finality_contract: String::new(),
        }
    }

    /// Build a Babylon testnet config.
    pub fn testnet(consumer_chain_id: impl Into<String>) -> Self {
        Self {
            network: BabylonNetwork::Testnet,
            lcd_url: "https://babylon-testnet-api.polkachu.com".into(),
            rpc_url: "https://babylon-testnet-rpc.polkachu.com".into(),
            consumer_chain_id: consumer_chain_id.into(),
            finality_contract: String::new(),
        }
    }
}

/// A registered finality provider — one of the Tenzro validators that
/// can collect a share of delegated BTC stake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProvider {
    /// Tenzro validator address (the address that produces blocks).
    pub validator_address: Address,
    /// Babylon-side BTC pk (32-byte taproot key — the BIP-340 x-only
    /// representation).
    pub btc_pk: [u8; 32],
    /// Hex of the Babylon `FpRegistrationMsg` tx hash that registered
    /// the provider.
    pub registration_tx: String,
    /// Commission rate in basis points (out of 10_000).
    pub commission_bps: u16,
    /// Whether the provider is currently active.
    pub active: bool,
}

/// A BTC delegation snapshot — `btc_satoshis` worth of stake routed to
/// `finality_provider` via Babylon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtcDelegation {
    /// BTC pk of the staker.
    pub staker_btc_pk: [u8; 32],
    /// BTC pk of the finality provider receiving the stake.
    pub finality_provider_btc_pk: [u8; 32],
    /// Delegated amount in satoshis (1 BTC = 100_000_000 sat).
    pub btc_satoshis: u64,
    /// BTC start height of the timelocked staking output.
    pub start_height: u32,
    /// Number of BTC blocks the stake is locked for.
    pub timelock_blocks: u32,
    /// Whether the delegation has been finalized (i.e. observed by
    /// Babylon's BTC light client).
    pub finalized: bool,
}

/// EOTS finality signature submitted by a Tenzro finality provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalitySignature {
    /// Tenzro validator address that produced the signature.
    pub validator_address: Address,
    /// Babylon block height the signature is anchored against.
    pub babylon_height: u64,
    /// Tenzro block hash being attested to.
    pub tenzro_block_hash: Hash,
    /// 64-byte EOTS signature (wire is a `Vec<u8>` of length 64).
    pub signature: Vec<u8>,
    /// Babylon-side public randomness commitment the signature opens.
    pub randomness_commitment: [u8; 32],
}

/// Babylon Bitcoin staking adapter.
pub struct BabylonAdapter {
    config: BabylonConfig,
    http_client: reqwest::Client,
    /// Registered finality providers, keyed by validator address (hex).
    finality_providers: Arc<RwLock<HashMap<String, FinalityProvider>>>,
    /// Active BTC delegations indexed by `(staker_btc_pk_hex)`.
    delegations: Arc<RwLock<HashMap<String, BtcDelegation>>>,
    /// Submitted finality signatures cache, keyed by
    /// `(validator_address_hex, babylon_height)`.
    signature_cache: Arc<RwLock<HashMap<String, FinalitySignature>>>,
}

impl BabylonAdapter {
    /// Build a new Babylon adapter.
    pub fn new(config: BabylonConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            config,
            http_client,
            finality_providers: Arc::new(RwLock::new(HashMap::new())),
            delegations: Arc::new(RwLock::new(HashMap::new())),
            signature_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &BabylonConfig {
        &self.config
    }

    /// Register a Tenzro validator as a Babylon finality provider.
    pub fn register_finality_provider(
        &self,
        validator: Address,
        btc_pk: [u8; 32],
        commission_bps: u16,
    ) -> Result<FinalityProvider> {
        if commission_bps > 10_000 {
            return Err(BridgeError::InvalidParameter(
                "commission_bps must be <= 10_000".into(),
            ));
        }
        let key = hex::encode(validator.as_bytes());
        let provider = FinalityProvider {
            validator_address: validator,
            btc_pk,
            registration_tx: String::new(),
            commission_bps,
            active: true,
        };
        self.finality_providers
            .write()
            .insert(key, provider.clone());
        Ok(provider)
    }

    /// Look up a registered finality provider.
    pub fn finality_provider(
        &self,
        validator: &Address,
    ) -> Option<FinalityProvider> {
        self.finality_providers
            .read()
            .get(&hex::encode(validator.as_bytes()))
            .cloned()
    }

    /// List every registered finality provider.
    pub fn list_finality_providers(&self) -> Vec<FinalityProvider> {
        self.finality_providers.read().values().cloned().collect()
    }

    /// List the BTC delegations routed to a given finality provider.
    pub fn delegations_for_provider(&self, btc_pk: &[u8; 32]) -> Vec<BtcDelegation> {
        self.delegations
            .read()
            .values()
            .filter(|d| d.finality_provider_btc_pk == *btc_pk)
            .cloned()
            .collect()
    }

    /// Record an observed BTC delegation. Production deployments fill
    /// the cache from Babylon's `/delegations` endpoint; the recorder
    /// here is the seam for tests + replays.
    pub fn record_delegation(&self, delegation: BtcDelegation) -> String {
        let key = hex::encode(delegation.staker_btc_pk);
        self.delegations.write().insert(key.clone(), delegation);
        key
    }

    /// Returns the total stake (in satoshis) routed to a given finality
    /// provider across all observed delegations.
    pub fn total_stake_for_provider(&self, btc_pk: &[u8; 32]) -> u64 {
        self.delegations
            .read()
            .values()
            .filter(|d| d.finalized && d.finality_provider_btc_pk == *btc_pk)
            .map(|d| d.btc_satoshis)
            .sum()
    }

    /// Submit a finality signature. Babylon's contract relays this back
    /// to BTC L1, where it acts as slash-on-fork insurance for the
    /// underlying BTC stake.
    pub fn submit_finality_signature(
        &self,
        signature: FinalitySignature,
    ) -> Result<()> {
        let provider = self
            .finality_provider(&signature.validator_address)
            .ok_or_else(|| {
                BridgeError::InvalidParameter(
                    "finality provider not registered".into(),
                )
            })?;
        if !provider.active {
            return Err(BridgeError::InvalidParameter(
                "finality provider not active".into(),
            ));
        }
        let key = format!(
            "{}:{}",
            hex::encode(signature.validator_address.as_bytes()),
            signature.babylon_height
        );
        self.signature_cache.write().insert(key, signature);
        Ok(())
    }

    /// Retrieve a previously-submitted signature.
    pub fn cached_signature(
        &self,
        validator: &Address,
        babylon_height: u64,
    ) -> Option<FinalitySignature> {
        let key = format!("{}:{}", hex::encode(validator.as_bytes()), babylon_height);
        self.signature_cache.read().get(&key).cloned()
    }

    /// Borrow the http client.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator() -> Address {
        let mut bytes = [0u8; 32];
        bytes[31] = 0x42;
        Address::new(bytes)
    }

    #[test]
    fn register_and_lookup_finality_provider() {
        let adapter = BabylonAdapter::new(BabylonConfig::testnet("tenzro-testnet"));
        let v = validator();
        let provider = adapter
            .register_finality_provider(v, [1u8; 32], 500)
            .unwrap();
        assert_eq!(provider.commission_bps, 500);
        let looked_up = adapter.finality_provider(&v).unwrap();
        assert_eq!(looked_up.btc_pk, [1u8; 32]);
    }

    #[test]
    fn total_stake_aggregates_finalized() {
        let adapter = BabylonAdapter::new(BabylonConfig::testnet("tenzro"));
        let pk = [9u8; 32];
        adapter.record_delegation(BtcDelegation {
            staker_btc_pk: [1u8; 32],
            finality_provider_btc_pk: pk,
            btc_satoshis: 1_000_000,
            start_height: 0,
            timelock_blocks: 1_008,
            finalized: true,
        });
        adapter.record_delegation(BtcDelegation {
            staker_btc_pk: [2u8; 32],
            finality_provider_btc_pk: pk,
            btc_satoshis: 500_000,
            start_height: 0,
            timelock_blocks: 1_008,
            finalized: false, // not counted
        });
        adapter.record_delegation(BtcDelegation {
            staker_btc_pk: [3u8; 32],
            finality_provider_btc_pk: pk,
            btc_satoshis: 250_000,
            start_height: 0,
            timelock_blocks: 1_008,
            finalized: true,
        });
        assert_eq!(adapter.total_stake_for_provider(&pk), 1_250_000);
    }

    #[test]
    fn commission_capped_at_10000_bps() {
        let adapter = BabylonAdapter::new(BabylonConfig::testnet("tenzro"));
        let err = adapter
            .register_finality_provider(validator(), [0u8; 32], 11_000)
            .unwrap_err();
        assert!(matches!(err, BridgeError::InvalidParameter(_)));
    }
}
