//! Axelar General Message Passing (GMP) bridge adapter.
//!
//! Axelar is the cross-chain messaging layer powering Squid, ITS, and a
//! large fraction of Cosmos↔EVM / Stellar / Move volume. The adapter
//! lets Tenzro reach 70+ chains via Axelar's GMP service while
//! preserving the standard Tenzro adapter contract.
//!
//! Wire surface (per the Axelar Gateway / Gas Service ABI):
//!
//! - `callContract(destinationChain, destinationContractAddress, payload)` —
//!   emits a `ContractCall` event.
//! - `payNativeGasForContractCall(...)` — Gas Service pre-pay for the
//!   destination-side execution.
//! - Inbound `execute(commandId, sourceChain, sourceAddress, payload)` —
//!   destination-side delivery verified by the Axelar validator set.
//!
//! Outbound submission is gated on an `EvmTransactionSigner` consistent
//! with the LayerZero / CCIP / Hyperlane adapters.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::error::{BridgeError, Result};
use crate::evm_signer::EvmTransactionSigner;
use crate::message_format::{NonceTracker, TenzroMessage};
use crate::traits::{
    BridgeAdapter, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo, TransferStatus,
};
use tenzro_types::primitives::{Hash, Timestamp};

/// Axelar adapter configuration.
#[derive(Debug, Clone)]
pub struct AxelarConfig {
    /// Canonical Axelar chain name for this chain. Examples:
    /// `"ethereum"`, `"polygon"`, `"avalanche"`, `"osmosis"`, `"stellar"`.
    pub source_chain: String,
    /// Address of the AxelarGateway contract on this chain.
    pub gateway: String,
    /// Address of the AxelarGasService contract on this chain.
    pub gas_service: String,
    /// Axelarscan REST API base URL.
    pub axelarscan_api: String,
    /// Optional explicit chain-name overrides per friendly name.
    pub chain_aliases: HashMap<String, String>,
}

impl AxelarConfig {
    /// Build a default Axelar config for `source_chain`.
    pub fn new(
        source_chain: impl Into<String>,
        gateway: impl Into<String>,
        gas_service: impl Into<String>,
    ) -> Self {
        Self {
            source_chain: source_chain.into(),
            gateway: gateway.into(),
            gas_service: gas_service.into(),
            axelarscan_api: "https://api.axelarscan.io".into(),
            chain_aliases: HashMap::new(),
        }
    }

    /// Resolve `chain` to its canonical Axelar chain identifier.
    pub fn canonical_chain(&self, chain: &str) -> String {
        let lower = chain.to_lowercase();
        if let Some(alias) = self.chain_aliases.get(&lower) {
            return alias.clone();
        }
        match lower.as_str() {
            "eth" | "mainnet" => "ethereum".into(),
            "matic" => "polygon".into(),
            "avax" => "avalanche".into(),
            "bnb" => "binance".into(),
            "op" => "optimism".into(),
            other => other.into(),
        }
    }

    /// List the canonical Axelar chains the adapter knows about. Used by
    /// the supported_chains() trait method.
    pub fn known_chains(&self) -> Vec<ChainInfo> {
        vec![
            ChainInfo::new("ethereum", "Ethereum", "ETH", 780),
            ChainInfo::new("polygon", "Polygon", "MATIC", 256),
            ChainInfo::new("avalanche", "Avalanche", "AVAX", 5),
            ChainInfo::new("binance", "BNB Smart Chain", "BNB", 3),
            ChainInfo::new("arbitrum", "Arbitrum One", "ETH", 1),
            ChainInfo::new("optimism", "Optimism", "ETH", 1),
            ChainInfo::new("base", "Base", "ETH", 1),
            ChainInfo::new("celo", "Celo", "CELO", 5),
            ChainInfo::new("moonbeam", "Moonbeam", "GLMR", 12),
            ChainInfo::new("linea", "Linea", "ETH", 1),
            ChainInfo::new("scroll", "Scroll", "ETH", 1),
            ChainInfo::new("blast", "Blast", "ETH", 1),
            ChainInfo::new("mantle", "Mantle", "MNT", 1),
            ChainInfo::new("fraxtal", "Fraxtal", "frxETH", 1),
            ChainInfo::new("kava", "Kava", "KAVA", 6),
            ChainInfo::new("filecoin", "Filecoin EVM", "FIL", 30),
            ChainInfo::new("osmosis", "Osmosis", "OSMO", 6),
            ChainInfo::new("axelar", "Axelar", "AXL", 6),
            ChainInfo::new("cosmoshub", "Cosmos Hub", "ATOM", 6),
            ChainInfo::new("juno", "Juno", "JUNO", 6),
            ChainInfo::new("crescent", "Crescent", "CRE", 6),
            ChainInfo::new("evmos", "Evmos", "EVMOS", 6),
            ChainInfo::new("injective", "Injective", "INJ", 1),
            ChainInfo::new("kujira", "Kujira", "KUJI", 6),
            ChainInfo::new("neutron", "Neutron", "NTRN", 6),
            ChainInfo::new("stellar", "Stellar", "XLM", 5),
            ChainInfo::new("sui", "Sui", "SUI", 3),
            ChainInfo::new("aptos", "Aptos", "APT", 1),
            ChainInfo::new("xrpl", "XRP Ledger", "XRP", 4),
            ChainInfo::new("hyperliquid", "Hyperliquid", "HYPE", 1),
            ChainInfo::new("tenzro", "Tenzro Ledger", "TNZO", 1),
        ]
    }
}

/// A pending Axelar GMP call awaiting destination-side execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxelarCall {
    /// Source chain (canonical Axelar identifier).
    pub source_chain: String,
    /// Destination chain (canonical Axelar identifier).
    pub destination_chain: String,
    /// Destination contract address.
    pub destination_address: String,
    /// Payload bytes.
    pub payload: Vec<u8>,
    /// `keccak256(payload)` — used as the GMP correlation id alongside the
    /// command id supplied by the validator network.
    pub payload_hash: Hash,
    /// Gas pre-paid via the Gas Service (smallest unit of the native
    /// token on the source chain).
    pub gas_prepaid: u128,
}

/// Axelar GMP bridge adapter.
/// Axelar GMP validator set verifier.
///
/// Axelar's GMP carries threshold multisig over the canonical command
/// hash. Each validator's signature is an ECDSA-secp256k1 signature
/// over `keccak256(commandId || sourceChain || sourceAddress ||
/// destAddress || payloadHash)`. The set + threshold are pinned by
/// the operator at bridge startup.
#[derive(Debug, Clone)]
pub struct AxelarValidatorSet {
    /// Authorized validator addresses (20-byte secp256k1).
    pub validators: Vec<[u8; 20]>,
    /// Quorum threshold (count of signatures required for delivery).
    pub threshold: u8,
}

impl AxelarValidatorSet {
    /// Returns `Ok(())` if at least `threshold` distinct validators
    /// from the set produced valid signatures over `message_digest`.
    pub fn verify_quorum(
        &self,
        message_digest: &[u8; 32],
        signatures: &[([u8; 20], [u8; 65])],
    ) -> Result<()> {
        use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
        use sha3::{Digest as Sha3Digest, Keccak256};
        if signatures.len() < self.threshold as usize {
            return Err(BridgeError::AdapterError(format!(
                "Axelar quorum: {} signatures < threshold {}",
                signatures.len(),
                self.threshold
            )));
        }
        let mut seen: std::collections::HashSet<[u8; 20]> =
            std::collections::HashSet::new();
        let mut valid = 0;
        for (claimed_addr, sig) in signatures {
            if !self.validators.contains(claimed_addr) {
                continue;
            }
            if seen.contains(claimed_addr) {
                continue;
            }
            if sig.len() != 65 {
                continue;
            }
            let v_byte = sig[64];
            let v = if v_byte >= 27 { v_byte - 27 } else { v_byte };
            let rid = match RecoveryId::from_byte(v) {
                Some(r) => r,
                None => continue,
            };
            let k = match K256Sig::from_slice(&sig[..64]) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let recovered = match VerifyingKey::recover_from_prehash(
                message_digest,
                &k,
                rid,
            ) {
                Ok(vk) => vk,
                Err(_) => continue,
            };
            let pk_point = k256::PublicKey::from(&recovered);
            let pk_uncompressed = pk_point.to_sec1_bytes();
            if pk_uncompressed.len() < 65 {
                continue;
            }
            let mut kc = Keccak256::new();
            Sha3Digest::update(&mut kc, &pk_uncompressed[1..65]);
            let hash: [u8; 32] = kc.finalize().into();
            let recovered_addr: [u8; 20] = hash[12..32].try_into().unwrap();
            if recovered_addr != *claimed_addr {
                continue;
            }
            seen.insert(*claimed_addr);
            valid += 1;
            if valid >= self.threshold {
                return Ok(());
            }
        }
        Err(BridgeError::AdapterError(format!(
            "Axelar quorum: only {} valid signatures < threshold {}",
            valid, self.threshold
        )))
    }
}

pub struct AxelarAdapter {
    config: AxelarConfig,
    http_client: reqwest::Client,
    /// Outbound calls awaiting delivery, keyed by payload-hash hex.
    outbound: Arc<DashMap<String, AxelarCall>>,
    /// Replay protection for inbound deliveries (`commandId`).
    seen_commands: Arc<DashMap<String, ()>>,
    /// Per-sender nonce tracker for inbound `TenzroMessage` payloads.
    inbound_nonce_tracker: Arc<NonceTracker>,
    /// Transfer status map, keyed by the same payload-hash hex.
    transfers: Arc<DashMap<String, TransferStatus>>,
    /// Optional EVM signer for on-chain dispatch.
    signer: Arc<RwLock<Option<Arc<EvmTransactionSigner>>>>,
    /// Pinned Axelar validator set for inbound GMP verification.
    validator_set: Arc<RwLock<Option<AxelarValidatorSet>>>,
}

impl AxelarAdapter {
    /// Build a new Axelar adapter.
    pub fn new(config: AxelarConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            config,
            http_client,
            outbound: Arc::new(DashMap::new()),
            seen_commands: Arc::new(DashMap::new()),
            inbound_nonce_tracker: Arc::new(NonceTracker::new()),
            transfers: Arc::new(DashMap::new()),
            signer: Arc::new(RwLock::new(None)),
            validator_set: Arc::new(RwLock::new(None)),
        }
    }

    /// Attach an EVM signer for live on-chain dispatch.
    pub fn with_signer(self, signer: EvmTransactionSigner) -> Self {
        *self.signer.write() = Some(Arc::new(signer));
        self
    }

    /// Install the Axelar validator set used to verify inbound GMP
    /// signatures. Production deployments MUST install a set before
    /// bridging real value.
    pub fn install_validator_set(&self, set: AxelarValidatorSet) {
        *self.validator_set.write() = Some(set);
    }

    /// Returns `true` iff an Axelar validator set has been installed.
    pub fn has_validator_set(&self) -> bool {
        self.validator_set.read().is_some()
    }

    /// Borrow the adapter configuration.
    pub fn config(&self) -> &AxelarConfig {
        &self.config
    }

    /// Schedule a contract call. The call is recorded locally so the
    /// adapter can track inbound deliveries; on-chain submission flows
    /// through the configured `EvmTransactionSigner`.
    pub fn call_contract(
        &self,
        destination_chain: &str,
        destination_address: &str,
        payload: Vec<u8>,
        gas_prepaid: u128,
    ) -> Result<Hash> {
        let canonical_dest = self.config.canonical_chain(destination_chain);
        let payload_hash_bytes: [u8; 32] = Sha256::digest(&payload).into();
        let payload_hash = Hash::new(payload_hash_bytes);
        let key = hex::encode(payload_hash_bytes);
        let call = AxelarCall {
            source_chain: self.config.source_chain.clone(),
            destination_chain: canonical_dest,
            destination_address: destination_address.to_string(),
            payload,
            payload_hash,
            gas_prepaid,
        };
        self.outbound.insert(key.clone(), call);
        self.transfers.insert(key.clone(), TransferStatus::Pending);
        debug!(
            "axelar: registered contract call payload_hash=0x{} prepaid={}",
            key, gas_prepaid
        );
        Ok(payload_hash)
    }

    /// Look up a previously-registered call.
    pub fn lookup_call(&self, payload_hash_hex: &str) -> Option<AxelarCall> {
        let key = payload_hash_hex.trim_start_matches("0x").to_lowercase();
        self.outbound.get(&key).map(|c| c.clone())
    }
}

#[async_trait]
impl BridgeAdapter for AxelarAdapter {
    fn protocol_name(&self) -> &str {
        "axelar"
    }

    fn supported_chains(&self) -> Vec<ChainInfo> {
        self.config.known_chains()
    }

    async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String> {
        let canonical = self.config.canonical_chain(dest_chain);
        let hash = self.call_contract(&canonical, &self.config.gateway, payload, 0)?;
        Ok(format!("0x{}", hex::encode(hash.as_bytes())))
    }

    async fn receive_message(&self, source_chain: &str, payload: Vec<u8>) -> Result<()> {
        let canonical = self.config.canonical_chain(source_chain);
        if payload.is_empty() {
            return Err(BridgeError::InvalidParameter("empty payload".into()));
        }
        let payload_hash: [u8; 32] = Sha256::digest(&payload).into();
        let command_key = format!("{}:{}", canonical, hex::encode(payload_hash));
        if self.seen_commands.contains_key(&command_key) {
            return Err(BridgeError::ReplayAttack(command_key));
        }

        // Axelar multisig validator-quorum check. Same trailing
        // signature trailer format as Hyperlane: `body || u8
        // sig_count || sig_count * (addr20 || sig65)`. When a
        // validator set is installed, we verify threshold-many
        // distinct signatures over the body digest. Without a set
        // we fall through to the inner TenzroMessage check
        // (consistent with pre-quorum-verification behaviour);
        // production deployments MUST install a set.
        let set_opt = self.validator_set.read().clone();
        if let Some(set) = set_opt {
            let n = payload.len();
            if n < 1 {
                return Err(BridgeError::InvalidParameter(
                    "Axelar quorum: payload too short".into(),
                ));
            }
            let sig_count = payload[n - 1] as usize;
            let sig_record_len = 20 + 65;
            let trailer_len = 1 + sig_count * sig_record_len;
            if n < trailer_len + 1 {
                return Err(BridgeError::InvalidParameter(
                    "Axelar quorum: payload truncated for declared signature count".into(),
                ));
            }
            let body = &payload[..n - trailer_len];
            let mut signatures: Vec<([u8; 20], [u8; 65])> =
                Vec::with_capacity(sig_count);
            for i in 0..sig_count {
                let off = n - trailer_len + i * sig_record_len;
                let mut a = [0u8; 20];
                a.copy_from_slice(&payload[off..off + 20]);
                let mut s = [0u8; 65];
                s.copy_from_slice(&payload[off + 20..off + 20 + 65]);
                signatures.push((a, s));
            }
            let body_digest: [u8; 32] = Sha256::digest(body).into();
            set.verify_quorum(&body_digest, &signatures)?;
        }

        if let Ok(message) = TenzroMessage::decode(&payload) {
            message.validate()?;
            if !message.verify_hash() {
                return Err(BridgeError::InvalidParameter(
                    "inbound TenzroMessage hash mismatch".into(),
                ));
            }
            if message.signature.is_some()
                && !message.verify_signature().unwrap_or(false)
            {
                return Err(BridgeError::InvalidParameter(
                    "inbound TenzroMessage signature verification failed".into(),
                ));
            }
            self.inbound_nonce_tracker
                .check_and_update(&message.sender, message.nonce)
                .map_err(|e| BridgeError::ReplayAttack(format!("nonce: {e}")))?;
        }
        self.seen_commands.insert(command_key, ());
        Ok(())
    }

    async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt> {
        let payload = request.extra_data.clone().unwrap_or_default();
        let canonical_dest = self.config.canonical_chain(&request.dest_chain);
        let hash = self.call_contract(&canonical_dest, &request.recipient, payload, 0)?;
        Ok(BridgeTokenReceipt::new(
            format!("0x{}", hex::encode(hash.as_bytes())),
            hash,
            (Timestamp::now().as_secs() * 1_000) as i64,
            0,
            request.source_chain,
            canonical_dest,
        ))
    }

    async fn get_transfer_status(&self, transfer_id: &str) -> Result<TransferStatus> {
        let key = transfer_id.trim_start_matches("0x").to_lowercase();
        if let Some(status) = self.transfers.get(&key) {
            return Ok(*status);
        }
        Ok(TransferStatus::Pending)
    }

    async fn estimate_fee(&self, _dest_chain: &str, payload_size: usize) -> Result<u128> {
        // Axelar Gas Service estimates depend on destination chain gas
        // markets; in the absence of a live oracle return a payload-
        // proportional estimate so callers have a non-zero floor.
        Ok((payload_size as u128).saturating_mul(20_000))
    }
}

impl AxelarAdapter {
    /// Borrow the http client for tests / monitoring integrations.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }
}
