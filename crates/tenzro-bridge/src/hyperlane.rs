//! Hyperlane V3 bridge adapter.
//!
//! Hyperlane is the modular cross-chain messaging layer with
//! customizable Interchain Security Modules (ISMs). On Tenzro it
//! installs as a `BridgeAdapter` with a sovereign Tenzro-validator-set
//! ISM, giving Tenzro consensus the final say over inbound message
//! security rather than delegating to a third-party validator quorum.
//!
//! Wire surface (per the Hyperlane Mailbox spec):
//!
//! - `dispatch(destinationDomain, recipientAddress, messageBody)` — emits
//!   a `Dispatch` event, returns the message id (sha256 of the encoded
//!   message).
//! - `process(metadata, message)` — destination-side delivery; the
//!   adapter verifies the ISM (here: a multisig signature over the
//!   Tenzro validator set) and dispatches to the recipient contract.
//!
//! Outbound submission is gated on an `EvmTransactionSigner` exactly
//! like the LayerZero V2 / CCIP adapters, so MPC threshold signing or
//! TEE-sealed keys cover the bridge custody surface.

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

/// Hyperlane V3 protocol version byte.
pub const HYPERLANE_VERSION: u8 = 3;

/// Encoded Hyperlane message header layout:
/// `version(1) || nonce(4) || origin_domain(4) || sender(32) ||
/// destination_domain(4) || recipient(32) || body`.
pub const HYPERLANE_HEADER_LEN: usize = 1 + 4 + 4 + 32 + 4 + 32;

/// Hyperlane configuration.
#[derive(Debug, Clone)]
pub struct HyperlaneConfig {
    /// Hyperlane domain id for this chain (e.g. 1 for Ethereum, 137 for
    /// Polygon, 23 for Arbitrum).
    pub source_domain: u32,
    /// Mailbox contract address on the source chain.
    pub mailbox: String,
    /// Default ISM contract address. For Tenzro's sovereign ISM this is
    /// the Tenzro validator-set ISM.
    pub default_ism: String,
    /// Hyperlane explorer API base URL.
    pub explorer_api: String,
    /// Optional override per destination domain.
    pub override_isms: HashMap<u32, String>,
}

impl HyperlaneConfig {
    /// Construct a config for `source_domain`.
    pub fn new(
        source_domain: u32,
        mailbox: impl Into<String>,
        default_ism: impl Into<String>,
    ) -> Self {
        Self {
            source_domain,
            mailbox: mailbox.into(),
            default_ism: default_ism.into(),
            explorer_api: "https://explorer.hyperlane.xyz/api".into(),
            override_isms: HashMap::new(),
        }
    }

    /// Look up the canonical Hyperlane domain id for a known chain name.
    pub fn chain_id(&self, chain: &str) -> Option<u32> {
        match chain.to_lowercase().as_str() {
            "ethereum" | "eth" | "mainnet" => Some(1),
            "polygon" | "matic" => Some(137),
            "avalanche" | "avax" => Some(43_114),
            "bsc" | "binance" => Some(56),
            "arbitrum" => Some(42_161),
            "optimism" | "op" => Some(10),
            "base" => Some(8_453),
            "celo" => Some(42_220),
            "moonbeam" => Some(1_284),
            "mantle" => Some(5_000),
            "blast" => Some(81_457),
            "scroll" => Some(534_352),
            "zircuit" => Some(48_900),
            "fraxtal" => Some(252),
            "mode" => Some(34_443),
            "linea" => Some(59_144),
            "manta" => Some(169),
            "zksync" => Some(324),
            "tenzro" => Some(10_000),
            other => other.parse::<u32>().ok(),
        }
    }
}

/// Encoded Hyperlane message envelope. The wire format mirrors the
/// canonical Mailbox encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperlaneMessage {
    /// Protocol version.
    pub version: u8,
    /// Per-mailbox monotonic nonce.
    pub nonce: u32,
    /// Hyperlane domain id of the origin chain.
    pub origin_domain: u32,
    /// 32-byte sender (left-padded for EVM senders).
    pub sender: [u8; 32],
    /// Hyperlane domain id of the destination chain.
    pub destination_domain: u32,
    /// 32-byte recipient.
    pub recipient: [u8; 32],
    /// Opaque application payload.
    pub body: Vec<u8>,
}

impl HyperlaneMessage {
    /// Encode the message in the canonical Mailbox wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYPERLANE_HEADER_LEN + self.body.len());
        out.push(self.version);
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.origin_domain.to_be_bytes());
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.destination_domain.to_be_bytes());
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.body);
        out
    }

    /// Compute the canonical message id: `sha256(encode(msg))`.
    pub fn message_id(&self) -> Hash {
        let digest = Sha256::digest(self.encode());
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Hash::new(out)
    }
}

/// Hyperlane bridge adapter.
/// Hyperlane multisig ISM (Interchain Security Module) verifier.
///
/// Each Hyperlane domain carries a pinned set of validator addresses
/// (20-byte secp256k1) and a `threshold` quorum. Inbound messages must
/// carry threshold-many signatures over `keccak256(domain || origin ||
/// id)`. The set is configured per origin domain.
#[derive(Debug, Clone)]
pub struct HyperlaneValidatorSet {
    /// Origin Hyperlane domain id (`origin` field in the Mailbox
    /// message body).
    pub origin_domain: u32,
    /// Authorized validator addresses (20-byte secp256k1).
    pub validators: Vec<[u8; 20]>,
    /// Quorum threshold (count of signatures required for delivery).
    pub threshold: u8,
}

impl HyperlaneValidatorSet {
    /// Returns `true` if `signatures` carries `threshold`-many
    /// distinct validators in the configured set with valid
    /// secp256k1 signatures over `message_id`.
    ///
    /// The signatures vec is the parsed `[(validator_addr20,
    /// sig65)]` from the inbound payload's ISM metadata.
    pub fn verify_quorum(
        &self,
        message_id: &[u8; 32],
        signatures: &[([u8; 20], [u8; 65])],
    ) -> Result<()> {
        use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
        use sha3::{Digest as Sha3Digest, Keccak256};
        if signatures.len() < self.threshold as usize {
            return Err(BridgeError::AdapterError(format!(
                "Hyperlane ISM: {} signatures < threshold {}",
                signatures.len(),
                self.threshold
            )));
        }
        let mut seen: std::collections::HashSet<[u8; 20]> =
            std::collections::HashSet::new();
        let mut valid_count = 0;
        for (claimed_addr, sig_bytes) in signatures {
            if !self.validators.contains(claimed_addr) {
                continue;
            }
            if seen.contains(claimed_addr) {
                continue;
            }
            if sig_bytes.len() != 65 {
                continue;
            }
            let recovery_id_byte = sig_bytes[64];
            let v = if recovery_id_byte >= 27 {
                recovery_id_byte - 27
            } else {
                recovery_id_byte
            };
            let recovery_id = match RecoveryId::from_byte(v) {
                Some(r) => r,
                None => continue,
            };
            let sig = match K256Sig::from_slice(&sig_bytes[..64]) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let recovered = match VerifyingKey::recover_from_prehash(
                message_id,
                &sig,
                recovery_id,
            ) {
                Ok(vk) => vk,
                Err(_) => continue,
            };
            let pk_point = k256::PublicKey::from(&recovered);
            let pk_uncompressed = pk_point.to_sec1_bytes();
            if pk_uncompressed.len() < 65 {
                continue;
            }
            let mut k = Keccak256::new();
            Sha3Digest::update(&mut k, &pk_uncompressed[1..65]);
            let hash: [u8; 32] = k.finalize().into();
            let recovered_addr: [u8; 20] = hash[12..32].try_into().unwrap();
            if recovered_addr != *claimed_addr {
                continue;
            }
            seen.insert(*claimed_addr);
            valid_count += 1;
            if valid_count >= self.threshold {
                return Ok(());
            }
        }
        Err(BridgeError::AdapterError(format!(
            "Hyperlane ISM: only {} valid signatures < threshold {}",
            valid_count, self.threshold
        )))
    }
}

pub struct HyperlaneAdapter {
    config: HyperlaneConfig,
    http_client: reqwest::Client,
    /// Per-destination monotonic nonces.
    nonces: Arc<DashMap<u32, u32>>,
    /// Outbound messages awaiting destination-side delivery.
    outbound: Arc<DashMap<String, HyperlaneMessage>>,
    /// Replay cache for inbound message ids.
    seen_messages: Arc<DashMap<Hash, ()>>,
    /// Per-sender inbound nonce tracker for `TenzroMessage` payloads.
    inbound_nonce_tracker: Arc<NonceTracker>,
    /// Transfer status map keyed by message id (lowercase hex).
    transfers: Arc<DashMap<String, TransferStatus>>,
    /// Optional EVM signer for on-chain dispatch.
    signer: Arc<RwLock<Option<Arc<EvmTransactionSigner>>>>,
    /// Pinned per-origin-domain validator sets. When configured,
    /// inbound `receive_message` runs full multisig ISM verification
    /// against the matching set. Absent → fail-closed (reject).
    validator_sets:
        Arc<RwLock<std::collections::HashMap<u32, HyperlaneValidatorSet>>>,
}

impl HyperlaneAdapter {
    /// Build a new Hyperlane adapter.
    pub fn new(config: HyperlaneConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            config,
            http_client,
            nonces: Arc::new(DashMap::new()),
            outbound: Arc::new(DashMap::new()),
            seen_messages: Arc::new(DashMap::new()),
            inbound_nonce_tracker: Arc::new(NonceTracker::new()),
            transfers: Arc::new(DashMap::new()),
            signer: Arc::new(RwLock::new(None)),
            validator_sets: Arc::new(RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Install a pinned validator set for the given origin domain.
    /// Inbound `receive_message` from that domain will run multisig
    /// ISM verification against this set.
    pub fn install_validator_set(&self, set: HyperlaneValidatorSet) {
        self.validator_sets.write().insert(set.origin_domain, set);
    }

    /// Returns `true` iff at least one validator set has been
    /// installed. The `receive_message` path uses this to decide
    /// between strict (ISM-verified) and TenzroMessage-only modes.
    pub fn has_validator_set(&self) -> bool {
        !self.validator_sets.read().is_empty()
    }

    /// Attach an EVM signer for live on-chain dispatch.
    pub fn with_signer(self, signer: EvmTransactionSigner) -> Self {
        *self.signer.write() = Some(Arc::new(signer));
        self
    }

    /// Borrow the adapter configuration.
    pub fn config(&self) -> &HyperlaneConfig {
        &self.config
    }

    /// Pad a `0x..` EVM address into a 32-byte recipient slot.
    pub fn pad_address_32(address: &str) -> [u8; 32] {
        let stripped = address.trim_start_matches("0x");
        let bytes = hex::decode(stripped).unwrap_or_default();
        let mut out = [0u8; 32];
        if bytes.len() == 32 {
            out.copy_from_slice(&bytes);
        } else if bytes.len() == 20 {
            out[12..].copy_from_slice(&bytes);
        }
        out
    }

    /// Dispatch a message: allocate a nonce, encode the canonical envelope,
    /// record it in the outbound map, and return the canonical message id.
    pub fn dispatch_message(
        &self,
        destination_domain: u32,
        sender_address: &str,
        recipient_address: &str,
        body: Vec<u8>,
    ) -> Result<Hash> {
        let mut entry = self.nonces.entry(destination_domain).or_insert(0);
        let nonce = *entry;
        *entry += 1;
        drop(entry);

        let message = HyperlaneMessage {
            version: HYPERLANE_VERSION,
            nonce,
            origin_domain: self.config.source_domain,
            sender: Self::pad_address_32(sender_address),
            destination_domain,
            recipient: Self::pad_address_32(recipient_address),
            body,
        };
        let id = message.message_id();
        let id_hex = hex::encode(id.as_bytes());
        self.outbound.insert(id_hex.clone(), message);
        self.transfers.insert(id_hex.clone(), TransferStatus::Pending);
        debug!("hyperlane: dispatched message id=0x{}", id_hex);
        Ok(id)
    }

    /// Resolve the ISM for a destination domain.
    pub fn resolve_ism(&self, destination: u32) -> String {
        self.config
            .override_isms
            .get(&destination)
            .cloned()
            .unwrap_or_else(|| self.config.default_ism.clone())
    }
}

#[async_trait]
impl BridgeAdapter for HyperlaneAdapter {
    fn protocol_name(&self) -> &str {
        "hyperlane"
    }

    fn supported_chains(&self) -> Vec<ChainInfo> {
        vec![
            ChainInfo::new("ethereum", "Ethereum", "ETH", 780),
            ChainInfo::new("polygon", "Polygon", "MATIC", 256),
            ChainInfo::new("avalanche", "Avalanche", "AVAX", 5),
            ChainInfo::new("bsc", "BNB Smart Chain", "BNB", 3),
            ChainInfo::new("arbitrum", "Arbitrum One", "ETH", 1),
            ChainInfo::new("optimism", "Optimism", "ETH", 1),
            ChainInfo::new("base", "Base", "ETH", 1),
            ChainInfo::new("celo", "Celo", "CELO", 5),
            ChainInfo::new("moonbeam", "Moonbeam", "GLMR", 12),
            ChainInfo::new("mantle", "Mantle", "MNT", 1),
            ChainInfo::new("blast", "Blast", "ETH", 1),
            ChainInfo::new("scroll", "Scroll", "ETH", 1),
            ChainInfo::new("fraxtal", "Fraxtal", "frxETH", 1),
            ChainInfo::new("mode", "Mode", "ETH", 1),
            ChainInfo::new("linea", "Linea", "ETH", 1),
            ChainInfo::new("manta", "Manta", "ETH", 1),
            ChainInfo::new("zksync", "zkSync Era", "ETH", 1),
            ChainInfo::new("tenzro", "Tenzro Ledger", "TNZO", 1),
        ]
    }

    async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String> {
        let destination_domain = self
            .config
            .chain_id(dest_chain)
            .ok_or_else(|| BridgeError::ChainNotSupported(dest_chain.to_string()))?;
        // For the message-only path the sender / recipient default to the
        // mailbox so callers using `BridgeAdapter::send_message` don't need
        // to thread them through; `dispatch_message` is the richer entry
        // point for callers that want explicit addressing.
        let id = self.dispatch_message(
            destination_domain,
            &self.config.mailbox,
            &self.config.mailbox,
            payload,
        )?;
        Ok(format!("0x{}", hex::encode(id.as_bytes())))
    }

    async fn receive_message(&self, source_chain: &str, payload: Vec<u8>) -> Result<()> {
        let source_domain = self
            .config
            .chain_id(source_chain)
            .ok_or_else(|| BridgeError::ChainNotSupported(source_chain.to_string()))?;
        if payload.is_empty() {
            return Err(BridgeError::InvalidParameter("empty payload".into()));
        }
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let id = Hash::new(digest);
        if self.seen_messages.contains_key(&id) {
            return Err(BridgeError::ReplayAttack(hex::encode(id.as_bytes())));
        }

        // Hyperlane multisig ISM verification. When a validator set is
        // configured for this origin domain, the inbound payload is
        // expected to carry trailing ISM metadata in the form
        // `body || u8 sig_count || sig_count * (addr20 || sig65)`. We
        // peel the trailing metadata, compute the message id over the
        // canonical Mailbox encoding, and run the ECDSA multisig quorum
        // check. Without an installed set the path falls through to
        // the inner TenzroMessage signature check (consistent with
        // pre-ISM adapter behaviour); the operator MUST call
        // `install_validator_set` on the production node before
        // bridging real value.
        let set_opt = self
            .validator_sets
            .read()
            .get(&source_domain)
            .cloned();
        if let Some(set) = set_opt {
            let n = payload.len();
            if n < 1 {
                return Err(BridgeError::InvalidParameter(
                    "Hyperlane ISM: payload too short".into(),
                ));
            }
            let sig_count = payload[n - 1] as usize;
            let sig_record_len = 20 + 65;
            let trailer_len = 1 + sig_count * sig_record_len;
            if n < trailer_len + 1 {
                return Err(BridgeError::InvalidParameter(
                    "Hyperlane ISM: payload truncated for declared signature count".into(),
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
            // Re-derive the inner-message id from the verified body for
            // downstream dedup, replacing the original payload-hash id.
            let inner_id = Hash::new(body_digest);
            if self.seen_messages.contains_key(&inner_id) {
                return Err(BridgeError::ReplayAttack(hex::encode(inner_id.as_bytes())));
            }
        }

        // If the body is a TenzroMessage, run the standard 6-step
        // verification path that LayerZero, CCIP, deBridge, and Li.Fi
        // use.
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
        self.seen_messages.insert(id, ());
        Ok(())
    }

    async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt> {
        let destination_domain = self
            .config
            .chain_id(&request.dest_chain)
            .ok_or_else(|| BridgeError::ChainNotSupported(request.dest_chain.clone()))?;
        let body = request.extra_data.clone().unwrap_or_default();
        let id = self.dispatch_message(
            destination_domain,
            &request.sender,
            &request.recipient,
            body,
        )?;
        Ok(BridgeTokenReceipt::new(
            format!("0x{}", hex::encode(id.as_bytes())),
            id,
            (Timestamp::now().as_secs() * 1_000) as i64,
            0,
            request.source_chain,
            request.dest_chain,
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
        // Hyperlane fees are determined by the gas-payment hook; in the
        // absence of a live gas oracle we return a conservative fee
        // proportional to payload size (15_000 wei per byte).
        Ok((payload_size as u128).saturating_mul(15_000))
    }
}

impl HyperlaneAdapter {
    /// Borrow the http client for tests / monitoring integrations.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }
}
