//! Wormhole Native Token Transfers (NTT) scaffolding.
//!
//! NTT is Wormhole's 2026 multi-chain token primitive. Instead of wrapped
//! tokens locked at a vault, a token's `NttManager` mints/burns the
//! native token directly on each chain, with the canonical supply
//! controlled by per-chain rate-limit queues and (optionally) multiple
//! `Transceiver`s for redundant cross-chain attestation.
//!
//! This module provides the protocol-side types Tenzro needs to:
//! 1. Quote outbound NTT transfers (manager.transfer() preflight)
//! 2. Track inbound rate-limit queues
//! 3. Aggregate Transceiver attestations before mint
//!
//! It does NOT ship the on-chain Solidity / Anchor contracts — those
//! deploy on the destination chain through the standard NTT CLI. This
//! file is the bridge-side protocol envelope.

use serde::{Deserialize, Serialize};

/// A registered `NttManager` deployment on a specific chain. Identified
/// by `(chain_id, manager_address)` — relying parties whitelist managers
/// at enrolment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NttManager {
    /// Wormhole chain identifier (e.g. 2 = Ethereum, 1 = Solana, 5 = Polygon).
    pub wormhole_chain_id: u16,
    /// 32-byte normalized address. Solidity managers are left-padded
    /// from 20 bytes; Solana program-ids occupy the full 32.
    pub manager_address: [u8; 32],
    /// Token the manager governs (32-byte normalized).
    pub token_address: [u8; 32],
    /// Number of `Transceiver`s registered. ≥ 1 quorum required for
    /// inbound transfers to mint.
    pub transceivers: Vec<NttTransceiver>,
    /// Per-chain rate-limit queue configuration.
    pub rate_limit: NttRateLimit,
}

/// A `Transceiver` is a wire-protocol adapter that carries NTT
/// attestation messages cross-chain. Wormhole-canonical is the Wormhole
/// Transceiver itself; alternatives include Axelar, LayerZero. Multiple
/// Transceivers per NttManager give redundant attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NttTransceiver {
    pub transceiver_address: [u8; 32],
    pub kind: NttTransceiverKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NttTransceiverKind {
    Wormhole,
    Axelar,
    Layerzero,
    Custom,
}

/// Per-chain rate-limit configuration. NTT canonically enforces both
/// outbound and inbound caps with rolling-window refill — a transfer
/// that exceeds the cap is queued, not rejected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct NttRateLimit {
    /// Outbound transfer cap per window (in token smallest unit).
    pub outbound_cap: u128,
    /// Inbound mint cap per window.
    pub inbound_cap: u128,
    /// Window in seconds. Default 86_400 (24h).
    pub window_seconds: u64,
}

/// An outbound NTT transfer request — the bridge-side envelope before
/// it crosses to the wire format expected by the destination chain's
/// `NttManager::transfer()` selector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NttTransferRequest {
    pub source_chain_id: u16,
    pub dest_chain_id: u16,
    pub source_manager: [u8; 32],
    pub dest_recipient: [u8; 32],
    pub amount_smallest_unit: u128,
    pub nonce: [u8; 32],
    /// `should_queue` flag — when `false`, the source manager reverts
    /// if `amount` exceeds the outbound rate-limit; when `true`, the
    /// transfer is queued for the next window.
    pub should_queue: bool,
}

/// Outcome of preflight quote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NttTransferQuote {
    pub estimated_fee_wei: u128,
    pub estimated_arrival_seconds: u64,
    /// `true` if the transfer would be queued at the source under
    /// current rate-limit window state.
    pub would_be_queued: bool,
}

/// Inbound NTT attestation. Aggregates Transceiver attestations until
/// the configured quorum is met, then triggers mint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NttInboundAttestation {
    pub transfer_request: NttTransferRequest,
    pub transceiver_attestations: Vec<NttTransceiverAttestation>,
    pub required_quorum: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NttTransceiverAttestation {
    pub transceiver_address: [u8; 32],
    pub signature: Vec<u8>,
}

impl NttInboundAttestation {
    /// `true` once the number of distinct transceiver attestations
    /// reaches `required_quorum`. Deduplicates by transceiver address.
    pub fn has_quorum(&self) -> bool {
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(self.transceiver_attestations.len());
        for att in &self.transceiver_attestations {
            if !seen.contains(&att.transceiver_address) {
                seen.push(att.transceiver_address);
            }
        }
        seen.len() as u8 >= self.required_quorum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_rate_limit_serializes() {
        let rl = NttRateLimit {
            outbound_cap: 1_000_000_000_000_000_000_000,
            inbound_cap: 1_000_000_000_000_000_000_000,
            window_seconds: 86_400,
        };
        let json = serde_json::to_string(&rl).unwrap();
        let parsed: NttRateLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, rl);
    }

    #[test]
    fn ntt_manager_with_two_transceivers() {
        let m = NttManager {
            wormhole_chain_id: 2,
            manager_address: [0xAB; 32],
            token_address: [0xCD; 32],
            transceivers: vec![
                NttTransceiver {
                    transceiver_address: [0x11; 32],
                    kind: NttTransceiverKind::Wormhole,
                },
                NttTransceiver {
                    transceiver_address: [0x22; 32],
                    kind: NttTransceiverKind::Axelar,
                },
            ],
            rate_limit: NttRateLimit {
                outbound_cap: 1_000_000,
                inbound_cap: 1_000_000,
                window_seconds: 86_400,
            },
        };
        assert_eq!(m.transceivers.len(), 2);
        let json = serde_json::to_string(&m).unwrap();
        let parsed: NttManager = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn quorum_requires_distinct_attestations() {
        let req = NttTransferRequest {
            source_chain_id: 2,
            dest_chain_id: 1,
            source_manager: [0xAB; 32],
            dest_recipient: [0x99; 32],
            amount_smallest_unit: 1000,
            nonce: [0x77; 32],
            should_queue: false,
        };
        let mut att = NttInboundAttestation {
            transfer_request: req,
            transceiver_attestations: vec![],
            required_quorum: 2,
        };
        assert!(!att.has_quorum());

        // 1 attestation: not enough.
        att.transceiver_attestations
            .push(NttTransceiverAttestation {
                transceiver_address: [0x11; 32],
                signature: vec![0u8; 65],
            });
        assert!(!att.has_quorum());

        // Same transceiver again — must not count.
        att.transceiver_attestations
            .push(NttTransceiverAttestation {
                transceiver_address: [0x11; 32],
                signature: vec![0u8; 65],
            });
        assert!(!att.has_quorum());

        // Distinct second transceiver — quorum.
        att.transceiver_attestations
            .push(NttTransceiverAttestation {
                transceiver_address: [0x22; 32],
                signature: vec![0u8; 65],
            });
        assert!(att.has_quorum());
    }
}
