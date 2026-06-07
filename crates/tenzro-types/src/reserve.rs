//! Proof-of-Reserve attestation — backing record for attested-mint.
//!
//! See `docs/architecture/agentic-economy-coordination.md` (gap: attested-mint).
//! Tenzro can already *read* external Proof-of-Reserve feeds (Chainlink, via
//! `tenzro-node/src/mcp/chainlink.rs`). The missing seam is **binding a reserve
//! statement to minting**, so a tokenized asset's supply can never exceed its
//! attested reserves (1:1 backing as a protocol invariant). This is the signed
//! reserve record the attested-mint path consumes; it deliberately reuses the
//! TDIP identity + `TrustedIssuer` machinery for the attestor signature rather
//! than introducing a parallel trust system.

use serde::{Deserialize, Serialize};

/// Where a reserve figure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveSource {
    /// Issuer/custodian self-attestation (a registered `TrustedIssuer`).
    Issuer,
    /// TEE-attested custody statement.
    Tee,
    /// Chainlink Proof-of-Reserve feed reading.
    ChainlinkPor,
    /// Generic oracle.
    Oracle,
}

impl ReserveSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReserveSource::Issuer => "issuer",
            ReserveSource::Tee => "tee",
            ReserveSource::ChainlinkPor => "chainlink_por",
            ReserveSource::Oracle => "oracle",
        }
    }
}

/// A signed statement of the reserves backing a tokenized asset. Consumed by
/// attested-mint to enforce `supply_after_mint <= reserves`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestation {
    /// Tokenized-asset id (hex token id, matching the `TokenRegistry`).
    pub asset_id: String,
    /// Attested reserve units backing the asset (smallest unit).
    pub reserves: u128,
    /// Provenance of the reserve figure.
    pub source: ReserveSource,
    /// DID of the attestor (a `TrustedIssuer` / oracle / TEE quote signer).
    pub attestor_did: String,
    /// Unix-seconds the attestation was produced.
    pub attested_at: i64,
    /// Attestor signature over [`ReserveAttestation::signing_payload`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

impl ReserveAttestation {
    /// Deterministic bytes the attestor signs (everything except the signature).
    pub fn signing_payload(&self) -> Vec<u8> {
        fn push_str(buf: &mut Vec<u8>, s: &str) {
            buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(b"tenzro-reserve-attestation:v1");
        push_str(&mut buf, &self.asset_id);
        buf.extend_from_slice(&self.reserves.to_be_bytes());
        push_str(&mut buf, self.source.as_str());
        push_str(&mut buf, &self.attestor_did);
        buf.extend_from_slice(&self.attested_at.to_be_bytes());
        buf
    }

    /// True if `proposed_supply` (total supply after a mint) stays within the
    /// attested reserves — the 1:1 backing invariant.
    pub fn covers(&self, proposed_supply: u128) -> bool {
        proposed_supply <= self.reserves
    }
}
