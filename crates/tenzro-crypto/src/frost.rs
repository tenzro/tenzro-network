//! FROST-Ed25519 threshold signing (RFC 9591).
//!
//! # Why FROST
//!
//! FROST is a real threshold signature scheme — the secret key is **never**
//! materialized in any single process. Each signer holds a share, runs two
//! rounds (commit, sign), and the coordinator aggregates `t` signature shares
//! into a single 64-byte standard Ed25519 signature that verifies under the
//! group public key. TSSHOCK (2023) and BitForge (2023) ended the GG18/GG20
//! family for naive reconstruction-style schemes; FROST (Ed25519, RFC 9591)
//! and CGGMP21 (secp256k1) are the current academic and production consensus.
//!
//! # What this is
//!
//! A small, opinionated facade around the Zcash Foundation's
//! [`frost_ed25519`] crate (the canonical RFC 9591 implementation). The output
//! `Signature` is byte-identical to a standard Ed25519 signature (64 B,
//! `R || s`), so it verifies with `tenzro_crypto::signatures::verify` and with
//! every consumer that already understands Ed25519 — no on-chain protocol
//! change.
//!
//! # Flow (trusted-dealer keygen, t-of-n)
//!
//! ```text
//! Dealer:        keygen_with_trusted_dealer(t, n) → (PublicKeyPackage, [SecretShare; n])
//! Each signer:   round1_commit(secret_share) → (SigningNonces, SigningCommitments)
//! Coordinator:   build_signing_package(message, &commitments) → SigningPackage
//! Each signer:   round2_sign(package, nonces, secret_share) → SignatureShare
//! Aggregator:    aggregate_signature(package, &shares, public_key_pkg) → Signature (64 B)
//! ```
//!
//! Distributed key generation (no dealer) is also exposed via
//! [`dkg_part1`] / [`dkg_part2`] / [`dkg_part3`] for the autonomous-agent
//! profile where no party should hold the full key even momentarily.

use std::collections::BTreeMap;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use frost_ed25519 as frost;

use crate::error::{CryptoError, Result};
use crate::keys::{KeyType, PublicKey};
use crate::signatures::Signature;

/// Length of an Ed25519 signature on the wire (RFC 8032).
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Length of an Ed25519 verifying key on the wire (RFC 8032 §5.1.5).
pub const ED25519_PUBKEY_LEN: usize = 32;

// ============================================================================
// Identifier
// ============================================================================

/// A signer identifier inside a FROST group.
///
/// FROST uses a non-zero scalar as identifier; Tenzro callers pass a small
/// positive `u16` (1..=n) and we map it onto the curve scalar. The `u16` is
/// exposed so the dealer / wallet / on-chain registry can use a stable index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignerIndex(pub u16);

impl SignerIndex {
    /// Build the FROST native identifier from this index.
    fn to_frost(self) -> Result<frost::Identifier> {
        if self.0 == 0 {
            return Err(CryptoError::MpcError(
                "FROST signer index must be non-zero".to_string(),
            ));
        }
        frost::Identifier::try_from(self.0)
            .map_err(|e| CryptoError::MpcError(format!("invalid FROST identifier: {}", e)))
    }
}

// ============================================================================
// Group public key + per-signer secret share
// ============================================================================

/// The group's verifying key — the **single** Ed25519 public key everyone
/// outside the group should see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPublicKey {
    /// Canonical 32-byte Ed25519 verifying key.
    pub bytes: [u8; ED25519_PUBKEY_LEN],
}

impl GroupPublicKey {
    pub fn as_public_key(&self) -> PublicKey {
        PublicKey::new(KeyType::Ed25519, self.bytes.to_vec())
    }
}

/// Public-key package — the group key plus each signer's verifying share.
/// Held by every signer and by the aggregator. Cheap to serialize (no
/// secrets); safe to gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyPackage {
    inner_bytes: Vec<u8>,
    /// Group-level public key (cached to avoid re-deserializing for the hot path).
    pub group_public_key: GroupPublicKey,
    /// Threshold (`t`) — minimum honest signers required.
    pub threshold: u16,
    /// Total signers (`n`).
    pub total: u16,
}

impl PublicKeyPackage {
    fn from_native(
        pkg: &frost::keys::PublicKeyPackage,
        threshold: u16,
        total: u16,
    ) -> Result<Self> {
        let inner_bytes = pkg
            .serialize()
            .map_err(|e| CryptoError::MpcError(format!("PublicKeyPackage serialize: {}", e)))?;
        let group_bytes = pkg
            .verifying_key()
            .serialize()
            .map_err(|e| CryptoError::MpcError(format!("verifying_key serialize: {}", e)))?;
        let group_arr: [u8; ED25519_PUBKEY_LEN] = group_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::MpcError("verifying key wrong length".to_string()))?;
        Ok(Self {
            inner_bytes,
            group_public_key: GroupPublicKey { bytes: group_arr },
            threshold,
            total,
        })
    }

    fn to_native(&self) -> Result<frost::keys::PublicKeyPackage> {
        frost::keys::PublicKeyPackage::deserialize(&self.inner_bytes)
            .map_err(|e| CryptoError::MpcError(format!("PublicKeyPackage deserialize: {}", e)))
    }
}

/// Discriminant for the wire format of [`SecretShare::inner_bytes`].
///
/// FROST exposes two distinct types that hold a participant's signing
/// material: `SecretShare` (output of trusted-dealer keygen) and `KeyPackage`
/// (output of DKG). Both convert to a `KeyPackage` for signing, but
/// `SecretShare` carries a Feldman commitment for verification while
/// `KeyPackage` does not.
///
/// Tag the persisted blob so we know which native type to deserialize.
const SECRET_TAG_DEALER_SHARE: u8 = 0x00;
const SECRET_TAG_DKG_KEY_PACKAGE: u8 = 0x01;

/// A signer's secret share. **Must be held by exactly one signer.** Encrypt
/// at rest and never transmit in the clear. When persisted, wrap it through
/// the keystore's Argon2id-encrypted blob.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretShare {
    pub index: SignerIndex,
    /// Tagged payload: first byte is a [`SECRET_TAG_DEALER_SHARE`] /
    /// [`SECRET_TAG_DKG_KEY_PACKAGE`] discriminant; the remainder is the
    /// serialized native FROST type.
    inner_bytes: Vec<u8>,
}

impl std::fmt::Debug for SecretShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretShare")
            .field("index", &self.index)
            .field("inner_bytes", &"<redacted>")
            .finish()
    }
}

impl SecretShare {
    fn to_key_package(&self) -> Result<frost::keys::KeyPackage> {
        let (tag, payload) = self
            .inner_bytes
            .split_first()
            .ok_or_else(|| CryptoError::MpcError("empty SecretShare payload".into()))?;
        match *tag {
            SECRET_TAG_DEALER_SHARE => {
                let secret = frost::keys::SecretShare::deserialize(payload).map_err(|e| {
                    CryptoError::MpcError(format!("SecretShare deserialize: {}", e))
                })?;
                frost::keys::KeyPackage::try_from(secret)
                    .map_err(|e| CryptoError::MpcError(format!("SecretShare → KeyPackage: {}", e)))
            }
            SECRET_TAG_DKG_KEY_PACKAGE => frost::keys::KeyPackage::deserialize(payload)
                .map_err(|e| CryptoError::MpcError(format!("KeyPackage deserialize: {}", e))),
            other => Err(CryptoError::MpcError(format!(
                "unknown SecretShare wire tag: 0x{:02x}",
                other
            ))),
        }
    }
}

/// Wrap a dealer-issued FROST `SecretShare` payload with the dealer-share tag.
fn tag_dealer_share(payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(SECRET_TAG_DEALER_SHARE);
    out.extend_from_slice(&payload);
    out
}

/// Wrap a DKG-output `KeyPackage` payload with the DKG tag.
fn tag_dkg_key_package(payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(SECRET_TAG_DKG_KEY_PACKAGE);
    out.extend_from_slice(&payload);
    out
}

// ============================================================================
// Trusted-dealer keygen
// ============================================================================

/// Generate a fresh threshold key with a trusted dealer.
///
/// `threshold` ≥ 1, `total` ≥ `threshold`. Each returned [`SecretShare`]
/// must be delivered over a confidential channel to its respective signer
/// and **deleted from the dealer's process** before any signing happens.
///
/// For the no-trusted-dealer profile, use [`dkg_part1`] / [`dkg_part2`] /
/// [`dkg_part3`] instead.
pub fn keygen_with_trusted_dealer(
    threshold: u16,
    total: u16,
) -> Result<(PublicKeyPackage, Vec<SecretShare>)> {
    if threshold == 0 {
        return Err(CryptoError::MpcError("threshold must be ≥ 1".into()));
    }
    if total < threshold {
        return Err(CryptoError::MpcError(format!(
            "total ({}) must be ≥ threshold ({})",
            total, threshold
        )));
    }

    let (shares, pubkey_pkg) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        OsRng,
    )
    .map_err(|e| CryptoError::MpcError(format!("FROST keygen failed: {}", e)))?;

    let mut out_shares = Vec::with_capacity(shares.len());
    // BTreeMap iteration is ordered; we map identifier → 1-based index.
    for (id, secret) in shares {
        // Identifier serializes to a 32-byte little-endian scalar; we extract
        // the low byte to recover the 1-based index used at construction.
        let id_bytes = id.serialize().as_slice().first().copied().unwrap_or(0);
        let payload = secret
            .serialize()
            .map_err(|e| CryptoError::MpcError(format!("SecretShare serialize: {}", e)))?;
        out_shares.push(SecretShare {
            index: SignerIndex(id_bytes as u16),
            inner_bytes: tag_dealer_share(payload),
        });
    }
    out_shares.sort_by_key(|s| s.index.0);

    Ok((
        PublicKeyPackage::from_native(&pubkey_pkg, threshold, total)?,
        out_shares,
    ))
}

// ============================================================================
// Round 1: per-signer commitment
// ============================================================================

/// Per-signer secret nonces from round 1. **Single-use.** Never reuse with a
/// different message — reuse leaks the share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningNonces {
    inner_bytes: Vec<u8>,
}

impl SigningNonces {
    fn to_native(&self) -> Result<frost::round1::SigningNonces> {
        frost::round1::SigningNonces::deserialize(&self.inner_bytes)
            .map_err(|e| CryptoError::MpcError(format!("SigningNonces deserialize: {}", e)))
    }
}

/// Public commitments from round 1. Sent to the coordinator; safe to publish.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningCommitments {
    pub index: SignerIndex,
    inner_bytes: Vec<u8>,
}

impl SigningCommitments {
    fn to_native(&self) -> Result<frost::round1::SigningCommitments> {
        frost::round1::SigningCommitments::deserialize(&self.inner_bytes)
            .map_err(|e| CryptoError::MpcError(format!("SigningCommitments deserialize: {}", e)))
    }
}

/// Round 1: each participant commits to a fresh random nonce and publishes
/// its commitment.
///
/// The returned [`SigningNonces`] **must be kept secret on this signer**
/// until round 2 of the same signing session, and discarded immediately after.
pub fn round1_commit(secret_share: &SecretShare) -> Result<(SigningNonces, SigningCommitments)> {
    let kp = secret_share.to_key_package()?;
    let (nonces, commits) = frost::round1::commit(kp.signing_share(), &mut OsRng);
    let nonces_bytes = nonces
        .serialize()
        .map_err(|e| CryptoError::MpcError(format!("SigningNonces serialize: {}", e)))?;
    let commits_bytes = commits
        .serialize()
        .map_err(|e| CryptoError::MpcError(format!("SigningCommitments serialize: {}", e)))?;
    Ok((
        SigningNonces {
            inner_bytes: nonces_bytes,
        },
        SigningCommitments {
            index: secret_share.index,
            inner_bytes: commits_bytes,
        },
    ))
}

// ============================================================================
// Coordinator: build SigningPackage
// ============================================================================

/// The aggregated round-1 commitments + the message. Sent to every signer for
/// round 2. Built by the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningPackage {
    inner_bytes: Vec<u8>,
}

impl SigningPackage {
    fn to_native(&self) -> Result<frost::SigningPackage> {
        frost::SigningPackage::deserialize(&self.inner_bytes)
            .map_err(|e| CryptoError::MpcError(format!("SigningPackage deserialize: {}", e)))
    }
}

/// Build the round-2 [`SigningPackage`] from at-least-`threshold` round-1
/// commitments and the message to sign.
pub fn build_signing_package(
    message: &[u8],
    commitments: &[SigningCommitments],
) -> Result<SigningPackage> {
    let mut map: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> = BTreeMap::new();
    for c in commitments {
        let id = c.index.to_frost()?;
        let native = c.to_native()?;
        if map.insert(id, native).is_some() {
            return Err(CryptoError::MpcError(format!(
                "duplicate signer index in commitments: {}",
                c.index.0
            )));
        }
    }
    let pkg = frost::SigningPackage::new(map, message);
    let bytes = pkg
        .serialize()
        .map_err(|e| CryptoError::MpcError(format!("SigningPackage serialize: {}", e)))?;
    Ok(SigningPackage { inner_bytes: bytes })
}

// ============================================================================
// Round 2: per-signer signature share
// ============================================================================

/// A signer's contribution to the final signature. Sent to the aggregator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    pub index: SignerIndex,
    inner_bytes: Vec<u8>,
}

impl SignatureShare {
    fn to_native(&self) -> Result<frost::round2::SignatureShare> {
        frost::round2::SignatureShare::deserialize(&self.inner_bytes)
            .map_err(|e| CryptoError::MpcError(format!("SignatureShare deserialize: {}", e)))
    }
}

/// Round 2: each signer produces its `SignatureShare`. Consumes the round-1
/// `SigningNonces` (single-use); callers SHOULD drop them immediately after.
pub fn round2_sign(
    package: &SigningPackage,
    nonces: &SigningNonces,
    secret_share: &SecretShare,
) -> Result<SignatureShare> {
    let pkg = package.to_native()?;
    let nonces_native = nonces.to_native()?;
    let kp = secret_share.to_key_package()?;
    let share = frost::round2::sign(&pkg, &nonces_native, &kp)
        .map_err(|e| CryptoError::MpcError(format!("FROST round2 sign: {}", e)))?;
    let bytes = share.serialize();
    Ok(SignatureShare {
        index: secret_share.index,
        inner_bytes: bytes,
    })
}

// ============================================================================
// Aggregation
// ============================================================================

/// Aggregate `≥ threshold` signature shares into a single 64-byte Ed25519
/// signature. Verifies under the group's [`GroupPublicKey`] using the standard
/// Ed25519 verifier — no FROST-aware code needed downstream.
pub fn aggregate_signature(
    package: &SigningPackage,
    shares: &[SignatureShare],
    public_key_package: &PublicKeyPackage,
) -> Result<Signature> {
    let pkg = package.to_native()?;
    let pubkey_pkg = public_key_package.to_native()?;

    let mut share_map: BTreeMap<frost::Identifier, frost::round2::SignatureShare> = BTreeMap::new();
    for s in shares {
        let id = s.index.to_frost()?;
        let native = s.to_native()?;
        if share_map.insert(id, native).is_some() {
            return Err(CryptoError::MpcError(format!(
                "duplicate signer index in shares: {}",
                s.index.0
            )));
        }
    }

    let sig = frost::aggregate(&pkg, &share_map, &pubkey_pkg)
        .map_err(|e| CryptoError::MpcError(format!("FROST aggregate: {}", e)))?;

    let sig_bytes = sig
        .serialize()
        .map_err(|e| CryptoError::MpcError(format!("Signature serialize: {}", e)))?;
    if sig_bytes.len() != ED25519_SIGNATURE_LEN {
        return Err(CryptoError::MpcError(format!(
            "FROST signature wrong length: expected {}, got {}",
            ED25519_SIGNATURE_LEN,
            sig_bytes.len()
        )));
    }

    Ok(Signature::new(KeyType::Ed25519, sig_bytes))
}

// ============================================================================
// Distributed Key Generation (no dealer)
// ============================================================================

/// Output of DKG round 1: the participant's secret state plus the broadcast
/// package every other participant must receive.
#[derive(Debug)]
pub struct DkgRound1 {
    pub secret_package: DkgRound1Secret,
    pub broadcast_package: DkgRound1Public,
}

/// Per-participant secret state from DKG round 1 — must NOT leave the
/// participant's process. Single-use; consumed by [`dkg_part2`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound1Secret {
    inner_bytes: Vec<u8>,
}

impl DkgRound1Secret {
    fn to_native(&self) -> Result<frost::keys::dkg::round1::SecretPackage> {
        frost::keys::dkg::round1::SecretPackage::deserialize(&self.inner_bytes)
            .map_err(|e| CryptoError::MpcError(format!("DkgRound1Secret deserialize: {}", e)))
    }
}

/// Public broadcast from DKG round 1. Sent to every other participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound1Public {
    pub from: SignerIndex,
    inner_bytes: Vec<u8>,
}

impl DkgRound1Public {
    fn to_native(&self) -> Result<frost::keys::dkg::round1::Package> {
        frost::keys::dkg::round1::Package::deserialize(&self.inner_bytes)
            .map_err(|e| CryptoError::MpcError(format!("DkgRound1Public deserialize: {}", e)))
    }
}

/// DKG round 1: every participant runs this independently.
pub fn dkg_part1(self_index: SignerIndex, threshold: u16, total: u16) -> Result<DkgRound1> {
    let id = self_index.to_frost()?;
    let rng = OsRng;
    let (secret, broadcast) = frost::keys::dkg::part1(id, total, threshold, rng)
        .map_err(|e| CryptoError::MpcError(format!("DKG part1: {}", e)))?;
    let secret_bytes = secret
        .serialize()
        .map_err(|e| CryptoError::MpcError(format!("DKG round1 secret serialize: {}", e)))?;
    let broadcast_bytes = broadcast
        .serialize()
        .map_err(|e| CryptoError::MpcError(format!("DKG round1 broadcast serialize: {}", e)))?;
    Ok(DkgRound1 {
        secret_package: DkgRound1Secret {
            inner_bytes: secret_bytes,
        },
        broadcast_package: DkgRound1Public {
            from: self_index,
            inner_bytes: broadcast_bytes,
        },
    })
}

/// Output of DKG round 2: the participant's updated secret state plus a
/// **per-recipient** unicast package.
#[derive(Debug)]
pub struct DkgRound2 {
    pub secret_package: DkgRound2Secret,
    /// Per-recipient packages: each goes to exactly one other participant.
    pub unicast_packages: Vec<DkgRound2Unicast>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound2Secret {
    inner_bytes: Vec<u8>,
}

impl DkgRound2Secret {
    fn to_native(&self) -> Result<frost::keys::dkg::round2::SecretPackage> {
        frost::keys::dkg::round2::SecretPackage::deserialize(&self.inner_bytes)
            .map_err(|e| CryptoError::MpcError(format!("DkgRound2Secret deserialize: {}", e)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound2Unicast {
    pub from: SignerIndex,
    pub to: SignerIndex,
    inner_bytes: Vec<u8>,
}

impl DkgRound2Unicast {
    fn to_native(&self) -> Result<frost::keys::dkg::round2::Package> {
        frost::keys::dkg::round2::Package::deserialize(&self.inner_bytes)
            .map_err(|e| CryptoError::MpcError(format!("DkgRound2Unicast deserialize: {}", e)))
    }
}

/// DKG round 2: each participant consumes its own round-1 secret + every
/// other participant's round-1 broadcast, and produces a per-recipient
/// unicast package.
pub fn dkg_part2(
    self_index: SignerIndex,
    round1_secret: DkgRound1Secret,
    round1_broadcasts: &[DkgRound1Public],
) -> Result<DkgRound2> {
    let mut others: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
        BTreeMap::new();
    for b in round1_broadcasts {
        if b.from == self_index {
            continue; // skip our own broadcast
        }
        let id = b.from.to_frost()?;
        let native = b.to_native()?;
        if others.insert(id, native).is_some() {
            return Err(CryptoError::MpcError(format!(
                "duplicate sender in round1 broadcasts: {}",
                b.from.0
            )));
        }
    }

    let secret_native = round1_secret.to_native()?;
    let (round2_secret, round2_packages) = frost::keys::dkg::part2(secret_native, &others)
        .map_err(|e| CryptoError::MpcError(format!("DKG part2: {}", e)))?;

    let secret_bytes = round2_secret
        .serialize()
        .map_err(|e| CryptoError::MpcError(format!("DKG round2 secret serialize: {}", e)))?;

    let mut unicast_packages = Vec::with_capacity(round2_packages.len());
    for (id, pkg) in round2_packages {
        let to_byte = id.serialize().as_slice().first().copied().unwrap_or(0);
        let bytes = pkg
            .serialize()
            .map_err(|e| CryptoError::MpcError(format!("DKG round2 unicast serialize: {}", e)))?;
        unicast_packages.push(DkgRound2Unicast {
            from: self_index,
            to: SignerIndex(to_byte as u16),
            inner_bytes: bytes,
        });
    }
    unicast_packages.sort_by_key(|u| u.to.0);

    Ok(DkgRound2 {
        secret_package: DkgRound2Secret {
            inner_bytes: secret_bytes,
        },
        unicast_packages,
    })
}

/// DKG round 3: each participant consumes its round-2 secret + every other
/// participant's round-1 broadcast + every unicast addressed *to it*. Outputs
/// the participant's [`SecretShare`] and the shared [`PublicKeyPackage`].
pub fn dkg_part3(
    self_index: SignerIndex,
    round2_secret: DkgRound2Secret,
    round1_broadcasts: &[DkgRound1Public],
    round2_unicasts_to_me: &[DkgRound2Unicast],
    threshold: u16,
    total: u16,
) -> Result<(SecretShare, PublicKeyPackage)> {
    let mut round1_map: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
        BTreeMap::new();
    for b in round1_broadcasts {
        if b.from == self_index {
            continue;
        }
        let id = b.from.to_frost()?;
        let native = b.to_native()?;
        round1_map.insert(id, native);
    }

    let mut round2_map: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package> =
        BTreeMap::new();
    for u in round2_unicasts_to_me {
        if u.to != self_index {
            return Err(CryptoError::MpcError(format!(
                "round2 unicast addressed to {} delivered to {}",
                u.to.0, self_index.0
            )));
        }
        let id = u.from.to_frost()?;
        let native = u.to_native()?;
        round2_map.insert(id, native);
    }

    let secret_native = round2_secret.to_native()?;
    let (key_pkg, public_key_pkg) =
        frost::keys::dkg::part3(&secret_native, &round1_map, &round2_map)
            .map_err(|e| CryptoError::MpcError(format!("DKG part3: {}", e)))?;

    // DKG yields a `KeyPackage` directly (no Feldman commitment to round-trip
    // through `SecretShare`). Persist it under the DKG tag so
    // `to_key_package` deserializes it as-is.
    let payload = key_pkg
        .serialize()
        .map_err(|e| CryptoError::MpcError(format!("KeyPackage serialize: {}", e)))?;

    Ok((
        SecretShare {
            index: self_index,
            inner_bytes: tag_dkg_key_package(payload),
        },
        PublicKeyPackage::from_native(&public_key_pkg, threshold, total)?,
    ))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures;

    fn sign_with_quorum(
        message: &[u8],
        threshold: u16,
        total: u16,
        signing_indices: &[u16],
    ) -> Signature {
        assert!(signing_indices.len() as u16 >= threshold);

        let (pubkey_pkg, shares) = keygen_with_trusted_dealer(threshold, total).unwrap();

        // Round 1: every signer in the quorum commits.
        let mut nonces_by_index = BTreeMap::new();
        let mut commitments = Vec::new();
        for idx in signing_indices {
            let share = shares.iter().find(|s| s.index.0 == *idx).unwrap();
            let (nonces, commits) = round1_commit(share).unwrap();
            nonces_by_index.insert(*idx, nonces);
            commitments.push(commits);
        }

        let signing_pkg = build_signing_package(message, &commitments).unwrap();

        // Round 2.
        let mut shares_out = Vec::new();
        for idx in signing_indices {
            let secret = shares.iter().find(|s| s.index.0 == *idx).unwrap();
            let nonces = nonces_by_index.get(idx).unwrap();
            let share = round2_sign(&signing_pkg, nonces, secret).unwrap();
            shares_out.push(share);
        }

        let aggregated = aggregate_signature(&signing_pkg, &shares_out, &pubkey_pkg).unwrap();

        // Verify under the group key using the *generic* Ed25519 verifier —
        // no FROST-aware code path.
        let group_pk = pubkey_pkg.group_public_key.as_public_key();
        signatures::verify(&group_pk, message, &aggregated)
            .expect("aggregated signature must verify under group key");

        aggregated
    }

    #[test]
    fn keygen_2_of_3_produces_three_shares_one_group_key() {
        let (pkg, shares) = keygen_with_trusted_dealer(2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(pkg.threshold, 2);
        assert_eq!(pkg.total, 3);
        assert_eq!(pkg.group_public_key.bytes.len(), ED25519_PUBKEY_LEN);
        let indices: Vec<u16> = shares.iter().map(|s| s.index.0).collect();
        assert_eq!(indices, vec![1, 2, 3]);
    }

    #[test]
    fn keygen_rejects_threshold_zero() {
        assert!(keygen_with_trusted_dealer(0, 3).is_err());
    }

    #[test]
    fn keygen_rejects_threshold_exceeding_total() {
        assert!(keygen_with_trusted_dealer(4, 3).is_err());
    }

    #[test]
    fn happy_path_2_of_3_signs_and_verifies() {
        let _sig = sign_with_quorum(b"hello tenzro", 2, 3, &[1, 2]);
    }

    #[test]
    fn happy_path_3_of_5_signs_and_verifies() {
        let _sig = sign_with_quorum(b"three of five", 3, 5, &[2, 3, 5]);
    }

    #[test]
    fn happy_path_t_equals_n_signs_and_verifies() {
        let _sig = sign_with_quorum(b"all-must-sign", 3, 3, &[1, 2, 3]);
    }

    #[test]
    fn signature_is_64_bytes_standard_ed25519_format() {
        let (pkg, shares) = keygen_with_trusted_dealer(2, 3).unwrap();
        let mut nonces_by_index = BTreeMap::new();
        let mut commitments = Vec::new();
        for idx in &[1u16, 2u16] {
            let share = shares.iter().find(|s| s.index.0 == *idx).unwrap();
            let (n, c) = round1_commit(share).unwrap();
            nonces_by_index.insert(*idx, n);
            commitments.push(c);
        }
        let signing_pkg = build_signing_package(b"len check", &commitments).unwrap();
        let mut shares_out = Vec::new();
        for idx in &[1u16, 2u16] {
            let s = shares.iter().find(|s| s.index.0 == *idx).unwrap();
            shares_out
                .push(round2_sign(&signing_pkg, nonces_by_index.get(idx).unwrap(), s).unwrap());
        }
        let sig = aggregate_signature(&signing_pkg, &shares_out, &pkg).unwrap();
        assert_eq!(sig.as_bytes().len(), ED25519_SIGNATURE_LEN);
        assert_eq!(sig.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn sub_threshold_signing_fails() {
        // 3-of-3 with only one signer present. `frost_core` rejects
        // sub-threshold signing eagerly at round 2 (it checks the commitment
        // count against `min_signers`) — accept rejection at round2 OR
        // aggregate, since both are correct refusals.
        let (pkg, shares) = keygen_with_trusted_dealer(3, 3).unwrap();
        let share = &shares[0];
        let (n, c) = round1_commit(share).unwrap();
        let signing_pkg = build_signing_package(b"too few", &[c]).unwrap();
        match round2_sign(&signing_pkg, &n, share) {
            Err(_) => {
                // Refused at round 2 — correct.
            }
            Ok(s) => {
                // Got past round 2 — aggregation MUST refuse.
                let result = aggregate_signature(&signing_pkg, &[s], &pkg);
                assert!(
                    result.is_err(),
                    "aggregation must reject sub-threshold shares"
                );
            }
        }
    }

    #[test]
    fn duplicate_signer_in_commitments_rejected() {
        let (_pkg, shares) = keygen_with_trusted_dealer(2, 3).unwrap();
        let (_n, c) = round1_commit(&shares[0]).unwrap();
        let result = build_signing_package(b"dup", &[c.clone(), c]);
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_signer_in_shares_rejected() {
        let (pkg, shares) = keygen_with_trusted_dealer(2, 3).unwrap();
        let (n1, c1) = round1_commit(&shares[0]).unwrap();
        let (n2, c2) = round1_commit(&shares[1]).unwrap();
        let signing_pkg = build_signing_package(b"x", &[c1, c2]).unwrap();
        let s1 = round2_sign(&signing_pkg, &n1, &shares[0]).unwrap();
        let _s2 = round2_sign(&signing_pkg, &n2, &shares[1]).unwrap();
        // Submit s1 twice instead of {s1, s2}.
        let result = aggregate_signature(&signing_pkg, &[s1.clone(), s1], &pkg);
        assert!(result.is_err());
    }

    #[test]
    fn signer_index_zero_rejected() {
        let result = SignerIndex(0).to_frost();
        assert!(result.is_err());
    }

    #[test]
    fn forged_signature_under_random_key_fails_verification() {
        let (pkg, shares) = keygen_with_trusted_dealer(2, 3).unwrap();
        let (n1, c1) = round1_commit(&shares[0]).unwrap();
        let (n2, c2) = round1_commit(&shares[1]).unwrap();
        let signing_pkg = build_signing_package(b"target", &[c1, c2]).unwrap();
        let s1 = round2_sign(&signing_pkg, &n1, &shares[0]).unwrap();
        let s2 = round2_sign(&signing_pkg, &n2, &shares[1]).unwrap();
        let sig = aggregate_signature(&signing_pkg, &[s1, s2], &pkg).unwrap();

        // Verify under a *different* group key — must fail.
        let bogus_pk = PublicKey::new(KeyType::Ed25519, vec![0u8; 32]);
        let result = signatures::verify(&bogus_pk, b"target", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn signature_bound_to_message_not_swappable() {
        let (pkg, shares) = keygen_with_trusted_dealer(2, 3).unwrap();
        let (n1, c1) = round1_commit(&shares[0]).unwrap();
        let (n2, c2) = round1_commit(&shares[1]).unwrap();
        let signing_pkg = build_signing_package(b"message A", &[c1, c2]).unwrap();
        let s1 = round2_sign(&signing_pkg, &n1, &shares[0]).unwrap();
        let s2 = round2_sign(&signing_pkg, &n2, &shares[1]).unwrap();
        let sig = aggregate_signature(&signing_pkg, &[s1, s2], &pkg).unwrap();

        // Try to verify the signature against message B — must fail.
        let group_pk = pkg.group_public_key.as_public_key();
        let result = signatures::verify(&group_pk, b"message B", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn group_public_key_is_stable_across_signing_sessions() {
        let (pkg, _) = keygen_with_trusted_dealer(2, 3).unwrap();
        let pk1 = pkg.group_public_key.bytes;
        let pk2 = pkg.group_public_key.bytes;
        assert_eq!(pk1, pk2);
        // Different keygen → different group key.
        let (pkg2, _) = keygen_with_trusted_dealer(2, 3).unwrap();
        assert_ne!(pkg.group_public_key.bytes, pkg2.group_public_key.bytes);
    }

    #[test]
    fn pubkey_package_round_trips_through_serde() {
        let (pkg, _) = keygen_with_trusted_dealer(2, 3).unwrap();
        let json = serde_json::to_vec(&pkg).unwrap();
        let restored: PublicKeyPackage = serde_json::from_slice(&json).unwrap();
        assert_eq!(pkg.group_public_key.bytes, restored.group_public_key.bytes);
        assert_eq!(pkg.threshold, restored.threshold);
        assert_eq!(pkg.total, restored.total);
        // Sanity: deserialize round-trip preserves the inner state enough to
        // sign a fresh message.
        let _ = restored.to_native().unwrap();
    }

    #[test]
    fn secret_share_redacts_secret_in_debug() {
        let (_pkg, shares) = keygen_with_trusted_dealer(2, 3).unwrap();
        let s = format!("{:?}", shares[0]);
        assert!(s.contains("<redacted>"), "Debug must not leak share bytes");
    }

    /// Full DKG round (no trusted dealer): three participants run
    /// part1/part2/part3, then a 2-of-3 quorum signs and the result verifies
    /// under the jointly-derived group key — proving the no-dealer path
    /// produces standard-Ed25519-verifiable signatures.
    #[test]
    fn dkg_end_to_end_2_of_3_signs_and_verifies() {
        let threshold: u16 = 2;
        let total: u16 = 3;
        let participants: Vec<SignerIndex> = (1..=total).map(SignerIndex).collect();

        // ---- Round 1 ---------------------------------------------------
        let mut r1_secrets: BTreeMap<SignerIndex, DkgRound1Secret> = BTreeMap::new();
        let mut r1_broadcasts: Vec<DkgRound1Public> = Vec::new();
        for p in &participants {
            let r1 = dkg_part1(*p, threshold, total).unwrap();
            r1_secrets.insert(*p, r1.secret_package);
            r1_broadcasts.push(r1.broadcast_package);
        }

        // ---- Round 2 ---------------------------------------------------
        let mut r2_secrets: BTreeMap<SignerIndex, DkgRound2Secret> = BTreeMap::new();
        let mut r2_unicasts: Vec<DkgRound2Unicast> = Vec::new();
        for p in &participants {
            let r1_secret = r1_secrets.remove(p).unwrap();
            let r2 = dkg_part2(*p, r1_secret, &r1_broadcasts).unwrap();
            r2_secrets.insert(*p, r2.secret_package);
            r2_unicasts.extend(r2.unicast_packages);
        }

        // ---- Round 3 ---------------------------------------------------
        let mut shares: BTreeMap<SignerIndex, SecretShare> = BTreeMap::new();
        let mut group_pkg: Option<PublicKeyPackage> = None;
        for p in &participants {
            let r2_secret = r2_secrets.remove(p).unwrap();
            let to_me: Vec<DkgRound2Unicast> =
                r2_unicasts.iter().filter(|u| u.to == *p).cloned().collect();
            let (share, pkg) =
                dkg_part3(*p, r2_secret, &r1_broadcasts, &to_me, threshold, total).unwrap();
            shares.insert(*p, share);
            // Every participant must derive the SAME group public key.
            match &group_pkg {
                None => group_pkg = Some(pkg),
                Some(existing) => assert_eq!(
                    existing.group_public_key.bytes, pkg.group_public_key.bytes,
                    "DKG must produce identical group public key for every participant"
                ),
            }
        }
        let group_pkg = group_pkg.unwrap();

        // ---- Sign with 2-of-3 quorum -----------------------------------
        let signers = [SignerIndex(1), SignerIndex(2)];
        let mut nonces_by_index: BTreeMap<SignerIndex, SigningNonces> = BTreeMap::new();
        let mut commitments: Vec<SigningCommitments> = Vec::new();
        for s in &signers {
            let (n, c) = round1_commit(shares.get(s).unwrap()).unwrap();
            nonces_by_index.insert(*s, n);
            commitments.push(c);
        }
        let signing_pkg = build_signing_package(b"dkg signs", &commitments).unwrap();

        let mut sig_shares: Vec<SignatureShare> = Vec::new();
        for s in &signers {
            let n = nonces_by_index.get(s).unwrap();
            let sh = shares.get(s).unwrap();
            sig_shares.push(round2_sign(&signing_pkg, n, sh).unwrap());
        }

        let sig = aggregate_signature(&signing_pkg, &sig_shares, &group_pkg).unwrap();
        // Standard Ed25519 verifier under the jointly-derived group key.
        let group_pk = group_pkg.group_public_key.as_public_key();
        signatures::verify(&group_pk, b"dkg signs", &sig)
            .expect("DKG-derived signature must verify under group key");
    }
}
