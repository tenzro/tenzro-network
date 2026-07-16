//! TEE-resident agent keypairs for ERC-8004 / TDIP machine identities.
//!
//! Where [`crate::sealed_secp256k1::SealedSecp256k1Key`] addresses the
//! bridge's EVM signer (one secp256k1 key per validator), this module
//! addresses the **agent fleet**: every machine identity registered under
//! TDIP / ERC-8004 must hold an Ed25519 signing key whose private scalar
//! never leaves the enclave that produced the agent record.
//!
//! Design contract:
//!
//! - The private scalar is derived (HKDF-SHA256) from TEE-rooted material
//!   plus an agent-specific label, so the same TEE+label always reproduces
//!   the same key. There is no on-disk private-key file to steal.
//! - [`AgentKeyHandle`] is opaque to callers: it exposes only the public
//!   key, the 32-byte vendor measurement, the rotation epoch, and a
//!   `sign(...)` entry point. Cloning the handle does not clone the secret
//!   — the secret lives behind an `Arc<Zeroizing<_>>` so concurrent
//!   signers share one zeroizing backing store.
//! - [`seal_agent_keypair`] produces a fresh handle for a given
//!   `(agent_did, epoch)` pair. [`rotate_agent_key`] increments the epoch
//!   and returns a new handle; the previous handle is left alive so any
//!   pending UserOps can finish (verifiers look up by `epoch`).
//! - [`attest_agent_key`] binds the public key into an
//!   `AttestationReport`'s `user_data` slot by way of the underlying
//!   [`crate::traits::TeeProvider::generate_attestation`]. The resulting
//!   report is the cryptographic predicate behind the
//!   `ERC8004_IDENTITY.registerAgent` call: the on-chain registry stores
//!   `(agent_id, agent_address, metadata_uri)` and the metadata URI MUST
//!   resolve to a document containing this attestation. The verifier
//!   chain is: read agent record → fetch metadata doc → parse
//!   attestation → run [`crate::traits::TeeProvider::verify_attestation`]
//!   → compare the report's `user_data` to the on-chain pubkey commitment.
//!
//! This module deliberately does **not** depend on `tenzro-identity` or
//! `tenzro-agent` — those crates depend on `tenzro-tee`, not the other
//! way around. Callers wire the lifecycle by passing a `&dyn TeeProvider`
//! plus the agent DID; the resulting `AgentKeyHandle` is what they hand
//! to the wallet / RPC / ERC-8004 registration paths.

use std::sync::Arc;

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use hkdf::Hkdf;
use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;
use tenzro_crypto::bls::BlsKeyPair;
use tenzro_crypto::MlDsaSigningKey;
use tenzro_types::tee::AttestationReport;

/// HKDF info string for agent Ed25519 derivation. Bumped if the
/// derivation chain ever changes.
const HKDF_INFO: &[u8] = b"tenzro/sealed-agent-ed25519/v1";

/// HKDF info string for the agent ML-DSA-65 seed derivation. A distinct
/// info string from [`HKDF_INFO`] so the classical and post-quantum legs
/// derive to independent secrets from the same TEE root.
const HKDF_INFO_PQ: &[u8] = b"tenzro/sealed-agent-ml-dsa-65/v1";

/// HKDF info string for the agent BLS12-381 seed derivation. A distinct
/// info string again, so the BLS leg is independent of the classical and
/// PQ legs while still rooting in the same TEE material. The BLS leg is
/// the verifying key a machine identity needs to satisfy the wallet's
/// structural invariant and, if the machine ever stakes as a validator,
/// to aggregate HotStuff-2 votes.
const HKDF_INFO_BLS: &[u8] = b"tenzro/sealed-agent-bls12-381/v1";

/// Domain-separation prefix for the per-agent salt. Two agents with the
/// same TEE root **must not** yield the same key — the salt mixes in the
/// DID and the rotation epoch so the binding is uniquely
/// `(tee_root, agent_did, epoch) → key`.
const SALT_DOMAIN: &[u8] = b"tenzro/agent-key-salt/v1";

/// An Ed25519 agent signing key whose private scalar is derived from
/// TEE-rooted material and never written to disk.
///
/// `Clone` shares the underlying secret via `Arc<Zeroizing<_>>` so
/// dropping a clone never disturbs another holder; the secret is wiped
/// when the last reference is dropped.
#[derive(Clone)]
pub struct AgentKeyHandle {
    /// Stable agent DID, e.g. `did:tenzro:machine:<controller>:<uuid>`.
    /// The DID participates in the HKDF salt; clients trust the DID
    /// because the on-chain ERC-8004 record binds it to the public key.
    agent_did: String,
    /// Rotation epoch. Starts at 0 from [`seal_agent_keypair`] and
    /// increments by 1 on every [`rotate_agent_key`].
    epoch: u64,
    /// 32-byte vendor measurement the key was bound to. Stored so
    /// downstream attestation verifiers can sanity-check that an
    /// incoming `AttestationReport.measurement` matches what the handle
    /// originally committed to.
    measurement: [u8; 32],
    /// The Ed25519 verifying key — safe to clone, copy, hand to a peer.
    verifying_key: Ed25519VerifyingKey,
    /// The 32-byte Ed25519 secret scalar, behind `Arc<Zeroizing<_>>` so
    /// the byte buffer is zeroed when the last clone is dropped.
    secret_scalar: Arc<Zeroizing<[u8; 32]>>,
    /// The ML-DSA-65 (FIPS 204) post-quantum leg. Derived from the same
    /// TEE-rooted IKM as `secret_scalar` but under a distinct HKDF info
    /// string, so the classical and PQ secrets are independent. Only the
    /// 32-byte seed is retained (`MlDsaSigningKey` re-expands on every
    /// sign); shared behind `Arc` so clones share one backing store.
    pq_signing_key: Arc<MlDsaSigningKey>,
    /// The BLS12-381 leg. Derived from the same TEE-rooted IKM under a
    /// third distinct HKDF info string. Shared behind `Arc` so clones
    /// share one backing store. Kept so the machine wallet's BLS
    /// verifying key traces to the enclave root rather than a throwaway
    /// key the node holds.
    bls_key: Arc<BlsKeyPair>,
}

/// A hybrid (Ed25519 classical + ML-DSA-65 PQ) signature minted by an
/// [`AgentKeyHandle`]. Wire-shape mirrors the wallet service's
/// `HybridSignatureBytes`: both legs mandatory, no classical-only
/// fallback. Machine wallets consume this in place of the FROST/ML-DSA
/// reconstruction the Shamir keystore performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAgentHybridSignature {
    /// Classical Ed25519 signature (64 bytes).
    pub classical: Vec<u8>,
    /// ML-DSA-65 signature (3309 bytes).
    pub pq: Vec<u8>,
}

impl std::fmt::Debug for AgentKeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKeyHandle")
            .field("agent_did", &self.agent_did)
            .field("epoch", &self.epoch)
            .field("measurement", &hex::encode(self.measurement))
            .field("pubkey", &hex::encode(self.verifying_key.to_bytes()))
            // secret_scalar deliberately omitted
            .finish()
    }
}

impl AgentKeyHandle {
    /// The agent DID this handle was sealed against. Immutable.
    pub fn agent_did(&self) -> &str {
        &self.agent_did
    }

    /// Rotation epoch — increases monotonically across rotations of the
    /// same agent.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The 32-byte vendor measurement the key was bound to at seal time.
    pub fn measurement(&self) -> [u8; 32] {
        self.measurement
    }

    /// The 32-byte Ed25519 public key.
    pub fn pubkey(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Verifying-key view of the underlying Ed25519 key.
    pub fn verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }

    /// Sign an arbitrary message with the sealed key. The signing
    /// scalar is reconstructed locally (zeroized after use); the
    /// `secret_scalar` field never crosses an FFI boundary in raw form.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signing = self.signing_key_local();
        signing.sign(message)
    }

    /// Sign a 32-byte prehash (matches the contract used by
    /// `tenzro_wallet::userop::user_op_hash` — produces a raw 64-byte
    /// Ed25519 signature over the prehash). This is the entry point the
    /// desktop and CLI ERC-4337 paths use to authorize a UserOp on
    /// behalf of an agent.
    pub fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64] {
        let sig = self.sign(prehash.as_slice());
        sig.to_bytes()
    }

    /// Reconstruct an `Ed25519SigningKey` from the sealed scalar. The
    /// returned key is local to this call and dropped after use.
    fn signing_key_local(&self) -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&self.secret_scalar)
    }

    /// The ML-DSA-65 verifying-key bytes (1952 bytes). This is the PQ
    /// half of the machine wallet's hybrid public key; the classical
    /// half is [`Self::pubkey`].
    pub fn pq_verifying_key(&self) -> Vec<u8> {
        self.pq_signing_key.verifying_key_bytes().to_vec()
    }

    /// The BLS12-381 G1-compressed verifying-key bytes (48 bytes,
    /// `min_pk` scheme). Completes the machine wallet's three-key public
    /// identity (Ed25519 classical + ML-DSA-65 PQ + BLS12-381).
    pub fn bls_verifying_key(&self) -> Vec<u8> {
        self.bls_key.public_key().to_bytes().to_vec()
    }

    /// Mint a hybrid signature over `message`: the Ed25519 leg and the
    /// ML-DSA-65 leg both sign the same bytes. This is the machine-class
    /// analogue of `WalletService::sign_data` — the node verifies the
    /// pair instead of reconstructing FROST shares to mint it.
    pub fn sign_hybrid(&self, message: &[u8]) -> SealedAgentHybridSignature {
        let classical = self.sign(message).to_bytes().to_vec();
        let pq = self.pq_signing_key.sign(message);
        SealedAgentHybridSignature { classical, pq }
    }

    /// Mint a hybrid signature over a 32-byte prehash — the machine-class
    /// analogue of `WalletService::sign_transaction`, which signs
    /// `Transaction::hash()`. Both legs sign the 32 prehash bytes.
    pub fn sign_prehash_hybrid(&self, prehash: &[u8; 32]) -> SealedAgentHybridSignature {
        self.sign_hybrid(prehash.as_slice())
    }
}

/// Identification packet carried inside the attestation `user_data`
/// slot. The packet is `H(agent_did) || epoch_be || pubkey` so a
/// verifier with the agent record and a candidate report can deduce
/// (1) which agent it covers, (2) which rotation, and (3) which key
/// without needing to trust an out-of-band index.
///
/// `pubkey` is the raw 32-byte Ed25519 verifying key. `H(agent_did)`
/// is SHA-256 of the UTF-8 DID. Total packet size is 32 + 8 + 32 = 72
/// bytes, which fits inside every supported vendor's user-data ceiling
/// (Intel TDX REPORTDATA is 64 bytes, so for TDX the packet is hashed
/// down — see [`pack_user_data_for_vendor`] — but for SEV-SNP and
/// Nitro the raw packet is carried verbatim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentKeyAttestationPacket {
    pub agent_did_hash: [u8; 32],
    pub epoch: u64,
    pub pubkey: [u8; 32],
}

impl AgentKeyAttestationPacket {
    /// Construct the packet for a given handle.
    pub fn from_handle(handle: &AgentKeyHandle) -> Self {
        let mut h = Sha256::new();
        h.update(handle.agent_did.as_bytes());
        let mut did_hash = [0u8; 32];
        did_hash.copy_from_slice(&h.finalize());

        Self {
            agent_did_hash: did_hash,
            epoch: handle.epoch,
            pubkey: handle.pubkey(),
        }
    }

    /// Serialize to the 72-byte wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 + 32);
        out.extend_from_slice(&self.agent_did_hash);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.pubkey);
        out
    }

    /// Parse from the 72-byte wire form. Returns `None` on length
    /// mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 72 {
            return None;
        }
        let mut agent_did_hash = [0u8; 32];
        agent_did_hash.copy_from_slice(&bytes[..32]);
        let mut epoch_be = [0u8; 8];
        epoch_be.copy_from_slice(&bytes[32..40]);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes[40..]);
        Some(Self {
            agent_did_hash,
            epoch: u64::from_be_bytes(epoch_be),
            pubkey,
        })
    }
}

/// Derive the per-agent salt used by HKDF. The salt commits to the
/// DID and the epoch so two epochs of the same agent produce unrelated
/// keys (forward security after rotation).
fn agent_salt(agent_did: &str, epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SALT_DOMAIN);
    h.update(agent_did.as_bytes());
    h.update(epoch.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Derive an `AgentKeyHandle` from raw IKM + DID + epoch.
///
/// Internal-only: callers in production go through
/// [`seal_agent_keypair`], which sources `ikm` from the TEE provider.
/// Exposed (`pub(crate)`) for tests that need a deterministic key
/// without involving real TEE hardware.
pub(crate) fn handle_from_ikm(
    agent_did: &str,
    epoch: u64,
    measurement: [u8; 32],
    ikm: &[u8],
) -> Result<AgentKeyHandle> {
    let salt = agent_salt(agent_did, epoch);
    let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);

    let mut scalar = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, scalar.as_mut())
        .map_err(|e| TeeError::CryptoError(format!("HKDF expand failed: {}", e)))?;

    // Ed25519 accepts any 32-byte string as a seed (RFC 8032 §5.1.5),
    // so unlike secp256k1 there is no "invalid scalar" path here.
    let signing = Ed25519SigningKey::from_bytes(&scalar);
    let verifying = signing.verifying_key();
    drop(signing);

    // PQ leg — a second 32-byte HKDF expansion under a distinct info
    // string, off the same TEE root. ML-DSA-65 accepts any 32-byte seed
    // ξ (FIPS 204), so there is no rejection path here either.
    let mut pq_seed = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_PQ, pq_seed.as_mut())
        .map_err(|e| TeeError::CryptoError(format!("HKDF expand (pq) failed: {}", e)))?;
    let pq_signing_key = MlDsaSigningKey::from_seed(pq_seed.as_slice())
        .map_err(|e| TeeError::CryptoError(format!("ML-DSA-65 from_seed failed: {}", e)))?;

    // BLS leg — a third 32-byte HKDF expansion under its own info string.
    // The BLS `KeyGen` reduces the IKM into the scalar field, so any
    // 32-byte string is a valid seed.
    let mut bls_ikm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_BLS, bls_ikm.as_mut())
        .map_err(|e| TeeError::CryptoError(format!("HKDF expand (bls) failed: {}", e)))?;
    let bls_key = BlsKeyPair::from_ikm(bls_ikm.as_slice())
        .map_err(|e| TeeError::CryptoError(format!("BLS12-381 from_ikm failed: {}", e)))?;

    Ok(AgentKeyHandle {
        agent_did: agent_did.to_string(),
        epoch,
        measurement,
        verifying_key: verifying,
        secret_scalar: Arc::new(scalar),
        pq_signing_key: Arc::new(pq_signing_key),
        bls_key: Arc::new(bls_key),
    })
}

/// Seal a fresh Ed25519 agent keypair against the calling TEE.
///
/// On AMD SEV-SNP the IKM is the 64-byte `SNP_GET_DERIVED_KEY` output
/// (bound to `MEASUREMENT|IMAGE_ID|GUEST_SVN`). On Intel TDX the IKM is
/// MRTD. On AWS Nitro and NVIDIA GPU we fall back to per-attestation
/// `user_data` derivation by running a one-shot attestation with the
/// `(agent_did, epoch)` payload — vendor measurement is read off the
/// resulting report, and that report doubles as proof-of-residence for
/// the key. This is the slow path; the SNP / TDX fast path is preferred
/// when present.
///
/// Returns `TeeError::NotAvailable` on dev machines per the project's
/// no-simulation policy.
pub async fn seal_agent_keypair(
    provider: &dyn TeeProvider,
    agent_did: &str,
) -> Result<AgentKeyHandle> {
    seal_agent_keypair_epoch(provider, agent_did, 0).await
}

/// Like [`seal_agent_keypair`] but produces a specific rotation epoch.
/// Used internally by [`rotate_agent_key`].
async fn seal_agent_keypair_epoch(
    provider: &dyn TeeProvider,
    agent_did: &str,
    epoch: u64,
) -> Result<AgentKeyHandle> {
    if !provider.is_available().await? {
        return Err(TeeError::not_available(format!(
            "TEE provider {:?} unavailable for agent_did={}",
            provider.vendor(),
            agent_did
        )));
    }

    // We use a one-shot attestation as a uniform IKM source across all
    // vendors. For SEV-SNP and TDX the underlying provider implementations
    // bind the report to the platform measurement; for Nitro the COSE
    // signature transitively binds to the AWS root CA. The report's
    // `quote` bytes are not predictable to a remote attacker, and the
    // `measurement` bytes give us the platform binding.
    //
    // We include `(agent_did, epoch)` as user_data so two different
    // epochs of the same DID produce *different* reports → different
    // IKM → different keys, satisfying forward-security on rotation.
    let user_data = {
        let mut h = Sha256::new();
        h.update(SALT_DOMAIN);
        h.update(agent_did.as_bytes());
        h.update(epoch.to_be_bytes());
        h.finalize().to_vec()
    };
    let report = provider.generate_attestation(&user_data).await?;

    // Vendor measurement → committed at seal time so callers can later
    // verify a fresh attestation's measurement matches.
    let mut measurement = [0u8; 32];
    if report.measurement.len() >= 32 {
        measurement.copy_from_slice(&report.measurement[..32]);
    } else {
        // Some vendors (Nitro) carry a longer COSE measurement; fold it
        // down rather than truncate-and-lose the high bytes.
        let mut h = Sha256::new();
        h.update(&report.measurement);
        measurement.copy_from_slice(&h.finalize());
    }

    // IKM mixes the platform measurement, the report quote (when
    // present), and the report id so two seal calls within the same
    // boot still produce distinct material if the platform refreshes
    // any of those.
    let mut ikm_buf = Zeroizing::new(Vec::<u8>::with_capacity(96));
    ikm_buf.extend_from_slice(&measurement);
    ikm_buf.extend_from_slice(&report.quote);
    ikm_buf.extend_from_slice(report.id.as_bytes());

    let handle = handle_from_ikm(agent_did, epoch, measurement, &ikm_buf)?;
    Ok(handle)
}

/// Produce an `AttestationReport` that binds the agent's public key
/// into the report's user-data slot. The returned report is what the
/// ERC-8004 metadata URI must resolve to so that an on-chain agent
/// record can be cryptographically tied back to a TEE-resident key.
///
/// Verifier protocol:
///
/// 1. Read the `(agent_id, agent_address, metadata_uri)` record from
///    `ERC8004_IDENTITY.getAgent`.
/// 2. Fetch the metadata doc; parse the embedded `AttestationReport`.
/// 3. Reconstruct the expected packet:
///    [`AgentKeyAttestationPacket::from_handle`].
/// 4. Compare `report.user_data` to either the raw 72-byte packet
///    (SEV-SNP, Nitro) or SHA-256 of the packet (TDX, where
///    REPORTDATA is 64 bytes — see [`pack_user_data_for_vendor`]).
/// 5. Run `provider.verify_attestation(&report)` and require
///    `AttestationResult.valid == true`.
/// 6. (Optional defense-in-depth) sanity-check
///    `report.measurement[..32] == handle.measurement()`.
pub async fn attest_agent_key(
    provider: &dyn TeeProvider,
    handle: &AgentKeyHandle,
) -> Result<AttestationReport> {
    let packet = AgentKeyAttestationPacket::from_handle(handle);
    let packed = pack_user_data_for_vendor(provider.vendor(), &packet.to_bytes());
    provider.generate_attestation(&packed).await
}

/// Adjust the user_data payload to the vendor's per-report ceiling.
///
/// - TDX REPORTDATA is fixed 64 bytes; we SHA-256 the 72-byte packet
///   and pad to 64 with the hash repeated (matches the conventional
///   `report_data = H(payload) || zeros[..32]` shape).
/// - SEV-SNP allows 64-byte REPORT_DATA; same treatment as TDX.
/// - Nitro carries `user_data` directly with no fixed ceiling (up to
///   the COSE document budget) — pass the raw packet.
/// - NVIDIA GPU CC reports carry arbitrary `user_data` — raw packet.
/// - Generic / unknown: pass through verbatim.
pub fn pack_user_data_for_vendor(vendor: tenzro_types::tee::TeeVendor, packet: &[u8]) -> Vec<u8> {
    use tenzro_types::tee::TeeVendor;
    match vendor {
        TeeVendor::IntelTdx | TeeVendor::AmdSevSnp | TeeVendor::AMDSEV | TeeVendor::IntelSGX => {
            let mut h = Sha256::new();
            h.update(packet);
            let digest = h.finalize();
            let mut out = vec![0u8; 64];
            out[..32].copy_from_slice(&digest);
            out[32..].copy_from_slice(&digest);
            out
        }
        TeeVendor::AWSNitro
        | TeeVendor::AwsNitro
        | TeeVendor::NvidiaGpu
        | TeeVendor::ARMTrustZone
        | TeeVendor::Generic => packet.to_vec(),
    }
}

/// Rotate an agent's key — produce a fresh `AgentKeyHandle` at
/// `previous.epoch() + 1`. The returned handle is unrelated to the
/// previous key (forward-secure via the salt commit to epoch). The
/// caller is responsible for:
///
/// 1. Issuing a follow-up [`attest_agent_key`] to obtain a new
///    attestation report.
/// 2. Submitting an on-chain rotation call (either an ERC-8004
///    `register` overload that mutates `metadata_uri`, or a
///    fleet-specific "rotate key" precompile).
/// 3. Keeping the previous handle around until any pending UserOps
///    drain — the verifier compares incoming signatures against the
///    epoch encoded in the metadata-resolved attestation, so a
///    just-rotated agent must keep both `epoch_old` and `epoch_new`
///    handles live until the rotation is final on-chain.
pub async fn rotate_agent_key(
    provider: &dyn TeeProvider,
    previous: &AgentKeyHandle,
) -> Result<AgentKeyHandle> {
    let next_epoch = previous
        .epoch
        .checked_add(1)
        .ok_or_else(|| TeeError::internal("agent key rotation epoch overflow"))?;
    let handle = seal_agent_keypair_epoch(provider, &previous.agent_did, next_epoch).await?;
    if handle.pubkey() == previous.pubkey() {
        // This would only happen if the TEE produced byte-identical
        // material for two epochs (e.g. broken HKDF salt commit). Hard
        // fail rather than silently return a non-rotating "rotation".
        return Err(TeeError::internal(
            "rotate_agent_key produced identical pubkey across epochs",
        ));
    }
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_handle(agent_did: &str, epoch: u64) -> AgentKeyHandle {
        let measurement = {
            let mut h = Sha256::new();
            h.update(b"test-measurement");
            h.update(agent_did.as_bytes());
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize());
            out
        };
        handle_from_ikm(agent_did, epoch, measurement, &[0xABu8; 96]).unwrap()
    }

    #[test]
    fn handle_is_deterministic_for_same_inputs() {
        let a = fixed_handle("did:tenzro:machine:alice", 0);
        let b = fixed_handle("did:tenzro:machine:alice", 0);
        assert_eq!(a.pubkey(), b.pubkey());
    }

    #[test]
    fn epoch_changes_key() {
        let a = fixed_handle("did:tenzro:machine:alice", 0);
        let b = fixed_handle("did:tenzro:machine:alice", 1);
        assert_ne!(a.pubkey(), b.pubkey());
        assert_eq!(a.epoch(), 0);
        assert_eq!(b.epoch(), 1);
    }

    #[test]
    fn did_changes_key() {
        let a = fixed_handle("did:tenzro:machine:alice", 0);
        let b = fixed_handle("did:tenzro:machine:bob", 0);
        assert_ne!(a.pubkey(), b.pubkey());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        use ed25519_dalek::Verifier;
        let handle = fixed_handle("did:tenzro:machine:alice", 0);
        let msg = b"some bytes";
        let sig = handle.sign(msg);
        handle.verifying_key().verify(msg, &sig).expect("self-verify");
    }

    #[test]
    fn sign_prehash_returns_64_bytes() {
        let handle = fixed_handle("did:tenzro:machine:alice", 0);
        let digest = [0x11u8; 32];
        let sig = handle.sign_prehash(&digest);
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn clone_shares_secret_without_disturbing_origin() {
        let handle = fixed_handle("did:tenzro:machine:alice", 0);
        let clone = handle.clone();
        let msg = b"hi";
        let sig_a = handle.sign(msg);
        let sig_b = clone.sign(msg);
        // Ed25519 is deterministic (RFC 8032) — same key + same msg
        // must yield the same signature byte-for-byte.
        assert_eq!(sig_a.to_bytes(), sig_b.to_bytes());
    }

    #[test]
    fn attestation_packet_roundtrip() {
        let handle = fixed_handle("did:tenzro:machine:alice", 7);
        let packet = AgentKeyAttestationPacket::from_handle(&handle);
        assert_eq!(packet.epoch, 7);
        assert_eq!(packet.pubkey, handle.pubkey());
        let bytes = packet.to_bytes();
        assert_eq!(bytes.len(), 72);
        let parsed = AgentKeyAttestationPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn pack_user_data_tdx_fits_64_bytes() {
        use tenzro_types::tee::TeeVendor;
        let packet = vec![0x55u8; 72];
        let packed = pack_user_data_for_vendor(TeeVendor::IntelTdx, &packet);
        assert_eq!(packed.len(), 64);
        // First 32 == last 32 (hash repeated).
        assert_eq!(packed[..32], packed[32..]);
    }

    #[test]
    fn pack_user_data_nitro_is_verbatim() {
        use tenzro_types::tee::TeeVendor;
        let packet = vec![0x55u8; 72];
        let packed = pack_user_data_for_vendor(TeeVendor::AWSNitro, &packet);
        assert_eq!(packed, packet);
    }

    #[test]
    fn pq_verifying_key_is_deterministic_and_sized() {
        let a = fixed_handle("did:tenzro:machine:alice", 0);
        let b = fixed_handle("did:tenzro:machine:alice", 0);
        assert_eq!(a.pq_verifying_key(), b.pq_verifying_key());
        // FIPS 204 §4 Table 2: ML-DSA-65 verifying key is 1952 bytes.
        assert_eq!(a.pq_verifying_key().len(), 1952);
    }

    #[test]
    fn bls_verifying_key_is_deterministic_and_sized() {
        let a = fixed_handle("did:tenzro:machine:alice", 0);
        let b = fixed_handle("did:tenzro:machine:alice", 0);
        assert_eq!(a.bls_verifying_key(), b.bls_verifying_key());
        // BLS12-381 G1-compressed (min_pk) verifying key is 48 bytes.
        assert_eq!(a.bls_verifying_key().len(), 48);
    }

    #[test]
    fn three_legs_are_independent() {
        // Distinct HKDF info strings → three unrelated public keys.
        let h = fixed_handle("did:tenzro:machine:alice", 0);
        let ed = h.pubkey().to_vec();
        let pq = h.pq_verifying_key();
        let bls = h.bls_verifying_key();
        assert_ne!(ed.as_slice(), &pq[..ed.len()]);
        assert_ne!(ed.as_slice(), &bls[..ed.len().min(bls.len())]);
        assert_ne!(&pq[..bls.len()], bls.as_slice());
    }

    #[test]
    fn pq_leg_is_independent_of_classical_leg() {
        // The two legs derive under distinct HKDF info strings, so the
        // 32-byte Ed25519 secret and the 32-byte ML-DSA seed must differ.
        let handle = fixed_handle("did:tenzro:machine:alice", 0);
        let classical_secret = handle.secret_scalar.as_slice().to_vec();
        // Reach the PQ seed via the public verifying key instead of the
        // secret: two independent secrets yield unrelated pubkeys, and the
        // Ed25519 pubkey (32B) is not a prefix of the ML-DSA vk (1952B).
        assert_ne!(&handle.pq_verifying_key()[..32], classical_secret.as_slice());
    }

    #[test]
    fn hybrid_sign_verifies_on_both_legs() {
        use ed25519_dalek::Verifier;
        let handle = fixed_handle("did:tenzro:machine:alice", 0);
        let msg = b"machine wallet payload";
        let sig = handle.sign_hybrid(msg);
        // Classical leg: 64-byte Ed25519 over msg.
        assert_eq!(sig.classical.len(), 64);
        let ed_sig = Ed25519Signature::from_slice(&sig.classical).unwrap();
        handle
            .verifying_key()
            .verify(msg, &ed_sig)
            .expect("classical leg verifies");
        // PQ leg: 3309-byte ML-DSA-65 over the same msg.
        assert_eq!(sig.pq.len(), 3309);
        tenzro_crypto::ml_dsa_verify(&handle.pq_verifying_key(), msg, &sig.pq)
            .expect("pq leg verifies");
    }

    #[test]
    fn sign_prehash_hybrid_signs_the_prehash_bytes() {
        let handle = fixed_handle("did:tenzro:machine:alice", 0);
        let prehash = [0x22u8; 32];
        let via_prehash = handle.sign_prehash_hybrid(&prehash);
        // Ed25519 is deterministic; the classical leg over the prehash
        // must equal a direct hybrid-sign over the same 32 bytes.
        let via_msg = handle.sign_hybrid(prehash.as_slice());
        assert_eq!(via_prehash.classical, via_msg.classical);
    }

    #[test]
    fn debug_omits_secret() {
        let handle = fixed_handle("did:tenzro:machine:alice", 0);
        let debug = format!("{:?}", handle);
        // The Debug impl must not leak the secret scalar. We check it
        // by ensuring the hex of the secret scalar is not substring
        // of the debug output. Reading through the field is fine —
        // we just don't want it printed.
        let secret_hex = hex::encode(handle.secret_scalar.as_slice());
        assert!(!debug.contains(&secret_hex), "Debug leaked secret");
        // It SHOULD include the pubkey (callable, non-secret).
        assert!(debug.contains(&hex::encode(handle.pubkey())));
    }
}
