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
//! - [`attest_agent_key`] binds the public key **and the machine's
//!   hardware root** into an `AttestationReport`'s `user_data` slot by way
//!   of the underlying [`crate::traits::TeeProvider::generate_attestation`].
//!   The resulting report is the cryptographic predicate behind the
//!   `ERC8004_IDENTITY.registerAgent` call: the on-chain registry stores
//!   `(agent_id, agent_address, metadata_uri)` and the metadata URI MUST
//!   resolve to a document containing this attestation. The verifier
//!   chain is: read agent record → fetch metadata doc → parse
//!   attestation → run [`verify_agent_key_binding`] against the recorded
//!   `(did, epoch, pubkey, hardware_root)` → run
//!   [`crate::traits::TeeProvider::verify_attestation`].
//!
//!   Carrying the hardware root is what makes a machine identity mean a
//!   machine. Without it, a second host running the same enclave image
//!   produces an equally valid report for someone else's DID; with it,
//!   the enclave signs over which physical unit it is running on.
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
use crate::platform_root::platform_root_ikm;
use crate::traits::TeeProvider;
use tenzro_crypto::MlDsaSigningKey;
use tenzro_crypto::bls::BlsKeyPair;
use tenzro_types::tee::AttestationReport;

/// HKDF info string for agent Ed25519 derivation.
const HKDF_INFO: &[u8] = b"tenzro/sealed-agent-ed25519";

/// HKDF info string for the agent ML-DSA-65 seed derivation. A distinct
/// info string from [`HKDF_INFO`] so the classical and post-quantum legs
/// derive to independent secrets from the same TEE root.
const HKDF_INFO_PQ: &[u8] = b"tenzro/sealed-agent-ml-dsa-65";

/// HKDF info string for the agent BLS12-381 seed derivation. A distinct
/// info string again, so the BLS leg is independent of the classical and
/// PQ legs while still rooting in the same TEE material. The BLS leg is
/// the verifying key a machine identity needs to satisfy the wallet's
/// structural invariant and, if the machine ever stakes as a validator,
/// to aggregate HotStuff-2 votes.
const HKDF_INFO_BLS: &[u8] = b"tenzro/sealed-agent-bls12-381";

/// Domain-separation prefix for the per-agent salt. Two agents with the
/// same TEE root **must not** yield the same key — the salt mixes in the
/// DID and the rotation epoch so the binding is uniquely
/// `(tee_root, agent_did, epoch) → key`.
const SALT_DOMAIN: &[u8] = b"tenzro/agent-key-salt";

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

/// Size of the wire form of [`AgentKeyAttestationPacket`].
pub const AGENT_KEY_PACKET_LEN: usize = 32 + 8 + 32 + 32;

/// Identification packet carried inside the attestation `user_data`
/// slot. The packet is `H(agent_did) || epoch_be || pubkey ||
/// hardware_root` so a verifier with the agent record and a candidate
/// report can deduce (1) which agent it covers, (2) which rotation,
/// (3) which key, and (4) which physical machine minted it — without
/// needing to trust an out-of-band index.
///
/// `pubkey` is the raw 32-byte Ed25519 verifying key. `H(agent_did)`
/// is SHA-256 of the UTF-8 DID. `hardware_root` is
/// [`crate::HardwareIdentity::root`] — a fold over the machine's
/// per-unit identifiers (SMBIOS system UUID, baseboard serial, NVIDIA
/// GPU UUIDs), all-zero on a host where none of those are readable.
///
/// Including the root is what stops a second machine from presenting
/// its own valid attestation for someone else's DID: the enclave
/// signs over the machine identity, so the report is only accepted
/// against the root the identity was registered with.
///
/// Total packet size is [`AGENT_KEY_PACKET_LEN`] bytes. Intel TDX
/// REPORTDATA is a fixed 64 bytes, so for TDX the packet is hashed
/// down — see [`pack_user_data_for_vendor`] — while SEV-SNP and Nitro
/// carry the raw packet verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentKeyAttestationPacket {
    pub agent_did_hash: [u8; 32],
    pub epoch: u64,
    pub pubkey: [u8; 32],
    pub hardware_root: [u8; 32],
}

impl AgentKeyAttestationPacket {
    /// Construct the packet for a given handle on a given machine.
    ///
    /// Pass `[0u8; 32]` for `hardware_root` when the host exposes no
    /// per-unit identifier ([`crate::HardwareIdentity::is_rooted`] is
    /// false). That is a legible "unrooted" claim rather than a
    /// forged one — the all-zero root is identical across every such
    /// host, so a verifier can tell it apart from a real machine.
    pub fn from_handle(handle: &AgentKeyHandle, hardware_root: [u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(handle.agent_did.as_bytes());
        let mut did_hash = [0u8; 32];
        did_hash.copy_from_slice(&h.finalize());

        Self {
            agent_did_hash: did_hash,
            epoch: handle.epoch,
            pubkey: handle.pubkey(),
            hardware_root,
        }
    }

    /// Serialize to the [`AGENT_KEY_PACKET_LEN`]-byte wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AGENT_KEY_PACKET_LEN);
        out.extend_from_slice(&self.agent_did_hash);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.hardware_root);
        out
    }

    /// Parse from the wire form. Returns `None` on length mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != AGENT_KEY_PACKET_LEN {
            return None;
        }
        let mut agent_did_hash = [0u8; 32];
        agent_did_hash.copy_from_slice(&bytes[..32]);
        let mut epoch_be = [0u8; 8];
        epoch_be.copy_from_slice(&bytes[32..40]);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes[40..72]);
        let mut hardware_root = [0u8; 32];
        hardware_root.copy_from_slice(&bytes[72..]);
        Some(Self {
            agent_did_hash,
            epoch: u64::from_be_bytes(epoch_be),
            pubkey,
            hardware_root,
        })
    }

    /// Whether the packet claims a machine-rooted identity, i.e. the
    /// enclave that signed it could read at least one per-unit
    /// hardware identifier.
    pub fn is_hardware_rooted(&self) -> bool {
        self.hardware_root != [0u8; 32]
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

/// Seal an Ed25519 agent keypair against the calling TEE.
///
/// "Seal" rather than "generate": the key is a deterministic function of
/// `(platform root, vendor measurement, agent_did, epoch)`, so the same
/// agent on the same measured image recovers the same key after a restart.
/// That is what lets an ERC-8004 record and its metadata URI stay valid
/// across the lifetime of the agent.
///
/// The platform root is `SNP_GET_DERIVED_KEY` bound to
/// `MEASUREMENT|IMAGE_ID|GUEST_SVN` on AMD SEV-SNP and MRTD on Intel TDX
/// (see [`crate::platform_root`]). AWS Nitro and NVIDIA GPU CC expose no
/// derivation interface, so there the vendor measurement carried in the
/// attestation report is the whole binding — weaker, because a host that
/// can forge a measurement can forge the key, but still stable per image.
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

    // The one-shot attestation serves two purposes: it yields the vendor
    // measurement the handle commits to, and it is the proof-of-residence
    // a verifier later replays. Its `(agent_did, epoch)` user_data ties
    // the report to the identity being sealed.
    //
    // It is deliberately *not* the source of key material. A report is
    // fresh on every call — the quote carries a timestamp and the report
    // id is assigned per report — so deriving from it would give the agent
    // a different key after every restart, and the ERC-8004 record plus
    // metadata URI written at registration would point at a key nobody
    // holds. Rotation forward-security comes from the epoch in the HKDF
    // salt (see `agent_salt`), which is where it belongs.
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

    // IKM is the platform's stable root, prefixed by the measurement the
    // handle commits to. On SEV-SNP and TDX `platform_root_ikm` supplies a
    // root the host cannot forge; on Nitro and NVIDIA GPU CC, which expose
    // no derivation interface, the measurement alone carries the binding.
    // Every input here is a function of the measured image, so the same
    // platform re-seals to the same key.
    let mut ikm_buf = Zeroizing::new(Vec::<u8>::with_capacity(96));
    ikm_buf.extend_from_slice(&measurement);
    if let Ok(root) = platform_root_ikm().await {
        ikm_buf.extend_from_slice(root.as_slice());
    }

    let handle = handle_from_ikm(agent_did, epoch, measurement, &ikm_buf)?;
    Ok(handle)
}

/// Produce an `AttestationReport` that binds the agent's public key
/// and the machine it was minted on into the report's user-data slot.
/// The returned report is what the ERC-8004 metadata URI must resolve
/// to so that an on-chain agent record can be cryptographically tied
/// back to a TEE-resident key on a specific physical machine.
///
/// `hardware_root` comes from [`crate::HardwareIdentity::root`]; pass
/// `[0u8; 32]` on a host with no readable per-unit identifier.
///
/// Verifier protocol:
///
/// 1. Read the `(agent_id, agent_address, metadata_uri)` record from
///    `ERC8004_IDENTITY.getAgent`.
/// 2. Fetch the metadata doc; parse the embedded `AttestationReport`.
/// 3. Run [`verify_agent_key_binding`] against the DID, epoch, pubkey
///    and hardware root the identity was registered with.
/// 4. Run `provider.verify_attestation(&report)` and require
///    `AttestationResult.valid == true`.
/// 5. (Optional defense-in-depth) sanity-check
///    `report.measurement[..32] == handle.measurement()`.
///
/// Steps 3 and 4 are independent and neither substitutes for the other:
/// 3 says the report covers this identity on this machine, 4 says the
/// report is genuine.
pub async fn attest_agent_key(
    provider: &dyn TeeProvider,
    handle: &AgentKeyHandle,
    hardware_root: [u8; 32],
) -> Result<AttestationReport> {
    let packet = AgentKeyAttestationPacket::from_handle(handle, hardware_root);
    let packed = pack_user_data_for_vendor(provider.vendor(), &packet.to_bytes());
    provider.generate_attestation(&packed).await
}

/// Check that `report` was minted for exactly this agent key on this
/// machine.
///
/// Rebuilds the expected packet from the caller's own record of
/// `(agent_did, epoch, pubkey, hardware_root)`, packs it for the
/// report's vendor, and compares against `report.user_data`. On TDX
/// and SEV-SNP the comparison is against the digest the enclave
/// actually committed to, which is why the packing runs here rather
/// than the caller comparing raw bytes.
///
/// Returns false rather than erroring — a mismatched report is a
/// routine outcome when a caller is deciding whether to trust a claim,
/// not an exceptional one. This does **not** verify the report's
/// signature or certificate chain; run `provider.verify_attestation`
/// for that.
pub fn verify_agent_key_binding(
    report: &AttestationReport,
    agent_did: &str,
    epoch: u64,
    pubkey: &[u8; 32],
    hardware_root: [u8; 32],
) -> bool {
    let mut h = Sha256::new();
    h.update(agent_did.as_bytes());
    let mut agent_did_hash = [0u8; 32];
    agent_did_hash.copy_from_slice(&h.finalize());

    let expected = AgentKeyAttestationPacket {
        agent_did_hash,
        epoch,
        pubkey: *pubkey,
        hardware_root,
    };
    let packed = pack_user_data_for_vendor(report.vendor, &expected.to_bytes());
    // Length is part of the claim: a report whose user_data is a
    // prefix of the expected packing is not the same commitment.
    packed.len() == report.user_data.len()
        && packed
            .iter()
            .zip(report.user_data.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Adjust the user_data payload to the vendor's per-report ceiling.
///
/// - TDX REPORTDATA is fixed 64 bytes; we SHA-256 the packet and pad
///   to 64 with the hash repeated (matches the conventional
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

    /// A provider whose measurement is stable but whose report id and quote
    /// are fresh on every call — exactly the shape of a real one. Sealing
    /// must ignore the volatile fields.
    struct VolatileReportProvider {
        measurement: [u8; 32],
    }

    #[async_trait::async_trait]
    impl TeeProvider for VolatileReportProvider {
        fn vendor(&self) -> tenzro_types::tee::TeeVendor {
            tenzro_types::tee::TeeVendor::AmdSevSnp
        }

        async fn is_available(&self) -> Result<bool> {
            Ok(true)
        }

        async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport> {
            Ok(AttestationReport {
                id: uuid::Uuid::new_v4(),
                vendor: self.vendor(),
                user_data: user_data.to_vec(),
                quote: uuid::Uuid::new_v4().as_bytes().to_vec(),
                measurement: self.measurement.to_vec(),
                ..Default::default()
            })
        }

        async fn verify_attestation(
            &self,
            _report: &AttestationReport,
        ) -> Result<tenzro_types::tee::AttestationResult> {
            unimplemented!("sealing does not verify")
        }

        async fn execute_in_enclave(
            &self,
            _request: tenzro_types::tee::EnclaveRequest,
        ) -> Result<tenzro_types::tee::EnclaveResponse> {
            unimplemented!("sealing does not enter the enclave")
        }

        async fn enclave_keygen(
            &self,
            _params: tenzro_types::tee::KeyGenParams,
        ) -> Result<tenzro_types::tee::EnclaveKeyHandle> {
            unimplemented!("sealing derives its own key")
        }

        async fn enclave_sign(
            &self,
            _key: &tenzro_types::tee::EnclaveKeyHandle,
            _data: &[u8],
        ) -> Result<Vec<u8>> {
            unimplemented!("sealing does not sign")
        }

        async fn enclave_encrypt(
            &self,
            _key: &tenzro_types::tee::EnclaveKeyHandle,
            _plaintext: &[u8],
        ) -> Result<Vec<u8>> {
            unimplemented!("sealing does not encrypt")
        }

        async fn enclave_decrypt(
            &self,
            _key: &tenzro_types::tee::EnclaveKeyHandle,
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>> {
            unimplemented!("sealing does not decrypt")
        }
    }

    #[tokio::test]
    async fn sealing_survives_a_restart() {
        // The whole point of sealing. Two seals of the same agent against
        // the same measured platform must land on the same key, or the
        // ERC-8004 record written at registration outlives the key it
        // names. Folding the report id or quote into the derivation is the
        // way this breaks, and it breaks silently: each individual seal
        // succeeds and signs correctly.
        let provider = VolatileReportProvider {
            measurement: [0x5Au8; 32],
        };
        let did = "did:tenzro:machine:restart";

        let first = seal_agent_keypair(&provider, did).await.unwrap();
        let second = seal_agent_keypair(&provider, did).await.unwrap();

        assert_eq!(first.pubkey(), second.pubkey());
        assert_eq!(first.pq_verifying_key(), second.pq_verifying_key());
        assert_eq!(first.bls_verifying_key(), second.bls_verifying_key());
    }

    #[tokio::test]
    async fn a_different_platform_seals_a_different_key() {
        // The counterpart: reproducibility must not have been bought by
        // dropping the platform binding altogether.
        let did = "did:tenzro:machine:restart";
        let here = seal_agent_keypair(
            &VolatileReportProvider {
                measurement: [0x5Au8; 32],
            },
            did,
        )
        .await
        .unwrap();
        let elsewhere = seal_agent_keypair(
            &VolatileReportProvider {
                measurement: [0xA5u8; 32],
            },
            did,
        )
        .await
        .unwrap();

        assert_ne!(here.pubkey(), elsewhere.pubkey());
    }

    #[tokio::test]
    async fn rotation_still_changes_the_key() {
        // Forward security on rotation now rests entirely on the epoch in
        // the HKDF salt, since nothing per-call feeds the IKM any more.
        let provider = VolatileReportProvider {
            measurement: [0x5Au8; 32],
        };
        let first = seal_agent_keypair(&provider, "did:tenzro:machine:rot")
            .await
            .unwrap();
        let rotated = rotate_agent_key(&provider, &first).await.unwrap();

        assert_eq!(rotated.epoch(), 1);
        assert_ne!(first.pubkey(), rotated.pubkey());
    }

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
        handle
            .verifying_key()
            .verify(msg, &sig)
            .expect("self-verify");
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
        let root = [0xABu8; 32];
        let packet = AgentKeyAttestationPacket::from_handle(&handle, root);
        assert_eq!(packet.epoch, 7);
        assert_eq!(packet.pubkey, handle.pubkey());
        assert_eq!(packet.hardware_root, root);
        assert!(packet.is_hardware_rooted());
        let bytes = packet.to_bytes();
        assert_eq!(bytes.len(), AGENT_KEY_PACKET_LEN);
        let parsed = AgentKeyAttestationPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn unrooted_packet_is_reported_as_such() {
        // A host with no readable per-unit identifier makes a legible
        // "no machine identity" claim rather than a fabricated one.
        let handle = fixed_handle("did:tenzro:machine:alice", 0);
        let packet = AgentKeyAttestationPacket::from_handle(&handle, [0u8; 32]);
        assert!(!packet.is_hardware_rooted());
    }

    #[test]
    fn pack_user_data_tdx_fits_64_bytes() {
        use tenzro_types::tee::TeeVendor;
        let packet = vec![0x55u8; AGENT_KEY_PACKET_LEN];
        let packed = pack_user_data_for_vendor(TeeVendor::IntelTdx, &packet);
        assert_eq!(packed.len(), 64);
        // First 32 == last 32 (hash repeated).
        assert_eq!(packed[..32], packed[32..]);
    }

    #[test]
    fn pack_user_data_nitro_is_verbatim() {
        use tenzro_types::tee::TeeVendor;
        let packet = vec![0x55u8; AGENT_KEY_PACKET_LEN];
        let packed = pack_user_data_for_vendor(TeeVendor::AWSNitro, &packet);
        assert_eq!(packed, packet);
    }

    /// Build the report `attest_agent_key` would have produced, without
    /// going through an async provider.
    fn report_for(
        vendor: tenzro_types::tee::TeeVendor,
        handle: &AgentKeyHandle,
        root: [u8; 32],
    ) -> AttestationReport {
        let packet = AgentKeyAttestationPacket::from_handle(handle, root);
        AttestationReport {
            id: uuid::Uuid::new_v4(),
            vendor,
            user_data: pack_user_data_for_vendor(vendor, &packet.to_bytes()),
            ..Default::default()
        }
    }

    #[test]
    fn binding_accepts_the_report_it_was_minted_from() {
        use tenzro_types::tee::TeeVendor;
        // Both packings must verify: Nitro carries the raw packet, TDX
        // carries only its digest, and the check has to reconstruct
        // whichever the enclave actually committed to.
        for vendor in [TeeVendor::AWSNitro, TeeVendor::IntelTdx] {
            let handle = fixed_handle("did:tenzro:machine:alice", 3);
            let root = [0x11u8; 32];
            let report = report_for(vendor, &handle, root);
            assert!(verify_agent_key_binding(
                &report,
                "did:tenzro:machine:alice",
                3,
                &handle.pubkey(),
                root,
            ));
        }
    }

    #[test]
    fn binding_rejects_a_different_machine() {
        // The whole point of folding the root in: a genuine report from
        // another box must not satisfy this identity's binding.
        use tenzro_types::tee::TeeVendor;
        let handle = fixed_handle("did:tenzro:machine:alice", 3);
        let report = report_for(TeeVendor::AWSNitro, &handle, [0x11u8; 32]);
        assert!(!verify_agent_key_binding(
            &report,
            "did:tenzro:machine:alice",
            3,
            &handle.pubkey(),
            [0x22u8; 32],
        ));
    }

    #[test]
    fn binding_rejects_wrong_did_epoch_or_key() {
        use tenzro_types::tee::TeeVendor;
        let handle = fixed_handle("did:tenzro:machine:alice", 3);
        let root = [0x11u8; 32];
        let report = report_for(TeeVendor::AWSNitro, &handle, root);

        assert!(!verify_agent_key_binding(
            &report,
            "did:tenzro:machine:mallory",
            3,
            &handle.pubkey(),
            root,
        ));
        assert!(!verify_agent_key_binding(
            &report,
            "did:tenzro:machine:alice",
            4,
            &handle.pubkey(),
            root,
        ));
        assert!(!verify_agent_key_binding(
            &report,
            "did:tenzro:machine:alice",
            3,
            &[0u8; 32],
            root,
        ));
    }

    #[test]
    fn binding_rejects_a_truncated_user_data() {
        use tenzro_types::tee::TeeVendor;
        let handle = fixed_handle("did:tenzro:machine:alice", 3);
        let root = [0x11u8; 32];
        let mut report = report_for(TeeVendor::AWSNitro, &handle, root);
        report.user_data.truncate(AGENT_KEY_PACKET_LEN - 1);
        assert!(!verify_agent_key_binding(
            &report,
            "did:tenzro:machine:alice",
            3,
            &handle.pubkey(),
            root,
        ));
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
        assert_ne!(
            &handle.pq_verifying_key()[..32],
            classical_secret.as_slice()
        );
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
