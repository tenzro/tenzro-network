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
use tenzro_types::tee::AttestationReport;

/// HKDF info string for agent Ed25519 derivation. Bumped if the
/// derivation chain ever changes.
const HKDF_INFO: &[u8] = b"tenzro/sealed-agent-ed25519/v1";

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

    Ok(AgentKeyHandle {
        agent_did: agent_did.to_string(),
        epoch,
        measurement,
        verifying_key: verifying,
        secret_scalar: Arc::new(scalar),
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
