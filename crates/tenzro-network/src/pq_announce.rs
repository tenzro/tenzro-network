//! A post-quantum signature leg for gossip announcements.
//!
//! # What this buys, stated precisely
//!
//! Not quantum resistance. Not yet, and it is worth being exact about why,
//! because the obvious reading of "we ML-DSA-signed the announcements" is
//! wrong and would stop someone from finishing the job.
//!
//! An announcement carries its own PQ verifying key. An adversary who can
//! break Ed25519 — the only adversary a PQ leg is for — forges the announce
//! key and the libp2p identity the announcement is bound to, and while doing
//! so substitutes a PQ keypair of their own. Both legs verify. The PQ
//! signature defended nothing, because the verifier had no independent reason
//! to expect *that* verifying key.
//!
//! A PQ signature is load-bearing only when the verifier learns the key
//! through a channel the adversary cannot forge. Validators already have one:
//! `ValidatorRegistryEntry` carries `pq_pubkey`, registered on-chain. Gossip
//! providers have no equivalent, so for them this is currently an unpinned
//! key.
//!
//! # So why ship it now
//!
//! Because pinning cannot come first. A registry of PQ keys is only possible
//! once nodes publish PQ keys that are stable enough to be worth recording,
//! and this is what makes them stable and published. Shipping the leg is the
//! prerequisite for the pinning that makes it matter.
//!
//! Two things it does buy today, against a classical adversary:
//!
//! - **Downgrade detection.** The classical signature is computed last and
//!   covers both PQ fields, so stripping the PQ leg to force a peer onto the
//!   weaker path invalidates the announcement. There is no silent downgrade.
//! - **A stable key to pin.** The PQ key is derived from the node's identity
//!   key, so it is the same key on every boot and survives whatever the
//!   identity survives — a wiped data directory under the TPM root, a restart
//!   under the passkey root. A key that changed each boot could never be
//!   pinned, registered, or revoked.
//!
//! Consumers should treat a valid PQ leg as *unproven provenance*, exactly as
//! they treat an unbound announcement — see [`verify_pq`]'s tri-state return.

use tenzro_crypto::pq::MlDsaSigningKey;

use crate::error::{NetworkError, Result};

/// Derivation label for the announcement PQ key.
///
/// Distinct from the identity derivation's own label so the two keys are
/// independent: recovering one must not reveal the other.
const PQ_ANNOUNCE_LABEL: &[u8] = b"tenzro/pq-announce-identity/v1";

/// Derive this node's ML-DSA-65 announcement key from its identity key.
///
/// Deriving rather than generating is the whole point. A generated key would
/// be new on every boot, which makes it unpinnable and unrevocable — and would
/// be random key material sitting next to an identity system built specifically
/// to have none. Derived, it inherits the identity's root: chip-bound under a
/// TPM, human-authorised under a passkey delegation, and in both cases the same
/// key tomorrow as today.
///
/// # Errors
///
/// Fails if the node identity is not Ed25519. There is no fallback — a PQ key
/// this function invented would be exactly the unrooted material the identity
/// design forbids.
pub fn pq_identity_key(node_key: &libp2p::identity::Keypair) -> Result<MlDsaSigningKey> {
    let ed = node_key.clone().try_into_ed25519().map_err(|e| {
        NetworkError::NoHardwareRoot(format!(
            "cannot derive a PQ announcement key: node identity is not Ed25519: {e}"
        ))
    })?;

    // `secret()` hands back the 32-byte Ed25519 seed. It is the strongest
    // material the node has; the HKDF label keeps this key independent of the
    // identity key itself.
    let secret = ed.secret();
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(PQ_ANNOUNCE_LABEL), secret.as_ref());
    let mut seed = [0u8; tenzro_crypto::pq::ML_DSA_65_SEED_LEN];
    hk.expand(b"ml-dsa-65", &mut seed).map_err(|e| {
        NetworkError::NoHardwareRoot(format!("PQ announcement key expansion failed: {e}"))
    })?;

    MlDsaSigningKey::from_seed(&seed).map_err(|e| {
        NetworkError::NoHardwareRoot(format!("PQ announcement key construction failed: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key must be a pure function of the identity, or it cannot be pinned
    /// — which is the only reason it is worth carrying at all.
    #[test]
    fn the_pq_key_is_stable_for_one_identity() {
        let node = libp2p::identity::Keypair::generate_ed25519();
        let a = pq_identity_key(&node).unwrap();
        let b = pq_identity_key(&node).unwrap();
        assert_eq!(a.verifying_key_bytes(), b.verifying_key_bytes());
    }

    /// Two nodes must not share an announcement key, or one could sign for the
    /// other the moment anything starts trusting these.
    #[test]
    fn distinct_identities_get_distinct_pq_keys() {
        let a = pq_identity_key(&libp2p::identity::Keypair::generate_ed25519()).unwrap();
        let b = pq_identity_key(&libp2p::identity::Keypair::generate_ed25519()).unwrap();
        assert_ne!(a.verifying_key_bytes(), b.verifying_key_bytes());
    }

    /// The PQ key is derived through a labelled HKDF rather than reusing the
    /// identity seed, so possession of one does not hand over the other.
    #[test]
    fn the_pq_seed_is_not_the_identity_seed() {
        let node = libp2p::identity::Keypair::generate_ed25519();
        let ed = node.clone().try_into_ed25519().unwrap();
        let identity_seed = ed.secret();

        let derived = pq_identity_key(&node).unwrap();
        assert_ne!(
            derived.seed_bytes(),
            identity_seed.as_ref(),
            "PQ key must not reuse the identity seed verbatim"
        );
    }

    /// A well-formed key of the size FIPS 204 specifies for ML-DSA-65.
    #[test]
    fn the_derived_key_is_ml_dsa_65() {
        let node = libp2p::identity::Keypair::generate_ed25519();
        let k = pq_identity_key(&node).unwrap();
        assert_eq!(
            k.verifying_key_bytes().len(),
            tenzro_crypto::pq::ML_DSA_65_VK_LEN
        );
    }
}
