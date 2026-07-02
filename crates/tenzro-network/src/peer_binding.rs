//! Signed PeerId ↔ validator-identity binding carried in the libp2p
//! Identify `agent_version` field.
//!
//! # Why this exists
//!
//! The libp2p PeerId is derived from a node's transport key
//! (`{data_dir}/p2p_key`), which is a *different* keypair from the
//! validator's consensus Ed25519 identity (the key registered in genesis /
//! the epoch validator set). Validator-only gossipsub topics (consensus,
//! attestations) are authorized by PeerId, so admission requires a
//! cryptographic proof that a given PeerId is operated by the holder of a
//! validator identity key.
//!
//! A validator produces that proof by signing the domain-separated payload
//!
//! ```text
//! "TENZRO_PEER_BINDING:" || peer_id.to_bytes()
//! ```
//!
//! with its validator Ed25519 key, and appending
//! `tenzro-peer-binding=<pubkey_hex>:<sig_hex>` to its Identify
//! `agent_version`. The receiver verifies the signature over the
//! *transport-authenticated* PeerId (libp2p Noise/TLS proves the remote
//! possesses the p2p key behind that PeerId), then checks the signing
//! pubkey against the current validator set before granting validator-topic
//! publish rights.
//!
//! No nonce or freshness is needed: the binding is a long-lived true
//! statement ("this validator key operates this PeerId"), and replaying it
//! from a different transport identity is useless because the observed
//! PeerId — authenticated by the transport handshake — would not match the
//! signed one.

use libp2p::PeerId;
use tenzro_crypto::{signatures, KeyType, PublicKey, Signature};

/// Domain-separation prefix for the binding signature payload.
pub const PEER_BINDING_DOMAIN: &[u8] = b"TENZRO_PEER_BINDING:";

/// Token prefix inside `agent_version` that carries the binding.
pub const AGENT_BINDING_PREFIX: &str = "tenzro-peer-binding=";

/// Ed25519 public key length in bytes.
const ED25519_PUBKEY_LEN: usize = 32;

/// Ed25519 signature length in bytes.
const ED25519_SIG_LEN: usize = 64;

/// Builds the canonical byte payload a validator signs to bind its
/// validator identity to a libp2p PeerId.
pub fn binding_payload(peer_id: &PeerId) -> Vec<u8> {
    let peer_bytes = peer_id.to_bytes();
    let mut payload = Vec::with_capacity(PEER_BINDING_DOMAIN.len() + peer_bytes.len());
    payload.extend_from_slice(PEER_BINDING_DOMAIN);
    payload.extend_from_slice(&peer_bytes);
    payload
}

/// Appends a binding token to a base `user_agent`, producing the full
/// Identify `agent_version` string:
/// `"{user_agent} tenzro-peer-binding={pubkey_hex}:{sig_hex}"`.
pub fn encode_agent_binding(user_agent: &str, validator_pubkey: &[u8], signature: &[u8]) -> String {
    format!(
        "{} {}{}:{}",
        user_agent,
        AGENT_BINDING_PREFIX,
        hex::encode(validator_pubkey),
        hex::encode(signature)
    )
}

/// Extracts `(validator_pubkey, signature)` from an Identify
/// `agent_version` string, if it carries a well-formed binding token.
///
/// Returns `None` when no token is present or the token is malformed
/// (wrong hex, wrong lengths). Malformed tokens are treated identically to
/// absent tokens — the peer simply isn't admitted as a validator.
pub fn parse_agent_binding(agent_version: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let token = agent_version
        .split_whitespace()
        .find_map(|t| t.strip_prefix(AGENT_BINDING_PREFIX))?;
    let (pubkey_hex, sig_hex) = token.split_once(':')?;
    let pubkey = hex::decode(pubkey_hex).ok()?;
    let signature = hex::decode(sig_hex).ok()?;
    if pubkey.len() != ED25519_PUBKEY_LEN || signature.len() != ED25519_SIG_LEN {
        return None;
    }
    Some((pubkey, signature))
}

/// Verifies that `signature` is a valid Ed25519 signature by
/// `validator_pubkey` over the binding payload for `peer_id`.
pub fn verify_peer_binding(peer_id: &PeerId, validator_pubkey: &[u8], signature: &[u8]) -> bool {
    let payload = binding_payload(peer_id);
    let pk = PublicKey::new(KeyType::Ed25519, validator_pubkey.to_vec());
    let sig = Signature::new(KeyType::Ed25519, signature.to_vec());
    signatures::verify(&pk, &payload, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
    use tenzro_crypto::KeyPair;

    fn signed_binding(peer_id: &PeerId) -> (Vec<u8>, Vec<u8>) {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pubkey = keypair.public_key().to_bytes();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();
        let sig = signer.sign(&binding_payload(peer_id)).unwrap();
        (pubkey, sig.to_bytes())
    }

    #[test]
    fn test_roundtrip_encode_parse_verify() {
        let peer_id = PeerId::random();
        let (pubkey, sig) = signed_binding(&peer_id);

        let agent_version = encode_agent_binding("tenzro-network/0.1.0", &pubkey, &sig);
        let (parsed_pk, parsed_sig) = parse_agent_binding(&agent_version).unwrap();
        assert_eq!(parsed_pk, pubkey);
        assert_eq!(parsed_sig, sig);
        assert!(verify_peer_binding(&peer_id, &parsed_pk, &parsed_sig));
    }

    #[test]
    fn test_binding_rejects_wrong_peer_id() {
        let peer_id = PeerId::random();
        let (pubkey, sig) = signed_binding(&peer_id);

        // Replaying the binding from a different transport identity fails:
        // the signed PeerId doesn't match the observed one.
        let other_peer = PeerId::random();
        assert!(!verify_peer_binding(&other_peer, &pubkey, &sig));
    }

    #[test]
    fn test_binding_rejects_tampered_signature() {
        let peer_id = PeerId::random();
        let (pubkey, mut sig) = signed_binding(&peer_id);
        sig[0] ^= 0xff;
        assert!(!verify_peer_binding(&peer_id, &pubkey, &sig));
    }

    #[test]
    fn test_parse_rejects_malformed_tokens() {
        assert!(parse_agent_binding("tenzro-network/0.1.0").is_none());
        assert!(parse_agent_binding("tenzro-peer-binding=nothex:alsonothex").is_none());
        assert!(parse_agent_binding("tenzro-peer-binding=abcd").is_none());
        // Wrong lengths (valid hex, wrong sizes)
        assert!(parse_agent_binding("tenzro-peer-binding=abcd:abcd").is_none());
    }
}
