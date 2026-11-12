//! The delivery envelope and the attestation its committees sign.
//!
//! A delivery is, in this exact layout and nothing more:
//!
//! ```text
//! dest_chain_id  u64 big-endian      this chain's id
//! nonce          u64 big-endian      equal to the message's sequence number
//! expiry_ms      u64 big-endian      unix ms after which it is refused
//! body           u32 length + bytes  the chain family's message
//! proof          u32 length + bytes  light-client proof, empty if none
//! committee      u8 count + (address 20 || signature 65) * count
//! committee_pq   u8 count + (address 20 || ML-DSA-65 signature 3309) * count
//! blessing       u8 count + (address 20 || signature 65) * count
//! blessing_pq    u8 count + (address 20 || ML-DSA-65 signature 3309) * count
//! ```
//!
//! Both committees sign [`attestation_digest`] with both of their keys, the
//! secp256k1 key and the ML-DSA-65 key of each member (see
//! [`verify_committee`]: a member counts only with both signatures, so a
//! forger of secp256k1 signatures alone moves nothing). The digest binds a domain tag,
//! this chain, the route (its key, chain identifiers, peer, ramp and
//! endpoints), the nonce, the expiry and the hashes of the body and proof.
//! A signature therefore verifies for one delivery on one route of one chain,
//! and nothing else.

use sha3::{Digest, Keccak256};

use super::canonical::{Reader, Writer};
use super::{BridgeRoute, VerifierQuorum};
use crate::error::{BridgeError, Result};
use crate::secp256k1_multisig::ValidatorSet;
use tenzro_crypto::pq::{ML_DSA_65_SIG_LEN, ml_dsa_verify};

/// FIPS 204 context under which a committee member's ML-DSA-65 key signs
/// [`attestation_digest`] and [`outbound_digest`]-style route digests.
pub const ROUTE_ATTESTATION_PQ_CONTEXT: &[u8] = b"tenzro/bridge/route-attestation/ml-dsa-65";

/// Domain tag of [`attestation_digest`].
pub const ROUTE_ATTESTATION_DOMAIN: &[u8] = b"tenzro/bridge/route-attestation";

/// Largest message body a delivery may carry.
pub const MAX_BODY_LEN: usize = 64 * 1024;

/// Largest light-client proof a delivery may carry.
pub const MAX_PROOF_LEN: usize = 2 * 1024 * 1024;

/// One committee signature: the member's address and its 65-byte signature.
pub type MemberSignature = ([u8; 20], [u8; 65]);

/// One committee member's ML-DSA-65 signature: the member's address (the
/// same address its secp256k1 leg carries) and the 3309-byte signature.
pub type PqMemberSignature = ([u8; 20], Vec<u8>);

/// A decoded delivery. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The chain the delivery is for.
    pub dest_chain_id: u64,
    /// Replay nonce.
    pub nonce: u64,
    /// Unix ms after which the attestation is refused.
    pub expiry_ms: i64,
    /// The chain family's message.
    pub body: Vec<u8>,
    /// Light-client proof, empty if none.
    pub proof: Vec<u8>,
    /// Verifier committee secp256k1 signatures.
    pub committee: Vec<MemberSignature>,
    /// Verifier committee ML-DSA-65 signatures.
    pub committee_pq: Vec<PqMemberSignature>,
    /// Blessing committee secp256k1 signatures.
    pub blessing: Vec<MemberSignature>,
    /// Blessing committee ML-DSA-65 signatures.
    pub blessing_pq: Vec<PqMemberSignature>,
}

fn signatures(r: &mut Reader<'_>) -> Result<Vec<MemberSignature>> {
    let count = r.u8()? as usize;
    (0..count)
        .map(|_| Ok((r.array::<20>()?, r.array::<65>()?)))
        .collect()
}

fn pq_signatures(r: &mut Reader<'_>) -> Result<Vec<PqMemberSignature>> {
    let count = r.u8()? as usize;
    (0..count)
        .map(|_| Ok((r.array::<20>()?, r.take(ML_DSA_65_SIG_LEN)?.to_vec())))
        .collect()
}

impl Delivery {
    /// Encode a delivery in the one layout [`Delivery::decode`] accepts.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_be(self.dest_chain_id)
            .u64_be(self.nonce)
            .u64_be(self.expiry_ms as u64)
            .be_bytes(&self.body)
            .be_bytes(&self.proof);
        for (set, pq) in [
            (&self.committee, &self.committee_pq),
            (&self.blessing, &self.blessing_pq),
        ] {
            w.u8(set.len() as u8);
            for (a, s) in set {
                w.raw(a).raw(s);
            }
            w.u8(pq.len() as u8);
            for (a, s) in pq {
                w.raw(a).raw(s);
            }
        }
        w.into_bytes()
    }

    /// Decode a delivery, refusing anything but the exact layout.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let dest_chain_id = r.u64_be()?;
        let nonce = r.u64_be()?;
        let expiry_ms = i64::try_from(r.u64_be()?)
            .map_err(|_| BridgeError::InvalidParameter("expiry out of range".into()))?;
        let body = r.be_bytes(MAX_BODY_LEN)?.to_vec();
        let proof = r.be_bytes(MAX_PROOF_LEN)?.to_vec();
        let committee = signatures(&mut r)?;
        let committee_pq = pq_signatures(&mut r)?;
        let blessing = signatures(&mut r)?;
        let blessing_pq = pq_signatures(&mut r)?;
        r.finish()?;
        Ok(Self {
            dest_chain_id,
            nonce,
            expiry_ms,
            body,
            proof,
            committee,
            committee_pq,
            blessing,
            blessing_pq,
        })
    }
}

/// Keccak-256 of a message body.
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    Keccak256::digest(body).into()
}

/// The digest both committees sign for `delivery` on `route`.
pub fn attestation_digest(route: &BridgeRoute, delivery: &Delivery) -> [u8; 32] {
    let key = route.storage_key();
    let mut h = Keccak256::new();
    h.update(ROUTE_ATTESTATION_DOMAIN);
    h.update((key.len() as u64).to_be_bytes());
    h.update(key.as_bytes());
    h.update(delivery.dest_chain_id.to_be_bytes());
    h.update(route.source_chain_id.to_be_bytes());
    h.update(route.local_selector.to_be_bytes());
    h.update(route.peer);
    h.update(route.ramp);
    h.update(route.local_endpoint);
    h.update(delivery.nonce.to_be_bytes());
    h.update(delivery.expiry_ms.to_be_bytes());
    h.update(body_hash(&delivery.body));
    h.update(body_hash(&delivery.proof));
    h.finalize().into()
}

/// Domain tag of the digest a route's committee signs to authorise an
/// outbound record on a chain reached through Tenzro's bridge contract.
pub const ROUTE_OUTBOUND_DOMAIN: &[u8] = b"tenzro/bridge/route-outbound";

/// The digest the route's committee signs so the bridge contract on the
/// external chain executes outbound `record` (the bytes Tenzro stored for
/// it) from Tenzro chain `chain_id`: Keccak-256 of the domain, the chain id,
/// the length-prefixed route key and the record. The contract recomputes it
/// and recovers each signer.
pub fn outbound_digest(chain_id: u64, route: &BridgeRoute, record: &[u8]) -> [u8; 32] {
    let key = route.storage_key();
    let mut h = Keccak256::new();
    h.update(ROUTE_OUTBOUND_DOMAIN);
    h.update(chain_id.to_be_bytes());
    h.update((key.len() as u64).to_be_bytes());
    h.update(key.as_bytes());
    h.update(record);
    h.finalize().into()
}

/// Domain tag of the digest a route's outgoing committee signs to hand the
/// bridge contract on the external chain over to the committee drawn next.
pub const ROUTE_COMMITTEE_DOMAIN: &[u8] = b"tenzro/bridge/route-committee";

/// The digest a route's committee signs so the bridge contract on the
/// external chain trusts committee `set_index` instead: Keccak-256 of the
/// domain, Tenzro's chain id, the length-prefixed route key, the set index,
/// the member count, each member's 20-byte address, the threshold and the
/// second (Unix time) after which the contract stops trusting that
/// committee. Integers are big-endian; the chain id is 8 bytes, the expiry
/// 8, the rest 4.
pub fn committee_handover_digest(
    chain_id: u64,
    route: &BridgeRoute,
    set_index: u32,
    members: &[[u8; 20]],
    threshold: u32,
    expires_at_secs: u64,
) -> [u8; 32] {
    let key = route.storage_key();
    let mut h = Keccak256::new();
    h.update(ROUTE_COMMITTEE_DOMAIN);
    h.update(chain_id.to_be_bytes());
    h.update((key.len() as u64).to_be_bytes());
    h.update(key.as_bytes());
    h.update(set_index.to_be_bytes());
    h.update((members.len() as u32).to_be_bytes());
    for m in members {
        h.update(m);
    }
    h.update(threshold.to_be_bytes());
    h.update(expires_at_secs.to_be_bytes());
    h.finalize().into()
}

/// The members of `quorum` with a valid signature on both legs over
/// `digest`, each once, in the order their secp256k1 signatures are given.
pub fn dual_signers(
    quorum: &VerifierQuorum,
    digest: &[u8; 32],
    sigs: &[MemberSignature],
    pq_sigs: &[PqMemberSignature],
) -> Vec<[u8; 20]> {
    let set = ValidatorSet::new(quorum.addresses(), 0, "dual signers");
    set.valid_signers(digest, sigs)
        .into_iter()
        .filter(|address| {
            let Some(member) = quorum.members.iter().find(|m| m.address == *address) else {
                return false;
            };
            pq_sigs.iter().any(|(a, pq)| {
                a == address
                    && ml_dsa_verify(
                        &member.pq_public_key,
                        ROUTE_ATTESTATION_PQ_CONTEXT,
                        digest,
                        pq,
                    )
                    .is_ok()
            })
        })
        .collect()
}

/// Require `threshold` distinct members of `quorum` to have signed `digest`
/// with both of their keys: a valid secp256k1 signature that recovers to the
/// member's address, and a valid ML-DSA-65 signature under the member's
/// registered verifying key, under [`ROUTE_ATTESTATION_PQ_CONTEXT`]. A member
/// with only one leg does not count, so signatures forged on the classical
/// leg alone cannot reach the threshold.
pub fn verify_committee(
    quorum: &VerifierQuorum,
    label: &'static str,
    digest: &[u8; 32],
    sigs: &[MemberSignature],
    pq_sigs: &[PqMemberSignature],
) -> Result<()> {
    let threshold = u8::try_from(quorum.threshold).map_err(|_| {
        BridgeError::AdapterError(format!(
            "{label}: threshold {} out of range",
            quorum.threshold
        ))
    })?;
    ValidatorSet::new(quorum.addresses(), threshold, label).verify_quorum(digest, sigs)?;
    let both = dual_signers(quorum, digest, sigs, pq_sigs).len();
    if both < threshold as usize {
        return Err(BridgeError::AdapterError(format!(
            "{label}: only {both} members signed with both secp256k1 and ML-DSA-65 < threshold {threshold}"
        )));
    }
    Ok(())
}

/// Deterministic member keys and signing for tests in this and other crates.
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use sha2::{Digest, Sha256};
    use tenzro_crypto::pq::MlDsaSigningKey;

    use super::{PqMemberSignature, ROUTE_ATTESTATION_PQ_CONTEXT};

    /// The ML-DSA-65 key paired with the member whose secp256k1 secret is
    /// `secret`.
    pub fn pq_key(secret: &[u8]) -> MlDsaSigningKey {
        let seed: [u8; 32] = Sha256::new()
            .chain_update(b"tenzro/test/bridge-member-pq")
            .chain_update(secret)
            .finalize()
            .into();
        MlDsaSigningKey::from_seed(&seed).expect("32-byte seed")
    }

    /// The ML-DSA-65 signature of the member with secp256k1 secret `secret`
    /// and address `address` over `digest`.
    pub fn sign_leg(secret: &[u8], address: [u8; 20], digest: &[u8; 32]) -> PqMemberSignature {
        sign_pq(&pq_key(secret), address, digest)
    }

    /// `key`'s ML-DSA-65 signature over `digest` for the member `address`.
    pub fn sign_pq(
        key: &MlDsaSigningKey,
        address: [u8; 20],
        digest: &[u8; 32],
    ) -> PqMemberSignature {
        (address, key.sign(ROUTE_ATTESTATION_PQ_CONTEXT, digest))
    }
}
