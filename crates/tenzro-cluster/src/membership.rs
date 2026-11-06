//! Verified cluster membership.
//!
//! A cluster's members are the machines its operator lists and each of those
//! machines accepts (see [`tenzro_types::cluster_membership`]). This module
//! turns a [`SignedClusterMembership`] into a [`VerifiedMembership`], the only
//! form the planners accept, and keeps the latest verified list per cluster in
//! a [`MembershipBook`]:
//!
//! - the cluster DID must be the one the operator DID and name derive;
//! - the operator's passkey (the key the operator's human DID derives from)
//!   must have approved exactly this list through the custody challenge;
//! - every listed machine must have accepted with the hardware key its own
//!   DID derives from, and nobody outside the list may carry an acceptance;
//! - a list whose sequence number is not above the one already held is stale.
//!
//! Local-network placement and split-inference member selection read this
//! book; a machine the operator removed (a new list without it) stops being
//! a member the moment the new list is accepted.

use std::collections::{BTreeMap, BTreeSet};

use tenzro_types::cluster_membership::{
    SignedClusterMembership, acceptance_digest, lan_binding_digest,
};
use tenzro_types::did_derivation::{CLUSTER_DID_PREFIX, cluster_did, did_derives_from_key};

use crate::reachability::MemberReachability;
use crate::tiered::TieredCandidate;

const HUMAN_DID_PREFIX: &str = "did:tenzro:human:";
const MACHINE_DID_PREFIX: &str = "did:tenzro:machine:";

/// Computes the custody challenge an operator's passkey answers for a list:
/// from the operator DID, the list's membership digest and the challenge
/// nonce. The node supplies its custody-challenge digest here, so a list is
/// approved through the same challenge every other owner action uses, bound
/// to the node's network.
pub type CustodyDigest = fn(&str, &[u8; 32], &[u8; 16]) -> [u8; 32];

/// Why a membership list was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    /// The cluster DID is not the one the operator DID and name derive.
    #[error("cluster DID {0} does not derive from the operator DID and name")]
    WrongClusterDid(String),
    /// The operator is not a human DID rooted in the presented passkey.
    #[error("operator {0} is not the human DID the presented passkey derives")]
    OperatorKey(String),
    /// The operator's passkey did not approve this list.
    #[error("operator approval refused: {0}")]
    OperatorNotApproved(String),
    /// The member list is empty, unsorted, repeats a member, or names
    /// something that is not a machine DID.
    #[error(
        "member list must be non-empty, sorted, without duplicates, and name only machine DIDs"
    )]
    MembersNotCanonical,
    /// A listed machine has no acceptance of its own.
    #[error("member {0} has not accepted its inclusion")]
    MemberNotAccepted(String),
    /// An acceptance was made by a key the member's DID does not derive from.
    #[error("acceptance for {0} is not made by the key that member's DID derives from")]
    AcceptanceKey(String),
    /// An acceptance signature does not verify.
    #[error("acceptance signature for {0} does not verify")]
    AcceptanceSignature(String),
    /// An acceptance names a machine the operator did not list.
    #[error("acceptance for {0}, which the list does not name")]
    AcceptanceForNonMember(String),
    /// The list's sequence number is not above the one already held.
    #[error("stale membership for {cluster_did}: held seq {held}, offered seq {offered}")]
    Stale {
        /// The cluster.
        cluster_did: String,
        /// Sequence number already held.
        held: u64,
        /// Sequence number offered.
        offered: u64,
    },
}

/// A membership list whose every signature has been checked.
///
/// The only constructor is [`VerifiedMembership::verify`], so holding one is
/// proof the checks ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMembership {
    record: SignedClusterMembership,
    member_keys: BTreeMap<String, Vec<u8>>,
}

impl VerifiedMembership {
    /// Check every signature on `record`. `rp_id` is the WebAuthn relying
    /// party the operator's passkey is registered under.
    pub fn verify(
        record: SignedClusterMembership,
        rp_id: &str,
        custody_digest: impl Fn(&str, &[u8; 32], &[u8; 16]) -> [u8; 32],
    ) -> Result<Self, MembershipError> {
        use tenzro_device_key::signer::{
            PasskeyAuthorization, PasskeyController, verify_authorization, verify_p256_prehash,
        };

        if !record.cluster_did.starts_with(CLUSTER_DID_PREFIX)
            || record.cluster_did != cluster_did(&record.operator_did, &record.name)
        {
            return Err(MembershipError::WrongClusterDid(record.cluster_did.clone()));
        }
        let approval = &record.operator_approval;
        if !record.operator_did.starts_with(HUMAN_DID_PREFIX)
            || !did_derives_from_key(&record.operator_did, &approval.passkey_public_key)
        {
            return Err(MembershipError::OperatorKey(record.operator_did.clone()));
        }
        let canonical = !record.members.is_empty()
            && record.members.windows(2).all(|w| w[0] < w[1])
            && record
                .members
                .iter()
                .all(|m| m.starts_with(MACHINE_DID_PREFIX));
        if !canonical {
            return Err(MembershipError::MembersNotCanonical);
        }
        let nonce: [u8; 16] =
            approval.nonce.as_slice().try_into().map_err(|_| {
                MembershipError::OperatorNotApproved("nonce is not 16 bytes".into())
            })?;
        let challenge = custody_digest(&record.operator_did, &record.membership_digest(), &nonce);
        verify_authorization(
            &PasskeyController {
                public_key_sec1: approval.passkey_public_key.clone(),
                rp_id: rp_id.to_string(),
            },
            &challenge,
            &PasskeyAuthorization {
                authenticator_data: approval.authenticator_data.clone(),
                client_data_json: approval.client_data_json.clone(),
                signature: approval.signature.clone(),
            },
        )
        .map_err(|e| MembershipError::OperatorNotApproved(e.to_string()))?;

        let mut member_keys = BTreeMap::new();
        for acceptance in &record.acceptances {
            if record
                .members
                .binary_search(&acceptance.member_did)
                .is_err()
            {
                return Err(MembershipError::AcceptanceForNonMember(
                    acceptance.member_did.clone(),
                ));
            }
            if !did_derives_from_key(&acceptance.member_did, &acceptance.public_key) {
                return Err(MembershipError::AcceptanceKey(
                    acceptance.member_did.clone(),
                ));
            }
            let digest = acceptance_digest(&record.cluster_did, &acceptance.member_did, record.seq);
            if !verify_p256_prehash(&acceptance.public_key, &digest, &acceptance.signature) {
                return Err(MembershipError::AcceptanceSignature(
                    acceptance.member_did.clone(),
                ));
            }
            member_keys.insert(acceptance.member_did.clone(), acceptance.public_key.clone());
        }
        if let Some(missing) = record
            .members
            .iter()
            .find(|m| !member_keys.contains_key(*m))
        {
            return Err(MembershipError::MemberNotAccepted(missing.clone()));
        }
        Ok(Self {
            record,
            member_keys,
        })
    }

    /// The cluster DID.
    pub fn cluster_did(&self) -> &str {
        &self.record.cluster_did
    }

    /// The operator DID.
    pub fn operator_did(&self) -> &str {
        &self.record.operator_did
    }

    /// The sequence number of this list.
    pub fn seq(&self) -> u64 {
        self.record.seq
    }

    /// Member machine DIDs, sorted.
    pub fn members(&self) -> &[String] {
        &self.record.members
    }

    /// Whether `machine_did` is a member.
    pub fn contains(&self, machine_did: &str) -> bool {
        self.member_keys.contains_key(machine_did)
    }

    /// The signed list, for storage and gossip.
    pub fn record(&self) -> &SignedClusterMembership {
        &self.record
    }

    /// The member whose DID ends in `member_id`, if its hardware key signed
    /// `signature` over its claim to `endpoint_id`.
    pub fn verify_lan_binding(
        &self,
        member_id: &str,
        endpoint_id: &[u8],
        signature: &[u8],
    ) -> Option<&str> {
        let (did, key) = self
            .member_keys
            .iter()
            .find(|(did, _)| did.rsplit(':').next() == Some(member_id))?;
        let digest = lan_binding_digest(did, endpoint_id);
        tenzro_device_key::signer::verify_p256_prehash(key, &digest, signature)
            .then_some(did.as_str())
    }

    /// A placement candidate for `machine_did` at `endpoint_id`. Only a member
    /// of this cluster that was found on the local network is placed in the
    /// local tier; anyone else keeps its announced tier, never the local one.
    pub fn candidate(
        &self,
        machine_did: Option<&str>,
        endpoint_id: impl Into<String>,
        found_on_lan: bool,
        announced: MemberReachability,
    ) -> TieredCandidate {
        let member = machine_did.is_some_and(|d| self.contains(d));
        let reachability = match (member && found_on_lan, announced) {
            (true, _) => MemberReachability::LocalDirect,
            (false, MemberReachability::LocalDirect) => MemberReachability::Direct,
            (false, tier) => tier,
        };
        TieredCandidate {
            endpoint_id: endpoint_id.into(),
            reachability,
        }
    }
}

/// The latest verified membership list of every cluster this node knows.
#[derive(Debug, Default)]
pub struct MembershipBook {
    clusters: BTreeMap<String, VerifiedMembership>,
}

impl MembershipBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `membership` if its sequence number is above the one held for its
    /// cluster. Returns `Ok(false)` for the list already held, and
    /// [`MembershipError::Stale`] for an older one or a different list at the
    /// same sequence number.
    pub fn offer(&mut self, membership: VerifiedMembership) -> Result<bool, MembershipError> {
        if let Some(held) = self.clusters.get(membership.cluster_did()) {
            if held == &membership {
                return Ok(false);
            }
            if membership.seq() <= held.seq() {
                return Err(MembershipError::Stale {
                    cluster_did: membership.cluster_did().to_string(),
                    held: held.seq(),
                    offered: membership.seq(),
                });
            }
        }
        self.clusters
            .insert(membership.cluster_did().to_string(), membership);
        Ok(true)
    }

    /// The verified list of `cluster_did`.
    pub fn get(&self, cluster_did: &str) -> Option<&VerifiedMembership> {
        self.clusters.get(cluster_did)
    }

    /// Every cluster `machine_did` is a member of.
    pub fn clusters_of<'a>(
        &'a self,
        machine_did: &'a str,
    ) -> impl Iterator<Item = &'a VerifiedMembership> + 'a {
        self.clusters
            .values()
            .filter(move |m| m.contains(machine_did))
    }

    /// The machines a serving entry stands for: a machine DID stands for
    /// itself, a cluster DID for its verified members. `None` for a cluster
    /// with no verified list, or anything that is not a machine or cluster
    /// DID.
    pub fn resolve_serving_entry(&self, entry: &str) -> Option<Vec<String>> {
        if entry.starts_with(MACHINE_DID_PREFIX) {
            return Some(vec![entry.to_string()]);
        }
        if entry.starts_with(CLUSTER_DID_PREFIX) {
            return self.get(entry).map(|m| m.members().to_vec());
        }
        None
    }

    /// The co-member of `self_did` that a local-network sighting names, if
    /// the sighting's binding signature checks against a cluster both
    /// machines belong to.
    pub fn verify_lan_peer(
        &self,
        self_did: &str,
        member_id: &str,
        endpoint_id: &[u8],
        signature: &[u8],
    ) -> Option<String> {
        self.clusters_of(self_did)
            .find_map(|m| m.verify_lan_binding(member_id, endpoint_id, signature))
            .map(str::to_string)
    }

    /// Every co-member of `self_did` across its clusters, excluding itself.
    pub fn co_members(&self, self_did: &str) -> BTreeSet<String> {
        self.clusters_of(self_did)
            .flat_map(|m| m.members().iter().cloned())
            .filter(|m| m != self_did)
            .collect()
    }
}

/// Builders for fully signed membership lists, for tests in this and other
/// crates. Keys are software keys; nothing here is reachable in a release
/// build.
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use base64::Engine;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};
    use tenzro_types::cluster_membership::{
        MemberAcceptance, OperatorApproval, SignedClusterMembership, acceptance_digest,
        lan_binding_digest,
    };
    use tenzro_types::did_derivation::{cluster_did, human_id, machine_device_id};

    /// The relying party test approvals are made under.
    pub const RP_ID: &str = "tenzro.test";

    /// A custody digest for tests: SHA-256 over its inputs.
    pub fn custody_digest(operator: &str, membership: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(operator.as_bytes());
        h.update(membership);
        h.update(nonce);
        h.finalize().into()
    }

    /// A software P-256 key standing in for a passkey or a machine's hardware
    /// key.
    pub struct Key(SigningKey);

    impl Key {
        /// The key derived from `seed`.
        pub fn new(seed: u8) -> Self {
            Self(SigningKey::from_slice(&[seed; 32]).unwrap())
        }
        /// Uncompressed SEC1 public key.
        pub fn public(&self) -> Vec<u8> {
            self.0
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec()
        }
        /// The human DID this key roots, as a passkey.
        pub fn human_did(&self) -> String {
            format!("did:tenzro:human:{}", human_id(&self.public()))
        }
        /// The machine DID this key roots, as a hardware key.
        pub fn machine_did(&self) -> String {
            format!("did:tenzro:machine:{}", machine_device_id(&self.public()))
        }
        /// Raw `r || s` over a digest.
        pub fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
            sig.to_bytes().to_vec()
        }
        /// This machine's acceptance of list `seq` of `cluster`.
        pub fn accept(&self, cluster: &str, seq: u64) -> MemberAcceptance {
            let did = self.machine_did();
            MemberAcceptance {
                signature: self.sign(&acceptance_digest(cluster, &did, seq)),
                member_did: did,
                public_key: self.public(),
            }
        }
        /// This machine's claim to `endpoint_id` on the local network.
        pub fn bind_lan(&self, endpoint_id: &[u8]) -> Vec<u8> {
            self.sign(&lan_binding_digest(&self.machine_did(), endpoint_id))
        }
    }

    /// A WebAuthn assertion by `passkey` over `challenge` under [`RP_ID`].
    pub fn approve(passkey: &Key, challenge: &[u8; 32], nonce: [u8; 16]) -> OperatorApproval {
        let mut authenticator_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());
        let client_data_json = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "origin": format!("https://{RP_ID}"),
        }))
        .unwrap();
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let digest: [u8; 32] = Sha256::digest(&signed).into();
        OperatorApproval {
            passkey_public_key: passkey.public(),
            nonce: nonce.to_vec(),
            authenticator_data,
            client_data_json,
            signature: passkey.sign(&digest),
        }
    }

    /// List `seq` of cluster `name`, approved by `operator` and accepted by
    /// every machine in `members`.
    pub fn membership(
        operator: &Key,
        name: &str,
        seq: u64,
        members: &[&Key],
    ) -> SignedClusterMembership {
        let operator_did = operator.human_did();
        let cluster = cluster_did(&operator_did, name);
        let mut dids: Vec<String> = members.iter().map(|k| k.machine_did()).collect();
        dids.sort();
        let mut record = SignedClusterMembership {
            cluster_did: cluster.clone(),
            operator_did: operator_did.clone(),
            name: name.to_string(),
            seq,
            members: dids,
            operator_approval: approve(operator, &[0; 32], [0; 16]),
            acceptances: members.iter().map(|k| k.accept(&cluster, seq)).collect(),
        };
        let nonce = [seq as u8; 16];
        let challenge = custody_digest(&operator_did, &record.membership_digest(), &nonce);
        record.operator_approval = approve(operator, &challenge, nonce);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn verify(record: SignedClusterMembership) -> Result<VerifiedMembership, MembershipError> {
        VerifiedMembership::verify(record, RP_ID, custody_digest)
    }

    #[test]
    fn a_list_the_operator_approved_and_every_member_accepted_verifies() {
        let (op, a, b) = (Key::new(1), Key::new(2), Key::new(3));
        let m = verify(membership(&op, "lab", 1, &[&a, &b])).unwrap();
        assert!(m.contains(&a.machine_did()));
        assert!(m.contains(&b.machine_did()));
        assert!(!m.contains(&Key::new(4).machine_did()));
    }

    #[test]
    fn a_list_not_signed_by_the_operator_is_refused() {
        let (op, other, a) = (Key::new(1), Key::new(9), Key::new(2));
        let mut record = membership(&op, "lab", 1, &[&a]);
        // Someone else's passkey approves the same digest.
        let challenge = custody_digest(&record.operator_did, &record.membership_digest(), &[1; 16]);
        record.operator_approval = approve(&other, &challenge, [1; 16]);
        assert!(matches!(
            verify(record.clone()),
            Err(MembershipError::OperatorKey(_))
        ));
        // The operator's key, but the approval covers a different list.
        let mut tampered = membership(&op, "lab", 1, &[&a]);
        tampered.members.push(Key::new(8).machine_did());
        tampered.members.sort();
        tampered
            .acceptances
            .push(Key::new(8).accept(&tampered.cluster_did, 1));
        assert!(matches!(
            verify(tampered),
            Err(MembershipError::OperatorNotApproved(_))
        ));
    }

    #[test]
    fn a_member_without_its_own_proof_is_refused() {
        let (op, a, b) = (Key::new(1), Key::new(2), Key::new(3));
        let mut record = membership(&op, "lab", 1, &[&a, &b]);
        let b_did = b.machine_did();
        record.acceptances.retain(|x| x.member_did != b_did);
        assert_eq!(
            verify(record),
            Err(MembershipError::MemberNotAccepted(b_did.clone()))
        );

        // An acceptance signed by some other key for b's DID.
        let mut forged = membership(&op, "lab", 1, &[&a, &b]);
        for x in forged
            .acceptances
            .iter_mut()
            .filter(|x| x.member_did == b_did)
        {
            let other = Key::new(7);
            x.public_key = other.public();
            x.signature = other.sign(&acceptance_digest(&forged.cluster_did, &b_did, 1));
        }
        assert_eq!(
            verify(forged),
            Err(MembershipError::AcceptanceKey(b_did.clone()))
        );

        // b's own key, but over a different sequence number.
        let mut replayed = membership(&op, "lab", 2, &[&a, &b]);
        for x in replayed
            .acceptances
            .iter_mut()
            .filter(|x| x.member_did == b_did)
        {
            *x = b.accept(&replayed.cluster_did, 1);
        }
        assert_eq!(
            verify(replayed),
            Err(MembershipError::AcceptanceSignature(b_did))
        );
    }

    #[test]
    fn a_cluster_did_that_does_not_derive_from_the_operator_is_refused() {
        let (op, a) = (Key::new(1), Key::new(2));
        let mut record = membership(&op, "lab", 1, &[&a]);
        record.cluster_did = cluster_did(&Key::new(5).human_did(), "lab");
        assert!(matches!(
            verify(record),
            Err(MembershipError::WrongClusterDid(_))
        ));
    }

    #[test]
    fn a_stale_sequence_is_refused() {
        let (op, a, b) = (Key::new(1), Key::new(2), Key::new(3));
        let mut book = MembershipBook::new();
        assert!(
            book.offer(verify(membership(&op, "lab", 2, &[&a, &b])).unwrap())
                .unwrap()
        );
        let older = verify(membership(&op, "lab", 1, &[&a])).unwrap();
        assert!(matches!(
            book.offer(older),
            Err(MembershipError::Stale {
                held: 2,
                offered: 1,
                ..
            })
        ));
        let same_seq = verify(membership(&op, "lab", 2, &[&a])).unwrap();
        assert!(matches!(
            book.offer(same_seq),
            Err(MembershipError::Stale { .. })
        ));
        let again = verify(membership(&op, "lab", 2, &[&a, &b])).unwrap();
        assert_eq!(book.offer(again), Ok(false));
    }

    #[test]
    fn removal_by_the_operator_takes_effect() {
        let (op, a, b) = (Key::new(1), Key::new(2), Key::new(3));
        let mut book = MembershipBook::new();
        let first = verify(membership(&op, "lab", 1, &[&a, &b])).unwrap();
        let cluster = first.cluster_did().to_string();
        book.offer(first).unwrap();
        assert!(book.get(&cluster).unwrap().contains(&b.machine_did()));
        book.offer(verify(membership(&op, "lab", 2, &[&a])).unwrap())
            .unwrap();
        assert!(!book.get(&cluster).unwrap().contains(&b.machine_did()));
        assert_eq!(book.co_members(&a.machine_did()).len(), 0);
        assert_eq!(book.clusters_of(&b.machine_did()).count(), 0);
    }

    #[test]
    fn a_cluster_did_resolves_as_a_serving_entry() {
        let (op, a, b) = (Key::new(1), Key::new(2), Key::new(3));
        let mut book = MembershipBook::new();
        let m = verify(membership(&op, "lab", 1, &[&a, &b])).unwrap();
        let cluster = m.cluster_did().to_string();
        let expected = m.members().to_vec();
        book.offer(m).unwrap();
        assert_eq!(book.resolve_serving_entry(&cluster), Some(expected));
        assert_eq!(
            book.resolve_serving_entry(&a.machine_did()),
            Some(vec![a.machine_did()])
        );
        assert_eq!(
            book.resolve_serving_entry(&cluster_did(&op.human_did(), "other")),
            None
        );
        assert_eq!(book.resolve_serving_entry(&op.human_did()), None);
    }

    #[test]
    fn only_a_member_found_on_the_lan_is_a_local_candidate() {
        let (op, a) = (Key::new(1), Key::new(2));
        let m = verify(membership(&op, "lab", 1, &[&a])).unwrap();
        let member = m.candidate(
            Some(&a.machine_did()),
            "a",
            true,
            MemberReachability::Direct,
        );
        assert_eq!(member.reachability, MemberReachability::LocalDirect);
        let stranger = m.candidate(
            Some(&Key::new(6).machine_did()),
            "s",
            true,
            MemberReachability::LocalDirect,
        );
        assert_eq!(stranger.reachability, MemberReachability::Direct);
        let far_member = m.candidate(
            Some(&a.machine_did()),
            "a",
            false,
            MemberReachability::Direct,
        );
        assert_eq!(far_member.reachability, MemberReachability::Direct);
    }

    #[test]
    fn a_lan_binding_checks_against_the_members_own_key() {
        let (op, a, b) = (Key::new(1), Key::new(2), Key::new(3));
        let mut book = MembershipBook::new();
        book.offer(verify(membership(&op, "lab", 1, &[&a, &b])).unwrap())
            .unwrap();
        let b_id = b.machine_did().rsplit(':').next().unwrap().to_string();
        let endpoint = [9u8; 32];
        let a_did = a.machine_did();
        assert_eq!(
            book.verify_lan_peer(&a_did, &b_id, &endpoint, &b.bind_lan(&endpoint)),
            Some(b.machine_did())
        );
        // A binding signed by a non-member's key under b's id.
        let forged = Key::new(7).bind_lan(&endpoint);
        assert_eq!(
            book.verify_lan_peer(&a_did, &b_id, &endpoint, &forged),
            None
        );
        // b's binding moved to a different endpoint.
        let real = b.bind_lan(&endpoint);
        assert_eq!(book.verify_lan_peer(&a_did, &b_id, &[8u8; 32], &real), None);
        // A machine outside every cluster b is in learns nothing.
        let outsider = Key::new(8).machine_did();
        assert_eq!(
            book.verify_lan_peer(&outsider, &b_id, &endpoint, &real),
            None
        );
    }
}
