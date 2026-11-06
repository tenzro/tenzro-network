//! The signed membership list of a cluster of machines.
//!
//! A cluster is a group of machines one operator runs together. Its DID
//! derives from the operator's DID and the cluster name
//! ([`crate::did_derivation::cluster_did`]); its members are listed here.
//!
//! A list is valid only when two kinds of signature agree:
//!
//! - the operator approves the whole list (cluster DID, name, sequence number
//!   and every member DID) with the passkey the operator's DID derives from,
//!   answering a custody challenge over [`membership_digest`];
//! - every listed machine accepts its own inclusion with its own hardware key
//!   over [`acceptance_digest`], which names the cluster, the machine and the
//!   sequence number, so an acceptance of one list cannot be moved to another.
//!
//! A change of membership is a new list with a higher sequence number, signed
//! the same way. The cluster DID itself never signs: every action taken on
//! behalf of a cluster is signed by the individual machine that took it.
//!
//! Verification lives in `tenzro_cluster::membership`; this module is the wire
//! form and the digests both sides compute.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::payment_authorization::hex_bytes;

const MEMBERSHIP_DOMAIN: &[u8] = b"tenzro/cluster/membership";
const ACCEPTANCE_DOMAIN: &[u8] = b"tenzro/cluster/member-acceptance";
const LAN_BINDING_DOMAIN: &[u8] = b"tenzro/cluster/lan-endpoint";

/// One cluster's membership at one sequence number, with every signature that
/// makes it valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedClusterMembership {
    /// `did:tenzro:cluster:{id}`, derived from `operator_did` and `name`.
    pub cluster_did: String,
    /// The human DID of the operator who approves the list.
    pub operator_did: String,
    /// The cluster name the operator chose.
    pub name: String,
    /// Strictly increasing per cluster. A list with a sequence number at or
    /// below the one already held is refused.
    pub seq: u64,
    /// Member machine DIDs, sorted, without duplicates.
    pub members: Vec<String>,
    /// The operator's approval of exactly this list.
    pub operator_approval: OperatorApproval,
    /// One acceptance per member, made by that member's hardware key.
    pub acceptances: Vec<MemberAcceptance>,
}

impl SignedClusterMembership {
    /// The digest the operator approves: [`membership_digest`] over this
    /// list's fields.
    pub fn membership_digest(&self) -> [u8; 32] {
        membership_digest(
            &self.cluster_did,
            &self.operator_did,
            &self.name,
            self.seq,
            &self.members,
        )
    }
}

/// The operator's passkey assertion over the custody challenge for a list.
///
/// The challenge is the custody digest over the operator DID, the
/// membership operation, the list's [`membership_digest`] and `nonce`, so any
/// node holding the list can recompute it and check the assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorApproval {
    /// The passkey public key (uncompressed SEC1 P-256) the operator's DID
    /// derives from.
    #[serde(with = "hex_bytes")]
    pub passkey_public_key: Vec<u8>,
    /// The 16-byte nonce of the custody challenge the assertion answers.
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    /// WebAuthn `authenticatorData`.
    #[serde(with = "hex_bytes")]
    pub authenticator_data: Vec<u8>,
    /// WebAuthn `clientDataJSON`.
    #[serde(with = "hex_bytes")]
    pub client_data_json: Vec<u8>,
    /// ECDSA P-256 signature, raw `r || s` or DER.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// A member machine's acceptance of its inclusion in one list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberAcceptance {
    /// The accepting machine's DID.
    pub member_did: String,
    /// The machine's hardware public key (uncompressed SEC1 P-256), the key
    /// `member_did` derives from.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// ECDSA P-256 over [`acceptance_digest`], raw `r || s`.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for p in parts {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// The digest the operator approves for a list: the cluster, its operator and
/// name, the sequence number and every member, each length-prefixed.
pub fn membership_digest(
    cluster_did: &str,
    operator_did: &str,
    name: &str,
    seq: u64,
    members: &[String],
) -> [u8; 32] {
    let seq = seq.to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![
        cluster_did.as_bytes(),
        operator_did.as_bytes(),
        name.as_bytes(),
        &seq,
    ];
    parts.extend(members.iter().map(|m| m.as_bytes()));
    digest(MEMBERSHIP_DOMAIN, &parts)
}

/// The digest a member signs to accept its inclusion in list `seq` of
/// `cluster_did`.
pub fn acceptance_digest(cluster_did: &str, member_did: &str, seq: u64) -> [u8; 32] {
    digest(
        ACCEPTANCE_DOMAIN,
        &[
            cluster_did.as_bytes(),
            member_did.as_bytes(),
            &seq.to_be_bytes(),
        ],
    )
}

/// The digest a member signs to claim, on the local network, the iroh
/// endpoint its announcements and cluster sessions come from, so a machine
/// found by local discovery can be checked against the membership list
/// before anyone talks to it.
pub fn lan_binding_digest(member_did: &str, endpoint_id: &[u8]) -> [u8; 32] {
    digest(LAN_BINDING_DOMAIN, &[member_did.as_bytes(), endpoint_id])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_member_and_the_sequence_reach_the_membership_digest() {
        let members = vec![
            "did:tenzro:machine:a".to_string(),
            "did:tenzro:machine:b".to_string(),
        ];
        let base = membership_digest("c", "o", "n", 1, &members);
        assert_ne!(base, membership_digest("c", "o", "n", 2, &members));
        assert_ne!(base, membership_digest("c", "o", "n", 1, &members[..1]));
        assert_ne!(base, membership_digest("c", "o2", "n", 1, &members));
    }

    #[test]
    fn an_acceptance_is_bound_to_its_cluster_member_and_sequence() {
        let a = acceptance_digest("c", "m", 1);
        assert_ne!(a, acceptance_digest("c", "m", 2));
        assert_ne!(a, acceptance_digest("c2", "m", 1));
        assert_ne!(a, acceptance_digest("c", "m2", 1));
    }

    #[test]
    fn a_membership_round_trips_through_json() {
        let m = SignedClusterMembership {
            cluster_did: "did:tenzro:cluster:x".into(),
            operator_did: "did:tenzro:human:y".into(),
            name: "lab".into(),
            seq: 3,
            members: vec!["did:tenzro:machine:z".into()],
            operator_approval: OperatorApproval {
                passkey_public_key: vec![4; 65],
                nonce: vec![1; 16],
                authenticator_data: vec![2; 37],
                client_data_json: b"{}".to_vec(),
                signature: vec![3; 64],
            },
            acceptances: vec![MemberAcceptance {
                member_did: "did:tenzro:machine:z".into(),
                public_key: vec![4; 65],
                signature: vec![5; 64],
            }],
        };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(
            serde_json::from_str::<SignedClusterMembership>(&json).unwrap(),
            m
        );
    }
}
