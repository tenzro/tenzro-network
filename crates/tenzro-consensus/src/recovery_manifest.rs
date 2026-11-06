//! The recovery restart manifest: the one way back from a halt that no
//! committee can certify its way out of.
//!
//! When more than a third of the voting power is gone for good, no block can
//! be certified, so no epoch closes and no governance decision or validator
//! exit can pass: the set cannot be repaired from inside. What survives is
//! the finalized history on every surviving node. A manifest names the last
//! checkpoint every survivor holds (the anchor: its last block, the
//! checkpoint itself, and the epoch that block belongs to) and the successor
//! validator set for the next epoch. A node started with a manifest checks it
//! with [`check`]; the checks make a manifest usable only at the exact tip it
//! was written for and only with a successor set that passes the same
//! arithmetic a launch must pass. The node applies it in
//! `tenzro_node::recovery`.
//!
//! The manifest is a social-consensus act, not a chain rule: the successor
//! set is agreed out of band and published on independent channels, and
//! every operator compares [`RecoveryManifest::digest`] with the published
//! one before starting; the node refuses to start unless it is given that
//! digest and it equals the digest of the file. It is deliberately not signed
//! by the dead set (it cannot be) and not accepted from the network (a node
//! reads it from its own command line only). The `live` field is taken as
//! written by whoever prepares the manifest; it records that the member
//! answered a hardware challenge while the manifest was prepared and is not
//! proof of liveness at the time of the restart.

use serde::{Deserialize, Serialize};
use tenzro_types::primitives::Address;

use crate::launch_check::{LaunchRefusal, LaunchValidator, check_launch_set};
use crate::validator::ValidatorInfo;
use crate::validator_key::ValidatorPublicKey;

/// Domain separation for the manifest digest.
pub const MANIFEST_DOMAIN: &[u8] = b"tenzro/recovery-manifest/v2";

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let t = String::deserialize(d)?;
        hex::decode(t.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let t = String::deserialize(d)?;
        let v = hex::decode(t.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(v.as_slice()).map_err(|_| serde::de::Error::custom("not 32 bytes"))
    }
}

mod hex_address {
    use serde::{Deserializer, Serializer};
    use tenzro_types::primitives::Address;

    pub fn serialize<S: Serializer>(a: &Address, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(a.as_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Address, D::Error> {
        super::hex_array::deserialize(d).map(Address::new)
    }
}

/// One validator of the successor set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessorMember {
    /// A label for the report.
    pub name: String,
    /// The validator account address.
    #[serde(with = "hex_address")]
    pub address: Address,
    /// Stake it holds in the successor set, in whole TNZO (the unit of the
    /// epoch validator sets).
    pub stake: u128,
    /// ML-DSA half of its hardware consensus key.
    #[serde(with = "hex_bytes")]
    pub ml_dsa_public_key: Vec<u8>,
    /// ECDSA half of its hardware consensus key.
    #[serde(with = "hex_bytes")]
    pub p256_public_key: Vec<u8>,
    /// Its Ed25519 node key.
    #[serde(with = "hex_array")]
    pub node_key: [u8; 32],
    /// It answered a challenge signed by its hardware identity while the
    /// manifest was being prepared.
    pub live: bool,
}

/// The manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryManifest {
    /// The chain this recovers. A node on another chain refuses it.
    pub chain_id: u64,
    /// Height of the last block of the anchor checkpoint, which every
    /// survivor holds.
    pub anchor_height: u64,
    /// Hash of that block.
    #[serde(with = "hex_array")]
    pub anchor_hash: [u8; 32],
    /// Index of the anchor checkpoint (`tenzro_getCheckpointCertificate`).
    pub anchor_checkpoint_index: u64,
    /// Digest of the anchor checkpoint (`tenzro_getCheckpointCertificate`).
    #[serde(with = "hex_array")]
    pub anchor_checkpoint_digest: [u8; 32],
    /// The epoch that block belongs to.
    pub from_epoch: u64,
    /// The epoch the successor set serves: `from_epoch + 1`.
    pub to_epoch: u64,
    /// The successor validator set.
    pub successor: Vec<SuccessorMember>,
}

fn put_bytes(h: &mut blake3::Hasher, b: &[u8]) {
    h.update(&(b.len() as u64).to_be_bytes());
    h.update(b);
}

impl RecoveryManifest {
    /// The digest operators compare out of band: a fixed-order,
    /// length-prefixed encoding of every field.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(MANIFEST_DOMAIN);
        h.update(&self.chain_id.to_be_bytes());
        h.update(&self.anchor_height.to_be_bytes());
        h.update(&self.anchor_hash);
        h.update(&self.anchor_checkpoint_index.to_be_bytes());
        h.update(&self.anchor_checkpoint_digest);
        h.update(&self.from_epoch.to_be_bytes());
        h.update(&self.to_epoch.to_be_bytes());
        h.update(&(self.successor.len() as u64).to_be_bytes());
        for s in &self.successor {
            put_bytes(&mut h, s.name.as_bytes());
            h.update(s.address.as_bytes());
            h.update(&s.stake.to_be_bytes());
            put_bytes(&mut h, &s.ml_dsa_public_key);
            put_bytes(&mut h, &s.p256_public_key);
            h.update(&s.node_key);
            h.update(&[s.live as u8]);
        }
        h.finalize().into()
    }

    /// Reads a manifest from its JSON file form.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("recovery manifest: {e}"))
    }

    /// The JSON file form.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a manifest encodes")
    }

    /// The successor set as the validators of epoch `to_epoch`, in manifest
    /// order.
    pub fn successor_validators(&self) -> Result<Vec<ValidatorInfo>, ManifestRefusal> {
        self.successor
            .iter()
            .map(|s| {
                let key =
                    ValidatorPublicKey::new(s.ml_dsa_public_key.clone(), s.p256_public_key.clone())
                        .map_err(|e| ManifestRefusal::BadKey(e.to_string()))?;
                Ok(ValidatorInfo::new(s.address, key, s.node_key, s.stake))
            })
            .collect()
    }
}

/// What the node knows locally when it is handed a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalView {
    /// The chain this node runs.
    pub chain_id: u64,
    /// Height of this node's last finalized block.
    pub tip_height: u64,
    /// Its hash.
    pub tip_hash: [u8; 32],
    /// The epoch that block belongs to.
    pub tip_epoch: u64,
    /// Index and digest of the checkpoint whose last block is the tip, when
    /// this node holds that checkpoint (a survivor does; a member that state
    /// synced to the anchor does not).
    pub tip_checkpoint: Option<(u64, [u8; 32])>,
}

/// Why a manifest is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestRefusal {
    /// The manifest is for another chain.
    WrongChain,
    /// The node's tip is not the anchor: either it holds less than the
    /// survivors agreed on, or the chain has moved on and needs no recovery.
    NotAtAnchor {
        /// The node's tip height.
        tip: u64,
        /// The anchor height.
        anchor: u64,
    },
    /// Same height, different block: the node is on a different history.
    AnchorHashDiffers,
    /// The node holds the checkpoint that ends at the anchor and it is not
    /// the one the manifest names.
    AnchorCheckpointDiffers,
    /// The epochs do not follow each other.
    EpochStep,
    /// Two members share an address or a key.
    DuplicateMember,
    /// A member has no key.
    EmptyKey,
    /// A member's key is malformed.
    BadKey(String),
    /// The successor set fails the launch arithmetic.
    Successor(LaunchRefusal),
}

/// Checks a manifest against the node's own view. Pure: it reads nothing and
/// changes nothing.
pub fn check(m: &RecoveryManifest, local: &LocalView) -> Result<(), ManifestRefusal> {
    if m.chain_id != local.chain_id {
        return Err(ManifestRefusal::WrongChain);
    }
    if local.tip_height != m.anchor_height {
        return Err(ManifestRefusal::NotAtAnchor {
            tip: local.tip_height,
            anchor: m.anchor_height,
        });
    }
    if local.tip_hash != m.anchor_hash {
        return Err(ManifestRefusal::AnchorHashDiffers);
    }
    if local
        .tip_checkpoint
        .is_some_and(|c| c != (m.anchor_checkpoint_index, m.anchor_checkpoint_digest))
    {
        return Err(ManifestRefusal::AnchorCheckpointDiffers);
    }
    if m.from_epoch != local.tip_epoch || m.to_epoch != m.from_epoch.saturating_add(1) {
        return Err(ManifestRefusal::EpochStep);
    }
    let mut keys: Vec<&[u8]> = Vec::with_capacity(m.successor.len());
    let mut addresses: Vec<&[u8]> = Vec::with_capacity(m.successor.len());
    for s in &m.successor {
        if s.ml_dsa_public_key.is_empty() || s.p256_public_key.is_empty() {
            return Err(ManifestRefusal::EmptyKey);
        }
        keys.push(&s.ml_dsa_public_key);
        addresses.push(s.address.as_bytes());
    }
    keys.sort_unstable();
    addresses.sort_unstable();
    if keys.windows(2).any(|w| w[0] == w[1]) || addresses.windows(2).any(|w| w[0] == w[1]) {
        return Err(ManifestRefusal::DuplicateMember);
    }
    m.successor_validators()?;
    let set: Vec<LaunchValidator> = m
        .successor
        .iter()
        .map(|s| LaunchValidator {
            name: s.name.clone(),
            stake: s.stake,
            live: s.live,
            hardware_identity: true,
        })
        .collect();
    check_launch_set(&set).map_err(ManifestRefusal::Successor)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_key::ValidatorSigner;
    use crate::validator_key::test_signer::SoftwareTestSigner;

    fn member(i: u8, stake: u128, live: bool) -> SuccessorMember {
        let key = SoftwareTestSigner::from_seed(i as u64 + 1)
            .public_key()
            .clone();
        SuccessorMember {
            name: format!("v{i}"),
            address: Address::new([i + 1; 32]),
            stake,
            ml_dsa_public_key: key.ml_dsa.clone(),
            p256_public_key: key.p256.clone(),
            node_key: [i + 1; 32],
            live,
        }
    }

    fn manifest(successor: Vec<SuccessorMember>) -> RecoveryManifest {
        RecoveryManifest {
            chain_id: 7,
            anchor_height: 7341,
            anchor_hash: [9; 32],
            anchor_checkpoint_index: 14,
            anchor_checkpoint_digest: [3; 32],
            from_epoch: 1233,
            to_epoch: 1234,
            successor,
        }
    }

    fn local() -> LocalView {
        LocalView {
            chain_id: 7,
            tip_height: 7341,
            tip_hash: [9; 32],
            tip_epoch: 1233,
            tip_checkpoint: Some((14, [3; 32])),
        }
    }

    #[test]
    fn the_2026_halt_is_recoverable_with_two_survivors_and_five_new_validators() {
        // Four equal validators, two of them gone for good: the old set
        // certifies nothing. The two survivors and five new machines form a
        // seven-validator successor set that passes the launch arithmetic.
        let mut set: Vec<SuccessorMember> = (0..7).map(|i| member(i, 5_000_000, true)).collect();
        assert_eq!(check(&manifest(set.clone()), &local()), Ok(()));
        // Two of the seven not yet answering the hardware challenge: refused.
        set[5].live = false;
        set[6].live = false;
        assert!(matches!(
            check(&manifest(set), &local()),
            Err(ManifestRefusal::Successor(_))
        ));
    }

    #[test]
    fn a_successor_set_with_no_spare_is_refused() {
        // Four equal validators, all live: three certify, no spare after a
        // loss is the launch rule's f = 1 floor and is accepted; three
        // validators are not.
        let four: Vec<_> = (0..4).map(|i| member(i, 1, true)).collect();
        assert_eq!(check(&manifest(four), &local()), Ok(()));
        let three: Vec<_> = (0..3).map(|i| member(i, 1, true)).collect();
        assert!(matches!(
            check(&manifest(three), &local()),
            Err(ManifestRefusal::Successor(LaunchRefusal::TooFew { .. }))
        ));
    }

    #[test]
    fn a_manifest_applies_only_at_the_exact_tip_it_was_written_for() {
        let m = manifest((0..7).map(|i| member(i, 1, true)).collect());
        let mut l = local();
        l.tip_height = 7342; // the chain moved on: no recovery is needed
        assert!(matches!(
            check(&m, &l),
            Err(ManifestRefusal::NotAtAnchor { .. })
        ));
        let mut l = local();
        l.tip_height = 7340; // this node holds less than the survivors agreed on
        assert!(matches!(
            check(&m, &l),
            Err(ManifestRefusal::NotAtAnchor { .. })
        ));
        let mut l = local();
        l.tip_hash = [8; 32]; // another history at the same height
        assert_eq!(check(&m, &l), Err(ManifestRefusal::AnchorHashDiffers));
        let mut l = local();
        l.chain_id = 8;
        assert_eq!(check(&m, &l), Err(ManifestRefusal::WrongChain));
        let mut l = local();
        l.tip_checkpoint = Some((14, [4; 32])); // a survivor holding another checkpoint
        assert_eq!(check(&m, &l), Err(ManifestRefusal::AnchorCheckpointDiffers));
        let mut l = local();
        l.tip_checkpoint = None; // a member that state synced holds none
        assert_eq!(check(&m, &l), Ok(()));
    }

    #[test]
    fn the_epochs_must_follow_and_the_members_must_differ() {
        let mut m = manifest((0..7).map(|i| member(i, 1, true)).collect());
        m.to_epoch = 1236;
        assert_eq!(check(&m, &local()), Err(ManifestRefusal::EpochStep));
        let mut m = manifest((0..7).map(|i| member(i, 1, true)).collect());
        m.successor[1].ml_dsa_public_key = m.successor[0].ml_dsa_public_key.clone();
        assert_eq!(check(&m, &local()), Err(ManifestRefusal::DuplicateMember));
        let mut m = manifest((0..7).map(|i| member(i, 1, true)).collect());
        m.successor[1].address = m.successor[0].address;
        assert_eq!(check(&m, &local()), Err(ManifestRefusal::DuplicateMember));
        m.successor[1].ml_dsa_public_key = Vec::new();
        assert_eq!(check(&m, &local()), Err(ManifestRefusal::EmptyKey));
        let mut m = manifest((0..7).map(|i| member(i, 1, true)).collect());
        m.successor[2].ml_dsa_public_key = vec![1, 2, 3];
        assert!(matches!(
            check(&m, &local()),
            Err(ManifestRefusal::BadKey(_))
        ));
    }

    #[test]
    fn the_digest_changes_with_every_field() {
        let m = manifest((0..7).map(|i| member(i, 1, true)).collect());
        let d = m.digest();
        let mut x = m.clone();
        x.successor[3].stake = 2;
        assert_ne!(d, x.digest());
        let mut x = m.clone();
        x.anchor_hash[0] ^= 1;
        assert_ne!(d, x.digest());
        let mut x = m.clone();
        x.anchor_checkpoint_index += 1;
        assert_ne!(d, x.digest());
        let mut x = m.clone();
        x.successor[0].node_key[0] ^= 1;
        assert_ne!(d, x.digest());
        assert_eq!(d, m.clone().digest());
    }

    #[test]
    fn the_file_form_round_trips_with_the_same_digest() {
        let m = manifest((0..4).map(|i| member(i, 1, true)).collect());
        let back = RecoveryManifest::from_json(m.to_json().as_bytes()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.digest(), m.digest());
        assert!(RecoveryManifest::from_json(b"{}").is_err());
    }
}
