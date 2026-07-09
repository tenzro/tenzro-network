//! Fuzzes the HotStuff-2 vote ingestion path: bincode + JSON
//! deserialization of `Vote` (the gossip and RPC wire encodings),
//! canonical signing-payload construction, and
//! `VoteCollector::add_vote` pre-registry validation
//! (vote_format_version, high_qc_view < view invariant, validator-set
//! membership).
//!
//! The collector holds a one-validator set with fixed-length dummy
//! keys; fuzzed voters are never members, so rejection is expected —
//! the property is that no decoded vote can panic the collector.

#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use tenzro_consensus::validator::{ValidatorInfo, ValidatorSet};
use tenzro_consensus::voter::{Vote, VoteCollector};
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_types::primitives::Address;

const ML_DSA_65_VK_LEN: usize = 1952;
const BLS_G1_COMPRESSED_LEN: usize = 48;

fn collector() -> &'static VoteCollector {
    static COLLECTOR: OnceLock<VoteCollector> = OnceLock::new();
    COLLECTOR.get_or_init(|| {
        let info = ValidatorInfo::new(
            Address::new([0u8; 32]),
            PublicKey::new(KeyType::Ed25519, vec![0u8; 32]),
            vec![0u8; ML_DSA_65_VK_LEN],
            vec![0u8; BLS_G1_COMPRESSED_LEN],
            1,
        );
        let set = ValidatorSet::new(0, vec![info]).expect("non-empty validator set");
        VoteCollector::new(Arc::new(set))
    })
}

fn exercise(vote: Vote) {
    let _ = vote.signing_payload();
    let _ = collector().add_vote(vote);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(vote) = bincode::deserialize::<Vote>(data) {
        exercise(vote);
    }
    if let Ok(vote) = serde_json::from_slice::<Vote>(data) {
        exercise(vote);
    }
});
