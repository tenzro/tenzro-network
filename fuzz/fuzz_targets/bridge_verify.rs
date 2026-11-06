//! Fuzzes inbound bridge message verification with input a relayer
//! controls: the delivery envelope with its committee signatures, and the
//! receipt proofs a delivery carries.
//!
//! Properties:
//! - decoding a delivery and verifying its committee signatures never panics;
//! - no delivery passes a committee whose members never signed: the members
//!   are fixed addresses with no known keys, so acceptance is a forgery;
//! - Merkle-Patricia receipt proof verification never panics on any root,
//!   key or proof nodes.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tenzro_bridge::route::attestation::Delivery;
use tenzro_bridge::route::receipt_proof::{verify_log, verify_trie_value};
use tenzro_bridge::secp256k1_multisig::ValidatorSet;

#[derive(Debug, Arbitrary)]
struct Input<'a> {
    delivery: &'a [u8],
    digest: [u8; 32],
    threshold: u8,
    root: [u8; 32],
    key: &'a [u8],
    proof: Vec<Vec<u8>>,
    tx_index: u32,
    log_index: u32,
}

fn committee() -> Vec<[u8; 20]> {
    (1u8..=7).map(|i| [i; 20]).collect()
}

fuzz_target!(|input: Input<'_>| {
    if let Ok(delivery) = Delivery::decode(input.delivery) {
        let set = ValidatorSet::new(committee(), input.threshold.clamp(1, 7), "fuzz");
        assert!(
            set.verify_quorum(&input.digest, &delivery.committee).is_err(),
            "signatures from no member key passed the committee"
        );
        assert!(set.verify_quorum(&input.digest, &delivery.blessing).is_err());
    }
    let proof: Vec<Vec<u8>> = input.proof.into_iter().take(64).collect();
    let _ = verify_trie_value(&input.root, input.key, &proof);
    let _ = verify_log(&input.root, input.tx_index, input.log_index, &proof);
});
