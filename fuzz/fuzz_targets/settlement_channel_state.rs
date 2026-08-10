//! Fuzzes micropayment-channel state verification: canonical preimage
//! construction (nonce || payer_balance || payee_balance, LE) and the
//! strict Ed25519 check in `verify_signature_with_key`, where both the
//! signature bytes and the payer address (which doubles as the Ed25519
//! public key) are attacker-controlled.
//!
//! Property: malformed keys and signatures of any length are rejected
//! without panicking inside the ed25519 verifier.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_settlement::ChannelState;
use tenzro_types::primitives::{Address, Nonce};

fuzz_target!(|input: (u64, u128, u128, Vec<u8>, [u8; 32])| {
    let (nonce, payer_balance, payee_balance, signature, addr) = input;
    let state = ChannelState {
        nonce: Nonce(nonce),
        payer_balance,
        payee_balance,
        signature,
    };
    let msg = state.canonical_message();
    assert_eq!(msg.len(), 40);
    let _ = state.verify_signature_with_key(&Address::new(addr));
});
