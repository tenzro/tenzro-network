//! Fuzzes ERC-7683 cross-chain-intent primitives:
//! - `u128_to_uint256_be` / `uint256_be_to_u128` round-trip (the
//!   uint256 decoder must reject non-zero high 128 bits rather than
//!   silently truncate).
//! - `compute_order_id` over decoded `CrossChainOrder`s (deterministic
//!   SHA-256 domain-tagged preimage, no panic on any field content).

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_types::intent_7683::{
    CrossChainOrder, compute_order_id, u128_to_uint256_be, uint256_be_to_u128,
};

fuzz_target!(|input: (u128, [u8; 32], &[u8])| {
    let (value, raw_word, data) = input;

    let encoded = u128_to_uint256_be(value);
    assert_eq!(uint256_be_to_u128(&encoded), Some(value));

    let decoded = uint256_be_to_u128(&raw_word);
    if raw_word[..16].iter().any(|&b| b != 0) {
        assert!(decoded.is_none());
    }

    if let Ok(order) = serde_json::from_slice::<CrossChainOrder>(data) {
        let id_a = compute_order_id(&order);
        let id_b = compute_order_id(&order);
        assert_eq!(id_a, id_b);
    }
});
