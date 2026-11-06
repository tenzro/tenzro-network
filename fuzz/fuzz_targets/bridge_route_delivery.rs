//! Fuzzes the bridge route delivery envelope: dest chain id || nonce ||
//! expiry || body || proof || committee signatures || blessing signatures.
//!
//! Properties:
//! - `Delivery::decode` never panics on arbitrary bytes (length prefixes,
//!   signature counts, truncation, trailing bytes).
//! - Decoding is canonical: a delivery that decodes re-encodes to exactly
//!   the input, so no two byte strings carry the same attestation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_bridge::route::attestation::Delivery;

fuzz_target!(|data: &[u8]| {
    let Ok(delivery) = Delivery::decode(data) else {
        return;
    };
    assert_eq!(delivery.encode(), data);
});
