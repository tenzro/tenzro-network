//! Fuzzes the bridge inner-message verification discipline that every
//! inbound cross-chain payload passes after its outer envelope
//! (Wormhole VAA quorum, Hyperlane ISM multisig, Axelar multisig)
//! has been verified: decode -> validate -> verify_hash ->
//! verify_signature.
//!
//! Property: arbitrary bytes must never panic; non-TenzroMessage
//! bodies return Ok(None); malformed TenzroMessages return Err.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_bridge::message_format::verify_inner_message;

fuzz_target!(|data: &[u8]| {
    let _ = verify_inner_message(data, None);
});
