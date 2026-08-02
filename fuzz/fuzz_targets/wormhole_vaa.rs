//! Fuzzes the Wormhole VAA binary wire parser and the guardian-quorum
//! verifier: version || guardian_set_index || sig_count || sigs ||
//! timestamp || nonce || emitter_chain || emitter_address || sequence ||
//! consistency_level || payload.
//!
//! Properties:
//! - `Vaa::parse` never panics on arbitrary bytes (offset arithmetic,
//!   truncation, declared-length vs actual-length mismatches).
//! - A parsed VAA's `signing_digest` and `verify_quorum` never panic —
//!   in particular the secp256k1 ECDSA recovery path must reject
//!   malformed (r, s, v) tuples with an error, not an abort.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_bridge::wormhole::{GuardianSet, Vaa};

fuzz_target!(|data: &[u8]| {
    let Ok(vaa) = Vaa::parse(data) else {
        return;
    };
    let _ = vaa.signing_digest();

    // Fixed 3-guardian set: recovery mismatches are expected (the
    // fuzzer does not hold guardian keys); the property under test is
    // that verification fails closed without panicking.
    let set = GuardianSet {
        index: vaa.guardian_set_index,
        guardians: vec![[0x11u8; 20], [0x22u8; 20], [0x33u8; 20]],
        expiration_time: 0,
    };
    let _ = vaa.verify_quorum(&set);
});
