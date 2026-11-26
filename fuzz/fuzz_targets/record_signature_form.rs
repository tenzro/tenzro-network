#![no_main]
//! The signed record form has one encoding: any JSON `RecordSignature`
//! decoding accepts re-encodes to a form that decodes to the same value and
//! encodes to the same bytes again, and no input panics the decoder.
//!
//! Seeded with the pinned vector, so mutations stay near the accepted form,
//! where a second accepted spelling of one record would show up.

use libfuzzer_sys::fuzz_target;
use tenzro_crypto::batch::RecordSignature;

fuzz_target!(|data: &[u8]| {
    let Ok(read) = serde_json::from_slice::<RecordSignature>(data) else {
        return;
    };
    let once = serde_json::to_vec(&read).expect("an accepted record encodes");
    let again: RecordSignature = serde_json::from_slice(&once).expect("the encoded form decodes");
    assert_eq!(again, read, "the encoded form decodes to another record");
    assert_eq!(
        serde_json::to_vec(&again).expect("encodes"),
        once,
        "the encoding is not stable"
    );
});
