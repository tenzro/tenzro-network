//! Fuzzes JSON-RPC request decoding: the body of a call or a batch as every
//! node surface decodes it before dispatch (envelope, version, params
//! normalization).
//!
//! Property: no body panics the decoder, and decoding is deterministic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_types::jsonrpc::decode_body;

fuzz_target!(|data: &[u8]| {
    let first = decode_body(data);
    assert_eq!(first, decode_body(data));
});
