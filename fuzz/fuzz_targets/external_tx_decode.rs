//! Fuzzes the decoders for transactions signed by external wallets: raw
//! Ethereum transactions (legacy RLP and typed envelopes) and Solana wire
//! transactions, both accepted from RPC callers and carried in blocks, and
//! the ERC-7579 `execute` call data a smart account decodes.
//!
//! Property: no input panics a decoder, and a decoded `execute` call
//! re-encodes to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_vm::external_tx::{decode_evm_raw, decode_svm_wire};
use tenzro_vm::{decode_execute, encode_batch, encode_single};

fuzz_target!(|data: &[u8]| {
    let _ = decode_evm_raw(data, 1337);
    let _ = decode_svm_wire(data);
    if let Ok(calls) = decode_execute(data) {
        let again = if calls.len() == 1 && data.get(4) == Some(&0) {
            encode_single(&calls[0])
        } else {
            encode_batch(&calls)
        };
        assert_eq!(again, data);
    }
});
