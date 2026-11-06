//! Fuzzes the TON bag-of-cells decoder with bytes a relayer controls: every
//! TON proof reaches the light client as a bag of cells.
//!
//! Properties:
//! - no bytes panic `parse_boc`;
//! - every root of an accepted bag re-serializes to a bag that parses back
//!   to a cell of the same hash;
//! - checking a parsed root as a Merkle proof against any hash never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_bridge::route::ton_cell::{parse_boc, proven_tree, serialize_boc};

fuzz_target!(|boc: &[u8]| {
    let Ok(roots) = parse_boc(boc) else {
        return;
    };
    // Any hash serves as the expected root; the input's own tail is as good
    // as any.
    let mut expected = [0u8; 32];
    let tail = &boc[boc.len().saturating_sub(32)..];
    expected[..tail.len()].copy_from_slice(tail);
    for root in roots {
        let again = parse_boc(&serialize_boc(&root)).expect("a serialized cell parses");
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].repr_hash(), root.repr_hash());
        let _ = proven_tree(&root, &expected);
    }
});
