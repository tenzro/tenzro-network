use crate::params::{HLL_MAX_RHO, MRT_MAX_BYPASS};
use crate::state::{
    decode_caller_entry, encode_caller_entry, hll_add, push_caller_mrt, BYPASS_FP_SIZE, FP_MASK,
    RING_BUFFER_SIZE,
};

#[kani::proof]
fn proof_encode_decode_roundtrip() {
    let fp: u64 = kani::any();
    let score: u8 = kani::any();
    let revoked: bool = kani::any();
    kani::assume(score <= 100);

    let fp56 = fp & FP_MASK;
    let entry = encode_caller_entry(fp56, score, revoked);
    let (decoded_fp, decoded_score, decoded_revoked) = decode_caller_entry(entry);

    assert_eq!(decoded_fp, fp56);
    assert_eq!(decoded_score, score);
    assert_eq!(decoded_revoked, revoked);
}

#[kani::proof]
fn proof_hll_add_keeps_register_nibbles_bounded() {
    let mut hll = [0u8; 128];
    let client_hash: [u8; 32] = kani::any();
    let salt: u64 = kani::any();

    let _ = hll_add(&mut hll, &client_hash, salt);

    for byte in hll {
        let low = byte & 0x0F;
        let high = byte >> 4;
        assert!(low <= HLL_MAX_RHO);
        assert!(high <= HLL_MAX_RHO);
    }
}

#[kani::proof]
fn proof_push_caller_mrt_cursor_and_bounds() {
    let mut recent = [0u64; RING_BUFFER_SIZE];
    let mut cursor: u8 = kani::any();
    cursor %= RING_BUFFER_SIZE as u8;

    let mut ring_base_slot: u64 = kani::any();

    let mut bypass_count: u8 = kani::any();
    kani::assume(bypass_count <= MRT_MAX_BYPASS);

    let mut bypass_fingerprints = [0u64; BYPASS_FP_SIZE];
    let mut bypass_fp_cursor: u8 = kani::any();
    bypass_fp_cursor %= BYPASS_FP_SIZE as u8;

    let fp56: u64 = kani::any::<u64>() & FP_MASK;
    let score: u8 = kani::any();
    kani::assume(score <= 100);
    let current_slot: u64 = kani::any();

    let _ = push_caller_mrt(
        &mut recent,
        &mut cursor,
        &mut ring_base_slot,
        &mut bypass_count,
        &mut bypass_fingerprints,
        &mut bypass_fp_cursor,
        fp56,
        score,
        current_slot,
    );

    assert!((cursor as usize) < RING_BUFFER_SIZE);
    assert!((bypass_fp_cursor as usize) < BYPASS_FP_SIZE);
    assert!(bypass_count <= MRT_MAX_BYPASS);
}
