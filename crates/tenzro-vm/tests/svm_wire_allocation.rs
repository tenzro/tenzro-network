//! A Solana wire transaction's length prefixes are attacker-chosen: decoding
//! must not reserve memory for more entries than the remaining bytes can hold.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use tenzro_vm::external_tx::decode_svm_wire;

struct Largest;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Largest = Largest;

fn largest_allocation_decoding(raw: &[u8]) -> usize {
    LARGEST.store(0, Ordering::Relaxed);
    assert!(decode_svm_wire(raw).is_err());
    LARGEST.load(Ordering::Relaxed)
}

#[test]
fn length_prefixes_do_not_reserve_memory_the_input_cannot_fill() {
    // The largest three-byte prefix claims 2^21 - 1 entries.
    let huge = [0xff, 0xff, 0x7f];

    // Signatures: 64 bytes each.
    assert!(largest_allocation_decoding(&huge) < 4_096);

    // Account keys: one signature, a header, then the huge key count.
    let mut keys = vec![1u8];
    keys.extend_from_slice(&[0u8; 64]);
    keys.extend_from_slice(&[1, 0, 0]);
    keys.extend_from_slice(&huge);
    assert!(largest_allocation_decoding(&keys) < 4_096);

    // Instructions: one signature, a header, one key, a blockhash, then the
    // huge instruction count.
    let mut ixs = vec![1u8];
    ixs.extend_from_slice(&[0u8; 64]);
    ixs.extend_from_slice(&[1, 0, 0, 1]);
    ixs.extend_from_slice(&[7u8; 32]);
    ixs.extend_from_slice(&[9u8; 32]);
    ixs.extend_from_slice(&huge);
    assert!(largest_allocation_decoding(&ixs) < 4_096);
}
