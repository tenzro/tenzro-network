//! What it costs to repair one lost share, run on demand:
//!
//! ```text
//! cargo test --release -p tenzro-storage-provider --lib repair_cost -- --ignored --nocapture
//! ```
//!
//! For the provider's Reed-Solomon shards, repair reads `k` surviving shards,
//! rebuilds the object and re-encodes the lost shard. For the committee
//! store's two-dimensional layout (Red Stuff, `tenzro_storage::da::redstuff`)
//! this tree repairs the same way: it reconstructs the blob from `2f+1`
//! secondary slivers and re-encodes the lost node's pair. Both are measured
//! as the bytes read. Beside them is the repair the Red Stuff design allows,
//! one symbol from each of `f+1` and `2f+1` other nodes, computed from the
//! measured symbol length: this layout extends each dimension on its own, so
//! that repair is not available here, and the figure is the target, not a
//! measurement.

use tenzro_storage::da::redstuff::{self, CommitteeShape};

use crate::redundancy::{RedundancyScheme, encode, reconstruct};

const MIB: f64 = 1024.0 * 1024.0;

#[test]
#[ignore = "measurement: scripts/netlab/measure.sh runs it with --ignored"]
fn repair_cost_of_one_lost_share() {
    let blob_mib = 64usize;
    let blob: Vec<u8> = (0..blob_mib * 1024 * 1024)
        .map(|i| (i % 253) as u8)
        .collect();
    let len = blob.len() as f64;

    for (k, m) in [(2usize, 2usize), (3, 2), (4, 2), (10, 4)] {
        let scheme = RedundancyScheme::erasure(k, m).unwrap();
        let shards = encode(&blob, scheme).unwrap();
        let stored: usize = shards.iter().map(|s| s.bytes.len()).sum();
        let survivors = shards[1..=k].to_vec();
        let read: usize = survivors.iter().map(|s| s.bytes.len()).sum();
        let rebuilt = reconstruct(&survivors, scheme, blob.len(), "measure").unwrap();
        let lost = &encode(&rebuilt, scheme).unwrap()[0];
        assert_eq!(
            lost.bytes, shards[0].bytes,
            "the lost shard is rebuilt exactly"
        );
        println!(
            "MEASURE repair reed_solomon k={k} m={m} blob_mib={blob_mib} storage_x={:.2} \
             lost_share_mib={:.2} repair_read_mib={:.2} read_per_lost={:.1}",
            stored as f64 / len,
            shards[0].bytes.len() as f64 / MIB,
            read as f64 / MIB,
            read as f64 / shards[0].bytes.len() as f64
        );
    }

    for f in [1usize, 3, 10, 33] {
        let shape = CommitteeShape::from_fault_bound(f).unwrap();
        let encoded = redstuff::encode(&blob, shape).unwrap();
        let stored: usize = encoded
            .slivers
            .iter()
            .map(|p| p.primary.len() + p.secondary.len())
            .sum();
        let lost = &encoded.slivers[0];
        let lost_len = lost.primary.len() + lost.secondary.len();
        let quorum: Vec<_> = encoded.slivers[1..=shape.cols()].to_vec();
        let read: usize = quorum.iter().map(|p| p.secondary.len()).sum();
        let rebuilt = redstuff::reconstruct(
            &quorum,
            shape,
            encoded.blob_len,
            encoded.symbol_len,
            &encoded.commitment,
        )
        .unwrap();
        let again = redstuff::encode(&rebuilt, shape).unwrap();
        assert_eq!(again.slivers[0].primary, lost.primary);
        assert_eq!(again.slivers[0].secondary, lost.secondary);
        let design = (shape.rows() + shape.cols()) * encoded.symbol_len;
        println!(
            "MEASURE repair red_stuff f={f} n={} blob_mib={blob_mib} storage_x={:.2} \
             lost_share_mib={:.3} repair_read_mib={:.2} read_per_lost={:.1} \
             design_repair_mib={:.4} (computed, not available in this layout)",
            shape.n(),
            stored as f64 / len,
            lost_len as f64 / MIB,
            read as f64 / MIB,
            read as f64 / lost_len as f64,
            design as f64 / MIB
        );
    }
}
