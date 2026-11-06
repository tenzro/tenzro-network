//! Pins the shared event-proof fixture the SDKs verify (under
//! `sdk/fixtures/event-proof`) to what the chain's own types serve.

use serde_json::Value;
use tenzro_consensus::checkpoint::{Checkpoint, checkpoint_state_height, merkle_root};
use tenzro_consensus::event_proof::{
    BlockIndexProof, CompletenessProof, EventProof, IndexEntryProof, ProvenAnswer,
};
use tenzro_types::block::{BlockHeader, BlockMetadata};
use tenzro_types::chain_event::{
    ChainEvent, EventCursor, Projection, block_index, event_root, event_tree_leaves, index_key,
    transaction_events,
};
use tenzro_types::merkle::merkle_path;
use tenzro_types::primitives::{Address, BlockHeight, Hash, Timestamp};

fn checkpoint(
    index: u64,
    prev: [u8; 32],
    first: u64,
    last: u64,
    blocks_root: [u8; 32],
) -> Checkpoint {
    Checkpoint {
        chain_id: 7,
        genesis_hash: [5; 32],
        epoch: 1,
        index,
        prev,
        first_height: first,
        last_height: last,
        blocks_root,
        state_height: checkpoint_state_height(first, last),
        state_root: [6; 32],
        statement_root: [8; 32],
        next_committee_root: if index == 1 { Some([9; 32]) } else { None },
        anchor_round: last * 3,
        timestamp_ms: 1_700_000_000_000 + last,
        ordering_root: [0; 32],
    }
}

struct Chain {
    headers: Vec<BlockHeader>,
    per_block: Vec<Vec<ChainEvent>>,
    hashes: Vec<[u8; 32]>,
    cps: Vec<Checkpoint>,
}

fn chain() -> Chain {
    let topics = [vec![3u8; 32], vec![4u8; 32]];
    let mut headers = Vec::new();
    let mut per_block = Vec::new();
    for h in 1..=3u64 {
        let logs = [(&[h as u8; 20][..], &topics[..], &b"payload"[..])];
        let events = transaction_events(
            h,
            0,
            Hash::new([h as u8; 32]),
            h != 2,
            21_000 + h,
            Some(vec![1; 20]),
            logs,
        );
        headers.push(BlockHeader {
            height: BlockHeight(h),
            epoch: 1,
            round: 10 + h,
            anchor: Hash::new([h as u8; 32]),
            prev_hash: Hash::new([2; 32]),
            tx_root: Hash::new([3; 32]),
            state_root: Hash::new([4; 32]),
            event_root: event_root(&events),
            receipts_root: Hash::new([5; 32]),
            logs_bloom: tenzro_types::LogsBloom::of_logs(logs.iter().map(|(a, t, _)| (*a, *t))),
            timestamp: Timestamp::new(1_700_000_000_000 + h as i64),
            proposer: Address::new([7; 32]),
            metadata: BlockMetadata {
                gas_used: 21_000,
                gas_limit: 30_000_000,
                tx_count: 1,
                protocol_version: 1,
                base_fee_per_gas: Some(1_000_000_000),
            },
        });
        per_block.push(events);
    }
    let hashes: Vec<[u8; 32]> = headers[..2].iter().map(|h| h.hash().0).collect();
    let cp0 = checkpoint(0, [0; 32], 1, 2, merkle_root(&hashes));
    let cp1 = checkpoint(1, cp0.digest(), 3, 3, merkle_root(&[headers[2].hash().0]));
    Chain {
        headers,
        per_block,
        hashes,
        cps: vec![cp0, cp1],
    }
}

fn proof() -> EventProof {
    let c = chain();
    let leaves = event_tree_leaves(&c.per_block[1]);
    EventProof {
        event: c.per_block[1][1].clone(),
        event_path: merkle_path(&leaves, 1).unwrap(),
        header: c.headers[1].clone(),
        block_path: merkle_path(&c.hashes, 1).unwrap(),
        checkpoints: c.cps,
    }
}

/// Logs of contract 2 over blocks 1..=3, all three checkpoints' worth: the
/// filter, the answer and the proof it left nothing out.
fn completeness() -> (serde_json::Value, Vec<ChainEvent>, CompletenessProof) {
    let c = chain();
    let filter = serde_json::json!({ "addresses": [hex::encode([2u8; 20])] });
    let key = index_key::address(&[2u8; 20]);
    let mut blocks = Vec::new();
    let mut answer = Vec::new();
    for (i, events) in c.per_block.iter().enumerate() {
        let index = block_index(events);
        let at = index.iter().position(|e| e.covers(&key).is_some()).unwrap();
        let leaves = event_tree_leaves(events);
        // Blocks 1 and 2 are under checkpoint 0; block 3 alone under checkpoint 1.
        let path = if i < 2 {
            merkle_path(&c.hashes, i).unwrap()
        } else {
            Vec::new()
        };
        blocks.push(BlockIndexProof {
            header: c.headers[i].clone(),
            block_path: path,
            entries: vec![IndexEntryProof {
                entry: index[at].clone(),
                path: merkle_path(&leaves, events.len() + at).unwrap(),
            }],
        });
        answer.extend(
            events
                .iter()
                .filter(|e| e.log_address() == Some(&[2u8; 20][..]))
                .cloned(),
        );
    }
    let proof = CompletenessProof {
        keys: vec![hex::encode(&key)],
        first_height: 1,
        after: None,
        through: EventCursor::new(3, u32::MAX, u32::MAX),
        blocks,
        checkpoints: c.cps.clone(),
        excluded: Vec::new(),
    };
    proof
        .verify(c.cps.last().unwrap(), &[key], &answer, &|e| {
            e.log_address() == Some(&[2u8; 20][..])
        })
        .unwrap();
    (filter, answer, proof)
}

/// The shared fixture the SDKs verify is exactly what the chain's
/// types serve. `TENZRO_WRITE_FIXTURES=1` rewrites it after a deliberate
/// change to the encoding.
#[test]
fn the_shared_fixture_is_what_the_chain_serves() {
    let p = proof();
    p.verify(p.anchor().unwrap()).unwrap();
    let answer = ProvenAnswer {
        projection: Projection::LatestPerAddress,
        result: Projection::LatestPerAddress.apply(std::slice::from_ref(&p.event)),
        proofs: vec![p.clone()],
    };
    let complete = {
        let (filter, answer, proof) = completeness();
        serde_json::json!({ "filter": filter, "answer": answer, "proof": proof })
    };
    let fixture = serde_json::json!({
        "anchor_digest": hex::encode(p.anchor().unwrap().digest()),
        "proof": p,
        "answer": answer,
        "completeness": complete,
        "blake3_3000": hex::encode(blake3::hash(&(0..3000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>()).as_bytes()),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/fixtures/event-proof/fixture.json");
    if std::env::var_os("TENZRO_WRITE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&fixture).unwrap() + "\n",
        )
        .unwrap();
    }
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the shared fixture")).unwrap();
    assert_eq!(on_disk, fixture);
}
