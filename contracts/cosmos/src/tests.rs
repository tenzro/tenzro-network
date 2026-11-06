// SPDX-License-Identifier: Apache-2.0
use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
use cosmwasm_std::{Addr, Binary, from_json, to_json_binary};
use sha2::{Digest, Sha256};

use super::*;

/// A real finality proof of a test build of the finality program.
const PROOF: &str = include_str!("../../../crates/tenzro-vm/tests/fixtures/finality_proof.json");

fn proof() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let v: serde_json::Value = serde_json::from_str(PROOF).unwrap();
    let h = |k: &str| hex::decode(v[k].as_str().unwrap().trim_start_matches("0x")).unwrap();
    (h("journal"), h("evm_seal"), h("image_id").try_into().unwrap())
}

fn setup() -> (cosmwasm_std::OwnedDeps<cosmwasm_std::testing::MockStorage, cosmwasm_std::testing::MockApi, cosmwasm_std::testing::MockQuerier>, Journal) {
    let (journal, _, image) = proof();
    let j = Journal::decode(&journal).unwrap();
    let mut deps = mock_dependencies();
    let client = ClientData {
        image_id: image,
        chain_id: j.chain_id,
        genesis_hash: j.genesis_hash,
        genesis_committee_root: [9; 32],
        latest_height: 1,
        latest_index: 0,
        frozen: false,
    };
    let consensus = ConsensusData { index: 0, checkpoint_digest: [0; 32], state_root: [0; 32], timestamp_ms: 0 };
    instantiate(
        deps.as_mut(),
        mock_env(),
        message_info(&Addr::unchecked("ibc"), &[]),
        InstantiateMessage {
            client_state: to_json_binary(&client).unwrap(),
            consensus_state: to_json_binary(&consensus).unwrap(),
            checksum: Binary::from(vec![1u8; 32]),
        },
    )
    .unwrap();
    // The committee of the proof's epoch, as earlier handovers left it.
    deps.storage.set(&committee_key(j.epoch), &j.committee_root);
    (deps, j)
}

fn message(journal: &[u8], seal: &[u8]) -> Binary {
    Binary::from([journal, seal].concat())
}

#[test]
fn a_real_finality_proof_updates_the_client() {
    let (mut deps, j) = setup();
    let (journal, seal, _) = proof();
    query(deps.as_ref(), mock_env(), QueryMsg::VerifyClientMessage { client_message: message(&journal, &seal) }).unwrap();
    let res = sudo(deps.as_mut(), mock_env(), SudoMsg::UpdateState { client_message: message(&journal, &seal) }).unwrap();
    let r: UpdateStateResult = from_json(res.data.unwrap()).unwrap();
    assert_eq!(r.heights, vec![Height { revision_number: 0, revision_height: j.state_height }]);
    let c = load_consensus(&deps.storage, j.state_height).unwrap();
    assert_eq!(c.state_root, j.state_root);
    // Where 08-wasm reads them.
    assert!(deps.storage.get(format!("consensusStates/0-{}", j.state_height).as_bytes()).is_some());
    assert!(deps.storage.get(b"clientState").unwrap().starts_with(&[0x0a, 0x25]));
    let t: TimestampAtHeightResult = from_json(
        query(deps.as_ref(), mock_env(), QueryMsg::TimestampAtHeight { height: Height { revision_number: 0, revision_height: j.state_height } })
            .unwrap(),
    )
    .unwrap();
    assert_eq!(t.timestamp, j.timestamp_ms * 1_000_000);
    // The same checkpoint twice is refused, and is not misbehaviour.
    assert!(sudo(deps.as_mut(), mock_env(), SudoMsg::UpdateState { client_message: message(&journal, &seal) }).is_err());
    let m: CheckForMisbehaviourResult =
        from_json(query(deps.as_ref(), mock_env(), QueryMsg::CheckForMisbehaviour { client_message: message(&journal, &seal) }).unwrap())
            .unwrap();
    assert!(!m.found_misbehaviour);
}

#[test]
fn a_tampered_proof_or_journal_is_refused() {
    let (mut deps, _) = setup();
    let (journal, seal, _) = proof();
    let mut bad_seal = seal.clone();
    bad_seal[100] ^= 1;
    assert!(sudo(deps.as_mut(), mock_env(), SudoMsg::UpdateState { client_message: message(&journal, &bad_seal) }).is_err());
    let mut bad_journal = journal.clone();
    bad_journal[300] ^= 1;
    assert!(sudo(deps.as_mut(), mock_env(), SudoMsg::UpdateState { client_message: message(&bad_journal, &seal) }).is_err());
    // A committee the client does not hold.
    let (mut other, j) = setup();
    other.storage.remove(&committee_key(j.epoch));
    assert!(sudo(other.as_mut(), mock_env(), SudoMsg::UpdateState { client_message: message(&journal, &seal) }).is_err());
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[test]
fn entries_are_proven_under_a_checkpoints_state_root() {
    let (mut deps, _) = setup();
    // A state holding one entry of Tenzro's IBC store: its stem alone at the
    // root. The store entry of an ICS-24 path is the route-state entry
    // `ibc/{hex(path)}` of the governed-state account.
    let ibc_path = b"commitments/ports/transfer/channels/channel-osmosis/sequences/1".as_slice();
    let entry = ibc_store_entry(ibc_path);
    assert_eq!(
        entry,
        format!("storage:{}:{}", "ff".repeat(20), hex::encode(format!("ibc/{}", hex::encode(ibc_path))))
    );
    let (ns, key, value) = ("state", entry.as_bytes(), b"packet".as_slice());
    let tk = sha(&[b"tenzro.state-trie.key", &(ns.len() as u16).to_le_bytes(), ns.as_bytes(), key]);
    let (stem, slot) = (&tk[..31], tk[31]);
    let mut slots = sha(&[&[0x00], value]);
    let mut index = slot as usize;
    for _ in 0..8 {
        slots = if index & 1 == 0 { sha(&[&[0x03], &slots, &[0; 32]]) } else { sha(&[&[0x03], &[0; 32], &slots]) };
        index >>= 1;
    }
    let root = sha(&[&[0x02], stem, &slots]);
    save_consensus(&mut deps.storage, 50, &ConsensusData { index: 9, checkpoint_digest: [1; 32], state_root: root, timestamp_ms: 5 }).unwrap();
    let path = MerklePath { key_path: vec![Binary::from(b"ibc".to_vec()), Binary::from(ibc_path.to_vec())] };
    // Encoded proofs: no siblings, then the terminal.
    let mut present = vec![0u8, 0, 2];
    present.extend_from_slice(&[0u8; 32 * 8]);
    let membership = |value: &[u8], height: u64| SudoMsg::VerifyMembership {
        height: Height { revision_number: 0, revision_height: height },
        delay_time_period: 0,
        delay_block_period: 0,
        proof: Binary::from(present.clone()),
        merkle_path: path.clone(),
        value: Binary::from(value.to_vec()),
    };
    sudo(deps.as_mut(), mock_env(), membership(value, 50)).unwrap();
    assert!(sudo(deps.as_mut(), mock_env(), membership(b"other", 50)).is_err());
    assert!(sudo(deps.as_mut(), mock_env(), membership(value, 51)).is_err());
    // Another key is absent: the path ends at this entry's stem.
    let mut absent = vec![0u8, 0, 1];
    absent.extend_from_slice(stem);
    absent.extend_from_slice(&slots);
    let other = MerklePath { key_path: vec![Binary::from(b"ibc".to_vec()), Binary::from(b"receipts/ports/transfer/channels/channel-osmosis/sequences/1".to_vec())] };
    // A path outside Tenzro's IBC store is not proven at all.
    let foreign = MerklePath { key_path: vec![Binary::from(ns.as_bytes().to_vec()), Binary::from(key.to_vec())] };
    assert!(sudo(deps.as_mut(), mock_env(), SudoMsg::VerifyMembership {
        height: Height { revision_number: 0, revision_height: 50 },
        delay_time_period: 0,
        delay_block_period: 0,
        proof: Binary::from(present.clone()),
        merkle_path: foreign,
        value: Binary::from(value.to_vec()),
    })
    .is_err());
    let non = |p: &Vec<u8>, path: &MerklePath| SudoMsg::VerifyNonMembership {
        height: Height { revision_number: 0, revision_height: 50 },
        delay_time_period: 0,
        delay_block_period: 0,
        proof: Binary::from(p.clone()),
        merkle_path: path.clone(),
    };
    sudo(deps.as_mut(), mock_env(), non(&absent, &other)).unwrap();
    assert!(sudo(deps.as_mut(), mock_env(), non(&present, &path)).is_err());
}
