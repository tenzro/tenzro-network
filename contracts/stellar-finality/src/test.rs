// SPDX-License-Identifier: Apache-2.0
extern crate std;

use super::*;
use soroban_sdk::Env;

/// A real finality proof of a test build of the finality program.
const PROOF: &str = include_str!("../../../crates/tenzro-vm/tests/fixtures/finality_proof.json");

struct Fixture {
    image_id: [u8; 32],
    journal: std::vec::Vec<u8>,
    seal: std::vec::Vec<u8>,
}

fn fixture() -> Fixture {
    let v: serde_json::Value = serde_json::from_str(PROOF).unwrap();
    let hex = |k: &str| hex::decode(v[k].as_str().unwrap().trim_start_matches("0x")).unwrap();
    Fixture { image_id: hex("image_id").try_into().unwrap(), journal: hex("journal"), seal: hex("evm_seal") }
}

fn client(env: &Env, f: &Fixture, chain_id: u64, committee: [u8; 32]) -> FinalityClientClient<'static> {
    let id = env.register(
        FinalityClient,
        (
            BytesN::from_array(env, &f.image_id),
            chain_id,
            BytesN::from_array(env, &[0x6e; 32]),
            BytesN::from_array(env, &committee),
        ),
    );
    FinalityClientClient::new(env, &id)
}

const COMMITTEE: [u8; 32] = [
    0xf1, 0x7b, 0x38, 0x36, 0x33, 0xcf, 0xd6, 0x4f, 0x3b, 0xf4, 0x3b, 0x34, 0x39, 0x4e, 0xe5, 0x38, 0x09, 0x6a, 0x72, 0x23,
    0x22, 0xbb, 0x16, 0x14, 0x4d, 0x84, 0x5a, 0xcd, 0x28, 0xe6, 0xe4, 0x81,
];

#[test]
fn a_real_proof_finalizes_its_checkpoint_and_hands_over() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let f = fixture();
    let c = client(&env, &f, 1337, COMMITTEE);
    env.cost_estimate().budget().reset_default();
    let index = c.submit(&Bytes::from_slice(&env, &f.journal), &Bytes::from_slice(&env, &f.seal));
    std::println!("submit: {} cpu instructions, {} memory bytes",
        env.cost_estimate().budget().cpu_instruction_cost(),
        env.cost_estimate().budget().memory_bytes_cost());
    assert_eq!(index, 7);
    assert_eq!(c.state_root(&7), BytesN::from_array(&env, &[0x5e; 32]));
    assert_eq!(c.timestamp_ms(&7), 1_790_000_000_000);
    assert_eq!(c.latest_index(), 7);
    assert_eq!(c.committee_root(&1), Some(BytesN::from_array(&env, &[0xc2; 32])));
}

#[test]
fn a_checkpoint_is_final_once() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let f = fixture();
    let c = client(&env, &f, 1337, COMMITTEE);
    let (j, s) = (Bytes::from_slice(&env, &f.journal), Bytes::from_slice(&env, &f.seal));
    c.submit(&j, &s);
    assert_eq!(c.try_submit(&j, &s), Err(Ok(Error::AlreadyFinal)));
}

#[test]
fn a_journal_the_proof_does_not_commit_is_refused() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let f = fixture();
    let c = client(&env, &f, 1337, COMMITTEE);
    let mut journal = f.journal.clone();
    journal[8 * 32] = 0x5f;
    let r = c.try_submit(&Bytes::from_slice(&env, &journal), &Bytes::from_slice(&env, &f.seal));
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
    assert_eq!(c.latest_index(), 0);
}

#[test]
fn a_seal_for_another_verifier_or_of_the_wrong_size_is_refused() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let f = fixture();
    let c = client(&env, &f, 1337, COMMITTEE);
    let j = Bytes::from_slice(&env, &f.journal);
    let mut seal = f.seal.clone();
    seal[0] = 0;
    assert_eq!(c.try_submit(&j, &Bytes::from_slice(&env, &seal)), Err(Ok(Error::WrongSelector)));
    assert_eq!(c.try_submit(&j, &Bytes::from_slice(&env, &f.seal[..100])), Err(Ok(Error::MalformedSeal)));
}

#[test]
fn proofs_of_another_chain_or_committee_are_refused() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let f = fixture();
    let (j, s) = (Bytes::from_slice(&env, &f.journal), Bytes::from_slice(&env, &f.seal));
    assert_eq!(client(&env, &f, 1, COMMITTEE).try_submit(&j, &s), Err(Ok(Error::WrongChain)));
    assert_eq!(client(&env, &f, 1337, [0xc2; 32]).try_submit(&j, &s), Err(Ok(Error::UnknownCommittee)));
}

#[test]
#[should_panic]
fn an_unknown_checkpoint_has_no_state_root() {
    let env = Env::default();
    let f = fixture();
    client(&env, &f, 1337, COMMITTEE).state_root(&3);
}
