// SPDX-License-Identifier: Apache-2.0
extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::token::{StellarAssetClient, TokenClient};

/// Final state roots this test chooses.
#[contract]
pub struct MockFinality;

#[contractimpl]
impl MockFinality {
    pub fn set(env: Env, index: u64, root: BytesN<32>) {
        env.storage().instance().set(&index, &root);
    }

    pub fn state_root(env: Env, index: u64) -> BytesN<32> {
        env.storage().instance().get(&index).unwrap()
    }
}

const VECTORS: &str = include_str!("../../../../sdk/fixtures/settlement_lock/vectors.json");
const HORIZON: u64 = 14 * 24 * 3600;
const CHECKPOINT: u64 = 7;
const ELSEWHERE: u64 = 8;

fn v() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn raw(x: &serde_json::Value) -> std::vec::Vec<u8> {
    hex::decode(x.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

struct T {
    env: Env,
    lock: SettlementLockClient<'static>,
    token: TokenClient<'static>,
    payer: Address,
    recipient: Address,
}

fn setup() -> T {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_800_000_000);
    let finality = env.register(MockFinality, ());
    let fc = MockFinalityClient::new(&env, &finality);
    let root: [u8; 32] = raw(&v()["root"]).try_into().unwrap();
    fc.set(&CHECKPOINT, &BytesN::from_array(&env, &root));
    fc.set(&ELSEWHERE, &BytesN::from_array(&env, &[7u8; 32]));
    let lock_id = env.register(SettlementLock, (finality, HORIZON));
    let admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(admin);
    let payer = Address::generate(&env);
    StellarAssetClient::new(&env, &sac.address()).mint(&payer, &1_000);
    let lock = SettlementLockClient::new(&env, &lock_id);
    let token = TokenClient::new(&env, &sac.address());
    let recipient = Address::generate(&env);
    T { env, lock, token, payer, recipient }
}

impl T {
    fn plan(&self, which: &str) -> BytesN<32> {
        BytesN::from_array(&self.env, &raw(&v()[which]["plan_id"]).try_into().unwrap())
    }

    fn lock_leg(&self, which: &str, index: u32, amount: i128) {
        self.lock.lock(&self.payer, &self.plan(which), &index, &self.token.address, &amount, &self.recipient);
    }

    fn settle(&self, which: &str, index: u32, proof_of: &str, checkpoint: u64) -> Result<(), Error> {
        let vv = v();
        let decision = Bytes::from_slice(&self.env, &raw(&vv[proof_of]["decision"]));
        let proof = Bytes::from_slice(&self.env, &raw(&vv[proof_of]["proof"]));
        match self.lock.try_settle(&self.plan(which), &index, &checkpoint, &decision, &proof) {
            Ok(Ok(())) => Ok(()),
            Err(Ok(e)) => Err(e),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn leg_ids_match_tenzro() {
    let t = setup();
    for which in ["committed", "aborted", "undecided"] {
        for i in 0..3u32 {
            let want: [u8; 32] = raw(&v()[which]["leg_ids"][i as usize]).try_into().unwrap();
            assert_eq!(t.lock.leg_id(&t.plan(which), &i).to_array(), want);
        }
    }
    assert_eq!(t.lock.try_leg_id(&t.plan("committed"), &256), Err(Ok(Error::BadIndex)));
}

#[test]
fn a_commit_pays_the_recipient_once() {
    let t = setup();
    t.lock_leg("committed", 2, 400);
    assert_eq!(t.token.balance(&t.lock.address), 400);
    assert_eq!(t.settle("committed", 2, "committed", CHECKPOINT), Ok(()));
    assert_eq!(t.token.balance(&t.recipient), 400);
    assert_eq!(t.token.balance(&t.payer), 600);
    assert_eq!(t.lock.leg(&t.plan("committed"), &2).stage, Stage::Released);
    assert_eq!(t.settle("committed", 2, "committed", CHECKPOINT), Err(Error::NotLocked));
    assert_eq!(t.lock.try_escape(&t.plan("committed"), &2), Err(Ok(Error::NotLocked)));
}

#[test]
fn an_abort_refunds_the_payer() {
    let t = setup();
    t.lock_leg("aborted", 0, 250);
    assert_eq!(t.token.balance(&t.payer), 750);
    assert_eq!(t.settle("aborted", 0, "aborted", CHECKPOINT), Ok(()));
    assert_eq!(t.token.balance(&t.payer), 1_000);
    assert_eq!(t.token.balance(&t.recipient), 0);
    assert_eq!(t.lock.leg(&t.plan("aborted"), &0).stage, Stage::Refunded);
}

#[test]
fn a_foreign_forged_or_unanchored_decision_moves_nothing() {
    let t = setup();
    t.lock_leg("undecided", 1, 300);
    // Another plan's decision and proof.
    assert_eq!(t.settle("undecided", 1, "committed", CHECKPOINT), Err(Error::Unproven));
    // The decision rewritten to this plan, under the real proof.
    let vv = v();
    let mut forged = raw(&vv["committed"]["decision"]);
    forged[10..].copy_from_slice(&raw(&vv["undecided"]["plan_id"]));
    let proof = Bytes::from_slice(&t.env, &raw(&vv["committed"]["proof"]));
    let r = t.lock.try_settle(&t.plan("undecided"), &1, &CHECKPOINT, &Bytes::from_slice(&t.env, &forged), &proof);
    assert_eq!(r, Err(Ok(Error::Unproven)));
    // A real decision under a root that does not hold it.
    t.lock_leg("committed", 0, 100);
    assert_eq!(t.settle("committed", 0, "committed", ELSEWHERE), Err(Error::Unproven));
    assert_eq!(t.token.balance(&t.lock.address), 400);
    assert_eq!(t.lock.leg(&t.plan("undecided"), &1).stage, Stage::Locked);
}

#[test]
fn an_undecided_leg_escapes_only_after_the_horizon() {
    let t = setup();
    t.lock_leg("undecided", 0, 500);
    let escape_at = t.lock.leg(&t.plan("undecided"), &0).escape_at;
    t.env.ledger().set_timestamp(escape_at - 1);
    assert_eq!(t.lock.try_escape(&t.plan("undecided"), &0), Err(Ok(Error::TooEarly)));
    t.env.ledger().set_timestamp(escape_at);
    t.lock.escape(&t.plan("undecided"), &0);
    assert_eq!(t.token.balance(&t.payer), 1_000);
    assert_eq!(t.lock.try_escape(&t.plan("undecided"), &0), Err(Ok(Error::NotLocked)));
}

#[test]
fn a_leg_locks_once_with_a_positive_amount() {
    let t = setup();
    let p = t.plan("committed");
    assert_eq!(t.lock.try_lock(&t.payer, &p, &1, &t.token.address, &0, &t.recipient), Err(Ok(Error::BadAmount)));
    t.lock_leg("committed", 1, 10);
    assert_eq!(t.lock.try_lock(&t.payer, &p, &1, &t.token.address, &10, &t.recipient), Err(Ok(Error::AlreadyLocked)));
    assert_eq!(t.lock.try_settle(&p, &0, &CHECKPOINT, &Bytes::new(&t.env), &Bytes::new(&t.env)), Err(Ok(Error::NotLocked)));
}

/// The Locked event exactly as the ledger records it, which Tenzro's Stellar
/// light client decodes (sdk/fixtures/settlement_lock/stellar_locked_event.hex).
#[test]
fn the_locked_event_matches_the_shared_vector() {
    use soroban_sdk::testutils::Events as _;
    use soroban_sdk::xdr::{Limits, WriteXdr};
    let t = setup();
    t.lock_leg("committed", 1, 700);
    let events = t.env.events().all().filter_by_contract(&t.lock.address);
    let event = events.events().last().unwrap().clone();
    let got = hex::encode(event.to_xdr(Limits::none()).unwrap());
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../sdk/fixtures/settlement_lock/stellar_locked_event.hex");
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::write(path, std::format!("{got}\n")).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap().trim(), got);
}

#[test]
fn the_reconciliation_hash_matches_the_shared_vector() {
    use soroban_sdk::testutils::Events as _;
    let rv: serde_json::Value =
        serde_json::from_str(include_str!("../../../../sdk/fixtures/settlement_lock/recon.json")).unwrap();
    let acc_at = |x: &serde_json::Value| -> [u8; 32] { raw(x).try_into().unwrap() };
    let t = setup();
    StellarAssetClient::new(&t.env, &t.token.address).mint(&t.payer, &2_000_000_000_000_000_000);
    t.lock_leg("committed", 0, 400);
    assert_eq!(t.lock.reconciliation().1.to_array(), acc_at(&rv["entries"][0]["acc"]));
    t.lock_leg("aborted", 2, 1_000_000_000_000_000_000);
    assert_eq!(t.settle("committed", 0, "committed", CHECKPOINT), Ok(()));
    assert_eq!(t.settle("aborted", 2, "aborted", CHECKPOINT), Ok(()));
    t.lock_leg("undecided", 1, 250);
    t.env.ledger().set_timestamp(1_800_000_000 + HORIZON);
    t.lock.escape(&t.plan("undecided"), &1);
    let (count, acc) = t.lock.reconciliation();
    assert_eq!(count, rv["count"].as_u64().unwrap());
    assert_eq!(acc.to_array(), acc_at(&rv["acc"]));
    t.lock.checkpoint();
    use soroban_sdk::xdr::{Limits, WriteXdr};
    let events = t.env.events().all().filter_by_contract(&t.lock.address);
    let event = events.events().last().unwrap().clone();
    let got = hex::encode(event.to_xdr(Limits::none()).unwrap());
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../sdk/fixtures/settlement_lock/stellar_accumulator_event.hex");
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::write(path, std::format!("{got}\n")).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap().trim(), got);
}
