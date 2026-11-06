// SPDX-License-Identifier: Apache-2.0
use super::*;
use cosmwasm_std::{Empty, Timestamp, coins};
use cw_multi_test::{App, AppBuilder, Contract, ContractWrapper, Executor};

const VECTORS: &str = include_str!("../../../../sdk/fixtures/settlement_lock/vectors.json");
const CHECKPOINT: u64 = 7;
const HORIZON: u64 = 3_600;

fn lock_code() -> Box<dyn Contract<Empty>> {
    Box::new(ContractWrapper::new(execute, instantiate, query))
}

// A registry holding one final checkpoint whose state root is the vectors'.
fn registry_code() -> Box<dyn Contract<Empty>> {
    Box::new(ContractWrapper::new(
        |_: DepsMut, _: Env, _: MessageInfo, _: Empty| -> StdResult<Response> { Ok(Response::new()) },
        |deps: DepsMut, _: Env, _: MessageInfo, root: Binary| -> StdResult<Response> {
            deps.storage.set(b"root", root.as_slice());
            Ok(Response::new())
        },
        |deps: Deps, _: Env, q: RegistryQuery| -> StdResult<Binary> {
            let RegistryQuery::StateRoot { index } = q;
            if index != CHECKPOINT {
                return Err(err(format!("no final checkpoint {index}")));
            }
            to_json_binary(&Binary::from(deps.storage.get(b"root").unwrap()))
        },
    ))
}

fn hex(v: &serde_json::Value) -> Binary {
    Binary::from(hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap())
}

struct T {
    app: App,
    lock: Addr,
    payer: Addr,
    recipient: Addr,
    v: serde_json::Value,
}

fn setup() -> T {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let mut app = AppBuilder::new().build(|_, _, _| {});
    app.update_block(|b| b.time = Timestamp::from_seconds(1_800_000_000));
    let payer = app.api().addr_make("payer");
    let recipient = app.api().addr_make("recipient");
    app.init_modules(|router, _, storage| router.bank.init_balance(storage, &payer, coins(1_000, "uatom")).unwrap());
    let rid = app.store_code(registry_code());
    let lid = app.store_code(lock_code());
    let registry = app.instantiate_contract(rid, payer.clone(), &hex(&v["root"]), &[], "registry", None).unwrap();
    let lock = app
        .instantiate_contract(
            lid,
            payer.clone(),
            &InstantiateMsg { registry: registry.to_string(), escape_horizon: HORIZON },
            &[],
            "lock",
            None,
        )
        .unwrap();
    T { app, lock, payer, recipient, v }
}

impl T {
    fn plan(&self, which: &str) -> Binary {
        hex(&self.v[which]["plan_id"])
    }
    fn lock_leg(&mut self, which: &str, index: u8) {
        let msg = ExecuteMsg::Lock { plan_id: self.plan(which), index, recipient: self.recipient.to_string() };
        self.app.execute_contract(self.payer.clone(), self.lock.clone(), &msg, &coins(100, "uatom")).unwrap();
    }
    fn settle(&mut self, which: &str, index: u8, proof_of: &str, checkpoint: u64) -> bool {
        let msg = ExecuteMsg::Settle {
            plan_id: self.plan(which),
            index,
            checkpoint,
            decision: hex(&self.v[proof_of]["decision"]),
            proof: hex(&self.v[proof_of]["proof"]),
        };
        let anyone = self.app.api().addr_make("relayer");
        self.app.execute_contract(anyone, self.lock.clone(), &msg, &[]).is_ok()
    }
    fn balance(&self, a: &Addr) -> u128 {
        self.app.wrap().query_balance(a, "uatom").unwrap().amount.to_string().parse().unwrap()
    }
}

#[test]
fn leg_ids_match_tenzro() {
    let t = setup();
    for which in ["committed", "aborted", "undecided"] {
        for i in 0..3u8 {
            let id: Binary = t.app.wrap().query_wasm_smart(&t.lock, &QueryMsg::LegId { plan_id: t.plan(which), index: i }).unwrap();
            assert_eq!(id, hex(&t.v[which]["leg_ids"][i as usize]));
        }
    }
}

#[test]
fn a_commit_pays_the_recipient_once() {
    let mut t = setup();
    t.lock_leg("committed", 1);
    assert_eq!(t.balance(&t.payer), 900);
    assert!(t.settle("committed", 1, "committed", CHECKPOINT));
    assert_eq!(t.balance(&t.recipient), 100);
    assert!(!t.settle("committed", 1, "committed", CHECKPOINT), "replay");
    let leg: Leg = t.app.wrap().query_wasm_smart(&t.lock, &QueryMsg::Leg { plan_id: t.plan("committed"), index: 1 }).unwrap();
    assert_eq!(leg.stage, Stage::Released);
    assert_eq!(t.balance(&t.recipient), 100);
}

#[test]
fn an_abort_refunds_the_payer() {
    let mut t = setup();
    t.lock_leg("aborted", 0);
    assert!(t.settle("aborted", 0, "aborted", CHECKPOINT));
    assert_eq!(t.balance(&t.payer), 1_000);
    assert_eq!(t.balance(&t.recipient), 0);
}

#[test]
fn a_foreign_forged_or_unanchored_decision_moves_nothing() {
    let mut t = setup();
    t.lock_leg("undecided", 0);
    // Another plan's proven commit.
    assert!(!t.settle("undecided", 0, "committed", CHECKPOINT));
    // A checkpoint the registry does not hold.
    t.lock_leg("committed", 0);
    assert!(!t.settle("committed", 0, "committed", CHECKPOINT + 1));
    // A decision rewritten to abort under the commit's proof.
    let mut forged = hex(&t.v["committed"]["decision"]).to_vec();
    forged[1] = 2;
    let msg = ExecuteMsg::Settle {
        plan_id: t.plan("committed"),
        index: 0,
        checkpoint: CHECKPOINT,
        decision: Binary::from(forged),
        proof: hex(&t.v["committed"]["proof"]),
    };
    assert!(t.app.execute_contract(t.payer.clone(), t.lock.clone(), &msg, &[]).is_err());
    assert_eq!(t.balance(&t.lock), 200);
}

#[test]
fn an_undecided_leg_escapes_only_after_the_horizon() {
    let mut t = setup();
    t.lock_leg("undecided", 2);
    let escape = ExecuteMsg::Escape { plan_id: t.plan("undecided"), index: 2 };
    assert!(t.app.execute_contract(t.payer.clone(), t.lock.clone(), &escape, &[]).is_err());
    t.app.update_block(|b| b.time = b.time.plus_seconds(HORIZON));
    t.app.execute_contract(t.payer.clone(), t.lock.clone(), &escape, &[]).unwrap();
    assert_eq!(t.balance(&t.payer), 1_000);
    assert!(t.app.execute_contract(t.payer.clone(), t.lock.clone(), &escape, &[]).is_err());
}

#[test]
fn a_leg_locks_once_with_one_nonzero_coin() {
    let mut t = setup();
    t.lock_leg("committed", 0);
    let msg = ExecuteMsg::Lock { plan_id: t.plan("committed"), index: 0, recipient: t.recipient.to_string() };
    assert!(t.app.execute_contract(t.payer.clone(), t.lock.clone(), &msg, &coins(100, "uatom")).is_err());
    let msg = ExecuteMsg::Lock { plan_id: t.plan("committed"), index: 1, recipient: t.recipient.to_string() };
    assert!(t.app.execute_contract(t.payer.clone(), t.lock.clone(), &msg, &[]).is_err());
}

/// The stored leg is the JSON Tenzro's light client reads from the wasm store.
#[test]
fn the_stored_leg_is_the_json_tenzro_reads() {
    let leg = Leg {
        payer: Addr::unchecked("payer"),
        recipient: Addr::unchecked("recipient"),
        coin: Coin::new(700u128, "uatom"),
        escape_at: 1_801_209_600,
        stage: Stage::Locked,
    };
    assert_eq!(
        String::from_utf8(cosmwasm_std::to_json_vec(&leg).unwrap()).unwrap(),
        r#"{"payer":"payer","recipient":"recipient","coin":{"denom":"uatom","amount":"700"},"escape_at":1801209600,"stage":"locked"}"#
    );
}

#[test]
fn the_reconciliation_hash_matches_the_shared_vector() {
    let rv: serde_json::Value =
        serde_json::from_str(include_str!("../../../../sdk/fixtures/settlement_lock/recon.json")).unwrap();
    let mut t = setup();
    let payer = t.payer.clone();
    t.app.init_modules(|router, _, storage| router.bank.init_balance(storage, &payer, coins(2_000_000_000_000_000_000, "uatom")).unwrap());
    let lock = |t: &mut T, which: &str, index: u8, amount: u128| {
        let msg = ExecuteMsg::Lock { plan_id: t.plan(which), index, recipient: t.recipient.to_string() };
        t.app.execute_contract(t.payer.clone(), t.lock.clone(), &msg, &coins(amount, "uatom")).unwrap();
    };
    let recon = |t: &T| -> Recon { t.app.wrap().query_wasm_smart(&t.lock, &QueryMsg::Reconciliation {}).unwrap() };
    let acc = |x: &serde_json::Value| x.as_str().unwrap().trim_start_matches("0x").to_string();
    lock(&mut t, "committed", 0, 400);
    assert_eq!(recon(&t), Recon { count: 1, acc: acc(&rv["entries"][0]["acc"]) });
    lock(&mut t, "aborted", 2, 1_000_000_000_000_000_000);
    assert!(t.settle("committed", 0, "committed", CHECKPOINT));
    assert!(t.settle("aborted", 2, "aborted", CHECKPOINT));
    lock(&mut t, "undecided", 1, 250);
    t.app.update_block(|b| b.time = b.time.plus_seconds(HORIZON));
    let escape = ExecuteMsg::Escape { plan_id: t.plan("undecided"), index: 1 };
    t.app.execute_contract(t.payer.clone(), t.lock.clone(), &escape, &[]).unwrap();
    assert_eq!(recon(&t), Recon { count: rv["count"].as_u64().unwrap(), acc: acc(&rv["acc"]) });

    // The stored checkpoint is the entry Tenzro's light client proves.
    let stored = t.app.wrap().query_wasm_raw(&t.lock, RECON.to_vec()).unwrap().unwrap();
    let got = String::from_utf8(stored).unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../sdk/fixtures/settlement_lock/cosmwasm_recon_entry.json");
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::write(path, format!("{got}\n")).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap().trim(), got);
}
