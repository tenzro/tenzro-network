//! Settlement plan operations under generated input: no panic, a refused
//! operation changes nothing, no sequence creates value, and a decided plan
//! stays decided. `PROPTEST_CASES` bounds each property's cases.

use std::collections::HashMap;
use std::sync::Arc;

use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use tenzro_settlement_fuzz::{PAYER, PAYER_FUNDS, RECIPIENTS, Step, open, prove, session};
use tenzro_storage::{CF_ACCOUNTS, KvStore, MemoryStore};
use tenzro_types::settlement::{PlanOp, PlanStatus};
use tenzro_vm::native::{
    SELECTOR_SETTLEMENT_PLAN, begin_block_plans, plan_vault_address, read_plan,
};
use tenzro_vm::{
    NativeExecutor, StateAdapter, VmConfig, VmExecutor, VmState, VmTransaction, VmType,
};

const CHAIN: u64 = 1337;
const T0: i64 = 1_800_000_000_000;

fn config() -> Config {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48);
    Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    }
}

struct Book {
    ex: NativeExecutor,
    store: Arc<dyn KvStore>,
    state: StateAdapter,
    nonce: u64,
    now: i64,
}

impl Book {
    fn new() -> Self {
        let store: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let mut state = StateAdapter::with_storage(store.clone());
        state.set_balance(&PAYER, PAYER_FUNDS);
        state.commit().unwrap();
        Self {
            ex: NativeExecutor::new(VmConfig::default()).unwrap(),
            store,
            state,
            nonce: 0,
            now: T0,
        }
    }

    /// Every stored balance, summed.
    fn total(&self) -> u128 {
        self.store
            .scan_prefix(CF_ACCOUNTS, b"balance:")
            .unwrap()
            .into_iter()
            .map(|(_, v)| u128::from_le_bytes(v.as_slice().try_into().unwrap()))
            .sum()
    }

    fn watched(&self, plans: &[[u8; 32]]) -> Vec<u128> {
        let mut out: Vec<u128> = RECIPIENTS
            .iter()
            .chain([&PAYER])
            .map(|a| self.state.get_balance(a))
            .collect();
        out.extend(
            plans
                .iter()
                .map(|id| self.state.get_balance(plan_vault_address(id).as_bytes())),
        );
        out
    }

    /// Run `payload` as a SettlementPlan transaction. A refusal leaves no
    /// state, as in a block.
    async fn run(&mut self, payload: Vec<u8>) -> Option<serde_json::Value> {
        let mut data = SELECTOR_SETTLEMENT_PLAN.to_vec();
        data.extend(payload);
        let t = VmTransaction::new(
            PAYER.to_vec(),
            None,
            0,
            data,
            50_000_000,
            0,
            self.nonce,
            VmType::Tenzro,
            CHAIN,
        )
        .with_block_timestamp_ms(self.now);
        self.nonce += 1;
        self.state.begin_transaction();
        let out = match self.ex.execute_transaction(&t, &mut self.state).await {
            Ok(r) if r.success => Some(serde_json::from_slice(&r.output).unwrap_or_default()),
            _ => None,
        };
        if out.is_some() {
            self.state.commit_transaction();
        } else {
            self.state.revert_transaction();
        }
        self.state.commit().unwrap();
        out
    }

    async fn send(&mut self, op: &PlanOp) -> Option<serde_json::Value> {
        self.run(serde_json::to_vec(op).unwrap()).await
    }

    fn block(&mut self, advance_ms: i64) {
        self.now += advance_ms;
        self.state.begin_transaction();
        match begin_block_plans(&mut self.state, self.now) {
            Ok(_) => self.state.commit_transaction(),
            Err(_) => self.state.revert_transaction(),
        }
        self.state.commit().unwrap();
    }
}

fn plan_id(out: &serde_json::Value) -> Option<[u8; 32]> {
    let id = hex::decode(out.get("plan_id")?.as_str()?).ok()?;
    id.try_into().ok()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn an_open_either_decides_value_without_creating_it_or_changes_nothing() {
    let rt = rt();
    TestRunner::new(config())
        .run(&open(T0), |op| {
            rt.block_on(async {
                let mut book = Book::new();
                let (total, watched) = (book.total(), book.watched(&[]));
                match book.send(&op).await {
                    Some(out) => {
                        let id = plan_id(&out).expect("an opened plan names its id");
                        prop_assert!(
                            read_plan(&book.state, &id).is_some(),
                            "an opened plan is stored"
                        );
                        prop_assert!(book.total() <= total, "an open created value");
                    }
                    None => {
                        prop_assert_eq!(book.total(), total, "a refused open moved value");
                        prop_assert_eq!(
                            book.watched(&[]),
                            watched,
                            "a refused open changed a balance"
                        );
                    }
                }
                Ok(())
            })
        })
        .unwrap();
}

#[test]
fn a_proof_for_an_unknown_plan_is_refused() {
    let rt = rt();
    TestRunner::new(config())
        .run(&prove(None), |op| {
            rt.block_on(async {
                let mut book = Book::new();
                let total = book.total();
                prop_assert!(
                    book.send(&op).await.is_none(),
                    "a proof for no plan was accepted: {op:?}"
                );
                prop_assert_eq!(book.total(), total);
                Ok(())
            })
        })
        .unwrap();
}

#[test]
fn arbitrary_payloads_never_panic_and_never_move_value_when_refused() {
    let rt = rt();
    let payloads = prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..1024),
        open(T0).prop_map(|op| {
            // Valid JSON with one byte flipped.
            let mut bytes = serde_json::to_vec(&op).unwrap();
            let i = bytes.len() / 2;
            bytes[i] ^= 0x20;
            bytes
        }),
    ];
    TestRunner::new(config())
        .run(&payloads, |payload| {
            rt.block_on(async {
                let mut book = Book::new();
                let total = book.total();
                if book.run(payload).await.is_none() {
                    prop_assert_eq!(book.total(), total);
                } else {
                    prop_assert!(book.total() <= total);
                }
                Ok(())
            })
        })
        .unwrap();
}

#[test]
fn no_session_creates_value_and_a_decided_plan_stays_decided() {
    let rt = rt();
    TestRunner::new(config())
        .run(&session(T0), |steps| {
            rt.block_on(async {
                let mut book = Book::new();
                let start = book.total();
                let mut plans: Vec<[u8; 32]> = Vec::new();
                let mut decided: HashMap<[u8; 32], PlanStatus> = HashMap::new();
                for step in steps {
                    match step {
                        Step::Open(op) => {
                            if let Some(id) = book.send(&op).await.as_ref().and_then(plan_id) {
                                plans.push(id);
                            }
                        }
                        Step::Prove(n, op) => {
                            let op = match (op, plans.is_empty()) {
                                (
                                    PlanOp::ProveLeg {
                                        index,
                                        evidence,
                                        network_fee,
                                        ..
                                    },
                                    false,
                                ) => PlanOp::ProveLeg {
                                    plan_id: plans[n % plans.len()],
                                    index,
                                    evidence,
                                    network_fee,
                                },
                                (
                                    PlanOp::DisputeRail {
                                        index, evidence, ..
                                    },
                                    false,
                                ) => PlanOp::DisputeRail {
                                    plan_id: plans[n % plans.len()],
                                    index,
                                    evidence,
                                },
                                (op, _) => op,
                            };
                            book.send(&op).await;
                        }
                        Step::Block(ms) => book.block(ms),
                        Step::Raw(bytes) => {
                            book.run(bytes).await;
                        }
                    }
                    prop_assert!(
                        book.total() <= start,
                        "value created: {} > {}",
                        book.total(),
                        start
                    );
                    for id in &plans {
                        let status = read_plan(&book.state, id)
                            .expect("an opened plan stays stored")
                            .status;
                        if let Some(prior) = decided.get(id) {
                            prop_assert_eq!(&status, prior, "a decided plan changed its decision");
                        } else if status != PlanStatus::Open {
                            decided.insert(*id, status);
                        }
                    }
                }
                Ok(())
            })
        })
        .unwrap();
}
