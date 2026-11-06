// SPDX-License-Identifier: Apache-2.0
use super::*;
use cosmwasm_std::{Api, Empty, Timestamp, coins};
use cw_multi_test::{App, AppBuilder, Contract, ContractWrapper, Executor};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

const PROOF: &str = include_str!("../../../crates/tenzro-vm/tests/fixtures/finality_proof.json");
const DID: &str = "did:tenzro:machine:vectors:agent";
const CAIP2: &str = "cosmos:cosmoshub-4";
const CAIP19: &str = "cosmos:cosmoshub-4/bank:uatom";
const NOW_MS: u64 = 1_800_000_001_000;

fn code() -> Box<dyn Contract<Empty>> {
    Box::new(ContractWrapper::new(execute, instantiate, query))
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn node(i: usize) -> (SigningKey, &'static str) {
    let ops = ["did:tenzro:human:operator-a", "did:tenzro:human:operator-b", "did:tenzro:human:operator-a"];
    (SigningKey::from_slice(&[0x11 * (i as u8 + 1); 32]).unwrap(), ops[i])
}

fn sec1(k: &SigningKey) -> [u8; 65] {
    k.verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap()
}

fn pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    sha(&[&[1], lo, hi])
}

fn keys() -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let leaves: Vec<[u8; 32]> = (0..3)
        .map(|i| {
            let (k, op) = node(i);
            sha(&[&[0], &sec1(&k), op.as_bytes()])
        })
        .collect();
    let n01 = pair(&leaves[0], &leaves[1]);
    (pair(&n01, &leaves[2]), vec![vec![leaves[1], leaves[2]], vec![leaves[0], leaves[2]], vec![n01]])
}

struct T {
    app: App,
    registry: Addr,
    account: Addr,
    relayer: Addr,
    seq: u64,
}

fn setup() -> T {
    let relayer = cosmwasm_std::testing::MockApi::default().addr_make("relayer");
    let mut app = AppBuilder::new().build(|_, _, _| {});
    app.update_block(|b| b.time = Timestamp::from_nanos(NOW_MS * 1_000_000));
    let id = app.store_code(code());
    let creator = app.api().addr_make("creator");
    let registry = app
        .instantiate_contract(
            id,
            creator.clone(),
            &InstantiateMsg::Registry {
                image_id: Binary::from([1u8; 32].to_vec()),
                chain_id: 1337,
                genesis_hash: Binary::from([0x6e; 32].to_vec()),
                genesis_committee_root: Binary::from([2u8; 32].to_vec()),
                caip2: CAIP2.into(),
            },
            &[],
            "registry",
            None,
        )
        .unwrap();
    app.execute_contract(creator.clone(), registry.clone(), &ExecuteMsg::CreateAccount { did: DID.into() }, &[]).unwrap();
    let account: Addr = app.wrap().query_wasm_smart(&registry, &QueryMsg::AccountOf { did: DID.into() }).unwrap();
    app.wrap().query_wasm_contract_info(&account).expect("the account is where the registry says");
    app.init_modules(|router, _, storage| router.bank.init_balance(storage, &account, coins(1_000_000, "uatom")).unwrap());
    T { app, registry, account, relayer, seq: 0 }
}

impl T {
    fn word(&self) -> [u8; 32] {
        let c = self.app.api().addr_canonicalize(self.account.as_str()).unwrap();
        let mut w = [0u8; 32];
        w[32 - c.len()..].copy_from_slice(c.as_slice());
        w
    }

    fn grant(&self, seq: u64, void: bool, payload: [u8; 32], targets_root: [u8; 32]) -> Vec<u8> {
        let mut g = vec![1u8];
        g.extend_from_slice(&sha(&[CAIP2.as_bytes()]));
        g.extend_from_slice(&self.word());
        g.extend_from_slice(&sha(&[DID.as_bytes()]));
        g.extend_from_slice(&1u64.to_be_bytes());
        g.extend_from_slice(&seq.to_be_bytes());
        g.extend_from_slice(&(NOW_MS - 1000).to_be_bytes());
        g.extend_from_slice(&(NOW_MS + 600_000).to_be_bytes());
        g.extend_from_slice(&sha(&[CAIP19.as_bytes()]));
        g.extend_from_slice(&1000u128.to_be_bytes());
        g.extend_from_slice(&400u128.to_be_bytes());
        g.extend_from_slice(&300u128.to_be_bytes());
        g.extend_from_slice(&keys().0);
        g.extend_from_slice(&targets_root);
        g.extend_from_slice(&payload);
        g.extend_from_slice(&10u128.to_be_bytes());
        g.push(u8::from(void));
        g
    }

    /// Install `grant` as the only entry of a state tree final at `index`.
    fn install(&mut self, index: u64, grant: &[u8]) -> Result<(), String> {
        let tk = agent::grant_tree_key(DID.as_bytes(), CAIP2.as_bytes());
        let mut s = sha(&[&[0], grant]);
        for i in 0..8 {
            s = if (tk[31] >> i) & 1 == 0 { sha(&[&[3], &s, &[0; 32]]) } else { sha(&[&[3], &[0; 32], &s]) };
        }
        let root = sha(&[&[2], &tk[..31], &s]);
        self.app.contract_storage_mut(&self.registry).set(&checkpoint_key(index), &root);
        let mut proof = vec![0u8, 0, 2];
        proof.extend_from_slice(&[0u8; 256]);
        self.app
            .execute_contract(
                self.relayer.clone(),
                self.account.clone(),
                &ExecuteMsg::Sync {
                    index,
                    grant: Binary::from(grant.to_vec()),
                    proof: Binary::from(proof),
                    caip19: CAIP19.into(),
                    payee: Binary::from([7u8; 32].to_vec()),
                },
                &[],
            )
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }

    fn target(&self) -> Vec<u8> {
        self.app.api().addr_canonicalize(self.app.api().addr_make("payee").as_str()).unwrap().to_vec()
    }

    fn action(&self, target: &[u8], amount: u128, refund: u128) -> Vec<u8> {
        let mut a = (target.len() as u16).to_be_bytes().to_vec();
        a.extend_from_slice(target);
        a.extend_from_slice(&9u16.to_be_bytes());
        a.extend_from_slice(b"bank_send");
        a.extend_from_slice(&amount.to_be_bytes());
        a.extend_from_slice(&refund.to_be_bytes());
        a.extend_from_slice(&0u32.to_be_bytes());
        a
    }

    fn signer(&self, i: usize, action: &[u8], nonce: u64, high_s: bool) -> ActSigner {
        let (k, op) = node(i);
        let mut m = agent::ACT_DOMAIN.to_vec();
        m.extend_from_slice(&sha(&[CAIP2.as_bytes()]));
        m.extend_from_slice(&self.word());
        m.extend_from_slice(&self.seq.to_be_bytes());
        m.extend_from_slice(&nonce.to_be_bytes());
        m.extend_from_slice(action);
        let sig: Signature = k.sign(&m);
        let low = sig.normalize_s().unwrap_or(sig);
        let bytes: [u8; 64] = if high_s {
            let (r, s) = low.split_scalars();
            Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap().to_bytes().into()
        } else {
            low.to_bytes().into()
        };
        ActSigner {
            key: Binary::from(sec1(&k).to_vec()),
            operator: op.into(),
            proof: keys().1[i].iter().map(|p| Binary::from(p.to_vec())).collect(),
            signature: Binary::from(bytes.to_vec()),
        }
    }

    fn act(&mut self, action: &[u8], signers: Vec<ActSigner>, target_proof: Vec<Binary>) -> Result<(), String> {
        self.app
            .execute_contract(
                self.relayer.clone(),
                self.account.clone(),
                &ExecuteMsg::Act { action: Binary::from(action.to_vec()), signers, target_proof },
                &[],
            )
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }
}

fn open() -> T {
    let mut t = setup();
    t.seq = 1;
    let g = t.grant(1, false, [0; 32], [0; 32]);
    t.install(1, &g).unwrap();
    t
}

#[test]
fn the_registry_accepts_a_real_recorded_finality_proof() {
    let v: serde_json::Value = serde_json::from_str(PROOF).unwrap();
    let h = |k: &str| hex::decode(v[k].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let mut app = App::default();
    let id = app.store_code(code());
    let creator = app.api().addr_make("creator");
    let registry = app
        .instantiate_contract(
            id,
            creator.clone(),
            &InstantiateMsg::Registry {
                image_id: Binary::from(h("image_id")),
                chain_id: 1337,
                genesis_hash: Binary::from([0x6e; 32].to_vec()),
                genesis_committee_root: Binary::from(
                    hex::decode("f17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481").unwrap(),
                ),
                caip2: CAIP2.into(),
            },
            &[],
            "registry",
            None,
        )
        .unwrap();
    app.execute_contract(
        creator,
        registry.clone(),
        &ExecuteMsg::SubmitCheckpoint { journal: Binary::from(h("journal")), seal: Binary::from(h("evm_seal")) },
        &[],
    )
    .unwrap();
    let root: Binary = app.wrap().query_wasm_smart(&registry, &QueryMsg::StateRoot { index: 7 }).unwrap();
    assert_eq!(root.to_vec(), vec![0x5e; 32]);
}

#[test]
fn the_account_address_is_instantiate2_of_the_registry_code_and_did() {
    let t = setup();
    let info = t.app.wrap().query_wasm_contract_info(&t.registry).unwrap();
    let code = t.app.wrap().query_wasm_code_info(info.code_id).unwrap();
    let creator = t.app.api().addr_canonicalize(t.registry.as_str()).unwrap();
    let expected = instantiate2_address(code.checksum.as_slice(), &creator, &salt(DID)).unwrap();
    assert_eq!(t.app.api().addr_humanize(&expected).unwrap(), t.account);
}

#[test]
fn a_signed_action_sends_and_refunds() {
    let mut t = open();
    let target = t.target();
    let a = t.action(&target, 100, 5);
    let s = t.signer(0, &a, 0, false);
    t.act(&a, vec![s.clone()], vec![]).unwrap();
    let payee = t.app.api().addr_make("payee");
    assert_eq!(t.app.wrap().query_balance(&payee, "uatom").unwrap().amount.to_string(), "100");
    assert_eq!(t.app.wrap().query_balance(&t.relayer, "uatom").unwrap().amount.to_string(), "5");
    assert!(t.act(&a, vec![s], vec![]).is_err(), "a replay");
}

#[test]
fn every_rule_of_the_grant_holds() {
    let mut t = open();
    let target = t.target();
    let a = t.action(&target, 100, 0);
    assert!(t.act(&a, vec![t.signer(0, &a, 0, true)], vec![]).unwrap_err().contains("low-S"));
    let mut wrong = t.signer(0, &a, 0, false);
    wrong.signature = t.signer(1, &a, 0, false).signature;
    assert!(t.act(&a, vec![wrong], vec![]).unwrap_err().contains("does not verify"));
    let mut stranger = t.signer(0, &a, 0, false);
    let k = SigningKey::from_slice(&[0x44; 32]).unwrap();
    let mut m = agent::ACT_DOMAIN.to_vec();
    m.extend_from_slice(&sha(&[CAIP2.as_bytes()]));
    m.extend_from_slice(&t.word());
    m.extend_from_slice(&1u64.to_be_bytes());
    m.extend_from_slice(&0u64.to_be_bytes());
    m.extend_from_slice(&a);
    let sig: Signature = k.sign(&m);
    stranger.key = Binary::from(sec1(&k).to_vec());
    stranger.signature = Binary::from(sig.normalize_s().unwrap_or(sig).to_bytes().to_vec());
    assert!(t.act(&a, vec![stranger], vec![]).unwrap_err().contains("key not in root"));
    let over = t.action(&target, 401, 0);
    assert!(t.act(&over, vec![t.signer(0, &over, 0, false)], vec![]).unwrap_err().contains("per-action"));
    let refund = t.action(&target, 100, 11);
    assert!(t.act(&refund, vec![t.signer(0, &refund, 0, false)], vec![]).unwrap_err().contains("refund"));
    let big = t.action(&target, 350, 0);
    assert!(t.act(&big, vec![t.signer(0, &big, 0, false)], vec![]).unwrap_err().contains("cosign"));
    assert!(t.act(&big, vec![t.signer(0, &big, 0, false), t.signer(2, &big, 0, false)], vec![]).unwrap_err().contains("cosign"));
    t.act(&big, vec![t.signer(0, &big, 0, false), t.signer(1, &big, 0, false)], vec![]).unwrap();
    t.act(&big, vec![t.signer(0, &big, 1, false), t.signer(1, &big, 1, false)], vec![]).unwrap();
    assert!(t.act(&big, vec![t.signer(0, &big, 2, false), t.signer(1, &big, 2, false)], vec![]).unwrap_err().contains("budget"));
}

#[test]
fn targets_voids_staleness_and_time_hold() {
    let mut t = setup();
    t.seq = 1;
    let target = t.target();
    let leaf = agent::target_leaf(&target, b"bank_send");
    let other = agent::target_leaf(b"elsewhere", b"bank_send");
    let root = pair(&leaf, &other);
    let g = t.grant(1, false, [0; 32], root);
    t.install(1, &g).unwrap();
    let a = t.action(&target, 10, 0);
    let s = t.signer(0, &a, 0, false);
    assert!(t.act(&a, vec![s.clone()], vec![]).unwrap_err().contains("target"));
    t.act(&a, vec![s], vec![Binary::from(other.to_vec())]).unwrap();
    let mut v = g.clone();
    v[321] = 1;
    t.install(2, &v).unwrap();
    let a1 = t.action(&target, 10, 0);
    assert!(t.act(&a1, vec![t.signer(0, &a1, 1, false)], vec![Binary::from(other.to_vec())]).unwrap_err().contains("void"));
    assert!(t.install(3, &g).unwrap_err().contains("stale"));
    let mut t = open();
    t.app.update_block(|b| b.time = Timestamp::from_nanos((NOW_MS + 600_001) * 1_000_000));
    let a = t.action(&t.target(), 10, 0);
    assert!(t.act(&a, vec![t.signer(0, &a, 0, false)], vec![]).unwrap_err().contains("time window"));
}

#[test]
fn an_exact_grant_runs_once_and_a_foreign_grant_is_refused() {
    let mut t = setup();
    let target = t.target();
    let a = t.action(&target, 100, 0);
    let g = t.grant(1, false, sha(&[&a]), [0; 32]);
    t.install(1, &g).unwrap();
    let exact = |t: &mut T| {
        t.app
            .execute_contract(t.relayer.clone(), t.account.clone(), &ExecuteMsg::ActExact { action: Binary::from(a.clone()) }, &[])
            .map_err(|e| format!("{e:?}"))
    };
    exact(&mut t).unwrap();
    assert!(exact(&mut t).unwrap_err().contains("used"));
    let mut other = t.grant(2, false, [0; 32], [0; 32]);
    other[40] ^= 1;
    assert!(t.install(2, &other).unwrap_err().contains("another"));
}

#[test]
fn a_paying_action_reports_the_payment_for_tenzro() {
    let mut t = open();
    let target = t.target();
    let mut data = vec![0x55u8; 32];
    data.extend_from_slice(&[1; 32]);
    data.extend_from_slice(&[2; 32]);
    data.extend_from_slice(&30u64.to_be_bytes());
    let action = |data: &[u8]| {
        let mut a = (target.len() as u16).to_be_bytes().to_vec();
        a.extend_from_slice(&target);
        a.extend_from_slice(&(agent::PAY_SELECTOR.len() as u16).to_be_bytes());
        a.extend_from_slice(agent::PAY_SELECTOR);
        a.extend_from_slice(&100u128.to_be_bytes());
        a.extend_from_slice(&0u128.to_be_bytes());
        a.extend_from_slice(&(data.len() as u32).to_be_bytes());
        a.extend_from_slice(data);
        a
    };
    let short = action(&data[..103]);
    let s = t.signer(0, &short, 0, false);
    assert!(t.act(&short, vec![s], vec![]).unwrap_err().contains("payee, request, quote and price"));

    let a = action(&data);
    let s = t.signer(0, &a, 0, false);
    let res = t
        .app
        .execute_contract(
            t.relayer.clone(),
            t.account.clone(),
            &ExecuteMsg::Act { action: Binary::from(a.clone()), signers: vec![s], target_proof: vec![] },
            &[],
        )
        .unwrap();
    let report = res
        .events
        .iter()
        .find(|e| e.ty == "wasm-reported")
        .and_then(|e| e.attributes.iter().find(|x| x.key == "report"))
        .map(|x| hex::decode(&x.value).unwrap())
        .expect("a payment report");
    let mut expected = vec![4u8];
    expected.extend_from_slice(&sha(&[CAIP2.as_bytes()]));
    expected.extend_from_slice(&t.word());
    expected.extend_from_slice(&sha(&[DID.as_bytes()]));
    expected.extend_from_slice(&t.seq.to_be_bytes());
    expected.extend_from_slice(&0u64.to_be_bytes());
    expected.extend_from_slice(&data);
    expected.extend_from_slice(&100u128.to_be_bytes());
    assert_eq!(report, expected);
    let payee = t.app.api().addr_make("payee");
    assert_eq!(t.app.wrap().query_balance(&payee, "uatom").unwrap().amount.to_string(), "100");
}

/// A contract that keeps the last message and funds it was called with.
fn recorder() -> Box<dyn Contract<Empty>> {
    Box::new(ContractWrapper::new(
        |deps: DepsMut, _env: Env, info: MessageInfo, msg: serde_json::Value| -> StdResult<Response> {
            deps.storage.set(b"msg", &cosmwasm_std::to_json_vec(&msg)?);
            deps.storage.set(b"funds", &cosmwasm_std::to_json_vec(&info.funds)?);
            Ok(Response::new())
        },
        |_: DepsMut, _: Env, _: MessageInfo, _: Empty| -> StdResult<Response> { Ok(Response::new()) },
        |deps: Deps, _: Env, key: String| -> StdResult<Binary> {
            Ok(Binary::from(deps.storage.get(key.as_bytes()).unwrap_or_default()))
        },
    ))
}

#[test]
fn an_execute_action_calls_the_lock_with_exactly_its_amount() {
    let mut t = open();
    let id = t.app.store_code(recorder());
    let creator = t.app.api().addr_make("creator");
    let lock = t.app.instantiate_contract(id, creator, &Empty {}, &[], "lock", None).unwrap();
    let msg = br#"{"lock":{"plan_id":"AA==","index":0,"recipient":"r"}}"#;
    let target = t.app.api().addr_canonicalize(lock.as_str()).unwrap().to_vec();
    let mut a = (target.len() as u16).to_be_bytes().to_vec();
    a.extend_from_slice(&target);
    a.extend_from_slice(&(EXECUTE_SELECTOR.len() as u16).to_be_bytes());
    a.extend_from_slice(EXECUTE_SELECTOR);
    a.extend_from_slice(&100u128.to_be_bytes());
    a.extend_from_slice(&5u128.to_be_bytes());
    a.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    a.extend_from_slice(msg);
    let s = t.signer(0, &a, 0, false);
    t.act(&a, vec![s], vec![]).unwrap();
    let funds: Vec<Coin> = t.app.wrap().query_wasm_smart(&lock, &"funds").unwrap();
    assert_eq!(funds, coins(100, "uatom"));
    let got: serde_json::Value = t.app.wrap().query_wasm_smart(&lock, &"msg").unwrap();
    assert_eq!(got, serde_json::from_slice::<serde_json::Value>(msg).unwrap());
    assert_eq!(t.app.wrap().query_balance(&lock, "uatom").unwrap().amount.to_string(), "100");
    assert_eq!(t.app.wrap().query_balance(&t.account, "uatom").unwrap().amount.to_string(), "999895");
}
