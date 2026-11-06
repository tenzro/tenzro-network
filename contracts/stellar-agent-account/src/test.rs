// SPDX-License-Identifier: Apache-2.0
extern crate std;

use super::*;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::auth::ContractContext;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{IntoVal, Val, contract, contractimpl, vec};
use std::vec::Vec as StdVec;

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

const DID: &[u8] = b"did:tenzro:machine:vectors:agent";
const CAIP2: &[u8] = b"stellar:pubnet";
const NOW_MS: u64 = 1_800_000_001_000;
const VECTORS: &str = include_str!("../../../sdk/fixtures/remote_grant/vectors.json");

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

/// Leaves of the three test nodes, the root and each one's proof.
fn keys() -> ([u8; 32], StdVec<StdVec<[u8; 32]>>) {
    let leaves: StdVec<[u8; 32]> = (0..3).map(|i| {
        let (k, op) = node(i);
        sha(&[&[0], &sec1(&k), op.as_bytes()])
    }).collect();
    let n01 = pair(&leaves[0], &leaves[1]);
    let root = pair(&n01, &leaves[2]);
    (root, std::vec![std::vec![leaves[1], leaves[2]], std::vec![leaves[0], leaves[2]], std::vec![n01]])
}

struct T {
    env: Env,
    account: Address,
    finality: Address,
    token: Address,
    caip19: std::string::String,
    seq: u64,
}

fn strkey(a: &Address) -> std::string::String {
    let s = a.to_string();
    let mut b = [0u8; 56];
    s.copy_into_slice(&mut b);
    std::string::String::from_utf8(b.to_vec()).unwrap()
}

fn setup() -> T {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().set_timestamp(NOW_MS / 1000);
    let finality = env.register(MockFinality, ());
    let account = env.register(AgentAccount, (Bytes::from_slice(&env, DID), Bytes::from_slice(&env, CAIP2), finality.clone()));
    let admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(admin);
    let token = sac.address();
    env.mock_all_auths();
    soroban_sdk::token::StellarAssetClient::new(&env, &token).mint(&account, &1_000_000);
    env.set_auths(&[]);
    let caip19 = std::format!("stellar:pubnet/sep41:{}", strkey(&token));
    T { env, account, finality, token, caip19, seq: 0 }
}

impl T {
    fn id(&self, a: &Address) -> [u8; 32] {
        contract_id(a).unwrap()
    }

    fn grant(&self, seq: u64, void: bool, payload: [u8; 32], targets_root: [u8; 32]) -> StdVec<u8> {
        let mut g = std::vec![1u8];
        g.extend_from_slice(&sha(&[CAIP2]));
        g.extend_from_slice(&self.id(&self.account));
        g.extend_from_slice(&sha(&[DID]));
        g.extend_from_slice(&1u64.to_be_bytes());
        g.extend_from_slice(&seq.to_be_bytes());
        g.extend_from_slice(&(NOW_MS - 1000).to_be_bytes());
        g.extend_from_slice(&(NOW_MS + 600_000).to_be_bytes());
        g.extend_from_slice(&sha(&[self.caip19.as_bytes()]));
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

    /// Install `grant` as the only entry of a state tree.
    fn install(&mut self, index: u64, grant: &[u8]) -> std::result::Result<(), Error> {
        let tk = agent::grant_tree_key(DID, CAIP2);
        let mut s = sha(&[&[0], grant]);
        let slot = tk[31];
        for i in 0..8 {
            s = if (slot >> i) & 1 == 0 { sha(&[&[3], &s, &[0; 32]]) } else { sha(&[&[3], &[0; 32], &s]) };
        }
        let root = sha(&[&[2], &tk[..31], &s]);
        MockFinalityClient::new(&self.env, &self.finality).set(&index, &BytesN::from_array(&self.env, &root));
        let mut proof = std::vec![0u8, 0, 2];
        proof.extend_from_slice(&[0u8; 256]);
        let c = AgentAccountClient::new(&self.env, &self.account);
        let r = c.try_sync(
            &index,
            &Bytes::from_slice(&self.env, grant),
            &Bytes::from_slice(&self.env, &proof),
            &String::from_str(&self.env, &self.caip19),
            &BytesN::from_array(&self.env, &[0x77; 32]),
        );
        match r {
            Ok(_) => Ok(()),
            Err(Ok(e)) => Err(e),
            Err(Err(_)) => panic!("sync trapped"),
        }
    }

    fn action(&self, target: &Address, f: &str, amount: u128, refund: u128, data: &[u8]) -> StdVec<u8> {
        let t = self.id(target);
        let mut a = 32u16.to_be_bytes().to_vec();
        a.extend_from_slice(&t);
        a.extend_from_slice(&(f.len() as u16).to_be_bytes());
        a.extend_from_slice(f.as_bytes());
        a.extend_from_slice(&amount.to_be_bytes());
        a.extend_from_slice(&refund.to_be_bytes());
        a.extend_from_slice(&(data.len() as u32).to_be_bytes());
        a.extend_from_slice(data);
        a
    }

    fn preimage(&self, action: &[u8], nonce: u64) -> StdVec<u8> {
        let mut m = b"tenzro/agent-act/v1".to_vec();
        m.extend_from_slice(&sha(&[CAIP2]));
        m.extend_from_slice(&self.id(&self.account));
        m.extend_from_slice(&self.seq.to_be_bytes());
        m.extend_from_slice(&nonce.to_be_bytes());
        m.extend_from_slice(action);
        m
    }

    fn signer(&self, i: usize, message: &[u8], high_s: bool) -> Signer {
        let (k, op) = node(i);
        let sig: Signature = k.sign(message);
        let low = sig.normalize_s().unwrap_or(sig);
        let bytes: [u8; 64] = if high_s {
            let (r, s) = low.split_scalars();
            Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap().to_bytes().into()
        } else {
            low.to_bytes().into()
        };
        let proof = keys().1[i].clone();
        Signer {
            key: BytesN::from_array(&self.env, &sec1(&k)),
            operator: Bytes::from_slice(&self.env, op.as_bytes()),
            proof: Vec::from_iter(&self.env, proof.iter().map(|p| BytesN::from_array(&self.env, p))),
            signature: BytesN::from_array(&self.env, &bytes),
        }
    }

    /// Authorize `token.transfer(account, to, amount)` with `signers` over
    /// the action.
    fn check(&self, payload: [u8; 32], action: &[u8], signers: StdVec<Signer>, contract: &Address, f: &str, amount: i128) -> std::result::Result<(), std::string::String> {
        let to = Address::generate(&self.env);
        let args: soroban_sdk::Vec<Val> = vec![&self.env, self.account.into_val(&self.env), to.into_val(&self.env), amount.into_val(&self.env)];
        let ctx = Context::Contract(ContractContext { contract: contract.clone(), fn_name: Symbol::new(&self.env, f), args });
        let auth = ActAuth {
            action: Bytes::from_slice(&self.env, action),
            signers: Vec::from_iter(&self.env, signers),
            target_proof: Vec::new(&self.env),
        };
        self.env
            .try_invoke_contract_check_auth::<Error>(&self.account, &BytesN::from_array(&self.env, &payload), auth.into_val(&self.env), &vec![&self.env, ctx])
            .map_err(|e| std::format!("{e:?}"))
    }
}

fn ok_open() -> (T, StdVec<u8>) {
    let mut t = setup();
    t.seq = 1;
    let g = t.grant(1, false, [0; 32], [0; 32]);
    t.install(1, &g).unwrap();
    (t, g)
}

#[test]
fn the_account_is_where_tenzro_derives_it() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let c = v["chains"].as_array().unwrap().iter().find(|c| c["chain"] == "stellar:pubnet").unwrap();
    let env = Env::default();
    env.ledger().set_network_id(sha(&[b"Public Global Stellar Network ; September 2015"]));
    let factory = Address::from_payload(&env, soroban_sdk::address_payload::AddressPayload::ContractIdHash(BytesN::from_array(&env, &[0x66; 32])));
    let salt: [u8; 32] = hex::decode(c["salt"].as_str().unwrap()).unwrap().try_into().unwrap();
    let at = env.deployer().with_address(factory, BytesN::from_array(&env, &salt)).deployed_address();
    assert_eq!(strkey(&at), c["account"].as_str().unwrap());
    assert_eq!(hex::encode(agent::grant_tree_key(DID, CAIP2)), c["tree_key"].as_str().unwrap());
}

#[test]
fn a_signed_transfer_is_authorized_once() {
    let (t, _) = ok_open();
    let payload = [9u8; 32];
    let a = t.action(&t.token, "transfer", 100, 0, &payload);
    let m = t.preimage(&a, 0);
    t.env.cost_estimate().budget().reset_default();
    t.check(payload, &a, std::vec![t.signer(0, &m, false)], &t.token, "transfer", 100).unwrap();
    std::println!("check_auth: {} cpu instructions", t.env.cost_estimate().budget().cpu_instruction_cost());
    t.env.cost_estimate().budget().reset_unlimited();
    assert_eq!(AgentAccountClient::new(&t.env, &t.account).nonce(), 1);
    assert_eq!(AgentAccountClient::new(&t.env, &t.account).spent(), 100);
    // The same signed action again: the nonce moved on.
    assert!(t.check(payload, &a, std::vec![t.signer(0, &m, false)], &t.token, "transfer", 100).is_err());
}

#[test]
fn every_rule_of_the_grant_holds() {
    let (t, _) = ok_open();
    let p = [9u8; 32];
    let a = t.action(&t.token, "transfer", 100, 0, &p);
    let m = t.preimage(&a, 0);
    let err = |r: std::result::Result<(), std::string::String>, code: &str| {
        let e = r.unwrap_err();
        assert!(e.contains(code), "{e} does not name {code}");
    };
    // Another authorization payload.
    err(t.check([8; 32], &a, std::vec![t.signer(0, &m, false)], &t.token, "transfer", 100), "PayloadMismatch");
    err(t.check(p, &a, std::vec![t.signer(0, &m, true)], &t.token, "transfer", 100), "HighS");
    // A key outside the root.
    let mut stranger = t.signer(0, &m, false);
    let k = SigningKey::from_slice(&[0x44; 32]).unwrap();
    let sig: Signature = k.sign(&m[..]);
    stranger.key = BytesN::from_array(&t.env, &sec1(&k));
    stranger.signature = BytesN::from_array(&t.env, &sig.normalize_s().unwrap_or(sig).to_bytes().into());
    err(t.check(p, &a, std::vec![stranger], &t.token, "transfer", 100), "KeyNotInRoot");
    // A signature by another key traps in the host.
    assert!(t.check(p, &a, std::vec![t.signer(1, &t.preimage(&a, 7), false)], &t.token, "transfer", 100).is_err());
    // The amount the call moves is the action's.
    err(t.check(p, &a, std::vec![t.signer(0, &m, false)], &t.token, "transfer", 101), "AmountMismatch");
    // Another contract than the action names.
    let other = t.env.register_stellar_asset_contract_v2(Address::generate(&t.env)).address();
    err(t.check(p, &a, std::vec![t.signer(0, &m, false)], &other, "transfer", 100), "TargetNotAllowed");
    let a2 = t.action(&other, "transfer", 100, 0, &p);
    let m2 = t.preimage(&a2, 0);
    err(t.check(p, &a2, std::vec![t.signer(0, &m2, false)], &other, "transfer", 100), "AssetMismatch");
    let big = t.action(&t.token, "transfer", 401, 0, &p);
    let mb = t.preimage(&big, 0);
    err(t.check(p, &big, std::vec![t.signer(0, &mb, false), t.signer(1, &mb, false)], &t.token, "transfer", 401), "OverPerAction");
    let refund = t.action(&t.token, "transfer", 100, 11, &p);
    let mr = t.preimage(&refund, 0);
    err(t.check(p, &refund, std::vec![t.signer(0, &mr, false)], &t.token, "transfer", 100), "RelayOverCap");
    let cos = t.action(&t.token, "transfer", 350, 0, &p);
    let mc = t.preimage(&cos, 0);
    err(t.check(p, &cos, std::vec![t.signer(0, &mc, false)], &t.token, "transfer", 350), "CosignRequired");
    err(t.check(p, &cos, std::vec![t.signer(0, &mc, false), t.signer(2, &mc, false)], &t.token, "transfer", 350), "CosignRequired");
    t.check(p, &cos, std::vec![t.signer(0, &mc, false), t.signer(1, &mc, false)], &t.token, "transfer", 350).unwrap();
    let mc1 = t.preimage(&cos, 1);
    t.check(p, &cos, std::vec![t.signer(0, &mc1, false), t.signer(1, &mc1, false)], &t.token, "transfer", 350).unwrap();
    let mc2 = t.preimage(&cos, 2);
    err(t.check(p, &cos, std::vec![t.signer(0, &mc2, false), t.signer(1, &mc2, false)], &t.token, "transfer", 350), "OverBudget");
}

#[test]
fn a_void_stops_everything_and_a_stale_grant_is_refused() {
    let (mut t, g) = ok_open();
    let mut v = g.clone();
    v[321] = 1;
    t.install(2, &v).unwrap();
    let p = [9u8; 32];
    let a = t.action(&t.token, "transfer", 100, 0, &p);
    let m = t.preimage(&a, 0);
    assert!(t.check(p, &a, std::vec![t.signer(0, &m, false)], &t.token, "transfer", 100).unwrap_err().contains("GrantVoid"));
    assert_eq!(t.install(3, &g), Err(Error::StaleGrant));
}

#[test]
fn an_expired_grant_authorizes_nothing() {
    let (t, _) = ok_open();
    t.env.ledger().set_timestamp((NOW_MS + 600_001) / 1000 + 1);
    let p = [9u8; 32];
    let a = t.action(&t.token, "transfer", 100, 0, &p);
    let m = t.preimage(&a, 0);
    assert!(t.check(p, &a, std::vec![t.signer(0, &m, false)], &t.token, "transfer", 100).unwrap_err().contains("OutsideWindow"));
}

#[test]
fn an_exact_grant_authorizes_its_action_once() {
    let mut t = setup();
    t.seq = 1;
    let a = t.action(&t.token, "transfer", 100, 0, b"exact");
    let g = t.grant(1, false, sha(&[&a]), [0; 32]);
    t.install(1, &g).unwrap();
    t.check([5; 32], &a, std::vec![], &t.token, "transfer", 100).unwrap();
    assert!(t.check([5; 32], &a, std::vec![], &t.token, "transfer", 100).unwrap_err().contains("ExactUsed"));
}

#[test]
fn a_grant_of_another_account_or_a_forged_proof_is_refused() {
    let mut t = setup();
    let mut g = t.grant(1, false, [0; 32], [0; 32]);
    g[40] ^= 1;
    assert_eq!(t.install(1, &g), Err(Error::NotThisAccount));
    let g = t.grant(1, false, [0; 32], [0; 32]);
    let c = AgentAccountClient::new(&t.env, &t.account);
    MockFinalityClient::new(&t.env, &t.finality).set(&9, &BytesN::from_array(&t.env, &[1; 32]));
    let mut proof = std::vec![0u8, 0, 2];
    proof.extend_from_slice(&[0u8; 256]);
    let r = c.try_sync(&9, &Bytes::from_slice(&t.env, &g), &Bytes::from_slice(&t.env, &proof), &String::from_str(&t.env, &t.caip19), &BytesN::from_array(&t.env, &[0; 32]));
    assert_eq!(r, Err(Ok(Error::BadStateProof)));
}

#[test]
fn a_payment_is_one_signed_action_and_is_reported_for_tenzro() {
    let (t, _) = ok_open();
    let to = Address::generate(&t.env);
    let (payee, request, quote) = ([0x55u8; 32], [1u8; 32], [2u8; 32]);
    let args: soroban_sdk::Vec<Val> = vec![
        &t.env,
        to.into_val(&t.env),
        100i128.into_val(&t.env),
        BytesN::from_array(&t.env, &payee).into_val(&t.env),
        BytesN::from_array(&t.env, &request).into_val(&t.env),
        BytesN::from_array(&t.env, &quote).into_val(&t.env),
        30u64.into_val(&t.env),
    ];
    let payload = [7u8; 32];
    let authorize = |amount: u128, args: soroban_sdk::Vec<Val>| {
        let a = t.action(&t.account, "pay", amount, 0, &payload);
        let m = t.preimage(&a, AgentAccountClient::new(&t.env, &t.account).nonce());
        let ctx = Context::Contract(ContractContext { contract: t.account.clone(), fn_name: Symbol::new(&t.env, "pay"), args });
        let auth = ActAuth {
            action: Bytes::from_slice(&t.env, &a),
            signers: Vec::from_iter(&t.env, std::vec![t.signer(0, &m, false)]),
            target_proof: Vec::new(&t.env),
        };
        t.env.try_invoke_contract_check_auth::<Error>(&t.account, &BytesN::from_array(&t.env, &payload), auth.into_val(&t.env), &vec![&t.env, ctx])
    };
    // The action must state what the payment moves.
    assert!(authorize(99, args.clone()).is_err());
    authorize(100, args).unwrap();
    assert_eq!(AgentAccountClient::new(&t.env, &t.account).spent(), 100);

    t.env.mock_all_auths();
    AgentAccountClient::new(&t.env, &t.account).pay(
        &to,
        &100,
        &BytesN::from_array(&t.env, &payee),
        &BytesN::from_array(&t.env, &request),
        &BytesN::from_array(&t.env, &quote),
        &30,
    );
    use soroban_sdk::testutils::Events as _;
    use soroban_sdk::xdr::{ContractEventBody, ScVal};
    let report_key = ScVal::Symbol("report".try_into().unwrap());
    let reports: StdVec<StdVec<u8>> = t
        .env
        .events()
        .all()
        .filter_by_contract(&t.account)
        .events()
        .iter()
        .filter_map(|e| {
            let ContractEventBody::V0(body) = &e.body;
            match &body.data {
                ScVal::Map(Some(m)) => m.iter().find(|kv| kv.key == report_key).and_then(|kv| match &kv.val {
                    ScVal::Bytes(b) => Some(b.to_vec()),
                    _ => None,
                }),
                _ => None,
            }
        })
        .collect();
    let mut expected = std::vec![4u8];
    expected.extend_from_slice(&sha(&[CAIP2]));
    expected.extend_from_slice(&t.id(&t.account));
    expected.extend_from_slice(&sha(&[DID]));
    expected.extend_from_slice(&t.seq.to_be_bytes());
    expected.extend_from_slice(&0u64.to_be_bytes());
    expected.extend_from_slice(&payee);
    expected.extend_from_slice(&request);
    expected.extend_from_slice(&quote);
    expected.extend_from_slice(&30u64.to_be_bytes());
    expected.extend_from_slice(&100u128.to_be_bytes());
    assert_eq!(reports, std::vec![expected]);
    assert_eq!(soroban_sdk::token::TokenClient::new(&t.env, &t.token).balance(&to), 100);
}

impl T {
    /// A call to `lock` on `target` that pulls `nested` from this account.
    fn check_lock(&self, payload: [u8; 32], action: &[u8], signers: StdVec<Signer>, target: &Address, nested: Context) -> std::result::Result<(), std::string::String> {
        let args: soroban_sdk::Vec<Val> = vec![&self.env, self.account.into_val(&self.env)];
        let outer = Context::Contract(ContractContext { contract: target.clone(), fn_name: Symbol::new(&self.env, "lock"), args });
        let auth = ActAuth {
            action: Bytes::from_slice(&self.env, action),
            signers: Vec::from_iter(&self.env, signers),
            target_proof: Vec::new(&self.env),
        };
        self.env
            .try_invoke_contract_check_auth::<Error>(&self.account, &BytesN::from_array(&self.env, &payload), auth.into_val(&self.env), &vec![&self.env, outer, nested])
            .map_err(|e| std::format!("{e:?}"))
    }

    fn pull(&self, token: &Address, f: &str, from: &Address, to: &Address, amount: i128) -> Context {
        let args: soroban_sdk::Vec<Val> = vec![&self.env, from.into_val(&self.env), to.into_val(&self.env), amount.into_val(&self.env)];
        Context::Contract(ContractContext { contract: token.clone(), fn_name: Symbol::new(&self.env, f), args })
    }
}

#[test]
fn a_lock_pulls_exactly_the_stated_amount_and_nothing_else() {
    let (t, _) = ok_open();
    let lock = Address::generate(&t.env);
    let payload = [7u8; 32];
    let a = t.action(&lock, "lock", 100, 0, &payload);
    let m = t.preimage(&a, 0);
    let sign = || std::vec![t.signer(0, &m, false)];
    // Another amount, another recipient, another asset, another function, or
    // a pull from another account: refused.
    assert!(t.check_lock(payload, &a, sign(), &lock, t.pull(&t.token, "transfer", &t.account, &lock, 101)).is_err());
    let other = Address::generate(&t.env);
    assert!(t.check_lock(payload, &a, sign(), &lock, t.pull(&t.token, "transfer", &t.account, &other, 100)).is_err());
    let foreign = t.env.register_stellar_asset_contract_v2(Address::generate(&t.env)).address();
    assert!(t.check_lock(payload, &a, sign(), &lock, t.pull(&foreign, "transfer", &t.account, &lock, 100)).is_err());
    assert!(t.check_lock(payload, &a, sign(), &lock, t.pull(&t.token, "approve", &t.account, &lock, 100)).is_err());
    assert!(t.check_lock(payload, &a, sign(), &lock, t.pull(&t.token, "transfer", &other, &lock, 100)).is_err());
    assert_eq!(AgentAccountClient::new(&t.env, &t.account).nonce(), 0);
    // Exactly the action's amount of the grant asset, to the called lock.
    t.check_lock(payload, &a, sign(), &lock, t.pull(&t.token, "transfer", &t.account, &lock, 100)).unwrap();
    assert_eq!(AgentAccountClient::new(&t.env, &t.account).nonce(), 1);
    assert_eq!(AgentAccountClient::new(&t.env, &t.account).spent(), 100);
    // A direct transfer may not carry a second context.
    let b = t.action(&t.token, "transfer", 100, 0, &payload);
    let mb = t.preimage(&b, 1);
    let args: soroban_sdk::Vec<Val> = vec![&t.env, t.account.into_val(&t.env), lock.into_val(&t.env), 100i128.into_val(&t.env)];
    let outer = Context::Contract(ContractContext { contract: t.token.clone(), fn_name: Symbol::new(&t.env, "transfer"), args });
    let auth = ActAuth { action: Bytes::from_slice(&t.env, &b), signers: Vec::from_iter(&t.env, std::vec![t.signer(0, &mb, false)]), target_proof: Vec::new(&t.env) };
    let r = t.env.try_invoke_contract_check_auth::<Error>(&t.account, &BytesN::from_array(&t.env, &payload), auth.into_val(&t.env), &vec![&t.env, outer, t.pull(&t.token, "transfer", &t.account, &lock, 100)]);
    assert!(r.is_err());
}
