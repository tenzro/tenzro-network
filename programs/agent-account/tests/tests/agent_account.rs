//! The agent account program in LiteSVM with the secp256r1 program, run on
//! the shared vectors (`sdk/fixtures/remote_grant`). Build the program first
//! and name it in `AGENT_ACCOUNT_SO`.
//!
//! The P-256 keys are the vectors' test keys standing in for serving nodes'
//! hardware keys; only the signatures they produce matter here.

use litesvm::LiteSVM;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const VECTORS: &str = include_str!("../../../../sdk/fixtures/remote_grant/vectors.json");
const STATE: &str = include_str!("../../../../sdk/fixtures/state_proof/vectors.json");
const PROGRAM: [u8; 32] = [0x07; 32];
const FINALITY_PROGRAM: [u8; 32] = [0x0f; 32];
const FINALITY_STATE: [u8; 32] = [0x5f; 32];
const SECP256R1: &str = "Secp256r1SigVerify1111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SYSTEM: &str = "11111111111111111111111111111111";
const SYSVAR_INSTRUCTIONS: &str = "Sysvar1nstructions1111111111111111111111111";
const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SOURCE: [u8; 32] = [0x5a; 32];

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn addr(b: [u8; 32]) -> Address {
    Address::new_from_array(b)
}

struct Env {
    svm: LiteSVM,
    v: Value,
    c: Value,
    s: Value,
    relayer: Keypair,
    account: Address,
    /// The last successful transaction's logs.
    logs: Vec<String>,
}

fn token_account(mint: &Address, owner: &Address, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

impl Env {
    fn new() -> Self {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let s: Value = serde_json::from_str(STATE).unwrap();
        let c = v["chains"].as_array().unwrap().iter().find(|c| c["chain"].as_str().unwrap().starts_with("solana:")).unwrap().clone();
        let mut svm = LiteSVM::new();
        let so = std::env::var("AGENT_ACCOUNT_SO").expect("AGENT_ACCOUNT_SO must name the program binary");
        svm.add_program(addr(PROGRAM), &std::fs::read(so).unwrap()).unwrap();
        let relayer = Keypair::new();
        svm.airdrop(&relayer.pubkey(), 10_000_000_000).unwrap();
        let account = addr(h(&c["account_raw"]).try_into().unwrap());
        let mut env = Env { svm, v, c, s, relayer, account, logs: Vec::new() };
        env.set_root("root_v1");
        env.clock(env.v["now_ms"].as_u64().unwrap() / 1000);
        // The asset: the vectors' mint, with the agent's token account and
        // the first target as the destination.
        let mint: Address = MINT.parse().unwrap();
        let token: Address = TOKEN.parse().unwrap();
        let mut m = vec![0u8; 82];
        m[44] = 6;
        m[45] = 1;
        env.put(mint, token, m);
        env.put(addr(SOURCE), token, token_account(&mint, &account, 1_000_000));
        let target = addr(h(&env.c["targets"][0]["target"]).try_into().unwrap());
        env.put(target, token, token_account(&mint, &addr([0x99; 32]), 0));
        env
    }

    fn put(&mut self, at: Address, owner: Address, data: Vec<u8>) {
        let lamports = self.svm.minimum_balance_for_rent_exemption(data.len());
        self.svm.set_account(at, Account { lamports, data, owner, executable: false, rent_epoch: 0 }).unwrap();
    }

    /// The finality client's state with `root` as its latest final root.
    fn set_root(&mut self, root: &str) {
        let mut d = vec![0u8; 1435];
        d[0] = 1;
        d[73] = 1;
        d[74..82].copy_from_slice(&7u64.to_le_bytes());
        let r = h(&Value::String(self.s[root].as_str().unwrap().trim_start_matches("0x").into()));
        d[114..146].copy_from_slice(&r);
        self.put(addr(FINALITY_STATE), addr(FINALITY_PROGRAM), d);
    }

    fn clock(&mut self, unix: u64) {
        let mut clock: solana_clock::Clock = self.svm.get_sysvar();
        clock.unix_timestamp = unix as i64;
        self.svm.set_sysvar(&clock);
    }

    fn send(&mut self, ixs: &[Instruction]) -> Result<u64, TransactionError> {
        let bh = self.svm.latest_blockhash();
        // The relayer asks for the most compute a transaction may use.
        let mut budget = vec![2u8];
        budget.extend_from_slice(&1_400_000u32.to_le_bytes());
        let mut all = vec![Instruction {
            program_id: "ComputeBudget111111111111111111111111111111".parse().unwrap(),
            accounts: vec![],
            data: budget,
        }];
        all.extend_from_slice(ixs);
        let tx = Transaction::new(&[&self.relayer], Message::new_with_blockhash(&all, Some(&self.relayer.pubkey()), &bh), bh);
        let r = self.svm.send_transaction(tx).map_err(|e| {
            println!("{:?}", e.meta.logs);
            e.err
        })?;
        self.svm.expire_blockhash();
        self.logs = r.logs;
        Ok(r.compute_units_consumed)
    }

    fn create(&mut self) -> u64 {
        let did = self.v["did"].as_str().unwrap().as_bytes().to_vec();
        let mut data = vec![0u8];
        data.extend_from_slice(&(did.len() as u16).to_be_bytes());
        data.extend_from_slice(&did);
        let ix = Instruction {
            program_id: addr(PROGRAM),
            accounts: vec![
                AccountMeta::new(self.relayer.pubkey(), true),
                AccountMeta::new(self.account, false),
                AccountMeta::new_readonly(SYSTEM.parse().unwrap(), false),
            ],
            data,
        };
        let cu = self.send(&[ix]).expect("create");
        // Lamports above rent for the relayer refunds.
        self.svm.airdrop(&self.account, 1_000_000).unwrap();
        cu
    }

    fn buffer(&self) -> Address {
        Address::find_program_address(&[b"sync", self.relayer.pubkey().as_ref()], &addr(PROGRAM)).0
    }

    fn sync(&mut self, grant: &[u8], proof: &[u8]) -> Result<u64, TransactionError> {
        let mut blob = (grant.len() as u16).to_be_bytes().to_vec();
        blob.extend_from_slice(grant);
        blob.extend_from_slice(&(proof.len() as u16).to_be_bytes());
        blob.extend_from_slice(proof);
        for (i, chunk) in blob.chunks(800).enumerate() {
            let mut data = vec![1u8];
            data.extend_from_slice(&((i * 800) as u16).to_be_bytes());
            data.extend_from_slice(chunk);
            let ix = Instruction {
                program_id: addr(PROGRAM),
                accounts: vec![
                    AccountMeta::new(self.relayer.pubkey(), true),
                    AccountMeta::new(self.buffer(), false),
                    AccountMeta::new_readonly(SYSTEM.parse().unwrap(), false),
                ],
                data,
            };
            self.send(&[ix]).expect("write");
        }
        let caip19 = self.c["asset"].as_str().unwrap().as_bytes().to_vec();
        let mut data = vec![2u8];
        data.extend_from_slice(&[0x77; 32]);
        data.extend_from_slice(&(caip19.len() as u16).to_be_bytes());
        data.extend_from_slice(&caip19);
        let ix = Instruction {
            program_id: addr(PROGRAM),
            accounts: vec![
                AccountMeta::new(self.relayer.pubkey(), true),
                AccountMeta::new(self.account, false),
                AccountMeta::new_readonly(self.buffer(), false),
                AccountMeta::new_readonly(addr(FINALITY_STATE), false),
            ],
            data,
        };
        self.send(&[ix])
    }

    fn sync_v(&mut self, which: &str) -> Result<u64, TransactionError> {
        let (g, p) = if which == "v1" { ("grant", "proof_v1") } else { ("void_grant", "proof_v2") };
        let grant = h(&self.c[g]["bytes"]);
        let proof = h(&self.c[p]);
        self.sync(&grant, &proof)
    }

    fn preimage(&self, encoded: &[u8], nonce: u64) -> Vec<u8> {
        let g = &self.c["grant"];
        let mut m = b"tenzro/agent-act/v1".to_vec();
        m.extend_from_slice(&h(&g["chain"]));
        m.extend_from_slice(&h(&g["account"]));
        m.extend_from_slice(&g["seq"].as_u64().unwrap().to_be_bytes());
        m.extend_from_slice(&nonce.to_be_bytes());
        m.extend_from_slice(encoded);
        m
    }

    fn act(&mut self, encoded: &[u8], signers: &[(usize, [u8; 64])], message: &[u8], target_proof: bool) -> Result<u64, TransactionError> {
        let target = addr(h(&self.c["targets"][0]["target"]).try_into().unwrap());
        let tail = vec![
            AccountMeta::new(addr(SOURCE), false),
            AccountMeta::new(target, false),
            AccountMeta::new_readonly(TOKEN.parse().unwrap(), false),
        ];
        self.act_with(encoded, signers, message, target_proof, tail)
    }

    fn act_with(
        &mut self,
        encoded: &[u8],
        signers: &[(usize, [u8; 64])],
        message: &[u8],
        target_proof: bool,
        tail: Vec<AccountMeta>,
    ) -> Result<u64, TransactionError> {
        let keys: Vec<(Vec<u8>, String, Vec<Vec<u8>>)> = signers
            .iter()
            .map(|(i, _)| {
                let k = &self.v["keys"][*i];
                (h(&k["public_key"]), k["operator_did"].as_str().unwrap().to_string(), k["proof"].as_array().unwrap().iter().map(h).collect())
            })
            .collect();
        // The secp256r1 instruction: every signature over the one message.
        let n = signers.len();
        let mut sv = vec![n as u8, 0];
        let header = 2 + 14 * n;
        let mut body = Vec::new();
        for (j, (_, sig)) in signers.iter().enumerate() {
            let sig_off = header + body.len();
            body.extend_from_slice(sig);
            let pk_off = header + body.len();
            let pk = &keys[j].0;
            let mut compressed = vec![2 + (pk[64] & 1)];
            compressed.extend_from_slice(&pk[1..33]);
            body.extend_from_slice(&compressed);
            let msg_off = header + 97 * n;
            for f in [sig_off, 0xFFFF, pk_off, 0xFFFF, msg_off, message.len(), 0xFFFF] {
                sv.extend_from_slice(&(f as u16).to_le_bytes());
            }
        }
        sv.extend_from_slice(&body);
        sv.extend_from_slice(message);
        let secp = Instruction { program_id: SECP256R1.parse().unwrap(), accounts: vec![], data: sv };
        let mut data = vec![3u8];
        data.extend_from_slice(encoded);
        data.push(n as u8);
        for (pk, op, proof) in &keys {
            data.extend_from_slice(&pk[1..65]);
            data.extend_from_slice(&(op.len() as u16).to_be_bytes());
            data.extend_from_slice(op.as_bytes());
            data.push(proof.len() as u8);
            for p in proof {
                data.extend_from_slice(p);
            }
        }
        if target_proof {
            let proof: Vec<Vec<u8>> = self.c["targets"][0]["proof"].as_array().unwrap().iter().map(h).collect();
            data.push(proof.len() as u8);
            for p in &proof {
                data.extend_from_slice(p);
            }
        }
        let mut accounts = vec![
            AccountMeta::new(self.relayer.pubkey(), true),
            AccountMeta::new(self.account, false),
            AccountMeta::new_readonly(SYSVAR_INSTRUCTIONS.parse().unwrap(), false),
        ];
        accounts.extend(tail);
        let ix = Instruction { program_id: addr(PROGRAM), accounts, data };
        self.send(&[secp, ix])
    }

    fn balance(&self, at: Address) -> u64 {
        let d = self.svm.get_account(&at).unwrap().data;
        u64::from_le_bytes(d[64..72].try_into().unwrap())
    }
}

fn key(i: usize) -> SigningKey {
    SigningKey::from_slice(&[0x11 * (i as u8 + 1); 32]).unwrap()
}

fn sign(i: usize, message: &[u8]) -> [u8; 64] {
    let sig: Signature = key(i).sign(message);
    sig.normalize_s().unwrap_or(sig).to_bytes().into()
}

fn custom(e: Result<u64, TransactionError>, code: u32) {
    match e {
        Err(TransactionError::InstructionError(_, solana_instruction::error::InstructionError::Custom(c))) => assert_eq!(c, code),
        other => panic!("expected custom error {code}, got {other:?}"),
    }
}

/// An encoded action like the vectors' with another amount and refund.
fn encoded_with(c: &Value, amount: u128, refund: u128) -> Vec<u8> {
    encoded_data(c, amount, refund, &h(&c["action"]["data"]))
}

/// An encoded action like the vectors' with another amount, refund and data.
fn encoded_data(c: &Value, amount: u128, refund: u128, d: &[u8]) -> Vec<u8> {
    let a = &c["action"];
    let t = h(&a["target"]);
    let s = h(&a["selector"]);
    let mut out = (t.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&t);
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(&s);
    out.extend_from_slice(&amount.to_be_bytes());
    out.extend_from_slice(&refund.to_be_bytes());
    out.extend_from_slice(&(d.len() as u32).to_be_bytes());
    out.extend_from_slice(d);
    out
}

#[test]
fn the_account_is_the_program_address_tenzro_derives() {
    let mut e = Env::new();
    let agent = Sha256::digest(e.v["did"].as_str().unwrap().as_bytes());
    assert_eq!(Address::find_program_address(&[b"agent", &agent], &addr(PROGRAM)).0, e.account);
    e.create();
    assert!(e.svm.get_account(&e.account).is_some());
}

#[test]
fn a_signed_action_runs_under_a_synced_grant() {
    let mut e = Env::new();
    e.create();
    let cu = e.sync_v("v1").expect("sync");
    println!("sync compute units: {cu}");
    let encoded = h(&e.c["action"]["encoded"]);
    let message = e.preimage(&encoded, 0);
    assert_eq!(Sha256::digest(&message).to_vec(), h(&e.c["action_digest"]));
    let sig: [u8; 64] = h(&e.c["action_signature"]).try_into().unwrap();
    let before = e.svm.get_balance(&e.relayer.pubkey()).unwrap();
    let cu = e.act(&encoded, &[(0, sig)], &message, true).expect("act");
    println!("act compute units: {cu}");
    let target = addr(h(&e.c["targets"][0]["target"]).try_into().unwrap());
    assert_eq!(e.balance(target), 100);
    assert_eq!(e.balance(addr(SOURCE)), 1_000_000 - 100);
    // The relayer paid the fee and got its refund back.
    let after = e.svm.get_balance(&e.relayer.pubkey()).unwrap();
    assert!(before - after < 10_000 + 5);
    // The same signed action again: the nonce moved on.
    custom(e.act(&encoded, &[(0, sig)], &message, true), 19);
}

#[test]
fn a_stranger_a_tampered_message_or_a_high_s_signature_is_refused() {
    let mut e = Env::new();
    e.create();
    e.sync_v("v1").unwrap();
    let encoded = h(&e.c["action"]["encoded"]);
    let message = e.preimage(&encoded, 0);
    // A key outside the root, its signature valid.
    let stranger = SigningKey::from_slice(&[0x44; 32]).unwrap();
    let sig: Signature = stranger.sign(&message[..]);
    let sig: [u8; 64] = sig.normalize_s().unwrap_or(sig).to_bytes().into();
    let mut v = e.v.clone();
    v["keys"][0]["public_key"] = Value::String(e.c["stranger_public_key"].as_str().unwrap().into());
    let saved = std::mem::replace(&mut e.v, v);
    custom(e.act(&encoded, &[(0, sig)], &message, true), 20);
    e.v = saved;
    // A message the account did not compute.
    let mut other = message.clone();
    other[40] ^= 1;
    custom(e.act(&encoded, &[(0, sign(0, &other))], &other, true), 19);
    // The high-S twin fails at the secp256r1 program.
    let high: [u8; 64] = h(&e.c["action_signature_high_s"]).try_into().unwrap();
    assert!(matches!(e.act(&encoded, &[(0, high)], &message, true), Err(TransactionError::InstructionError(1, _))));
}

#[test]
fn limits_cosigns_targets_refunds_and_time_are_enforced() {
    let mut e = Env::new();
    e.create();
    e.sync_v("v1").unwrap();
    let per = encoded_with(&e.c, 401, 0);
    let m = e.preimage(&per, 0);
    custom(e.act(&per, &[(0, sign(0, &m))], &m, true), 23);
    let refund = encoded_with(&e.c, 100, 11);
    let m = e.preimage(&refund, 0);
    custom(e.act(&refund, &[(0, sign(0, &m))], &m, true), 25);
    let other = h(&e.c["other_target_action"]["encoded"]);
    let m = e.preimage(&other, 0);
    custom(e.act(&other, &[(0, sign(0, &m))], &m, true), 22);
    let big = h(&e.c["big_action"]["encoded"]);
    let m = e.preimage(&big, 0);
    custom(e.act(&big, &[(0, sign(0, &m))], &m, true), 21);
    custom(e.act(&big, &[(0, sign(0, &m)), (2, sign(2, &m))], &m, true), 21);
    e.act(&big, &[(0, sign(0, &m)), (1, sign(1, &m))], &m, true).expect("cosigned");
    for nonce in 1..3u64 {
        let m = e.preimage(&big, nonce);
        let r = e.act(&big, &[(0, sign(0, &m)), (1, sign(1, &m))], &m, true);
        if nonce == 1 {
            r.expect("second");
        } else {
            custom(r, 24);
        }
    }
    let late = e.c["grant"]["not_after_ms"].as_u64().unwrap() / 1000 + 1;
    e.clock(late);
    let small = encoded_with(&e.c, 1, 0);
    let m = e.preimage(&small, 2);
    custom(e.act(&small, &[(0, sign(0, &m))], &m, true), 13);
}

#[test]
fn a_void_stops_actions_and_stale_or_foreign_grants_are_refused() {
    let mut e = Env::new();
    e.create();
    e.sync_v("v1").unwrap();
    e.set_root("root_v2");
    e.sync_v("v2").unwrap();
    let encoded = h(&e.c["action"]["encoded"]);
    let m = e.preimage(&encoded, 0);
    custom(e.act(&encoded, &[(0, sign(0, &m))], &m, true), 12);
    e.set_root("root_v1");
    custom(e.sync_v("v1"), 9);
    // Another chain's grant does not prove at this account's tree key.
    let base = e.v["chains"][0].clone();
    custom(e.sync(&h(&base["grant"]["bytes"]), &h(&base["proof_v1"])), 6);
}

/// The root of a state tree whose only entry is `value` at `tk`, and the
/// proof of it.
fn single(tk: &[u8; 32], value: &[u8]) -> ([u8; 32], Vec<u8>) {
    let mut s: [u8; 32] = Sha256::digest([&[0u8][..], value].concat()).into();
    let mut index = tk[31];
    for _ in 0..8 {
        let b = if index & 1 == 0 { [&[3u8][..], &s, &[0u8; 32]].concat() } else { [&[3u8][..], &[0u8; 32], &s].concat() };
        s = Sha256::digest(b).into();
        index >>= 1;
    }
    let root: [u8; 32] = Sha256::digest([&[2u8][..], &tk[..31], &s].concat()).into();
    let mut proof = vec![0, 0, 2];
    proof.extend_from_slice(&[0u8; 256]);
    (root, proof)
}

const LOCK_PROGRAM: [u8; 32] = [0x0c; 32];

#[test]
fn a_lock_action_locks_exactly_its_amount_with_the_account_as_payer() {
    let mut e = Env::new();
    e.create();
    // The vectors' grant with no target list, proven under a root of its own.
    let mut grant = h(&e.c["grant"]["bytes"]);
    grant[241..273].fill(0);
    let tk: [u8; 32] = h(&e.c["tree_key"]).try_into().unwrap();
    let (root, proof) = single(&tk, &grant);
    let mut d = e.svm.get_account(&addr(FINALITY_STATE)).unwrap().data;
    d[114..146].copy_from_slice(&root);
    e.put(addr(FINALITY_STATE), addr(FINALITY_PROGRAM), d);
    e.sync(&grant, &proof).expect("sync");
    // The settlement lock program and its config.
    let so = std::env::var("SETTLEMENT_LOCK_SO").expect("SETTLEMENT_LOCK_SO must name the lock program binary");
    e.svm.add_program(addr(LOCK_PROGRAM), &std::fs::read(so).unwrap()).unwrap();
    let config = Keypair::new();
    e.put(config.pubkey(), addr(LOCK_PROGRAM), vec![0u8; 1 + 32 + 32 + 8 + 8 + 32]);
    let mut init = vec![0u8];
    init.extend_from_slice(&FINALITY_PROGRAM);
    init.extend_from_slice(&FINALITY_STATE);
    init.extend_from_slice(&3600u64.to_le_bytes());
    let ix = Instruction { program_id: addr(LOCK_PROGRAM), accounts: vec![AccountMeta::new(config.pubkey(), true)], data: init };
    let bh = e.svm.latest_blockhash();
    let tx = Transaction::new(&[&e.relayer, &config], Message::new_with_blockhash(&[ix], Some(&e.relayer.pubkey()), &bh), bh);
    e.svm.send_transaction(tx).expect("initialize the lock");
    let plan = [7u8; 32];
    let leg_id = tenzro_finality_verifier::settlement::leg_id(&plan, 0);
    let leg = Address::find_program_address(&[b"leg", config.pubkey().as_ref(), &leg_id], &addr(LOCK_PROGRAM)).0;
    let mint: Address = MINT.parse().unwrap();
    let token: Address = TOKEN.parse().unwrap();
    let vault = addr([0x0d; 32]);
    e.put(vault, token, token_account(&mint, &leg, 0));
    let lock_action = |stated: u64| {
        let mut ix = vec![1u8];
        ix.extend_from_slice(&plan);
        ix.push(0);
        ix.extend_from_slice(&stated.to_le_bytes());
        ix.extend_from_slice(&[0xcc; 32]);
        let mut out = 32u16.to_be_bytes().to_vec();
        out.extend_from_slice(&LOCK_PROGRAM);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(4);
        out.extend_from_slice(&100u128.to_be_bytes());
        out.extend_from_slice(&0u128.to_be_bytes());
        out.extend_from_slice(&(ix.len() as u32).to_be_bytes());
        out.extend_from_slice(&ix);
        out
    };
    let tail = || {
        vec![
            AccountMeta::new_readonly(addr(LOCK_PROGRAM), false),
            AccountMeta::new(config.pubkey(), false),
            AccountMeta::new(leg, false),
            AccountMeta::new_readonly(SYSTEM.parse().unwrap(), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(addr(SOURCE), false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(token, false),
        ]
    };
    // A lock instruction for another amount than the action's: refused.
    let wrong = lock_action(101);
    let m = e.preimage(&wrong, 0);
    custom(e.act_with(&wrong, &[(0, sign(0, &m))], &m, false, tail()), 26);
    let encoded = lock_action(100);
    let m = e.preimage(&encoded, 0);
    e.act_with(&encoded, &[(0, sign(0, &m))], &m, false, tail()).expect("lock");
    assert_eq!(e.balance(addr(SOURCE)), 1_000_000 - 100);
    assert_eq!(e.balance(vault), 100);
    let l = e.svm.get_account(&leg).unwrap();
    assert_eq!(l.owner, addr(LOCK_PROGRAM));
    assert_eq!(&l.data[2..34], e.account.as_ref(), "the account is the leg's payer");
}

#[test]
fn a_transfer_carrying_pay_data_is_reported_as_the_agents_payment() {
    use tenzro_finality_verifier::agent::{Grant, PAY_DATA_LEN, paid_report};
    let mut e = Env::new();
    e.create();
    e.sync_v("v1").expect("sync");
    let grant = Grant::decode(&h(&e.c["grant"]["bytes"])).expect("grant");
    // Payee, request digest, quote digest, USD price.
    let mut pay = vec![0u8; PAY_DATA_LEN];
    pay[..32].fill(0x02);
    pay[32..64].fill(0xaa);
    pay[64..96].fill(0xbb);
    pay[96..].copy_from_slice(&1_250_000u64.to_be_bytes());

    let encoded = encoded_data(&e.c, 100, 0, &pay);
    let m = e.preimage(&encoded, 0);
    e.act(&encoded, &[(0, sign(0, &m))], &m, true).expect("pay");
    let target = addr(h(&e.c["targets"][0]["target"]).try_into().unwrap());
    assert_eq!(e.balance(target), 100);
    let report = paid_report(&grant, 0, &pay, 100).unwrap();
    let data_logs: Vec<&String> = e.logs.iter().filter(|l| l.starts_with("Program data: ")).collect();
    let reported = data_logs.last().expect("a data log");
    let fields: Vec<&str> = reported.trim_start_matches("Program data: ").split(' ').collect();
    assert_eq!(fields.len(), 2, "{reported}");
    assert_eq!(b64(fields[0]), b"Reported".to_vec());
    assert_eq!(b64(fields[1]), report.to_vec(), "the report is the layout Tenzro records proven payments from");

    // A transfer with other data pays but reports nothing.
    let plain = encoded_with(&e.c, 100, 0);
    let m = e.preimage(&plain, 1);
    e.act(&plain, &[(0, sign(0, &m))], &m, true).expect("transfer");
    assert!(
        !e.logs.iter().any(|l| l.starts_with("Program data: ") && l.contains(&b64e(b"Reported"))),
        "{:?}",
        e.logs
    );
}

fn b64(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| *c != b'=') {
        acc = (acc << 6) | A.iter().position(|a| *a == c).expect("base64") as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn b64e(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, x)| n | (*x as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
