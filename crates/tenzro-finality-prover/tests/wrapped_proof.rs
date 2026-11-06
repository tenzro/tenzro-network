//! Finality proofs of a real checkpoint certificate: the STARK, checked by a
//! light client from the proof alone, and its Groth16 wrap, checked by
//! Tenzro and by the EVM verifier contract in a local EVM.
//!
//! The checkpoint is certified by a one-member committee: a full-size
//! committee proves the same program for more cycles, not a different one.
//! Proving runs in the production's two stages, so these tests are ignored
//! by default. The STARK stage runs on an NVIDIA GPU and writes the STARK
//! proof to `FINALITY_PROOF`, and a light client checks it there:
//!
//! ```text
//! FINALITY_PROOF=/path/proof.json cargo test --release --features cuda --test wrapped_proof -- --ignored --nocapture --test-threads 1 the_stark_stage a_light_client
//! ```
//!
//! The wrap stage reads it on an x86-64 host with the Groth16 prover
//! container, in a build without `cuda`:
//!
//! ```text
//! FINALITY_PROOF=/path/proof.json SOLC=/path/to/solc-0.8.26 cargo test --release --test wrapped_proof -- --ignored --nocapture a_wrapped_proof
//! ```

use ml_dsa::{ExpandedSigningKey, MlDsa65};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{Address, ExecutionResult, Output, TxKind, U256};
use revm::Evm;
use sha2::Digest as _;
use sha3::Keccak256;
use tenzro_finality::checkpoint::{CHECKPOINT_VOTE_DOMAIN, Certificate, Checkpoint, checkpoint_state_height};
use tenzro_finality::committee::Member;
use tenzro_finality::key::{CompositeSignature, ValidatorPublicKey, message_representative, ml_dsa_context};
use tenzro_finality::session::{SESSION_CERTIFICATE_DOMAIN, SessionCertificate, certificate_message};
use tenzro_finality::step::{FinalityJournal, FinalityStep};
use tenzro_finality::committee::Committee;
use tenzro_finality_prover::{StarkProof, image_id, prove, wrap};
use tenzro_types::primitives::Address as TenzroAddress;

const CHAIN_ID: u64 = 1337;
const GENESIS: [u8; 32] = [0x6e; 32];

/// A composite ML-DSA-65 + P-256 key held in memory, for the test only.
struct Key {
    ml: ExpandedSigningKey<MlDsa65>,
    ec: p256::ecdsa::SigningKey,
    public: ValidatorPublicKey,
}

impl Key {
    fn new(seed: u8) -> Self {
        let ml = ExpandedSigningKey::<MlDsa65>::from_seed(&[seed; 32].into());
        let ec = p256::ecdsa::SigningKey::from_slice(&[seed.wrapping_add(1); 32]).unwrap();
        let public = ValidatorPublicKey::new(
            ml.verifying_key().encode().to_vec(),
            ec.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
        )
        .unwrap();
        Self { ml, ec, public }
    }

    fn sign(&self, domain: &[u8], message: &[u8]) -> CompositeSignature {
        let rep = message_representative(domain, message).unwrap();
        let ml = self.ml.sign_deterministic(&rep, ml_dsa_context()).unwrap().encode().to_vec();
        let digest: [u8; 32] = sha2::Sha256::digest(&rep).into();
        let ec: p256::ecdsa::Signature = self.ec.sign_prehash(&digest).unwrap();
        CompositeSignature { ml_dsa: ml, p256: ec.to_bytes().to_vec() }
    }
}

/// A checkpoint ending epoch 0, certified by a one-member committee, and the
/// step over it.
fn step() -> FinalityStep {
    let hardware = Key::new(1);
    let session_key = Key::new(9);
    let members = vec![Member {
        address: TenzroAddress([0x11; 32]),
        public_key: hardware.public.clone(),
        stake: 1,
        seats: 1,
    }];
    let mut session = SessionCertificate {
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS,
        epoch: 0,
        validator: hardware.public.fingerprint(),
        session_key: session_key.public.clone(),
        signature: CompositeSignature { ml_dsa: Vec::new(), p256: Vec::new() },
    };
    session.signature = hardware.sign(SESSION_CERTIFICATE_DOMAIN, &certificate_message(&session));
    let checkpoint = Checkpoint {
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS,
        epoch: 0,
        index: 7,
        prev: [0x70; 32],
        first_height: 1,
        last_height: 40,
        blocks_root: [0xb1; 32],
        state_height: checkpoint_state_height(1, 40),
        state_root: [0x5e; 32],
        statement_root: [0x57; 32],
        next_committee_root: Some([0xc2; 32]),
        anchor_round: 12,
        timestamp_ms: 1_790_000_000_000,
        ordering_root: [0; 32],
    };
    let signature = session_key.sign(CHECKPOINT_VOTE_DOMAIN, &checkpoint.digest());
    let certificate = Certificate {
        checkpoint,
        signers: vec![0],
        sessions: vec![session.digest()],
        signatures: vec![signature],
    };
    FinalityStep { chain_id: CHAIN_ID, genesis_hash: GENESIS, members, sessions: vec![session], certificate }
}

/// Where the STARK stage writes the proof and the later stages read it.
fn proof_path() -> std::path::PathBuf {
    std::env::var_os("FINALITY_PROOF").expect("set FINALITY_PROOF to the STARK proof's path").into()
}

fn read_proof() -> StarkProof {
    let bytes = std::fs::read(proof_path()).expect("the STARK stage wrote the proof");
    StarkProof::from_json(&serde_json::from_slice(&bytes).unwrap()).unwrap()
}

#[test]
#[ignore]
fn the_stark_stage_proves_the_step() {
    let start = std::time::Instant::now();
    let proof = prove(&step()).expect("the step proves");
    eprintln!("PROVED in {:.1} s", start.elapsed().as_secs_f64());
    std::fs::write(proof_path(), serde_json::to_vec(&proof.to_json()).unwrap()).unwrap();
}

/// A light client holds the root of the checkpoint epoch's committee and
/// nothing else, and checks finality from the STARK proof alone: no Groth16
/// seal, no pairing, no attestation.
#[test]
#[ignore]
fn a_light_client_verifies_finality_from_the_stark_alone() {
    let step = step();
    let held_root = Committee::from_members(0, step.members.clone()).unwrap().root();
    let proof = read_proof();
    let json = proof.to_json();
    assert_eq!(json["form"], "stark");
    assert_eq!(json["quantum_safe"], true);

    let runs = 5;
    let start = std::time::Instant::now();
    for _ in 0..runs {
        proof.verify().expect("the STARK verifies");
    }
    let verify_ms = start.elapsed().as_secs_f64() * 1e3 / runs as f64;
    let journal = proof.verify().unwrap();
    assert_eq!(journal, step.verify().unwrap());
    assert_eq!(journal.committee_root, held_root, "certified by the committee the client holds");
    assert_eq!(journal.next_committee_root, [0xc2; 32], "the client adopts the next committee");
    eprintln!("STARK bytes={} verify_ms={verify_ms:.1}", proof.stark.len());

    // A changed journal, a changed proof, another program or a seal in its place do not verify.
    let mut changed = proof.clone();
    changed.journal[8 * 32 + 3] ^= 1;
    assert!(changed.verify().is_err());
    let mut changed = proof.clone();
    let at = changed.stark.len() / 2;
    changed.stark[at] ^= 1;
    assert!(changed.verify().is_err());
    assert!(tenzro_zk::finality_proof::verify_stark(&[7; 32], &proof.journal, &proof.stark).is_err());
    let seal = StarkProof { journal: proof.journal.clone(), stark: vec![0; tenzro_zk::finality_proof::SEAL_LEN] };
    assert!(seal.verify().is_err());

    // The chain checks the same proof as a `finality_proof` evidence item.
    tenzro_zk::finality_proof::verify(
        tenzro_zk::finality_proof::ProofForm::Stark,
        &image_id(),
        &proof.journal,
        &proof.stark,
    )
    .expect("Tenzro accepts the STARK");
}

/// Compiled contracts, by name.
fn compile() -> std::collections::HashMap<String, Vec<u8>> {
    let solc = std::env::var("SOLC").unwrap_or_else(|_| "solc".into());
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/finality");
    let out = std::process::Command::new(solc)
        .current_dir(&dir)
        .args([
            "--optimize",
            "openzeppelin/=vendor/openzeppelin/",
            "--combined-json",
            "bin",
            "TenzroFinalityClient.sol",
            "vendor/risc0-ethereum/groth16/RiscZeroGroth16Verifier.sol",
        ])
        .output()
        .expect("solc runs (set SOLC to a solc 0.8.26 binary)");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    v["contracts"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, c)| (k.rsplit(':').next().unwrap().to_string(), hex::decode(c["bin"].as_str().unwrap()).unwrap()))
        .collect()
}

fn word(b: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[32 - b.len()..].copy_from_slice(b);
    w
}

fn selector(sig: &str) -> Vec<u8> {
    Keccak256::digest(sig.as_bytes())[..4].to_vec()
}

/// `abi.encode(bytes, bytes)` after a selector.
fn call_two_bytes(sel: &[u8], a: &[u8], b: &[u8]) -> Vec<u8> {
    let tail = |x: &[u8]| {
        let mut t = word(&(x.len() as u64).to_be_bytes()).to_vec();
        t.extend_from_slice(x);
        t.resize(32 + x.len().div_ceil(32) * 32, 0);
        t
    };
    let (ta, tb) = (tail(a), tail(b));
    let mut out = sel.to_vec();
    out.extend_from_slice(&word(&64u64.to_be_bytes()));
    out.extend_from_slice(&word(&((64 + ta.len()) as u64).to_be_bytes()));
    out.extend(ta);
    out.extend(tb);
    out
}

const CALLER: Address = Address::repeat_byte(0xca);

fn run(db: &mut CacheDB<EmptyDB>, to: TxKind, data: Vec<u8>, commit: bool) -> ExecutionResult {
    let mut evm = Evm::builder()
        .with_db(db)
        .modify_tx_env(|tx| {
            tx.caller = CALLER;
            tx.transact_to = to;
            tx.data = data.into();
            tx.gas_limit = 30_000_000;
            tx.gas_price = U256::ZERO;
        })
        .build();
    if commit { evm.transact_commit().unwrap() } else { evm.transact().unwrap().result }
}

fn deploy(db: &mut CacheDB<EmptyDB>, mut code: Vec<u8>, args: &[[u8; 32]]) -> Address {
    for a in args {
        code.extend_from_slice(a);
    }
    match run(db, TxKind::Create, code, true) {
        ExecutionResult::Success { output: Output::Create(_, Some(addr)), .. } => addr,
        other => panic!("deploy failed: {other:?}"),
    }
}

#[test]
#[ignore]
fn a_wrapped_proof_verifies_on_tenzro_and_in_the_evm_and_fails_when_tampered() {
    let step = step();
    let expected = step.verify().expect("the step verifies natively");
    let start = std::time::Instant::now();
    let proof = wrap(&read_proof()).expect("the STARK wraps");
    eprintln!("WRAPPED in {:.1} s", start.elapsed().as_secs_f64());
    assert_eq!(FinalityJournal::decode(&proof.journal), Some(expected));

    // Tenzro's check, as an application runs it.
    let id = image_id();
    tenzro_zk::finality_proof::verify_groth16(&id, &proof.journal, &proof.seal).expect("Tenzro accepts the proof");
    let mut journal = proof.journal.clone();
    journal[8 * 32 + 3] ^= 1;
    assert!(tenzro_zk::finality_proof::verify_groth16(&id, &journal, &proof.seal).is_err());
    let mut seal = proof.seal.clone();
    seal[40] ^= 1;
    assert!(tenzro_zk::finality_proof::verify_groth16(&id, &proof.journal, &seal).is_err());
    assert!(tenzro_zk::finality_proof::verify_groth16(&[7; 32], &proof.journal, &proof.seal).is_err());

    // The EVM: the Groth16 verifier and the finality client.
    let code = compile();
    let mut db = CacheDB::new(EmptyDB::default());
    let params = risc0_zkvm::Groth16ReceiptVerifierParameters::default();
    let mut bn254 = params.bn254_control_id.as_bytes().to_vec();
    bn254.reverse();
    let verifier = deploy(&mut db, code["RiscZeroGroth16Verifier"].clone(), &[
        params.control_root.as_bytes().try_into().unwrap(),
        bn254.as_slice().try_into().unwrap(),
    ]);
    let committee_root = expected.committee_root;
    let client = deploy(&mut db, code["TenzroFinalityClient"].clone(), &[
        word(verifier.as_slice()),
        id,
        word(&CHAIN_ID.to_be_bytes()),
        GENESIS,
        committee_root,
    ]);
    let submit = selector("submit(bytes,bytes)");
    let to = TxKind::Call(client);

    let mut bad_journal = proof.journal.clone();
    bad_journal[8 * 32 + 3] ^= 1;
    let r = run(&mut db, to, call_two_bytes(&submit, &bad_journal, &proof.evm_seal()), true);
    assert!(!r.is_success(), "a tampered journal is refused: {r:?}");
    let mut bad_seal = proof.evm_seal();
    bad_seal[4 + 40] ^= 1;
    let r = run(&mut db, to, call_two_bytes(&submit, &proof.journal, &bad_seal), true);
    assert!(!r.is_success(), "a tampered seal is refused: {r:?}");

    let r = run(&mut db, to, call_two_bytes(&submit, &proof.journal, &proof.evm_seal()), true);
    assert!(r.is_success(), "the proof is accepted: {r:?}");
    eprintln!("SUBMIT gas={}", r.gas_used());

    // The checkpoint is final, and its epoch handed over to the next committee.
    let mut q = selector("checkpoints(uint64)");
    q.extend_from_slice(&word(&expected.index.to_be_bytes()));
    let ExecutionResult::Success { output: Output::Call(out), .. } = run(&mut db, to, q, false) else { panic!() };
    assert_eq!(&out[..32], &expected.checkpoint_digest);
    assert_eq!(&out[32..64], &expected.state_root);
    let mut q = selector("committeeRoot(uint64)");
    q.extend_from_slice(&word(&1u64.to_be_bytes()));
    let ExecutionResult::Success { output: Output::Call(out), .. } = run(&mut db, to, q, false) else { panic!() };
    assert_eq!(&out[..32], &expected.next_committee_root);

    // The same checkpoint twice is refused.
    let r = run(&mut db, to, call_two_bytes(&submit, &proof.journal, &proof.evm_seal()), true);
    assert!(!r.is_success());

    // The verifier alone, as other contracts call it.
    let mut v = selector("verify(bytes,bytes32,bytes32)");
    let journal_digest: [u8; 32] = sha2::Sha256::digest(&proof.journal).into();
    let seal = proof.evm_seal();
    v.extend_from_slice(&word(&96u64.to_be_bytes()));
    v.extend_from_slice(&id);
    v.extend_from_slice(&journal_digest);
    v.extend_from_slice(&word(&(seal.len() as u64).to_be_bytes()));
    let mut padded = seal.clone();
    padded.resize(seal.len().div_ceil(32) * 32, 0);
    v.extend(padded);
    let r = run(&mut db, TxKind::Call(verifier), v, false);
    assert!(r.is_success(), "{r:?}");
    eprintln!("VERIFY gas={}", r.gas_used());
}

#[test]
fn the_step_verifies_natively_and_a_forged_signature_does_not() {
    let s = step();
    let j = s.verify().expect("verifies");
    assert_eq!(j.index, 7);
    assert_eq!(j.next_committee_root, [0xc2; 32]);
    let mut forged = s.clone();
    forged.certificate.signatures[0].ml_dsa[10] ^= 1;
    assert!(forged.verify().is_err());
    let mut other_chain = s;
    other_chain.chain_id += 1;
    assert!(other_chain.verify().is_err());
}

/// Runs the program on the test step without proving, and reports its
/// cycles: what a prover's cost scales with.
#[test]
#[ignore]
fn the_program_commits_the_journal_of_the_step() {
    let s = step();
    let input = bincode::serialize(&s).unwrap();
    let env = risc0_zkvm::ExecutorEnv::builder().write_slice(&input).build().unwrap();
    let info = risc0_zkvm::default_executor().execute(env, tenzro_finality_prover::FINALITY_GUEST_ELF).unwrap();
    assert_eq!(info.journal.bytes, s.verify().unwrap().encode());
    eprintln!("CYCLES total={} segments={}", info.cycles(), info.segments.len());
}

#[cfg(not(all(target_arch = "x86_64", not(feature = "cuda"))))]
#[test]
fn a_gpu_build_refuses_to_wrap() {
    let proof = StarkProof { journal: b"journal".to_vec(), stark: Vec::new() };
    let err = wrap(&proof).unwrap_err();
    assert_eq!(err.to_string(), tenzro_finality_prover::WRAP_HOST);
}

/// The wrap takes a receipt of the finality or the handover program and
/// refuses one that verifies as neither before it runs the container.
#[cfg(all(target_arch = "x86_64", not(feature = "cuda")))]
#[test]
fn the_wrap_refuses_a_receipt_of_neither_program_before_running_the_container() {
    use risc0_zkvm::{FakeReceipt, InnerReceipt, Receipt, ReceiptClaim};
    let journal = vec![1u8; 192];
    let claim = ReceiptClaim::ok(tenzro_finality_prover::HANDOVER_GUEST_ID, journal.clone());
    let receipt = Receipt::new(InnerReceipt::Fake(FakeReceipt::new(claim)), journal);
    let err = tenzro_finality_prover::wrap_receipt(&receipt).unwrap_err().to_string();
    assert!(err.contains("the finality or the handover program"), "{err}");
}

#[test]
fn a_stark_that_is_not_one_does_not_verify_and_the_forms_are_labelled() {
    let proof = StarkProof { journal: step().verify().unwrap().encode(), stark: b"not a stark".to_vec() };
    assert!(proof.verify().is_err());
    let back = StarkProof::from_json(&proof.to_json()).unwrap();
    assert_eq!(back, proof);
    assert_eq!(proof.to_json()["quantum_safe"], true);
    let wrapped = tenzro_finality_prover::WrappedProof { journal: proof.journal.clone(), seal: vec![0; 256] };
    assert_eq!(wrapped.to_json()["form"], "groth16-bn254");
    assert_eq!(wrapped.to_json()["quantum_safe"], false);
}

/// The production genesis names the finality program this crate embeds
/// (as RISC Zero's guest-builder container builds it, so the id is the
/// same everywhere).
#[test]
fn the_production_genesis_names_this_program() {
    let genesis = include_str!("../../../config/genesis-prod.toml");
    let line = genesis
        .lines()
        .find(|l| l.trim_start().starts_with("finality_program"))
        .expect("genesis-prod.toml names the finality program");
    let id = line.split('"').nth(1).expect("a quoted image id");
    assert_eq!(id, hex::encode(image_id()));
}

#[test]
fn the_wrap_runs_its_container_by_digest() {
    let (name, digest) = tenzro_finality_prover::GROTH16_PROVER_IMAGE.split_once("@sha256:").expect("a digest reference");
    assert_eq!(name, "risczero/risc0-groth16-prover");
    assert!(digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
}
