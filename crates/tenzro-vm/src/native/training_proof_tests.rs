//! Training receipts, challenges and milestone release, and a scenario with
//! an honest trainer and three cheating ones checked by a reference backend.

use super::*;
use crate::state_adapter::StateAdapter;
use tenzro_types::merkle::merkle_path;
use tenzro_types::training_verification::{
    LeafOpening, StepFault, StepOpening, TrainingBackend, TrainingVerdict, batch_leaf,
    catch_chance_ppm, check_challenge, step_leaf,
};

const DID: &str = "did:tenzro:machine:trainer";
const TNZO: u128 = 1_000_000_000 * GWEI;
const ESCROW: u128 = 50 * TNZO;
const T0: i64 = 1_000_000;

fn trainer_account() -> Vec<u8> {
    vec![5u8; 20]
}

fn signer() -> &'static tenzro_crypto::session::SessionSigner {
    static SIGNER: std::sync::OnceLock<tenzro_crypto::session::SessionSigner> =
        std::sync::OnceLock::new();
    SIGNER.get_or_init(|| session(4))
}

fn session(seed: u8) -> tenzro_crypto::session::SessionSigner {
    tenzro_crypto::session::SessionSigner::new(
        std::sync::Arc::new(tenzro_crypto::testing::TestHybridSigner::hybrid(seed)),
        tenzro_crypto::session::SESSION_LIFETIME,
    )
    .unwrap()
}

fn register(state: &mut StateAdapter, did: &str, key: &tenzro_crypto::CompositePublicKey) {
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: did.into(),
        identity_type: "machine".into(),
        display_name: String::new(),
        controller_pubkey: key.p256.clone(),
        key_type: "p256".into(),
        wallet_id: String::new(),
        wallet_address: tenzro_types::primitives::Address::new([5; 32]),
        pq_verifying_key: key.pq.clone().unwrap_or_default(),
        metadata: Default::default(),
        proof: tenzro_types::identity::RegistrationProof::Hardware {
            signature: tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        },
    };
    state.set_storage(
        &SYSTEM_ADDRESS,
        &super::super::identity_storage_key(did),
        serde_json::to_vec(&record).unwrap(),
    );
}

fn bond_validator(state: &mut StateAdapter, who: &[u8], stake: u128) {
    staking::add_bond(state, who, stake, -crate::governance::MIN_BOND_AGE_MS).unwrap();
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    state.set_balance(&STAKING_VAULT_ADDRESS, vault + stake);
    state.set_balance(who, 10_000 * TNZO);
}

fn validators() -> [Vec<u8>; 3] {
    [vec![1u8; 20], vec![2u8; 20], vec![3u8; 20]]
}

/// Validators, the trainer's identity and compute bond, and a funded payer
/// and challenger.
fn setup(bond: u128) -> (NativeExecutor, StateAdapter) {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    for v in validators() {
        bond_validator(&mut state, &v, 100);
    }
    register(&mut state, DID, signer().identity());
    let marker = serde_json::json!({
        "provider_did": DID,
        "provider_address": hex::encode(trainer_account()),
        "amount": bond.to_string(),
        "op": "Posted",
    });
    state.set_storage(
        &SYSTEM_ADDRESS,
        compute_bond_storage_key(DID).as_bytes(),
        serde_json::to_vec(&marker).unwrap(),
    );
    state.set_balance(derive_compute_bond_vault_address(DID).as_bytes(), bond);
    state.set_balance(&payer(), 1_000 * TNZO);
    state.set_balance(&challenger(), 1_000 * TNZO);
    (executor, state)
}

fn payer() -> Vec<u8> {
    vec![8u8; 20]
}

fn challenger() -> Vec<u8> {
    vec![9u8; 20]
}

/// Lock the milestone escrow; returns its id.
fn escrow(state: &mut StateAdapter, nonce: u64, executor: Address, expires_at: u64) -> [u8; 32] {
    let payload = CreateEscrowPayload {
        payee: Address::new(pad_address_32(&trainer_account()).unwrap()),
        amount: ESCROW,
        asset_id: tenzro_types::asset::AssetId::tnzo(),
        usd_e6: 0,
        expires_at,
        release_conditions: ReleaseConditions::Executor { executor },
        reference: None,
    };
    let (id, _, _) = lock_escrow(state, &payer(), nonce, &payload, 0, T0).unwrap();
    id
}

fn far_expiry() -> u64 {
    (T0 as u64) + 10 * DEFAULT_WINDOW_MS
}

fn tx(from: &[u8], op: &TrainingProofOp, now_ms: i64) -> VmTransaction {
    let mut data = SELECTOR_TRAINING_PROOF.to_vec();
    data.extend_from_slice(&serde_json::to_vec(op).unwrap());
    let mut tx = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        10_000_000,
        0,
        0,
        VmType::Tenzro,
        1337,
    );
    tx.block_timestamp_ms = Some(now_ms);
    tx
}

async fn run(
    executor: &NativeExecutor,
    state: &mut StateAdapter,
    from: &[u8],
    op: TrainingProofOp,
    now: i64,
) -> std::result::Result<ExecutionResult, VmError> {
    executor
        .execute_transaction(&tx(from, &op, now), state)
        .await
}

// ---------------------------------------------------------------------------
// The reference backend and the trainers.
// ---------------------------------------------------------------------------

/// A linear model trained by full-batch gradient steps in fixed point, so
/// every replay is bit-exact.
struct Linear;

const DIM: usize = 4;

fn enc(v: &[i64]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn dec(b: &[u8]) -> Option<Vec<i64>> {
    b.len().is_multiple_of(8).then(|| {
        b.chunks(8)
            .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
            .collect()
    })
}

impl TrainingBackend for Linear {
    fn kernel_class(&self) -> &str {
        "reference-fixed-point"
    }

    fn step(
        &self,
        state: &[u8],
        batch: &[u8],
        hp: &[u8],
        _step: u64,
    ) -> std::result::Result<Vec<u8>, String> {
        let mut w = dec(state).filter(|w| w.len() == DIM).ok_or("bad state")?;
        let rows = dec(batch).ok_or("bad batch")?;
        let shift = *hp.first().ok_or("no learning rate")? as u32;
        let mut grad = [0i64; DIM];
        for row in rows.chunks(DIM + 1) {
            let (x, y) = (&row[..DIM], row[DIM]);
            let pred: i64 = w.iter().zip(x).map(|(a, b)| (a * b) >> 16).sum();
            let err = pred - y;
            for (g, xi) in grad.iter_mut().zip(x) {
                *g += (err * xi) >> 16;
            }
        }
        for (wi, g) in w.iter_mut().zip(grad) {
            *wi -= g >> shift;
        }
        Ok(enc(&w))
    }

    fn distance_ppm(&self, a: &[u8], b: &[u8]) -> Option<u64> {
        let (a, b) = (dec(a)?, dec(b)?);
        if a.len() != b.len() {
            return None;
        }
        let scale = b.iter().map(|x| x.unsigned_abs()).max().unwrap_or(0).max(1);
        let diff = a
            .iter()
            .zip(&b)
            .map(|(x, y)| x.abs_diff(*y))
            .max()
            .unwrap_or(0);
        Some(((diff as u128 * 1_000_000) / scale as u128) as u64)
    }
}

const HP: &[u8] = &[5];

fn batch(step: u64, salt: u8) -> Vec<u8> {
    let mut rows = Vec::new();
    for r in 0..3i64 {
        let x: Vec<i64> = (0..DIM as i64)
            .map(|i| ((step as i64 * 7 + r * 3 + i + salt as i64) % 11 - 5) << 14)
            .collect();
        // Labels off the linear fit, so the gradient never vanishes.
        let noise = ((step as i64 * 13 + r) % 7 - 3) << 14;
        let y = x
            .iter()
            .enumerate()
            .map(|(i, v)| v * (i as i64 + 1))
            .sum::<i64>()
            + noise;
        rows.extend(x);
        rows.push(y);
    }
    enc(&rows)
}

/// How a trainer behaves.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Trainer {
    Honest,
    /// Reports steps whose index is in the set without running them.
    SkipSteps(&'static [u64]),
    /// Trains on batches other than the committed shard's.
    WrongShard,
    /// Reports an end checkpoint its log never reached.
    FabricatedCheckpoint,
}

/// Everything a trainer keeps for one round, to open on challenge.
struct Round {
    receipt: TrainingReceipt,
    states: Vec<Vec<u8>>,
    batches: Vec<Vec<u8>>,
    leaves: Vec<([u8; 32], [u8; 32])>,
    shard_leaves: Vec<[u8; 32]>,
}

fn train(kind: Trainer, steps: u64, escrow_id: [u8; 32]) -> Round {
    let b = Linear;
    let job_batches: Vec<Vec<u8>> = (0..steps).map(|k| batch(k, 0)).collect();
    let used: Vec<Vec<u8>> = match kind {
        Trainer::WrongShard => (0..steps).map(|k| batch(k, 1)).collect(),
        _ => job_batches.clone(),
    };
    let mut states = vec![enc(&[1 << 16, 0, -(1 << 15), 1 << 14])];
    let mut leaves = Vec::new();
    for k in 0..steps {
        let before = states.last().unwrap().clone();
        let after = match kind {
            Trainer::SkipSteps(skip) if skip.contains(&k) => before,
            _ => b.step(&before, &used[k as usize], HP, k).unwrap(),
        };
        leaves.push((b.batch_digest(&used[k as usize]), b.state_digest(&after)));
        states.push(after);
    }
    let shard_leaves: Vec<[u8; 32]> = job_batches
        .iter()
        .enumerate()
        .map(|(k, x)| batch_leaf(k as u64, &b.batch_digest(x)))
        .collect();
    let mut end = leaves.last().unwrap().1;
    if kind == Trainer::FabricatedCheckpoint {
        end = [0xEE; 32];
    }
    let receipt = TrainingReceipt {
        escrow_id: hex::encode(escrow_id),
        trainer_did: DID.into(),
        round: 1,
        start_checkpoint: hex::encode(b.state_digest(&states[0])),
        shard_commitment: hex::encode(tenzro_types::merkle::merkle_root(&shard_leaves)),
        hyperparameters: hex::encode(Sha256::digest(HP)),
        steps,
        end_checkpoint: hex::encode(end),
        step_root: hex::encode(tenzro_types::training_verification::step_root(&leaves)),
        kernel_class: b.kernel_class().into(),
        signed_at_ms: T0 as u64,
    };
    Round {
        receipt,
        states,
        batches: used,
        leaves,
        shard_leaves,
    }
}

impl Round {
    fn leaf_nodes(&self) -> Vec<[u8; 32]> {
        self.leaves
            .iter()
            .enumerate()
            .map(|(k, (b, s))| step_leaf(k as u64, b, s))
            .collect()
    }

    fn leaf(&self, k: u64) -> LeafOpening {
        let (batch_digest, state_after) = self.leaves[k as usize];
        LeafOpening {
            batch_digest,
            state_after,
            path: merkle_path(&self.leaf_nodes(), k as usize).unwrap(),
        }
    }

    /// What the trainer opens for step `k`.
    fn open(&self, k: u64) -> Option<StepOpening> {
        (k < self.receipt.steps).then(|| StepOpening {
            step: k,
            previous: (k > 0).then(|| self.leaf(k - 1)),
            leaf: self.leaf(k),
            batch: self.batches[k as usize].clone(),
            batch_path: merkle_path(&self.shard_leaves, k as usize).unwrap(),
            state_before: self.states[k as usize].clone(),
            state_after: self.states[k as usize + 1].clone(),
        })
    }

    fn check(&self, seed: &[u8; 32], count: u64) -> TrainingVerdict {
        self.check_within(seed, count, DEFAULT_TOLERANCE_PPM)
    }

    fn check_within(&self, seed: &[u8; 32], count: u64, tolerance_ppm: u64) -> TrainingVerdict {
        check_challenge(
            &Linear,
            &self.receipt,
            HP,
            seed,
            count,
            tolerance_ppm,
            &|k| self.open(k),
        )
    }
}

// ---------------------------------------------------------------------------
// Bond arithmetic.
// ---------------------------------------------------------------------------

#[test]
fn a_challenge_bond_is_split_without_creating_or_losing_value() {
    let mut x: u128 = 0x9E37_79B9_7F4A_7C15;
    for i in 0..10_000u64 {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let bond = match i % 4 {
            0 => x,
            1 => x >> 64,
            2 => u128::MAX - (x >> 100),
            _ => x % 10_000,
        };
        let bps = (x >> 7) as u64 % 12_000;
        for outcome in [
            ChallengeOutcome::Upheld,
            ChallengeOutcome::Dismissed,
            ChallengeOutcome::Expired,
        ] {
            let s = split_challenge_bond(bond, bps, outcome);
            assert_eq!(s.to_challenger + s.to_trainer + s.to_pool, bond);
            assert!(s.to_pool <= bond);
            if outcome == ChallengeOutcome::Dismissed {
                assert_eq!(s.to_challenger, 0);
            } else {
                assert_eq!(s.to_trainer, 0);
            }
        }
    }
    let s = split_challenge_bond(10_000, 500, ChallengeOutcome::Upheld);
    assert_eq!((s.to_challenger, s.to_pool), (9_500, 500));
}

#[test]
fn every_training_value_is_governed() {
    for key in [
        WINDOW_MS_PARAM,
        TEE_WINDOW_MS_PARAM,
        DECIDE_WINDOW_MS_PARAM,
        CHALLENGE_BOND_GWEI_PARAM,
        CHALLENGE_FEE_BPS_PARAM,
        CHALLENGER_REWARD_GWEI_PARAM,
        PENALTY_GWEI_PARAM,
        SAMPLE_STEPS_PARAM,
        TOLERANCE_PPM_PARAM,
        MAX_CHALLENGES_PARAM,
    ] {
        assert!(crate::governance::governed_param(key).is_some(), "{key}");
    }
    const { assert!(DEFAULT_TEE_WINDOW_MS < DEFAULT_WINDOW_MS) };
    assert!(
        crate::governance::governed_param(SAMPLE_STEPS_PARAM)
            .unwrap()
            .min
            >= 2
    );
}

// ---------------------------------------------------------------------------
// Commit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_receipt_commits_only_against_a_milestone_escrow_it_can_settle() {
    let (ex, mut state) = setup(100 * TNZO);
    let anyone = vec![7u8; 20];
    state.set_balance(&anyone, TNZO);

    // An escrow the payer alone releases is not a training milestone.
    let own = escrow(&mut state, 1, Address::new([4; 32]), far_expiry());
    let r = train(Trainer::Honest, 8, own);
    let err = run(
        &ex,
        &mut state,
        &anyone,
        TrainingProofOp::Commit {
            receipt: sign_batched(r.receipt),
        },
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("training executor"), "{err}");

    // One that expires before a challenge could be settled.
    let short = escrow(
        &mut state,
        2,
        training_executor(),
        (T0 as u64) + DEFAULT_WINDOW_MS,
    );
    let r = train(Trainer::Honest, 8, short);
    let err = run(
        &ex,
        &mut state,
        &anyone,
        TrainingProofOp::Commit {
            receipt: sign_batched(r.receipt),
        },
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("expires"), "{err}");

    // Signed by a key the trainer never registered.
    let id = escrow(&mut state, 3, training_executor(), far_expiry());
    let r = train(Trainer::Honest, 8, id);
    let err = run(
        &ex,
        &mut state,
        &anyone,
        TrainingProofOp::Commit {
            receipt: sign_batched_by(r.receipt.clone(), 9),
        },
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("not signed"), "{err}");

    // A TEE attestation that does not verify is refused, not ignored.
    let mut with_tee = sign_batched(r.receipt.clone());
    with_tee.tee = Some(tenzro_types::tee::AttestationReport {
        vendor: tenzro_types::tee::TeeVendor::IntelTdx,
        attestation_data: vec![0xAA; 1184],
        user_data: r.receipt.digest().to_vec(),
        ..Default::default()
    });
    let err = run(
        &ex,
        &mut state,
        &anyone,
        TrainingProofOp::Commit { receipt: with_tee },
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("TEE"), "{err}");

    // The proper one commits, once, and binds its escrow.
    run(
        &ex,
        &mut state,
        &anyone,
        TrainingProofOp::Commit {
            receipt: sign_batched(r.receipt.clone()),
        },
        T0,
    )
    .await
    .unwrap();
    let rec = read_training_record(&state, &r.receipt.receipt_id()).unwrap();
    assert_eq!(rec.window_ms, DEFAULT_WINDOW_MS);
    assert!(!rec.tee);
    assert_eq!(
        round_of_escrow(&state, &hex::encode(id)),
        Some(r.receipt.receipt_id())
    );
    let mut again = r.receipt.clone();
    again.round = 2;
    let err = run(
        &ex,
        &mut state,
        &anyone,
        TrainingProofOp::Commit {
            receipt: sign_batched(again),
        },
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("another round"), "{err}");
}

#[tokio::test]
async fn a_trainer_whose_bond_cannot_pay_a_fault_cannot_commit() {
    let (ex, mut state) = setup(TNZO);
    let id = escrow(&mut state, 1, training_executor(), far_expiry());
    let r = train(Trainer::Honest, 4, id);
    let err = run(
        &ex,
        &mut state,
        &payer(),
        TrainingProofOp::Commit {
            receipt: sign_batched(r.receipt),
        },
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("compute bond holds"), "{err}");
}

// ---------------------------------------------------------------------------
// Settlement paths.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_receipt_signed_up_to_a_minute_ahead_of_its_block_commits() {
    // The block that includes a commit carries the time its slot opened, and
    // the trainer's clock may run ahead of the validators' within the
    // network's 60 s tolerance: a receipt signed just before it is sent is
    // ahead of that block. Further ahead than the tolerance it is refused.
    let (ex, mut state) = setup(100 * TNZO);
    let id = escrow(&mut state, 1, training_executor(), far_expiry());
    let mut ahead = train(Trainer::Honest, 8, id);
    ahead.receipt.signed_at_ms = (T0 + 60_000) as u64;
    run(
        &ex,
        &mut state,
        &payer(),
        TrainingProofOp::Commit {
            receipt: sign_batched(ahead.receipt.clone()),
        },
        T0,
    )
    .await
    .unwrap();

    let id = escrow(&mut state, 2, training_executor(), far_expiry());
    let mut too_far = train(Trainer::Honest, 8, id);
    too_far.receipt.signed_at_ms = (T0 + 60_001) as u64;
    let err = run(
        &ex,
        &mut state,
        &payer(),
        TrainingProofOp::Commit {
            receipt: sign_batched(too_far.receipt.clone()),
        },
        T0,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("signed in the future"), "{err}");
}

async fn committed(kind: Trainer, steps: u64) -> (NativeExecutor, StateAdapter, Round) {
    let (ex, mut state) = setup(100 * TNZO);
    let id = escrow(&mut state, 1, training_executor(), far_expiry());
    let r = train(kind, steps, id);
    run(
        &ex,
        &mut state,
        &payer(),
        TrainingProofOp::Commit {
            receipt: sign_batched(r.receipt.clone()),
        },
        T0,
    )
    .await
    .unwrap();
    (ex, state, r)
}

fn settle(r: &Round) -> TrainingProofOp {
    TrainingProofOp::Settle {
        receipt_id: r.receipt.receipt_id(),
    }
}

#[tokio::test]
async fn an_unchallenged_round_is_paid_only_after_its_window_closes() {
    let (ex, mut state, r) = committed(Trainer::Honest, 8).await;
    let end = T0 + DEFAULT_WINDOW_MS as i64;
    let err = run(&ex, &mut state, &payer(), settle(&r), end)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("still open"), "{err}");
    let before = state.get_balance(&trainer_account());
    run(&ex, &mut state, &payer(), settle(&r), end + 1)
        .await
        .unwrap();
    // The release is a settlement: paid less the settlement fee.
    assert_eq!(
        state.get_balance(&trainer_account()),
        before + ESCROW - crate::native::economy::settlement_fee(&state, ESCROW)
    );
    let rec = read_training_record(&state, &r.receipt.receipt_id()).unwrap();
    assert_eq!(rec.settled, Some(RoundSettlement::Released));
    assert!(
        run(&ex, &mut state, &payer(), settle(&r), end + 2)
            .await
            .is_err()
    );
    // A closed window takes no more challenges.
    let err = run(
        &ex,
        &mut state,
        &challenger(),
        TrainingProofOp::Challenge {
            receipt_id: r.receipt.receipt_id(),
        },
        end + 3,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("settled"), "{err}");
}

#[tokio::test]
async fn an_undecided_challenge_expires_and_then_the_round_is_paid() {
    let (ex, mut state, r) = committed(Trainer::Honest, 8).await;
    let id = r.receipt.receipt_id();
    let c0 = state.get_balance(&challenger());
    run(
        &ex,
        &mut state,
        &challenger(),
        TrainingProofOp::Challenge {
            receipt_id: id.clone(),
        },
        T0 + 10,
    )
    .await
    .unwrap();
    let bond = DEFAULT_CHALLENGE_BOND_GWEI as u128 * GWEI;
    assert_eq!(state.get_balance(&challenger()), c0 - bond);
    // The window closes but the challenge is still within its decision window.
    let after_window = T0 + DEFAULT_WINDOW_MS as i64 + 1;
    let err = run(&ex, &mut state, &payer(), settle(&r), after_window)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("still being decided"), "{err}");
    // Past it, settling expires the challenge (bond back less the fee) and pays.
    let late = T0 + 10 + DEFAULT_DECIDE_WINDOW_MS as i64 + 1;
    run(&ex, &mut state, &payer(), settle(&r), late)
        .await
        .unwrap();
    let fee = bond * DEFAULT_CHALLENGE_FEE_BPS as u128 / 10_000;
    assert_eq!(state.get_balance(&challenger()), c0 - fee);
    let rec = read_training_record(&state, &id).unwrap();
    assert_eq!(rec.challenges[0].outcome, Some(ChallengeOutcome::Expired));
    assert_eq!(rec.settled, Some(RoundSettlement::Released));
}

// ---------------------------------------------------------------------------
// The scenario: honest and cheating trainers, one challenge each, every
// validator replaying the sampled steps on the reference backend.
// ---------------------------------------------------------------------------

struct Outcome {
    verdict: TrainingVerdict,
    record: TrainingRecord,
    challenger_delta: i128,
    trainer_delta: i128,
    payer_delta: i128,
    bond_after: u128,
}

async fn challenge_round(kind: Trainer, steps: u64) -> Outcome {
    let (ex, mut state, r) = committed(kind, steps).await;
    let id = r.receipt.receipt_id();
    let bal = |s: &StateAdapter, a: &[u8]| s.get_balance(a) as i128;
    let (c0, t0, p0) = (
        bal(&state, &challenger()),
        bal(&state, &trainer_account()),
        bal(&state, &payer()),
    );
    run(
        &ex,
        &mut state,
        &challenger(),
        TrainingProofOp::Challenge {
            receipt_id: id.clone(),
        },
        T0 + 10,
    )
    .await
    .unwrap();
    let rec = read_training_record(&state, &id).unwrap();
    let seed: [u8; 32] = hex::decode(&rec.challenges[0].seed)
        .unwrap()
        .try_into()
        .unwrap();
    let c = &rec.challenges[0];
    assert_eq!(
        (c.samples, c.tolerance_ppm),
        (DEFAULT_SAMPLE_STEPS, DEFAULT_TOLERANCE_PPM)
    );
    let verdict = r.check_within(&seed, c.samples, c.tolerance_ppm);
    for v in validators() {
        run(
            &ex,
            &mut state,
            &v,
            TrainingProofOp::Attest {
                receipt_id: id.clone(),
                challenge: 0,
                upheld: verdict.upheld(),
            },
            T0 + 20,
        )
        .await
        .ok();
    }
    let end = T0 + DEFAULT_WINDOW_MS as i64 + 1;
    let _ = run(&ex, &mut state, &payer(), settle(&r), end).await;
    Outcome {
        verdict,
        record: read_training_record(&state, &id).unwrap(),
        challenger_delta: bal(&state, &challenger()) - c0,
        trainer_delta: bal(&state, &trainer_account()) - t0,
        payer_delta: bal(&state, &payer()) - p0,
        bond_after: state.get_balance(derive_compute_bond_vault_address(DID).as_bytes()),
    }
}

#[tokio::test]
async fn scenario_honest_trainer_is_paid_and_the_challenger_compensates_it() {
    let o = challenge_round(Trainer::Honest, 64).await;
    assert_eq!(o.verdict, TrainingVerdict::Reproduced);
    assert_eq!(
        o.record.challenges[0].outcome,
        Some(ChallengeOutcome::Dismissed)
    );
    assert_eq!(o.record.settled, Some(RoundSettlement::Released));
    let bond = DEFAULT_CHALLENGE_BOND_GWEI as u128 * GWEI;
    let fee = bond * DEFAULT_CHALLENGE_FEE_BPS as u128 / 10_000;
    assert_eq!(o.challenger_delta, -(bond as i128));
    let settlement = crate::native::economy::settlement_fee(&setup(0).1, ESCROW);
    assert_eq!(o.trainer_delta, (ESCROW + bond - fee - settlement) as i128);
    assert_eq!(o.payer_delta, 0);
    assert_eq!(o.bond_after, 100 * TNZO);
}

async fn assert_caught(kind: Trainer, fault: impl Fn(&StepFault) -> bool) {
    let o = challenge_round(kind, 64).await;
    match &o.verdict {
        TrainingVerdict::Fault { fault: f, .. } => assert!(fault(f), "{kind:?}: {f:?}"),
        other => panic!("{kind:?} not caught: {other:?}"),
    }
    assert_eq!(
        o.record.challenges[0].outcome,
        Some(ChallengeOutcome::Upheld)
    );
    assert_eq!(o.record.settled, Some(RoundSettlement::Voided));
    let bond = DEFAULT_CHALLENGE_BOND_GWEI as u128 * GWEI;
    let fee = bond * DEFAULT_CHALLENGE_FEE_BPS as u128 / 10_000;
    let reward = DEFAULT_CHALLENGER_REWARD_GWEI as u128 * GWEI;
    let penalty = DEFAULT_PENALTY_GWEI as u128 * GWEI;
    assert_eq!(o.challenger_delta, reward as i128 - fee as i128);
    assert_eq!(o.trainer_delta, 0, "{kind:?} was paid");
    assert_eq!(o.payer_delta, ESCROW as i128);
    assert_eq!(o.bond_after, 100 * TNZO - reward - penalty);
}

#[tokio::test]
async fn scenario_a_trainer_that_skips_steps_is_slashed() {
    // Every other step skipped: any sampled step past the first catches it.
    static ODD: std::sync::OnceLock<Vec<u64>> = std::sync::OnceLock::new();
    let odd: &'static [u64] = ODD.get_or_init(|| (1..64).step_by(2).collect());
    assert_caught(Trainer::SkipSteps(odd), |f| {
        matches!(f, StepFault::Mismatch(_))
    })
    .await;
}

#[tokio::test]
async fn scenario_a_trainer_on_the_wrong_shard_is_slashed() {
    assert_caught(Trainer::WrongShard, |f| *f == StepFault::WrongBatch).await;
}

#[tokio::test]
async fn scenario_a_fabricated_checkpoint_is_always_caught() {
    assert_caught(Trainer::FabricatedCheckpoint, |f| {
        *f == StepFault::WrongCheckpoint
    })
    .await;
}

/// A trainer skipping a small share of its steps is not always sampled; the
/// share of challenges that catch it matches `1 - (1 - f)^s` over the
/// interior samples, and its expected loss when challenged exceeds what
/// skipping saved.
#[test]
fn scenario_rare_skips_are_caught_at_the_sampling_rate_and_do_not_pay() {
    const STEPS: u64 = 200;
    const SAMPLES: u64 = 10;
    static SKIP: std::sync::OnceLock<Vec<u64>> = std::sync::OnceLock::new();
    let skip: &'static [u64] = SKIP.get_or_init(|| (1..STEPS - 1).step_by(10).collect());
    let r = train(Trainer::SkipSteps(skip), STEPS, [1; 32]);
    let trials = 400u32;
    let caught = (0..trials)
        .filter(|i| {
            let seed = challenge_seed("round", *i, b"beacon");
            r.check(&seed, SAMPLES).upheld()
        })
        .count() as u64;
    let fake_ppm = skip.len() as u64 * 1_000_000 / STEPS;
    // The ends are always sampled and never skipped here; the rest are draws.
    let expected = catch_chance_ppm(fake_ppm, SAMPLES - 2);
    let observed = caught * 1_000_000 / trials as u64;
    assert!(
        observed + 80_000 >= expected && observed <= expected + 120_000,
        "observed {observed} ppm, expected about {expected} ppm"
    );
    // Expected loss of one challenge against the gain of the skipped work,
    // at the governed defaults: the forfeited milestone plus the slash,
    // weighted by the catch chance, against the skipped share of the pay.
    let at_risk = ESCROW
        + DEFAULT_PENALTY_GWEI as u128 * GWEI
        + DEFAULT_CHALLENGER_REWARD_GWEI as u128 * GWEI;
    let expected_loss = at_risk * expected as u128 / 1_000_000;
    let gain = ESCROW * fake_ppm as u128 / 1_000_000;
    assert!(expected_loss > gain, "loss {expected_loss} <= gain {gain}");
    // And for every share of skipped steps, not only this one.
    for f in [1u64, 1_000, 10_000, 100_000, 500_000, 1_000_000] {
        assert!(catch_chance_ppm(f, DEFAULT_SAMPLE_STEPS - 2) >= f);
    }
}

#[test]
fn an_honest_round_reproduces_on_every_seed_and_a_withheld_step_convicts() {
    let r = train(Trainer::Honest, 50, [2; 32]);
    for i in 0..50u32 {
        assert_eq!(
            r.check(&challenge_seed("x", i, b"m"), 8),
            TrainingVerdict::Reproduced
        );
    }
    let withheld = check_challenge(
        &Linear,
        &r.receipt,
        HP,
        &[0; 32],
        8,
        DEFAULT_TOLERANCE_PPM,
        &|k| (k != 49).then(|| r.open(k)).flatten(),
    );
    assert_eq!(
        withheld,
        TrainingVerdict::Fault {
            step: 49,
            fault: StepFault::Unopened
        }
    );
    // A verifier on another kernel class does not judge the round.
    let mut other = r.receipt.clone();
    other.kernel_class = "another".into();
    assert!(matches!(
        check_challenge(&Linear, &other, HP, &[0; 32], 8, 0, &|k| r.open(k)),
        TrainingVerdict::BadReceipt(_)
    ));
}

fn sign_batched(
    receipt: TrainingReceipt,
) -> tenzro_types::training_verification::SignedTrainingReceipt {
    sign_batched_by(receipt, 4)
}

fn sign_batched_by(
    receipt: TrainingReceipt,
    seed: u8,
) -> tenzro_types::training_verification::SignedTrainingReceipt {
    use tenzro_crypto::batch::{BatchParams, BatchService};
    let svc = BatchService::new(
        std::sync::Arc::new(tenzro_crypto::testing::TestHybridSigner::hybrid(seed)),
        BatchParams {
            max_batch: 1,
            flush_interval_ms: 1_000,
        },
        0,
    )
    .unwrap();
    let sig = svc
        .submit(receipt.digest().to_vec(), receipt.signed_at_ms)
        .unwrap()
        .wait(std::time::Duration::from_millis(100))
        .unwrap();
    tenzro_types::training_verification::SignedTrainingReceipt {
        receipt,
        batched: hex::encode(serde_json::to_vec(&sig).unwrap()),
        tee: None,
    }
}

#[tokio::test]
async fn only_a_batched_signature_commits_a_receipt() {
    let (ex, mut state) = setup(100 * TNZO);
    let commit_b = |receipt| TrainingProofOp::Commit { receipt };
    let id = escrow(&mut state, 2, training_executor(), far_expiry());
    let r2 = train(Trainer::Honest, 8, id);
    run(
        &ex,
        &mut state,
        &payer(),
        commit_b(sign_batched(r2.receipt.clone())),
        T0,
    )
    .await
    .unwrap();

    // A commit with no batched signature is refused.
    let id = escrow(&mut state, 4, training_executor(), far_expiry());
    let r4 = train(Trainer::Honest, 8, id);
    let mut unsigned = sign_batched(r4.receipt.clone());
    unsigned.batched = String::new();
    assert!(
        run(&ex, &mut state, &payer(), commit_b(unsigned), T0)
            .await
            .is_err()
    );

    // A batch signed by another identity is refused.
    let id = escrow(&mut state, 5, training_executor(), far_expiry());
    let r5 = train(Trainer::Honest, 8, id);
    let mut forged = sign_batched(r5.receipt.clone());
    forged.receipt.signed_at_ms += 1;
    assert!(
        run(&ex, &mut state, &payer(), commit_b(forged), T0)
            .await
            .is_err()
    );
}
