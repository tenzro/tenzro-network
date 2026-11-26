//! Upgrade readiness and the security-fix track, end to end through the
//! executor.

use super::*;
use crate::VmType;
use crate::config::VmConfig;
use crate::governance::{
    DEFAULT_SECURITY_REVEAL_WINDOW_MS, DEFAULT_UPGRADE_ACTIVATION_DELAY_BLOCKS, PolicyTrack,
    Proposal, ProposalAction, ProposalStatus, SecurityBasis, upgrade_ready_digest,
};
use crate::state_adapter::StateAdapter;
use sha2::Digest;
use tenzro_tee::tpm_attest::tests::{SoftTpm, evidence};
use tenzro_tee::tpm_attest::{
    MachineAttestation, admission_challenge, attestation_key_sec1, machine_did_for_attestation_key,
};
use tenzro_types::token::PolicyUpdate;

const GAS: u128 = 10_000_000_000_000_000_000;
const GAS_PRICE: u128 = 1_000_000_000;
pub(super) const CODE: [u8; 32] = [0xc0; 32];
pub(super) const HEIGHT: u64 = 5_000;

pub(super) fn tx(from: &[u8], data: Vec<u8>, at_ms: i64) -> VmTransaction {
    let mut tx = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        400_000,
        GAS_PRICE,
        0,
        VmType::Evm,
        1337,
    );
    tx.block_timestamp_ms = Some(at_ms);
    tx.block_height = Some(HEIGHT);
    tx
}

pub(super) struct Validator {
    pub(super) addr: Vec<u8>,
    pub(super) tpm: SoftTpm,
}

/// A bonded validator whose account is a machine identity admitted with
/// `tpm`'s attestation key.
fn validator(state: &mut StateAdapter, seed: u8, stake: u128) -> Validator {
    let addr = vec![seed; 32];
    let tpm = SoftTpm::new(seed);
    let (probe, _) = evidence(&tpm, &[0; 32]);
    let ak = attestation_key_sec1(&probe).unwrap();
    let did = machine_did_for_attestation_key(&ak);
    let controller = vec![seed; 33];
    let nonce = [seed; 32];
    let (ev, _) = evidence(&tpm, &admission_challenge(&did, &controller, &nonce));
    let att = MachineAttestation {
        evidence: ev,
        nonce: nonce.to_vec(),
        activated: true,
    };
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert(
        tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
        serde_json::to_string(&att).unwrap(),
    );
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: did.clone(),
        identity_type: "machine".into(),
        display_name: String::new(),
        controller_pubkey: controller,
        key_type: "p256".into(),
        wallet_id: String::new(),
        wallet_address: Address::new([seed; 32]),
        pq_verifying_key: Vec::new(),
        metadata,
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
        &identity_storage_key(&did),
        serde_json::to_vec(&record).unwrap(),
    );
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(&addr).as_bytes(),
        did.into_bytes(),
    );
    staking::add_bond(state, &addr, stake, -crate::governance::MIN_BOND_AGE_MS).unwrap();
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    state.set_balance(&STAKING_VAULT_ADDRESS, vault + stake);
    state.set_balance(&addr, GAS);
    Validator { addr, tpm }
}

pub(super) fn ready_data(v: &Validator, code: &[u8; 32], quoted_for: &[u8; 32]) -> Vec<u8> {
    let (ev, _) = evidence(&v.tpm, &upgrade_ready_digest(quoted_for, &v.addr));
    let mut data = SELECTOR_UPGRADE_READY.to_vec();
    data.extend_from_slice(code);
    data.extend_from_slice(&serde_json::to_vec(&ev).unwrap());
    data
}

pub(super) fn upgrade(track: PolicyTrack) -> ProposalAction {
    ProposalAction::PolicyUpdate {
        update: PolicyUpdate::ProtocolUpgrade {
            version: "2".into(),
            code_hash: CODE.to_vec(),
        },
        memo: "ship 2".into(),
        track,
    }
}

/// A protocol upgrade already through its vote and timelock.
pub(super) fn queued(state: &mut StateAdapter, id: [u8; 32], action: ProposalAction) {
    let mut p = Proposal::open(
        hex::encode(id),
        Address::new([0x77; 32]),
        action,
        0,
        crate::governance::GovernanceRules::GENESIS,
    );
    p.status = ProposalStatus::Queued;
    p.queued_ms = Some(0);
    p.eta_ms = Some(0);
    store_proposal(state, &p).unwrap();
}

pub(super) fn execute_data(id: &[u8; 32]) -> Vec<u8> {
    let mut data = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
    data.extend_from_slice(id);
    data
}

/// Three validators: 66%, 1% and 33% of bonded stake.
pub(super) fn network() -> (NativeExecutor, StateAdapter, Vec<Validator>) {
    let mut state = StateAdapter::new();
    let vs = vec![
        validator(&mut state, 1, 66),
        validator(&mut state, 2, 1),
        validator(&mut state, 3, 33),
    ];
    (NativeExecutor::new(VmConfig::default()).unwrap(), state, vs)
}

#[tokio::test]
async fn sixty_six_percent_does_not_enact_and_sixty_seven_does() {
    let (ex, mut state, vs) = network();
    let id = [0xcd; 32];
    queued(&mut state, id, upgrade(PolicyTrack::Standard));

    ex.execute_transaction(
        &tx(&vs[0].addr, ready_data(&vs[0], &CODE, &CODE), 1),
        &mut state,
    )
    .await
    .expect("a validator's machine signals readiness");
    assert_eq!(readiness(&state, &CODE).ready_bps(), 6_600);
    let err = ex
        .execute_transaction(&tx(&vs[2].addr, execute_data(&id), 2), &mut state)
        .await
        .expect_err("66% must not enact");
    assert!(err.to_string().contains("6700 bps must"), "{err}");

    ex.execute_transaction(
        &tx(&vs[1].addr, ready_data(&vs[1], &CODE, &CODE), 3),
        &mut state,
    )
    .await
    .unwrap();
    assert!(readiness(&state, &CODE).met());
    let r = ex
        .execute_transaction(&tx(&vs[2].addr, execute_data(&id), 4), &mut state)
        .await
        .unwrap();
    assert!(
        r.logs
            .iter()
            .any(|l| l.topics[0] == UPGRADE_SCHEDULED_TOPIC)
    );
    let a = read_upgrade_activation(&state).unwrap();
    assert_eq!(
        a.activation_height,
        HEIGHT + DEFAULT_UPGRADE_ACTIVATION_DELAY_BLOCKS
    );
    assert_eq!(a.code_hash, hex::encode(CODE));

    // The decision record binds the executed proposal record and its height.
    let id_hex = hex::encode(id);
    let record = state
        .get_storage(&SYSTEM_ADDRESS, governance_proposal_key(&id_hex).as_bytes())
        .unwrap();
    let decision = state
        .get_storage(
            &SYSTEM_ADDRESS,
            governance_decision_slot(&id_hex).as_bytes(),
        )
        .unwrap();
    let (digest, height) = tenzro_types::evidence_pack::decode_decision(&decision).unwrap();
    assert_eq!(digest.as_slice(), sha2::Sha256::digest(&record).as_slice());
    assert_eq!(height, HEIGHT);
    let kinds: Vec<_> = governance_receipt_slots(&state, &id_hex)
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(
        kinds,
        [
            "proposal",
            "tally",
            "readiness",
            "activation",
            "veto_total",
            "decision"
        ]
    );
}

#[tokio::test]
async fn the_activation_height_is_the_same_on_every_replica() {
    let mut seen = Vec::new();
    for _ in 0..2 {
        let (ex, mut state, vs) = network();
        let id = [0xcd; 32];
        queued(&mut state, id, upgrade(PolicyTrack::Standard));
        for v in &vs {
            ex.execute_transaction(&tx(&v.addr, ready_data(v, &CODE, &CODE), 1), &mut state)
                .await
                .unwrap();
        }
        ex.execute_transaction(&tx(&vs[0].addr, execute_data(&id), 2), &mut state)
            .await
            .unwrap();
        seen.push(read_upgrade_activation(&state).unwrap());
    }
    assert_eq!(seen[0], seen[1]);
}

#[tokio::test]
async fn a_forged_quote_is_refused() {
    let (ex, mut state, vs) = network();
    // A quote over another binary.
    let err = ex
        .execute_transaction(
            &tx(&vs[0].addr, ready_data(&vs[0], &CODE, &[0xee; 32]), 1),
            &mut state,
        )
        .await
        .expect_err("the quote answers another digest");
    assert!(err.to_string().contains("quote refused"), "{err}");
    // A quote by a TPM other than the one the validator was admitted with.
    let other = Validator {
        addr: vs[0].addr.clone(),
        tpm: SoftTpm::new(9),
    };
    let err = ex
        .execute_transaction(
            &tx(&vs[0].addr, ready_data(&other, &CODE, &CODE), 1),
            &mut state,
        )
        .await
        .expect_err("another machine's quote");
    assert!(
        err.to_string().contains("admitted attestation key"),
        "{err}"
    );
    // A tampered signature.
    let (mut ev, _) = evidence(&vs[0].tpm, &upgrade_ready_digest(&CODE, &vs[0].addr));
    ev.quote_signature[10] ^= 1;
    let mut data = SELECTOR_UPGRADE_READY.to_vec();
    data.extend_from_slice(&CODE);
    data.extend_from_slice(&serde_json::to_vec(&ev).unwrap());
    assert!(
        ex.execute_transaction(&tx(&vs[0].addr, data, 1), &mut state)
            .await
            .is_err()
    );
    assert!(upgrade::ready_signals(&state, &CODE).is_empty());
}

#[tokio::test]
async fn a_security_fix_without_a_record_is_refused() {
    let (ex, mut state, vs) = network();
    let fix = upgrade(PolicyTrack::SecurityFix {
        basis: SecurityBasis::Fault {
            fault_id: "missing".into(),
        },
    });
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&fix).unwrap());
    let err = ex
        .execute_transaction(&tx(&vs[0].addr, data, 1), &mut state)
        .await
        .expect_err("no upheld fault");
    assert!(err.to_string().contains("upheld fault"), "{err}");

    let not_upgrade = ProposalAction::PolicyUpdate {
        update: PolicyUpdate::TpmEndorsementRootsSet {
            roots_pem: Vec::new(),
        },
        memo: "x".into(),
        track: PolicyTrack::SecurityFix {
            basis: SecurityBasis::Vulnerability {
                commitment: "ab".repeat(32),
            },
        },
    };
    assert!(
        not_upgrade.validate().is_err(),
        "only a protocol upgrade is a security fix"
    );
}

/// Propose a security fix on a commitment, carry it, ready every machine and
/// enact it at `at`. Returns the proposal id.
async fn enacted_fix(
    ex: &NativeExecutor,
    state: &mut StateAdapter,
    vs: &[Validator],
    commitment: &str,
    at: i64,
) -> [u8; 32] {
    let fix = upgrade(PolicyTrack::SecurityFix {
        basis: SecurityBasis::Vulnerability {
            commitment: commitment.into(),
        },
    });
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&fix).unwrap());
    let out = ex
        .execute_transaction(&tx(&vs[0].addr, data, 1), state)
        .await
        .expect("propose")
        .output;
    let id: [u8; 32] = out.as_slice().try_into().unwrap();
    let mut p = load_proposal(state, &hex::encode(id)).unwrap();
    assert_eq!(p.track, crate::governance::ProposalTrack::SecurityFix);
    p.status = ProposalStatus::Queued;
    p.queued_ms = Some(0);
    p.eta_ms = Some(0);
    store_proposal(state, &p).unwrap();
    for v in vs {
        ex.execute_transaction(&tx(&v.addr, ready_data(v, &CODE, &CODE), 2), state)
            .await
            .unwrap();
    }
    ex.execute_transaction(&tx(&vs[2].addr, execute_data(&id), at), state)
        .await
        .expect("enacts");
    id
}

fn disclosure_data(id: &[u8; 32], disclosure: &[u8]) -> Vec<u8> {
    let mut data = SELECTOR_SECURITY_DISCLOSURE.to_vec();
    data.extend_from_slice(id);
    data.extend_from_slice(disclosure);
    data
}

#[tokio::test]
async fn a_missing_reveal_slashes_the_proposer() {
    let (ex, mut state, vs) = network();
    let report = b"overflow in the fee path";
    let commitment = hex::encode(sha2::Sha256::digest(report));
    let id = enacted_fix(&ex, &mut state, &vs, &commitment, 10).await;
    let window = DEFAULT_SECURITY_REVEAL_WINDOW_MS as i64;

    let early = ex
        .execute_transaction(
            &tx(&vs[1].addr, disclosure_data(&id, &[]), 10 + window),
            &mut state,
        )
        .await;
    assert!(early.is_err(), "the reveal window is still open");

    let before = bonded_stake_of(&state, &vs[0].addr);
    ex.execute_transaction(
        &tx(&vs[1].addr, disclosure_data(&id, &[]), 11 + window),
        &mut state,
    )
    .await
    .expect("anyone settles a lapse");
    assert!(
        bonded_stake_of(&state, &vs[0].addr) < before,
        "the proposer is slashed"
    );
    assert_eq!(
        read_security_commitment(&state, &hex::encode(id))
            .unwrap()
            .settled
            .as_deref(),
        Some("slashed")
    );
    assert!(
        ex.execute_transaction(
            &tx(&vs[0].addr, disclosure_data(&id, report), 12 + window),
            &mut state
        )
        .await
        .is_err(),
        "settled once"
    );
}

#[tokio::test]
async fn a_reveal_settles_without_a_slash() {
    let (ex, mut state, vs) = network();
    let report = b"overflow in the fee path";
    let commitment = hex::encode(sha2::Sha256::digest(report));
    let id = enacted_fix(&ex, &mut state, &vs, &commitment, 10).await;
    assert!(
        ex.execute_transaction(
            &tx(&vs[0].addr, disclosure_data(&id, b"something else"), 20),
            &mut state
        )
        .await
        .is_err()
    );
    let before = bonded_stake_of(&state, &vs[0].addr);
    ex.execute_transaction(
        &tx(&vs[0].addr, disclosure_data(&id, report), 20),
        &mut state,
    )
    .await
    .unwrap();
    let window = DEFAULT_SECURITY_REVEAL_WINDOW_MS as i64;
    assert!(
        ex.execute_transaction(
            &tx(&vs[1].addr, disclosure_data(&id, &[]), window * 2),
            &mut state
        )
        .await
        .is_err()
    );
    assert_eq!(bonded_stake_of(&state, &vs[0].addr), before);
}

/// The governance receipt vectors contracts on other chains are tested
/// against: a protocol upgrade enacted by the executor, its proposal and
/// decision records committed to a state trie, and their state proofs. Run
/// with `TENZRO_WRITE_FIXTURES=1` to rewrite `sdk/fixtures/governance_receipt`.
#[tokio::test]
async fn the_governance_receipt_vectors_are_current() {
    use tenzro_storage::state_trie::capture::Writes;
    use tenzro_storage::{MemoryStore, StateTrie};
    use tenzro_types::evidence_pack::{STATE_NAMESPACE, vm_storage_key};
    use tenzro_types::remote_grant::system_slot_tree_key;

    let (ex, mut state, vs) = network();
    let id = [0xcd; 32];
    queued(&mut state, id, upgrade(PolicyTrack::Standard));
    for v in &vs {
        ex.execute_transaction(&tx(&v.addr, ready_data(v, &CODE, &CODE), 1), &mut state)
            .await
            .unwrap();
    }
    ex.execute_transaction(&tx(&vs[0].addr, execute_data(&id), 2), &mut state)
        .await
        .unwrap();

    let id_hex = hex::encode(id);
    let other = hex::encode([0xce; 32]);
    let trie = StateTrie::new(std::sync::Arc::new(MemoryStore::new()));
    let mut writes = Writes::new();
    for slot in [
        governance_proposal_key(&id_hex),
        governance_decision_slot(&id_hex),
    ] {
        writes.insert(
            (
                STATE_NAMESPACE.to_string(),
                vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
            ),
            state.get_storage(&SYSTEM_ADDRESS, slot.as_bytes()),
        );
    }
    let root = trie.commit(1, &writes).unwrap();
    let prove = |slot: &str| {
        let (value, proof) = trie
            .prove(
                1,
                STATE_NAMESPACE,
                &vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
            )
            .unwrap();
        (value, hex::encode(proof.encode()))
    };
    let (record, record_proof) = prove(&governance_proposal_key(&id_hex));
    let (decision, decision_proof) = prove(&governance_decision_slot(&id_hex));
    let (absent, absent_proof) = prove(&governance_decision_slot(&other));
    let (record, decision) = (record.unwrap(), decision.unwrap());
    assert!(absent.is_none());
    let (record_hash, height) = tenzro_types::evidence_pack::decode_decision(&decision).unwrap();
    let vectors = serde_json::json!({
        "state_root": root.to_string(),
        "proposal_id": id_hex,
        "proposal_record": hex::encode(&record),
        "proposal_record_hash": hex::encode(record_hash),
        "executed_height": height,
        "decision_tree_key": hex::encode(system_slot_tree_key(governance_decision_slot(&id_hex).as_bytes())),
        "decision": hex::encode(&decision),
        "decision_proof": decision_proof,
        "proposal_tree_key": hex::encode(system_slot_tree_key(governance_proposal_key(&id_hex).as_bytes())),
        "proposal_proof": record_proof,
        "absent_proposal_id": other,
        "absent_decision_tree_key": hex::encode(system_slot_tree_key(governance_decision_slot(&other).as_bytes())),
        "absent_decision_proof": absent_proof,
    });
    let full = format!(
        "{}/../../sdk/fixtures/governance_receipt/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(&full).parent().unwrap()).unwrap();
        std::fs::write(&full, text).unwrap();
        return;
    }
    assert_eq!(
        std::fs::read_to_string(&full).unwrap_or_default(),
        text,
        "rerun with TENZRO_WRITE_FIXTURES=1"
    );
}

/// A manufacturer root as governance records it: one PEM certificate.
fn root_pem(seed: u8, name: &str) -> String {
    use base64::Engine;
    use tenzro_tee::x509::testca;
    let k = testca::key(seed);
    let der = testca::issue(name, &k, name, &k, true, 1);
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

fn machine_did(v: &Validator) -> String {
    let (probe, _) = evidence(&v.tpm, &[0; 32]);
    machine_did_for_attestation_key(&attestation_key_sec1(&probe).unwrap())
}

/// Re-records `v`'s admission with an endorsement certificate issued by the
/// root `seed` / `name`, as a machine from another manufacturer would carry.
fn endorse_under(state: &mut StateAdapter, v: &Validator, seed: u8, name: &str) {
    use p256::pkcs8::EncodePublicKey;
    use tenzro_tee::x509::testca;
    let did = machine_did(v);
    let key = identity_storage_key(&did);
    let mut record: tenzro_types::identity::RegisterIdentityPayload =
        serde_json::from_slice(&state.get_storage(&SYSTEM_ADDRESS, &key).unwrap()).unwrap();
    let slot = tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string();
    let mut att: MachineAttestation = serde_json::from_str(&record.metadata[&slot]).unwrap();
    let spki = v.tpm.ek.public_key().to_public_key_der().unwrap();
    att.evidence.ek_certificate = testca::issue_with_spki(
        "EK",
        spki.as_bytes(),
        name,
        &testca::key(seed),
        false,
        2,
        (1_000_000_000, 4_000_000_000),
        &[],
    );
    record
        .metadata
        .insert(slot, serde_json::to_string(&att).unwrap());
    state.set_storage(&SYSTEM_ADDRESS, &key, serde_json::to_vec(&record).unwrap());
}

/// Enacts `roots` as the recognised endorsement roots through a queued
/// governance proposal, on the running executor.
async fn enact_roots(
    ex: &NativeExecutor,
    state: &mut StateAdapter,
    by: &Validator,
    id: [u8; 32],
    roots: Vec<String>,
    at: i64,
) {
    queued(
        state,
        id,
        ProposalAction::PolicyUpdate {
            update: PolicyUpdate::TpmEndorsementRootsSet { roots_pem: roots },
            memo: "manufacturer root rotation".into(),
            track: PolicyTrack::Standard,
        },
    );
    ex.execute_transaction(&tx(&by.addr, execute_data(&id), at), state)
        .await
        .expect("the root rotation enacts");
}

/// A TPM manufacturer root is added alongside the one in force and the old
/// one retired, each by a governance decision on the running chain. While
/// both are recognised, machines under either are endorsed; once the old
/// one is retired, only machines under the new one are. Admission records,
/// bonds and balances are untouched throughout.
#[tokio::test]
async fn a_tpm_root_is_added_then_the_old_one_retired_by_governance_without_a_restart() {
    const AT: i64 = 2_000_000_000_000;
    let (ex, mut state, vs) = network();
    let (old, new) = (root_pem(40, "TPM Root"), root_pem(41, "TPM Root 2"));
    endorse_under(&mut state, &vs[2], 41, "TPM Root 2");
    let mut changes = Vec::new();
    funding::set_endorsement_roots(&mut state, std::slice::from_ref(&old), &mut changes).unwrap();
    let (a, b) = (machine_did(&vs[0]), machine_did(&vs[2]));
    let records = |s: &StateAdapter| {
        [&a, &b].map(|d| s.get_storage(&SYSTEM_ADDRESS, &identity_storage_key(d)))
    };
    let held = |s: &StateAdapter| {
        vs.iter()
            .map(|v| (s.get_balance(&v.addr), staking::bonded_stake_of(s, &v.addr)))
            .collect::<Vec<_>>()
    };
    let (records_before, held_before) = (records(&state), held(&state));

    assert!(machine_endorsed(&state, &a, AT).is_ok());
    assert!(machine_endorsed(&state, &b, AT).is_err());

    enact_roots(
        &ex,
        &mut state,
        &vs[0],
        [0xa1; 32],
        vec![old.clone(), new.clone()],
        1,
    )
    .await;
    assert_eq!(
        read_endorsement_roots(&state),
        vec![old.clone(), new.clone()]
    );
    assert!(machine_endorsed(&state, &a, AT).is_ok());
    assert!(machine_endorsed(&state, &b, AT).is_ok());

    enact_roots(&ex, &mut state, &vs[0], [0xa2; 32], vec![new.clone()], 2).await;
    assert_eq!(read_endorsement_roots(&state), vec![new]);
    assert!(machine_endorsed(&state, &a, AT).is_err());
    assert!(machine_endorsed(&state, &b, AT).is_ok());

    assert_eq!(records(&state), records_before);
    let after = held(&state);
    for (i, ((bal, bond), (bal0, bond0))) in after.iter().zip(&held_before).enumerate() {
        assert_eq!(bond, bond0, "validator {i}'s bond");
        if i != 0 {
            assert_eq!(bal, bal0, "validator {i}'s balance");
        }
    }
}

const OTHER: [u8; 32] = [0xc1; 32];
const THIRD: [u8; 32] = [0xc2; 32];

fn platform(code_hash: [u8; 32], platform: &str) -> tenzro_types::token::PlatformDigest {
    tenzro_types::token::PlatformDigest {
        platform: platform.into(),
        code_hash: code_hash.to_vec(),
    }
}

fn platforms_update() -> &'static PolicyUpdate {
    static U: std::sync::OnceLock<PolicyUpdate> = std::sync::OnceLock::new();
    U.get_or_init(|| match two_platform_upgrade() {
        ProposalAction::PolicyUpdate { update, .. } => update,
        _ => unreachable!("an upgrade proposal"),
    })
}

fn single_update() -> &'static PolicyUpdate {
    static U: std::sync::OnceLock<PolicyUpdate> = std::sync::OnceLock::new();
    U.get_or_init(|| match upgrade(PolicyTrack::Standard) {
        ProposalAction::PolicyUpdate { update, .. } => update,
        _ => unreachable!("an upgrade proposal"),
    })
}

/// An upgrade of a release built for x86_64 and aarch64 Linux.
fn two_platform_upgrade() -> ProposalAction {
    ProposalAction::PolicyUpdate {
        update: PolicyUpdate::ProtocolUpgradePlatforms {
            version: "2".into(),
            digests: vec![
                platform(CODE, "x86_64-unknown-linux-gnu"),
                platform(OTHER, "aarch64-unknown-linux-gnu"),
            ],
        },
        memo: "ship 2".into(),
        track: PolicyTrack::Standard,
    }
}

/// An upgrade built for two platforms enacts on the stake of validators
/// running either binary, each counted once; a validator quoting a binary
/// the upgrade does not name adds nothing.
#[tokio::test]
async fn validators_on_either_platforms_binary_count_towards_one_upgrade() {
    let (ex, mut state, vs) = network();
    set_governed_param_for_test(&mut state, upgrade::PLATFORMS_GATE, 0);
    let id = [0xce; 32];
    queued(&mut state, id, two_platform_upgrade());
    let binaries: [&[u8]; 2] = [&CODE, &OTHER];

    // 66% on the first platform, 33% on a binary the upgrade does not name.
    ex.execute_transaction(
        &tx(&vs[0].addr, ready_data(&vs[0], &CODE, &CODE), 1),
        &mut state,
    )
    .await
    .unwrap();
    ex.execute_transaction(
        &tx(&vs[2].addr, ready_data(&vs[2], &THIRD, &THIRD), 2),
        &mut state,
    )
    .await
    .unwrap();
    assert_eq!(upgrade_readiness(&state, &binaries).ready_bps(), 6_600);
    ex.execute_transaction(&tx(&vs[2].addr, execute_data(&id), 3), &mut state)
        .await
        .expect_err("the third binary is not this upgrade's");

    // The same validator signalling for the other platform too is one
    // validator.
    ex.execute_transaction(
        &tx(&vs[0].addr, ready_data(&vs[0], &OTHER, &OTHER), 4),
        &mut state,
    )
    .await
    .unwrap();
    assert_eq!(upgrade_readiness(&state, &binaries).ready_bps(), 6_600);

    // 1% on the second platform carries it.
    ex.execute_transaction(
        &tx(&vs[1].addr, ready_data(&vs[1], &OTHER, &OTHER), 5),
        &mut state,
    )
    .await
    .unwrap();
    assert!(upgrade_readiness(&state, &binaries).met());
    let r = ex
        .execute_transaction(&tx(&vs[2].addr, execute_data(&id), 6), &mut state)
        .await
        .unwrap();
    assert!(
        r.logs
            .iter()
            .any(|l| l.topics[0] == upgrade::UPGRADE_PLATFORMS_TOPIC)
    );
    let a = read_upgrade_activation(&state).unwrap();
    let p = read_upgrade_platforms(&state).unwrap();
    assert_eq!(p.proposal_id, a.proposal_id);
    assert_eq!(a.code_hash, hex::encode(CODE));
    assert!(p.names_binary(&hex::encode(CODE)));
    assert!(p.names_binary(&hex::encode(OTHER)));
    assert!(!p.names_binary(&hex::encode(THIRD)));
}

/// Before the vote that puts them in force, an upgrade naming a binary per
/// platform is refused when proposed and, had one been queued, when enacted;
/// a single-binary upgrade enacts as it always did and records no platforms.
#[tokio::test]
async fn until_voted_in_an_upgrade_names_one_binary() {
    let (ex, mut state, vs) = network();
    let err = crate::feature_gate::refuse_dormant_policy(&state, platforms_update()).unwrap_err();
    assert!(err.to_string().contains("not in force"), "{err}");
    crate::feature_gate::refuse_dormant_policy(&state, single_update()).unwrap();

    for (v, at) in [(&vs[0], 1), (&vs[1], 2)] {
        ex.execute_transaction(&tx(&v.addr, ready_data(v, &CODE, &CODE), at), &mut state)
            .await
            .unwrap();
    }
    let platforms = [0xcf; 32];
    queued(&mut state, platforms, two_platform_upgrade());
    let err = ex
        .execute_transaction(&tx(&vs[2].addr, execute_data(&platforms), 3), &mut state)
        .await
        .expect_err("dormant");
    assert!(err.to_string().contains("not in force"), "{err}");
    assert!(read_upgrade_activation(&state).is_none());

    let single = [0xd0; 32];
    queued(&mut state, single, upgrade(PolicyTrack::Standard));
    ex.execute_transaction(&tx(&vs[2].addr, execute_data(&single), 4), &mut state)
        .await
        .unwrap();
    assert_eq!(
        read_upgrade_activation(&state).unwrap().code_hash,
        hex::encode(CODE)
    );
    assert!(read_upgrade_platforms(&state).is_none());

    // From the epoch of the vote the same proposal is admitted.
    set_governed_param_for_test(&mut state, upgrade::PLATFORMS_GATE, 0);
    crate::feature_gate::refuse_dormant_policy(&state, platforms_update()).unwrap();
}

#[test]
fn an_upgrade_names_each_platform_and_each_binary_once() {
    use crate::governance::validate_policy_update;
    let digest = |name: &str, byte: u8| platform([byte; 32], name);
    let upgrade = |digests| PolicyUpdate::ProtocolUpgradePlatforms {
        version: "2".into(),
        digests,
    };
    let (x86, arm) = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu");
    assert!(validate_policy_update(&upgrade(vec![digest(x86, 1), digest(arm, 2)])).is_ok());
    assert!(validate_policy_update(&upgrade(Vec::new())).is_err());
    assert!(validate_policy_update(&upgrade(vec![digest(x86, 1), digest(x86, 2)])).is_err());
    assert!(validate_policy_update(&upgrade(vec![digest(x86, 1), digest(arm, 1)])).is_err());
    assert!(validate_policy_update(&upgrade(vec![digest("", 1)])).is_err());
    assert!(validate_policy_update(&upgrade(vec![digest("Linux x86", 1)])).is_err());
    let mut short = digest(x86, 1);
    short.code_hash.pop();
    assert!(validate_policy_update(&upgrade(vec![short])).is_err());
    let many = (0..=tenzro_types::token::MAX_UPGRADE_PLATFORMS as u8)
        .map(|i| digest(&format!("platform-{i}"), i))
        .collect();
    assert!(validate_policy_update(&upgrade(many)).is_err());
}

/// An account bonded in the attestor role with ample stake.
fn builder(state: &mut StateAdapter, seed: u8) -> Vec<u8> {
    let account = vec![seed; 32];
    let stake = tenzro_types::token::RoleStake {
        bonded: 1_000_000 * 1_000_000_000_000_000_000,
        capacity: tenzro_types::token::StakeCapacity::None,
        unbonding: 0,
        release_at_ms: 0,
        bonded_at_ms: 0,
        endpoint: None,
    };
    state.set_storage(
        &SYSTEM_ADDRESS,
        format!("role_stake:{}:attestor", hex::encode(&account)).as_bytes(),
        serde_json::to_vec(&stake).unwrap(),
    );
    state.set_balance(&account, GAS);
    account
}

fn attest_data(code: &[u8; 32]) -> Vec<u8> {
    let mut data = native_call::SELECTOR_NATIVE_CALL.to_vec();
    data.extend(build_attestation::SELECTOR_BUILD_ATTESTATION);
    data.extend_from_slice(
        &serde_json::to_vec(&serde_json::json!({
            "version": "2",
            "platform": "x86_64-unknown-linux-gnu",
            "code_hash": hex::encode(code),
        }))
        .unwrap(),
    );
    data
}

/// Once builder attestations are in force, an upgrade with its readiness met
/// still waits for the governed number of bonded builders to have rebuilt
/// its binary; a builder counts once, and an unbonded account not at all.
#[tokio::test]
async fn an_upgrade_waits_for_its_builders_once_they_are_in_force() {
    let id = [0xd1; 32];
    // A queued upgrade whose readiness is met, and one bonded builder.
    async fn ready(id: [u8; 32]) -> (NativeExecutor, StateAdapter, Vec<Validator>, Vec<u8>) {
        let (ex, mut state, vs) = network();
        queued(&mut state, id, upgrade(PolicyTrack::Standard));
        for (v, at) in [(&vs[0], 1), (&vs[1], 2)] {
            ex.execute_transaction(&tx(&v.addr, ready_data(v, &CODE, &CODE), at), &mut state)
                .await
                .unwrap();
        }
        let first = builder(&mut state, 0xb1);
        (ex, state, vs, first)
    }

    // Dormant: attestations are refused, and readiness alone enacts.
    let (ex, mut dormant, vs, first) = ready(id).await;
    assert!(
        ex.execute_transaction(&tx(&first, attest_data(&CODE), 3), &mut dormant)
            .await
            .is_err()
    );
    ex.execute_transaction(&tx(&vs[2].addr, execute_data(&id), 4), &mut dormant)
        .await
        .expect("dormant: readiness is enough");

    let (ex, mut state, vs, first) = ready(id).await;
    set_governed_param_for_test(&mut state, build_attestation::GATE, 0);
    set_governed_param_for_test(&mut state, native_call::GATE, 0);
    let err = ex
        .execute_transaction(&tx(&vs[2].addr, execute_data(&id), 4), &mut state)
        .await
        .expect_err("no builder has rebuilt it");
    assert!(err.to_string().contains("bonded builders"), "{err}");

    // One builder, attesting twice, and an account with no attestor bond.
    ex.execute_transaction(&tx(&first, attest_data(&CODE), 5), &mut state)
        .await
        .unwrap();
    assert!(
        ex.execute_transaction(&tx(&first, attest_data(&CODE), 6), &mut state)
            .await
            .is_err()
    );
    let stranger = vec![0xb9; 32];
    state.set_balance(&stranger, GAS);
    assert!(
        ex.execute_transaction(&tx(&stranger, attest_data(&CODE), 7), &mut state)
            .await
            .is_err()
    );
    // A builder of another binary does not count for this one.
    let other = builder(&mut state, 0xb2);
    ex.execute_transaction(&tx(&other, attest_data(&[0xc9; 32]), 8), &mut state)
        .await
        .unwrap();
    assert!(
        ex.execute_transaction(&tx(&vs[2].addr, execute_data(&id), 9), &mut state)
            .await
            .is_err()
    );
    assert_eq!(build_attestation::standing_builders(&state, &CODE), 1);

    // The second builder of this binary: it enacts.
    ex.execute_transaction(&tx(&other, attest_data(&CODE), 10), &mut state)
        .await
        .unwrap();
    ex.execute_transaction(&tx(&vs[2].addr, execute_data(&id), 11), &mut state)
        .await
        .unwrap();
    assert_eq!(
        read_upgrade_activation(&state).unwrap().code_hash,
        hex::encode(CODE)
    );
}

/// A builder whose attestor bond is gone by enactment no longer counts.
#[tokio::test]
async fn a_builder_without_a_standing_bond_at_enactment_does_not_count() {
    let (ex, mut state, vs) = network();
    set_governed_param_for_test(&mut state, build_attestation::GATE, 0);
    set_governed_param_for_test(&mut state, native_call::GATE, 0);
    set_governed_param_for_test(&mut state, build_attestation::MIN_BUILDERS_PARAM, 1);
    let id = [0xd2; 32];
    queued(&mut state, id, upgrade(PolicyTrack::Standard));
    for (v, at) in [(&vs[0], 1), (&vs[1], 2)] {
        ex.execute_transaction(&tx(&v.addr, ready_data(v, &CODE, &CODE), at), &mut state)
            .await
            .unwrap();
    }
    let b = builder(&mut state, 0xb3);
    ex.execute_transaction(&tx(&b, attest_data(&CODE), 3), &mut state)
        .await
        .unwrap();
    state.set_storage(
        &SYSTEM_ADDRESS,
        format!("role_stake:{}:attestor", hex::encode(&b)).as_bytes(),
        Vec::new(),
    );
    assert_eq!(build_attestation::standing_builders(&state, &CODE), 0);
    assert!(
        ex.execute_transaction(&tx(&vs[2].addr, execute_data(&id), 4), &mut state)
            .await
            .is_err()
    );
}
