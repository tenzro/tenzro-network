//! Hardware levels end to end: derived from TPM evidence in chain state,
//! re-derived at every reward epoch close, paid as a capped bonus on the
//! provider share, and checked wherever a quote or receipt carries one.

use super::*;
use crate::state_adapter::StateAdapter;
use tenzro_tee::nvidia_device::testgpu::SoftGpu;
use tenzro_tee::tpm_attest::tests::{SoftTpm, evidence, pem};
use tenzro_tee::tpm_attest::{
    MachineAttestation, admission_challenge, attestation_key_sec1, machine_did_for_attestation_key,
};
use tenzro_token::rewards::{RoleBucket, WorkClass};
use tenzro_types::hardware_level::{HardwareKind, HardwareLevel, HardwareProofOp, HardwareStamp};
use tenzro_types::payment_authorization::{DeliveryReceipt, Quote};

/// Block time inside the test manufacturer certificate's validity.
pub(super) const NOW_MS: i64 = 2_000_000_000_000;
const DAY_MS: i64 = 86_400_000;

fn genesis_state() -> StateAdapter {
    let mut state = StateAdapter::new();
    let schedule = rewards::genesis_reward_schedule(DAY_MS as u64).unwrap();
    state.set_storage(
        &SYSTEM_ADDRESS,
        rewards::REWARD_SCHEDULE_KEY.as_bytes(),
        schedule,
    );
    state
}

/// Registers machine identity `did` with `evidence` under wallet `[seed; 32]`.
fn register(
    state: &mut StateAdapter,
    seed: u8,
    did: &str,
    controller: Vec<u8>,
    att: MachineAttestation,
) -> Address {
    let wallet = Address::new([seed; 32]);
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert(
        tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
        serde_json::to_string(&att).unwrap(),
    );
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: did.to_string(),
        identity_type: "machine".into(),
        display_name: String::new(),
        controller_pubkey: controller,
        key_type: "p256".into(),
        wallet_id: String::new(),
        wallet_address: wallet,
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
        &identity_storage_key(did),
        serde_json::to_vec(&record).unwrap(),
    );
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(wallet.as_bytes()).as_bytes(),
        did.as_bytes().to_vec(),
    );
    wallet
}

/// A machine admitted with `tpm`'s attestation key; with `ek_of`, its
/// evidence presents that other TPM's endorsement key and certificate.
pub(super) fn machine(
    state: &mut StateAdapter,
    seed: u8,
    tpm: &SoftTpm,
    ek_of: Option<&SoftTpm>,
) -> (Address, String) {
    let (probe, root) = evidence(tpm, &[0; 32]);
    let ak = attestation_key_sec1(&probe).unwrap();
    let did = machine_did_for_attestation_key(&ak);
    let controller = vec![seed; 33];
    let nonce = [seed; 32];
    let (mut ev, _) = evidence(tpm, &admission_challenge(&did, &controller, &nonce));
    if let Some(other) = ek_of {
        let (o, _) = evidence(other, &[0; 32]);
        ev.ek_public = o.ek_public;
        ev.ek_certificate = o.ek_certificate;
    }
    let att = MachineAttestation {
        evidence: ev,
        nonce: nonce.to_vec(),
        activated: true,
    };
    let wallet = register(state, seed, &did, controller, att);
    state.set_storage(
        &SYSTEM_ADDRESS,
        funding::ENDORSEMENT_ROOTS_KEY.as_bytes(),
        serde_json::to_vec(&vec![pem(&root)]).unwrap(),
    );
    (wallet, did)
}

fn revoke(state: &mut StateAdapter, did: &str) {
    state.set_storage(&SYSTEM_ADDRESS, &identity_revocation_key(did), vec![1]);
}

fn provider_paid(state: &StateAdapter, who: &Address, epoch: u64) -> u128 {
    rewards::read_coupons(state, who)
        .unwrap()
        .iter()
        .find(|c| c.epoch == epoch && c.bucket == RoleBucket::Provider)
        .map_or(0, |c| c.amount)
}

/// A `HardwareProof` payload: `tpm` quoting the current possession
/// challenge of `wallet`'s identity.
fn possession_payload(state: &StateAdapter, wallet: &Address, tpm: &SoftTpm) -> Vec<u8> {
    let did = identity_of_wallet(state, wallet.as_bytes()).unwrap();
    let (epoch, _, challenge) = hardware_level::current_challenge(state, &did).unwrap();
    let (ev, _) = evidence(tpm, &challenge);
    serde_json::to_vec(&HardwareProofOp::Possession {
        epoch,
        quote: ev.quote,
        signature: ev.quote_signature,
    })
    .unwrap()
}

fn prove(state: &mut StateAdapter, wallet: &Address, payload: &[u8]) -> Result<()> {
    hardware_level::prove(state, wallet.as_bytes(), NOW_MS, payload).map(|_| ())
}

/// Runs one reward epoch in which each of `earners` serves `weight` of
/// inference and each of `proving` (a wallet and the TPM its machine was
/// admitted with) answers the epoch's possession challenge, then closes it
/// with the next epoch's first block.
fn serve_epoch(
    state: &mut StateAdapter,
    epoch: u64,
    earners: &[Address],
    weight: u128,
    proving: &[(Address, &SoftTpm)],
) {
    let at = NOW_MS + epoch as i64 * DAY_MS;
    rewards::begin_block(state, epoch, &Address::new([0xee; 32]), at).unwrap();
    beacon::record_for_test(state, at + 1);
    for (wallet, tpm) in proving {
        let payload = possession_payload(state, wallet, tpm);
        prove(state, wallet, &payload).unwrap();
    }
    for e in earners {
        rewards::record_settled_work(
            state,
            *e,
            WorkClass::InferenceServed,
            weight,
            &mut Vec::new(),
        )
        .unwrap();
    }
    rewards::begin_block(state, epoch + 1, &Address::new([0xee; 32]), at + DAY_MS).unwrap();
}

fn bps_of(amount: u128, bps: u128) -> u128 {
    amount / 10_000 * bps + amount % 10_000 * bps / 10_000
}

/// Two providers identical except that one is a manufacturer-certified TPM
/// machine earn in the governed ratio; once that machine's identity is
/// revoked, the next epoch's close drops it to level 0 and they earn alike.
#[test]
fn identical_providers_earn_in_the_governed_ratio_until_a_revocation_drops_the_level() {
    let mut state = genesis_state();
    let (l1, did) = machine(&mut state, 0x31, &SoftTpm::new(0x31), None);
    let l0 = Address::new([0x30; 32]);
    let weight = tenzro_token::rewards::ONE_TNZO;

    serve_epoch(
        &mut state,
        0,
        &[l0, l1],
        weight,
        &[(l1, &SoftTpm::new(0x31))],
    );
    let record = hardware_level::read_record(&state, l1.as_bytes()).unwrap();
    assert_eq!(record.stamp.level, HardwareLevel::L1);
    assert_eq!(record.stamp.kind, HardwareKind::Tpm2);
    assert_eq!(record.stamp.scheme, "ecdsa-p256");
    assert_eq!(record.did, did);
    assert_eq!(record.epoch, 0);
    let (base, bonused) = (provider_paid(&state, &l0, 0), provider_paid(&state, &l1, 0));
    assert!(base > 0);
    assert_eq!(
        bonused,
        base + bps_of(base, u128::from(hardware_level::DEFAULT_LEVEL1_BONUS_BPS))
    );

    revoke(&mut state, &did);
    serve_epoch(&mut state, 1, &[l0, l1], weight, &[]);
    let record = hardware_level::read_record(&state, l1.as_bytes()).unwrap();
    assert_eq!(record.stamp.level, HardwareLevel::L0);
    assert_eq!(record.epoch, 1);
    assert_eq!(provider_paid(&state, &l1, 1), provider_paid(&state, &l0, 1));
}

/// Removing the manufacturer root from the recognised roots drops the level
/// at the next close too: nothing carries over from an earlier epoch.
#[test]
fn a_removed_manufacturer_root_drops_the_level_at_the_next_close() {
    let mut state = genesis_state();
    let (l1, _) = machine(&mut state, 0x41, &SoftTpm::new(0x41), None);
    serve_epoch(&mut state, 0, &[l1], 1, &[(l1, &SoftTpm::new(0x41))]);
    assert_eq!(
        hardware_level::read_record(&state, l1.as_bytes())
            .unwrap()
            .stamp
            .level,
        HardwareLevel::L1
    );
    state.set_storage(
        &SYSTEM_ADDRESS,
        funding::ENDORSEMENT_ROOTS_KEY.as_bytes(),
        serde_json::to_vec(&Vec::<String>::new()).unwrap(),
    );
    serve_epoch(&mut state, 1, &[l1], 1, &[(l1, &SoftTpm::new(0x41))]);
    assert_eq!(
        hardware_level::read_record(&state, l1.as_bytes())
            .unwrap()
            .stamp
            .level,
        HardwareLevel::L0
    );
}

/// One TPM backs one live identity: a second identity presenting the same
/// endorsement key derives level 0 while the first holds it, and takes it
/// once the first is revoked.
#[test]
fn one_tpm_backs_one_live_identity() {
    let mut state = genesis_state();
    let shared = SoftTpm::new(0x51);
    let (first, first_did) = machine(&mut state, 0x51, &shared, None);
    let (second, _) = machine(&mut state, 0x52, &SoftTpm::new(0x52), Some(&shared));
    let second_tpm = SoftTpm::new(0x52);
    serve_epoch(
        &mut state,
        0,
        &[first, second],
        1,
        &[(first, &shared), (second, &second_tpm)],
    );
    let level = |s: &StateAdapter, a: &Address| {
        hardware_level::read_record(s, a.as_bytes())
            .unwrap()
            .stamp
            .level
    };
    assert_eq!(level(&state, &first), HardwareLevel::L1);
    assert_eq!(level(&state, &second), HardwareLevel::L0);
    revoke(&mut state, &first_did);
    serve_epoch(&mut state, 1, &[first, second], 1, &[(second, &second_tpm)]);
    assert_eq!(level(&state, &first), HardwareLevel::L0);
    assert_eq!(level(&state, &second), HardwareLevel::L1);
}

/// The level and type a quote and a delivery receipt carry are the attested
/// record's; a stamp that claims more than the attestation shows is refused.
#[test]
fn quote_and_receipt_stamps_match_the_attested_record_and_claims_are_refused() {
    let mut state = genesis_state();
    let (l1, did) = machine(&mut state, 0x61, &SoftTpm::new(0x61), None);
    serve_epoch(&mut state, 0, &[l1], 1, &[(l1, &SoftTpm::new(0x61))]);
    let at = NOW_MS + DAY_MS;
    let record = hardware_level::read_record(&state, l1.as_bytes()).unwrap();
    let (stamp, _, _) = hardware_level::derive(&state, l1.as_bytes(), at);
    let quote = Quote {
        payee: l1,
        request_digest: [1; 32],
        usd_e6: 1,
        accepts: Vec::new(),
        licence: String::new(),
        content_usage: String::new(),
        lines: Vec::new(),
        expires_at_ms: 0,
        hardware: Some(stamp.clone()),
    };
    let receipt = DeliveryReceipt {
        pay_ref: [2; 32],
        body_digest: [3; 32],
        inference_receipt: None,
        delivered_at_ms: 0,
        hardware: Some(stamp),
    };
    for carried in [&quote.hardware, &receipt.hardware] {
        let carried = carried.as_ref().unwrap();
        assert_eq!(carried, &record.stamp);
        hardware_level::check_stamp(&state, l1.as_bytes(), carried, at).unwrap();
    }

    // A level-0 participant claiming level 1 on a TPM is refused.
    let claim = HardwareStamp {
        level: HardwareLevel::L1,
        kind: HardwareKind::Tpm2,
        scheme: "ecdsa-p256".into(),
        ..Default::default()
    };
    let l0 = Address::new([0x60; 32]);
    assert!(hardware_level::check_stamp(&state, l0.as_bytes(), &claim, at).is_err());
    // So is a different vendor or scheme than the attestation shows.
    let mut other_vendor = record.stamp.clone();
    other_vendor.vendor = "id:00000000".into();
    assert!(hardware_level::check_stamp(&state, l1.as_bytes(), &other_vendor, at).is_err());
    // And, once revoked, the level the machine held.
    revoke(&mut state, &did);
    assert!(hardware_level::check_stamp(&state, l1.as_bytes(), &record.stamp, at).is_err());
}

/// A certified TPM that never answers the epoch's possession challenge
/// proves nothing about still holding the chip: its level is 0 at the close.
#[test]
fn a_machine_without_a_possession_quote_for_the_epoch_is_level_0() {
    let mut state = genesis_state();
    let (machine, _) = machine(&mut state, 0x71, &SoftTpm::new(0x71), None);
    serve_epoch(&mut state, 0, &[machine], 1, &[]);
    let record = hardware_level::read_record(&state, machine.as_bytes()).unwrap();
    assert_eq!(record.stamp.level, HardwareLevel::L0);
}

/// Possession is shown again every epoch: the level holds while the TPM
/// answers each epoch's challenge, drops at the close of an epoch it does
/// not, and returns at the next epoch it does. The record names the quote.
#[test]
fn possession_is_proven_every_epoch_and_a_missed_epoch_drops_the_level() {
    let mut state = genesis_state();
    let tpm = SoftTpm::new(0x81);
    let (machine, _) = machine(&mut state, 0x81, &tpm, None);
    let level = |s: &StateAdapter| {
        hardware_level::read_record(s, machine.as_bytes())
            .unwrap()
            .stamp
            .level
    };
    serve_epoch(&mut state, 0, &[machine], 1, &[(machine, &tpm)]);
    assert_eq!(level(&state), HardwareLevel::L1);
    let record = hardware_level::read_record(&state, machine.as_bytes()).unwrap();
    assert_eq!(record.possession.len(), 64);
    serve_epoch(&mut state, 1, &[machine], 1, &[]);
    assert_eq!(level(&state), HardwareLevel::L0);
    assert!(
        hardware_level::read_record(&state, machine.as_bytes())
            .unwrap()
            .possession
            .is_empty()
    );
    serve_epoch(&mut state, 2, &[machine], 1, &[(machine, &tpm)]);
    assert_eq!(level(&state), HardwareLevel::L1);
}

/// A possession quote counts only when the admitted attestation key signs
/// this epoch's challenge: not before the beacon has drawn it, not by
/// another TPM, not an earlier epoch's quote, and once per epoch.
#[test]
fn a_possession_quote_must_answer_this_epochs_challenge_with_the_admitted_key() {
    let mut state = genesis_state();
    let tpm = SoftTpm::new(0x91);
    let (machine, did) = machine(&mut state, 0x91, &tpm, None);
    rewards::begin_block(&mut state, 0, &Address::new([0xee; 32]), NOW_MS).unwrap();
    assert!(hardware_level::current_challenge(&state, &did).is_none());
    let early = serde_json::to_vec(&HardwareProofOp::Possession {
        epoch: 0,
        quote: evidence(&tpm, &[0; 32]).0.quote,
        signature: vec![0; 64],
    })
    .unwrap();
    assert!(prove(&mut state, &machine, &early).is_err());

    beacon::record_for_test(&mut state, NOW_MS + 1);
    let foreign = possession_payload(&state, &machine, &SoftTpm::new(0x92));
    assert!(prove(&mut state, &machine, &foreign).is_err());
    let answer = possession_payload(&state, &machine, &tpm);
    prove(&mut state, &machine, &answer).unwrap();
    assert!(prove(&mut state, &machine, &answer).is_err());
    assert_eq!(
        hardware_level::read_possession(&state, &did).unwrap().epoch,
        0
    );

    rewards::begin_block(&mut state, 1, &Address::new([0xee; 32]), NOW_MS + DAY_MS).unwrap();
    beacon::record_for_test(&mut state, NOW_MS + DAY_MS + 1);
    // Epoch 0's answer, as sent and relabelled for epoch 1.
    assert!(prove(&mut state, &machine, &answer).is_err());
    let mut relabelled: serde_json::Value = serde_json::from_slice(&answer).unwrap();
    relabelled["possession"]["epoch"] = 1.into();
    assert!(
        prove(
            &mut state,
            &machine,
            &serde_json::to_vec(&relabelled).unwrap()
        )
        .is_err()
    );
    // A wallet with no identity proves nothing.
    assert!(prove(&mut state, &Address::new([0x99; 32]), &answer).is_err());
    let fresh = possession_payload(&state, &machine, &tpm);
    prove(&mut state, &machine, &fresh).unwrap();
}

/// On a machine with a provisioned TPM 2.0: the machine is admitted with
/// its own TPM, the attestation key quotes the epoch's possession challenge,
/// the chain accepts that quote and refuses one over another value, and the
/// close derives level 1 naming the quote. `TENZRO_TEST_TPM_CA` is a
/// directory holding the manufacturer root (`root.pem`) and, for a TPM that
/// does not carry it, the endorsement certificate's issuer (`issuer.pem`).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a provisioned TPM 2.0 at /dev/tpmrm0 and TENZRO_TEST_TPM_CA"]
fn a_real_tpm_answers_the_possession_challenge() {
    use tenzro_tee::tpm_attest::{attest_local_machine, quote_local_machine};
    let dir = std::env::var("TENZRO_TEST_TPM_CA").expect("TENZRO_TEST_TPM_CA");
    let root = std::fs::read_to_string(format!("{dir}/root.pem")).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut state = genesis_state();
    let controller = vec![0x07; 33];
    let (did, mut att) = attest_local_machine(&controller).unwrap();
    if att.evidence.ek_intermediates.is_empty()
        && let Ok(issuer) = std::fs::read_to_string(format!("{dir}/issuer.pem"))
    {
        att.evidence.ek_intermediates = tenzro_tee::x509::parse_pem_chain(&issuer)
            .unwrap()
            .into_iter()
            .map(|c| c.der)
            .collect();
    }
    let wallet = register(&mut state, 0x07, &did, controller, att);
    state.set_storage(
        &SYSTEM_ADDRESS,
        funding::ENDORSEMENT_ROOTS_KEY.as_bytes(),
        serde_json::to_vec(&vec![root]).unwrap(),
    );
    funding::machine_endorsed(&state, &did, now).unwrap();

    let proposer = Address::new([0xee; 32]);
    rewards::begin_block(&mut state, 0, &proposer, now).unwrap();
    beacon::record_for_test(&mut state, now + 1);
    let (epoch, round, challenge) = hardware_level::current_challenge(&state, &did).unwrap();
    let payload = |ev: tenzro_tee::tpm_attest::TpmEvidence| {
        serde_json::to_vec(&HardwareProofOp::Possession {
            epoch,
            quote: ev.quote,
            signature: ev.quote_signature,
        })
        .unwrap()
    };
    let (_, other) = quote_local_machine(&[0x55; 32]).unwrap();
    let refused = prove(&mut state, &wallet, &payload(other)).unwrap_err();
    println!("quote over another value: {refused}");
    let (quoting, ev) = quote_local_machine(&challenge).unwrap();
    assert_eq!(quoting, did);
    let quote_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&ev.quote));
    prove(&mut state, &wallet, &payload(ev)).unwrap();

    rewards::record_settled_work(
        &mut state,
        wallet,
        WorkClass::InferenceServed,
        1,
        &mut Vec::new(),
    )
    .unwrap();
    rewards::begin_block(&mut state, 1, &proposer, now + DAY_MS).unwrap();
    let record = hardware_level::read_record(&state, wallet.as_bytes()).unwrap();
    println!(
        "did {did} epoch {epoch} beacon round {round} challenge {} -> {} {} vendor {} spec {} scheme {} device {} possession {}",
        hex::encode(challenge),
        record.stamp.level.as_str(),
        record.stamp.kind.as_str(),
        record.stamp.vendor,
        record.stamp.spec,
        record.stamp.scheme,
        record.device_id,
        record.possession
    );
    assert_eq!(record.stamp.level, HardwareLevel::L1);
    assert_eq!(record.stamp.kind, HardwareKind::Tpm2);
    assert_eq!(record.possession, quote_hash);
}

/// Enrols `key` as `did`'s ML-DSA-65 key.
fn enrol_ml_dsa(state: &mut StateAdapter, did: &str, key: &[u8]) {
    let storage_key = identity_storage_key(did);
    let mut record: tenzro_types::identity::RegisterIdentityPayload =
        serde_json::from_slice(&state.get_storage(&SYSTEM_ADDRESS, &storage_key).unwrap()).unwrap();
    record.pq_verifying_key = key.to_vec();
    state.set_storage(
        &SYSTEM_ADDRESS,
        &storage_key,
        serde_json::to_vec(&record).unwrap(),
    );
}

fn ml_dsa_key(seed: u8) -> Vec<u8> {
    tenzro_crypto::pq::MlDsaSigningKey::from_seed(&[seed; 32])
        .unwrap()
        .verifying_key_bytes()
        .to_vec()
}

/// A `HardwareProof` payload: `tpm` certifying the ML-DSA key `key` as an
/// attestation key or not, over the binding of `bound_did` and `bound_key`.
fn ml_dsa_payload(
    tpm: &SoftTpm,
    key: &[u8],
    attestation_key: bool,
    bound_did: &str,
    bound_key: &[u8],
) -> Vec<u8> {
    let key_public = SoftTpm::ml_dsa_public(key, attestation_key);
    let binding = tenzro_types::hardware_level::ml_dsa_binding(bound_did, bound_key);
    let (attest, signature) = tpm.certify(&key_public, &binding);
    serde_json::to_vec(&HardwareProofOp::MlDsaKey {
        key_public,
        attest,
        signature,
    })
    .unwrap()
}

/// A TPM that certifies the identity's own ML-DSA key as a v1.85 TPM
/// object lifts the machine to level 2, or to level 3 when the key is a
/// restricted ML-DSA attestation key; the bonus follows the level. Enrolling
/// a different ML-DSA key afterwards drops the machine back to level 1, and
/// without the epoch's possession quote it is level 0 whatever it proved.
#[test]
fn a_tpm_held_ml_dsa_key_lifts_the_level_to_2_and_an_ml_dsa_attestation_key_to_3() {
    let mut state = genesis_state();
    let (tpm2, tpm3) = (SoftTpm::new(0xa1), SoftTpm::new(0xa2));
    let (l2, did2) = machine(&mut state, 0xa1, &tpm2, None);
    let (l3, did3) = machine(&mut state, 0xa2, &tpm3, None);
    let l0 = Address::new([0xa0; 32]);
    let (key2, key3) = (ml_dsa_key(0xa1), ml_dsa_key(0xa2));
    enrol_ml_dsa(&mut state, &did2, &key2);
    enrol_ml_dsa(&mut state, &did3, &key3);
    let p2 = ml_dsa_payload(&tpm2, &key2, false, &did2, &key2);
    prove(&mut state, &l2, &p2).unwrap();
    let p3 = ml_dsa_payload(&tpm3, &key3, true, &did3, &key3);
    prove(&mut state, &l3, &p3).unwrap();
    assert!(
        hardware_level::read_ml_dsa(&state, &did3)
            .unwrap()
            .attestation_key
    );

    let weight = tenzro_token::rewards::ONE_TNZO;
    serve_epoch(
        &mut state,
        0,
        &[l0, l2, l3],
        weight,
        &[(l2, &tpm2), (l3, &tpm3)],
    );
    let level =
        |s: &StateAdapter, a: &Address| hardware_level::read_record(s, a.as_bytes()).unwrap().stamp;
    assert_eq!(level(&state, &l2).level, HardwareLevel::L2);
    assert_eq!(level(&state, &l2).scheme, "ecdsa-p256+ml-dsa-65");
    assert_eq!(level(&state, &l3).level, HardwareLevel::L3);
    let base = provider_paid(&state, &l0, 0);
    assert_eq!(
        provider_paid(&state, &l2, 0),
        base + bps_of(base, u128::from(hardware_level::DEFAULT_LEVEL2_BONUS_BPS))
    );
    assert_eq!(
        provider_paid(&state, &l3, 0),
        base + bps_of(base, u128::from(hardware_level::DEFAULT_LEVEL3_BONUS_BPS))
    );

    enrol_ml_dsa(&mut state, &did2, &ml_dsa_key(0xa9));
    serve_epoch(&mut state, 1, &[l2, l3], weight, &[(l2, &tpm2)]);
    assert_eq!(level(&state, &l2).level, HardwareLevel::L1);
    assert_eq!(level(&state, &l3).level, HardwareLevel::L0);
}

/// An ML-DSA certification counts only when the machine's admitted TPM
/// certified the key its identity enrolled, bound to that identity: not
/// before a key is enrolled, not by another TPM, not one bound to another
/// identity or key, and not of another key.
#[test]
fn an_ml_dsa_certification_must_be_the_admitted_tpms_over_this_identitys_key() {
    let mut state = genesis_state();
    let tpm = SoftTpm::new(0xb1);
    let (wallet, did) = machine(&mut state, 0xb1, &tpm, None);
    let key = ml_dsa_key(0xb1);
    let good = ml_dsa_payload(&tpm, &key, false, &did, &key);
    assert!(prove(&mut state, &wallet, &good).is_err());
    enrol_ml_dsa(&mut state, &did, &key);
    let other_key = ml_dsa_key(0xb2);
    for refused in [
        ml_dsa_payload(&SoftTpm::new(0xb3), &key, false, &did, &key),
        ml_dsa_payload(&tpm, &key, false, "did:tenzro:machine:other", &key),
        ml_dsa_payload(&tpm, &key, false, &did, &other_key),
        ml_dsa_payload(&tpm, &other_key, false, &did, &key),
    ] {
        assert!(prove(&mut state, &wallet, &refused).is_err());
    }
    assert!(hardware_level::read_ml_dsa(&state, &did).is_none());
    prove(&mut state, &wallet, &good).unwrap();
}

fn set_gpu_roots(state: &mut StateAdapter, roots: &[&str]) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        hardware_level::GPU_ROOTS_KEY.as_bytes(),
        serde_json::to_vec(&roots).unwrap(),
    );
    let (index, value) = tenzro_tee::nvidia_device::testgpu::MEASUREMENT;
    set_gpu_references(state, &[(index, &value[..])]);
}

fn set_gpu_references(state: &mut StateAdapter, references: &[(u8, &[u8])]) {
    let references: Vec<tenzro_types::hardware_level::GpuReferenceValue> = references
        .iter()
        .map(
            |(index, value)| tenzro_types::hardware_level::GpuReferenceValue {
                index: *index,
                values: vec![hex::encode(value)],
            },
        )
        .collect();
    state.set_storage(
        &SYSTEM_ADDRESS,
        hardware_level::GPU_REFERENCES_KEY.as_bytes(),
        serde_json::to_vec(&references).unwrap(),
    );
}

/// A `HardwareProof` payload: `gpu` signing the current GPU challenge of
/// `wallet`'s identity.
fn gpu_payload(state: &StateAdapter, wallet: &Address, gpu: &SoftGpu) -> Vec<u8> {
    let did = identity_of_wallet(state, wallet.as_bytes()).unwrap();
    let (epoch, _, possession) = hardware_level::current_challenge(state, &did).unwrap();
    let report = gpu.report(&tenzro_types::hardware_level::gpu_challenge(&possession));
    serde_json::to_vec(&HardwareProofOp::GpuDevice {
        epoch,
        report,
        chain: gpu.chain.clone(),
    })
    .unwrap()
}

/// [`serve_epoch`], with each of `gpus` proving its GPU in the epoch too.
fn serve_epoch_with_gpus(
    state: &mut StateAdapter,
    epoch: u64,
    earners: &[Address],
    proving: &[(Address, &SoftTpm)],
    gpus: &[(Address, &SoftGpu)],
) {
    let at = NOW_MS + epoch as i64 * DAY_MS;
    rewards::begin_block(state, epoch, &Address::new([0xee; 32]), at).unwrap();
    beacon::record_for_test(state, at + 1);
    for (wallet, tpm) in proving {
        let payload = possession_payload(state, wallet, tpm);
        prove(state, wallet, &payload).unwrap();
    }
    for (wallet, gpu) in gpus {
        let payload = gpu_payload(state, wallet, gpu);
        prove(state, wallet, &payload).unwrap();
    }
    for e in earners {
        rewards::record_settled_work(
            state,
            *e,
            WorkClass::InferenceServed,
            tenzro_token::rewards::ONE_TNZO,
            &mut Vec::new(),
        )
        .unwrap();
    }
    rewards::begin_block(state, epoch + 1, &Address::new([0xee; 32]), at + DAY_MS).unwrap();
}

/// A GPU whose per-device chain ends at a governed root and which signs the
/// epoch's GPU challenge is a second, independent hardware scheme: with the
/// TPM it lifts the machine to level 3 for that epoch. An epoch without the
/// GPU's answer is level 1, and the GPU without the TPM's possession quote
/// is level 0.
#[test]
fn a_gpu_proven_in_the_epoch_beside_the_tpm_is_level_3() {
    let mut state = genesis_state();
    let tpm = SoftTpm::new(0xc1);
    let gpu = SoftGpu::new(0xc1, 0xc0);
    let (machine, _) = machine(&mut state, 0xc1, &tpm, None);
    set_gpu_roots(&mut state, &[&gpu.root_pem]);
    let stamp = |s: &StateAdapter| {
        hardware_level::read_record(s, machine.as_bytes())
            .unwrap()
            .stamp
    };
    serve_epoch_with_gpus(
        &mut state,
        0,
        &[machine],
        &[(machine, &tpm)],
        &[(machine, &gpu)],
    );
    assert_eq!(stamp(&state).level, HardwareLevel::L3);
    assert_eq!(stamp(&state).scheme, "ecdsa-p256+nvidia-device");
    serve_epoch_with_gpus(&mut state, 1, &[machine], &[(machine, &tpm)], &[]);
    assert_eq!(stamp(&state).level, HardwareLevel::L1);
    serve_epoch_with_gpus(&mut state, 2, &[machine], &[], &[(machine, &gpu)]);
    assert_eq!(stamp(&state).level, HardwareLevel::L0);
}

/// One GPU counts for one live identity: a second machine presenting the
/// same GPU stays at level 1 while the first holds it.
#[test]
fn one_gpu_backs_one_live_identity() {
    let mut state = genesis_state();
    let gpu = SoftGpu::new(0xd1, 0xd0);
    let (t1, t2) = (SoftTpm::new(0xd1), SoftTpm::new(0xd2));
    let (first, _) = machine(&mut state, 0xd1, &t1, None);
    let (second, _) = machine(&mut state, 0xd2, &t2, None);
    set_gpu_roots(&mut state, &[&gpu.root_pem]);
    serve_epoch_with_gpus(
        &mut state,
        0,
        &[first, second],
        &[(first, &t1), (second, &t2)],
        &[(first, &gpu), (second, &gpu)],
    );
    let level = |a: &Address| {
        hardware_level::read_record(&state, a.as_bytes())
            .unwrap()
            .stamp
            .level
    };
    assert_eq!(level(&first), HardwareLevel::L3);
    assert_eq!(level(&second), HardwareLevel::L1);
}

/// A GPU report counts only when its chain ends at a governed root and it
/// answers this epoch's GPU challenge, once per epoch. NVIDIA's own sample
/// H100 report verifies against NVIDIA's root, and is still refused on
/// chain: it answers another nonce.
#[test]
fn a_gpu_report_must_chain_to_a_governed_root_and_answer_this_epochs_challenge() {
    let mut state = genesis_state();
    let tpm = SoftTpm::new(0xe1);
    let gpu = SoftGpu::new(0xe1, 0xe0);
    let (wallet, did) = machine(&mut state, 0xe1, &tpm, None);
    rewards::begin_block(&mut state, 0, &Address::new([0xee; 32]), NOW_MS).unwrap();
    beacon::record_for_test(&mut state, NOW_MS + 1);
    let good = gpu_payload(&state, &wallet, &gpu);
    // No governed root, then another device's root.
    assert!(prove(&mut state, &wallet, &good).is_err());
    set_gpu_roots(&mut state, &[&SoftGpu::new(0xe5, 0xe4).root_pem]);
    assert!(prove(&mut state, &wallet, &good).is_err());

    let nvidia_root = include_str!("../../../tenzro-tee/testdata/nvidia/device_identity_ca.crt");
    set_gpu_roots(&mut state, &[&gpu.root_pem, nvidia_root]);
    let (_, _, possession) = hardware_level::current_challenge(&state, &did).unwrap();
    let pem = include_str!("../../../tenzro-tee/testdata/nvidia/hopper_cert_chain.crt");
    let sample = HardwareProofOp::GpuDevice {
        epoch: 0,
        report: hex::decode(
            include_str!("../../../tenzro-tee/testdata/nvidia/hopper_attestation_report.hex")
                .trim(),
        )
        .unwrap(),
        chain: tenzro_tee::nvidia_device::parse_chain(pem.as_bytes())
            .unwrap()
            .into_iter()
            .flat_map(|c| c.der)
            .collect(),
    };
    let refused = prove(&mut state, &wallet, &serde_json::to_vec(&sample).unwrap()).unwrap_err();
    assert!(refused.to_string().contains("another nonce"), "{refused}");
    // The TPM's challenge itself is not the GPU's.
    let unseparated = serde_json::to_vec(&HardwareProofOp::GpuDevice {
        epoch: 0,
        report: gpu.report(&possession),
        chain: gpu.chain.clone(),
    })
    .unwrap();
    assert!(prove(&mut state, &wallet, &unseparated).is_err());
    let mut wrong_epoch: serde_json::Value = serde_json::from_slice(&good).unwrap();
    wrong_epoch["gpu_device"]["epoch"] = 1.into();
    assert!(
        prove(
            &mut state,
            &wallet,
            &serde_json::to_vec(&wrong_epoch).unwrap()
        )
        .is_err()
    );

    prove(&mut state, &wallet, &good).unwrap();
    assert!(prove(&mut state, &wallet, &good).is_err());
    assert_eq!(hardware_level::read_gpu(&state, &did).unwrap().epoch, 0);
}

/// A GPU whose chain and answer are good still counts only when its
/// measurements are NVIDIA's reference values governance recognises: none
/// recognised, another value, or an index it does not measure is refused.
#[test]
fn a_gpu_report_must_match_the_governed_reference_values() {
    let mut state = genesis_state();
    let tpm = SoftTpm::new(0xf1);
    let gpu = SoftGpu::new(0xf1, 0xf0);
    let (wallet, did) = machine(&mut state, 0xf1, &tpm, None);
    set_gpu_roots(&mut state, &[&gpu.root_pem]);
    rewards::begin_block(&mut state, 0, &Address::new([0xee; 32]), NOW_MS).unwrap();
    beacon::record_for_test(&mut state, NOW_MS + 1);
    let good = gpu_payload(&state, &wallet, &gpu);
    let (index, value) = tenzro_tee::nvidia_device::testgpu::MEASUREMENT;
    for refused in [
        vec![],
        vec![(index, &[0xAA, 0xBB, 0xCC, 0xDE][..])],
        vec![(index, &value[..]), (index + 1, &value[..])],
    ] {
        set_gpu_references(&mut state, &refused);
        let err = prove(&mut state, &wallet, &good).unwrap_err();
        assert!(err.to_string().contains("measurement"), "{err}");
    }
    assert!(hardware_level::read_gpu(&state, &did).is_none());
    set_gpu_references(&mut state, &[(index, &value[..])]);
    prove(&mut state, &wallet, &good).unwrap();
}

/// A reference record is refused when an index repeats or accepts nothing,
/// or a value is not 1 to 64 bytes of hex.
#[test]
fn malformed_gpu_reference_values_are_refused() {
    use tenzro_types::hardware_level::{GpuReferenceValue, decode_gpu_references};
    let r = |index: u8, values: &[&str]| GpuReferenceValue {
        index,
        values: values.iter().map(|v| v.to_string()).collect(),
    };
    assert_eq!(
        decode_gpu_references(&[r(1, &["aabb", "ccdd"])]).unwrap(),
        vec![(1, vec![vec![0xaa, 0xbb], vec![0xcc, 0xdd]])]
    );
    for bad in [
        vec![r(1, &["aa"]), r(1, &["bb"])],
        vec![r(1, &[])],
        vec![r(1, &["zz"])],
        vec![r(1, &[""])],
        vec![r(1, &[&"00".repeat(65)])],
    ] {
        assert!(decode_gpu_references(&bad).is_err(), "{bad:?}");
    }
}

// Datacenter fleets: one operator account proves many TPM hosts and their
// GPUs in one signed transaction.

use tenzro_types::hardware_level::{FleetHost, FleetUnit, GpuEvidence, TpmQuote};

/// A human operator identity with no hardware of its own, under wallet
/// `[seed; 32]`.
fn operator(state: &mut StateAdapter, seed: u8) -> (Address, String) {
    let wallet = Address::new([seed; 32]);
    let did = format!("did:tenzro:human:operator-{seed:02x}");
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: did.clone(),
        identity_type: "human".into(),
        display_name: String::new(),
        controller_pubkey: vec![seed; 33],
        key_type: "p256".into(),
        wallet_id: String::new(),
        wallet_address: wallet,
        pq_verifying_key: Vec::new(),
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
        &identity_storage_key(&did),
        serde_json::to_vec(&record).unwrap(),
    );
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(wallet.as_bytes()).as_bytes(),
        did.as_bytes().to_vec(),
    );
    (wallet, did)
}

/// A datacenter host: its TPM, its machine identity and wallet, its GPUs.
struct Host {
    tpm: SoftTpm,
    wallet: Address,
    did: String,
    gpus: Vec<SoftGpu>,
}

/// Root seed of every fleet GPU's device identity chain, above every
/// device and alias seed the tests draw.
const FLEET_GPU_ROOT: u8 = 0xf0;

/// The seed of GPU `k` of a test: odd, as a device and its alias take two
/// seeds each.
fn gpu_seed(k: usize) -> u8 {
    u8::try_from(1 + 2 * k).expect("at most 127 GPUs a test")
}

/// `n` hosts from seed `first`, each with `gpus` GPUs, numbered from GPU
/// `first_gpu`.
fn hosts(
    state: &mut StateAdapter,
    first: u8,
    n: usize,
    gpus: usize,
    first_gpu: usize,
) -> Vec<Host> {
    (0..n)
        .map(|i| {
            let seed = first + i as u8;
            let tpm = SoftTpm::new(seed);
            let (wallet, did) = machine(state, seed, &tpm, None);
            let gpus = (0..gpus)
                .map(|g| SoftGpu::new(gpu_seed(first_gpu + i * gpus + g), FLEET_GPU_ROOT))
                .collect();
            Host {
                tpm,
                wallet,
                did,
                gpus,
            }
        })
        .collect()
}

/// The GPU root's own certificate, DER.
fn gpu_root_der(gpu: &SoftGpu) -> Vec<u8> {
    use base64::Engine;
    let body: String = gpu
        .root_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

/// `host`'s fleet entry for the current epoch: a binding quote to
/// `operator` when `bind`, its possession quote and each GPU's report, with
/// the shared root left out of each chain when `shared_root`.
fn fleet_host(
    state: &StateAdapter,
    operator: &str,
    host: &Host,
    bind: bool,
    shared_root: bool,
) -> FleetHost {
    let (epoch, _, challenge) = hardware_level::current_challenge(state, &host.did).unwrap();
    let quote = |statement: &[u8; 32]| {
        let (ev, _) = evidence(&host.tpm, statement);
        TpmQuote {
            quote: ev.quote,
            signature: ev.quote_signature,
        }
    };
    let nonce = tenzro_types::hardware_level::gpu_challenge(&challenge);
    FleetHost {
        did: host.did.clone(),
        binding: bind.then(|| {
            quote(&tenzro_types::hardware_level::fleet_binding(
                operator, &host.did,
            ))
        }),
        epoch,
        possession: quote(&challenge),
        gpus: host
            .gpus
            .iter()
            .map(|gpu| {
                let mut chain = gpu.chain.clone();
                if shared_root {
                    chain.truncate(chain.len() - gpu_root_der(gpu).len());
                }
                GpuEvidence {
                    report: gpu.report(&nonce),
                    chain,
                }
            })
            .collect(),
    }
}

fn fleet_payload(issuers: Vec<u8>, units: Vec<FleetUnit>) -> Vec<u8> {
    serde_json::to_vec(&HardwareProofOp::Fleet { issuers, units }).unwrap()
}

/// Opens reward epoch `epoch` with a beacon value, so its challenges exist.
fn open_epoch(state: &mut StateAdapter, epoch: u64) {
    let at = NOW_MS + epoch as i64 * DAY_MS;
    rewards::begin_block(state, epoch, &Address::new([0xee; 32]), at).unwrap();
    beacon::record_for_test(state, at + 1);
}

/// Each of `earners` serves one TNZO of inference, then the epoch closes.
fn close_epoch(state: &mut StateAdapter, epoch: u64, earners: &[Address]) {
    for e in earners {
        rewards::record_settled_work(
            state,
            *e,
            WorkClass::InferenceServed,
            tenzro_token::rewards::ONE_TNZO,
            &mut Vec::new(),
        )
        .unwrap();
    }
    let at = NOW_MS + (epoch + 1) as i64 * DAY_MS;
    rewards::begin_block(state, epoch + 1, &Address::new([0xee; 32]), at).unwrap();
}

fn fleet_log(logs: &[Log]) -> serde_json::Value {
    let log = logs
        .iter()
        .find(|l| l.topics.get(1).is_some_and(|t| t == b"fleet"))
        .expect("a fleet log");
    serde_json::from_slice(&log.data).unwrap()
}

/// One operator account proves eight hosts of eight GPUs each in one
/// transaction. Every host is level 3 at the close, each counts its own
/// eight GPUs, earns its own provider reward with the level bonus, and
/// each GPU is claimed for its host. The next epoch the hosts prove again
/// without binding quotes, as members of the fleet.
#[test]
fn one_operator_proves_many_hosts_and_their_gpus_in_one_transaction() {
    let mut state = genesis_state();
    let (op_wallet, op) = operator(&mut state, 0x0f);
    let fleet = hosts(&mut state, 0x10, 8, 8, 0);
    set_gpu_roots(&mut state, &[&fleet[0].gpus[0].root_pem]);
    let (plain, _) = machine(&mut state, 0x40, &SoftTpm::new(0x40), None);
    open_epoch(&mut state, 0);
    let units = fleet
        .iter()
        .map(|h| FleetUnit::Host(fleet_host(&state, &op, h, true, false)))
        .collect();
    let payload = fleet_payload(Vec::new(), units);
    let (_, logs) =
        hardware_level::prove(&mut state, op_wallet.as_bytes(), NOW_MS, &payload).unwrap();
    let log = fleet_log(&logs);
    assert_eq!(log["accepted"].as_array().unwrap().len(), 8);
    assert!(log["refused"].as_array().unwrap().is_empty());
    let earners: Vec<Address> = fleet.iter().map(|h| h.wallet).chain([plain]).collect();
    close_epoch(&mut state, 0, &earners);
    let mut devices = std::collections::BTreeSet::new();
    for h in &fleet {
        let record = hardware_level::read_record(&state, h.wallet.as_bytes()).unwrap();
        assert_eq!(record.stamp.level, HardwareLevel::L3, "{}", h.did);
        assert_eq!(record.stamp.scheme, "ecdsa-p256+nvidia-device");
        assert_eq!(record.gpus.len(), 8);
        for d in &record.gpus {
            assert_eq!(
                hardware_level::gpu_holder(&state, d).as_deref(),
                Some(h.did.as_str())
            );
            assert!(devices.insert(d.clone()), "GPU {d} counted twice");
        }
        assert_eq!(
            hardware_level::fleet_of(&state, &h.did).unwrap().operator,
            op
        );
        // Level 3's bonus over a level-0 provider that served the same.
        let base = provider_paid(&state, &plain, 0);
        let paid = provider_paid(&state, &h.wallet, 0);
        let bonus = bps_of(base, hardware_level::DEFAULT_LEVEL3_BONUS_BPS as u128);
        assert!(
            paid >= base + bonus - 1 && paid <= base + bonus + 1,
            "{paid} vs {base}+{bonus}"
        );
    }
    assert_eq!(devices.len(), 64);
    // Members prove the next epoch with no binding quote.
    open_epoch(&mut state, 1);
    let units = fleet
        .iter()
        .map(|h| FleetUnit::Host(fleet_host(&state, &op, h, false, false)))
        .collect();
    let payload = fleet_payload(Vec::new(), units);
    let (_, logs) =
        hardware_level::prove(&mut state, op_wallet.as_bytes(), NOW_MS, &payload).unwrap();
    assert_eq!(fleet_log(&logs)["accepted"].as_array().unwrap().len(), 8);
}

/// A batch with one bad host: the host whose possession quote is by another
/// TPM is refused with its reason and the others are accepted and counted.
/// A host not yet in the fleet and sent with no binding quote is refused
/// too, and so is one whose GPU another host of the batch already presents.
#[test]
fn a_bad_host_in_a_batch_is_refused_and_the_rest_are_accepted() {
    let mut state = genesis_state();
    let (op_wallet, op) = operator(&mut state, 0x0e);
    let mut fleet = hosts(&mut state, 0x50, 6, 2, 0);
    set_gpu_roots(&mut state, &[&fleet[0].gpus[0].root_pem]);
    open_epoch(&mut state, 0);
    let mut units: Vec<FleetUnit> = fleet
        .iter()
        .map(|h| FleetUnit::Host(fleet_host(&state, &op, h, true, false)))
        .collect();
    // Host 1 quotes with another TPM.
    let impostor = Host {
        tpm: SoftTpm::new(0x9e),
        wallet: fleet[1].wallet,
        did: fleet[1].did.clone(),
        gpus: Vec::new(),
    };
    units[1] = FleetUnit::Host(fleet_host(&state, &op, &impostor, true, false));
    // Host 3 has not joined and carries no binding quote.
    units[3] = FleetUnit::Host(fleet_host(&state, &op, &fleet[3], false, false));
    // Host 5 presents host 4's first GPU.
    let stolen = SoftGpu::new(gpu_seed(4 * 2), FLEET_GPU_ROOT);
    fleet[5].gpus[0] = stolen;
    units[5] = FleetUnit::Host(fleet_host(&state, &op, &fleet[5], true, false));
    let payload = fleet_payload(Vec::new(), units);
    let (_, logs) =
        hardware_level::prove(&mut state, op_wallet.as_bytes(), NOW_MS, &payload).unwrap();
    let log = fleet_log(&logs);
    let accepted: Vec<&str> = log["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["host"].as_str().unwrap())
        .collect();
    assert_eq!(
        accepted,
        vec![
            fleet[0].did.as_str(),
            fleet[2].did.as_str(),
            fleet[4].did.as_str()
        ]
    );
    let refused: Vec<(String, String)> = log["refused"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["host"].as_str().unwrap().to_string(),
                r["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(refused.len(), 3);
    assert_eq!(refused[0].0, fleet[1].did);
    assert!(
        refused[0].1.contains("fleet binding quote refused"),
        "{}",
        refused[0].1
    );
    assert_eq!(refused[1].0, fleet[3].did);
    assert!(
        refused[1].1.contains("has not joined the fleet"),
        "{}",
        refused[1].1
    );
    assert_eq!(refused[2].0, fleet[5].did);
    assert!(
        refused[2].1.contains("appears twice in the proof"),
        "{}",
        refused[2].1
    );
    let wallets: Vec<Address> = fleet.iter().map(|h| h.wallet).collect();
    close_epoch(&mut state, 0, &wallets);
    let level = |i: usize| {
        hardware_level::read_record(&state, fleet[i].wallet.as_bytes())
            .unwrap()
            .stamp
            .level
    };
    assert_eq!(
        (0..6).map(level).collect::<Vec<_>>(),
        vec![
            HardwareLevel::L3,
            HardwareLevel::L0,
            HardwareLevel::L3,
            HardwareLevel::L0,
            HardwareLevel::L3,
            HardwareLevel::L0
        ]
    );
    assert!(hardware_level::fleet_of(&state, &fleet[1].did).is_none());
    assert!(hardware_level::fleet_of(&state, &fleet[3].did).is_none());
}

/// A batch in which nothing verifies changes nothing and is refused.
#[test]
fn a_batch_with_no_good_host_is_refused_whole() {
    let mut state = genesis_state();
    let (op_wallet, op) = operator(&mut state, 0x0d);
    let fleet = hosts(&mut state, 0x60, 2, 0, 0);
    open_epoch(&mut state, 0);
    let units = fleet
        .iter()
        .map(|h| FleetUnit::Host(fleet_host(&state, &op, h, false, false)))
        .collect();
    let err = hardware_level::prove(
        &mut state,
        op_wallet.as_bytes(),
        NOW_MS,
        &fleet_payload(Vec::new(), units),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("no host of the fleet proof was accepted"),
        "{err}"
    );
    assert!(hardware_level::read_possession(&state, &fleet[0].did).is_none());
}

/// An NVL72 rack, 18 hosts of 4 GPUs, is proven as one unit with each GPU's
/// own device certificate and the shared root sent once. Every host and all
/// 72 GPUs count, and the rack record names them. When one GPU of a rack
/// fails, the whole rack is refused while a separate host in the same batch
/// is accepted.
#[test]
fn an_nvl72_rack_is_one_unit_with_per_gpu_certificates() {
    let mut state = genesis_state();
    let (op_wallet, op) = operator(&mut state, 0x0c);
    let rack = hosts(&mut state, 0x80, 18, 4, 0);
    let lone = hosts(&mut state, 0xa0, 1, 1, 72);
    set_gpu_roots(&mut state, &[&rack[0].gpus[0].root_pem]);
    let issuers = gpu_root_der(&rack[0].gpus[0]);
    open_epoch(&mut state, 0);
    let units = vec![FleetUnit::Rack {
        label: "hall-a/row-3/nvl72-07".into(),
        hosts: rack
            .iter()
            .map(|h| fleet_host(&state, &op, h, true, true))
            .collect(),
    }];
    let payload = fleet_payload(issuers.clone(), units);
    hardware_level::prove(&mut state, op_wallet.as_bytes(), NOW_MS, &payload).unwrap();
    let id = hardware_level::rack_id(&op, "hall-a/row-3/nvl72-07");
    let record = hardware_level::read_rack(&state, &id).unwrap();
    assert_eq!(record.hosts.len(), 18);
    assert_eq!(record.gpus.len(), 72);
    assert_eq!(
        record
            .gpus
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        72
    );
    let wallets: Vec<Address> = rack.iter().map(|h| h.wallet).collect();
    close_epoch(&mut state, 0, &wallets);
    for h in &rack {
        let r = hardware_level::read_record(&state, h.wallet.as_bytes()).unwrap();
        assert_eq!(r.stamp.level, HardwareLevel::L3);
        assert_eq!(r.gpus.len(), 4);
        assert_eq!(
            hardware_level::fleet_of(&state, &h.did)
                .unwrap()
                .rack
                .as_deref(),
            Some(id.as_str())
        );
    }
    // Next epoch: one GPU of the rack answers another nonce. The rack is
    // refused whole; the lone host beside it is accepted.
    open_epoch(&mut state, 1);
    let mut hosts_1: Vec<FleetHost> = rack
        .iter()
        .map(|h| fleet_host(&state, &op, h, false, true))
        .collect();
    hosts_1[9].gpus[2].report = rack[9].gpus[2].report(&[7; 32]);
    let units = vec![
        FleetUnit::Rack {
            label: "hall-a/row-3/nvl72-07".into(),
            hosts: hosts_1,
        },
        FleetUnit::Host(fleet_host(&state, &op, &lone[0], true, true)),
    ];
    let (_, logs) = hardware_level::prove(
        &mut state,
        op_wallet.as_bytes(),
        NOW_MS,
        &fleet_payload(issuers, units),
    )
    .unwrap();
    let log = fleet_log(&logs);
    assert_eq!(log["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(log["accepted"][0]["host"], lone[0].did.as_str());
    assert_eq!(log["refused"][0]["rack"], "hall-a/row-3/nvl72-07");
    assert!(
        log["refused"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("GPU 2: report refused"),
        "{}",
        log["refused"][0]
    );
    for h in &rack {
        assert_ne!(
            hardware_level::read_possession(&state, &h.did)
                .unwrap()
                .epoch,
            1
        );
    }
}

/// The shape limits hold at admission: at most 8 GPUs a host, 18 hosts and
/// 72 GPUs a rack, and an NVL72 rack's real evidence (NVIDIA's sample H100
/// report and device certificates, 18 hosts' quotes) fits one proof whose
/// encoding fits one gossip message. Gas grows with the quotes and reports
/// and stays under the transaction gas limit at the largest proof.
#[test]
fn fleet_proof_limits_fit_a_rack_and_a_gossip_message() {
    use tenzro_types::hardware_level::{MAX_FLEET_EVIDENCE_BYTES, MAX_FLEET_GPUS, MAX_FLEET_HOSTS};
    let report = hex::decode(
        include_str!("../../../tenzro-tee/testdata/nvidia/hopper_attestation_report.hex").trim(),
    )
    .unwrap();
    let certs = tenzro_tee::x509::parse_pem_chain(include_str!(
        "../../../tenzro-tee/testdata/nvidia/hopper_cert_chain.crt"
    ))
    .unwrap();
    let ders: Vec<Vec<u8>> = certs.iter().map(|c| c.der.clone()).collect();
    let device_chain = [ders[0].clone(), ders[1].clone()].concat();
    let issuers = ders[2..].concat();
    let host = |gpus: usize| FleetHost {
        did: format!("did:tenzro:machine:{}", "a".repeat(64)),
        binding: Some(TpmQuote {
            quote: vec![0x5a; 145],
            signature: vec![1; 64],
        }),
        epoch: 0,
        possession: TpmQuote {
            quote: vec![0x5a; 145],
            signature: vec![1; 64],
        },
        gpus: (0..gpus)
            .map(|_| GpuEvidence {
                report: report.clone(),
                chain: device_chain.clone(),
            })
            .collect(),
    };
    let nvl72 = HardwareProofOp::Fleet {
        issuers: issuers.clone(),
        units: vec![FleetUnit::Rack {
            label: "nvl72".into(),
            hosts: (0..18).map(|_| host(4)).collect(),
        }],
    };
    nvl72.validate().unwrap();
    let json = serde_json::to_vec(&nvl72).unwrap();
    let wire = bincode::serialize(&tenzro_types::transaction::TransactionType::HardwareProof {
        op: nvl72.clone(),
    })
    .unwrap();
    println!(
        "NVL72 fleet proof: {} bytes of evidence, {} bytes JSON, {} bytes on the wire, gas {}",
        report.len() * 72 + device_chain.len() * 72 + issuers.len() + 18 * 2 * (145 + 64),
        json.len(),
        wire.len(),
        hardware_level::proof_gas(&json)
    );
    assert!(wire.len() < (1 << 20) - 16 * 1024, "{} bytes", wire.len());
    let over = |op: HardwareProofOp| op.validate().unwrap_err();
    assert!(
        over(HardwareProofOp::Fleet {
            issuers: Vec::new(),
            units: vec![FleetUnit::Host(FleetHost {
                gpus: vec![host(1).gpus[0].clone(); 9],
                ..host(0)
            })],
        })
        .contains("at most 8 GPUs")
    );
    assert!(
        over(HardwareProofOp::Fleet {
            issuers: Vec::new(),
            units: vec![FleetUnit::Rack {
                label: "r".into(),
                hosts: (0..19).map(|_| host(0)).collect(),
            }],
        })
        .contains("1 to 18 hosts")
    );
    assert!(
        over(HardwareProofOp::Fleet {
            issuers: Vec::new(),
            units: vec![FleetUnit::Rack {
                label: "r".into(),
                hosts: (0..10).map(|_| host(8)).collect(),
            }],
        })
        .contains("at most 72 GPUs")
    );
    assert!(
        over(HardwareProofOp::Fleet {
            issuers: Vec::new(),
            units: (0..MAX_FLEET_HOSTS + 1)
                .map(|_| FleetUnit::Host(host(0)))
                .collect(),
        })
        .contains("at most 64 hosts")
    );
    assert!(
        over(HardwareProofOp::Fleet {
            issuers: Vec::new(),
            units: Vec::new(),
        })
        .contains("at least one host")
    );
    // The largest proof the limits allow stays under the gas limit.
    let largest = HardwareProofOp::Fleet {
        issuers: Vec::new(),
        units: (0..MAX_FLEET_HOSTS)
            .map(|i| FleetUnit::Host(host(if i < MAX_FLEET_GPUS / 8 { 8 } else { 0 })))
            .collect(),
    };
    let gas = hardware_level::proof_gas(&serde_json::to_vec(&largest).unwrap());
    assert!(gas < crate::MAX_GAS_LIMIT, "{gas}");
    const { assert!(MAX_FLEET_EVIDENCE_BYTES * 2 < 1 << 20) };
}

/// With hardware binding on, the availability reward pays a host once per
/// GPU it proved, and once when it proved none.
#[test]
fn the_availability_reward_pays_each_gpu_of_a_host() {
    let mut state = genesis_state();
    let (op_wallet, op) = operator(&mut state, 0x0b);
    let fleet = hosts(&mut state, 0xb0, 2, 3, 0);
    let bare = &hosts(&mut state, 0xb8, 1, 0, 6)[0];
    set_gpu_roots(&mut state, &[&fleet[0].gpus[0].root_pem]);
    open_epoch(&mut state, 0);
    let units = fleet
        .iter()
        .chain([bare])
        .map(|h| FleetUnit::Host(fleet_host(&state, &op, h, true, false)))
        .collect();
    hardware_level::prove(
        &mut state,
        op_wallet.as_bytes(),
        NOW_MS,
        &fleet_payload(Vec::new(), units),
    )
    .unwrap();
    assert_eq!(hardware_level::current_gpus(&state, &fleet[0].did).len(), 3);
    assert_eq!(hardware_level::current_gpus(&state, &bare.did).len(), 0);
    set_governed_param_for_test(
        &mut state,
        availability_reward::AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM,
        1_000,
    );
    set_governed_param_for_test(
        &mut state,
        availability_reward::AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM,
        1,
    );
    let treasury: [u8; 32] = derive_treasury_address().as_bytes().try_into().unwrap();
    state.set_balance(&treasury, 1_000_000);
    let mut pay = |did: &str| {
        availability_reward::pay_if_available(
            &mut state,
            did,
            &[7u8; 20],
            0,
            NOW_MS,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap()
        .unwrap()
    };
    let one = pay(&bare.did);
    let three = pay(&fleet[0].did);
    assert!(one > 0);
    assert_eq!(three, 3 * one);
}
