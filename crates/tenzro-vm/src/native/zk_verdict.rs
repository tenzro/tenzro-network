//! Zero-knowledge proofs recorded by validators' verdicts.
//!
//! A proof envelope is larger than a batch part or a gossip message can
//! carry (about 1.1 MB for KoalaBear, 1.5 MB for Goldilocks), so no block can
//! hold one. It reaches validators directly instead; each runs the verifier
//! on it outside block execution and, when it verifies, states a verdict:
//! the statement, the proof's commitment and the proof system. Once
//! validators whose bonds hold two thirds of the bonded stake have stated
//! the same verdict, the proof is recorded where the ZK_VERIFY precompile
//! reads it, exactly as a verified `AttestZkProof` was recorded.
//!
//! The rule waits for [`GATE`].

use serde::{Deserialize, Serialize};

use super::funding::{read_json, refuse, write_json};
use super::*;

/// The gate of ZK verdicts.
pub const GATE: &str = "feature.zk_verdict.activation_epoch";

pub use tenzro_native_ops::SELECTOR_ZK_VERDICT;

/// Gas for one verdict: the verifier ran outside the block.
pub const GAS_ZK_VERDICT: u64 = 40_000;

/// Topic of the log a verdict emits.
pub const ZK_VERDICT_TOPIC: &[u8] = b"ZkVerdict";

/// Most validators whose verdicts are kept for one proof.
const MAX_VERDICTS: usize = 1_024;

/// The verdicts stated for one proof in one system.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVerdicts {
    /// The statement the proof proves, hex.
    pub statement: String,
    /// The validators that stated it, hex accounts, each once.
    pub validators: Vec<String>,
    /// Whether the proof is recorded.
    pub recorded: bool,
}

fn key(proof: &[u8], system: &str) -> String {
    format!("zk_verdicts:{}:{system}", hex::encode(proof))
}

/// The verdicts stated for the proof `proof` in `system`.
pub fn zk_verdicts(state: &dyn VmState, proof: &[u8], system: &str) -> ZkVerdicts {
    read_json(state, &key(proof, system)).unwrap_or_default()
}

/// Whether `account` may state a verdict: it holds a validator bond.
pub fn may_state(state: &dyn VmState, account: &[u8]) -> bool {
    staking::bonded_stake_of(state, account) > 0
}

/// The bonded stake of the validators in `validators` whose bonds stand now.
fn standing_stake(state: &dyn VmState, validators: &[String]) -> u128 {
    validators
        .iter()
        .filter_map(|v| hex::decode(v).ok())
        .map(|acct| staking::bonded_stake_of(state, &acct))
        .fold(0u128, u128::saturating_add)
}

/// Whether `stake` is two thirds or more of `total`.
fn two_thirds(stake: u128, total: u128) -> bool {
    total > 0 && stake.saturating_mul(3) >= total.saturating_mul(2)
}

/// Record the verdict `payload` from the validator `from`.
pub(super) fn apply(
    state: &mut dyn VmState,
    from: &[u8],
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Err(refuse("ZK verdicts are not in force on this chain yet"));
    }
    let op: tenzro_native_ops::zk_verdict::ZkVerdictOp = serde_json::from_slice(payload)
        .map_err(|e| refuse(format!("Invalid ZK verdict payload: {e}")))?;
    op.validate().map_err(refuse)?;
    let system = tenzro_zk::ProofSystem::parse(&op.system)
        .ok_or_else(|| refuse(format!("{} names no proof system", op.system)))?;
    require_lever_enabled(
        state,
        crate::governance::proof_system_status_key(system),
        &format!("ZK verdict: the {} proof system", system.as_str()),
    )?;
    if !may_state(state, from) {
        return Err(refuse(format!(
            "{} holds no validator bond; a ZK verdict is stated by a bonded validator",
            hex::encode(from)
        )));
    }
    let statement = hex::encode(&op.statement);
    let mut verdicts = zk_verdicts(state, &op.proof, system.as_str());
    if !verdicts.validators.is_empty() && verdicts.statement != statement {
        return Err(refuse(
            "this proof is already stated for another statement in this system",
        ));
    }
    let validator = hex::encode(from);
    if verdicts.validators.contains(&validator) {
        return Err(refuse(format!(
            "{validator} has already stated this verdict"
        )));
    }
    if verdicts.validators.len() >= MAX_VERDICTS {
        return Err(refuse("this proof holds the most verdicts kept"));
    }
    verdicts.statement = statement;
    verdicts.validators.push(validator.clone());

    let mut changes = Vec::new();
    let newly_recorded = !verdicts.recorded
        && two_thirds(
            standing_stake(state, &verdicts.validators),
            staking::total_bonded(state),
        );
    if newly_recorded {
        let proof: [u8; 32] = op.proof.as_slice().try_into().expect("validated: 32 bytes");
        let statement: [u8; 32] = op
            .statement
            .as_slice()
            .try_into()
            .expect("validated: 32 bytes");
        changes.extend(zk_registry::record(
            state,
            &proof,
            &statement,
            system.as_str(),
        ));
        verdicts.recorded = true;
    }
    write_json(
        state,
        &key(&op.proof, system.as_str()),
        &verdicts,
        &mut changes,
    )?;
    let data = serde_json::to_vec(&serde_json::json!({
        "statement": verdicts.statement,
        "proof": hex::encode(&op.proof),
        "system": system.as_str(),
        "validator": validator,
        "recorded": newly_recorded,
    }))
    .map_err(|e| VmError::Internal(format!("encode ZK verdict log: {e}")))?;
    Ok((
        changes,
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![ZK_VERDICT_TOPIC.to_vec()],
            data,
        )],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;
    use crate::precompiles::{PRECOMPILE_ZK_VERIFY, zk_attestation_slot, zk_statement_count_slot};
    use tenzro_native_ops::zk_verdict::ZkVerdictOp;

    const STATEMENT: [u8; 32] = [7; 32];
    const PROOF: [u8; 32] = [9; 32];
    const TNZO: u128 = 1_000_000_000_000_000_000;

    fn bond_validator(state: &mut StateAdapter, who: &[u8], stake: u128) {
        staking::add_bond(state, who, stake, -crate::governance::MIN_BOND_AGE_MS).unwrap();
        let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        state.set_balance(&STAKING_VAULT_ADDRESS, vault + stake);
    }

    fn verdict(system: &str) -> Vec<u8> {
        tenzro_native_ops::encode(&ZkVerdictOp {
            statement: STATEMENT.to_vec(),
            proof: PROOF.to_vec(),
            system: system.into(),
        })
    }

    fn recorded(state: &StateAdapter) -> bool {
        state
            .get_storage(&PRECOMPILE_ZK_VERIFY, &zk_attestation_slot(&PROOF))
            .is_some_and(|v| v.iter().any(|b| *b != 0))
    }

    fn systems(state: &StateAdapter) -> u128 {
        state
            .get_storage(&PRECOMPILE_ZK_VERIFY, &zk_statement_count_slot(&STATEMENT))
            .filter(|v| v.len() == 32)
            .map_or(0, |v| {
                let mut w = [0u8; 32];
                w.copy_from_slice(&v);
                crate::evm::precompile_host::word_to_u128(&w)
            })
    }

    /// Three validators of equal stake: dormant, a verdict is refused; live,
    /// one verdict records nothing, the second (two thirds) records the
    /// proof where ZK_VERIFY reads it and counts its system once, and the
    /// third changes nothing. A repeat, an account with no bond and an
    /// unknown system are refused.
    #[test]
    fn a_proof_is_recorded_once_two_thirds_of_the_stake_stated_it() {
        let mut state = StateAdapter::new();
        let v: Vec<Vec<u8>> = (1..=3u8).map(|i| vec![i; 20]).collect();
        for who in &v {
            bond_validator(&mut state, who, 1_000 * TNZO);
        }
        let system = tenzro_zk::ProofSystem::ALL[0].as_str();
        assert!(
            apply(&mut state, &v[0], &verdict(system)).is_err(),
            "dormant"
        );

        set_governed_param_for_test(&mut state, GATE, 0);
        apply(&mut state, &v[0], &verdict(system)).unwrap();
        assert!(!recorded(&state), "one third records nothing");
        assert!(
            apply(&mut state, &v[0], &verdict(system)).is_err(),
            "a repeat"
        );
        assert!(
            apply(&mut state, &[42u8; 20], &verdict(system)).is_err(),
            "no bond"
        );
        assert!(apply(&mut state, &v[1], &verdict("no-such-system")).is_err());

        let (_, logs) = apply(&mut state, &v[1], &verdict(system)).unwrap();
        assert!(recorded(&state), "two thirds record the proof");
        assert_eq!(systems(&state), 1);
        assert!(String::from_utf8_lossy(&logs[0].data).contains("\"recorded\":true"));

        apply(&mut state, &v[2], &verdict(system)).unwrap();
        assert_eq!(systems(&state), 1, "recorded once");
        assert!(zk_verdicts(&state, &PROOF, system).recorded);
    }

    /// The same proof stated for another statement in the same system is
    /// refused.
    #[test]
    fn a_proof_names_one_statement() {
        let mut state = StateAdapter::new();
        let v: Vec<Vec<u8>> = (1..=3u8).map(|i| vec![i; 20]).collect();
        for who in &v {
            bond_validator(&mut state, who, 1_000 * TNZO);
        }
        set_governed_param_for_test(&mut state, GATE, 0);
        let system = tenzro_zk::ProofSystem::ALL[0].as_str();
        apply(&mut state, &v[0], &verdict(system)).unwrap();
        let other = tenzro_native_ops::encode(&ZkVerdictOp {
            statement: vec![8; 32],
            proof: PROOF.to_vec(),
            system: system.into(),
        });
        assert!(apply(&mut state, &v[1], &other).is_err());
    }

    /// AttestZkProof is admitted at submission until verdicts are in force,
    /// then refused with where to send the proof.
    #[test]
    fn a_proof_in_a_transaction_is_refused_once_verdicts_are_live() {
        let mut state = StateAdapter::new();
        let attest =
            tenzro_types::transaction::TransactionType::AttestZkProof { proof: vec![0; 8] };
        assert!(crate::feature_gate::refuse_dormant_kind(&state, &attest).is_ok());
        set_governed_param_for_test(&mut state, GATE, 0);
        let refused = crate::feature_gate::refuse_dormant_kind(&state, &attest).unwrap_err();
        assert!(refused.contains("tenzro/zk-proof"), "{refused}");
    }
}
