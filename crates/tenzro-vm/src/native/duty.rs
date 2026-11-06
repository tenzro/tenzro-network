//! Network duties in chain state (see [`tenzro_types::duty`]).
//!
//! Records, under `SYSTEM_ADDRESS`:
//! - `duty:<id>`: the [`Duty`].
//! - `duties_open`: ids of open duties, oldest first.
//!
//! A duty's vault is funded by its opener before [`open`]; [`pay`] moves the
//! reward to the prover, [`close`] returns what is left to the funder.
//!
//! Handover proof duties are opened, delivered and closed by the
//! `HandoverDuty` transaction ([`handover_op`]).

use tenzro_finality::chain::HandoverChainJournal;
use tenzro_types::duty::{Duty, DutyKind, DutyState, HandoverDutyOp};

use super::funding::{move_balance, read_json, refuse, write_json};
use super::*;

/// Gas of a `HandoverDuty` transaction; a delivery's Groth16 check is most
/// of it.
pub const GAS_HANDOVER_DUTY: u64 = 150_000;

/// Log topic of a `HandoverDuty` transaction.
pub const HANDOVER_DUTY_TOPIC: &[u8] = b"tenzro/duty/handover";

const OPEN_KEY: &str = "duties_open";

/// System storage slot of a duty.
pub fn duty_key(id: &[u8; 32]) -> String {
    format!("duty:{}", hex::encode(id))
}

/// A duty.
pub fn read_duty(state: &dyn VmState, id: &[u8; 32]) -> Option<Duty> {
    read_json(state, &duty_key(id))
}

/// Ids of open duties, oldest first.
pub fn open_duties(state: &dyn VmState) -> Vec<[u8; 32]> {
    let ids: Vec<String> = read_json(state, OPEN_KEY).unwrap_or_default();
    ids.iter()
        .filter_map(|h| hex::decode(h).ok().and_then(|b| b.try_into().ok()))
        .collect()
}

/// A keyless vault derived from a duty id.
pub fn duty_vault(id: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(b"tenzro/duty/vault")
        .chain_update(id)
        .finalize()
        .into()
}

fn set_open(
    state: &mut dyn VmState,
    id: &[u8; 32],
    open: bool,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut ids: Vec<String> = read_json(state, OPEN_KEY).unwrap_or_default();
    let h = hex::encode(id);
    let at = ids.iter().position(|i| *i == h);
    match (open, at) {
        (true, None) => ids.push(h),
        (false, Some(i)) => {
            ids.remove(i);
        }
        _ => return Ok(()),
    }
    write_json(state, OPEN_KEY, &ids, changes)?;
    Ok(())
}

/// Open the duty `kind` whose `reward` already sits in `vault`, returning
/// its id. An open duty of the same kind is returned as it is.
#[allow(clippy::too_many_arguments)]
pub(super) fn open(
    state: &mut dyn VmState,
    kind: DutyKind,
    vault: [u8; 32],
    funder: [u8; 32],
    reward: u128,
    now_ms: i64,
    expires_at_ms: Option<i64>,
    changes: &mut Vec<StateChange>,
) -> Result<[u8; 32]> {
    let id = kind.id();
    if read_duty(state, &id).is_some() {
        return Ok(id);
    }
    let duty = Duty {
        id,
        kind,
        vault,
        funder,
        reward,
        opened_at_ms: now_ms,
        expires_at_ms,
        state: DutyState::Open,
        paid_to: None,
    };
    write_json(state, &duty_key(&id), &duty, changes)?;
    set_open(state, &id, true, changes)?;
    Ok(id)
}

/// Pay open duty `id` to `payee`. A duty already paid or closed pays
/// nothing and is not an error: only the first proof is paid.
pub(super) fn pay(
    state: &mut dyn VmState,
    id: &[u8; 32],
    payee: &[u8; 32],
    changes: &mut Vec<StateChange>,
) -> Result<bool> {
    let Some(mut duty) = read_duty(state, id) else {
        return Ok(false);
    };
    if duty.state != DutyState::Open {
        return Ok(false);
    }
    let amount = duty.reward.min(state.get_balance(&duty.vault));
    move_balance(state, &duty.vault, payee, amount, changes)?;
    duty.state = DutyState::Paid;
    duty.paid_to = Some(*payee);
    write_json(state, &duty_key(id), &duty, changes)?;
    set_open(state, id, false, changes)?;
    Ok(true)
}

/// Close open duty `id` unpaid, returning what its vault holds to the
/// funder (nothing moves when the funder is the vault itself).
pub(super) fn close(
    state: &mut dyn VmState,
    id: &[u8; 32],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let Some(mut duty) = read_duty(state, id) else {
        return Ok(());
    };
    if duty.state != DutyState::Open {
        return Ok(());
    }
    if duty.funder != duty.vault {
        let held = state.get_balance(&duty.vault);
        move_balance(state, &duty.vault, &duty.funder, held, changes)?;
    }
    duty.state = DutyState::Expired;
    write_json(state, &duty_key(id), &duty, changes)?;
    set_open(state, id, false, changes)?;
    Ok(())
}

/// Apply a `HandoverDuty` transaction from `from`: open a handover proof
/// duty with the sender's reward, pay it to the sender for a proof the
/// governed handover program made, or close it once expired.
pub(super) fn handover_op(
    state: &mut dyn VmState,
    from: &[u8],
    now_ms: i64,
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    handover_op_with(
        state,
        from,
        now_ms,
        payload,
        tenzro_zk::finality_proof::verify_groth16,
    )
}

/// [`handover_op`] with the Groth16 verifier `verify(image_id, journal, seal)`.
fn handover_op_with(
    state: &mut dyn VmState,
    from: &[u8],
    now_ms: i64,
    payload: &[u8],
    verify: impl FnOnce(&[u8; 32], &[u8], &[u8]) -> std::result::Result<(), String>,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let op: HandoverDutyOp = serde_json::from_slice(payload)
        .map_err(|e| VmError::InvalidTransaction(format!("Invalid HandoverDuty payload: {e}")))?;
    let sender: [u8; 32] = from
        .try_into()
        .map_err(|_| refuse("the sender is not a 32-byte account"))?;
    let mut changes = Vec::new();
    let open_handover = |state: &dyn VmState, id: &[u8; 32]| -> Result<Duty> {
        let duty = read_duty(state, id).ok_or_else(|| refuse("no such duty"))?;
        if !matches!(duty.kind, DutyKind::HandoverProof { .. }) {
            return Err(refuse("the duty is not a handover proof duty"));
        }
        if duty.state != DutyState::Open {
            return Err(refuse("the duty is no longer open"));
        }
        Ok(duty)
    };
    let record = match op {
        HandoverDutyOp::Open {
            chain_id,
            genesis_hash,
            genesis_root,
            epoch,
            reward,
            expires_at_ms,
        } => {
            if reward == 0 {
                return Err(refuse("a handover proof duty pays a reward"));
            }
            if expires_at_ms <= now_ms {
                return Err(refuse("a handover proof duty expires after it opens"));
            }
            let kind = DutyKind::HandoverProof {
                chain_id,
                genesis_hash,
                genesis_root,
                epoch,
            };
            let id = kind.id();
            if read_duty(state, &id).is_some() {
                return Err(refuse("a duty for that chain and epoch exists"));
            }
            let vault = duty_vault(&id);
            move_balance(state, from, &vault, reward, &mut changes)?;
            open(
                state,
                kind,
                vault,
                sender,
                reward,
                now_ms,
                Some(expires_at_ms),
                &mut changes,
            )?;
            serde_json::json!({"opened": hex::encode(id), "reward": reward.to_string()})
        }
        HandoverDutyOp::Deliver {
            duty_id,
            journal,
            seal,
        } => {
            let duty = open_handover(state, &duty_id)?;
            if duty.expires_at_ms.is_some_and(|t| now_ms >= t) {
                return Err(refuse("the duty has expired"));
            }
            let program = super::evidence::read_handover_program(state)
                .ok_or_else(|| refuse("no handover program is configured on chain"))?;
            let proven = check_handover_proof(&duty.kind, &program, &journal, &seal, verify)?;
            pay(state, &duty_id, &sender, &mut changes)?;
            serde_json::json!({
                "paid": hex::encode(duty_id),
                "to": hex::encode(sender),
                "epoch": proven.epoch,
            })
        }
        HandoverDutyOp::Close { duty_id } => {
            let duty = open_handover(state, &duty_id)?;
            if duty.expires_at_ms.is_none_or(|t| now_ms < t) {
                return Err(refuse("the duty has not expired"));
            }
            close(state, &duty_id, &mut changes)?;
            serde_json::json!({"closed": hex::encode(duty_id)})
        }
    };
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![HANDOVER_DUTY_TOPIC.to_vec()],
        serde_json::to_vec(&record)
            .map_err(|e| VmError::Internal(format!("encode handover duty log: {e}")))?,
    );
    Ok((changes, vec![log]))
}

/// What a Groth16 proof of the handover program states, once it verifies
/// under `program` (`verify(program, journal, seal)`), names that program as
/// the one behind every link, is of the chain `kind` names and reaches its
/// epoch.
pub fn check_handover_proof(
    kind: &DutyKind,
    program: &[u8; 32],
    journal: &[u8],
    seal: &[u8],
    verify: impl FnOnce(&[u8; 32], &[u8], &[u8]) -> std::result::Result<(), String>,
) -> Result<HandoverChainJournal> {
    let DutyKind::HandoverProof {
        chain_id,
        genesis_hash,
        genesis_root,
        epoch,
    } = kind
    else {
        return Err(refuse("the duty is not a handover proof duty"));
    };
    verify(program, journal, seal)
        .map_err(|e| refuse(format!("the handover proof does not verify: {e}")))?;
    let j = HandoverChainJournal::decode(journal)
        .ok_or_else(|| refuse("the proof commits no chain journal"))?;
    if j.program != *program {
        return Err(refuse("the proven chain names another program"));
    }
    if j.chain_id != *chain_id || j.genesis_hash != *genesis_hash || j.genesis_root != *genesis_root
    {
        return Err(refuse("the proof is of another chain"));
    }
    if j.epoch < *epoch {
        return Err(refuse(format!(
            "the proof reaches epoch {}, the duty asks for epoch {epoch}",
            j.epoch
        )));
    }
    Ok(j)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;

    fn state() -> StateAdapter {
        StateAdapter::new()
    }

    #[test]
    fn a_duty_pays_its_first_prover_once() {
        let mut s = state();
        let kind = DutyKind::Reconciliation {
            route: "r".into(),
            epoch: 1,
        };
        let vault = duty_vault(&kind.id());
        s.set_balance(&vault, 10);
        let mut changes = Vec::new();
        let id = open(&mut s, kind, vault, [9; 32], 10, 0, Some(5), &mut changes).unwrap();
        assert_eq!(open_duties(&s), vec![id]);
        assert!(pay(&mut s, &id, &[1; 32], &mut changes).unwrap());
        assert!(!pay(&mut s, &id, &[2; 32], &mut changes).unwrap());
        assert_eq!(s.get_balance(&[1; 32]), 10);
        assert_eq!(s.get_balance(&[2; 32]), 0);
        assert!(open_duties(&s).is_empty());
        assert_eq!(read_duty(&s, &id).unwrap().paid_to, Some([1; 32]));
    }

    fn handover_kind(epoch: u64) -> DutyKind {
        DutyKind::HandoverProof {
            chain_id: 7,
            genesis_hash: [1; 32],
            genesis_root: [2; 32],
            epoch,
        }
    }

    fn chain_journal(program: [u8; 32], epoch: u64) -> Vec<u8> {
        HandoverChainJournal {
            program,
            chain_id: 7,
            genesis_hash: [1; 32],
            genesis_root: [2; 32],
            epoch,
            committee_root: [4; 32],
        }
        .encode()
    }

    fn op(state: &mut StateAdapter, from: [u8; 32], now: i64, op: serde_json::Value) -> Result<()> {
        handover_op_with(
            state,
            &from,
            now,
            &serde_json::to_vec(&op).unwrap(),
            |_: &[u8; 32], _: &[u8], seal: &[u8]| {
                if seal == b"seal" {
                    Ok(())
                } else {
                    Err("forged".into())
                }
            },
        )
        .map(|_| ())
    }

    /// A handover proof duty holds its funder's reward and pays it to the
    /// first proof of the governed program that reaches its chain's epoch;
    /// a proof of another chain, one short of the epoch or one that does not
    /// verify is refused, and an unpaid duty returns its reward on expiry.
    #[test]
    fn a_handover_proof_duty_pays_the_first_proof_of_its_chain_and_epoch() {
        let mut s = state();
        let program = [3; 32];
        let mut changes = Vec::new();
        super::super::evidence::set_handover_program(&mut s, &program, &mut changes).unwrap();
        let (funder, prover) = ([9; 32], [5; 32]);
        s.set_balance(&funder, 100);
        let opening = |epoch: u64| {
            serde_json::json!({
                "op": "open", "chain_id": 7, "genesis_hash": hex::encode([1u8; 32]),
                "genesis_root": hex::encode([2u8; 32]), "epoch": epoch,
                "reward": "40", "expires_at_ms": 1_000,
            })
        };
        op(&mut s, funder, 10, opening(20)).unwrap();
        let id = handover_kind(20).id();
        assert_eq!(s.get_balance(&funder), 60);
        assert_eq!(s.get_balance(&duty_vault(&id)), 40);
        assert!(
            op(&mut s, funder, 11, opening(20)).is_err(),
            "one duty per chain and epoch"
        );

        let deliver = |journal: Vec<u8>, seal: &[u8]| {
            serde_json::json!({
                "op": "deliver", "duty_id": hex::encode(id),
                "journal": hex::encode(journal), "seal": hex::encode(seal),
            })
        };
        assert!(
            op(
                &mut s,
                prover,
                20,
                deliver(chain_journal(program, 20), b"forged")
            )
            .is_err()
        );
        assert!(
            op(
                &mut s,
                prover,
                20,
                deliver(chain_journal(program, 19), b"seal")
            )
            .is_err(),
            "short of the epoch"
        );
        assert!(
            op(
                &mut s,
                prover,
                20,
                deliver(chain_journal([8; 32], 20), b"seal")
            )
            .is_err(),
            "another program"
        );
        let mut other = HandoverChainJournal::decode(&chain_journal(program, 20)).unwrap();
        other.genesis_root = [6; 32];
        assert!(
            op(&mut s, prover, 20, deliver(other.encode(), b"seal")).is_err(),
            "another chain"
        );
        assert!(
            op(
                &mut s,
                prover,
                20,
                serde_json::json!({"op": "close", "duty_id": hex::encode(id)})
            )
            .is_err(),
            "not expired"
        );

        op(
            &mut s,
            prover,
            20,
            deliver(chain_journal(program, 25), b"seal"),
        )
        .unwrap();
        assert_eq!(s.get_balance(&prover), 40);
        assert_eq!(read_duty(&s, &id).unwrap().paid_to, Some(prover));
        assert!(
            op(
                &mut s,
                [6; 32],
                21,
                deliver(chain_journal(program, 25), b"seal")
            )
            .is_err(),
            "paid once"
        );

        op(&mut s, funder, 30, opening(30)).unwrap();
        let late = handover_kind(30).id();
        assert!(
            op(
                &mut s,
                funder,
                999,
                serde_json::json!({"op": "close", "duty_id": hex::encode(late)})
            )
            .is_err()
        );
        assert!(
            op(&mut s, prover, 1_000, serde_json::json!({
                "op": "deliver", "duty_id": hex::encode(late),
                "journal": hex::encode(chain_journal(program, 30)), "seal": hex::encode(b"seal"),
            }))
            .is_err(),
            "expired"
        );
        op(
            &mut s,
            prover,
            1_000,
            serde_json::json!({"op": "close", "duty_id": hex::encode(late)}),
        )
        .unwrap();
        assert_eq!(s.get_balance(&funder), 60, "the unpaid reward is back");
        assert_eq!(read_duty(&s, &late).unwrap().state, DutyState::Expired);
    }

    #[test]
    fn closing_returns_the_reward_to_the_funder() {
        let mut s = state();
        let kind = DutyKind::Reconciliation {
            route: "r".into(),
            epoch: 2,
        };
        let vault = duty_vault(&kind.id());
        s.set_balance(&vault, 7);
        let mut changes = Vec::new();
        let id = open(&mut s, kind, vault, [9; 32], 7, 0, Some(5), &mut changes).unwrap();
        close(&mut s, &id, &mut changes).unwrap();
        assert_eq!(s.get_balance(&[9; 32]), 7);
        assert_eq!(read_duty(&s, &id).unwrap().state, DutyState::Expired);
        assert!(!pay(&mut s, &id, &[1; 32], &mut changes).unwrap());
    }
}
