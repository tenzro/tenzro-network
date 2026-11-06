//! The holders' chamber: veto escrow and human-root concerns.
//!
//! Any TNZO holder may lock TNZO against a proposal that moves value, takes
//! something from a named party, or upgrades the protocol. The lock sits in
//! an escrow vault keyed by the proposal. Past `veto.signal_bps` of supply the
//! timelock stretches in proportion to the locked share, up to
//! `veto.max_extension_ms`; at `veto.block_bps` the proposal is contested and
//! voted again on the Ratify track. A lock is withdrawn once the proposal is
//! decided, exactly as it went in: no reward and no slash, so it cannot be
//! farmed, and its weight is locked value, so splitting it across accounts
//! adds nothing.
//!
//! A registered human root that is at least `governance.root_min_age_ms` old
//! when the proposal opened may raise one concern on a queued proposal. Past
//! `governance.concern_quorum` concerns the timelock doubles, once only.
//! Concerns are a count, never weight: they delay and never decide.

use sha2::{Digest, Sha256};

use super::*;
use crate::governance::{
    CONCERN_QUORUM_PARAM, Proposal, ProposalStatus, ROOT_MIN_AGE_PARAM, VETO_BLOCK_BPS_PARAM,
    VETO_MAX_EXTENSION_PARAM, VETO_SIGNAL_BPS_PARAM, holder_veto_applies, veto_blocks,
    veto_extension_ms,
};

/// Lock TNZO against a proposal: `selector || proposal_id(32) || amount(u128 LE)`.
pub const SELECTOR_GOVERNANCE_VETO_SIGNAL: [u8; 4] = [0x02, 0x00, 0x00, 0x07];
/// Return a decided proposal's lock to its holder:
/// `selector || proposal_id(32) || holder_len(1) || holder`.
pub const SELECTOR_GOVERNANCE_VETO_WITHDRAW: [u8; 4] = [0x02, 0x00, 0x00, 0x08];
/// Raise a human root's concern on a queued proposal: `selector || proposal_id(32)`.
pub const SELECTOR_GOVERNANCE_CONCERN: [u8; 4] = [0x02, 0x00, 0x00, 0x09];

/// Gas for a veto signal, a withdrawal or a concern.
pub const GAS_HOLDER_GOVERNANCE: u64 = 60_000;

const VETO_VAULT_DOMAIN: &[u8] = b"tenzro/governance/veto-escrow";

fn lock_key(proposal_id: &str, holder: &[u8]) -> String {
    format!("veto_lock:{proposal_id}:{}", hex::encode(holder))
}

fn total_key(proposal_id: &str) -> String {
    format!("veto_total:{proposal_id}")
}

fn concern_key(proposal_id: &str, root: &str) -> String {
    format!("governance_concern:{proposal_id}:{root}")
}

/// The escrow vault holding every lock against `proposal_id`.
fn vault(proposal_id: &[u8; 32]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(VETO_VAULT_DOMAIN);
    h.update(proposal_id);
    let id: [u8; 32] = h.finalize().into();
    derive_vault_address(&id).as_bytes().to_vec()
}

fn read_u128(state: &dyn VmState, key: &str) -> u128 {
    state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .map(u128::from_le_bytes)
        .unwrap_or(0)
}

fn write_u128(state: &mut dyn VmState, key: &str, value: u128, changes: &mut Vec<StateChange>) {
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let blob = if value == 0 {
        Vec::new()
    } else {
        value.to_le_bytes().to_vec()
    };
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        prior,
        Some(blob),
    ));
}

/// TNZO locked against `proposal_id` by every holder.
pub fn locked_total(state: &dyn VmState, proposal_id: &str) -> u128 {
    read_u128(state, &total_key(proposal_id))
}

/// TNZO `holder` has locked against `proposal_id`.
pub fn locked_by(state: &dyn VmState, proposal_id: &str, holder: &[u8]) -> u128 {
    read_u128(state, &lock_key(proposal_id, holder))
}

fn proposal_arg(tx: &VmTransaction, len: usize) -> Result<([u8; 32], String)> {
    if tx.data.len() != len {
        return Err(VmError::InvalidTransaction(format!(
            "this governance transaction is {len} bytes: selector, proposal id (32 bytes){}",
            if len > 36 { ", amount (16 bytes)" } else { "" }
        )));
    }
    let id: [u8; 32] = tx.data[4..36].try_into().expect("length checked");
    let id_hex = hex::encode(id);
    Ok((id, id_hex))
}

fn load(state: &dyn VmState, id_hex: &str) -> Result<Proposal> {
    load_proposal(state, id_hex)
        .ok_or_else(|| VmError::InvalidTransaction(format!("Proposal {id_hex} does not exist")))
}

fn persist(
    state: &mut dyn VmState,
    proposal: &Proposal,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let (blob, prior) = store_proposal(state, proposal)?;
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        governance_proposal_key(&proposal.id).into_bytes(),
        prior,
        Some(blob),
    ));
    Ok(())
}

fn gas_cost(tx: &VmTransaction) -> u128 {
    tx.gas_price
        .saturating_mul(u128::from(GAS_HOLDER_GOVERNANCE))
}

/// Whether `proposal` has been decided at `now_ms`, which is when a veto
/// lock against it may be withdrawn.
fn decided(state: &dyn VmState, proposal: &Proposal, now_ms: i64) -> bool {
    match proposal.status {
        ProposalStatus::Executed | ProposalStatus::Vetoed | ProposalStatus::Rejected => true,
        ProposalStatus::Queued => proposal.is_executable_at(now_ms),
        ProposalStatus::Voting | ProposalStatus::Contested => {
            !proposal.is_open_at(now_ms)
                && crate::governance::decide_guarded(
                    proposal,
                    &load_tally(state, &proposal.ballot_id()),
                    now_ms,
                    super::loosens_capture_guard(state, &proposal.action),
                )
                .is_ok_and(|s| s != ProposalStatus::Passed)
        }
        ProposalStatus::Passed => false,
    }
}

/// Lock `amount` TNZO of `holder` against `id`: the stretch or the contest
/// it causes, persisted. Returns the proposal and whether it was contested.
fn lock(
    state: &mut dyn VmState,
    holder: &[u8],
    id: &[u8; 32],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<Proposal> {
    let id_hex = hex::encode(id);
    if amount == 0 {
        return Err(VmError::InvalidTransaction(
            "a veto signal locks a positive amount".into(),
        ));
    }
    let mut proposal = load(state, &id_hex)?;
    if !holder_veto_applies(&proposal.action) {
        return Err(VmError::InvalidTransaction(format!(
            "holders veto treasury, sanction and protocol upgrade proposals; {id_hex} is {}",
            proposal.action.kind()
        )));
    }
    let open = match proposal.status {
        ProposalStatus::Voting | ProposalStatus::Passed | ProposalStatus::Contested => true,
        ProposalStatus::Queued => !proposal.is_executable_at(now_ms),
        _ => false,
    };
    if !open {
        return Err(VmError::InvalidTransaction(format!(
            "proposal {id_hex} is past the point a veto signal can delay it ({:?})",
            proposal.status
        )));
    }
    payment_settlement::move_asset(
        state,
        &crate::token_ledger::tnzo_id(),
        holder,
        &vault(id),
        amount,
        now_ms,
        changes,
    )?;
    let mine = locked_by(state, &id_hex, holder).saturating_add(amount);
    write_u128(state, &lock_key(&id_hex, holder), mine, changes);
    let total = locked_total(state, &id_hex).saturating_add(amount);
    write_u128(state, &total_key(&id_hex), total, changes);

    let supply = state.native_total_supply();
    let signal_bps = network_param(state, VETO_SIGNAL_BPS_PARAM);
    let block_bps = network_param(state, VETO_BLOCK_BPS_PARAM);
    let max_ext = network_param(state, VETO_MAX_EXTENSION_PARAM);
    let electorate = load_tally(state, &proposal.ballot_id()).total_eligible;
    let contested = veto_blocks(total, supply, block_bps) && proposal.contest(now_ms);
    if contested {
        // The Ratify vote starts from an empty tally over the same electorate.
        let fresh = crate::governance::Tally {
            total_eligible: electorate,
            ..Default::default()
        };
        let ballot_id = proposal.ballot_id();
        let (blob, prior) = store_tally(state, &ballot_id, &fresh)?;
        changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            governance_tally_key(&ballot_id).into_bytes(),
            prior,
            Some(blob),
        ));
    } else {
        proposal.extend_by_veto(veto_extension_ms(
            total, supply, signal_bps, block_bps, max_ext,
        ));
    }
    persist(state, &proposal, changes)?;

    let mut data = id.to_vec();
    data.extend_from_slice(&total.to_le_bytes());
    data.extend_from_slice(holder);
    let topic: &[u8] = if contested {
        b"GovernanceContested"
    } else {
        b"GovernanceVetoSignal"
    };
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![topic.to_vec()],
        data,
    ));
    Ok(proposal)
}

/// `GovernanceVetoSignal`: lock TNZO against a proposal.
pub(super) fn execute_veto_signal(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    gas_meter: &mut GasMeter,
) -> Result<ExecutionResult> {
    gas_meter.consume(GAS_HOLDER_GOVERNANCE)?;
    let (id, _) = proposal_arg(tx, 52)?;
    let amount = u128::from_le_bytes(tx.data[36..52].try_into().expect("length checked"));
    let now_ms = deterministic_now_ms(tx);
    let cost = gas_cost(tx);
    let available = state.get_balance(&tx.from);
    let required = amount.saturating_add(cost);
    if available < required {
        return Err(VmError::InsufficientBalance {
            required,
            available,
        });
    }
    let mut changes = charge_and_advance(tx, state, cost);
    let mut logs = Vec::new();
    let proposal = lock(
        state,
        &tx.from,
        &id,
        amount,
        now_ms,
        &mut changes,
        &mut logs,
    )?;
    Ok(ExecutionResult::success(
        gas_meter.final_used(),
        proposal.eta_ms.unwrap_or_default().to_le_bytes().to_vec(),
        logs,
        changes,
    ))
}

/// An agent's veto signal from its wallet, for its principal: the terms give
/// it `may_veto_signal` in the proposal's domain, a treasury or sanction
/// signal carries the principal's step-up, and one signal locks at most the
/// governed agent share of supply.
#[allow(clippy::too_many_arguments)]
pub(crate) fn agent_signal(
    state: &mut dyn VmState,
    terms: &tenzro_types::agent_terms::AgentTerms,
    action: &tenzro_types::agent_terms::AgentAction,
    wallet: &[u8],
    proposal_id: &str,
    at_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    use crate::governance::{AGENT_WEIGHT_MAX_PARAM, ActionDomain};
    let refuse = |m: String| VmError::InvalidTransaction(format!("agent veto signal refused: {m}"));
    let scope = terms
        .delegation_scope
        .governance
        .as_ref()
        .filter(|g| g.may_veto_signal)
        .ok_or_else(|| refuse("the agent's terms give it no veto signal".into()))?;
    let id: [u8; 32] = hex::decode(proposal_id.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| refuse("a proposal id is 64 hex".into()))?;
    let proposal = load(state, &hex::encode(id))?;
    let domain = proposal.action.domain();
    let name = match domain {
        ActionDomain::Network => "network",
        ActionDomain::Treasury => "treasury",
        ActionDomain::Sanction => "sanction",
    };
    if !scope.domains.iter().any(|d| d.eq_ignore_ascii_case(name)) {
        return Err(refuse(format!(
            "the agent may not signal in the {name} domain"
        )));
    }
    if matches!(domain, ActionDomain::Treasury | ActionDomain::Sanction) && action.step_up.is_none()
    {
        return Err(refuse(format!(
            "a {name} signal needs the principal's step-up"
        )));
    }
    let cap_bps = u128::from(scope.max_weight_bps)
        .min(u128::from(network_param(state, AGENT_WEIGHT_MAX_PARAM)));
    let cap = state.native_total_supply().saturating_mul(cap_bps) / 10_000;
    if action.amount > cap {
        return Err(refuse(format!("one agent signal locks at most {cap}")));
    }
    lock(state, wallet, &id, action.amount, at_ms, changes, logs).map(|_| ())
}

/// `GovernanceVetoWithdraw`: return a holder's lock to it once the proposal
/// is decided. Anyone may submit it; the lock only ever goes back to the
/// account it came from, which lets an agent's wallet, which has no key of
/// its own, be paid back too.
pub(super) fn execute_veto_withdraw(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    gas_meter: &mut GasMeter,
) -> Result<ExecutionResult> {
    gas_meter.consume(GAS_HOLDER_GOVERNANCE)?;
    let holder = match tx.data.get(36).map(|l| *l as usize) {
        Some(len @ (20 | 32)) if tx.data.len() == 37 + len => tx.data[37..].to_vec(),
        _ => {
            return Err(VmError::InvalidTransaction(
                "a veto withdrawal is selector, proposal id (32 bytes) and the holder (length-prefixed, \
                 20 or 32 bytes)"
                    .into(),
            ));
        }
    };
    let id: [u8; 32] = tx.data[4..36].try_into().expect("length checked");
    let id_hex = hex::encode(id);
    let now_ms = deterministic_now_ms(tx);
    let proposal = load(state, &id_hex)?;
    let amount = locked_by(state, &id_hex, &holder);
    if amount == 0 {
        return Err(VmError::InvalidTransaction(format!(
            "{} holds no veto lock against {id_hex}",
            hex::encode(&holder)
        )));
    }
    if !decided(state, &proposal, now_ms) {
        return Err(VmError::InvalidTransaction(format!(
            "proposal {id_hex} is not decided yet; a veto lock returns once it is"
        )));
    }
    let cost = gas_cost(tx);
    let available = state.get_balance(&tx.from);
    if available < cost {
        return Err(VmError::InsufficientBalance {
            required: cost,
            available,
        });
    }
    let mut changes = charge_and_advance(tx, state, cost);
    payment_settlement::move_asset(
        state,
        &crate::token_ledger::tnzo_id(),
        &vault(&id),
        &holder,
        amount,
        now_ms,
        &mut changes,
    )?;
    write_u128(state, &lock_key(&id_hex, &holder), 0, &mut changes);
    let total = locked_total(state, &id_hex).saturating_sub(amount);
    write_u128(state, &total_key(&id_hex), total, &mut changes);

    let mut data = id.to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    Ok(ExecutionResult::success(
        gas_meter.final_used(),
        Vec::new(),
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"GovernanceVetoWithdrawn".to_vec()],
            data,
        )],
        changes,
    ))
}

/// `GovernanceConcern`: an aged human root's concern on a queued proposal.
pub(super) fn execute_concern(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    gas_meter: &mut GasMeter,
) -> Result<ExecutionResult> {
    gas_meter.consume(GAS_HOLDER_GOVERNANCE)?;
    let (id, id_hex) = proposal_arg(tx, 36)?;
    let now_ms = deterministic_now_ms(tx);
    let mut proposal = load(state, &id_hex)?;
    if proposal.status != ProposalStatus::Queued || proposal.is_executable_at(now_ms) {
        return Err(VmError::InvalidTransaction(format!(
            "a concern is raised on a proposal in its timelock; {id_hex} is not"
        )));
    }
    let did = identity_of_wallet(state, &tx.from).ok_or_else(|| {
        VmError::InvalidTransaction(format!(
            "{} has no registered identity",
            hex::encode(&tx.from)
        ))
    })?;
    let root = crate::funding::root_did(&did);
    if !root.starts_with(crate::governance::HUMAN_DID_PREFIX) || is_identity_revoked(state, &root) {
        return Err(VmError::InvalidTransaction(format!(
            "{did} has no live human root; a concern is raised by a human identity"
        )));
    }
    let min_age = network_param(state, ROOT_MIN_AGE_PARAM);
    let aged = identity_registered_at(state, &root).is_some_and(|at| {
        at.saturating_add(i64::try_from(min_age).unwrap_or(i64::MAX)) <= proposal.created_ms
    });
    if !aged {
        return Err(VmError::InvalidTransaction(format!(
            "{root} was registered less than {min_age} ms before the proposal opened; its concern does not count"
        )));
    }
    let key = concern_key(&id_hex, &root);
    if state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .is_some_and(|b| !b.is_empty())
    {
        return Err(VmError::InvalidTransaction(format!(
            "{root} has already raised a concern on {id_hex}"
        )));
    }
    let cost = gas_cost(tx);
    let available = state.get_balance(&tx.from);
    if available < cost {
        return Err(VmError::InsufficientBalance {
            required: cost,
            available,
        });
    }
    let mut changes = charge_and_advance(tx, state, cost);
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), vec![1]);
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        None,
        Some(vec![1]),
    ));
    let quorum = network_param(state, CONCERN_QUORUM_PARAM);
    let doubled = proposal.raise_concern(quorum);
    persist(state, &proposal, &mut changes)?;

    let mut data = id.to_vec();
    data.extend_from_slice(&proposal.concerns.to_le_bytes());
    data.push(u8::from(doubled));
    Ok(ExecutionResult::success(
        gas_meter.final_used(),
        proposal.eta_ms.unwrap_or_default().to_le_bytes().to_vec(),
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"GovernanceConcern".to_vec()],
            data,
        )],
        changes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VmType;
    use crate::config::VmConfig;
    use crate::governance::{
        ProposalAction, ProposalTrack, RATIFY_TIMELOCK_MS, TIMELOCK_DELAY_MS, VOTING_PERIOD_MS,
    };
    use crate::state_adapter::StateAdapter;

    const STAKE: u128 = 1_000_000;
    const GAS: u128 = 10_000_000_000_000_000_000;
    const SUPPLY: u128 = 1_000_000 * GAS;
    const GAS_PRICE: u128 = 1_000_000_000;
    const DAY: i64 = 24 * 60 * 60 * 1000;

    fn tx(from: &[u8], data: Vec<u8>, at_ms: i64) -> VmTransaction {
        let mut tx = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            200_000,
            GAS_PRICE,
            0,
            VmType::Evm,
            1337,
        );
        tx.block_timestamp_ms = Some(at_ms);
        tx
    }

    fn bind(state: &mut StateAdapter, addr: &[u8], did: &str, registered_ms: i64) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            identity_wallet_index_key(addr).as_bytes(),
            did.as_bytes().to_vec(),
        );
        state.set_storage(
            &SYSTEM_ADDRESS,
            &identity_storage_key(did),
            br#"{"did":"placeholder"}"#.to_vec(),
        );
        state.set_storage(
            &SYSTEM_ADDRESS,
            identity_registered_at_key(&crate::funding::root_did(did)).as_bytes(),
            registered_ms.to_le_bytes().to_vec(),
        );
        state.set_balance(addr, GAS);
    }

    struct World {
        executor: NativeExecutor,
        state: StateAdapter,
        validator: Vec<u8>,
        operator: Vec<u8>,
    }

    /// One validator holding all the stake, its operator, and a native
    /// supply holders are measured against.
    fn world() -> World {
        let mut state = StateAdapter::new();
        state.record_supply_change(SUPPLY, 0);
        let validator = vec![0x10; 32];
        let operator = vec![0x11; 32];
        staking::add_bond(
            &mut state,
            &validator,
            STAKE,
            -crate::governance::MIN_BOND_AGE_MS,
        )
        .unwrap();
        let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        state.set_balance(&STAKING_VAULT_ADDRESS, vault + STAKE);
        bind(&mut state, &validator, "did:tenzro:machine:op:v1", 0);
        bind(&mut state, &operator, "did:tenzro:human:op", 0);
        bind(&mut state, &[0x12; 32], "did:tenzro:human:subject", 0);
        World {
            executor: NativeExecutor::new(VmConfig::default()).unwrap(),
            state,
            validator,
            operator,
        }
    }

    impl World {
        async fn run(&mut self, from: &[u8], data: Vec<u8>, at: i64) -> Result<ExecutionResult> {
            self.executor
                .execute_transaction(&tx(from, data, at), &mut self.state)
                .await
        }

        async fn open(&mut self, action: ProposalAction, at: i64) -> Vec<u8> {
            let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
            data.extend_from_slice(&serde_json::to_vec(&action).unwrap());
            let v = self.validator.clone();
            self.run(&v, data, at).await.expect("propose").output
        }

        async fn vote_yes(&mut self, id: &[u8], at: i64) {
            let (op, v) = (self.operator.clone(), self.validator.clone());
            self.run(&op, crate::native::test_vote_data(id, true, &v), at)
                .await
                .expect("ballot");
        }

        async fn execute(&mut self, id: &[u8], at: i64) -> Result<ExecutionResult> {
            let mut data = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
            data.extend_from_slice(id);
            let v = self.validator.clone();
            self.run(&v, data, at).await
        }

        async fn signal(
            &mut self,
            holder: &[u8],
            id: &[u8],
            amount: u128,
            at: i64,
        ) -> Result<ExecutionResult> {
            let mut data = SELECTOR_GOVERNANCE_VETO_SIGNAL.to_vec();
            data.extend_from_slice(id);
            data.extend_from_slice(&amount.to_le_bytes());
            self.run(holder, data, at).await
        }

        async fn by_id(
            &mut self,
            selector: [u8; 4],
            from: &[u8],
            id: &[u8],
            at: i64,
        ) -> Result<ExecutionResult> {
            let mut data = selector.to_vec();
            data.extend_from_slice(id);
            self.run(from, data, at).await
        }

        async fn withdraw(
            &mut self,
            from: &[u8],
            holder: &[u8],
            id: &[u8],
            at: i64,
        ) -> Result<ExecutionResult> {
            let mut data = SELECTOR_GOVERNANCE_VETO_WITHDRAW.to_vec();
            data.extend_from_slice(id);
            data.push(holder.len() as u8);
            data.extend_from_slice(holder);
            self.run(from, data, at).await
        }

        fn proposal(&self, id: &[u8]) -> Proposal {
            load_proposal(&self.state, &hex::encode(id)).unwrap()
        }

        fn holder(&mut self, tag: u8, balance: u128) -> Vec<u8> {
            let h = vec![tag; 32];
            self.state.set_balance(&h, balance);
            h
        }
    }

    fn sanction() -> ProposalAction {
        ProposalAction::RevokeIdentity {
            did: "did:tenzro:human:subject".into(),
            reason: "evidence".into(),
        }
    }

    fn gas() -> u128 {
        GAS_PRICE * u128::from(GAS_HOLDER_GOVERNANCE)
    }

    #[test]
    fn the_extension_starts_at_the_signal_share_and_grows_linearly_to_the_cap() {
        let max = 30 * DAY as u64;
        let at = |bps: u128| veto_extension_ms(SUPPLY * bps / 10_000, SUPPLY, 100, 1_000, max);
        assert_eq!(at(99), 0, "below 1% nothing stretches");
        assert_eq!(at(100), 3 * DAY);
        assert_eq!(at(500), 15 * DAY);
        assert_eq!(at(1_000), 30 * DAY);
        assert_eq!(at(5_000), 30 * DAY, "capped");
        assert!(!veto_blocks(SUPPLY / 10 - 1, SUPPLY, 1_000));
        assert!(veto_blocks(SUPPLY / 10, SUPPLY, 1_000));
    }

    #[tokio::test]
    async fn one_percent_stretches_a_queued_timelock_and_only_value_moving_proposals_take_signals()
    {
        let mut w = world();
        let param = ProposalAction::ParameterChange {
            key: "agent.remote_grant_budget_divisor".into(),
            value: 4,
            memo: "m".into(),
        };
        let pid = w.open(param, 0).await;
        let h = w.holder(0x40, SUPPLY);
        let err = w.signal(&h, &pid, SUPPLY / 100, 10).await.unwrap_err();
        assert!(err.to_string().contains("holders veto"), "{err}");

        let id = w.open(sanction(), 0).await;
        w.vote_yes(&id, 10).await;
        w.execute(&id, VOTING_PERIOD_MS).await.expect("queue");
        let eta = w.proposal(&id).eta_ms.unwrap();
        assert_eq!(eta, VOTING_PERIOD_MS + TIMELOCK_DELAY_MS);

        w.signal(&h, &id, SUPPLY / 100, VOTING_PERIOD_MS + 1)
            .await
            .expect("signal");
        let p = w.proposal(&id);
        assert_eq!(p.status, ProposalStatus::Queued);
        assert_eq!(p.eta_ms.unwrap(), eta + 3 * DAY);
        assert_eq!(locked_total(&w.state, &hex::encode(&id)), SUPPLY / 100);
    }

    #[tokio::test]
    async fn ten_percent_contests_and_a_three_quarter_ratify_vote_enacts_after_thirty_days() {
        let mut w = world();
        let id = w.open(sanction(), 0).await;
        let h = w.holder(0x40, SUPPLY);
        w.signal(&h, &id, SUPPLY / 20, 10)
            .await
            .expect("first lock");
        w.signal(&h, &id, SUPPLY / 20, 20)
            .await
            .expect("top up to 10%");

        let p = w.proposal(&id);
        assert_eq!(p.status, ProposalStatus::Contested);
        assert_eq!(p.track, ProposalTrack::Ratify);
        let ends = 20 + VOTING_PERIOD_MS;
        assert_eq!(p.voting_ends_ms, ends);
        assert_eq!(
            load_tally(&w.state, &p.ballot_id()).yes,
            0,
            "the Ratify vote starts empty"
        );

        // Not decided while the Ratify vote runs: the lock stays.
        let err = w.withdraw(&h, &h, &id, 30).await.unwrap_err();
        assert!(err.to_string().contains("not decided"), "{err}");

        w.vote_yes(&id, 30).await;
        w.execute(&id, ends)
            .await
            .expect("queue the ratified proposal");
        let p = w.proposal(&id);
        assert_eq!(p.eta_ms.unwrap(), ends + RATIFY_TIMELOCK_MS);
        assert!(w.execute(&id, ends + RATIFY_TIMELOCK_MS - 1).await.is_err());
        w.execute(&id, ends + RATIFY_TIMELOCK_MS)
            .await
            .expect("enact");
        assert_eq!(w.proposal(&id).status, ProposalStatus::Executed);
        assert!(identity_is_revoked(&w.state, "did:tenzro:human:subject"));
    }

    #[tokio::test]
    async fn the_escrow_returns_in_full_on_decision_with_no_reward() {
        let mut w = world();
        let id = w.open(sanction(), 0).await;
        let h = w.holder(0x40, SUPPLY);
        w.signal(&h, &id, SUPPLY / 50, 10).await.expect("signal");
        assert_eq!(w.state.get_balance(&h), SUPPLY - SUPPLY / 50 - gas());

        // No ballot: the vote fails, which decides it.
        let other = w.holder(0x41, GAS);
        let err = w
            .withdraw(&other, &other, &id, VOTING_PERIOD_MS)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no veto lock"), "{err}");
        // Anyone may submit it; the lock goes back to its holder only.
        w.withdraw(&other, &h, &id, VOTING_PERIOD_MS)
            .await
            .expect("withdraw");
        assert_eq!(
            w.state.get_balance(&h),
            SUPPLY - gas(),
            "exactly what went in, less the signal's gas"
        );
        assert_eq!(w.state.get_balance(&other), GAS - gas());
        assert_eq!(locked_total(&w.state, &hex::encode(&id)), 0);
        let mut vid = [0u8; 32];
        vid.copy_from_slice(&id);
        assert_eq!(w.state.get_balance(&vault(&vid)), 0);
        assert!(w.withdraw(&h, &h, &id, VOTING_PERIOD_MS + 1).await.is_err());
    }

    #[tokio::test]
    async fn one_concern_per_aged_root_doubles_the_timelock_once() {
        let mut w = world();
        let opened = 40 * DAY;
        w.state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(CONCERN_QUORUM_PARAM).as_bytes(),
            2u64.to_le_bytes().to_vec(),
        );
        let id = w.open(sanction(), opened).await;
        w.vote_yes(&id, opened + 10).await;
        let queued = opened + VOTING_PERIOD_MS;
        w.execute(&id, queued).await.expect("queue");

        let mut roots = Vec::new();
        for i in 0..4u8 {
            let a = vec![0x50 + i; 32];
            bind(&mut w.state, &a, &format!("did:tenzro:human:r{i}"), 0);
            roots.push(a);
        }
        let young = vec![0x60; 32];
        bind(&mut w.state, &young, "did:tenzro:human:young", opened - DAY);
        let err = w
            .by_id(SELECTOR_GOVERNANCE_CONCERN, &young, &id, queued + 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not count"), "{err}");

        w.by_id(SELECTOR_GOVERNANCE_CONCERN, &roots[0], &id, queued + 1)
            .await
            .expect("first");
        let same_root = vec![0x70; 32];
        bind(&mut w.state, &same_root, "did:tenzro:machine:r0:m1", 0);
        let err = w
            .by_id(SELECTOR_GOVERNANCE_CONCERN, &same_root, &id, queued + 2)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already raised"), "{err}");

        w.by_id(SELECTOR_GOVERNANCE_CONCERN, &roots[1], &id, queued + 3)
            .await
            .expect("second");
        assert_eq!(
            w.proposal(&id).eta_ms.unwrap(),
            queued + TIMELOCK_DELAY_MS,
            "at the quorum, not past it"
        );
        w.by_id(SELECTOR_GOVERNANCE_CONCERN, &roots[2], &id, queued + 4)
            .await
            .expect("third");
        assert_eq!(
            w.proposal(&id).eta_ms.unwrap(),
            queued + 2 * TIMELOCK_DELAY_MS
        );
        w.by_id(SELECTOR_GOVERNANCE_CONCERN, &roots[3], &id, queued + 5)
            .await
            .expect("fourth");
        let p = w.proposal(&id);
        assert_eq!(p.concerns, 4);
        assert_eq!(
            p.eta_ms.unwrap(),
            queued + 2 * TIMELOCK_DELAY_MS,
            "doubles once only"
        );
    }
}
