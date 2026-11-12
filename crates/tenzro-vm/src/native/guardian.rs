//! Guardian seats, their m-of-n signals, and the self-expiring pauses.
//!
//! A seat lives at `governance_guardian:<addr>` in system storage, written
//! only by an enacted `SetGuardian` proposal or the genesis seed, and listed
//! in `governance_guardian_index`. A veto or a pause is a signal from one
//! seated guardian; it takes effect once `governance.guardian_threshold`
//! distinct guardians of the role holding a live seat have signalled. Two
//! live seats of one role never share a key root, so the threshold counts
//! independent keys.
//!
//! A protocol guardian's pause holds all enactment; a Foundation steward's
//! holds treasury and expedited enactment only. Either lifts by itself after
//! `governance.max_pause_ms`, and a new one cannot start until
//! `governance.pause_cooloff_ms` after the last one ended.
//!
//! Foundation steward seats hold power only before
//! `governance.steward_sunset_ms`, and at most `governance.steward_max_seats`
//! are live at once. Both values only ever shrink, so stewardship ends on the
//! schedule governance set and cannot be extended from inside.

use serde::{Deserialize, Serialize};

use super::{SYSTEM_ADDRESS, network_param};
use crate::governance::{
    GUARDIAN_SIGNAL_WINDOW_PARAM, GUARDIAN_THRESHOLD_PARAM, GuardianRole, GuardianSeat,
    MAX_PAUSE_PARAM, PAUSE_COOLOFF_PARAM, STEWARD_MAX_SEATS_PARAM, STEWARD_SUNSET_PARAM,
    SeatKeyRoot,
};
use crate::traits::VmState;
use crate::types::StateChange;

/// Storage key of the guardian seat held by `addr`.
pub fn seat_key(addr: &[u8]) -> String {
    format!("governance_guardian:{}", hex::encode(addr))
}

/// The seat held by `addr`, live or lapsed.
pub fn load_seat(state: &dyn VmState, addr: &[u8]) -> Option<GuardianSeat> {
    let blob = state.get_storage(&SYSTEM_ADDRESS, seat_key(addr).as_bytes())?;
    if blob.is_empty() {
        return None;
    }
    serde_json::from_slice(&blob).ok()
}

/// Block time after which steward seats hold no power.
pub fn steward_sunset_ms(state: &dyn VmState) -> i64 {
    network_param(state, STEWARD_SUNSET_PARAM).min(i64::MAX as u64) as i64
}

/// Most live steward seats.
pub fn steward_max_seats(state: &dyn VmState) -> usize {
    network_param(state, STEWARD_MAX_SEATS_PARAM) as usize
}

/// Whether `seat` holds its power at block time `now_ms`: within its term,
/// and for a steward also before the sunset.
pub fn seat_live(state: &dyn VmState, seat: &GuardianSeat, now_ms: i64) -> bool {
    seat.is_active(now_ms)
        && (seat.role != GuardianRole::Steward || now_ms < steward_sunset_ms(state))
}

/// The role `addr` holds at block time `now_ms`, if its seat is live.
pub fn active_role(state: &dyn VmState, addr: &[u8], now_ms: i64) -> Option<GuardianRole> {
    load_seat(state, addr)
        .filter(|s| seat_live(state, s, now_ms))
        .map(|s| s.role)
}

/// Storage key of the list of seated addresses.
pub const INDEX_KEY: &str = "governance_guardian_index";

/// Every address holding a seat, live or lapsed, hex.
pub fn seated_addresses(state: &dyn VmState) -> Vec<String> {
    state
        .get_storage(&SYSTEM_ADDRESS, INDEX_KEY.as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Every seat with its address, live or lapsed.
pub fn seats(state: &dyn VmState) -> Vec<(String, GuardianSeat)> {
    seated_addresses(state)
        .into_iter()
        .filter_map(|a| {
            let bytes = hex::decode(&a).ok()?;
            load_seat(state, &bytes).map(|s| (a, s))
        })
        .collect()
}

/// The index entry for a seat set: the sorted address list with `addr`
/// added or removed.
pub fn index_with(mut index: Vec<String>, addr: &[u8], seated: bool) -> Vec<String> {
    let me = hex::encode(addr);
    index.retain(|a| a != &me);
    if seated {
        index.push(me);
    }
    index.sort();
    index
}

/// Write (or, with `None`, clear) the seat at `addr`.
pub fn write_seat(
    state: &mut dyn VmState,
    addr: &[u8],
    seat: Option<&GuardianSeat>,
    changes: &mut Vec<StateChange>,
) {
    let key = seat_key(addr);
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let blob = seat
        .map(|s| serde_json::to_vec(s).expect("a seat serialises"))
        .unwrap_or_default();
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        previous,
        Some(blob),
    ));

    let index = index_with(seated_addresses(state), addr, seat.is_some());
    let previous = state.get_storage(&SYSTEM_ADDRESS, INDEX_KEY.as_bytes());
    let blob = serde_json::to_vec(&index).expect("an index serialises");
    state.set_storage(&SYSTEM_ADDRESS, INDEX_KEY.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        INDEX_KEY.as_bytes().to_vec(),
        previous,
        Some(blob),
    ));
}

/// Distinct live guardians needed for a veto, pause or resume.
pub fn threshold(state: &dyn VmState) -> usize {
    network_param(state, GUARDIAN_THRESHOLD_PARAM) as usize
}

/// One guardian's signal: who and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// Signer account, hex.
    pub guardian: String,
    /// Block time it was signalled at.
    pub at_ms: i64,
}

fn load_signals(state: &dyn VmState, key: &str) -> Vec<Signal> {
    state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn store_signals(
    state: &mut dyn VmState,
    key: &str,
    signals: &[Signal],
    changes: &mut Vec<StateChange>,
) {
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let blob = if signals.is_empty() {
        Vec::new()
    } else {
        serde_json::to_vec(signals).expect("signals serialise")
    };
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        previous,
        Some(blob),
    ));
}

/// Outcome of recording a guardian signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tallied {
    /// Distinct live signers counted, including this one.
    pub signers: usize,
    /// Signers needed.
    pub threshold: usize,
}

impl Tallied {
    /// Whether the signal carried.
    pub fn carried(&self) -> bool {
        self.signers >= self.threshold
    }
}

/// Record `signer`'s signal under `key` and count the distinct signers whose
/// seat for `role` is live and whose signal is newer than `window_ms`. A
/// signer signalling twice is refused. When the signal carries the stored
/// signals are cleared.
fn signal(
    state: &mut dyn VmState,
    key: &str,
    role: GuardianRole,
    signer: &[u8],
    now_ms: i64,
    window_ms: Option<u64>,
    changes: &mut Vec<StateChange>,
) -> Result<Tallied, String> {
    let me = hex::encode(signer);
    let mut signals: Vec<Signal> = load_signals(state, key)
        .into_iter()
        .filter(|s| window_ms.is_none_or(|w| now_ms.saturating_sub(s.at_ms) <= w as i64))
        .filter(|s| {
            hex::decode(&s.guardian)
                .ok()
                .and_then(|a| active_role(state, &a, now_ms))
                == Some(role)
        })
        .collect();
    if signals.iter().any(|s| s.guardian == me) {
        return Err("this guardian has already signalled".to_string());
    }
    signals.push(Signal {
        guardian: me,
        at_ms: now_ms,
    });
    let tallied = Tallied {
        signers: signals.len(),
        threshold: threshold(state),
    };
    if tallied.carried() {
        signals.clear();
    }
    store_signals(state, key, &signals, changes);
    Ok(tallied)
}

/// Record a veto signal on `proposal_id` from a seated guardian of `role`.
/// Governance guardians and stewards tally separately: neither completes
/// the other's threshold.
pub fn signal_veto(
    state: &mut dyn VmState,
    role: GuardianRole,
    proposal_id: &str,
    signer: &[u8],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<Tallied, String> {
    let key = format!("governance_veto_signals:{}:{proposal_id}", role.as_str());
    signal(state, &key, role, signer, now_ms, None, changes)
}

/// What a carried pause holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseScope {
    /// All governance enactment (protocol guardians).
    Enactment,
    /// Treasury and expedited enactment (Foundation stewards).
    Treasury,
}

impl PauseScope {
    /// The scope a pause by `role` holds.
    pub fn of(role: Option<GuardianRole>) -> PauseScope {
        match role {
            Some(GuardianRole::Steward) => PauseScope::Treasury,
            _ => PauseScope::Enactment,
        }
    }

    fn role(self) -> GuardianRole {
        match self {
            PauseScope::Enactment => GuardianRole::Protocol,
            PauseScope::Treasury => GuardianRole::Steward,
        }
    }

    fn key(self) -> &'static str {
        match self {
            PauseScope::Enactment => "governance_pause",
            PauseScope::Treasury => "governance_treasury_hold",
        }
    }
}

/// Record a pause (`true`) or resume (`false`) signal in `scope`.
pub fn signal_pause(
    state: &mut dyn VmState,
    scope: PauseScope,
    want_paused: bool,
    signer: &[u8],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<Tallied, String> {
    let key = format!("{}_signals:{}", scope.key(), u8::from(want_paused));
    let window = network_param(state, GUARDIAN_SIGNAL_WINDOW_PARAM);
    signal(
        state,
        &key,
        scope.role(),
        signer,
        now_ms,
        Some(window),
        changes,
    )
}

/// Record a signal to pause the feature governed by the status lever `key`
/// for `epochs` epochs. Only protocol guardians count, and only signals for
/// the same feature and the same number of epochs add up.
pub fn signal_feature_pause(
    state: &mut dyn VmState,
    key: &str,
    epochs: u64,
    signer: &[u8],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<Tallied, String> {
    let signals = format!("governance_feature_pause_signals:{key}:{epochs}");
    let window = network_param(state, GUARDIAN_SIGNAL_WINDOW_PARAM);
    signal(
        state,
        &signals,
        GuardianRole::Protocol,
        signer,
        now_ms,
        Some(window),
        changes,
    )
}

/// A pause: until when it holds, and until when a new one may not start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseRecord {
    /// Block time the pause lifts at.
    pub paused_until_ms: i64,
    /// Block time before which a new pause is refused.
    pub cooloff_until_ms: i64,
}

/// The current pause record in `scope`.
pub fn pause_record(state: &dyn VmState, scope: PauseScope) -> PauseRecord {
    state
        .get_storage(&SYSTEM_ADDRESS, scope.key().as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Whether `scope` is paused at block time `now_ms`.
pub fn is_paused(state: &dyn VmState, scope: PauseScope, now_ms: i64) -> bool {
    now_ms < pause_record(state, scope).paused_until_ms
}

/// Apply a carried pause or resume in `scope` at `now_ms`.
pub fn apply_pause(
    state: &mut dyn VmState,
    scope: PauseScope,
    want_paused: bool,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> PauseRecord {
    let max_pause = network_param(state, MAX_PAUSE_PARAM) as i64;
    let cooloff = network_param(state, PAUSE_COOLOFF_PARAM) as i64;
    let ends = if want_paused {
        now_ms.saturating_add(max_pause)
    } else {
        now_ms
    };
    let record = PauseRecord {
        paused_until_ms: ends,
        cooloff_until_ms: ends.saturating_add(cooloff),
    };
    let key = scope.key();
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let blob = serde_json::to_vec(&record).expect("a pause record serialises");
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        previous,
        Some(blob),
    ));
    record
}

/// Check a seat proposal against chain state at block time `now_ms`: the DID
/// is a registered, unrevoked human identity, registered to `address`; the
/// term ends within the governed maximum; no other live seat of the role
/// shares `key_root`; and a steward seat ends by the sunset and fits under
/// the seat cap.
pub fn check_seat(
    state: &dyn VmState,
    address: &[u8],
    did: &str,
    role: GuardianRole,
    term_ends_ms: i64,
    key_root: &SeatKeyRoot,
    now_ms: i64,
) -> Result<(), String> {
    key_root.validate().map_err(|e| e.to_string())?;
    let me = hex::encode(address);
    let others: Vec<GuardianSeat> = seats(state)
        .into_iter()
        .filter(|(a, s)| a != &me && s.role == role && seat_live(state, s, now_ms))
        .map(|(_, s)| s)
        .collect();
    if others.iter().any(|s| &s.key_root == key_root) {
        return Err(format!(
            "another live {} seat holds a key with the same root",
            role.as_str()
        ));
    }
    if role == GuardianRole::Steward {
        let sunset = steward_sunset_ms(state);
        if term_ends_ms > sunset {
            return Err(format!(
                "a steward seat must end by the stewardship sunset at {sunset}"
            ));
        }
        let cap = steward_max_seats(state);
        if others.len() >= cap {
            return Err(format!(
                "{} live steward seats already fill the cap of {cap}",
                others.len()
            ));
        }
    }
    let max_term = network_param(state, crate::governance::GUARDIAN_MAX_TERM_PARAM);
    crate::governance::check_guardian_term(did, term_ends_ms, now_ms, max_term)
        .map_err(|e| e.to_string())?;
    if super::identity_of_wallet(state, address).as_deref() != Some(did) {
        return Err(format!(
            "{did} is not the identity registered to {}",
            hex::encode(address)
        ));
    }
    if super::is_identity_revoked(state, did) {
        return Err(format!("identity {did} is revoked"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::VmType;
    use crate::config::VmConfig;
    use crate::governance::{GuardianRole, ProposalAction};
    use crate::state_adapter::StateAdapter;
    use crate::types::{ExecutionResult, VmTransaction};

    const STAKE: u128 = 1_000_000;
    const GAS: u128 = 10_000_000_000_000_000_000;
    const DAY: i64 = 24 * 60 * 60 * 1000;

    fn tx(from: &[u8], data: Vec<u8>, at_ms: i64) -> VmTransaction {
        let mut tx = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            200_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );
        tx.block_timestamp_ms = Some(at_ms);
        tx
    }

    fn with(selector: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut d = selector.to_vec();
        d.extend_from_slice(body);
        d
    }

    fn human(n: u8) -> String {
        format!("did:tenzro:human:{n:02x}")
    }

    fn setup() -> (NativeExecutor, StateAdapter, Vec<u8>) {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let voter = vec![1u8; 20];
        staking::add_bond(
            &mut state,
            &voter,
            STAKE,
            -crate::governance::MIN_BOND_AGE_MS,
        )
        .unwrap();
        let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        state.set_balance(&STAKING_VAULT_ADDRESS, vault + STAKE);
        state.set_balance(&voter, GAS);
        test_operate_own_validator(&mut state, &voter);
        (executor, state, voter)
    }

    fn guardian_account(state: &mut StateAdapter, n: u8) -> Vec<u8> {
        let mut a = [0u8; 32];
        a[..20].fill(0x40 + n);
        state.set_balance(&a, GAS);
        crate::native::payout_gates::approve_grantee_for_test(
            state,
            &a,
            crate::governance::GranteeClass::Developer,
        );
        state.set_storage(
            &SYSTEM_ADDRESS,
            identity_wallet_index_key(&a).as_bytes(),
            human(n).into_bytes(),
        );
        a.to_vec()
    }

    fn root(n: u8) -> SeatKeyRoot {
        SeatKeyRoot::Device {
            credential_id: format!("{n:02x}{n:02x}"),
        }
    }

    fn seat_directly(
        state: &mut StateAdapter,
        addr: &[u8],
        n: u8,
        role: GuardianRole,
        term_ends_ms: i64,
    ) {
        let seat = GuardianSeat {
            did: human(n),
            role,
            term_ends_ms,
            key_root: root(n),
        };
        write_seat(state, addr, Some(&seat), &mut Vec::new());
    }

    fn set_param(state: &mut StateAdapter, key: &str, value: u64) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(key).as_bytes(),
            value.to_le_bytes().to_vec(),
        );
    }

    fn grant_to(recipient: &[u8]) -> ProposalAction {
        ProposalAction::TreasuryGrant {
            recipient: tenzro_types::primitives::Address::from_bytes(recipient).unwrap(),
            amount: 1,
            memo: "grant".into(),
            category: "development".into(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        }
    }

    /// Propose, vote and queue `action` from `voter` starting at `t0`;
    /// returns the proposal id and the time its timelock ends.
    async fn queue(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
        voter: &[u8],
        action: &ProposalAction,
        t0: i64,
    ) -> (Vec<u8>, i64) {
        let created = executor
            .execute_transaction(
                &tx(
                    voter,
                    with(
                        SELECTOR_GOVERNANCE_PROPOSE,
                        &serde_json::to_vec(action).unwrap(),
                    ),
                    t0,
                ),
                state,
            )
            .await
            .expect("propose");
        let id = created.output.clone();
        executor
            .execute_transaction(&tx(voter, test_vote_data(&id, true, voter), t0 + 10), state)
            .await
            .expect("vote");
        let track = action.track();
        let after = t0 + track.voting_period_ms(&crate::governance::GovernanceRules::GENESIS) + 1;
        executor
            .execute_transaction(
                &tx(voter, with(SELECTOR_GOVERNANCE_EXECUTE, &id), after),
                state,
            )
            .await
            .expect("queue");
        (
            id,
            after + track.timelock_ms(&crate::governance::GovernanceRules::GENESIS) + 1,
        )
    }

    async fn enact(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
        voter: &[u8],
        id: &[u8],
        at: i64,
    ) -> crate::error::Result<ExecutionResult> {
        executor
            .execute_transaction(&tx(voter, with(SELECTOR_GOVERNANCE_EXECUTE, id), at), state)
            .await
    }

    fn param_change(value: u64) -> ProposalAction {
        ProposalAction::ParameterChange {
            key: "agent.remote_grant_budget_divisor".into(),
            value,
            memo: "test".into(),
        }
    }

    async fn veto(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
        who: &[u8],
        id: &[u8],
        at: i64,
    ) -> crate::error::Result<ExecutionResult> {
        executor
            .execute_transaction(
                &tx(
                    who,
                    with(SELECTOR_GOVERNANCE_VETO, hex::encode(id).as_bytes()),
                    at,
                ),
                state,
            )
            .await
    }

    fn topic(r: &ExecutionResult) -> Vec<u8> {
        r.logs[0].topics[0].clone()
    }

    #[tokio::test]
    async fn guardians_are_seated_by_proposal_and_veto_m_of_n() {
        let (executor, mut state, voter) = setup();
        let g1 = guardian_account(&mut state, 1);
        let g2 = guardian_account(&mut state, 2);
        let mut t = 0;
        for (g, n) in [(&g1, 1u8), (&g2, 2u8)] {
            let action = ProposalAction::SetGuardian {
                address: tenzro_types::primitives::Address::from_bytes(g).unwrap(),
                did: human(n),
                role: GuardianRole::Governance,
                term_ends_ms: 300 * DAY,
                key_root: root(n),
                memo: "seat".into(),
            };
            let (id, ready) = queue(&executor, &mut state, &voter, &action, t).await;
            let r = enact(&executor, &mut state, &voter, &id, ready)
                .await
                .expect("seat enacts");
            assert!(r.logs.iter().any(|l| l.topics[0] == b"GuardianSeated"));
            t = ready + 1;
        }
        assert_eq!(active_role(&state, &g1, t), Some(GuardianRole::Governance));

        let (id, ready) = queue(&executor, &mut state, &voter, &param_change(4), t).await;
        let first = veto(&executor, &mut state, &g1, &id, ready - 2)
            .await
            .unwrap();
        assert_eq!(
            topic(&first),
            b"ProposalVetoSignalled",
            "one of two guardians does not veto"
        );
        assert!(
            veto(&executor, &mut state, &g1, &id, ready - 2)
                .await
                .is_err(),
            "a guardian signals once"
        );
        let second = veto(&executor, &mut state, &g2, &id, ready - 1)
            .await
            .unwrap();
        assert_eq!(topic(&second), b"ProposalVetoed");
        assert!(
            enact(&executor, &mut state, &voter, &id, ready)
                .await
                .is_err(),
            "a vetoed proposal never enacts"
        );
    }

    #[tokio::test]
    async fn an_unseated_or_expired_guardian_cannot_veto() {
        let (executor, mut state, voter) = setup();
        let g1 = guardian_account(&mut state, 1);
        let stranger = guardian_account(&mut state, 9);
        let (id, ready) = queue(&executor, &mut state, &voter, &param_change(4), 0).await;
        seat_directly(&mut state, &g1, 1, GuardianRole::Governance, ready - 10);
        let err = veto(&executor, &mut state, &stranger, &id, ready - 20)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no guardian role"), "{err}");
        let err = veto(&executor, &mut state, &g1, &id, ready - 5)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no guardian role"),
            "an expired seat holds no power: {err}"
        );
    }

    #[test]
    fn a_guardian_must_be_human() {
        let action = ProposalAction::SetGuardian {
            address: tenzro_types::primitives::Address::new([4u8; 32]),
            did: "did:tenzro:agent:abc".into(),
            role: GuardianRole::Protocol,
            term_ends_ms: DAY,
            key_root: root(4),
            memo: String::new(),
        };
        assert!(action.validate().is_err());
        assert!(
            crate::governance::check_guardian_term("did:tenzro:machine:x", DAY, 0, DAY as u64)
                .is_err()
        );
        assert!(
            crate::governance::check_guardian_term(&human(1), DAY + 1, 0, DAY as u64).is_err(),
            "over the max term"
        );
        assert!(crate::governance::check_guardian_term(&human(1), DAY, 0, DAY as u64).is_ok());
    }

    async fn pause(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
        who: &[u8],
        want: bool,
        at: i64,
    ) -> crate::error::Result<ExecutionResult> {
        executor
            .execute_transaction(
                &tx(who, with(SELECTOR_GOVERNANCE_PAUSE, &[u8::from(want)]), at),
                state,
            )
            .await
    }

    #[tokio::test]
    async fn a_pause_needs_m_guardians_and_lifts_by_itself() {
        let (executor, mut state, voter) = setup();
        let p1 = guardian_account(&mut state, 1);
        let p2 = guardian_account(&mut state, 2);
        let (id, ready) = queue(&executor, &mut state, &voter, &param_change(4), 0).await;
        for (g, n) in [(&p1, 1u8), (&p2, 2u8)] {
            seat_directly(&mut state, g, n, GuardianRole::Protocol, ready + 400 * DAY);
        }

        let first = pause(&executor, &mut state, &p1, true, ready)
            .await
            .unwrap();
        assert_eq!(topic(&first), b"GuardianPauseSignalled");
        assert!(
            !is_paused(&state, PauseScope::Enactment, ready),
            "m-1 signers do not pause"
        );
        let second = pause(&executor, &mut state, &p2, true, ready + 1)
            .await
            .unwrap();
        assert_eq!(topic(&second), b"GovernancePaused");
        assert!(is_paused(&state, PauseScope::Enactment, ready + 1));
        assert!(
            enact(&executor, &mut state, &voter, &id, ready + 2)
                .await
                .is_err(),
            "paused enactment"
        );

        let max = crate::governance::DEFAULT_MAX_PAUSE_MS as i64;
        let lifted = ready + 1 + max;
        assert!(
            !is_paused(&state, PauseScope::Enactment, lifted),
            "a pause expires with no action"
        );
        // A new pause inside the cool-off is refused.
        assert!(
            pause(&executor, &mut state, &p1, true, lifted + 1)
                .await
                .is_err()
        );
        enact(&executor, &mut state, &voter, &id, lifted + 1)
            .await
            .expect("enacts once the pause lapsed");
    }

    /// Every guardian power stops something and moves nothing: whatever role
    /// acts, the only state it writes is governance bookkeeping and its own
    /// gas.
    #[tokio::test]
    async fn guardian_powers_never_move_funds_or_set_parameters() {
        for role in [
            GuardianRole::Protocol,
            GuardianRole::Governance,
            GuardianRole::Steward,
        ] {
            let (executor, mut state, voter) = setup();
            set_param(
                &mut state,
                crate::governance::STEWARD_SUNSET_PARAM,
                1_000 * DAY as u64,
            );
            let g1 = guardian_account(&mut state, 1);
            let g2 = guardian_account(&mut state, 2);
            let action = if role == GuardianRole::Steward {
                grant_to(&g1)
            } else {
                param_change(4)
            };
            let (id, ready) = queue(&executor, &mut state, &voter, &action, 0).await;
            seat_directly(&mut state, &g1, 1, role, ready + DAY);
            seat_directly(&mut state, &g2, 2, role, ready + DAY);
            let mut results = Vec::new();
            for g in [&g1, &g2] {
                let r = match role {
                    GuardianRole::Protocol => {
                        pause(&executor, &mut state, g, true, ready - 5).await
                    }
                    GuardianRole::Governance | GuardianRole::Steward => {
                        veto(&executor, &mut state, g, &id, ready - 5).await
                    }
                };
                results.push(r.expect("the role's own power"));
            }
            for r in &results {
                for c in &r.state_changes {
                    let key = String::from_utf8_lossy(&c.key);
                    assert!(
                        key.starts_with("governance_") && !key.starts_with("governance_param"),
                        "guardian action wrote {key}"
                    );
                }
            }
            // The other role's power stays out of reach.
            let other = match role {
                GuardianRole::Protocol => veto(&executor, &mut state, &g1, &id, ready - 4).await,
                GuardianRole::Governance => {
                    pause(&executor, &mut state, &g1, true, ready - 4).await
                }
                // A steward cannot reach a network decision at all.
                GuardianRole::Steward => {
                    let (other, _) =
                        queue(&executor, &mut state, &voter, &param_change(5), ready).await;
                    veto(&executor, &mut state, &g1, &other, ready + 10).await
                }
            };
            assert!(other.is_err());
        }
    }

    #[tokio::test]
    async fn stewards_veto_treasury_proposals_only() {
        let (executor, mut state, voter) = setup();
        set_param(
            &mut state,
            crate::governance::STEWARD_SUNSET_PARAM,
            1_000 * DAY as u64,
        );
        let s1 = guardian_account(&mut state, 1);
        let s2 = guardian_account(&mut state, 2);
        let (grant, ready) = queue(&executor, &mut state, &voter, &grant_to(&s1), 0).await;
        let (network, _) = queue(&executor, &mut state, &voter, &param_change(4), 0).await;
        for (g, n) in [(&s1, 1u8), (&s2, 2u8)] {
            seat_directly(&mut state, g, n, GuardianRole::Steward, 500 * DAY);
        }
        let err = veto(&executor, &mut state, &s1, &network, ready - 3)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("treasury or expedited"), "{err}");
        let first = veto(&executor, &mut state, &s1, &grant, ready - 2)
            .await
            .unwrap();
        assert_eq!(
            topic(&first),
            b"ProposalVetoSignalled",
            "one steward alone does not veto"
        );
        let second = veto(&executor, &mut state, &s2, &grant, ready - 1)
            .await
            .unwrap();
        assert_eq!(topic(&second), b"ProposalVetoed");
        assert!(
            enact(&executor, &mut state, &voter, &grant, ready)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_steward_hold_stops_treasury_enactment_only_and_lifts_by_itself() {
        let (executor, mut state, voter) = setup();
        set_param(
            &mut state,
            crate::governance::STEWARD_SUNSET_PARAM,
            1_000 * DAY as u64,
        );
        let s1 = guardian_account(&mut state, 1);
        let s2 = guardian_account(&mut state, 2);
        let (grant, ready) = queue(&executor, &mut state, &voter, &grant_to(&s1), 0).await;
        let (network, _) = queue(&executor, &mut state, &voter, &param_change(4), 0).await;
        for (g, n) in [(&s1, 1u8), (&s2, 2u8)] {
            seat_directly(&mut state, g, n, GuardianRole::Steward, 500 * DAY);
        }
        pause(&executor, &mut state, &s1, true, ready - 2)
            .await
            .unwrap();
        let held = pause(&executor, &mut state, &s2, true, ready - 1)
            .await
            .unwrap();
        assert_eq!(topic(&held), b"TreasuryHeld");
        assert!(is_paused(&state, PauseScope::Treasury, ready));
        assert!(
            !is_paused(&state, PauseScope::Enactment, ready),
            "a steward hold is not a network pause"
        );
        let err = enact(&executor, &mut state, &voter, &grant, ready)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("held by Foundation stewards"),
            "{err}"
        );
        enact(&executor, &mut state, &voter, &network, ready)
            .await
            .expect("network decisions are not held");
        let lifted = ready - 1 + crate::governance::DEFAULT_MAX_PAUSE_MS as i64;
        assert!(
            !is_paused(&state, PauseScope::Treasury, lifted),
            "the hold lifts with no action"
        );
    }

    #[tokio::test]
    async fn stewardship_ends_at_the_sunset_which_only_moves_earlier() {
        let (executor, mut state, voter) = setup();
        let sunset = 200 * DAY;
        set_param(
            &mut state,
            crate::governance::STEWARD_SUNSET_PARAM,
            sunset as u64,
        );
        let s1 = guardian_account(&mut state, 1);
        seat_directly(&mut state, &s1, 1, GuardianRole::Steward, 300 * DAY);
        assert_eq!(
            active_role(&state, &s1, sunset - 1),
            Some(GuardianRole::Steward)
        );
        assert_eq!(
            active_role(&state, &s1, sunset),
            None,
            "no steward power after the sunset"
        );

        let extend = ProposalAction::ParameterChange {
            key: crate::governance::STEWARD_SUNSET_PARAM.into(),
            value: sunset as u64 + 1,
            memo: "extend".into(),
        };
        let proposed = executor
            .execute_transaction(
                &tx(
                    &voter,
                    with(
                        SELECTOR_GOVERNANCE_PROPOSE,
                        &serde_json::to_vec(&extend).unwrap(),
                    ),
                    0,
                ),
                &mut state,
            )
            .await;
        assert!(proposed.is_err(), "the sunset never moves later");
        let shorten = ProposalAction::ParameterChange {
            key: crate::governance::STEWARD_SUNSET_PARAM.into(),
            value: 10 * DAY as u64,
            memo: "end early".into(),
        };
        let (id, ready) = queue(&executor, &mut state, &voter, &shorten, 0).await;
        enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("governance ends stewardship early");
        // It applies from the next epoch.
        crate::native::begin_block_params(&mut state, 1).unwrap();
        assert_eq!(steward_sunset_ms(&state), 10 * DAY);
        assert_eq!(active_role(&state, &s1, 10 * DAY), None);
        assert!(
            crate::governance::steward_change_allowed(
                crate::governance::STEWARD_MAX_SEATS_PARAM,
                5,
                6
            )
            .is_err()
        );
        assert!(
            crate::governance::steward_change_allowed(
                crate::governance::STEWARD_MAX_SEATS_PARAM,
                5,
                0
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn loosening_a_treasury_guard_moves_one_step_and_waits_the_guard_grace() {
        let (executor, mut state, voter) = setup();
        let key = crate::governance::MAX_PERIOD_OUTFLOW_PARAM;
        let change = |value: u64| ProposalAction::ParameterChange {
            key: key.into(),
            value,
            memo: "treasury outflow".into(),
        };
        let start = crate::governance::MAX_PERIOD_OUTFLOW_BPS;
        // More than one raise step is refused at submission.
        let too_far = executor
            .execute_transaction(
                &tx(
                    &voter,
                    with(
                        SELECTOR_GOVERNANCE_PROPOSE,
                        &serde_json::to_vec(&change(start * 2 + 1)).unwrap(),
                    ),
                    0,
                ),
                &mut state,
            )
            .await;
        assert!(too_far.is_err(), "a guard loosens one step at a time");
        let (id, ready) = queue(&executor, &mut state, &voter, &change(start * 2), 0).await;
        enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("one step is allowed");
        let grace = crate::governance::DEFAULT_GUARD_LOOSENING_GRACE_EPOCHS;
        crate::native::begin_block_params(&mut state, 1).unwrap();
        crate::native::begin_block_params(&mut state, grace).unwrap();
        assert_eq!(network_param(&state, key), start, "still waiting");
        crate::native::begin_block_params(&mut state, grace + 1).unwrap();
        assert_eq!(network_param(&state, key), start * 2);
        // Tightening it back waits only the tightening grace.
        let (id, ready) = queue(&executor, &mut state, &voter, &change(start), ready).await;
        enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("tightening");
        let tightening = crate::governance::DEFAULT_TIGHTENING_GRACE_EPOCHS;
        crate::native::begin_block_params(&mut state, grace + 2 + tightening).unwrap();
        assert_eq!(network_param(&state, key), start);
    }

    #[tokio::test]
    async fn raising_issuance_waits_the_guard_grace_and_cutting_it_does_not() {
        let (executor, mut state, voter) = setup();
        let key = crate::native::rewards::MINT_BASE_PARAM;
        let change = |value: u64| ProposalAction::ParameterChange {
            key: key.into(),
            value,
            memo: "issuance".into(),
        };
        let start = network_param(&state, key);
        let (id, ready) = queue(&executor, &mut state, &voter, &change(start * 2), 0).await;
        enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("one step is allowed");
        let grace = crate::governance::DEFAULT_GUARD_LOOSENING_GRACE_EPOCHS;
        crate::native::begin_block_params(&mut state, grace).unwrap();
        assert_eq!(network_param(&state, key), start, "a raise waits the grace");
        crate::native::begin_block_params(&mut state, grace + 1).unwrap();
        assert_eq!(network_param(&state, key), start * 2);
        let (id, ready) = queue(&executor, &mut state, &voter, &change(start), ready).await;
        enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("a cut");
        crate::native::begin_block_params(&mut state, grace + 2).unwrap();
        assert_eq!(
            network_param(&state, key),
            start,
            "a cut applies next epoch"
        );
    }

    #[tokio::test]
    async fn back_to_back_loosenings_move_a_guard_one_step_per_grace() {
        let (executor, mut state, voter) = setup();
        let key = crate::native::rewards::MINT_BASE_PARAM;
        let change = |value: u64| ProposalAction::ParameterChange {
            key: key.into(),
            value,
            memo: "issuance".into(),
        };
        let start = network_param(&state, key);
        let (id, ready) = queue(&executor, &mut state, &voter, &change(start * 2), 0).await;
        enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("one step is allowed");
        let refused = executor
            .execute_transaction(
                &tx(
                    &voter,
                    with(
                        SELECTOR_GOVERNANCE_PROPOSE,
                        &serde_json::to_vec(&change(start * 4)).unwrap(),
                    ),
                    ready,
                ),
                &mut state,
            )
            .await;
        assert!(
            refused.is_err(),
            "a doubling still in its grace is no base for another"
        );
        // The same step again is still allowed.
        queue(&executor, &mut state, &voter, &change(start * 2), ready).await;
    }

    #[tokio::test]
    async fn a_parameter_that_guards_nothing_still_applies_next_epoch() {
        let (executor, mut state, voter) = setup();
        let (id, ready) = queue(&executor, &mut state, &voter, &param_change(4), 0).await;
        enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("enacted");
        crate::native::begin_block_params(&mut state, 1).unwrap();
        assert_eq!(
            network_param(&state, "agent.remote_grant_budget_divisor"),
            4
        );
    }

    #[test]
    fn a_recovery_cannot_draw_on_the_treasury_or_pay_a_person() {
        let treasury = derive_treasury_address();
        assert!(!crate::native::is_recoverable_source(treasury.as_bytes()));
        let person = tenzro_types::primitives::Address::new([0x44; 32]);
        let draw = ProposalAction::RecoverUnownedFunds {
            from: treasury,
            to: person,
            amount: 200,
            memo: "unattributed balance".into(),
        };
        assert!(draw.validate().is_err(), "the treasury is owned");
        let vault = crate::native::vault_recovery_address();
        let pay = ProposalAction::RecoverUnownedFunds {
            from: vault,
            to: person,
            amount: 200,
            memo: "unattributed balance".into(),
        };
        assert!(
            pay.validate().is_err(),
            "unowned funds return to the treasury"
        );
        let back = ProposalAction::RecoverUnownedFunds {
            from: vault,
            to: treasury,
            amount: 200,
            memo: "unattributed balance".into(),
        };
        back.validate()
            .expect("the vault surplus may return to the treasury");
    }

    #[test]
    fn steward_seats_are_independent_capped_and_end_by_the_sunset() {
        let mut state = StateAdapter::new();
        set_param(
            &mut state,
            crate::governance::STEWARD_SUNSET_PARAM,
            100 * DAY as u64,
        );
        set_param(&mut state, crate::governance::STEWARD_MAX_SEATS_PARAM, 2);
        let accounts: Vec<Vec<u8>> = (1..=3).map(|n| guardian_account(&mut state, n)).collect();
        seat_directly(&mut state, &accounts[0], 1, GuardianRole::Steward, 50 * DAY);
        let check = |state: &StateAdapter, i: usize, n: u8, term: i64, r: SeatKeyRoot| {
            check_seat(
                state,
                &accounts[i],
                &human(n),
                GuardianRole::Steward,
                term,
                &r,
                0,
            )
        };
        let err = check(&state, 1, 2, 50 * DAY, root(1)).unwrap_err();
        assert!(err.contains("same root"), "{err}");
        let err = check(&state, 1, 2, 101 * DAY, root(2)).unwrap_err();
        assert!(err.contains("sunset"), "{err}");
        check(&state, 1, 2, 50 * DAY, root(2)).expect("an independent steward fits");
        seat_directly(&mut state, &accounts[1], 2, GuardianRole::Steward, 50 * DAY);
        let err = check(&state, 2, 3, 50 * DAY, root(3)).unwrap_err();
        assert!(err.contains("cap"), "{err}");
        // The same root may serve a different role.
        check_seat(
            &state,
            &accounts[2],
            &human(3),
            GuardianRole::Protocol,
            50 * DAY,
            &root(1),
            0,
        )
        .expect("roots are compared within a role");
        assert_eq!(seats(&state).len(), 2);
    }

    fn treasury_chains() -> Vec<(&'static str, tenzro_types::omni_account::AccountDeployment)> {
        use tenzro_types::omni_account::AccountDeployment as D;
        vec![
            (
                "eip155:8453",
                D::Eip155 {
                    factory: [0x42; 20],
                    init_code_hash: [0x24; 32],
                },
            ),
            (
                "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                D::Solana {
                    program_id: [7; 32],
                },
            ),
            ("sui:mainnet", D::Sui { registry: [3; 32] }),
            ("aptos:1", D::Aptos { creator: [4; 32] }),
            (
                "stellar:pubnet",
                D::Stellar {
                    network_passphrase: "Public Global Stellar Network ; September 2015".into(),
                    factory: [5; 32],
                },
            ),
            (
                "cosmos:osmosis-1",
                D::Cosmos {
                    hrp: "osmo".into(),
                    factory: vec![6; 32],
                    code_checksum: [8; 32],
                },
            ),
            (
                "tvm:-239",
                D::Tvm {
                    workchain: 0,
                    code_hash: [9; 32],
                    code_depth: 1,
                },
            ),
        ]
    }

    fn install_chains(state: &mut StateAdapter) {
        for (caip2, deployment) in treasury_chains() {
            let chain = tenzro_types::omni_account::AgentAccountChain {
                caip2: caip2.into(),
                deployment,
                open: true,
                report_route: None,
            };
            let mut changes = Vec::new();
            funding::write_json(
                state,
                &tenzro_types::omni_account::AgentAccountChain::storage_key(caip2),
                &chain,
                &mut changes,
            )
            .unwrap();
            treasury_remote::index_chain(state, caip2, &mut changes).unwrap();
        }
    }

    fn remote_action(caip2: &str, memo: &str) -> ProposalAction {
        ProposalAction::TreasuryRemoteAction {
            caip2: caip2.into(),
            caip19: format!("{caip2}/slip44:1"),
            remote: tenzro_types::remote_grant::RemoteAction {
                target: vec![0xAB; 20],
                selector: vec![0xa9, 0x05, 0x9c, 0xbb],
                amount: 0,
                relay_refund: 0,
                data: vec![1, 2, 3],
            },
            ttl_ms: DAY as u64,
            payout: None,
            memo: memo.into(),
        }
    }

    #[test]
    fn the_treasury_has_a_keyless_account_on_every_chain_from_the_agent_account_code() {
        let mut state = StateAdapter::new();
        install_chains(&mut state);
        let accounts = treasury_remote::treasury_accounts(&state);
        assert_eq!(accounts.len(), treasury_chains().len());
        for (caip2, deployment) in treasury_chains() {
            let expected = tenzro_types::omni_account::omni_address(
                treasury_remote::TREASURY_DID,
                caip2,
                &deployment,
            )
            .unwrap();
            assert_eq!(
                treasury_remote::treasury_account(&state, caip2).unwrap(),
                expected,
                "{caip2}"
            );
        }
        assert!(
            treasury_remote::treasury_account(&state, "bip122:000000000019d6689c085ae165831e93")
                .is_err()
        );
        let btc = ProposalAction::TreasuryRemoteAction {
            caip2: "bip122:000000000019d6689c085ae165831e93".into(),
            caip19: "bip122:000000000019d6689c085ae165831e93/slip44:0".into(),
            remote: tenzro_types::remote_grant::RemoteAction {
                target: vec![1],
                selector: vec![],
                amount: 1,
                relay_refund: 0,
                data: vec![],
            },
            ttl_ms: DAY as u64,
            payout: None,
            memo: String::new(),
        };
        let err = btc.validate().unwrap_err().to_string();
        assert!(err.contains("deposit route"), "{err}");
    }

    #[tokio::test]
    async fn treasury_funds_on_another_chain_move_only_by_an_enacted_proposal_after_the_steward_window()
     {
        for (caip2, _) in treasury_chains() {
            let (executor, mut state, voter) = setup();
            install_chains(&mut state);
            set_param(
                &mut state,
                crate::governance::STEWARD_SUNSET_PARAM,
                1_000 * DAY as u64,
            );
            let s1 = guardian_account(&mut state, 1);
            let s2 = guardian_account(&mut state, 2);
            for (g, n) in [(&s1, 1u8), (&s2, 2u8)] {
                seat_directly(&mut state, g, n, GuardianRole::Steward, 500 * DAY);
            }

            // Vetoed inside the timelock: no grant is ever written.
            let (vetoed, ready) = queue(
                &executor,
                &mut state,
                &voter,
                &remote_action(caip2, "vetoed"),
                0,
            )
            .await;
            veto(&executor, &mut state, &s1, &vetoed, ready - 2)
                .await
                .unwrap();
            veto(&executor, &mut state, &s2, &vetoed, ready - 1)
                .await
                .unwrap();
            assert!(
                enact(&executor, &mut state, &voter, &vetoed, ready)
                    .await
                    .is_err()
            );
            assert!(
                remote_grant::read_grant(&state, treasury_remote::TREASURY_DID, caip2).is_none(),
                "{caip2}"
            );

            // Not vetoed: enactment writes the one exact, keyless grant.
            let (id, ready) = queue(
                &executor,
                &mut state,
                &voter,
                &remote_action(caip2, "pay"),
                ready + 1,
            )
            .await;
            assert!(
                enact(&executor, &mut state, &voter, &id, ready - 2)
                    .await
                    .is_err(),
                "not before the timelock ends"
            );
            enact(&executor, &mut state, &voter, &id, ready)
                .await
                .expect("enacts");
            let g = remote_grant::read_grant(&state, treasury_remote::TREASURY_DID, caip2).unwrap();
            let ProposalAction::TreasuryRemoteAction { remote: action, .. } =
                remote_action(caip2, "pay")
            else {
                unreachable!()
            };
            assert!(g.is_exact());
            assert_eq!(
                g.payload_hash,
                tenzro_types::remote_grant::payload_hash(&action)
            );
            assert_eq!(g.keys_root, [0u8; 32], "no key can act for the treasury");
            assert_eq!(g.budget, 0);
            let account = treasury_remote::treasury_account(&state, caip2).unwrap();
            assert_eq!(g.account, account.account_word(), "{caip2}");
            assert_eq!(g.seq, 1);
        }
    }

    /// Admission needing approval, as the public genesis sets it.
    fn require_approval(state: &mut StateAdapter) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(VALIDATOR_ADMISSION_APPROVAL_PARAM).as_bytes(),
            1u64.to_le_bytes().to_vec(),
        );
    }

    /// What a validator registration from `who` at `at` is refused with.
    async fn registration_refusal(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
        who: &[u8],
        at: i64,
    ) -> String {
        match executor
            .execute_transaction(
                &tx(who, with(SELECTOR_VALIDATOR_REGISTER, b"{}"), at),
                state,
            )
            .await
        {
            Ok(r) => String::from_utf8_lossy(&r.output).into_owned(),
            Err(e) => e.to_string(),
        }
    }

    #[tokio::test]
    async fn only_an_approved_account_registers_while_admission_needs_approval() {
        let (executor, mut state, voter) = setup();
        let mut candidate = vec![0u8; 32];
        candidate[..20].fill(0x55);
        state.set_balance(&candidate, GAS);
        require_approval(&mut state);
        let refused = registration_refusal(&executor, &mut state, &candidate, 0).await;
        assert!(
            refused.contains(crate::validator_admission::REFUSAL_CODE),
            "{refused}"
        );

        let approve = |approve: bool| ProposalAction::ApproveValidators {
            accounts: vec![tenzro_types::primitives::Address::from_bytes(&candidate).unwrap()],
            approve,
            memo: "vetted operator".into(),
        };
        let (id, ready) = queue(&executor, &mut state, &voter, &approve(true), 1).await;
        let r = enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("approval enacts");
        assert!(r.logs.iter().any(|l| l.topics[0] == b"ValidatorsApproved"));
        assert!(validator_approved(&state, &candidate));
        // Past the gate: what refuses it now is the empty registration.
        let next = registration_refusal(&executor, &mut state, &candidate, ready + 1).await;
        assert!(
            !next.contains(crate::validator_admission::REFUSAL_CODE),
            "{next}"
        );

        let (id, ready) = queue(&executor, &mut state, &voter, &approve(false), ready + 2).await;
        enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("withdrawal enacts");
        assert!(!validator_approved(&state, &candidate));
        let again = registration_refusal(&executor, &mut state, &candidate, ready + 1).await;
        assert!(
            again.contains(crate::validator_admission::REFUSAL_CODE),
            "{again}"
        );
    }

    #[tokio::test]
    async fn open_admission_needs_no_approval() {
        let (executor, mut state, voter) = setup();
        let mut candidate = vec![0u8; 32];
        candidate[..20].fill(0x56);
        state.set_balance(&candidate, GAS);
        require_approval(&mut state);
        let open = ProposalAction::ParameterChange {
            key: VALIDATOR_ADMISSION_APPROVAL_PARAM.into(),
            value: 0,
            memo: "admission opens".into(),
        };
        let (id, ready) = queue(&executor, &mut state, &voter, &open, 0).await;
        enact(&executor, &mut state, &voter, &id, ready)
            .await
            .expect("opening enacts");
        // A parameter change takes effect at the next epoch boundary.
        let due = pending_param(&state, VALIDATOR_ADMISSION_APPROVAL_PARAM)
            .expect("scheduled")
            .activates_epoch;
        begin_block_params(&mut state, due).unwrap();
        assert_eq!(network_param(&state, VALIDATOR_ADMISSION_APPROVAL_PARAM), 0);
        let refused = registration_refusal(&executor, &mut state, &candidate, ready + 1).await;
        assert!(!refused.contains("not approved"), "{refused}");
    }

    #[test]
    fn an_approval_names_between_one_and_the_most_accounts() {
        let named = |n: usize| ProposalAction::ApproveValidators {
            accounts: (0..n)
                .map(|i| {
                    let mut a = [0u8; 32];
                    a[0] = 1;
                    a[1] = i as u8;
                    tenzro_types::primitives::Address::from_bytes(&a).unwrap()
                })
                .collect(),
            approve: true,
            memo: String::new(),
        };
        assert!(named(0).validate().is_err());
        assert!(named(1).validate().is_ok());
        assert!(
            named(crate::governance::MAX_APPROVED_VALIDATORS)
                .validate()
                .is_ok()
        );
        assert!(
            named(crate::governance::MAX_APPROVED_VALIDATORS + 1)
                .validate()
                .is_err()
        );
    }
}
