//! Funding operations in consensus state: requests filed without a balance
//! and tranched grants. The rules are in [`crate::funding`]; this module
//! reads and writes the state they apply to.

use super::*;
use crate::funding::{
    FundingOp, GrantRecord, MilestoneRecord, ParticipantKind, is_requestable, participant_kind,
    root_did,
};
use crate::governance::{GrantRelease, GrantVesting, ProposalAction, ProposalStatus};

/// Log topic: a scheduled grant's milestone reached its verifier threshold.
pub const MILESTONE_VERIFIED_TOPIC: &[u8] = b"GrantMilestoneVerified";

fn milestone_key(grant_id: &str, index: u32) -> String {
    format!("grant_milestone:{grant_id}:{index}")
}

/// `Funding(op)` — see [`FundingOp`].
pub const SELECTOR_FUNDING: [u8; 4] = [0x02, 0x00, 0x00, 0x06];

/// Gas for one funding operation, paid by the treasury.
pub const GAS_FUNDING: u64 = 80_000;

fn open_request_key(root: &str) -> String {
    format!("funding_open:{root}")
}

fn request_window_key(window: u64) -> String {
    format!("funding_window:{window}")
}

/// Storage key of a tranched grant.
pub fn grant_key(proposal_id: &str) -> String {
    format!("grant:{proposal_id}")
}

/// Key of the TPM endorsement roots governance recognises.
pub const ENDORSEMENT_ROOTS_KEY: &str = "tpm_endorsement_roots";

/// The TPM manufacturer roots (PEM) governance recognises. Genesis seeds
/// them; a policy update replaces them.
pub fn read_endorsement_roots(state: &dyn VmState) -> Vec<String> {
    read_json(state, ENDORSEMENT_ROOTS_KEY).unwrap_or_default()
}

/// Replace the recognised TPM endorsement roots, refused when one does not
/// parse as a certificate.
pub(super) fn set_endorsement_roots(
    state: &mut dyn VmState,
    roots_pem: &[String],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    for pem in roots_pem {
        tenzro_tee::x509::parse_pem_chain(pem)
            .map_err(|e| refuse(format!("an endorsement root does not parse: {e}")))?;
    }
    write_json(state, ENDORSEMENT_ROOTS_KEY, &roots_pem.to_vec(), changes)?;
    Ok(())
}

/// The TPM attestation recorded when machine `did` was admitted, checked to
/// bind the DID: its attestation key is the one the machine quotes with.
pub fn machine_attestation(
    state: &dyn VmState,
    did: &str,
) -> std::result::Result<tenzro_tee::tpm_attest::MachineAttestation, String> {
    use tenzro_tee::identity_evidence::{TPM_ATTESTATION_KEY, tpm_evidence_binds};
    let record = identity_record(state, did).ok_or_else(|| format!("{did} is not registered"))?;
    let att: tenzro_tee::tpm_attest::MachineAttestation = record
        .metadata
        .get(TPM_ATTESTATION_KEY)
        .and_then(|json| serde_json::from_str(json).ok())
        .ok_or_else(|| format!("{did} carries no TPM attestation"))?;
    if !tpm_evidence_binds(did, &record.controller_pubkey, &att) {
        return Err(format!("{did}'s TPM attestation does not bind it"));
    }
    Ok(att)
}

/// Whether machine `did` holds a TPM whose endorsement certificate, recorded
/// at admission, chains to a root governance recognises at `now_ms`.
pub fn machine_endorsed(
    state: &dyn VmState,
    did: &str,
    now_ms: i64,
) -> std::result::Result<(), String> {
    use tenzro_tee::tpm_attest::verify_endorsement;
    let att = machine_attestation(state, did)?;
    if att.evidence.ek_certificate.is_empty() {
        return Err(format!("{did}'s TPM holds no endorsement certificate"));
    }
    let roots = tenzro_tee::tpm_attest::parse_roots(&read_endorsement_roots(state))
        .map_err(|e| e.to_string())?;
    verify_endorsement(&att.evidence, &roots, (now_ms.max(0) / 1000) as u64)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Read a JSON record from `SYSTEM_ADDRESS` storage.
pub(super) fn read_json<T: serde::de::DeserializeOwned>(
    state: &dyn VmState,
    key: &str,
) -> Option<T> {
    state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// Write a JSON record, recording the change.
pub(super) fn write_json<T: serde::Serialize>(
    state: &mut dyn VmState,
    key: &str,
    value: &T,
    changes: &mut Vec<StateChange>,
) -> Result<Vec<u8>> {
    let blob =
        serde_json::to_vec(value).map_err(|e| VmError::Internal(format!("encode {key}: {e}")))?;
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        prior,
        Some(blob.clone()),
    ));
    Ok(blob)
}

/// Delete a record, recording the change. An absent record is left as it is,
/// so deleting it again writes nothing.
pub(super) fn delete_record(state: &mut dyn VmState, key: &str, changes: &mut Vec<StateChange>) {
    let Some(prior) = state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .filter(|b| !b.is_empty())
    else {
        return;
    };
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), Vec::new());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        Some(prior),
        None,
    ));
}

fn read_u64(state: &dyn VmState, key: &str) -> u64 {
    state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .and_then(|b| Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?)))
        .unwrap_or(0)
}

fn write_u64(state: &mut dyn VmState, key: &str, value: u64, changes: &mut Vec<StateChange>) {
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(
        &SYSTEM_ADDRESS,
        key.as_bytes(),
        value.to_le_bytes().to_vec(),
    );
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        prior,
        Some(value.to_le_bytes().to_vec()),
    ));
}

/// Move `amount` from `from` to `to`, recording both balance changes.
pub(super) fn move_balance(
    state: &mut dyn VmState,
    from: &[u8],
    to: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let from_balance = state.get_balance(from);
    if from_balance < amount {
        return Err(VmError::InsufficientBalance {
            required: amount,
            available: from_balance,
        });
    }
    let to_balance = state.get_balance(to);
    let new_to = to_balance
        .checked_add(amount)
        .ok_or_else(|| VmError::Internal("balance overflow".into()))?;
    state.set_balance(from, from_balance - amount);
    state.set_balance(to, new_to);
    changes.push(StateChange::new(
        from.to_vec(),
        b"balance".to_vec(),
        Some(from_balance.to_le_bytes().to_vec()),
        Some((from_balance - amount).to_le_bytes().to_vec()),
    ));
    changes.push(StateChange::new(
        to.to_vec(),
        b"balance".to_vec(),
        Some(to_balance.to_le_bytes().to_vec()),
        Some(new_to.to_le_bytes().to_vec()),
    ));
    Ok(())
}

pub(super) fn refuse(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(msg.into())
}

/// The registered identity behind `addr`, refused when there is none or it
/// has been revoked.
fn live_identity(state: &dyn VmState, addr: &[u8]) -> Result<String> {
    let did = identity_did_of(state, addr)
        .ok_or_else(|| refuse("funding needs a registered identity; this account has none"))?;
    if state
        .get_storage(&SYSTEM_ADDRESS, &identity_revocation_key(&did))
        .is_some_and(|b| !b.is_empty())
    {
        return Err(refuse(format!("identity {did} is revoked")));
    }
    Ok(did)
}

/// The on-chain registration of `did`.
pub(super) fn identity_record(
    state: &dyn VmState,
    did: &str,
) -> Option<tenzro_types::identity::RegisterIdentityPayload> {
    state
        .get_storage(&SYSTEM_ADDRESS, &identity_storage_key(did))
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// Whether a proposal still counts as an open request: voting has not
/// closed, or it passed and waits for execution.
fn is_open(proposal: &crate::governance::Proposal, now_ms: i64) -> bool {
    match proposal.status {
        ProposalStatus::Voting | ProposalStatus::Contested => now_ms < proposal.voting_ends_ms,
        ProposalStatus::Passed | ProposalStatus::Queued => true,
        _ => false,
    }
}

impl NativeExecutor {
    /// `Funding(op)`: a funding operation whose gas the treasury pays.
    pub(super) async fn execute_funding(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_FUNDING)?;
        let op: FundingOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid funding operation: {e}")))?;
        let did = live_identity(state, &tx.from)?;
        let kind = participant_kind(&did)
            .ok_or_else(|| refuse(format!("{did} is not a did:tenzro identity")))?;

        let mut changes = Vec::new();
        let mut logs = Vec::new();
        let output = match op {
            FundingOp::Request { action } => {
                self.funding_request(tx, state, &did, kind, action, &mut changes, &mut logs)?
            }
            FundingOp::ReportSettledWork { legs } => {
                super::rewards::report_settled_work(tx, state, &legs, &mut changes)?
            }
            FundingOp::ClaimRewards => {
                super::rewards::claim_rewards(tx, state, &mut changes, &mut logs)?
            }
            FundingOp::ReleaseVesting => {
                super::rewards::release_vesting(tx, state, &mut changes, &mut logs)?
            }
            FundingOp::VerifyMilestone {
                grant_id,
                index,
                evidence,
            } => verify_milestone(
                state,
                &tx.from,
                &grant_id,
                index,
                &evidence,
                deterministic_now_ms(tx),
                &mut changes,
                &mut logs,
            )?,
            FundingOp::ReleaseMilestone { grant_id, index } => release_milestone(
                state,
                &grant_id,
                index,
                deterministic_now_ms(tx),
                &mut changes,
                &mut logs,
            )?,
        };

        // The protocol pays: the treasury covers the gas, so an identity with
        // a zero balance can take part. Charged last, after every check.
        let gas_cost = tx.gas_price.saturating_mul(GAS_FUNDING as u128);
        let treasury = derive_treasury_address();
        let treasury_balance = state.get_balance(treasury.as_bytes());
        if treasury_balance < gas_cost {
            return Err(refuse(
                "the treasury cannot pay for funding operations right now",
            ));
        }
        state.set_balance(treasury.as_bytes(), treasury_balance - gas_cost);
        changes.push(StateChange::new(
            treasury.as_bytes().to_vec(),
            b"balance".to_vec(),
            Some(treasury_balance.to_le_bytes().to_vec()),
            Some((treasury_balance - gas_cost).to_le_bytes().to_vec()),
        ));
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            output,
            logs,
            changes,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn funding_request(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        did: &str,
        kind: ParticipantKind,
        action: ProposalAction,
        changes: &mut Vec<StateChange>,
        logs: &mut Vec<Log>,
    ) -> Result<Vec<u8>> {
        if !is_requestable(&action) {
            return Err(refuse(format!(
                "a {} action cannot be filed as a funding request",
                action.kind()
            )));
        }
        action.validate().map_err(|e| refuse(e.to_string()))?;
        let now_ms = deterministic_now_ms(tx);
        let root = root_did(did);

        match &action {
            ProposalAction::TreasuryGrant {
                recipient, asset, ..
            } => {
                if let Some(token_id) = asset {
                    super::stable_payout::check_grant_asset(state, token_id)?;
                }
                require_registered_recipient(state, recipient.as_bytes())?;
                super::payout_gates::require_approved_grantee(state, recipient.as_bytes())?;
                // An agent receives only into its own account, which its
                // delegation governs.
                if kind == ParticipantKind::Agent && recipient.as_bytes() != tx.from.as_slice() {
                    return Err(refuse(
                        "an agent may request a grant only to its own account",
                    ));
                }
            }
            ProposalAction::ReleaseGrantTranche {
                grant_id, index, ..
            } => {
                let grant: GrantRecord = read_json(state, &grant_key(grant_id))
                    .ok_or_else(|| refuse(format!("no tranched grant {grant_id}")))?;
                if grant.recipient.as_bytes() != tx.from.as_slice() {
                    return Err(refuse(
                        "only the grant's recipient may request its tranches",
                    ));
                }
                check_governed_release(&grant)?;
                check_next_tranche(&grant, *index)?;
            }
            _ => unreachable!("is_requestable admitted only funding actions"),
        }

        // One open request per root identity.
        let open_key = open_request_key(&root);
        if let Some(prior) = state
            .get_storage(&SYSTEM_ADDRESS, open_key.as_bytes())
            .and_then(|b| String::from_utf8(b).ok())
            && load_proposal(state, &prior).is_some_and(|p| is_open(&p, now_ms))
        {
            return Err(refuse(format!(
                "{root} already has an open funding request ({prior})"
            )));
        }

        // A network-wide cap per window.
        let window_ms = network_param(state, "funding.request_window_ms").max(1);
        let window = now_ms.max(0) as u64 / window_ms;
        let cap = network_param(state, "funding.requests_per_window");
        let filed = read_u64(state, &request_window_key(window));
        if filed >= cap {
            return Err(refuse(format!(
                "the network has taken its {cap} funding requests for this window"
            )));
        }

        let data = serde_json::to_vec(&action)
            .map_err(|e| VmError::Internal(format!("encode request: {e}")))?;
        let opened = open_proposal(state, tx, &action, &data)?;
        changes.extend(opened.state_changes);
        write_u64(state, &request_window_key(window), filed + 1, changes);
        let prior = state.get_storage(&SYSTEM_ADDRESS, open_key.as_bytes());
        state.set_storage(
            &SYSTEM_ADDRESS,
            open_key.as_bytes(),
            opened.id.clone().into_bytes(),
        );
        changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            open_key.into_bytes(),
            prior,
            Some(opened.id.clone().into_bytes()),
        ));
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"FundingRequested".to_vec()],
            [
                opened.hash.as_slice(),
                tx.from.as_slice(),
                action.kind().as_bytes(),
            ]
            .concat(),
        ));
        Ok(opened.hash.to_vec())
    }
}

/// The recipient of value must hold a registered identity.
pub(super) fn require_registered_recipient(state: &dyn VmState, recipient: &[u8]) -> Result<()> {
    let known = state
        .get_storage(
            &SYSTEM_ADDRESS,
            identity_wallet_index_key(recipient).as_bytes(),
        )
        .is_some_and(|b| !b.is_empty());
    if !known {
        return Err(refuse(format!(
            "recipient {} has no registered identity; every wallet on this network answers to one",
            hex::encode(recipient)
        )));
    }
    Ok(())
}

/// `index` must be the next unpaid tranche of `grant`.
fn check_next_tranche(grant: &GrantRecord, index: u32) -> Result<()> {
    if index as usize >= grant.tranches.len() {
        return Err(refuse(format!(
            "the grant has {} tranches; there is no tranche {index}",
            grant.tranches.len()
        )));
    }
    if index != grant.paid {
        return Err(refuse(format!(
            "tranche {} is next; tranche {index} cannot be released now",
            grant.paid
        )));
    }
    Ok(())
}

/// A grant set to scheduled release pays its tranches against verified
/// milestones; a release proposal for one is refused, so the two routes
/// never both pay the same tranche.
fn check_governed_release(grant: &GrantRecord) -> Result<()> {
    if grant.release != GrantRelease::Governed {
        return Err(refuse(
            "this grant releases its tranches against verified milestones, not by release proposal",
        ));
    }
    Ok(())
}

/// Record a verifier's attestation that tranche `index`'s milestone is met.
#[allow(clippy::too_many_arguments)]
fn verify_milestone(
    state: &mut dyn VmState,
    verifier: &[u8],
    grant_id: &str,
    index: u32,
    evidence: &str,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<Vec<u8>> {
    let grant: GrantRecord = read_json(state, &grant_key(grant_id))
        .ok_or_else(|| refuse(format!("no tranched grant {grant_id}")))?;
    let GrantRelease::Scheduled {
        verifiers,
        threshold,
    } = &grant.release
    else {
        return Err(refuse(
            "this grant releases its tranches by release proposal",
        ));
    };
    if !verifiers.iter().any(|v| v.as_bytes() == verifier) {
        return Err(refuse(
            "only a verifier the approved grant named may record its milestones",
        ));
    }
    if (index as usize) >= grant.tranches.len() || index < grant.paid {
        return Err(refuse(format!(
            "tranche {index} is not awaiting a milestone"
        )));
    }
    if evidence.trim().is_empty() || evidence.len() > crate::governance::MAX_TEXT_LEN {
        return Err(refuse("a milestone is recorded with its evidence"));
    }
    let key = milestone_key(grant_id, index);
    let mut record: MilestoneRecord = read_json(state, &key).unwrap_or_default();
    let who = hex::encode(verifier);
    if record.verifiers.contains(&who) {
        return Err(refuse("this verifier has recorded the milestone already"));
    }
    record.verifiers.push(who);
    record.evidence.push(evidence.to_string());
    if record.verified_ms.is_none() && record.verifiers.len() >= *threshold as usize {
        record.verified_ms = Some(now_ms);
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![MILESTONE_VERIFIED_TOPIC.to_vec()],
            format!("{grant_id}:{index}").into_bytes(),
        ));
    }
    write_json(state, &key, &record, changes)?;
    Ok(Vec::new())
}

/// Pay the next tranche of a scheduled grant against its verified milestone.
fn release_milestone(
    state: &mut dyn VmState,
    grant_id: &str,
    index: u32,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<Vec<u8>> {
    let mut grant: GrantRecord = read_json(state, &grant_key(grant_id))
        .ok_or_else(|| refuse(format!("no tranched grant {grant_id}")))?;
    if !matches!(grant.release, GrantRelease::Scheduled { .. }) {
        return Err(refuse(
            "this grant releases its tranches by release proposal; file one",
        ));
    }
    check_next_tranche(&grant, index)?;
    let record: MilestoneRecord = read_json(state, &milestone_key(grant_id, index))
        .ok_or_else(|| refuse(format!("tranche {index}'s milestone has not been verified")))?;
    if record.verified_ms.is_none() {
        return Err(refuse(format!(
            "tranche {index}'s milestone has {} of the verifiers it needs",
            record.verifiers.len()
        )));
    }
    super::treasury_reserve::check_grant_floor(state)?;
    let amount = grant.tranches[index as usize];
    let milestone = grant
        .milestones
        .get(index as usize)
        .cloned()
        .unwrap_or_default();
    pay_grant(
        state,
        grant_id,
        &grant.recipient,
        amount,
        &milestone,
        grant.vesting,
        grant.asset.as_deref(),
        now_ms,
        changes,
        logs,
    )?;
    grant.paid += 1;
    write_json(state, &grant_key(grant_id), &grant, changes)?;
    Ok(amount.to_le_bytes().to_vec())
}

/// Submission check for a tranche release: the grant exists and `index` is
/// its next unpaid tranche.
pub(super) fn check_release_admissible(
    state: &dyn VmState,
    grant_id: &str,
    index: u32,
) -> Result<()> {
    let grant: GrantRecord = read_json(state, &grant_key(grant_id))
        .ok_or_else(|| refuse(format!("no tranched grant {grant_id}")))?;
    super::payout_gates::require_approved_grantee(state, grant.recipient.as_bytes())?;
    check_governed_release(&grant)?;
    check_next_tranche(&grant, index)
}

/// Where the current treasury outflow period is recorded.
const OUTFLOW_PERIOD_KEY: &str = "treasury_outflow_period";

/// The treasury outflow period in progress: when it began, the treasury
/// balance then, and what has been paid out since.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct OutflowPeriod {
    pub started_ms: i64,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub opening_balance: u128,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub paid: u128,
}

/// The outflow period in progress at `now_ms`.
pub fn outflow_period(state: &dyn VmState, now_ms: i64) -> OutflowPeriod {
    let length = network_param(state, crate::governance::OUTFLOW_PERIOD_PARAM) as i64;
    match read_json::<OutflowPeriod>(state, OUTFLOW_PERIOD_KEY) {
        Some(p) if now_ms < p.started_ms.saturating_add(length) => p,
        _ => OutflowPeriod {
            started_ms: now_ms,
            opening_balance: state.get_balance(derive_treasury_address().as_bytes()),
            paid: 0,
        },
    }
}

/// Check what one enacting proposal commits out of the treasury: at most the
/// governed share of the balance. Payments count against the period cap as
/// they are made.
pub(super) fn commit_outflow(state: &dyn VmState, committed: u128) -> Result<()> {
    let cap = bps_of(
        state.get_balance(derive_treasury_address().as_bytes()),
        network_param(state, crate::governance::MAX_PROPOSAL_OUTFLOW_PARAM),
    );
    if committed > cap {
        return Err(refuse(format!(
            "a proposal may pay at most {cap} from the treasury; this one commits {committed}"
        )));
    }
    Ok(())
}

/// A treasury outflow other than a grant: check the proposal's commitment
/// and count `paid` against the outflow period.
pub(super) fn treasury_outflow(
    state: &mut dyn VmState,
    committed: u128,
    paid: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    commit_outflow(state, committed)?;
    record_outflow(state, paid, now_ms, changes)
}

/// What the treasury may still pay out in the outflow period in progress.
pub(super) fn outflow_headroom(state: &dyn VmState, now_ms: i64) -> u128 {
    let period = outflow_period(state, now_ms);
    bps_of(
        period.opening_balance,
        network_param(state, crate::governance::MAX_PERIOD_OUTFLOW_PARAM),
    )
    .saturating_sub(period.paid)
}

/// Count `amount` against the treasury's outflow period, refusing it when
/// the period's governed cap would be exceeded.
pub(super) fn record_outflow(
    state: &mut dyn VmState,
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut period = outflow_period(state, now_ms);
    let cap = bps_of(
        period.opening_balance,
        network_param(state, crate::governance::MAX_PERIOD_OUTFLOW_PARAM),
    );
    let paid = period.paid.saturating_add(amount);
    if paid > cap {
        return Err(refuse(format!(
            "the treasury may pay out {cap} in this outflow period and has paid {}; \
             {amount} more is over the cap",
            period.paid
        )));
    }
    period.paid = paid;
    write_json(state, OUTFLOW_PERIOD_KEY, &period, changes)?;
    Ok(())
}

pub(super) fn bps_of(value: u128, bps: u64) -> u128 {
    value / 10_000 * u128::from(bps) + value % 10_000 * u128::from(bps) / 10_000
}

/// Pay one grant payment from the treasury: to the recipient's balance, or
/// into a vesting schedule starting now. It counts against the treasury's
/// outflow period.
#[allow(clippy::too_many_arguments)]
fn pay_grant(
    state: &mut dyn VmState,
    proposal_id: &str,
    recipient: &Address,
    amount: u128,
    milestone: &str,
    vesting: GrantVesting,
    asset: Option<&str>,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    if let Some(token_id) = asset {
        return super::stable_payout::pay_grant_stable(
            state,
            proposal_id,
            recipient,
            token_id,
            amount,
            milestone,
            now_ms,
            changes,
            logs,
        );
    }
    super::payout_gates::record_grant_payment(
        state,
        proposal_id,
        recipient.as_bytes(),
        amount,
        milestone,
        now_ms,
        changes,
        logs,
    )?;
    record_outflow(state, amount, now_ms, changes)?;
    let treasury = derive_treasury_address();
    match vesting.schedule() {
        None => move_balance(
            state,
            treasury.as_bytes(),
            recipient.as_bytes(),
            amount,
            changes,
        ),
        Some((kind, cliff_ms, duration_ms)) => super::rewards::open_vesting(
            state,
            treasury.as_bytes(),
            *recipient,
            kind,
            amount,
            now_ms,
            cliff_ms,
            duration_ms,
            changes,
        ),
    }
}

/// Enact a grant: pay the first tranche (or the whole amount) from the
/// treasury and, when tranched, record the grant for later releases.
#[allow(clippy::too_many_arguments)]
pub(super) fn enact_grant(
    state: &mut dyn VmState,
    proposal_id: &str,
    recipient: &Address,
    amount: u128,
    tranches: &[u128],
    milestones: &[String],
    vesting: GrantVesting,
    asset: Option<&str>,
    release: &GrantRelease,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<u128> {
    super::payout_gates::require_approved_grantee(state, recipient.as_bytes())?;
    super::treasury_reserve::check_grant_floor(state)?;
    // One proposal commits at most the governed share of the treasury,
    // counting every tranche it promises.
    match asset {
        None => commit_outflow(state, amount)?,
        Some(token_id) => super::stable_payout::commit_grant(state, token_id, amount)?,
    }
    let first = tranches.first().copied().unwrap_or(amount);
    let milestone = milestones.first().map(String::as_str).unwrap_or_default();
    pay_grant(
        state,
        proposal_id,
        recipient,
        first,
        milestone,
        vesting,
        asset,
        now_ms,
        changes,
        logs,
    )?;
    if !tranches.is_empty() {
        let record = GrantRecord {
            recipient: *recipient,
            tranches: tranches.to_vec(),
            milestones: milestones.to_vec(),
            paid: 1,
            vesting,
            asset: asset.map(str::to_string),
            release: release.clone(),
        };
        write_json(state, &grant_key(proposal_id), &record, changes)?;
    }
    Ok(first)
}

/// Enact a tranche release: pay tranche `index` exactly once, vesting as the
/// grant says.
pub(super) fn enact_tranche_release(
    state: &mut dyn VmState,
    grant_id: &str,
    index: u32,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<(u128, Vec<u8>)> {
    let mut grant: GrantRecord = read_json(state, &grant_key(grant_id))
        .ok_or_else(|| refuse(format!("no tranched grant {grant_id}")))?;
    check_governed_release(&grant)?;
    check_next_tranche(&grant, index)?;
    super::treasury_reserve::check_grant_floor(state)?;
    let amount = grant.tranches[index as usize];
    let milestone = grant
        .milestones
        .get(index as usize)
        .cloned()
        .unwrap_or_default();
    pay_grant(
        state,
        grant_id,
        &grant.recipient,
        amount,
        &milestone,
        grant.vesting,
        grant.asset.as_deref(),
        now_ms,
        changes,
        logs,
    )?;
    grant.paid += 1;
    write_json(state, &grant_key(grant_id), &grant, changes)?;
    Ok((amount, grant.recipient.as_bytes().to_vec()))
}

/// A governance proposal and its running tally, as stored.
pub fn read_proposal(
    state: &dyn VmState,
    proposal_id: &str,
) -> Option<(crate::governance::Proposal, crate::governance::Tally)> {
    let proposal = load_proposal(state, proposal_id)?;
    let tally = load_tally(state, &proposal.ballot_id());
    Some((proposal, tally))
}

/// A tranched grant, as stored.
pub fn read_grant(state: &dyn VmState, grant_id: &str) -> Option<GrantRecord> {
    read_json(state, &grant_key(grant_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VmConfig;
    use crate::governance::{TIMELOCK_DELAY_MS, VOTING_PERIOD_MS};
    use crate::state_adapter::StateAdapter;
    use crate::traits::VmExecutor;

    const TREASURY_FUNDS: u128 = 1_000_000_000_000_000_000_000_000;
    const VALIDATOR_STAKE: u128 = 1_000_000 * tenzro_types::constants::ONE_TNZO;

    fn exec() -> NativeExecutor {
        NativeExecutor::new(VmConfig::default()).unwrap()
    }

    fn world() -> (NativeExecutor, StateAdapter, Vec<u8>) {
        let mut state = StateAdapter::new();
        let treasury = derive_treasury_address();
        state.set_balance(treasury.as_bytes(), TREASURY_FUNDS);
        let validator = vec![0xEE; 20];
        staking::add_bond(
            &mut state,
            &validator,
            VALIDATOR_STAKE,
            -crate::governance::MIN_BOND_AGE_MS,
        )
        .unwrap();
        super::test_operate_own_validator(&mut state, &validator);
        let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        state.set_balance(&STAKING_VAULT_ADDRESS, vault + VALIDATOR_STAKE);
        state.set_balance(&validator, 10_000_000_000_000_000_000);
        (exec(), state, validator)
    }

    /// Give `addr` the identity `did`, registered with `proof`.
    fn identity(
        state: &mut StateAdapter,
        addr: &[u8],
        did: &str,
        pubkey: Vec<u8>,
        key_type: &str,
        proof: tenzro_types::identity::RegistrationProof,
    ) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            identity_wallet_index_key(addr).as_bytes(),
            did.as_bytes().to_vec(),
        );
        let mut wallet = [0u8; 32];
        wallet[..addr.len().min(32)].copy_from_slice(&addr[..addr.len().min(32)]);
        let record = tenzro_types::identity::RegisterIdentityPayload {
            did: did.into(),
            identity_type: "machine".into(),
            display_name: String::new(),
            controller_pubkey: pubkey,
            key_type: key_type.into(),
            wallet_id: String::new(),
            wallet_address: Address::new(wallet),
            pq_verifying_key: Vec::new(),
            metadata: Default::default(),
            proof,
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            &identity_storage_key(did),
            serde_json::to_vec(&record).unwrap(),
        );
    }

    /// A 32-byte account address with 20 significant bytes.
    fn account(tag: u8) -> Vec<u8> {
        let mut a = vec![tag; 20];
        a.resize(32, 0);
        a
    }

    fn person(state: &mut StateAdapter, tag: u8, did: &str) -> Vec<u8> {
        let addr = account(tag);
        super::super::payout_gates::approve_grantee_for_test(
            state,
            &addr,
            crate::governance::GranteeClass::Developer,
        );
        identity(
            state,
            &addr,
            did,
            vec![tag; 32],
            "Ed25519",
            tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        );
        addr
    }

    fn tx(from: &[u8], data: Vec<u8>, gas: u64, at_ms: i64) -> VmTransaction {
        let mut tx = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            gas,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );
        tx.block_timestamp_ms = Some(at_ms);
        tx
    }

    fn funding_tx(from: &[u8], op: &FundingOp, at_ms: i64) -> VmTransaction {
        let mut data = SELECTOR_FUNDING.to_vec();
        data.extend_from_slice(&serde_json::to_vec(op).unwrap());
        tx(from, data, GAS_FUNDING, at_ms)
    }

    fn grant(recipient: &[u8], amount: u128, tranches: Vec<u128>) -> ProposalAction {
        let mut a = [0u8; 32];
        a[..recipient.len()].copy_from_slice(recipient);
        let milestones = (0..tranches.len().max(1))
            .map(|i| format!("milestone {i}"))
            .collect();
        ProposalAction::TreasuryGrant {
            recipient: Address::new(a),
            amount,
            memo: "tooling".into(),
            category: "development".into(),
            link: "https://example.org/proposal".into(),
            tranches,
            milestones,
            vesting: crate::governance::GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        }
    }

    async fn request(
        ex: &NativeExecutor,
        state: &mut StateAdapter,
        from: &[u8],
        action: ProposalAction,
        at_ms: i64,
    ) -> Result<Vec<u8>> {
        let r = ex
            .execute_transaction(
                &funding_tx(from, &FundingOp::Request { action }, at_ms),
                state,
            )
            .await?;
        Ok(r.output)
    }

    /// Vote yes with the validator, then execute past the timelock.
    async fn carry(
        ex: &NativeExecutor,
        state: &mut StateAdapter,
        validator: &[u8],
        id: &[u8],
        at: i64,
    ) -> Result<ExecutionResult> {
        let vote = super::test_vote_data(id, true, validator);
        ex.execute_transaction(&tx(validator, vote, 30_000, at + 10), state)
            .await?;
        let mut exe = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
        exe.extend_from_slice(id);
        let after = at + VOTING_PERIOD_MS + 1;
        ex.execute_transaction(&tx(validator, exe.clone(), 120_000, after), state)
            .await?;
        ex.execute_transaction(
            &tx(validator, exe, 120_000, after + TIMELOCK_DELAY_MS + 1),
            state,
        )
        .await
    }

    #[tokio::test]
    async fn a_zero_balance_identity_files_a_request_and_the_treasury_pays_the_gas() {
        let (ex, mut state, _) = world();
        let alice = person(&mut state, 0xA1, "did:tenzro:human:alice");
        assert_eq!(state.get_balance(&alice), 0);
        let treasury = derive_treasury_address();
        let before = state.get_balance(treasury.as_bytes());

        let id = request(&ex, &mut state, &alice, grant(&alice, 500, vec![]), 1_000)
            .await
            .expect("a zero-balance identity can file");
        assert_eq!(id.len(), 32);
        assert_eq!(state.get_balance(&alice), 0, "the requester pays nothing");
        assert_eq!(
            state.get_balance(treasury.as_bytes()),
            before - 1_000_000_000u128 * GAS_FUNDING as u128
        );
    }

    #[tokio::test]
    async fn an_account_without_an_identity_cannot_file() {
        let (ex, mut state, _) = world();
        let nobody = account(0x0B);
        let err = request(&ex, &mut state, &nobody, grant(&nobody, 5, vec![]), 1_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("registered identity"), "{err}");
    }

    #[tokio::test]
    async fn one_open_request_per_root_identity_counting_agents_against_their_controller() {
        let (ex, mut state, _) = world();
        let alice = person(&mut state, 0xA1, "did:tenzro:human:alice");
        let agent = person(&mut state, 0xA2, "did:tenzro:machine:alice:bot1");
        request(&ex, &mut state, &alice, grant(&alice, 5, vec![]), 1_000)
            .await
            .unwrap();
        let err = request(&ex, &mut state, &alice, grant(&alice, 6, vec![]), 2_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("open funding request"), "{err}");
        // An agent under the same controller counts against the controller.
        let err = request(&ex, &mut state, &agent, grant(&agent, 7, vec![]), 3_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did:tenzro:human:alice"), "{err}");
        // Once voting has closed the root may file again.
        request(
            &ex,
            &mut state,
            &alice,
            grant(&alice, 8, vec![]),
            VOTING_PERIOD_MS + 5_000,
        )
        .await
        .expect("a closed request frees the root");
    }

    #[tokio::test]
    async fn the_window_cap_bounds_what_requests_cost_the_treasury() {
        let (ex, mut state, _) = world();
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key("funding.requests_per_window").as_bytes(),
            2u64.to_le_bytes().to_vec(),
        );
        for tag in 1..=2u8 {
            let who = person(&mut state, tag, &format!("did:tenzro:human:p{tag}"));
            request(&ex, &mut state, &who, grant(&who, 1, vec![]), 1_000)
                .await
                .unwrap();
        }
        let third = person(&mut state, 3, "did:tenzro:human:p3");
        let err = request(&ex, &mut state, &third, grant(&third, 1, vec![]), 1_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("for this window"), "{err}");
    }

    #[tokio::test]
    async fn a_tranche_is_paid_only_after_its_own_approval_and_only_once() {
        let (ex, mut state, validator) = world();
        let dev = person(&mut state, 0xD1, "did:tenzro:human:dev");
        let id = request(&ex, &mut state, &dev, grant(&dev, 300, vec![100, 200]), 0)
            .await
            .unwrap();
        carry(&ex, &mut state, &validator, &id, 0)
            .await
            .expect("grant enacts");
        assert_eq!(
            state.get_balance(&dev),
            100,
            "only the first tranche at enactment"
        );

        let grant_id = hex::encode(&id);
        let release = ProposalAction::ReleaseGrantTranche {
            grant_id: grant_id.clone(),
            index: 1,
            memo: "milestone 1 shipped".into(),
        };
        let at = 10 * VOTING_PERIOD_MS;
        let rid = request(&ex, &mut state, &dev, release.clone(), at)
            .await
            .unwrap();
        assert_eq!(state.get_balance(&dev), 100, "filing pays nothing");
        carry(&ex, &mut state, &validator, &rid, at)
            .await
            .expect("release enacts");
        assert_eq!(state.get_balance(&dev), 300);

        // Paid once: a second release of the same tranche is refused.
        let err = request(&ex, &mut state, &dev, release, 20 * VOTING_PERIOD_MS)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no tranche 1") || err.to_string().contains("next"),
            "{err}"
        );
    }

    /// A contributor grant pays each tranche into its own vesting schedule,
    /// out of the treasury, not to the recipient's balance.
    #[tokio::test]
    async fn contributor_grant_tranches_vest() {
        let (ex, mut state, validator) = world();
        let dev = person(&mut state, 0xD3, "did:tenzro:human:contributor");
        let mut action = grant(&dev, 300, vec![100, 200]);
        if let ProposalAction::TreasuryGrant { vesting, .. } = &mut action {
            *vesting = GrantVesting::Contributor;
        }
        let id = request(&ex, &mut state, &dev, action, 0).await.unwrap();
        carry(&ex, &mut state, &validator, &id, 0)
            .await
            .expect("grant enacts");
        assert_eq!(state.get_balance(&dev), 0, "nothing liquid");
        let beneficiary = Address::new(dev.as_slice().try_into().unwrap());
        let schedules = crate::native::read_vesting(&state, &beneficiary).unwrap();
        assert_eq!(schedules.len(), 1);
        assert_eq!(schedules[0].total, 100);
        assert_eq!(
            schedules[0].kind,
            tenzro_token::vesting::VestingKind::Contributor
        );
        assert_eq!(
            schedules[0].cliff_ms,
            tenzro_token::vesting::CONTRIBUTOR_CLIFF_MS
        );
        assert_eq!(
            state.get_balance(tenzro_token::vesting::vesting_escrow_address().as_bytes()),
            100
        );

        let release = ProposalAction::ReleaseGrantTranche {
            grant_id: hex::encode(&id),
            index: 1,
            memo: "milestone 1 shipped".into(),
        };
        let at = 10 * VOTING_PERIOD_MS;
        let rid = request(&ex, &mut state, &dev, release, at).await.unwrap();
        carry(&ex, &mut state, &validator, &rid, at)
            .await
            .expect("release enacts");
        assert_eq!(state.get_balance(&dev), 0);
        let schedules = crate::native::read_vesting(&state, &beneficiary).unwrap();
        assert_eq!(schedules.len(), 2);
        assert_eq!(schedules[1].total, 200);
    }

    #[tokio::test]
    async fn a_rejected_request_pays_nothing() {
        let (ex, mut state, validator) = world();
        let dev = person(&mut state, 0xD2, "did:tenzro:human:dev2");
        let id = request(&ex, &mut state, &dev, grant(&dev, 50, vec![]), 0)
            .await
            .unwrap();
        let vote = super::test_vote_data(&id, false, &validator);
        ex.execute_transaction(&tx(&validator, vote, 30_000, 10), &mut state)
            .await
            .unwrap();
        let mut exe = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
        exe.extend_from_slice(&id);
        let _ = ex
            .execute_transaction(
                &tx(&validator, exe, 120_000, VOTING_PERIOD_MS + 1),
                &mut state,
            )
            .await;
        assert_eq!(state.get_balance(&dev), 0);
    }

    // ---- governed policy ----------------------------------------------------

    fn burn(base: u16, expedited: bool) -> ProposalAction {
        ProposalAction::PolicyUpdate {
            update: tenzro_types::token::PolicyUpdate::AdaptiveBurnConfigUpdate {
                base_fee_burn_bps: base,
                local_fee_burn_bps: 10_000,
            },
            memo: "supply above target".into(),
            track: if expedited {
                crate::governance::PolicyTrack::Expedited
            } else {
                crate::governance::PolicyTrack::Standard
            },
        }
    }

    async fn propose(
        ex: &NativeExecutor,
        state: &mut StateAdapter,
        validator: &[u8],
        action: &ProposalAction,
    ) -> Result<ExecutionResult> {
        let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
        data.extend_from_slice(&serde_json::to_vec(action).unwrap());
        ex.execute_transaction(&tx(validator, data, 100_000, 0), state)
            .await
    }

    #[tokio::test]
    async fn an_enacted_policy_change_is_recorded_in_consensus_and_logged_for_every_node() {
        let (ex, mut state, validator) = world();
        let created = propose(&ex, &mut state, &validator, &burn(9_000, false))
            .await
            .unwrap();
        let id = hex::encode(&created.output);
        assert_eq!(crate::native::proposal_count(&state), 1);
        assert_eq!(
            crate::native::proposal_id_at(&state, 1).as_deref(),
            Some(id.as_str())
        );
        assert!(crate::native::read_policy(&state, "adaptive_burn_config").is_none());

        let enacted = carry(&ex, &mut state, &validator, &created.output, 0)
            .await
            .unwrap();
        let log = enacted
            .logs
            .iter()
            .find(|l| l.topics[0] == crate::native::POLICY_ENACTED_TOPIC)
            .expect("policy log");
        let logged: crate::governance::PolicyEnactedLog =
            serde_json::from_slice(&log.data).unwrap();
        assert_eq!(logged.proposal_id, id);
        let stored = crate::native::read_policy(&state, "adaptive_burn_config").unwrap();
        assert_eq!(stored, logged);
        assert!(matches!(
            stored.update,
            tenzro_types::token::PolicyUpdate::AdaptiveBurnConfigUpdate {
                base_fee_burn_bps: 9_000,
                ..
            }
        ));

        // Block fee settlement now burns the voted share of the base fee and
        // credits the rest to the treasury.
        assert_eq!(crate::ledger::base_fee_burn_bps(&state), 9_000);
        let pool = crate::ledger::FEE_POOL_ADDRESS;
        let before = state.get_balance(&pool);
        state.set_balance(&pool, before + 1_000_000);
        let fees = crate::ledger::BlockFees {
            collected: 1_000_000,
            base_fee_revenue: 1_000_000,
            ..Default::default()
        };
        let settled = crate::ledger::settle_block(&mut state, &fees);
        assert_eq!(settled.burned, 900_000);
        assert_eq!(settled.to_treasury + settled.to_insurance, before + 100_000);
    }

    #[tokio::test]
    async fn a_settlement_asset_is_installed_and_disabled_only_by_a_vote() {
        use tenzro_types::settlement_asset::SettlementAsset;
        let (ex, mut state, validator) = world();
        let spec = crate::token_ledger::TokenRecord {
            name: "Dollar".into(),
            symbol: "USDC".into(),
            decimals: 6,
            total_supply: 1_000,
            creator: Vec::new(),
            max_supply: None,
            powers: tenzro_types::token_policy::PowerManifest::NONE,
            policy: tenzro_types::token_policy::TokenPolicy::default(),
            council: None,
            reserve_backing: None,
            pending: None,
        };
        let id =
            crate::token_ledger::create(&mut state, &[0x42; 32], &spec, &mut Vec::new()).unwrap();
        let entry = SettlementAsset::new(&format!("0x{}", hex::encode(id)), "USDC", "USD", 6);
        let set = |asset: SettlementAsset| ProposalAction::SetSettlementAsset {
            asset,
            memo: "permit USDC".into(),
        };

        let mut wide = entry.clone();
        wide.par_band_bps = 301;
        assert!(
            propose(&ex, &mut state, &validator, &set(wide))
                .await
                .is_err()
        );
        let mut wrong_decimals = entry.clone();
        wrong_decimals.decimals = 18;
        assert!(
            propose(&ex, &mut state, &validator, &set(wrong_decimals))
                .await
                .is_err()
        );
        let mut not_on_ledger = entry.clone();
        not_on_ledger.token_id = format!("0x{}", hex::encode([0x01; 32]));
        assert!(
            propose(&ex, &mut state, &validator, &set(not_on_ledger))
                .await
                .is_err()
        );

        let created = propose(&ex, &mut state, &validator, &set(entry.clone()))
            .await
            .unwrap();
        assert!(crate::native::settlement_asset::read_settlement_asset(&state, &id).is_none());
        carry(&ex, &mut state, &validator, &created.output, 0)
            .await
            .unwrap();
        assert_eq!(
            crate::native::settlement_asset::read_settlement_asset(&state, &id),
            Some(entry.clone())
        );

        let mut off = entry.clone();
        off.enabled = false;
        let created = propose(&ex, &mut state, &validator, &set(off.clone()))
            .await
            .unwrap();
        carry(&ex, &mut state, &validator, &created.output, 1)
            .await
            .unwrap();
        assert_eq!(
            crate::native::settlement_asset::read_settlement_asset(&state, &id),
            Some(off)
        );
    }

    #[tokio::test]
    async fn a_reserve_feed_is_installed_and_removed_only_by_a_vote() {
        let (ex, mut state, validator) = world();
        let feed = tenzro_types::ReserveFeed {
            asset_id: "tnzo:ccip/ethereum".into(),
            aggregator_address: "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01".into(),
            chain_caip2: "eip155:1".into(),
            decimals: 18,
            max_staleness_secs: 3_600,
        };
        let set = |feed: tenzro_types::ReserveFeed| ProposalAction::SetReserveFeed {
            feed,
            memo: "route reserve".into(),
        };
        let remove = ProposalAction::RemoveReserveFeed {
            asset_id: feed.asset_id.clone(),
            memo: "route closed".into(),
        };

        let mut stale = feed.clone();
        stale.max_staleness_secs = 5;
        assert!(
            propose(&ex, &mut state, &validator, &set(stale))
                .await
                .is_err()
        );
        let mut not_evm = feed.clone();
        not_evm.chain_caip2 = "solana:mainnet".into();
        assert!(
            propose(&ex, &mut state, &validator, &set(not_evm))
                .await
                .is_err()
        );
        assert!(
            propose(&ex, &mut state, &validator, &remove).await.is_err(),
            "nothing to remove yet"
        );

        let created = propose(&ex, &mut state, &validator, &set(feed.clone()))
            .await
            .unwrap();
        assert!(crate::native::economy::read_reserve_feed(&state, &feed.asset_id).is_none());
        carry(&ex, &mut state, &validator, &created.output, 0)
            .await
            .unwrap();
        let installed = crate::native::economy::read_reserve_feed(&state, &feed.asset_id).unwrap();
        assert_eq!(
            installed.aggregator_address,
            "0xabcdef0123456789abcdef0123456789abcdef01"
        );
        assert_eq!(installed.max_staleness_secs, 3_600);

        let created = propose(&ex, &mut state, &validator, &remove).await.unwrap();
        carry(&ex, &mut state, &validator, &created.output, 1)
            .await
            .unwrap();
        assert!(crate::native::economy::read_reserve_feed(&state, &feed.asset_id).is_none());
    }

    #[tokio::test]
    async fn an_expedited_burn_change_enacts_before_the_standard_window_closes() {
        use crate::governance::{
            EXPEDITED_TIMELOCK_DELAY_MS, EXPEDITED_VOTING_PERIOD_MS, ProposalTrack,
        };
        let (ex, mut state, validator) = world();
        let created = propose(&ex, &mut state, &validator, &burn(9_500, true))
            .await
            .unwrap();
        let id = hex::encode(&created.output);
        let (proposal, _) = read_proposal(&state, &id).unwrap();
        assert_eq!(proposal.track, ProposalTrack::Expedited);

        let vote = super::test_vote_data(&created.output, true, &validator);
        ex.execute_transaction(&tx(&validator, vote, 30_000, 10), &mut state)
            .await
            .unwrap();
        let mut exe = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
        exe.extend_from_slice(&created.output);
        let closed = EXPEDITED_VOTING_PERIOD_MS + 1;
        assert!(closed < VOTING_PERIOD_MS);
        ex.execute_transaction(&tx(&validator, exe.clone(), 120_000, closed), &mut state)
            .await
            .unwrap();
        ex.execute_transaction(
            &tx(
                &validator,
                exe,
                120_000,
                closed + EXPEDITED_TIMELOCK_DELAY_MS + 1,
            ),
            &mut state,
        )
        .await
        .expect("enacts on the expedited timetable");
        assert!(crate::native::read_policy(&state, "adaptive_burn_config").is_some());
    }

    #[tokio::test]
    async fn an_inapplicable_or_wrongly_expedited_policy_change_never_reaches_a_vote() {
        let (ex, mut state, validator) = world();
        // Only the burn dial answers an alarm.
        let expedited_upgrade = ProposalAction::PolicyUpdate {
            update: tenzro_types::token::PolicyUpdate::ProtocolUpgrade {
                version: "2.0.0".into(),
                code_hash: vec![7; 32],
            },
            memo: "release".into(),
            track: crate::governance::PolicyTrack::Expedited,
        };
        assert!(
            propose(&ex, &mut state, &validator, &expedited_upgrade)
                .await
                .is_err()
        );
        // A burn share above the whole.
        assert!(
            propose(&ex, &mut state, &validator, &burn(10_001, false))
                .await
                .is_err()
        );
        // An upgrade that does not pin its code.
        let unpinned = ProposalAction::PolicyUpdate {
            update: tenzro_types::token::PolicyUpdate::ProtocolUpgrade {
                version: "2.0.0".into(),
                code_hash: vec![],
            },
            memo: "release".into(),
            track: crate::governance::PolicyTrack::Standard,
        };
        assert!(
            propose(&ex, &mut state, &validator, &unpinned)
                .await
                .is_err()
        );
        // No reason given.
        let silent = ProposalAction::PolicyUpdate {
            update: tenzro_types::token::PolicyUpdate::TpmEndorsementRootsSet { roots_pem: vec![] },
            memo: " ".into(),
            track: crate::governance::PolicyTrack::Standard,
        };
        assert!(propose(&ex, &mut state, &validator, &silent).await.is_err());
        assert_eq!(crate::native::proposal_count(&state), 0);
    }

    /// A validator that proposed blocks in an epoch holds a coupon once the
    /// next epoch begins, and a `ClaimRewards` funding operation pays it out
    /// of the rewards pool: the liquid share to its balance, the rest into a
    /// reward vesting schedule. The treasury pays the gas, and a second
    /// claim finds nothing left.
    #[tokio::test]
    async fn a_validator_claims_its_epoch_coupon_through_a_funding_operation() {
        use super::super::rewards::{self, CLAIM_VESTING_PARAM};
        use tenzro_token::rewards::{CouponStatus, DEFAULT_LIQUID_BPS, NETWORK_REWARDS_POOL};
        use tenzro_token::vesting::{VestingKind, vesting_escrow_address};

        let (ex, mut state, _) = world();
        state.set_storage(
            &SYSTEM_ADDRESS,
            rewards::REWARD_SCHEDULE_KEY.as_bytes(),
            rewards::genesis_reward_schedule(86_400_000).unwrap(),
        );
        let pool = tenzro_token::rewards::rewards_pool_address();
        state.set_balance(pool.as_bytes(), NETWORK_REWARDS_POOL);

        let validator = person(&mut state, 0xB7, "did:tenzro:machine:op:node1");
        let at = Address::new(validator.clone().try_into().unwrap());
        rewards::begin_block(&mut state, 0, &at, 1_000).unwrap();
        // A paid settlement in the epoch: without one, nothing is released.
        rewards::record_settled_work(
            &mut state,
            Address::new([0xB9; 32]),
            tenzro_token::rewards::WorkClass::InferenceServed,
            1_000_000_000_000_000_000_000,
            &mut Vec::new(),
        )
        .unwrap();
        rewards::begin_block(&mut state, 1, &Address::new([0xB8; 32]), 2_000).unwrap();
        let issued = rewards::read_coupons(&state, &at).unwrap()[0].clone();
        let coupon = issued.amount;
        assert!(coupon > 0);
        assert_eq!(state.get_balance(&validator), 0);

        let treasury = derive_treasury_address();
        let treasury_before = state.get_balance(treasury.as_bytes());
        let r = ex
            .execute_transaction(
                &funding_tx(&validator, &FundingOp::ClaimRewards, 3_000),
                &mut state,
            )
            .await
            .expect("the claim executes");
        assert!(r.success);

        // The base part of the coupon is the operator's and is paid liquid.
        let (liquid, vesting) =
            tenzro_token::rewards::claim_parts(coupon, issued.base, DEFAULT_LIQUID_BPS, 10_000);
        assert!(liquid > 0 && vesting > 0);
        assert_eq!(state.get_balance(&validator), liquid);
        assert_eq!(
            state.get_balance(vesting_escrow_address().as_bytes()),
            vesting
        );
        assert_eq!(
            state.get_balance(pool.as_bytes()),
            NETWORK_REWARDS_POOL - coupon
        );
        assert!(state.get_balance(treasury.as_bytes()) < treasury_before);

        let schedules = rewards::read_vesting(&state, &at).unwrap();
        assert_eq!(schedules.len(), 1);
        assert_eq!(schedules[0].kind, VestingKind::Reward);
        assert_eq!(schedules[0].total, vesting);
        assert_eq!(
            schedules[0].duration_ms,
            super::super::network_param(&state, CLAIM_VESTING_PARAM) as i64
        );
        assert_eq!(
            rewards::read_coupons(&state, &at).unwrap()[0].status,
            CouponStatus::Claimed
        );

        assert!(
            ex.execute_transaction(
                &funding_tx(&validator, &FundingOp::ClaimRewards, 4_000),
                &mut state
            )
            .await
            .is_err(),
            "nothing is left to claim"
        );
    }
}

#[cfg(test)]
mod outflow_cap_tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    fn grant(
        state: &mut StateAdapter,
        id: &str,
        amount: u128,
        tranches: &[u128],
        at: i64,
    ) -> Result<u128> {
        super::super::payout_gates::approve_grantee_for_test(
            state,
            &[7u8; 32],
            crate::governance::GranteeClass::Developer,
        );
        let milestones: Vec<String> = (0..tranches.len().max(1))
            .map(|i| format!("milestone {i}"))
            .collect();
        enact_grant(
            state,
            id,
            &Address::new([7u8; 32]),
            amount,
            tranches,
            &milestones,
            GrantVesting::Liquid,
            None,
            &crate::governance::GrantRelease::Governed,
            at,
            &mut Vec::new(),
            &mut Vec::new(),
        )
    }

    #[test]
    fn treasury_outflow_is_capped_per_proposal_and_per_period() {
        let mut state = StateAdapter::new();
        let treasury = derive_treasury_address();
        state.set_balance(treasury.as_bytes(), 10_000);
        // 2% of the treasury per proposal.
        assert!(grant(&mut state, "a", 201, &[], 0).is_err());
        grant(&mut state, "b", 200, &[], 0).unwrap();
        // 3% of the opening balance (300) per period.
        grant(&mut state, "c", 90, &[], 1).unwrap();
        assert!(grant(&mut state, "d", 20, &[], 2).is_err());
        grant(&mut state, "e", 10, &[], 3).unwrap();
        // A new period opens on the balance then.
        let next = crate::governance::OUTFLOW_PERIOD_MS as i64;
        grant(&mut state, "f", 190, &[], next).unwrap();
        assert_eq!(outflow_period(&state, next).opening_balance, 9_700);
    }

    #[test]
    fn treasury_recoveries_share_the_grant_caps() {
        let mut state = StateAdapter::new();
        let treasury = derive_treasury_address();
        state.set_balance(treasury.as_bytes(), 10_000);
        let mut changes = Vec::new();
        // The per-proposal cap applies to what the proposal commits.
        assert!(treasury_outflow(&mut state, 201, 201, 0, &mut changes).is_err());
        treasury_outflow(&mut state, 200, 200, 0, &mut changes).unwrap();
        state.set_balance(treasury.as_bytes(), 9_800);
        // The period cap counts grants and other outflows together.
        grant(&mut state, "a", 100, &[], 1).unwrap();
        assert!(treasury_outflow(&mut state, 1, 1, 2, &mut changes).is_err());
    }
}
