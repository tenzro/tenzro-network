//! Token-factory tokens as native transactions: creation, issuance,
//! retirement, holder transfers, and the issuer powers, all against the one
//! token ledger ([`crate::token_ledger`]) and its one rule engine.
//!
//! Every issuer power is named in the token's power manifest, fixed at
//! creation and only ever narrowed. A power held by the issuer is exercised
//! by the issuer account; one held by the issuer council by `k` members,
//! each approving with its own signed transaction ([`TokenOp::Approve`]).
//! Freeze, halt and forced transfer act at once and carry a reason code and
//! an evidence hash. Policy and reserve-backing changes queue for the token's
//! policy timelock; holders keep moving under the policy in force until the
//! change is executed.

use tenzro_types::reserve::ReserveAttestation;
use tenzro_types::token_op::TokenOp;
use tenzro_types::token_policy::{Authority, ReserveBacking};

use super::funding::{read_json, refuse, write_json};
use super::*;
use crate::evm::precompile_host::{state_blob, state_write_blob};
use crate::evm::token_factory::{approvals_slot, claim_slot};
use crate::precompiles::PRECOMPILE_TOKEN_FACTORY;
use crate::token_ledger::{self, Claim, PendingChange, TokenRecord};

/// Selector of `Token`.
pub const SELECTOR_TOKEN: [u8; 4] = [0x01, 0x00, 0x00, 0x84];
/// Gas for a token operation.
pub const GAS_TOKEN: u64 = 60_000;
/// Topic of the log every token operation emits.
pub const TOKEN_TOPIC: &[u8] = b"Token";

/// Governed key: the shortest policy timelock a token may set.
pub const POLICY_TIMELOCK_FLOOR_PARAM: &str = "token.policy_timelock_floor_ms";
/// Genesis value of [`POLICY_TIMELOCK_FLOOR_PARAM`]: seven days.
pub const DEFAULT_POLICY_TIMELOCK_FLOOR_MS: u64 = 7 * 24 * 60 * 60 * 1000;

fn record_of(state: &dyn VmState, id: &[u8; 32]) -> Result<TokenRecord> {
    token_ledger::read_token(state, id).ok_or_else(|| refuse("unknown token"))
}

fn is_issuer(record: &TokenRecord, sender: &[u8]) -> bool {
    record.creator.as_slice() == crate::state_adapter::ledger_account(sender)
}

/// Require `sender` to hold the authority `op` needs, acting alone.
fn authorize_direct(record: &TokenRecord, op: &TokenOp, sender: &[u8]) -> Result<()> {
    let power = op
        .power()
        .ok_or_else(|| refuse("not an issuer operation"))?;
    match record.powers.get(power) {
        Authority::Disabled => Err(refuse(format!("the token has no {power:?} power"))),
        Authority::Issuer if is_issuer(record, sender) => Ok(()),
        Authority::Issuer => Err(refuse("only the token's issuer may do this")),
        Authority::IssuerCouncil { k } => Err(refuse(format!(
            "this power needs {k} issuer-council approvals (TokenOp::Approve)"
        ))),
    }
}

/// Governed: oldest a reserve attestation behind a mint may be, seconds.
pub const RESERVE_ATTESTATION_MAX_AGE_PARAM: &str = "token.reserve_attestation_max_age_secs";
/// Genesis value of [`RESERVE_ATTESTATION_MAX_AGE_PARAM`]: one day.
pub const DEFAULT_RESERVE_ATTESTATION_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Require a reserve-backed token's mint to carry attestations, each covering
/// `supply_after`, signed by accounts bonded as attestors whose attestor
/// stake together meets the token's backing. An attestor is the identity the
/// attestation names: its signature is checked against the hardware key
/// registered on chain for that identity, and its bond is the attestor stake
/// of that key's account. Any bonded attestor may attest; an attestation
/// older than the governed maximum age does not count.
fn check_reserves(
    state: &dyn VmState,
    id: &[u8; 32],
    backing: Option<&ReserveBacking>,
    reserves: &[ReserveAttestation],
    supply_after: u128,
    now_ms: i64,
) -> Result<()> {
    use tenzro_crypto::composite::{PqPolicy, SignatureContext, verify_composite};
    use tenzro_types::network::NetworkRole;
    let Some(backing) = backing else {
        return Ok(());
    };
    let max_age = network_param(state, RESERVE_ATTESTATION_MAX_AGE_PARAM);
    let now_secs = now_ms.max(0) / 1000;
    let mut staked: std::collections::BTreeMap<[u8; 32], u128> = std::collections::BTreeMap::new();
    for att in reserves {
        if att.asset_id.trim_start_matches("0x").to_ascii_lowercase() != hex::encode(id) {
            return Err(refuse("a reserve attestation is for another asset"));
        }
        if !att.covers(supply_after) {
            return Err(refuse(format!(
                "the supply after the mint, {supply_after}, exceeds the attested reserves {}",
                att.reserves
            )));
        }
        if att.attested_at > now_secs
            || now_secs.saturating_sub(att.attested_at) > i64::try_from(max_age).unwrap_or(i64::MAX)
        {
            return Err(refuse(format!(
                "a reserve attestation counts for {max_age} seconds after it was made"
            )));
        }
        let Some(signature) = att.signature.as_ref() else {
            return Err(refuse("a reserve attestation is unsigned"));
        };
        let key = super::registered_identity_key(state, &att.attestor_did)?;
        verify_composite(
            &key,
            SignatureContext::ReserveAttestation,
            &att.signing_payload(),
            signature,
            PqPolicy::WhenPresent,
        )
        .map_err(|_| {
            refuse(format!(
                "the reserve attestation of {} does not verify",
                att.attestor_did
            ))
        })?;
        let account = key.account_slot();
        if !super::role_bonded(state, &account, NetworkRole::Attestor) {
            return Err(refuse(format!(
                "{} holds no attestor bond",
                att.attestor_did
            )));
        }
        let bonded =
            super::read_role_stake(state, &account, NetworkRole::Attestor).map_or(0, |s| s.bonded);
        staked.insert(account, bonded);
    }
    let behind: u128 = staked.values().fold(0u128, |a, v| a.saturating_add(*v));
    let needed = u128::from(backing.min_attestor_stake_tnzo)
        .saturating_mul(tenzro_types::constants::ONE_TNZO);
    if behind < needed {
        return Err(refuse(format!(
            "a reserve-backed mint needs attestations from bonded attestors holding {needed} between them; \
             they hold {behind}"
        )));
    }
    Ok(())
}

fn write_record(
    state: &mut dyn VmState,
    id: &[u8; 32],
    record: &TokenRecord,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let bytes = serde_json::to_vec(record)
        .map_err(|e| VmError::Internal(format!("token record encode: {e}")))?;
    let slot = crate::evm::token_factory::token_slot(id);
    let prior = state_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot);
    state_write_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot, &bytes);
    changes.push(StateChange::new(
        PRECOMPILE_TOKEN_FACTORY.to_vec(),
        slot.to_vec(),
        prior,
        Some(bytes),
    ));
    Ok(())
}

/// Apply an issuer operation whose authority has been established.
fn apply_issuer_op(
    state: &mut dyn VmState,
    op: &TokenOp,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<(&'static str, serde_json::Value)> {
    let id = op
        .token_id()
        .ok_or_else(|| refuse("not an issuer operation"))?;
    let mut record = record_of(state, &id)?;
    let out = match op {
        TokenOp::Mint {
            to,
            amount,
            reserves,
            ..
        } => {
            let supply_after = record
                .total_supply
                .checked_add(*amount)
                .ok_or_else(|| refuse("the supply overflows"))?;
            check_reserves(
                &*state,
                &id,
                record.reserve_backing.as_ref(),
                reserves,
                supply_after,
                now_ms,
            )?;
            token_ledger::mint(state, &id, to, *amount, now_ms, changes)?;
            (
                "mint",
                serde_json::json!({
                    "token_id": hex::encode(id), "to": hex::encode(to),
                    "amount": amount.to_string(), "total_supply": supply_after.to_string(),
                }),
            )
        }
        TokenOp::SetFrozen {
            account,
            amount,
            action,
            ..
        } => {
            token_ledger::set_frozen(state, &id, account, *amount, changes)?;
            (
                "frozen",
                serde_json::json!({
                    "token_id": hex::encode(id), "account": hex::encode(account), "frozen": amount.to_string(),
                    "reason_code": action.reason_code, "evidence_hash": hex::encode(action.evidence_hash),
                }),
            )
        }
        TokenOp::SetHalted { halted, action, .. } => {
            token_ledger::set_halted(state, &id, *halted, changes);
            (
                "halted",
                serde_json::json!({
                    "token_id": hex::encode(id), "halted": halted,
                    "reason_code": action.reason_code, "evidence_hash": hex::encode(action.evidence_hash),
                }),
            )
        }
        TokenOp::ForcedTransfer {
            from,
            to,
            amount,
            action,
            ..
        } => {
            token_ledger::forced_transfer(state, &id, from, to, *amount, now_ms, changes)?;
            (
                "forced_transfer",
                serde_json::json!({
                    "token_id": hex::encode(id), "from": hex::encode(from), "to": hex::encode(to),
                    "amount": amount.to_string(),
                    "reason_code": action.reason_code, "evidence_hash": hex::encode(action.evidence_hash),
                }),
            )
        }
        TokenOp::RenouncePower { power, to, .. } => {
            record.powers = record
                .powers
                .narrowed(*power, *to)
                .ok_or_else(|| refuse("a power can only be narrowed"))?;
            let k = record.powers.max_council_k();
            if k > 0
                && record
                    .council
                    .as_ref()
                    .is_none_or(|c| usize::from(k) > c.members.len())
            {
                return Err(refuse(
                    "a council threshold needs a council at least that large",
                ));
            }
            write_record(state, &id, &record, changes)?;
            (
                "renounce_power",
                serde_json::json!({ "token_id": hex::encode(id), "powers": record.powers }),
            )
        }
        TokenOp::SetPolicy { policy, .. } => {
            let floor = network_param(state, POLICY_TIMELOCK_FLOOR_PARAM);
            if policy.policy_timelock_ms < floor {
                return Err(refuse(format!("a policy timelock is at least {floor} ms")));
            }
            let reserve_backing = record
                .pending
                .as_ref()
                .map_or(record.reserve_backing, |p| p.reserve_backing);
            let eta_ms = queue_eta(&record, floor, now_ms);
            record.pending = Some(PendingChange {
                policy: policy.clone(),
                reserve_backing,
                eta_ms,
            });
            write_record(state, &id, &record, changes)?;
            (
                "policy_queued",
                serde_json::json!({ "token_id": hex::encode(id), "eta_ms": eta_ms }),
            )
        }
        TokenOp::SetReserveBacking { backing, .. } => {
            let floor = network_param(state, POLICY_TIMELOCK_FLOOR_PARAM);
            let policy = record
                .pending
                .as_ref()
                .map_or(record.policy.clone(), |p| p.policy.clone());
            let eta_ms = queue_eta(&record, floor, now_ms);
            record.pending = Some(PendingChange {
                policy,
                reserve_backing: *backing,
                eta_ms,
            });
            write_record(state, &id, &record, changes)?;
            (
                "reserve_backing_queued",
                serde_json::json!({ "token_id": hex::encode(id), "eta_ms": eta_ms }),
            )
        }
        _ => return Err(refuse("not an issuer operation")),
    };
    record_issuer_action(state, &id, out.0, &out.1, now_ms, changes)?;
    Ok(out)
}

/// Storage slot, under the system account, of a token's `seq`th issuer
/// action.
pub fn issuer_action_slot(token_id: &[u8; 32], seq: u64) -> String {
    format!("token_action:{}:{seq}", hex::encode(token_id))
}

/// Storage slot of how many issuer actions a token has recorded.
pub fn issuer_action_count_slot(token_id: &[u8; 32]) -> String {
    format!("token_action_count:{}", hex::encode(token_id))
}

/// Keep an issuer action in consensus state, numbered per token, so a
/// holder or an assessor can prove what was done to a token and why.
fn record_issuer_action(
    state: &mut dyn VmState,
    id: &[u8; 32],
    kind: &str,
    detail: &serde_json::Value,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let count_slot = issuer_action_count_slot(id);
    let seq: u64 = read_json(state, &count_slot).unwrap_or(0);
    let entry = serde_json::json!({ "kind": kind, "at_ms": now_ms, "detail": detail });
    write_json(state, &issuer_action_slot(id, seq), &entry, changes)?;
    write_json(state, &count_slot, &(seq + 1), changes)?;
    Ok(())
}

/// When a change queued now may apply: the token's own policy timelock, and
/// never less than the governed floor.
fn queue_eta(record: &TokenRecord, floor: u64, now_ms: i64) -> i64 {
    now_ms.saturating_add(record.policy.policy_timelock_ms.max(floor) as i64)
}

fn op_hash(op: &TokenOp) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let bytes =
        serde_json::to_vec(op).map_err(|e| VmError::Internal(format!("encode token op: {e}")))?;
    let mut h = Sha256::new();
    h.update(b"tenzro/token/council-approval");
    h.update(&bytes);
    Ok(h.finalize().into())
}

impl NativeExecutor {
    /// Handle `Token`.
    pub(super) fn execute_token(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let op: TokenOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid Token payload: {e}")))?;
        op.validate().map_err(refuse)?;
        gas_meter.consume(GAS_TOKEN)?;
        let cost = tx.gas_price.saturating_mul(u128::from(GAS_TOKEN));
        let balance = state.get_balance(&tx.from);
        if balance < cost {
            return Err(VmError::InsufficientBalance {
                required: cost,
                available: balance,
            });
        }
        state.set_balance(&tx.from, balance - cost);
        let mut changes = vec![StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(balance.to_le_bytes().to_vec()),
            Some((balance - cost).to_le_bytes().to_vec()),
        )];
        let mut logs = Vec::new();
        let now_ms = deterministic_now_ms(tx);

        let (kind, out) = match &op {
            TokenOp::Create {
                name,
                symbol,
                decimals,
                initial_supply,
                max_supply,
                powers,
                policy,
                council,
                reserve_backing,
            } => {
                let floor = network_param(state, POLICY_TIMELOCK_FLOOR_PARAM);
                if policy.policy_timelock_ms < floor {
                    return Err(refuse(format!("a policy timelock is at least {floor} ms")));
                }
                let spec = TokenRecord {
                    name: name.clone(),
                    symbol: symbol.clone(),
                    decimals: *decimals,
                    total_supply: *initial_supply,
                    creator: Vec::new(),
                    max_supply: *max_supply,
                    powers: *powers,
                    policy: policy.clone(),
                    council: council.clone(),
                    reserve_backing: *reserve_backing,
                    pending: None,
                };
                let id = token_ledger::create(state, &tx.from, &spec, &mut changes)?;
                let record = token_ledger::read_token(state, &id)
                    .ok_or_else(|| VmError::Internal("created token has no record".into()))?;
                logs.push(token_ledger::created_log(&id, &record)?);
                (
                    "create",
                    serde_json::json!({
                        "token_id": hex::encode(id),
                        "issuer": hex::encode(&record.creator),
                        "initial_supply": initial_supply.to_string(),
                    }),
                )
            }
            TokenOp::Burn { token_id, amount } => {
                token_ledger::burn(state, token_id, &tx.from, *amount, &mut changes)?;
                (
                    "burn",
                    serde_json::json!({
                        "token_id": hex::encode(token_id),
                        "from": hex::encode(&tx.from),
                        "amount": amount.to_string(),
                    }),
                )
            }
            TokenOp::Transfer {
                token_id,
                to,
                amount,
            } => {
                let moved = token_ledger::transfer(state, token_id, &tx.from, to, *amount, now_ms)?
                    .ok_or_else(|| refuse("the sender holds less than the transfer"))?;
                changes.extend(moved);
                (
                    "transfer",
                    serde_json::json!({
                        "token_id": hex::encode(token_id),
                        "from": hex::encode(&tx.from),
                        "to": hex::encode(to),
                        "amount": amount.to_string(),
                    }),
                )
            }
            TokenOp::ExecutePolicy { token_id } => {
                let mut record = record_of(state, token_id)?;
                let pending = record
                    .pending
                    .take()
                    .ok_or_else(|| refuse("no policy change is queued"))?;
                if now_ms < pending.eta_ms {
                    return Err(refuse(format!(
                        "the policy change applies from {}",
                        pending.eta_ms
                    )));
                }
                record.policy = pending.policy;
                record.reserve_backing = pending.reserve_backing;
                write_record(state, token_id, &record, &mut changes)?;
                (
                    "policy_executed",
                    serde_json::json!({ "token_id": hex::encode(token_id) }),
                )
            }
            TokenOp::AddClaim {
                token_id,
                subject,
                kind,
                value,
                expires_ms,
            } => {
                let record = record_of(state, token_id)?;
                let issuer = claim_issuer(state, &record, &tx.from)?;
                if *expires_ms <= now_ms {
                    return Err(refuse("a claim must expire after the block it is made in"));
                }
                let claim = Claim {
                    value: value.clone(),
                    expires_ms: *expires_ms,
                };
                let bytes = serde_json::to_vec(&claim)
                    .map_err(|e| VmError::Internal(format!("claim encode: {e}")))?;
                let slot = claim_slot(token_id, subject, kind, &issuer);
                let prior = state_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot);
                state_write_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot, &bytes);
                changes.push(StateChange::new(
                    PRECOMPILE_TOKEN_FACTORY.to_vec(),
                    slot.to_vec(),
                    prior,
                    Some(bytes),
                ));
                (
                    "claim",
                    serde_json::json!({
                        "token_id": hex::encode(token_id), "subject": hex::encode(subject),
                        "kind": kind, "value": value, "issuer": issuer, "expires_ms": expires_ms,
                    }),
                )
            }
            TokenOp::RevokeClaim {
                token_id,
                subject,
                kind,
            } => {
                let record = record_of(state, token_id)?;
                let issuer = claim_issuer(state, &record, &tx.from)?;
                let slot = claim_slot(token_id, subject, kind, &issuer);
                let prior = state_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot);
                state_write_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot, &[]);
                changes.push(StateChange::new(
                    PRECOMPILE_TOKEN_FACTORY.to_vec(),
                    slot.to_vec(),
                    prior,
                    Some(Vec::new()),
                ));
                (
                    "claim_revoked",
                    serde_json::json!({
                        "token_id": hex::encode(token_id), "subject": hex::encode(subject), "kind": kind, "issuer": issuer,
                    }),
                )
            }
            TokenOp::Approve { op: inner } => {
                let id = inner
                    .token_id()
                    .ok_or_else(|| refuse("not an issuer operation"))?;
                let record = record_of(state, &id)?;
                let power = inner
                    .power()
                    .ok_or_else(|| refuse("not an issuer operation"))?;
                let Authority::IssuerCouncil { k } = record.powers.get(power) else {
                    return Err(refuse("this power is not held by the issuer council"));
                };
                let council = record
                    .council
                    .as_ref()
                    .ok_or_else(|| refuse("the token has no issuer council"))?;
                let me = crate::state_adapter::ledger_account(&tx.from).to_vec();
                if !council
                    .member_bytes()
                    .iter()
                    .any(|m| crate::state_adapter::ledger_account(m) == me.as_slice())
                {
                    return Err(refuse("only an issuer-council member may approve"));
                }
                let hash = op_hash(inner)?;
                let slot = approvals_slot(&id, &hash);
                let mut approvals: Vec<String> = state_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot)
                    .filter(|b| !b.is_empty())
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_default();
                let me_hex = hex::encode(&me);
                if approvals.contains(&me_hex) {
                    return Err(refuse("this member has already approved the operation"));
                }
                approvals.push(me_hex);
                let carried = approvals.len() >= usize::from(k);
                let bytes = if carried {
                    Vec::new()
                } else {
                    serde_json::to_vec(&approvals).unwrap_or_default()
                };
                let prior = state_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot);
                state_write_blob(state, &PRECOMPILE_TOKEN_FACTORY, slot, &bytes);
                changes.push(StateChange::new(
                    PRECOMPILE_TOKEN_FACTORY.to_vec(),
                    slot.to_vec(),
                    prior,
                    Some(bytes),
                ));
                if carried {
                    apply_issuer_op(state, inner, now_ms, &mut changes)?
                } else {
                    (
                        "approval",
                        serde_json::json!({
                            "token_id": hex::encode(id), "op_hash": hex::encode(hash),
                            "approvals": approvals.len(), "needed": k,
                        }),
                    )
                }
            }
            issuer_op => {
                let id = issuer_op
                    .token_id()
                    .ok_or_else(|| refuse("not an issuer operation"))?;
                let record = record_of(state, &id)?;
                authorize_direct(&record, issuer_op, &tx.from)?;
                apply_issuer_op(state, issuer_op, now_ms, &mut changes)?
            }
        };
        let data = serde_json::to_vec(&out)
            .map_err(|e| VmError::Internal(format!("encode token log: {e}")))?;
        logs.insert(
            0,
            Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![TOKEN_TOPIC.to_vec(), kind.as_bytes().to_vec()],
                data.clone(),
            ),
        );
        Ok(ExecutionResult::success(GAS_TOKEN, data, logs, changes))
    }
}

/// The claim-issuer DID `sender` acts as, which the token's policy (in force
/// or queued) must name.
fn claim_issuer(state: &dyn VmState, record: &TokenRecord, sender: &[u8]) -> Result<String> {
    let did = identity_of_wallet(state, sender)
        .ok_or_else(|| refuse("a claim issuer has a registered identity"))?;
    let mut named = token_ledger::named_issuers(record);
    if let Some(p) = &record.pending {
        let queued = TokenRecord {
            policy: p.policy.clone(),
            ..record.clone()
        };
        named.extend(token_ledger::named_issuers(&queued));
    }
    if !named.contains(&did) {
        return Err(refuse(format!(
            "{did} is not a claim issuer this token names"
        )));
    }
    Ok(did)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    use tenzro_types::reserve::ReserveSource;

    const NOW_MS: i64 = 10_000_000;

    fn attestation(id: &[u8; 32], did: &str, signer: &TestHybridSigner) -> ReserveAttestation {
        let mut att = ReserveAttestation {
            asset_id: hex::encode(id),
            reserves: 1_000,
            source: ReserveSource::Issuer,
            attestor_did: did.into(),
            attested_at: NOW_MS / 1000 - 60,
            signature: None,
        };
        att.signature = Some(
            signer
                .sign(SignatureContext::ReserveAttestation, &att.signing_payload())
                .unwrap(),
        );
        att
    }

    /// Register `did` with `signer`'s key and bond its account as an attestor
    /// with `stake`.
    fn bonded_attestor(
        state: &mut crate::StateAdapter,
        did: &str,
        signer: &TestHybridSigner,
        stake: u128,
    ) {
        let key = signer.public_key();
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
        super::super::role_stake::bond_role_for_test(
            state,
            &key.account_slot(),
            tenzro_types::network::NetworkRole::Attestor,
            stake,
        );
    }

    /// A reserve-backed mint counts the attestor stake of the bonded
    /// attestors behind it, whoever they are; an unbonded or stale attestor
    /// counts for nothing.
    #[test]
    fn a_mint_needs_bonded_attestor_stake_not_named_attestors() {
        let id = [0x44u8; 32];
        let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        let whole = (floor / tenzro_types::constants::ONE_TNZO) as u64;
        let backing = ReserveBacking {
            min_attestor_stake_tnzo: 2 * whole,
        };
        let mut state = crate::StateAdapter::new();
        let (a, b, c) = (
            TestHybridSigner::hybrid(0x2A),
            TestHybridSigner::hybrid(0x2B),
            TestHybridSigner::hybrid(0x2C),
        );
        bonded_attestor(&mut state, "did:tenzro:machine:a", &a, floor);
        bonded_attestor(&mut state, "did:tenzro:machine:b", &b, floor);

        let one = [attestation(&id, "did:tenzro:machine:a", &a)];
        assert!(
            check_reserves(&state, &id, Some(&backing), &one, 500, NOW_MS).is_err(),
            "one attestor's stake is short"
        );
        let two = [
            attestation(&id, "did:tenzro:machine:a", &a),
            attestation(&id, "did:tenzro:machine:b", &b),
        ];
        check_reserves(&state, &id, Some(&backing), &two, 500, NOW_MS).unwrap();
        // The same attestor twice counts once.
        let twice = [
            attestation(&id, "did:tenzro:machine:a", &a),
            attestation(&id, "did:tenzro:machine:a", &a),
        ];
        assert!(check_reserves(&state, &id, Some(&backing), &twice, 500, NOW_MS).is_err());
        // More than the attested reserve is refused.
        assert!(check_reserves(&state, &id, Some(&backing), &two, 1_001, NOW_MS).is_err());

        // A registered identity without an attestor bond does not count.
        let mut unbonded = crate::StateAdapter::new();
        bonded_attestor(&mut unbonded, "did:tenzro:machine:a", &a, floor);
        bonded_attestor(&mut unbonded, "did:tenzro:machine:c", &c, 0);
        let with_unbonded = [
            attestation(&id, "did:tenzro:machine:a", &a),
            attestation(&id, "did:tenzro:machine:c", &c),
        ];
        assert!(
            check_reserves(&unbonded, &id, Some(&backing), &with_unbonded, 500, NOW_MS).is_err()
        );

        // An attestation older than the governed maximum age is refused.
        let late = NOW_MS + 2 * DEFAULT_RESERVE_ATTESTATION_MAX_AGE_SECS as i64 * 1000;
        assert!(check_reserves(&state, &id, Some(&backing), &two, 500, late).is_err());
    }

    /// An attestation stamped at the earliest representable time is refused
    /// as stale rather than overflowing the age.
    #[test]
    fn an_attestation_at_the_earliest_time_is_refused_without_overflow() {
        let id = [0x45u8; 32];
        let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        let backing = ReserveBacking {
            min_attestor_stake_tnzo: 1,
        };
        let mut state = crate::StateAdapter::new();
        let a = TestHybridSigner::hybrid(0x3A);
        bonded_attestor(&mut state, "did:tenzro:machine:a", &a, floor);
        let mut att = attestation(&id, "did:tenzro:machine:a", &a);
        att.attested_at = i64::MIN;
        att.signature = Some(
            a.sign(SignatureContext::ReserveAttestation, &att.signing_payload())
                .unwrap(),
        );
        assert!(check_reserves(&state, &id, Some(&backing), &[att], 500, NOW_MS).is_err());
    }
}
