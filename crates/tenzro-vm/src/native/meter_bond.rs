//! Bonds behind usage meters, and the disputes that take from them.
//!
//! A seller that meters `upto` HTTP-402 charges signs a
//! [`UsageRecord`](tenzro_types::metering::UsageRecord) with its meter key.
//! `PostMeterBond` locks value behind that key; the key signs its consent so a
//! bond cannot be posted against someone else's meter. For
//! the governed dispute window ([`DISPUTE_WINDOW_PARAM`]) after a record is measured, its payer may
//! submit `DisputeMeteredCharge` with signed evidence the chain can decide
//! alone ([`MeterDispute`]). A proven dispute takes the penalty from the
//! bond, repays the payer what it provably lost (what it settled to the
//! bond's owner above what the meter could charge) and credits the rest to
//! the insurance pool. The bond is a payer's whole recourse: a meter and a
//! payer can be one party, so nothing a dispute proves is ever paid from
//! the insurance pool, and a payer should not let a meter charge more than
//! its bond covers. A signed record nobody paid against moves nothing.
//! `WithdrawMeterBond` asks to withdraw. The bond covers records measured
//! up to one window after the ask, and pays out a window after that, so
//! every record it covers can still be disputed against it.

use sha2::{Digest, Sha256};
use tenzro_types::metering::{MeterBond, MeterDispute, UsageRecord, meter_bond_consent};
use tenzro_types::primitives::Address;

use super::{NativeExecutor, SYSTEM_ADDRESS, deterministic_now_ms};
use crate::error::{Result, VmError};
use crate::gas::GasMeter;
use crate::traits::VmState;
use crate::types::{ExecutionResult, Log, StateChange, VmTransaction};

/// Gas for posting a meter bond: a signature check, a record write and a move.
pub(super) const GAS_METER_BOND_POST: u64 = 60_000;
/// Gas for asking to withdraw, or withdrawing, a meter bond.
pub(super) const GAS_METER_BOND_WITHDRAW: u64 = 40_000;
/// Gas for a metered-charge dispute: up to two signature checks and a move.
pub(super) const GAS_METER_DISPUTE: u64 = 90_000;

/// Governed key: ms after a record is measured that its payer may dispute
/// it, and that a bond stays slashable after its owner asks to withdraw it.
pub const DISPUTE_WINDOW_PARAM: &str = "metering.dispute_window_ms";
/// Genesis value of [`DISPUTE_WINDOW_PARAM`]: 72 hours.
pub const DEFAULT_DISPUTE_WINDOW_MS: u64 = 72 * 60 * 60 * 1000;

/// Governed key: how many times a disputed record's ceiling a proven
/// dispute takes from the bond, capped by what the bond holds.
pub const DISPUTE_PENALTY_MULTIPLE_PARAM: &str = "metering.dispute_penalty_multiple";
/// Genesis value of [`DISPUTE_PENALTY_MULTIPLE_PARAM`].
pub const DEFAULT_DISPUTE_PENALTY_MULTIPLE: u64 = 2;

fn dispute_window(state: &dyn VmState) -> i64 {
    i64::try_from(super::network_param(state, DISPUTE_WINDOW_PARAM)).unwrap_or(i64::MAX)
}

/// What the payer of `record`'s challenge provably lost to the bond's owner
/// on chain: the TNZO it settled to `owner` for the challenge, net of
/// refunds, above `legitimate`, the most the meter could have charged. Zero
/// when nothing was settled from `payer` to `owner` under the challenge.
fn verified_loss(
    state: &dyn VmState,
    challenge_id: &str,
    payer: &[u8],
    owner: &[u8; 32],
    legitimate: u128,
) -> u128 {
    let Some(payment) = super::payment_settlement::read_payment_by_id(state, challenge_id) else {
        return 0;
    };
    if payment.asset != "TNZO"
        || payment.payee.as_bytes() != owner
        || !payment.payer.eq_ignore_ascii_case(&hex::encode(payer))
    {
        return 0;
    }
    payment
        .amount
        .saturating_sub(payment.refunded)
        .saturating_sub(legitimate)
}

const METER_BOND_VAULT_DOMAIN: &[u8] = b"tenzro/metering/bond-vault";

/// Storage key of the bond behind `meter_id`.
pub fn meter_bond_storage_key(meter_id: &[u8; 32]) -> String {
    format!("meter_bond:{}", hex::encode(meter_id))
}

fn dispute_storage_key(meter_id: &[u8; 32], challenge_id: &str) -> String {
    format!("meter_dispute:{}:{}", hex::encode(meter_id), challenge_id)
}

/// The account a meter bond's value is held in.
pub fn meter_bond_vault(meter_id: &[u8; 32]) -> Address {
    let mut h = Sha256::new();
    h.update(METER_BOND_VAULT_DOMAIN);
    h.update(meter_id);
    Address::new(h.finalize().into())
}

/// The bond behind `meter_id`, if one stands.
pub fn read_meter_bond(state: &dyn VmState, meter_id: &[u8; 32]) -> Option<MeterBond> {
    let blob = state.get_storage(&SYSTEM_ADDRESS, meter_bond_storage_key(meter_id).as_bytes())?;
    serde_json::from_slice(&blob).ok()
}

fn invalid(why: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(why.into())
}

fn from_32(from: &[u8]) -> Result<[u8; 32]> {
    from.try_into().map_err(|_| {
        invalid(format!(
            "sender is {} bytes; a Tenzro account is 32",
            from.len()
        ))
    })
}

/// Check a record's signature under its own meter key and the ML-DSA-65 key
/// enrolled for it, and return the meter id.
fn verify_record(state: &dyn VmState, record: &UsageRecord) -> Result<[u8; 32]> {
    let key = record
        .meter_public_key()
        .ok_or_else(|| invalid("the record's meter key is not a 64-byte P-256 key in hex"))?;
    if !tenzro_types::metering::commitments_well_formed(&record.commitments) {
        return Err(invalid(
            "the record's commitments are not at most 8 labelled 32-byte hex values",
        ));
    }
    let meter_id = tenzro_crypto::account_slot(&key);
    crate::account_keys::verify_account_signature(
        state,
        &key,
        &meter_id,
        tenzro_crypto::composite::SignatureContext::UsageRecord,
        &record.preimage(),
        &record.signature,
        tenzro_crypto::composite::PqPolicy::WhenPresent,
    )?;
    Ok(meter_id)
}

#[derive(serde::Deserialize)]
struct PostPayload {
    meter_public_key: Vec<u8>,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    amount: u128,
    consent: tenzro_crypto::composite::CompositeSignature,
}

#[derive(serde::Deserialize)]
struct WithdrawPayload {
    meter_id: [u8; 32],
}

/// The last measurement time a bond whose withdrawal was asked at `asked`
/// still covers: one window after the ask.
fn covered_until(asked: i64, window: i64) -> i64 {
    asked.saturating_add(window)
}

/// When a bond whose withdrawal was asked at `asked` pays out: a window
/// after the last record it covers, so each can still be disputed.
fn payout_at(asked: i64, window: i64) -> i64 {
    covered_until(asked, window).saturating_add(window)
}

/// Charge `gas` at the transaction's price to its sender.
fn charge_gas(tx: &VmTransaction, state: &mut dyn VmState, gas: u64) -> Result<StateChange> {
    let cost = tx.gas_price.saturating_mul(gas as u128);
    let balance = state.get_balance(&tx.from);
    if balance < cost {
        return Err(VmError::InsufficientBalance {
            required: cost,
            available: balance,
        });
    }
    state.set_balance(&tx.from, balance - cost);
    Ok(StateChange::new(
        tx.from.clone(),
        b"balance".to_vec(),
        Some(balance.to_le_bytes().to_vec()),
        Some((balance - cost).to_le_bytes().to_vec()),
    ))
}

fn move_value(
    state: &mut dyn VmState,
    from: &[u8],
    to: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let old_from = state.get_balance(from);
    if old_from < amount {
        return Err(VmError::InsufficientBalance {
            required: amount,
            available: old_from,
        });
    }
    state.set_balance(from, old_from - amount);
    let old_to = state.get_balance(to);
    let new_to = old_to
        .checked_add(amount)
        .ok_or_else(|| VmError::Internal("balance overflow".to_string()))?;
    state.set_balance(to, new_to);
    changes.push(StateChange::new(
        from.to_vec(),
        b"balance".to_vec(),
        Some(old_from.to_le_bytes().to_vec()),
        Some((old_from - amount).to_le_bytes().to_vec()),
    ));
    changes.push(StateChange::new(
        to.to_vec(),
        b"balance".to_vec(),
        Some(old_to.to_le_bytes().to_vec()),
        Some(new_to.to_le_bytes().to_vec()),
    ));
    Ok(())
}

fn write_bond(
    state: &mut dyn VmState,
    bond: Option<&MeterBond>,
    meter_id: &[u8; 32],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let key = meter_bond_storage_key(meter_id);
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let new = match bond {
        Some(b) => serde_json::to_vec(b)
            .map_err(|e| VmError::Internal(format!("Failed to serialize meter bond: {e}")))?,
        None => Vec::new(),
    };
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), new.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        old,
        Some(new),
    ));
    Ok(())
}

fn bump_nonce(tx: &VmTransaction, state: &mut dyn VmState, changes: &mut Vec<StateChange>) {
    let old = state.get_nonce(&tx.from);
    state.set_nonce(&tx.from, old + 1);
    changes.push(StateChange::new(
        tx.from.clone(),
        b"nonce".to_vec(),
        Some(old.to_le_bytes().to_vec()),
        Some((old + 1).to_le_bytes().to_vec()),
    ));
}

impl NativeExecutor {
    /// Handle `PostMeterBond`: lock `amount` from the sender behind a meter
    /// key that signed its consent to the sender as the bond's owner. A bond
    /// may be topped up by its owner while no withdrawal is pending.
    pub(super) async fn execute_meter_bond_post(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_METER_BOND_POST)?;
        let p: PostPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| invalid(format!("Invalid PostMeterBond payload: {e}")))?;
        if p.amount == 0 {
            return Err(invalid("a meter bond must hold something"));
        }
        let owner = from_32(&tx.from)?;
        let meter_id = tenzro_crypto::account_slot(&p.meter_public_key);
        crate::account_keys::verify_account_signature(
            state,
            &p.meter_public_key,
            &meter_id,
            tenzro_crypto::composite::SignatureContext::MeterBondConsent,
            &meter_bond_consent(tx.chain_id, &meter_id, &owner),
            &p.consent,
            tenzro_crypto::composite::PqPolicy::WhenPresent,
        )
        .map_err(|e| invalid(format!("the meter did not consent to this owner: {e}")))?;

        let mut bond = match read_meter_bond(state, &meter_id) {
            Some(b) if b.owner != owner => {
                return Err(invalid("this meter's bond belongs to another account"));
            }
            Some(b) if b.withdrawal_requested_at_ms.is_some() => {
                return Err(invalid("this meter's bond is being withdrawn"));
            }
            Some(b) => b,
            None => MeterBond {
                meter_id,
                owner,
                amount: 0,
                withdrawal_requested_at_ms: None,
            },
        };
        bond.amount = bond
            .amount
            .checked_add(p.amount)
            .ok_or_else(|| VmError::Internal("meter bond overflow".to_string()))?;

        let mut changes = vec![charge_gas(tx, state, GAS_METER_BOND_POST)?];
        let vault = meter_bond_vault(&meter_id);
        move_value(state, &tx.from, vault.as_bytes(), p.amount, &mut changes)?;
        write_bond(state, Some(&bond), &meter_id, &mut changes)?;
        bump_nonce(tx, state, &mut changes);

        // meter_id(32) || owner(32) || total(16)
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"MeterBondPosted".to_vec()],
            [
                meter_id.as_slice(),
                owner.as_slice(),
                &bond.amount.to_le_bytes(),
            ]
            .concat(),
        );
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            meter_id.to_vec(),
            vec![log],
            changes,
        ))
    }

    /// Handle `WithdrawMeterBond`. The first call by the owner starts the
    /// dispute window; a call once it has passed pays the bond back.
    pub(super) async fn execute_meter_bond_withdraw(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_METER_BOND_WITHDRAW)?;
        let p: WithdrawPayload = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| invalid(format!("Invalid WithdrawMeterBond payload: {e}")))?;
        let owner = from_32(&tx.from)?;
        let mut bond = read_meter_bond(state, &p.meter_id)
            .ok_or_else(|| invalid("no bond stands behind this meter"))?;
        if bond.owner != owner {
            return Err(invalid("only the bond's owner may withdraw it"));
        }
        let now = deterministic_now_ms(tx);
        let mut changes = vec![charge_gas(tx, state, GAS_METER_BOND_WITHDRAW)?];
        let log = match bond.withdrawal_requested_at_ms {
            None => {
                bond.withdrawal_requested_at_ms = Some(now);
                write_bond(state, Some(&bond), &p.meter_id, &mut changes)?;
                Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"MeterBondUnbonding".to_vec()],
                    [
                        p.meter_id.as_slice(),
                        &payout_at(now, dispute_window(state)).to_le_bytes(),
                    ]
                    .concat(),
                )
            }
            Some(asked) if now >= payout_at(asked, dispute_window(state)) => {
                let vault = meter_bond_vault(&p.meter_id);
                move_value(state, vault.as_bytes(), &tx.from, bond.amount, &mut changes)?;
                write_bond(state, None, &p.meter_id, &mut changes)?;
                Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![b"MeterBondWithdrawn".to_vec()],
                    [p.meter_id.as_slice(), &bond.amount.to_le_bytes()].concat(),
                )
            }
            Some(asked) => {
                return Err(invalid(format!(
                    "the bond stays disputable until {}",
                    payout_at(asked, dispute_window(state))
                )));
            }
        };
        bump_nonce(tx, state, &mut changes);
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            vec![log],
            changes,
        ))
    }

    /// Handle `DisputeMeteredCharge`: decide the dispute from its signed
    /// evidence and chain state, and pay a proven one to the record's payer
    /// from the meter's bond. One dispute per meter and challenge.
    pub(super) async fn execute_meter_dispute(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_METER_DISPUTE)?;
        let dispute: MeterDispute = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| invalid(format!("Invalid DisputeMeteredCharge payload: {e}")))?;
        let record = dispute.record().clone();
        let meter_id = verify_record(state, &record)?;

        // What the evidence proves, the ceiling the penalty scales with, and
        // the most the meter could legitimately have charged.
        let (kind, ceiling, latest_measured, legitimate) = match &dispute {
            MeterDispute::Equivocation { first, second } => {
                let other_key = verify_record(state, second)?;
                if other_key != meter_id {
                    return Err(invalid("the two records are signed by different meters"));
                }
                if first.challenge_id != second.challenge_id {
                    return Err(invalid("the two records meter different challenges"));
                }
                if first.preimage() == second.preimage() {
                    return Err(invalid("the two records are the same record"));
                }
                let lower = |r: &UsageRecord| r.charge().unwrap_or(u128::MAX).min(r.ceiling);
                (
                    "equivocation",
                    first.ceiling.max(second.ceiling),
                    first.measured_at_ms.max(second.measured_at_ms),
                    lower(first).min(lower(second)),
                )
            }
            MeterDispute::OverCeiling { record } => {
                if record.charge().is_some_and(|c| c <= record.ceiling) {
                    return Err(invalid("the record charges within its ceiling"));
                }
                (
                    "over_ceiling",
                    record.ceiling,
                    record.measured_at_ms,
                    record.ceiling,
                )
            }
            MeterDispute::OverSettled { record } => {
                let charge = record.charge().ok_or_else(|| {
                    invalid("the record's charge overflows; dispute it as over-ceiling")
                })?;
                (
                    "over_settled",
                    record.ceiling,
                    record.measured_at_ms,
                    charge.min(record.ceiling),
                )
            }
        };

        let now = deterministic_now_ms(tx);
        let window = dispute_window(state);
        if now > latest_measured.saturating_add(window) {
            return Err(invalid("the dispute window for this record has closed"));
        }
        let caller_payer = hex::encode(&tx.from[..tx.from.len().min(20)]);
        if !record.payer.eq_ignore_ascii_case(&caller_payer) {
            return Err(invalid("only the record's payer may dispute it"));
        }
        let marker = dispute_storage_key(&meter_id, &record.challenge_id);
        if state
            .get_storage(&SYSTEM_ADDRESS, marker.as_bytes())
            .is_some_and(|b| !b.is_empty())
        {
            return Err(invalid("this charge has already been disputed"));
        }
        let mut bond = read_meter_bond(state, &meter_id)
            .filter(|b| b.amount > 0)
            .ok_or_else(|| invalid("no bond stands behind this meter"))?;
        if let Some(asked) = bond.withdrawal_requested_at_ms
            && latest_measured > covered_until(asked, window)
        {
            return Err(invalid(
                "the record was measured after the bond stopped covering this meter",
            ));
        }
        // Only a loss the chain can see is repaid, from the bond alone: what
        // the payer settled to the bond's owner for this challenge above what
        // the meter could charge. A signed record nobody paid against moves
        // nothing, so a meter cannot hand its bond to an accomplice; and as a
        // meter and its payer can be one party, the insurance pool never
        // covers what the bond does not.
        let loss = verified_loss(
            state,
            &record.challenge_id,
            &tx.from,
            &bond.owner,
            legitimate,
        );
        if loss == 0 {
            return Err(invalid(
                "nothing was settled to the bond's owner above what the meter could charge",
            ));
        }
        let multiple = u128::from(super::network_param(state, DISPUTE_PENALTY_MULTIPLE_PARAM));
        let penalty = ceiling.saturating_mul(multiple).max(loss).min(bond.amount);
        let repaid = loss.min(penalty);
        let to_pool = penalty - repaid;
        bond.amount -= penalty;

        let mut changes = vec![charge_gas(tx, state, GAS_METER_DISPUTE)?];
        let vault = meter_bond_vault(&meter_id);
        move_value(state, vault.as_bytes(), &tx.from, repaid, &mut changes)?;
        if to_pool > 0 {
            let pool = super::insurance::pool_address();
            move_value(
                state,
                vault.as_bytes(),
                pool.as_bytes(),
                to_pool,
                &mut changes,
            )?;
            super::insurance::note_credit(
                state,
                to_pool,
                super::insurance::PoolSource::Slash,
                &mut changes,
            )?;
        }
        write_bond(state, Some(&bond), &meter_id, &mut changes)?;
        let marker_value = penalty.to_le_bytes().to_vec();
        state.set_storage(&SYSTEM_ADDRESS, marker.as_bytes(), marker_value.clone());
        changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            marker.into_bytes(),
            None,
            Some(marker_value),
        ));
        bump_nonce(tx, state, &mut changes);

        // meter_id(32) || penalty(16) || kind || 0x00 || challenge_id
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"MeterDisputeUpheld".to_vec()],
            [
                meter_id.as_slice(),
                &penalty.to_le_bytes(),
                kind.as_bytes(),
                &[0u8],
                record.challenge_id.as_bytes(),
            ]
            .concat(),
        );
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            penalty.to_le_bytes().to_vec(),
            vec![log],
            changes,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VmConfig;
    use crate::VmType;
    use crate::state_adapter::StateAdapter;
    use crate::traits::VmExecutor as _;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    use tenzro_types::metering::UsageLine;

    const CHAIN: u64 = 1337;
    const T0: i64 = 1_800_000_000_000;
    const RICH: u128 = 10_000_000_000_000_000_000;

    fn tx(
        from: &[u8],
        selector: [u8; 4],
        body: serde_json::Value,
        nonce: u64,
        at: i64,
    ) -> VmTransaction {
        let mut data = selector.to_vec();
        data.extend(serde_json::to_vec(&body).unwrap());
        let mut t = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            2_000_000,
            // Free gas, so balances show exactly the value moved.
            0,
            nonce,
            VmType::Tenzro,
            CHAIN,
        );
        t.block_timestamp_ms = Some(at);
        t
    }

    fn meter() -> TestHybridSigner {
        TestHybridSigner::p256_only(11)
    }

    fn meter_id() -> [u8; 32] {
        meter().public_key().account_slot()
    }

    fn consent_to(owner: &[u8; 32]) -> serde_json::Value {
        let sig = meter()
            .sign(
                SignatureContext::MeterBondConsent,
                &meter_bond_consent(CHAIN, &meter_id(), owner),
            )
            .unwrap();
        serde_json::to_value(sig).unwrap()
    }

    fn signed(challenge: &str, payer: &[u8], ceiling: u128, qty: u128, at: i64) -> UsageRecord {
        let mut r = UsageRecord {
            challenge_id: challenge.into(),
            payer: hex::encode(&payer[..20]),
            ceiling,
            lines: vec![UsageLine {
                unit: "requests".into(),
                quantity: qty,
                unit_price: 100,
            }],
            measured_at_ms: at,
            commitments: Default::default(),
            meter_key: hex::encode(&meter().public_key().p256),
            signature: tenzro_crypto::composite::CompositeSignature::classical(
                tenzro_crypto::composite::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        };
        r.signature = meter()
            .sign(SignatureContext::UsageRecord, &r.preimage())
            .unwrap();
        r
    }

    async fn run(ex: &NativeExecutor, state: &mut StateAdapter, t: &VmTransaction) -> bool {
        matches!(ex.execute_transaction(t, state).await, Ok(r) if r.success)
    }

    /// A seller posts a 10_000 bond behind its meter; returns the executor,
    /// state, seller and payer accounts.
    async fn bonded() -> (NativeExecutor, StateAdapter, Vec<u8>, Vec<u8>) {
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let seller = vec![2u8; 32];
        let payer = vec![3u8; 32];
        state.set_balance(&seller, RICH);
        state.set_balance(&payer, RICH);
        let consent = consent_to(seller.as_slice().try_into().unwrap());
        let post = tx(
            &seller,
            super::super::SELECTOR_METER_BOND_POST,
            serde_json::json!({
                "meter_public_key": meter().public_key().p256,
                "amount": "10000",
                "consent": consent,
            }),
            0,
            T0,
        );
        assert!(run(&ex, &mut state, &post).await);
        assert_eq!(
            state.get_balance(meter_bond_vault(&meter_id()).as_bytes()),
            10_000
        );
        (ex, state, seller, payer)
    }

    fn dispute(from: &[u8], d: &MeterDispute, nonce: u64, at: i64) -> VmTransaction {
        tx(
            from,
            super::super::SELECTOR_METER_DISPUTE,
            serde_json::to_value(d).unwrap(),
            nonce,
            at,
        )
    }

    #[tokio::test]
    async fn a_bond_needs_its_meter_keys_consent_to_its_owner() {
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let thief = vec![9u8; 32];
        state.set_balance(&thief, RICH);
        // Consent given to someone else does not let the thief post.
        let consent = consent_to(&[2u8; 32]);
        let post = tx(
            &thief,
            super::super::SELECTOR_METER_BOND_POST,
            serde_json::json!({
                "meter_public_key": meter().public_key().p256,
                "amount": "10000",
                "consent": consent,
            }),
            0,
            T0,
        );
        assert!(!run(&ex, &mut state, &post).await);
        assert!(read_meter_bond(&state, &meter_id()).is_none());
    }

    /// What the payer settled to the seller for `challenge`.
    fn settle(
        state: &mut StateAdapter,
        challenge: &str,
        payer: &[u8],
        seller: &[u8],
        amount: u128,
    ) {
        super::super::payment_settlement::record_settled(
            state,
            challenge,
            payer,
            seller.try_into().unwrap(),
            amount,
        );
    }

    fn pool(state: &StateAdapter) -> u128 {
        state.get_balance(super::super::insurance::pool_address().as_bytes())
    }

    /// A meter with a 1-wei bond, and a payer that may be the meter's own
    /// account, cannot reach the insurance pool: a record nobody paid
    /// against moves nothing, and a paid one is repaid from the bond alone,
    /// with nothing left owed for the pool to cover.
    #[tokio::test]
    async fn the_insurance_pool_never_pays_for_a_meter() {
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let seller = vec![2u8; 32];
        let payer = vec![3u8; 32];
        state.set_balance(&seller, RICH);
        state.set_balance(&payer, RICH);
        let post = tx(
            &seller,
            super::super::SELECTOR_METER_BOND_POST,
            serde_json::json!({
                "meter_public_key": meter().public_key().p256,
                "amount": "1",
                "consent": consent_to(seller.as_slice().try_into().unwrap()),
            }),
            0,
            T0,
        );
        assert!(run(&ex, &mut state, &post).await);
        let unpaid_key =
            |challenge: &str| format!("meter_shortfall:{}:{challenge}", hex::encode(meter_id()));
        let huge = u128::MAX / 4;
        let mut record = signed("ch-free", &payer, huge, 1, T0);
        record.lines[0].unit_price = u128::MAX / 2;
        record.signature = meter()
            .sign(SignatureContext::UsageRecord, &record.preimage())
            .unwrap();
        let d = MeterDispute::OverCeiling { record };
        assert!(!run(&ex, &mut state, &dispute(&payer, &d, 0, T0 + 10)).await);

        // Paid 5_000 against a 1_000 ceiling: the 1-wei bond repays 1, and
        // nothing is left for anyone to claim.
        let pool_before = pool(&state);
        let paid = signed("ch-paid", &payer, 1_000, 50, T0);
        settle(&mut state, "ch-paid", &payer, &seller, 5_000);
        let before = state.get_balance(&payer);
        let d = MeterDispute::OverCeiling { record: paid };
        assert!(run(&ex, &mut state, &dispute(&payer, &d, 0, T0 + 10)).await);
        assert_eq!(state.get_balance(&payer), before + 1);
        assert_eq!(pool(&state), pool_before);
        for c in ["ch-free", "ch-paid"] {
            assert!(
                state
                    .get_storage(&SYSTEM_ADDRESS, unpaid_key(c).as_bytes())
                    .is_none_or(|b| b.is_empty()),
                "a claim on the pool was written for {c}"
            );
        }
    }

    /// An accomplice the meter signs a bogus over-ceiling record for, and
    /// who paid nothing against it, cannot empty the bond that stands for
    /// the meter's real payers.
    #[tokio::test]
    async fn an_accomplice_cannot_empty_the_bond_with_an_unpaid_record() {
        let (ex, mut state, _seller, _payer) = bonded().await;
        let accomplice = vec![8u8; 32];
        state.set_balance(&accomplice, RICH);
        let bogus = signed("ch-acc", &accomplice, 10_000, 200, T0);
        let d = MeterDispute::OverCeiling { record: bogus };
        assert!(!run(&ex, &mut state, &dispute(&accomplice, &d, 0, T0 + 10)).await);
        assert_eq!(read_meter_bond(&state, &meter_id()).unwrap().amount, 10_000);
        assert_eq!(state.get_balance(&accomplice), RICH);
    }

    /// A record measured just before the payout the ask scheduled is still
    /// disputable against the bond: the bond does not pay out until every
    /// record it covers has had its own window.
    #[tokio::test]
    async fn a_record_measured_during_unbonding_is_still_covered() {
        let (ex, mut state, seller, payer) = bonded().await;
        let w = DEFAULT_DISPUTE_WINDOW_MS as i64;
        let ask = T0 + 1_000;
        let withdraw = |nonce: u64, at: i64| {
            tx(
                &seller,
                super::super::SELECTOR_METER_BOND_WITHDRAW,
                serde_json::json!({ "meter_id": meter_id() }),
                nonce,
                at,
            )
        };
        assert!(run(&ex, &mut state, &withdraw(1, ask)).await);
        let late = signed("ch-late", &payer, 100, 3, ask + w - 1);
        settle(&mut state, "ch-late", &payer, &seller, 300);
        assert!(!run(&ex, &mut state, &withdraw(2, ask + w)).await);
        let before = state.get_balance(&payer);
        let d = MeterDispute::OverCeiling { record: late };
        assert!(run(&ex, &mut state, &dispute(&payer, &d, 0, ask + w + 1)).await);
        assert_eq!(state.get_balance(&payer), before + 200);

        // A record measured after the bond stopped covering is refused.
        let after = signed("ch-after", &payer, 100, 3, ask + w + 1);
        settle(&mut state, "ch-after", &payer, &seller, 300);
        let d = MeterDispute::OverCeiling { record: after };
        assert!(!run(&ex, &mut state, &dispute(&payer, &d, 1, ask + w + 2)).await);
    }

    /// The governed window at its largest value schedules the payout at the
    /// end of time instead of overflowing.
    #[tokio::test]
    async fn the_largest_window_saturates() {
        let (ex, mut state, seller, _payer) = bonded().await;
        state.set_storage(
            &SYSTEM_ADDRESS,
            super::super::governed_param_key(DISPUTE_WINDOW_PARAM).as_bytes(),
            u64::MAX.to_le_bytes().to_vec(),
        );
        let ask = tx(
            &seller,
            super::super::SELECTOR_METER_BOND_WITHDRAW,
            serde_json::json!({ "meter_id": meter_id() }),
            1,
            T0 + 1_000,
        );
        let out = ex.execute_transaction(&ask, &mut state).await.unwrap();
        assert!(out.success);
        let at = i64::from_le_bytes(out.logs[0].data[32..40].try_into().unwrap());
        assert_eq!(at, i64::MAX);
    }

    #[tokio::test]
    async fn equivocating_meters_pay_their_payer_once() {
        let (ex, mut state, seller, payer) = bonded().await;
        let a = signed("ch-1", &payer, 1_000, 2, T0);
        let b = signed("ch-1", &payer, 1_000, 5, T0 + 1);
        let before = state.get_balance(&payer);

        // The same record twice proves nothing.
        let same = MeterDispute::Equivocation {
            first: a.clone(),
            second: a.clone(),
        };
        assert!(!run(&ex, &mut state, &dispute(&payer, &same, 0, T0 + 10)).await);

        // Someone who is not the payer cannot collect.
        let stranger = vec![7u8; 32];
        state.set_balance(&stranger, RICH);
        let proof = MeterDispute::Equivocation {
            first: a.clone(),
            second: b.clone(),
        };
        assert!(!run(&ex, &mut state, &dispute(&stranger, &proof, 0, T0 + 10)).await);

        // The payer, who settled the larger charge, does: the bond loses
        // twice the ceiling, the payer is repaid what it paid above the
        // smaller charge, and the rest goes to the insurance pool.
        settle(&mut state, "ch-1", &payer, &seller, 500);
        let pool_before = pool(&state);
        assert!(run(&ex, &mut state, &dispute(&payer, &proof, 0, T0 + 10)).await);
        assert_eq!(state.get_balance(&payer), before + 300);
        assert_eq!(pool(&state), pool_before + 1_700);
        assert_eq!(read_meter_bond(&state, &meter_id()).unwrap().amount, 8_000);

        // Once per challenge.
        assert!(!run(&ex, &mut state, &dispute(&payer, &proof, 1, T0 + 20)).await);
        assert_eq!(read_meter_bond(&state, &meter_id()).unwrap().amount, 8_000);
    }

    #[tokio::test]
    async fn a_record_is_disputable_only_for_what_it_proves_and_only_in_the_window() {
        let (ex, mut state, seller, payer) = bonded().await;

        // Within its ceiling: nothing to dispute.
        let fair = signed("ch-2", &payer, 1_000, 3, T0);
        let d = MeterDispute::OverCeiling {
            record: fair.clone(),
        };
        assert!(!run(&ex, &mut state, &dispute(&payer, &d, 0, T0 + 10)).await);

        // Over its ceiling: upheld.
        let over = signed("ch-3", &payer, 250, 3, T0);
        settle(&mut state, "ch-3", &payer, &seller, 300);
        let d = MeterDispute::OverCeiling { record: over };
        assert!(run(&ex, &mut state, &dispute(&payer, &d, 0, T0 + 10)).await);
        assert_eq!(read_meter_bond(&state, &meter_id()).unwrap().amount, 9_500);

        // Settled for more than the meter signed: upheld while the window is
        // open, refused after it closes.
        let signed_300 = signed("ch-4", &payer, 1_000, 3, T0);
        settle(&mut state, "ch-4", &payer, &seller, 1_000);
        let d = MeterDispute::OverSettled { record: signed_300 };
        let late = T0 + (DEFAULT_DISPUTE_WINDOW_MS as i64) + 1;
        assert!(!run(&ex, &mut state, &dispute(&payer, &d, 1, late)).await);
        assert!(run(&ex, &mut state, &dispute(&payer, &d, 1, T0 + 10)).await);
        assert_eq!(read_meter_bond(&state, &meter_id()).unwrap().amount, 7_500);

        // Settled exactly what it signed: not a dispute.
        let honest = signed("ch-5", &payer, 1_000, 3, T0);
        settle(&mut state, "ch-5", &payer, &seller, 300);
        let d = MeterDispute::OverSettled { record: honest };
        assert!(!run(&ex, &mut state, &dispute(&payer, &d, 2, T0 + 10)).await);

        // A forged record is not evidence.
        let mut forged = signed("ch-6", &payer, 100, 3, T0);
        forged.lines[0].quantity = 1;
        forged.ceiling = 50;
        let d = MeterDispute::OverCeiling { record: forged };
        assert!(!run(&ex, &mut state, &dispute(&payer, &d, 2, T0 + 10)).await);
    }

    #[tokio::test]
    async fn a_bond_pays_back_only_after_every_record_it_covers_had_its_window() {
        let (ex, mut state, seller, payer) = bonded().await;
        let withdraw = |nonce: u64, at: i64| {
            tx(
                &seller,
                super::super::SELECTOR_METER_BOND_WITHDRAW,
                serde_json::json!({ "meter_id": meter_id() }),
                nonce,
                at,
            )
        };
        // Ask at T0 + 1000.
        assert!(run(&ex, &mut state, &withdraw(1, T0 + 1_000)).await);
        // A record measured just before the ask is still disputable against
        // the bond while it unbonds.
        let over = signed("ch-7", &payer, 100, 3, T0 + 999);
        settle(&mut state, "ch-7", &payer, &seller, 300);
        let d = MeterDispute::OverCeiling { record: over };
        assert!(run(&ex, &mut state, &dispute(&payer, &d, 0, T0 + 2_000)).await);
        // Too early to pay out: the bond covers records measured up to a
        // window after the ask, and each of those has a window of its own.
        let w = DEFAULT_DISPUTE_WINDOW_MS as i64;
        assert!(!run(&ex, &mut state, &withdraw(2, T0 + 1_000 + w)).await);
        assert!(!run(&ex, &mut state, &withdraw(2, T0 + 999 + 2 * w)).await);
        let before = state.get_balance(&seller);
        assert!(run(&ex, &mut state, &withdraw(2, T0 + 1_000 + 2 * w)).await);
        assert_eq!(state.get_balance(&seller), before + 9_800);
        assert_eq!(
            state.get_balance(meter_bond_vault(&meter_id()).as_bytes()),
            0
        );
        assert!(read_meter_bond(&state, &meter_id()).is_none());
    }
}
