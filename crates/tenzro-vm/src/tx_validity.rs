//! Expiry of signed transactions.
//!
//! Every signed transaction names the last block time at which it may
//! execute (`valid_until`). Execution refuses it once the block time has
//! passed that instant, and refuses a window that reaches further ahead of
//! the block time than the governed cap for the transaction's class. A
//! transaction pre-signed for a future nonce therefore cannot sit unused and
//! execute much later. The check reads only the block time and chain state,
//! so every validator reaches the same answer.

use crate::VmType;
use crate::error::{Result, VmError};
use crate::native::network_param;
use crate::traits::VmState;
use crate::types::VmTransaction;

/// Governed key: longest validity window of an ordinary transaction.
pub const MAX_VALIDITY_PARAM: &str = "tx.max_validity_ms";

/// Genesis value of [`MAX_VALIDITY_PARAM`]: one hour.
pub const DEFAULT_MAX_VALIDITY_MS: u64 = 60 * 60 * 1000;

/// Governed key: longest validity window of a privileged transaction.
pub const PRIVILEGED_MAX_VALIDITY_PARAM: &str = "tx.privileged_max_validity_ms";

/// Genesis value of [`PRIVILEGED_MAX_VALIDITY_PARAM`]: ten minutes.
pub const DEFAULT_PRIVILEGED_MAX_VALIDITY_MS: u64 = 10 * 60 * 1000;

/// Whether the transaction exercises a privileged power: a governance
/// action, an agent Terms or kill-switch change, or an issuer power over a
/// token. These hold a shorter validity cap.
pub fn is_privileged(tx: &VmTransaction) -> bool {
    use crate::native::*;
    if tx.vm_type != VmType::Tenzro || tx.data.len() < 4 {
        return false;
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&tx.data[..4]);
    match selector {
        SELECTOR_GOVERNANCE_PROPOSE
        | SELECTOR_GOVERNANCE_VOTE
        | SELECTOR_GOVERNANCE_EXECUTE
        | SELECTOR_GOVERNANCE_PAUSE
        | SELECTOR_GOVERNANCE_FEATURE_PAUSE
        | SELECTOR_GOVERNANCE_VETO
        | SELECTOR_GOVERNANCE_VETO_SIGNAL
        | SELECTOR_GOVERNANCE_VETO_WITHDRAW
        | SELECTOR_GOVERNANCE_CONCERN
        | SELECTOR_UPGRADE_READY
        | SELECTOR_SECURITY_DISCLOSURE
        | SELECTOR_SET_AGENT_TERMS
        | SELECTOR_RECLAIM_AGENT_FUNDS
        | SELECTOR_SET_AGENT_TOPUP
        | SELECTOR_REVOKE_DELEGATED_AGENT
        | SELECTOR_KILLSWITCH_PAUSE
        | SELECTOR_KILLSWITCH_QUARANTINE
        | SELECTOR_KILLSWITCH_TERMINATE
        | SELECTOR_LIFT_AGENT_QUARANTINE => true,
        SELECTOR_TOKEN => serde_json::from_slice::<tenzro_types::token_op::TokenOp>(&tx.data[4..])
            .map(|op| op.is_issuer_power())
            .unwrap_or(false),
        _ => false,
    }
}

/// Validity cap in milliseconds for this transaction's class.
pub fn validity_cap_ms(tx: &VmTransaction, state: &dyn VmState) -> u64 {
    let max = network_param(state, MAX_VALIDITY_PARAM);
    if is_privileged(tx) {
        network_param(state, PRIVILEGED_MAX_VALIDITY_PARAM).min(max)
    } else {
        max
    }
}

/// Refuses a signed transaction that carries no expiry, has expired at the
/// block time it executes at, or names an expiry beyond its class's cap.
/// Unsigned transactions built in-process (read-only calls) carry no
/// `signing_digest` and no expiry, and outside block execution there is no
/// block time to compare against.
pub fn check(tx: &VmTransaction, state: &dyn VmState) -> Result<()> {
    if tx.signing_digest.is_none() {
        return Ok(());
    }
    let valid_until = tx.valid_until_ms.ok_or_else(|| {
        VmError::InvalidTransaction("signed transaction carries no valid_until".to_string())
    })?;
    let Some(calendar_now) = tx.block_timestamp_ms else {
        return Ok(());
    };
    // The expiry bounds the signed envelope in real time, as the mempool
    // reads it: block time, not the calendar a genesis may compress (the
    // VM's block timestamp is calendar time).
    let now = crate::native::block_ms_at(state, calendar_now)?;
    if now > valid_until {
        return Err(VmError::InvalidTransaction(format!(
            "transaction expired: valid_until {valid_until} is before block time {now}"
        )));
    }
    let cap = validity_cap_ms(tx, state);
    let window = (valid_until - now) as u64;
    if window > cap {
        return Err(VmError::InvalidTransaction(format!(
            "valid_until {valid_until} is {window} ms past block time {now}; the cap for this transaction is {cap} ms"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{SELECTOR_GOVERNANCE_VOTE, SYSTEM_ADDRESS, governed_param_key};
    use crate::state_adapter::StateAdapter;

    const NOW: i64 = 1_700_000_000_000;

    fn signed(data: Vec<u8>, valid_until: Option<i64>) -> VmTransaction {
        let mut tx = VmTransaction::new(
            vec![7u8; 32],
            None,
            0,
            data,
            100_000,
            1,
            0,
            VmType::Tenzro,
            1337,
        )
        .with_block_timestamp_ms(NOW);
        tx.signing_digest = Some(vec![1u8; 32]);
        tx.valid_until_ms = valid_until;
        tx
    }

    fn vote() -> Vec<u8> {
        let mut d = SELECTOR_GOVERNANCE_VOTE.to_vec();
        d.extend_from_slice(b"{}");
        d
    }

    #[test]
    fn expired_transaction_is_refused_at_block_time() {
        let state = StateAdapter::new();
        assert!(check(&signed(vec![], Some(NOW)), &state).is_ok());
        let err = check(&signed(vec![], Some(NOW - 1)), &state).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn absent_valid_until_is_refused() {
        let state = StateAdapter::new();
        let err = check(&signed(vec![], None), &state).unwrap_err();
        assert!(err.to_string().contains("no valid_until"), "{err}");
    }

    #[test]
    fn window_past_the_cap_is_refused() {
        let state = StateAdapter::new();
        let max = DEFAULT_MAX_VALIDITY_MS as i64;
        assert!(check(&signed(vec![], Some(NOW + max)), &state).is_ok());
        assert!(check(&signed(vec![], Some(NOW + max + 1)), &state).is_err());
    }

    #[test]
    fn privileged_class_holds_the_shorter_cap() {
        let state = StateAdapter::new();
        let cap = DEFAULT_PRIVILEGED_MAX_VALIDITY_MS as i64;
        assert!(is_privileged(&signed(vote(), None)));
        assert!(check(&signed(vote(), Some(NOW + cap)), &state).is_ok());
        let err = check(&signed(vote(), Some(NOW + cap + 1)), &state).unwrap_err();
        assert!(err.to_string().contains("cap"), "{err}");
        // The same window is fine for an ordinary transaction.
        assert!(check(&signed(vec![], Some(NOW + cap + 1)), &state).is_ok());
    }

    /// A genesis that runs the calendar 8,640 times faster than block time,
    /// anchored 10 s of block time before `NOW`.
    fn compressed_calendar() -> (StateAdapter, i64, i64) {
        let anchor = NOW - 10_000;
        let mut state = StateAdapter::new();
        state.set_storage(
            &SYSTEM_ADDRESS,
            crate::native::CALENDAR_KEY.as_bytes(),
            crate::native::genesis_calendar(anchor, 8_640).unwrap(),
        );
        let calendar_now = crate::native::calendar_ms(&state, NOW).unwrap();
        (state, anchor, calendar_now)
    }

    fn at_calendar(data: Vec<u8>, valid_until: i64, calendar_now: i64) -> VmTransaction {
        let mut tx = signed(data, Some(valid_until));
        tx.block_timestamp_ms = Some(calendar_now);
        tx
    }

    #[test]
    fn expiry_reads_block_time_under_a_compressed_calendar() {
        let (state, _, calendar_now) = compressed_calendar();
        assert!(calendar_now > NOW + 80_000_000, "the calendar runs ahead");
        // Signed against block time, as the mempool reads it: the ordinary
        // five-minute window holds, and the cap is an hour of block time.
        assert!(check(&at_calendar(vec![], NOW + 300_000, calendar_now), &state).is_ok());
        assert!(
            check(
                &at_calendar(vec![], NOW + DEFAULT_MAX_VALIDITY_MS as i64, calendar_now),
                &state
            )
            .is_ok()
        );
        let past_cap = check(
            &at_calendar(
                vec![],
                NOW + DEFAULT_MAX_VALIDITY_MS as i64 + 1,
                calendar_now,
            ),
            &state,
        );
        assert!(past_cap.unwrap_err().to_string().contains("cap"));
        let expired = check(&at_calendar(vec![], NOW - 1, calendar_now), &state);
        assert!(expired.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn block_time_round_trips_through_the_calendar() {
        let (state, anchor, calendar_now) = compressed_calendar();
        assert_eq!(
            crate::native::block_ms_at(&state, calendar_now).unwrap(),
            NOW
        );
        assert_eq!(crate::native::block_ms_at(&state, anchor).unwrap(), anchor);
        // Without a compressed calendar, calendar time is block time.
        assert_eq!(
            crate::native::block_ms_at(&StateAdapter::new(), NOW).unwrap(),
            NOW
        );
    }

    #[test]
    fn governed_cap_applies() {
        let mut state = StateAdapter::new();
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(MAX_VALIDITY_PARAM).as_bytes(),
            5_000u64.to_le_bytes().to_vec(),
        );
        assert!(check(&signed(vec![], Some(NOW + 5_000)), &state).is_ok());
        assert!(check(&signed(vec![], Some(NOW + 5_001)), &state).is_err());
        // The privileged cap never exceeds the ordinary one.
        assert!(check(&signed(vote(), Some(NOW + 5_001)), &state).is_err());
    }

    #[test]
    fn issuer_powers_are_privileged_and_holder_transfers_are_not() {
        use tenzro_types::token_op::TokenOp;
        let enc = |op: &TokenOp| {
            let mut d = crate::native::SELECTOR_TOKEN.to_vec();
            d.extend_from_slice(&serde_json::to_vec(op).unwrap());
            d
        };
        let freeze = TokenOp::SetHalted {
            token_id: [1; 32],
            halted: true,
            action: tenzro_types::token_policy::IssuerAction {
                reason_code: 1,
                evidence_hash: [1; 32],
            },
        };
        let transfer = TokenOp::Transfer {
            token_id: [1; 32],
            to: vec![2; 32],
            amount: 1,
        };
        assert!(is_privileged(&signed(enc(&freeze), None)));
        assert!(!is_privileged(&signed(enc(&transfer), None)));
    }
}
