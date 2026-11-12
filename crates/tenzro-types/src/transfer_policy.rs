//! Transfer policy for ordinary human accounts: a governed ceiling on what
//! one account sends in a rolling window, and a governed amount above which a
//! transfer needs a second, deliberate confirmation (step-up). Pure: the
//! caller supplies what the account has already sent in the window.
//!
//! Where it is enforced today: the CLI and the wallet front ends evaluate it
//! before they ask the hardware to sign. It is not yet a consensus rule, so a
//! compromised client can skip it; the hold with a cancel window that
//! consensus would add is described in docs/security/incident-runbook.md.
//! Agent accounts have their own, consensus-enforced limits in their Terms.

use serde::{Deserialize, Serialize};

/// Governed parameter: most one account sends in the window, whole TNZO.
pub const DAILY_CEILING_PARAM: &str = "wallet.human_daily_ceiling_tnzo";
/// Governed parameter: a transfer of at least this much needs step-up, whole TNZO.
pub const STEP_UP_THRESHOLD_PARAM: &str = "wallet.step_up_threshold_tnzo";
/// Governed parameter: the rolling window the ceiling covers, ms.
pub const WINDOW_PARAM: &str = "wallet.human_ceiling_window_ms";
/// Genesis value of [`DAILY_CEILING_PARAM`].
pub const DEFAULT_DAILY_CEILING_TNZO: u64 = 10_000;
/// Genesis value of [`STEP_UP_THRESHOLD_PARAM`].
pub const DEFAULT_STEP_UP_THRESHOLD_TNZO: u64 = 1_000;
/// Genesis value of [`WINDOW_PARAM`]: one day.
pub const DEFAULT_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

/// The three governed values, in whole TNZO and ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferPolicy {
    /// Most one account sends in the window, whole TNZO.
    pub daily_ceiling_tnzo: u64,
    /// Amount from which a transfer needs step-up, whole TNZO.
    pub step_up_threshold_tnzo: u64,
    /// The rolling window, ms.
    pub window_ms: u64,
}

impl TransferPolicy {
    /// From the governed values; a missing one falls back to genesis.
    pub fn from_governed(
        ceiling: Option<u64>,
        step_up: Option<u64>,
        window_ms: Option<u64>,
    ) -> Self {
        Self {
            daily_ceiling_tnzo: ceiling.unwrap_or(DEFAULT_DAILY_CEILING_TNZO),
            step_up_threshold_tnzo: step_up.unwrap_or(DEFAULT_STEP_UP_THRESHOLD_TNZO),
            window_ms: window_ms.unwrap_or(DEFAULT_WINDOW_MS),
        }
    }
}

impl Default for TransferPolicy {
    fn default() -> Self {
        Self::from_governed(None, None, None)
    }
}

/// What the policy says about one transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDecision {
    /// Within every limit.
    Allow,
    /// Allowed only after the sender types the amount back.
    StepUp {
        /// Plain-language reason.
        reason: String,
    },
    /// Over the ceiling for the window: not signed.
    Refuse {
        /// Plain-language reason.
        reason: String,
    },
}

/// Evaluate sending `amount_wei` when `sent_in_window_wei` already left the
/// account inside the window.
pub fn evaluate_transfer(
    amount_wei: u128,
    sent_in_window_wei: u128,
    policy: &TransferPolicy,
) -> TransferDecision {
    let ceiling = u128::from(policy.daily_ceiling_tnzo).saturating_mul(ONE_TNZO);
    let after = sent_in_window_wei.saturating_add(amount_wei);
    if after > ceiling {
        return TransferDecision::Refuse {
            reason: format!(
                "this account may send {} TNZO per {} hours; {} TNZO already left it in that window, so {} TNZO more is refused",
                policy.daily_ceiling_tnzo,
                policy.window_ms / 3_600_000,
                sent_in_window_wei / ONE_TNZO,
                amount_wei / ONE_TNZO
            ),
        };
    }
    let step = u128::from(policy.step_up_threshold_tnzo).saturating_mul(ONE_TNZO);
    if amount_wei >= step {
        return TransferDecision::StepUp {
            reason: format!(
                "a transfer of {} TNZO or more needs the amount typed back before it is signed",
                policy.step_up_threshold_tnzo
            ),
        };
    }
    TransferDecision::Allow
}

/// Whether `typed` is the amount being sent, in TNZO, as a plain decimal.
pub fn amount_confirmation_matches(amount_wei: u128, typed: &str) -> bool {
    let t = typed.trim();
    let (whole, frac) = t.split_once('.').unwrap_or((t, ""));
    if whole.is_empty() && frac.is_empty() || frac.len() > 18 {
        return false;
    }
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    if !digits(whole) || !digits(frac) {
        return false;
    }
    let w: u128 = if whole.is_empty() {
        0
    } else {
        match whole.parse() {
            Ok(v) => v,
            Err(_) => return false,
        }
    };
    let f: u128 = if frac.is_empty() {
        0
    } else {
        match format!("{frac:0<18}").parse() {
            Ok(v) => v,
            Err(_) => return false,
        }
    };
    w.checked_mul(ONE_TNZO).and_then(|x| x.checked_add(f)) == Some(amount_wei)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u128 = ONE_TNZO;

    #[test]
    fn small_transfer_is_allowed() {
        assert_eq!(
            evaluate_transfer(5 * T, 0, &TransferPolicy::default()),
            TransferDecision::Allow
        );
    }

    #[test]
    fn large_transfer_needs_step_up() {
        assert!(matches!(
            evaluate_transfer(1_000 * T, 0, &TransferPolicy::default()),
            TransferDecision::StepUp { .. }
        ));
    }

    #[test]
    fn over_the_ceiling_is_refused_including_what_already_left() {
        let p = TransferPolicy::default();
        assert!(matches!(
            evaluate_transfer(2_000 * T, 9_000 * T, &p),
            TransferDecision::Refuse { .. }
        ));
        assert!(matches!(
            evaluate_transfer(1_000 * T, 9_000 * T, &p),
            TransferDecision::StepUp { .. }
        ));
    }

    #[test]
    fn governed_values_replace_genesis() {
        let p = TransferPolicy::from_governed(Some(10), Some(5), Some(3_600_000));
        assert!(matches!(
            evaluate_transfer(6 * T, 0, &p),
            TransferDecision::StepUp { .. }
        ));
        assert!(matches!(
            evaluate_transfer(11 * T, 0, &p),
            TransferDecision::Refuse { .. }
        ));
    }

    #[test]
    fn amount_confirmation_is_exact() {
        assert!(amount_confirmation_matches(1_500 * T, "1500"));
        assert!(amount_confirmation_matches(1_500 * T, " 1500.0 "));
        assert!(amount_confirmation_matches(T / 2, "0.5"));
        assert!(!amount_confirmation_matches(1_500 * T, "150"));
        assert!(!amount_confirmation_matches(1_500 * T, "1,500"));
        assert!(!amount_confirmation_matches(1_500 * T, ""));
    }
}
