//! The wallet-side warning for a delegation (an EIP-7702 style grant that
//! sets an account's code to a delegate): is the delegate on the network's
//! governed list of recognised smart-account code, and does the network
//! refuse one that is not?
//!
//! The list and the switch are governed (`SetDelegateCode`,
//! `evm.delegate_allowlist_enforced`); the node answers
//! `tenzro_checkDelegateTarget` from chain state and this module words the
//! answer. A delegate that is not recognised gets the warning whether or not
//! the network enforces the list yet.

use serde_json::Value;

/// What the node says about one delegate target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegateStatus {
    /// The network refuses delegates that are not listed.
    pub allowlist_enforced: bool,
    /// The delegate's code is on the governed list.
    pub listed: bool,
    /// The target is the zero address, which clears a delegation.
    pub clears: bool,
}

impl DelegateStatus {
    /// Read the node's `tenzro_checkDelegateTarget` answer.
    pub fn from_rpc(v: &Value) -> Option<Self> {
        Some(Self {
            allowlist_enforced: v.get("allowlist_enforced")?.as_bool()?,
            listed: v.get("listed")?.as_bool()?,
            clears: v.get("clears").and_then(Value::as_bool).unwrap_or(false),
        })
    }

    /// Lines to show before signing a delegation to `target` (hex). Empty for
    /// a recognised delegate or for clearing a delegation.
    pub fn warning(&self, target: &str) -> Vec<String> {
        if self.clears || self.listed {
            return Vec::new();
        }
        let mut out = vec![
            format!(
                "WARNING: 0x{} is not on the network's list of recognised smart-account code.",
                target.trim_start_matches("0x")
            ),
            "Delegating to it lets that code act as this account and move everything it holds. \
             Wallet-draining scams work exactly this way; only continue if you wrote or audited this code."
                .to_string(),
        ];
        out.push(if self.allowlist_enforced {
            "The network enforces its list, so this delegation will be refused.".to_string()
        } else {
            "The network does not enforce its list yet, so nothing but you stands between this code and your funds."
                .to_string()
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_listed_delegate_and_a_clearing_are_quiet() {
        let s = DelegateStatus::from_rpc(&json!({"allowlist_enforced": false, "listed": true})).unwrap();
        assert!(s.warning("ab").is_empty());
        let c = DelegateStatus::from_rpc(&json!({"allowlist_enforced": true, "listed": false, "clears": true})).unwrap();
        assert!(c.warning("00").is_empty());
    }

    #[test]
    fn an_unlisted_delegate_is_warned_about_either_way() {
        let open = DelegateStatus::from_rpc(&json!({"allowlist_enforced": false, "listed": false})).unwrap();
        let t = open.warning("0xabc").join(" ");
        assert!(t.contains("not on the network's list") && t.contains("does not enforce"), "{t}");
        let shut = DelegateStatus::from_rpc(&json!({"allowlist_enforced": true, "listed": false})).unwrap();
        assert!(shut.warning("abc").join(" ").contains("will be refused"));
        assert!(DelegateStatus::from_rpc(&json!({})).is_none());
    }
}
