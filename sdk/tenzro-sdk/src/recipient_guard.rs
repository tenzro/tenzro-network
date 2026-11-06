//! Recipient checks before a transfer is signed: first-time recipient friction
//! and look-alike (address poisoning) detection. The same rules as the node's
//! `tenzro_types::recipient_guard` and the TypeScript and Python SDKs; the
//! byte counts are the governed parameters
//! `wallet.recipient_lookalike_prefix_bytes` and
//! `wallet.recipient_lookalike_suffix_bytes`, read from
//! `tenzro_getNetworkParams`. Pure: it never signs and never holds a key.

use serde::{Deserialize, Serialize};

/// Governed parameter: leading bytes that must match for a look-alike.
pub const PREFIX_BYTES_PARAM: &str = "wallet.recipient_lookalike_prefix_bytes";
/// Governed parameter: trailing bytes that must match for a look-alike.
pub const SUFFIX_BYTES_PARAM: &str = "wallet.recipient_lookalike_suffix_bytes";
/// Genesis value of [`PREFIX_BYTES_PARAM`].
pub const DEFAULT_PREFIX_BYTES: u64 = 3;
/// Genesis value of [`SUFFIX_BYTES_PARAM`].
pub const DEFAULT_SUFFIX_BYTES: u64 = 3;

/// How alike two addresses must be to count as a look-alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookalikeParams {
    /// Leading bytes that must match.
    pub prefix_bytes: usize,
    /// Trailing bytes that must match.
    pub suffix_bytes: usize,
}

impl LookalikeParams {
    /// Build from the two governed values; a missing one falls back to genesis.
    pub fn from_governed(prefix: Option<u64>, suffix: Option<u64>) -> Self {
        Self {
            prefix_bytes: prefix.unwrap_or(DEFAULT_PREFIX_BYTES) as usize,
            suffix_bytes: suffix.unwrap_or(DEFAULT_SUFFIX_BYTES) as usize,
        }
    }
}

impl Default for LookalikeParams {
    fn default() -> Self {
        Self::from_governed(None, None)
    }
}

/// One reason a recipient needs more than a single click.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientFlag {
    /// This account has never paid this address and it is not a contact.
    FirstTimeRecipient,
    /// The address shares its ends with a trusted address but is not it.
    LooksLike {
        /// The trusted address it imitates, as lowercase hex.
        trusted: String,
    },
    /// The address only ever sent to this account.
    SeenOnlyAsInboundSender,
}

/// The result of checking one recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientAssessment {
    /// The recipient as lowercase hex without `0x`, never shortened.
    pub full_address: String,
    /// Reasons for friction; empty for a trusted recipient.
    pub flags: Vec<RecipientFlag>,
}

fn norm(a: &str) -> String {
    a.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase()
}

fn alike(a: &str, b: &str, p: &LookalikeParams) -> bool {
    if a == b || a.len() != b.len() {
        return false;
    }
    let pre = (p.prefix_bytes * 2).min(a.len());
    let suf = (p.suffix_bytes * 2).min(a.len());
    if pre + suf == 0 {
        return false;
    }
    a[..pre] == b[..pre] && a[a.len() - suf..] == b[b.len() - suf..]
}

impl RecipientAssessment {
    /// Whether the user must type the full address before the sign button.
    pub fn requires_full_address_confirmation(&self) -> bool {
        !self.flags.is_empty()
    }

    /// Whether a look-alike was found.
    pub fn is_lookalike(&self) -> bool {
        self.flags
            .iter()
            .any(|f| matches!(f, RecipientFlag::LooksLike { .. }))
    }

    /// Plain-language lines for the confirmation screen.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = vec![format!("Recipient: 0x{}", self.full_address)];
        for f in &self.flags {
            lines.push(match f {
                RecipientFlag::FirstTimeRecipient => {
                    "First payment to this address from this account: compare every character."
                        .to_string()
                }
                RecipientFlag::LooksLike { trusted } => format!(
                    "This address looks like a trusted one (0x{trusted}) but is a different \
                     address. This is how address poisoning works: do not send unless you \
                     meant this one."
                ),
                RecipientFlag::SeenOnlyAsInboundSender => "This address has only ever sent to \
                     you. Copying an address from your history is how address poisoning works."
                    .to_string(),
            });
        }
        lines
    }

    /// Whether `typed` is the full address; a shortened form never matches.
    pub fn confirmation_matches(&self, typed: &str) -> bool {
        norm(typed) == self.full_address
    }
}

/// Check `recipient` against trusted addresses and those that only sent to the account.
pub fn assess_recipient(
    recipient: &str,
    trusted: &[String],
    inbound_only: &[String],
    params: &LookalikeParams,
) -> RecipientAssessment {
    let to = norm(recipient);
    let trusted: Vec<String> = trusted.iter().map(|t| norm(t)).collect();
    let mut flags = Vec::new();
    if !trusted.contains(&to) {
        flags.push(RecipientFlag::FirstTimeRecipient);
        if let Some(t) = trusted.iter().find(|t| alike(&to, t, params)) {
            flags.push(RecipientFlag::LooksLike { trusted: t.clone() });
        }
        if inbound_only.iter().any(|a| norm(a) == to) {
            flags.push(RecipientFlag::SeenOnlyAsInboundSender);
        }
    }
    RecipientAssessment {
        full_address: to,
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(first: &str, mid: &str, last: &str) -> String {
        format!("0x{first}{}{last}", mid.repeat(26))
    }

    #[test]
    fn trusted_recipient_has_no_friction() {
        let t = addr("010203", "09", "070809");
        let a = assess_recipient(&t, &[t.clone()], &[], &LookalikeParams::default());
        assert!(!a.requires_full_address_confirmation());
    }

    #[test]
    fn first_time_recipient_is_flagged() {
        let a = assess_recipient(
            &addr("010203", "09", "070809"),
            &[],
            &[],
            &Default::default(),
        );
        assert_eq!(a.flags, vec![RecipientFlag::FirstTimeRecipient]);
    }

    #[test]
    fn poisoned_lookalike_is_flagged() {
        let real = addr("010203", "09", "070809");
        let fake = addr("010203", "05", "070809");
        let a = assess_recipient(&fake, &[real.clone()], &[fake.clone()], &Default::default());
        assert!(a.is_lookalike());
        assert!(a.flags.contains(&RecipientFlag::SeenOnlyAsInboundSender));
        assert_eq!(a.full_address.len(), 64);
        assert!(a.describe().iter().any(|l| l.contains("poisoning")));
    }

    #[test]
    fn different_ends_and_zero_width_never_match() {
        let real = addr("010203", "09", "070809");
        let other = addr("040203", "05", "070809");
        assert!(
            !assess_recipient(&other, &[real.clone()], &[], &Default::default()).is_lookalike()
        );
        let fake = addr("010203", "05", "070809");
        let zero = LookalikeParams {
            prefix_bytes: 0,
            suffix_bytes: 0,
        };
        assert!(!assess_recipient(&fake, &[real], &[], &zero).is_lookalike());
    }

    #[test]
    fn only_the_full_address_confirms() {
        let r = addr("010203", "09", "070809");
        let a = assess_recipient(&r, &[], &[], &Default::default());
        assert!(a.confirmation_matches(&r.to_uppercase().replace("0X", "0x")));
        assert!(!a.confirmation_matches(&r[..30]));
        assert!(!a.confirmation_matches(""));
    }
}
