//! Recipient checks before a transfer is signed: first-time recipient
//! friction and look-alike (address poisoning) detection.
//!
//! Address poisoning plants an address that shares its first and last bytes
//! with one the user really pays, usually through a zero or dust inbound
//! transfer, so that a copy from the history or a glance at the shortened
//! form picks the attacker's address. This module is pure: it never signs and
//! never holds a key. A wallet front end calls [`assess_recipient`]  before it offers the signing prompt and shows the
//! result next to the full recipient address.
//!
//! The thresholds are a [`LookalikeParams`] passed in by the caller. The two byte counts are the governed parameters
//! [`PREFIX_BYTES_PARAM`] and [`SUFFIX_BYTES_PARAM`]; the CLI and the SDKs read
//! them from `tenzro_getNetworkParams`, and `Default` is the value genesis
//! writes, not a limit baked into the protocol.

use crate::primitives::Address;
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
    /// Build from the two governed values as `tenzro_getNetworkParams`
    /// returns them; a value that is not a number falls back to genesis.
    pub fn from_governed(prefix: Option<u64>, suffix: Option<u64>) -> Self {
        Self {
            prefix_bytes: prefix.unwrap_or(DEFAULT_PREFIX_BYTES) as usize,
            suffix_bytes: suffix.unwrap_or(DEFAULT_SUFFIX_BYTES) as usize,
        }
    }
}

impl Default for LookalikeParams {
    fn default() -> Self {
        // Three bytes at each end is six hex characters per side, which is
        // more than the shortened forms wallets usually show.
        Self {
            prefix_bytes: DEFAULT_PREFIX_BYTES as usize,
            suffix_bytes: DEFAULT_SUFFIX_BYTES as usize,
        }
    }
}

/// One reason a recipient needs more than a single click.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientFlag {
    /// This wallet has never sent to this address and it is not a contact.
    FirstTimeRecipient,
    /// The address shares its ends with a trusted address but is not it.
    LooksLike {
        /// The trusted address it imitates.
        trusted: Address,
    },
    /// The address only ever appeared as a sender to this wallet, never as a
    /// recipient: the shape of a planted history entry.
    SeenOnlyAsInboundSender,
}

/// The result of checking one recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientAssessment {
    /// The recipient checked.
    pub recipient: Address,
    /// Reasons for friction; empty for a trusted recipient.
    pub flags: Vec<RecipientFlag>,
    /// The full address in hex, for display and for the user to compare. It
    /// is never shortened.
    pub full_address: String,
}

impl RecipientAssessment {
    /// Whether the front end must make the user re-enter or compare the full
    /// address before it offers the sign button.
    pub fn requires_full_address_confirmation(&self) -> bool {
        !self.flags.is_empty()
    }

    /// Whether a look-alike was found. A front end should refuse to default
    /// the send button for this one and show the trusted address beside it.
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
                    "First payment to this address from this wallet: compare every character."
                        .to_string()
                }
                RecipientFlag::LooksLike { trusted } => format!(
                    "This address looks like a trusted one (0x{}) but is a different address. \
                     This is how address poisoning works: do not send unless you meant this one.",
                    hex::encode(trusted.as_bytes())
                ),
                RecipientFlag::SeenOnlyAsInboundSender => {
                    "This address has only ever sent to you. Copying an address from your \
                     history is how address poisoning works."
                        .to_string()
                }
            });
        }
        lines
    }
}

/// Whether `typed` is the assessed recipient's full address, ignoring case,
/// whitespace and a leading `0x`. A shortened form never matches.
pub fn confirmation_matches(assessment: &RecipientAssessment, typed: &str) -> bool {
    let t = typed.trim().trim_start_matches("0x").to_ascii_lowercase();
    t == assessment.full_address
}

fn alike(a: &Address, b: &Address, p: &LookalikeParams) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a == b || a.len() != b.len() {
        return false;
    }
    let (pre, suf) = (p.prefix_bytes.min(a.len()), p.suffix_bytes.min(a.len()));
    if pre + suf == 0 {
        return false;
    }
    a[..pre] == b[..pre] && a[a.len() - suf..] == b[b.len() - suf..]
}

/// Check `recipient` against the addresses this wallet trusts (contacts and
/// past recipients) and those that only ever sent to it.
pub fn assess_recipient(
    recipient: &Address,
    trusted: &[Address],
    inbound_only: &[Address],
    params: &LookalikeParams,
) -> RecipientAssessment {
    let mut flags = Vec::new();
    let is_trusted = trusted.iter().any(|t| t == recipient);
    if !is_trusted {
        flags.push(RecipientFlag::FirstTimeRecipient);
        if let Some(t) = trusted.iter().find(|t| alike(recipient, t, params)) {
            flags.push(RecipientFlag::LooksLike { trusted: *t });
        }
        if inbound_only.iter().any(|a| a == recipient) {
            flags.push(RecipientFlag::SeenOnlyAsInboundSender);
        }
    }
    RecipientAssessment {
        recipient: *recipient,
        flags,
        full_address: hex::encode(recipient.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(first: [u8; 3], mid: u8, last: [u8; 3]) -> Address {
        let mut b = [mid; 32];
        b[..3].copy_from_slice(&first);
        b[29..].copy_from_slice(&last);
        Address::new(b)
    }

    #[test]
    fn trusted_recipient_has_no_friction() {
        let t = addr([1, 2, 3], 9, [7, 8, 9]);
        let a = assess_recipient(&t, &[t], &[], &LookalikeParams::default());
        assert!(a.flags.is_empty());
        assert!(!a.requires_full_address_confirmation());
    }

    #[test]
    fn first_time_recipient_is_flagged() {
        let a = assess_recipient(
            &addr([1, 2, 3], 9, [7, 8, 9]),
            &[],
            &[],
            &LookalikeParams::default(),
        );
        assert_eq!(a.flags, vec![RecipientFlag::FirstTimeRecipient]);
        assert!(a.requires_full_address_confirmation());
    }

    #[test]
    fn poisoned_lookalike_is_flagged_with_the_trusted_address() {
        let real = addr([1, 2, 3], 9, [7, 8, 9]);
        let fake = addr([1, 2, 3], 5, [7, 8, 9]);
        let a = assess_recipient(&fake, &[real], &[fake], &LookalikeParams::default());
        assert!(a.is_lookalike());
        assert!(a
            .flags
            .contains(&RecipientFlag::LooksLike { trusted: real }));
        assert!(a.flags.contains(&RecipientFlag::SeenOnlyAsInboundSender));
        assert!(a.describe().iter().any(|l| l.contains("poisoning")));
        assert_eq!(a.full_address.len(), 64);
    }

    #[test]
    fn different_ends_are_not_a_lookalike() {
        let real = addr([1, 2, 3], 9, [7, 8, 9]);
        let other = addr([4, 2, 3], 5, [7, 8, 9]);
        let a = assess_recipient(&other, &[real], &[], &LookalikeParams::default());
        assert!(!a.is_lookalike());
    }

    #[test]
    fn zero_width_params_never_match() {
        let real = addr([1, 2, 3], 9, [7, 8, 9]);
        let fake = addr([1, 2, 3], 5, [7, 8, 9]);
        let p = LookalikeParams {
            prefix_bytes: 0,
            suffix_bytes: 0,
        };
        assert!(!assess_recipient(&fake, &[real], &[], &p).is_lookalike());
    }

    #[test]
    fn only_the_full_address_confirms() {
        let r = addr([1, 2, 3], 9, [7, 8, 9]);
        let a = assess_recipient(&r, &[], &[], &LookalikeParams::default());
        let full = format!("0x{}", a.full_address.to_uppercase());
        assert!(confirmation_matches(&a, &full));
        assert!(confirmation_matches(&a, &format!(" {} ", a.full_address)));
        assert!(!confirmation_matches(&a, &a.full_address[..40]));
        assert!(!confirmation_matches(&a, ""));
    }

    #[test]
    fn governed_values_fall_back_to_genesis() {
        assert_eq!(
            LookalikeParams::from_governed(None, None),
            LookalikeParams::default()
        );
        let p = LookalikeParams::from_governed(Some(2), Some(5));
        assert_eq!((p.prefix_bytes, p.suffix_bytes), (2, 5));
    }
}
