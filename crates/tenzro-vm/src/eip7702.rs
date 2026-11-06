//! EIP-7702 delegation designators.
//!
//! A delegation is installed only by a standard EIP-7702 transaction
//! (`TransactionType::ExternalEvm`): executing its authorization list writes
//! the designator `0xef0100 || target` into the authority's code. These
//! helpers read that designator back from account code.

use crate::account_abstraction::parse_7702_designator;

/// Returns `true` iff `code` is a 23-byte 7702 designator (`0xef0100 || 20 bytes`).
pub fn is_delegation_designator(code: &[u8]) -> bool {
    parse_7702_designator(code).is_some()
}

/// Extract the delegation target from a 23-byte designator. Returns `None`
/// if `code` is not a valid 7702 designator.
pub fn extract_delegation_target(code: &[u8]) -> Option<[u8; 20]> {
    let raw = parse_7702_designator(code)?;
    if raw.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_abstraction::build_7702_designator;

    #[test]
    fn designator_roundtrip() {
        let target = [0x42u8; 20];
        let bytes = build_7702_designator(&target).unwrap();
        assert_eq!(bytes.len(), 23);
        assert!(is_delegation_designator(&bytes));
        assert_eq!(extract_delegation_target(&bytes), Some(target));
    }

    #[test]
    fn non_designator_rejected() {
        assert!(!is_delegation_designator(&[0xef, 0x01, 0x00]));
        assert!(extract_delegation_target(&[0xef, 0x01, 0x01]).is_none());
    }
}
