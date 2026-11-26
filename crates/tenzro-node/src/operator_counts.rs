//! Distinct operators beside machine counts.
//!
//! A listing of validators or providers counts machines. How decentralised
//! the set is depends on how many parties stand behind them, so every such
//! listing also reports its operators: the root identity the chain derives
//! for each machine's account (`tenzro_vm::native::rewards::root_identity`,
//! the same derivation that decides whether the two sides of a payment are
//! one party). A machine a human or another machine delegated counts under
//! that root; a machine nobody delegated is its own operator, so one person
//! running several such machines reads as several operators. An account with
//! no identity on chain is counted apart and belongs to no operator.

use serde::{Deserialize, Serialize};
use tenzro_vm::traits::VmState;

/// The machines of a whole listing and the operators behind them.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct OperatorCounts {
    /// Entries in the whole listing, before paging.
    pub machines: usize,
    /// Distinct root identities behind the entries that have one.
    pub distinct_operators: usize,
    /// Entries whose account has no identity on chain.
    pub without_identity: usize,
}

/// The root id of the operator behind `did`.
pub(crate) fn operator_of_did(chain: &dyn VmState, did: &str) -> String {
    tenzro_vm::native::rewards::root_identity(chain, did)
}

/// The root id of the operator behind the account `address`; `None` when no
/// identity is registered to it.
pub(crate) fn operator_of_account(chain: &dyn VmState, address: &[u8]) -> Option<String> {
    tenzro_vm::native::identity_of_wallet(chain, address).map(|did| operator_of_did(chain, &did))
}

/// Counts over the operator of every entry of a listing.
pub(crate) fn count<'a>(operators: impl IntoIterator<Item = Option<&'a str>>) -> OperatorCounts {
    let mut distinct = std::collections::BTreeSet::new();
    let mut counts = OperatorCounts::default();
    for operator in operators {
        counts.machines += 1;
        match operator {
            Some(root) => {
                distinct.insert(root);
            }
            None => counts.without_identity += 1,
        }
    }
    counts.distinct_operators = distinct.len();
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machines_of_one_root_are_one_operator() {
        let mut chain = tenzro_vm::StateAdapter::new();
        for (who, did) in [
            (1u8, "did:tenzro:human:aa"),
            (2, "did:tenzro:machine:aa:m1"),
            (3, "did:tenzro:machine:aa:m2"),
            (4, "did:tenzro:machine:bb"),
        ] {
            chain.set_storage(
                &tenzro_vm::native::SYSTEM_ADDRESS,
                format!("identity_wallet:{}", hex::encode([who; 32])).as_bytes(),
                did.as_bytes().to_vec(),
            );
        }
        let operators: Vec<Option<String>> = (1u8..=5)
            .map(|who| operator_of_account(&chain, &[who; 32]))
            .collect();
        assert_eq!(operators[0].as_deref(), Some("aa"));
        assert_eq!(operators[1], operators[0]);
        assert_eq!(operators[2], operators[0]);
        assert_eq!(operators[3].as_deref(), Some("bb"));
        assert_eq!(operators[4], None);
        assert_eq!(
            count(operators.iter().map(Option::as_deref)),
            OperatorCounts {
                machines: 5,
                distinct_operators: 2,
                without_identity: 1,
            }
        );
        assert_eq!(count(std::iter::empty()), OperatorCounts::default());
    }
}
