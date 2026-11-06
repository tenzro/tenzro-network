//! Wallet-side recipient checks: the pure logic lives in
//! [`tenzro_types::recipient_guard`]; this module feeds it from the wallet's
//! own address book and transaction history.

use crate::contacts::AddressBook;
use crate::history::{TransactionHistory, TxDirection};
use std::collections::HashSet;
use tenzro_types::primitives::Address;
pub use tenzro_types::recipient_guard::{
    assess_recipient, LookalikeParams, RecipientAssessment, RecipientFlag,
};

/// [`assess_recipient`] fed from this wallet's address book and history. An
/// address is trusted when it is a contact or when this wallet has already
/// sent to it; it is inbound-only when it appears only as a sender.
pub fn assess_for_wallet(
    book: &AddressBook,
    history: &TransactionHistory,
    owner: &Address,
    recipient: &Address,
    params: &LookalikeParams,
) -> RecipientAssessment {
    let mut trusted: Vec<Address> = book.list_all().into_iter().map(|c| c.address).collect();
    let mut senders: HashSet<Address> = HashSet::new();
    for r in history.get_history(owner) {
        match r.direction {
            TxDirection::Outgoing => trusted.push(r.to),
            TxDirection::Incoming => {
                senders.insert(r.from);
            }
            TxDirection::Internal => {}
        }
    }
    let inbound_only: Vec<Address> = senders
        .into_iter()
        .filter(|a| !trusted.contains(a))
        .collect();
    assess_recipient(recipient, &trusted, &inbound_only, params)
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
    fn contacts_are_trusted() {
        let book = AddressBook::new();
        let c = addr([1, 2, 3], 9, [7, 8, 9]);
        book.add_contact(crate::contacts::Contact::new("alice".into(), c))
            .unwrap();
        let hist = TransactionHistory::new();
        let owner = Address::new([0xAA; 32]);
        let ok = assess_for_wallet(&book, &hist, &owner, &c, &LookalikeParams::default());
        assert!(ok.flags.is_empty());
        let fake = addr([1, 2, 3], 5, [7, 8, 9]);
        let bad = assess_for_wallet(&book, &hist, &owner, &fake, &LookalikeParams::default());
        assert!(bad.is_lookalike());
    }
}
