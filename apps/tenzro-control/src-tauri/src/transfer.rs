//! Sending TNZO out of the operator's wallet.
//!
//! The operator's account is the ledger account of this machine's hardware
//! key (TPM 2.0 or Secure Enclave). A send is a native `Transfer`
//! transaction from it, built with the SDK's typed-transaction builder,
//! signed inside the hardware and submitted to the embedded node, which
//! admits it to consensus like any other transaction. Value moves only in
//! consensus; this process never changes a balance itself.

use serde::Serialize;

use crate::config::Custody;
use crate::state::AppState;
use crate::wallet::format_tnzo;

/// What a completed send reports back to the UI.
#[derive(Debug, Clone, Serialize)]
pub struct SendReceipt {
    pub custody: Custody,
    pub from: String,
    pub to: String,
    pub amount_wei: String,
    pub amount_display: String,
    /// Transaction hash, hex with an `0x` prefix.
    pub reference: String,
}

/// Decode an `0x`-prefixed hex address into its raw bytes, insisting on
/// one of the two lengths the ledger recognises.
fn parse_recipient(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Recipient address is empty".to_string());
    }
    let hex_part = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex_part)
        .map_err(|e| format!("Recipient address is not valid hex: {}", e))?;
    match bytes.len() {
        20 | 32 => Ok(bytes),
        n => Err(format!(
            "Recipient address must be 20 or 32 bytes, got {}",
            n
        )),
    }
}

/// The `Transfer` of `amount_wei` to `to`, built with the SDK's
/// typed-transaction builder, and the recipient's 32-byte ledger slot.
fn transfer_tx(to: &str, amount_wei: u128) -> Result<(tenzro_sdk::TypedTransaction, [u8; 32]), String> {
    if amount_wei == 0 {
        return Err("Amount must be greater than zero".to_string());
    }
    let mut recipient = parse_recipient(to)?;
    recipient.resize(32, 0);
    let to_slot: [u8; 32] = recipient.try_into().map_err(|_| "recipient is 32 bytes".to_string())?;
    let mut tx = crate::native_tx::typed(&tenzro_types::transaction::TransactionType::Transfer { amount: amount_wei })?;
    tx.to = Some(tenzro_sdk::types::Address::new(to_slot));
    Ok((tx, to_slot))
}

/// Send `amount_wei` to `to` from the operator's account.
pub async fn send(
    state: &AppState,
    to: &str,
    amount_wei: u128,
) -> Result<SendReceipt, String> {
    let (tx, to_slot) = transfer_tx(to, amount_wei)?;
    let identity = crate::config::get().identity;
    if identity.custody != Custody::Hardware || identity.address.is_empty() {
        return Err("No wallet is set up yet".to_string());
    }
    let (node, signer) = crate::native_tx::ready(state).await?;
    if !identity.address.eq_ignore_ascii_case(&signer.address()) {
        return Err("The wallet on record is not this machine's hardware key's account".to_string());
    }
    let sent = crate::native_tx::send_typed(node, &signer, &tx).await?;
    let reference = sent
        .hash
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| sent.hash.to_string());
    Ok(SendReceipt {
        custody: Custody::Hardware,
        from: identity.address,
        to: format!("0x{}", hex::encode(to_slot)),
        amount_wei: amount_wei.to_string(),
        amount_display: format_tnzo(amount_wei),
        reference,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_both_ledger_address_widths() {
        assert_eq!(parse_recipient(&format!("0x{}", "ab".repeat(20))).unwrap().len(), 20);
        assert_eq!(parse_recipient(&"cd".repeat(32)).unwrap().len(), 32);
    }

    #[test]
    fn rejects_anything_else() {
        assert!(parse_recipient("").is_err());
        assert!(parse_recipient("0xzz").is_err());
        assert!(parse_recipient(&format!("0x{}", "ab".repeat(19))).is_err());
    }

    #[test]
    fn a_zero_amount_is_refused_before_anything_is_signed() {
        let err = transfer_tx(&format!("0x{}", "ab".repeat(32)), 0).unwrap_err();
        assert!(err.contains("greater than zero"));
    }

    #[test]
    fn a_short_recipient_is_padded_to_its_ledger_slot() {
        let (tx, slot) = transfer_tx(&format!("0x{}", "ab".repeat(20)), 7).unwrap();
        let mut expected = [0u8; 32];
        expected[..20].copy_from_slice(&[0xab; 20]);
        assert_eq!(slot, expected);
        assert_eq!(tx.to, Some(tenzro_sdk::types::Address::new(expected)));
    }

    /// A send is a native `Transfer` from the hardware key's account, carrying
    /// the amount and recipient, submitted to the embedded node.
    #[tokio::test]
    async fn a_send_submits_a_transfer_from_the_hardware_account() {
        use crate::native_tx::tests::{in_process_node, signer, submitted_tx, SUBMITTED};
        use tenzro_types::transaction::TransactionType;
        use tenzro_vm::traits::VmState as _;

        let tmp = tempfile::tempdir().unwrap();
        let node = in_process_node(&tmp).await;
        let machine = signer(41);
        let from = tenzro_types::primitives::Address::from_hex(&machine.address()).unwrap();
        let mut state = tenzro_vm::StateAdapter::with_storage(node.storage().expect("node storage").clone());
        state.set_balance(from.as_bytes(), 1_000_000_000_000_000_000);
        state.commit().expect("commit funded balance");

        let recipient = format!("0x{}", "cd".repeat(32));
        let (tx, slot) = transfer_tx(&recipient, 1_234).unwrap();
        crate::native_tx::send_typed(node.clone(), &machine, &tx).await.unwrap();

        let sent = SUBMITTED
            .lock()
            .unwrap()
            .iter()
            .map(submitted_tx)
            .rfind(|t| t.from == from)
            .expect("the transfer was submitted");
        assert!(matches!(sent.tx_type, TransactionType::Transfer { amount: 1_234 }));
        assert_eq!(sent.to.as_bytes(), &slot);
    }
}
