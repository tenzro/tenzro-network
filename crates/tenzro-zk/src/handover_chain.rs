//! Proofs of the epoch handover chain.
//!
//! The handover program proves, one link at a time inside the RISC Zero
//! zkVM, that each epoch was handed over under the committee the previous
//! proof reached, verifying that previous proof as it goes. Its newest
//! receipt is succinct and carries no assumption, so it is checked here
//! alone, against the program's image id, and the journal it returns states
//! the chain from genesis to the epoch it reaches.

use risc0_zkvm::Receipt;
use risc0_zkvm::sha::Digest;

/// Checks that `receipt` (a bincode-encoded receipt) proves the program
/// `image_id` halted normally with nothing left assumed, and returns the
/// journal it committed.
pub fn verify_receipt(image_id: &[u8; 32], receipt: &[u8]) -> Result<Vec<u8>, String> {
    let receipt: Receipt =
        bincode::deserialize(receipt).map_err(|e| format!("the receipt does not decode: {e}"))?;
    receipt
        .verify(Digest::from(*image_id))
        .map_err(|e| e.to_string())?;
    Ok(receipt.journal.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_that_are_no_receipt_are_refused() {
        assert!(verify_receipt(&[1; 32], b"receipt").is_err());
        assert!(verify_receipt(&[1; 32], &[]).is_err());
    }
}
