//! A validator bond bought with a stable settlement asset.
//!
//! The caller pays `units` of a stable settlement asset to the treasury and
//! the treasury pays TNZO for it straight into the caller's validator bond.
//! The rule that prices it and holds it to its caps is in `tenzro-vm`.

use serde::{Deserialize, Serialize};

/// The purchase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondWithStableOp {
    /// The stable asset's token id, 32 bytes, hex.
    #[serde(with = "hex::serde")]
    pub asset: Vec<u8>,
    /// What the caller pays, in the asset's smallest unit; a decimal string.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub units: u128,
    /// The least TNZO, base units, the caller accepts for it; a decimal
    /// string. The purchase is refused below it.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub min_tnzo: u128,
}

impl BondWithStableOp {
    /// The asset id is 32 bytes and something is paid.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.asset.len() != 32 {
            return Err("a bond purchase names the 32-byte token id of a stable settlement asset");
        }
        if self.units == 0 {
            return Err("a bond purchase pays something");
        }
        Ok(())
    }
}
