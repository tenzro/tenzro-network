//! The delivery of an ERC-7786 gateway message to an EVM contract.
//!
//! Anyone may submit a delivery a governed route's committees attested. The
//! rules that admit it and call the contract it names are in `tenzro-vm`.

use serde::{Deserialize, Serialize};
use tenzro_types::bridge_route::{BridgeRouteAdapter, MAX_CHAIN_NAME_LEN};
use tenzro_types::bridge_transfer::MAX_BRIDGE_PAYLOAD_LEN;

/// The delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayDeliveryOp {
    /// Transport of the route.
    pub adapter: BridgeRouteAdapter,
    /// External chain the message comes from.
    pub source_chain: String,
    /// The delivery as the route's transport encodes it, hex.
    #[serde(with = "hex::serde")]
    pub delivery: Vec<u8>,
}

impl GatewayDeliveryOp {
    /// The chain is named and the delivery carries 1 byte to 256 KiB.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.source_chain.is_empty() || self.source_chain.len() > MAX_CHAIN_NAME_LEN {
            return Err("a gateway delivery names its source chain in 1 to 64 bytes");
        }
        if self.delivery.is_empty() || self.delivery.len() > MAX_BRIDGE_PAYLOAD_LEN {
            return Err("a gateway delivery carries 1 byte to 256 KiB");
        }
        Ok(())
    }
}
