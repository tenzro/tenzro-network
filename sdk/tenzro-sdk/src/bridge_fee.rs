//! Bridge fee in TNZO client.
//!
//! Converts a destination-native bridge fee into TNZO at the USD rates
//! validators commit on chain. A quote is refused while the destination's
//! native asset is unpriced.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct BridgeFeeClient {
    rpc: Arc<RpcClient>,
}

impl BridgeFeeClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Quote a destination-native bridge fee in TNZO.
    /// `adapter` is the route transport (`ccip`, `ibc`, `deposit` or `contract`); `dest_chain` is the
    /// CAIP-2 identifier (e.g. `eip155:1`).
    pub async fn quote(&self, req: QuoteBridgeFeeRequest) -> SdkResult<QuoteBridgeFeeResponse> {
        self.rpc
            .call("tenzro_quoteBridgeFeeInTnzo", serde_json::json!([req]))
            .await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteBridgeFeeRequest {
    pub adapter: String,
    pub dest_chain: String,
    pub native_fee_smallest_unit: String,
}

/// A destination-native fee and the TNZO that pays it at committed rates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteBridgeFeeResponse {
    pub quote_id_hex: String,
    pub adapter: String,
    pub dest_chain: String,
    pub native_symbol: String,
    pub native_fee_smallest_unit: String,
    pub tnzo_amount_wei: String,
    pub native_rate_nano_usd: String,
    pub tnzo_rate_nano_usd: String,
    pub rate_epoch: Option<u64>,
    pub issued_at_ms: u64,
    pub valid_until_ms: u64,
}
