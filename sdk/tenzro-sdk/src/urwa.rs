//! ERC-7943 (uRWA) client — universal Real-World Asset compliance.
//!
//! Tenzro implements ERC-7943, the canonical 2026 standard for
//! tokenized real-world assets that must respect regulator orders,
//! legal-entity mandates, and routine compliance (KYC-refresh-pending
//! sub-balance freeze).
//!
//! Read-only RPCs:
//! - `tenzro_urwaIsKillSwitched` — global kill-switch state per token.
//! - `tenzro_urwaGetFrozenTokens` — per-(token, account) frozen amount.
//!
//! The issuer's controls (freezing part of a holder's balance, halting
//! transfers, forced transfers) are `Token` transactions the issuer signs
//! ([`crate::typed_tx`]); these reads see their effect
//! in chain state.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct UrwaClient {
    rpc: Arc<RpcClient>,
}

impl UrwaClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Read-only check whether the kill-switch is active for the
    /// given 32-byte `token_id`.
    pub async fn is_kill_switched(
        &self,
        token_id_hex: impl Into<String>,
    ) -> SdkResult<UrwaKillSwitchState> {
        self.rpc
            .call(
                "tenzro_urwaIsKillSwitched",
                serde_json::json!([{
                    "token_id_hex": token_id_hex.into(),
                }]),
            )
            .await
    }

    /// Read-only frozen-amount lookup for a `(token_id, account)` pair.
    pub async fn get_frozen_tokens(
        &self,
        token_id_hex: impl Into<String>,
        account_hex: impl Into<String>,
    ) -> SdkResult<UrwaFrozenAmount> {
        self.rpc
            .call(
                "tenzro_urwaGetFrozenTokens",
                serde_json::json!([{
                    "token_id_hex": token_id_hex.into(),
                    "account_hex": account_hex.into(),
                }]),
            )
            .await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrwaKillSwitchState {
    pub token_id_hex: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrwaFrozenAmount {
    pub token_id_hex: String,
    pub account_hex: String,
    pub frozen_amount: String,
}
