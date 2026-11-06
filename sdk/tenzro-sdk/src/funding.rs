//! Network funding: grant requests and tranche releases.
//!
//! Every write is a signed `Funding` transaction whose gas the treasury pays,
//! so an identity with a zero balance can take part. Requests go to the
//! governance vote.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use serde_json::{Value, json};
use std::sync::Arc;

/// Funding client.
#[derive(Clone)]
pub struct FundingClient {
    rpc: Arc<RpcClient>,
}

impl FundingClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// A tranched grant (null when absent).
    pub async fn get_grant(&self, grant_id: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_getGrant",
                json!([{ "grant_id": grant_id.trim_start_matches("0x") }]),
            )
            .await
    }
}

/// Gas limit of a funding operation (paid by the treasury).
const FUNDING_GAS: u64 = 80_000;

/// How a grant's later tranches are released.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum GrantReleaseOption {
    /// Each later tranche needs a release proposal.
    #[default]
    Governed,
    /// Later tranches are released against milestones the named verifiers
    /// record; `threshold` distinct verifiers must record each.
    Scheduled {
        /// Verifier accounts (64 hex each).
        verifiers: Vec<String>,
        /// Distinct verifiers needed per milestone.
        threshold: u32,
    },
}

/// A request for a treasury grant, filed for the governance vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequest {
    /// Who is paid (64 hex).
    pub recipient: String,
    /// Total amount, smallest unit of the asset paid.
    pub amount: u128,
    /// Why.
    pub memo: String,
    /// Free category label.
    pub category: String,
    /// Link to the public write-up.
    pub link: String,
    /// Tranche amounts in order; empty pays `amount` at once.
    pub tranches: Vec<u128>,
    /// The milestone each payment is for, one per tranche (one without).
    pub milestones: Vec<String>,
    /// `liquid`, `grant` or `contributor`.
    pub vesting: String,
    /// A settlement token id (`0x` and 64 hex) to pay in a USD stable
    /// asset; `None` pays TNZO.
    pub asset: Option<String>,
    /// How later tranches are released.
    pub release: GrantReleaseOption,
}

fn account_bytes(account: &str) -> SdkResult<Vec<u8>> {
    let bytes = hex::decode(account.trim_start_matches("0x"))
        .map_err(|e| SdkError::InvalidParameter(format!("account is not hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(SdkError::InvalidParameter(format!(
            "account must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn funding_tx(op: Value) -> SdkResult<crate::TypedTransaction> {
    let bytes = serde_json::to_vec(&op)?;
    Ok(
        crate::TypedTransaction::new(crate::TxKind::Funding, json!({ "op": bytes }))?
            .gas_limit(FUNDING_GAS),
    )
}

/// The transaction that files a grant request: in tranches or at once, in
/// TNZO or a USD stable asset, released by governance or against verified
/// milestones.
pub fn request_grant(request: &GrantRequest) -> SdkResult<crate::TypedTransaction> {
    let mut action = json!({
        "action": "treasury_grant",
        "recipient": account_bytes(&request.recipient)?,
        "amount": request.amount.to_string(),
        "memo": request.memo,
        "category": request.category,
        "link": request.link,
        "tranches": request.tranches.iter().map(u128::to_string).collect::<Vec<_>>(),
        "milestones": request.milestones,
        "vesting": request.vesting,
    });
    if let Some(asset) = &request.asset {
        action["asset"] = json!(asset);
    }
    if let GrantReleaseOption::Scheduled {
        verifiers,
        threshold,
    } = &request.release
    {
        let verifiers = verifiers
            .iter()
            .map(|v| account_bytes(v))
            .collect::<SdkResult<Vec<_>>>()?;
        action["release"] = json!({
            "mode": "scheduled",
            "verifiers": verifiers,
            "threshold": threshold,
        });
    }
    funding_tx(json!({ "op": "request", "action": action }))
}

/// The transaction that files a request to release a grant's next tranche.
pub fn request_tranche(
    grant_id: &str,
    index: u32,
    memo: &str,
) -> SdkResult<crate::TypedTransaction> {
    funding_tx(json!({
        "op": "request",
        "action": {
            "action": "release_grant_tranche",
            "grant_id": grant_id.trim_start_matches("0x"),
            "index": index,
            "memo": memo,
        }
    }))
}

/// The transaction a named verifier sends to record that the milestone of
/// tranche `index` of a scheduled grant is met.
pub fn verify_milestone(
    grant_id: &str,
    index: u32,
    evidence: &str,
) -> SdkResult<crate::TypedTransaction> {
    funding_tx(json!({
        "op": "verify_milestone",
        "grant_id": grant_id.trim_start_matches("0x"),
        "index": index,
        "evidence": evidence,
    }))
}

/// The transaction that releases the next tranche of a scheduled grant
/// against its verified milestone. Anyone may send it.
pub fn release_milestone(grant_id: &str, index: u32) -> SdkResult<crate::TypedTransaction> {
    funding_tx(json!({
        "op": "release_milestone",
        "grant_id": grant_id.trim_start_matches("0x"),
        "index": index,
    }))
}
