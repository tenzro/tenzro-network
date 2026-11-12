//! On-chain governance.
//!
//! Proposals, votes, enactment and vetoes are signed transactions decided in
//! consensus, and voting weight is bonded stake. A proposal carries one
//! action, tagged by `action`: `policy_update` (economic policy, burn dial,
//! supply targets, protocol upgrade),
//! `parameter_change`, `treasury_grant`, `revoke_identity`, and the rest the
//! node documents. The read methods return what consensus holds.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

/// Governance client.
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let governance = client.governance();
/// let page = governance.list_proposals(20, None, Some("policy_update")).await?;
/// for p in page.proposals {
///     println!("{} {} yes={}", p.kind, p.proposal["id"], p.tally.yes);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct GovernanceClient {
    rpc: Arc<RpcClient>,
}

/// Running vote totals, in units of bonded stake (decimal strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tally {
    pub yes: String,
    pub no: String,
    pub total_eligible: String,
}

/// A proposal as consensus holds it: id, proposer, action, track, status,
/// voting deadline and, once passed, when it may be enacted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalView {
    pub proposal: Value,
    /// The action's kind, e.g. `policy_update`.
    pub kind: String,
    pub tally: Tally,
    /// TNZO holders have locked against it in its veto escrow (decimal string).
    #[serde(default)]
    pub veto_locked: String,
}

/// One page of proposals, newest first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalPage {
    pub proposals: Vec<ProposalView>,
    /// Proposals ever opened.
    pub total: u64,
    /// Pass as `before` for the next page; `None` on the last.
    pub next: Option<u64>,
}

/// The weight an account votes with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingPower {
    pub address: String,
    /// Bonded stake (decimal string).
    pub voting_power: String,
    /// Network-wide bonded stake a tally is measured against.
    pub total_bonded: String,
}

/// The governance-sponsored part of a validator's stake. Amounts are decimal
/// strings in the smallest unit; caps are whole TNZO, 0 disables sponsorship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsoredBond {
    pub address: String,
    /// The whole bond.
    pub bonded: String,
    /// The part the validator put up itself, the part that votes.
    pub own_bonded: String,
    /// Treasury TNZO bonded on its behalf.
    pub sponsored_bonded: String,
    /// Recalled or exiting sponsored stake, still slashable, owed to the
    /// treasury.
    pub sponsored_unbonding: String,
    /// Sponsored stake out of the treasury network-wide.
    pub sponsored_outstanding_total: String,
    /// `validator.sponsored_bond_max_tnzo`.
    pub max_per_validator_tnzo: u64,
    /// `validator.sponsored_bond_total_max_tnzo`.
    pub max_total_tnzo: u64,
}

/// Every disbursement of treasury sponsorship and grants, the governed caps
/// and, for one address, its approvals. Amounts are decimal strings in the
/// smallest unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryPayouts {
    /// Disbursements logged so far.
    pub count: u64,
    /// Paid per class: validator, provider, developer, contributor, community.
    pub by_class: std::collections::BTreeMap<String, String>,
    /// The page asked for, oldest first.
    pub records: Vec<PayoutRecord>,
    /// The governed caps; 0 disables.
    pub caps: PayoutCaps,
    /// Present when an address was asked about.
    pub address: Option<PayoutAddress>,
}

/// One disbursement of sponsorship or a grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutRecord {
    pub n: u64,
    /// `bond_sponsorship`, `running_cost` or `grant`.
    pub kind: String,
    pub recipient: String,
    /// `validator`, `provider`, `developer`, `contributor` or `community`.
    pub class: String,
    pub amount: String,
    /// The proposal that enacted or released it.
    pub proposal_id: String,
    /// The milestone or the verified hours it was paid against.
    pub milestone: String,
    pub at_ms: i64,
}

/// The governed caps on sponsorship and grants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutCaps {
    pub sponsorship_yearly_max_tnzo: u64,
    pub running_cost_per_verified_epoch_wei: u64,
    pub per_grantee_yearly_max_tnzo: u64,
    pub combined_yearly_max_tnzo: u64,
}

/// One address's approvals and what it has been paid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutAddress {
    pub address: String,
    pub total_received: String,
    /// The operator approval and its criteria, when there is one.
    pub operator: Option<serde_json::Value>,
    /// The grantee approval and its criteria, when there is one.
    pub grantee: Option<serde_json::Value>,
}

fn id(proposal_id: &str) -> String {
    proposal_id.trim_start_matches("0x").to_string()
}

impl GovernanceClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Proposals newest first, optionally only one action `kind`.
    pub async fn list_proposals(
        &self,
        limit: u64,
        before: Option<u64>,
        kind: Option<&str>,
    ) -> SdkResult<ProposalPage> {
        self.rpc
            .call(
                "tenzro_listProposals",
                json!([{ "limit": limit, "before": before, "kind": kind }]),
            )
            .await
    }

    /// One proposal and its tally, or `None`.
    pub async fn get_proposal(&self, proposal_id: &str) -> SdkResult<Option<ProposalView>> {
        self.rpc
            .call(
                "tenzro_getProposal",
                json!([{ "proposal_id": id(proposal_id) }]),
            )
            .await
    }

    /// The treasury's keyless accounts on other chains, each with the last
    /// remote grant an enacted proposal wrote for it.
    pub async fn get_treasury_accounts(&self) -> SdkResult<TreasuryAccounts> {
        self.rpc
            .call("tenzro_getTreasuryAccounts", json!([{}]))
            .await
    }

    /// Every guardian and Foundation steward seat, the enactment pause, the
    /// steward treasury hold, the guardian threshold, the steward sunset and
    /// seat cap and, with an address, the seat it holds and whether it is
    /// live.
    pub async fn get_guardian_state(&self, address: Option<&str>) -> SdkResult<Value> {
        let params = match address {
            Some(a) => json!([{ "address": a }]),
            None => json!([{}]),
        };
        self.rpc.call("tenzro_getGuardianState", params).await
    }

    /// The bonded stake `address` votes with.
    pub async fn get_voting_power(&self, address: &str) -> SdkResult<VotingPower> {
        self.rpc
            .call("tenzro_getVotingPower", json!([{ "address": address }]))
            .await
    }

    /// The governance-sponsored part of a validator's stake, bonded and
    /// unbonding, and the governed caps.
    pub async fn get_sponsored_bond(&self, address: &str) -> SdkResult<SponsoredBond> {
        self.rpc
            .call("tenzro_getSponsoredBond", json!([{ "address": address }]))
            .await
    }

    /// Every sponsorship and grant disbursement by recipient and class, the
    /// governed caps, and with `address` its approvals and total received.
    pub async fn get_treasury_payouts(
        &self,
        address: Option<&str>,
        offset: u64,
        limit: u64,
    ) -> SdkResult<TreasuryPayouts> {
        self.rpc
            .call(
                "tenzro_getTreasuryPayouts",
                json!([{ "address": address, "offset": offset, "limit": limit }]),
            )
            .await
    }

    /// The last enacted change of a network policy `kind`
    /// (`economic_policy`, `adaptive_burn_config`, `supply_targets`,
    /// `protocol_upgrade`), with the proposal that decided it. `Null` while
    /// the genesis setting stands.
    pub async fn get_policy(&self, kind: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getPolicy", json!([{ "kind": kind }]))
            .await
    }

    /// A proposal's governance receipt: the proposal, tally, veto escrow and
    /// decision records (and an upgrade's readiness and activation), each
    /// with a state proof under a certified checkpoint, and that
    /// checkpoint's proof from genesis. Check it offline with
    /// `tenzro governance receipt --verify`.
    pub async fn get_governance_receipt(&self, proposal_id: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_getGovernanceReceipt",
                json!([{ "proposal_id": proposal_id }]),
            )
            .await
    }

    /// The typed preimage a privileged transaction (an unsigned transaction
    /// as JSON) is signed over, with its digest and what it does in words.
    /// The digest is recomputed here from the returned preimage bytes, and a
    /// mismatch is refused, so the words shown are those of the preimage
    /// that is signed.
    pub async fn decode_action(&self, transaction: Value) -> SdkResult<Value> {
        use sha2::{Digest, Sha256};
        let decoded: Value = self
            .rpc
            .call(
                "tenzro_decodeAction",
                json!([{ "transaction": transaction }]),
            )
            .await?;
        let preimage = decoded["preimage_hex"]
            .as_str()
            .and_then(|h| hex::decode(h).ok())
            .ok_or_else(|| {
                crate::error::SdkError::RpcError("decodeAction returned no preimage".into())
            })?;
        if hex::encode(Sha256::digest(&preimage)) != decoded["digest"].as_str().unwrap_or_default()
        {
            return Err(crate::error::SdkError::RpcError(
                "decodeAction returned a digest that is not the preimage's".into(),
            ));
        }
        let parsed: Value = serde_json::from_slice(&preimage)
            .map_err(|e| crate::error::SdkError::RpcError(format!("decodeAction preimage: {e}")))?;
        if parsed["action"] != transaction["tx_type"] {
            return Err(crate::error::SdkError::RpcError(
                "decodeAction described another action than the one given".into(),
            ));
        }
        Ok(decoded)
    }

    /// Which validators' machines have quoted the binary `code_hash` (hex
    /// SHA-256), their share of bonded stake against the share a protocol
    /// upgrade needs, and the activation consensus scheduled last.
    pub async fn get_upgrade_readiness(&self, code_hash: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_getUpgradeReadiness",
                json!([{ "code_hash": code_hash }]),
            )
            .await
    }

    /// Every governed network parameter from chain state (fees, slashing
    /// rates, bonds, windows, caps), or the one named `key`: value, bounds,
    /// genesis value, the direction that tightens it, its capture-guard
    /// direction (`capture_guard`: a change against it moves one step and
    /// waits the guard grace), and any enacted change waiting for its epoch.
    /// Values are decimal strings.
    pub async fn get_network_params(&self, key: Option<&str>) -> SdkResult<Value> {
        let params = match key {
            Some(key) => json!({ "key": key }),
            None => json!({}),
        };
        self.rpc.call("tenzro_getNetworkParams", params).await
    }

    /// Every governance lever, or those of one `area` (fees, bridge, roles,
    /// keystore, zk, consensus...): kind (status, switch or value), value,
    /// status, bounds, and any enacted change waiting with the epoch it
    /// activates in; plus each bridge route's mode after its transport's
    /// lever.
    pub async fn list_levers(&self, area: Option<&str>) -> SdkResult<Value> {
        let params = match area {
            Some(area) => json!({ "area": area }),
            None => json!({}),
        };
        self.rpc.call("tenzro_listLevers", params).await
    }
}

/// A proposal to change one governed network parameter, ready to sign and
/// send with [`crate::TypedTxClient`]. The node refuses it at submission when
/// `value` is outside the parameter's bounds; once enacted the value applies
/// from the next epoch, or after the tightening grace window when it asks
/// more of those the rule binds.
pub fn parameter_change_proposal(
    key: &str,
    value: u64,
    memo: &str,
) -> SdkResult<crate::TypedTransaction> {
    let action = json!({ "action": "parameter_change", "key": key, "value": value, "memo": memo });
    let proposal = serde_json::to_vec(&action)?;
    Ok(crate::TypedTransaction::new(
        crate::TxKind::GovernancePropose,
        json!({ "proposal": proposal }),
    )?
    .gas_limit(100_000))
}

fn address_bytes(validator: &str) -> SdkResult<Vec<u8>> {
    let bytes = hex::decode(validator.trim_start_matches("0x")).map_err(|e| {
        crate::error::SdkError::InvalidParameter(format!("validator is not hex: {e}"))
    })?;
    if bytes.len() != 32 {
        return Err(crate::error::SdkError::InvalidParameter(format!(
            "validator must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn proposal_tx(action: Value) -> SdkResult<crate::TypedTransaction> {
    let proposal = serde_json::to_vec(&action)?;
    Ok(crate::TypedTransaction::new(
        crate::TxKind::GovernancePropose,
        json!({ "proposal": proposal }),
    )?
    .gas_limit(100_000))
}

/// A proposal to bond `amount` (smallest unit) of existing treasury TNZO on
/// a registered validator's behalf. It counts toward the bond and is
/// slashable, never votes, earns nothing and returns to the treasury on
/// recall or exit. The node refuses it while the governed caps are zero.
pub fn sponsor_validator_bond_proposal(
    validator: &str,
    amount: u128,
    memo: &str,
) -> SdkResult<crate::TypedTransaction> {
    proposal_tx(json!({
        "action": "sponsor_validator_bond",
        "validator": address_bytes(validator)?,
        "amount": amount.to_string(),
        "memo": memo,
    }))
}

/// A proposal to recall `amount` of a validator's sponsored bond: it unbonds,
/// still slashable, and then returns to the treasury.
pub fn recall_sponsored_bond_proposal(
    validator: &str,
    amount: u128,
    memo: &str,
) -> SdkResult<crate::TypedTransaction> {
    proposal_tx(json!({
        "action": "recall_sponsored_bond",
        "validator": address_bytes(validator)?,
        "amount": amount.to_string(),
        "memo": memo,
    }))
}

/// A proposal to approve an operator (`validator` or `provider`) for
/// sponsorship. The chain checks the machine identity holds a recognised TPM
/// endorsement and counts its verified-available hours in the history named.
#[allow(clippy::too_many_arguments)]
pub fn approve_operator_proposal(
    operator: &str,
    class: &str,
    provider_did: &str,
    region: &str,
    history_from_epoch: u64,
    history_to_epoch: u64,
    independence: &str,
    link: &str,
    memo: &str,
) -> SdkResult<crate::TypedTransaction> {
    proposal_tx(json!({
        "action": "approve_operator",
        "operator": address_bytes(operator)?,
        "class": class,
        "criteria": {
            "provider_did": provider_did,
            "region": region,
            "history_from_epoch": history_from_epoch,
            "history_to_epoch": history_to_epoch,
            "independence": independence,
            "link": link,
        },
        "memo": memo,
    }))
}

/// A proposal to revoke an operator's approval; every later payment is
/// refused.
pub fn revoke_operator_proposal(operator: &str, memo: &str) -> SdkResult<crate::TypedTransaction> {
    proposal_tx(json!({
        "action": "revoke_operator",
        "operator": address_bytes(operator)?,
        "memo": memo,
    }))
}

/// A proposal to return a jailed validator to candidacy at the next epoch
/// boundary, ahead of the end of its jail term. It is admitted again like any
/// candidate; slashing is not undone. For a validator that is not jailed it
/// does nothing.
pub fn reinstate_validator_proposal(
    validator: &str,
    memo: &str,
) -> SdkResult<crate::TypedTransaction> {
    proposal_tx(json!({
        "action": "reinstate_validator",
        "validator": address_bytes(validator)?,
        "memo": memo,
    }))
}

/// A proposal to approve a grantee (`developer`, `contributor` or
/// `community`) to receive grants. The grantee must hold a registered
/// identity.
pub fn approve_grantee_proposal(
    grantee: &str,
    class: &str,
    summary: &str,
    link: &str,
    memo: &str,
) -> SdkResult<crate::TypedTransaction> {
    proposal_tx(json!({
        "action": "approve_grantee",
        "grantee": address_bytes(grantee)?,
        "class": class,
        "criteria": { "summary": summary, "link": link },
        "memo": memo,
    }))
}

/// A proposal to revoke a grantee's approval; every later tranche is
/// refused.
pub fn revoke_grantee_proposal(grantee: &str, memo: &str) -> SdkResult<crate::TypedTransaction> {
    proposal_tx(json!({
        "action": "revoke_grantee",
        "grantee": address_bytes(grantee)?,
        "memo": memo,
    }))
}

/// A proposal to pay an approved operator `amount` (smallest unit) of its
/// running cost out of the treasury, against its verified-available hours in
/// `from_epoch` to `to_epoch`. Each verified hour backs one payment.
pub fn sponsor_operator_running_cost_proposal(
    operator: &str,
    from_epoch: u64,
    to_epoch: u64,
    amount: u128,
    memo: &str,
) -> SdkResult<crate::TypedTransaction> {
    proposal_tx(json!({
        "action": "sponsor_operator_running_cost",
        "operator": address_bytes(operator)?,
        "from_epoch": from_epoch,
        "to_epoch": to_epoch,
        "amount": amount.to_string(),
        "memo": memo,
    }))
}

/// A proposal to pay an approved operator `amount` (the asset's smallest
/// unit) of its running cost in the USD stable asset `token_id`, against its
/// verified-available hours in `from_epoch` to `to_epoch`. The value is in
/// dollars, so a falling TNZO price does not shrink what an hour is worth.
/// `period_exception` asks for the governed per-payment headroom above the
/// period outflow limit.
pub fn sponsor_operator_stable_proposal(
    operator: &str,
    from_epoch: u64,
    to_epoch: u64,
    token_id: &str,
    amount: u128,
    period_exception: bool,
    memo: &str,
) -> SdkResult<crate::TypedTransaction> {
    proposal_tx(json!({
        "action": "sponsor_operator_stable",
        "operator": address_bytes(operator)?,
        "from_epoch": from_epoch,
        "to_epoch": to_epoch,
        "token_id": token_id,
        "amount": amount.to_string(),
        "period_exception": period_exception,
        "memo": memo,
    }))
}

/// The transaction that returns a validator's matured unbonding sponsored
/// stake to the treasury. Anyone may send it.
pub fn release_sponsored_bond(validator: &str) -> SdkResult<crate::TypedTransaction> {
    Ok(crate::TypedTransaction::new(
        crate::TxKind::SponsoredBond,
        json!({ "op": { "release": { "validator": address_bytes(validator)? } } }),
    )?
    .gas_limit(60_000))
}

/// What a verified governance receipt establishes, read from its proven
/// records only.
#[derive(Debug, Clone, PartialEq)]
pub struct GovernanceReceiptReport {
    /// The proposal record, as consensus stores it.
    pub proposal: Value,
    /// The tally record, if a vote was cast.
    pub tally: Option<Value>,
    /// TNZO locked in the veto escrow, base units.
    pub veto_locked: u128,
    /// Height the proposal was enacted at, if it was.
    pub executed_height: Option<u64>,
    /// The scheduled activation, for an enacted protocol upgrade.
    pub activation: Option<Value>,
}

/// Checks a governance receipt (as `tenzro_getGovernanceReceipt` returns it)
/// offline, against the state root of a checkpoint the caller holds as
/// certified (from a light client, the finality verifier, or
/// `tenzro governance receipt --verify`, which proves the receipt's
/// checkpoint from the genesis anchor). Every record must be proven under
/// that root and be about the receipt's proposal, the proposal, tally, veto
/// and decision records must all be proven (present or absent), and a
/// decision must be of exactly the proven proposal record. Nothing the node
/// says is trusted.
pub fn verify_governance_receipt(
    receipt: &Value,
    certified_state_root: &[u8; 32],
) -> SdkResult<GovernanceReceiptReport> {
    let root = receipt_proof::hex32(&receipt["state_root"], "state_root")?;
    if &root != certified_state_root {
        return Err(receipt_proof::bad(
            "the receipt names another state root than the certified one",
        ));
    }
    let id = receipt["proposal_id"]
        .as_str()
        .ok_or_else(|| receipt_proof::bad("no proposal_id"))?;
    let mut values: std::collections::HashMap<String, Option<Vec<u8>>> =
        std::collections::HashMap::new();
    for r in receipt["records"]
        .as_array()
        .ok_or_else(|| receipt_proof::bad("no records"))?
    {
        let kind = r["kind"]
            .as_str()
            .ok_or_else(|| receipt_proof::bad("a record has no kind"))?;
        if r["subject"].as_str() != Some(id) {
            return Err(receipt_proof::bad(format!(
                "a {kind} record is about another proposal"
            )));
        }
        let value = match &r["value"] {
            Value::Null => None,
            v => Some(
                v.as_str()
                    .and_then(|h| hex::decode(h).ok())
                    .ok_or_else(|| receipt_proof::bad(format!("the {kind} value is not hex")))?,
            ),
        };
        let slot = r["slot"]
            .as_str()
            .ok_or_else(|| receipt_proof::bad("a record has no slot"))?;
        let key = receipt_proof::system_slot_tree_key(slot.as_bytes());
        if !receipt_proof::verify(&root, &key, value.as_deref(), &r["proof"])? {
            return Err(receipt_proof::bad(format!(
                "the {kind} record is not proven under the certified root"
            )));
        }
        if values.insert(kind.to_string(), value).is_some() {
            return Err(receipt_proof::bad(format!(
                "the receipt carries two {kind} records"
            )));
        }
    }
    let proposal_bytes = values
        .get("proposal")
        .cloned()
        .flatten()
        .ok_or_else(|| receipt_proof::bad("the receipt proves no proposal record"))?;
    let proposal: Value = serde_json::from_slice(&proposal_bytes)
        .map_err(|_| receipt_proof::bad("the proposal record is not JSON"))?;
    if proposal["id"].as_str() != Some(id) {
        return Err(receipt_proof::bad(
            "the proposal record is of another proposal",
        ));
    }
    for kind in ["tally", "veto_total", "decision"] {
        if !values.contains_key(kind) {
            return Err(receipt_proof::bad(format!(
                "the receipt does not prove the {kind} record"
            )));
        }
    }
    let executed_height = match values.get("decision").cloned().flatten() {
        Some(v) if v.len() == 40 => {
            use sha2::Digest as _;
            if v[..32] != sha2::Sha256::digest(&proposal_bytes)[..] {
                return Err(receipt_proof::bad(
                    "the decision record is not of the proven proposal record",
                ));
            }
            if proposal["status"] != "executed" {
                return Err(receipt_proof::bad(
                    "a decision is recorded for a proposal that is not executed",
                ));
            }
            Some(u64::from_be_bytes(
                v[32..].try_into().expect("length checked"),
            ))
        }
        Some(_) => return Err(receipt_proof::bad("the decision record is malformed")),
        None => None,
    };
    let json = |k: &str| {
        values
            .get(k)
            .cloned()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
    };
    let veto_locked = values
        .get("veto_total")
        .cloned()
        .flatten()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .map(u128::from_le_bytes)
        .unwrap_or(0);
    Ok(GovernanceReceiptReport {
        tally: json("tally"),
        activation: json("activation"),
        proposal,
        veto_locked,
        executed_height,
    })
}

/// State proofs under a state root, by the rules of the chain's state trie
/// (SHA-256 throughout): an entry's 32-byte tree key is a 31-byte stem (a
/// path of 248 bits) and a slot byte; a proof is the sibling hashes down the
/// path and where the path ends.
mod receipt_proof {
    use crate::error::{SdkError, SdkResult};
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    const STEM_LEN: usize = 31;
    const EMPTY: [u8; 32] = [0u8; 32];
    const SYSTEM_ADDRESS_HEX: &str = "ffffffffffffffffffffffffffffffffffffffff";

    pub(super) fn bad(msg: impl Into<String>) -> SdkError {
        SdkError::InvalidParameter(format!("governance receipt: {}", msg.into()))
    }

    fn sha(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    pub(super) fn hex32(v: &Value, what: &str) -> SdkResult<[u8; 32]> {
        v.as_str()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad(format!("{what} is not 32 bytes of hex")))
    }

    fn bytes<const N: usize>(v: &Value, what: &str) -> SdkResult<[u8; N]> {
        let out: Option<Vec<u8>> = match v {
            Value::String(h) => hex::decode(h).ok(),
            Value::Array(a) => a
                .iter()
                .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect(),
            _ => None,
        };
        out.and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad(format!("{what} is not {N} bytes")))
    }

    /// The tree key of system storage slot `slot`: the committed key is
    /// `storage:<system account hex>:<hex of the slot>` in namespace `state`.
    pub(super) fn system_slot_tree_key(slot: &[u8]) -> [u8; 32] {
        let key = format!("storage:{SYSTEM_ADDRESS_HEX}:{}", hex::encode(slot));
        sha(&[
            b"tenzro.state-trie.key",
            &5u16.to_le_bytes(),
            b"state",
            key.as_bytes(),
        ])
    }

    fn bit(stem: &[u8], depth: usize) -> u8 {
        (stem[depth / 8] >> (7 - (depth % 8))) & 1
    }

    fn slot_pair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        if *l == EMPTY && *r == EMPTY {
            return EMPTY;
        }
        sha(&[&[0x03], l, r])
    }

    /// Whether, under `root`, the entry with tree key `tk` holds `value`
    /// (`Some`) or is absent (`None`), by `proof` as the node serves it.
    pub(super) fn verify(
        root: &[u8; 32],
        tk: &[u8; 32],
        value: Option<&[u8]>,
        proof: &Value,
    ) -> SdkResult<bool> {
        let siblings = proof["siblings"]
            .as_array()
            .ok_or_else(|| bad("a proof has no siblings"))?;
        let siblings: Vec<[u8; 32]> = siblings
            .iter()
            .map(|s| bytes::<32>(s, "a sibling"))
            .collect::<SdkResult<_>>()?;
        if siblings.len() > STEM_LEN * 8 {
            return Ok(false);
        }
        let depth = siblings.len();
        let stem = &tk[..STEM_LEN];
        let terminal = &proof["terminal"];
        let mut acc = if terminal == "Empty" {
            if value.is_some() {
                return Ok(false);
            }
            EMPTY
        } else if let Some(other) = terminal.get("OtherStem") {
            let other_stem = bytes::<STEM_LEN>(&other["stem"], "a stem")?;
            let slots_root = bytes::<32>(&other["slots_root"], "a slots root")?;
            if value.is_some()
                || other_stem == stem
                || !(0..depth).all(|d| bit(&other_stem, d) == bit(stem, d))
            {
                return Ok(false);
            }
            sha(&[&[0x02], &other_stem, &slots_root])
        } else if let Some(own) = terminal.get("Stem") {
            let slot_siblings = own["slot_siblings"]
                .as_array()
                .filter(|s| s.len() == 8)
                .ok_or_else(|| bad("a stem proof needs 8 slot siblings"))?;
            let mut s = value.map(|v| sha(&[&[0x00], v])).unwrap_or(EMPTY);
            let mut index = tk[STEM_LEN] as usize;
            for sib in slot_siblings {
                let sib = bytes::<32>(sib, "a slot sibling")?;
                s = if index & 1 == 0 {
                    slot_pair(&s, &sib)
                } else {
                    slot_pair(&sib, &s)
                };
                index >>= 1;
            }
            if s == EMPTY {
                return Ok(false);
            }
            sha(&[&[0x02], stem, &s])
        } else {
            return Err(bad("a proof has an unknown terminal"));
        };
        for d in (0..depth).rev() {
            let sib = &siblings[d];
            acc = if bit(stem, d) == 0 {
                sha(&[&[0x01], &acc, sib])
            } else {
                sha(&[&[0x01], sib, &acc])
            };
        }
        Ok(&acc == root)
    }
}

impl GovernanceClient {
    /// Calls `tenzro_signalUpgradeReady`: signal upgrade ready.
    pub async fn signal_upgrade_ready(
        &self,
        code_hash: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_signalUpgradeReady",
                serde_json::json!({ "code_hash": code_hash }),
            )
            .await
    }
}

/// `tenzro_getTreasuryAccounts`: the network treasury and its keyless
/// accounts on other chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryAccounts {
    /// The treasury's DID.
    pub did: String,
    /// The treasury's account on Tenzro, hex.
    pub tenzro: String,
    /// One entry per chain the treasury holds an account on.
    pub accounts: Vec<TreasuryAccount>,
    /// How the treasury holds bitcoin.
    #[serde(default)]
    pub bitcoin: Option<String>,
}

/// The treasury's account on one chain, or why it has none.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryAccount {
    /// The chain, CAIP-2.
    pub caip2: String,
    /// The account address on that chain.
    #[serde(default)]
    pub address: Option<String>,
    /// The account, CAIP-10.
    #[serde(default)]
    pub caip10: Option<String>,
    /// The last remote grant an enacted proposal wrote for it.
    #[serde(default)]
    pub grant: Option<TreasuryGrant>,
    /// Why the account could not be derived.
    #[serde(default)]
    pub error: Option<String>,
}

/// A remote grant on a treasury account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryGrant {
    /// The grant's sequence number.
    pub seq: u64,
    /// The hash of the granted payload, hex.
    pub payload_hash: String,
    /// The budget (smallest unit, decimal).
    pub amount: String,
    /// When it lapses, Unix milliseconds.
    pub not_after_ms: u64,
    /// Whether it was voided.
    pub void: bool,
}

#[cfg(test)]
mod proposal_tests {
    use super::*;

    fn action(tx: &crate::TypedTransaction) -> Value {
        let bytes: Vec<u8> =
            serde_json::from_value(tx.fields["proposal"].clone()).expect("proposal bytes");
        serde_json::from_slice(&bytes).expect("the proposal is JSON")
    }

    #[test]
    fn reinstate_validator_carries_the_account_as_32_bytes() {
        let tx = reinstate_validator_proposal(&format!("0x{}", "ab".repeat(32)), "wrongly jailed")
            .unwrap();
        assert_eq!(
            action(&tx),
            json!({ "action": "reinstate_validator", "validator": vec![0xabu8; 32], "memo": "wrongly jailed" })
        );
    }

    #[test]
    fn reinstate_validator_refuses_a_malformed_account() {
        for bad in ["ab".repeat(31), "zz".repeat(32), String::new()] {
            assert!(
                reinstate_validator_proposal(&bad, "memo").is_err(),
                "{bad:?}"
            );
        }
    }
}
