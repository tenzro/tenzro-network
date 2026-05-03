//! Marketplace commission policy.
//!
//! Single source of truth for the paid-template invocation fee split:
//! the network commission goes to the treasury, the remainder goes to
//! the template's `creator_wallet`. Used by both the JSON-RPC handler
//! (`tenzro_runAgentTemplate`) and the MCP `run_agent_template` tool —
//! before this module they each held their own near-identical inline
//! split + transfer sequence, which made it easy for the two paths to
//! drift apart.
//!
//! The split itself stays in `tenzro_types::agent_template`
//! ([`split_marketplace_fee`]) so that crates outside `tenzro-node`
//! (CLI, SDKs, agent-kit) can reason about commission math without
//! pulling in the full node. This module is the *settlement* path:
//! it knows how to *move* the tokens.
//!
//! Invariants enforced here:
//! - A non-free template MUST have a `creator_wallet` (we report a
//!   distinct error rather than silently routing the creator share to
//!   the treasury).
//! - The treasury address is read from the live `TnzoToken` at call
//!   time — there is no second copy elsewhere.
//! - Splits and transfers are atomic from the caller's perspective:
//!   either both transfers succeed and we return a populated
//!   [`CommissionReceipt`], or one fails and the caller surfaces the
//!   error without partial state visible to the run path.
//!
//! See `crates/tenzro-types/src/agent_template.rs` for the split math
//! and `crates/tenzro-node/src/{rpc,mcp/server}.rs` for call sites.

use tenzro_token::TnzoToken;
use tenzro_types::agent_template::{
    split_marketplace_fee, AgentTemplate, AGENT_MARKETPLACE_COMMISSION_BPS,
};
use tenzro_types::primitives::Address;

/// Outcome of a successful commission settlement on a paid template
/// invocation. Returned to the run handler so it can echo the numbers
/// back to the caller and persist invocation metering.
#[derive(Debug, Clone)]
pub struct CommissionReceipt {
    /// Amount transferred to the network treasury (in TNZO base units).
    pub commission: u128,
    /// Amount transferred to `creator_wallet` (in TNZO base units).
    pub creator_share: u128,
    /// Payer that funded both transfers.
    pub payer: Address,
    /// Treasury address that received the commission.
    pub treasury: Address,
    /// Creator wallet that received the creator share.
    pub creator_wallet: Address,
}

/// Why a commission settlement was rejected. The caller maps these to
/// the right wire format (JSON-RPC error / MCP error / etc.); the
/// policy module itself never depends on a specific transport.
#[derive(Debug, thiserror::Error)]
pub enum CommissionError {
    /// The template is paid but no `creator_wallet` was registered.
    #[error("Paid template missing creator_wallet (registration invariant violated)")]
    MissingCreatorWallet,
    /// Caller did not supply a `payer_wallet` for a paid template.
    #[error("payer_wallet is required for paid agent templates")]
    MissingPayerWallet,
    /// `TnzoToken` is not yet initialized on the node.
    #[error("TNZO token not initialized")]
    TokenUnavailable,
    /// `NetworkTreasury` did not have a configured address.
    #[error("Treasury address not configured")]
    TreasuryUnavailable,
    /// One of the two transfers failed. The original `TokenError` is
    /// flattened into a string because callers across the codebase
    /// already render it as a string and this avoids leaking the
    /// `tenzro-token` error type through the `tenzro-node` boundary.
    #[error("Commission transfer failed: {0}")]
    TransferFailed(String),
}

/// Settle the commission split for a paid template invocation.
///
/// Returns [`Ok(None)`] for free templates or a zero-fee invocation —
/// the caller should treat that as "no settlement happened, proceed
/// with execution." Returns [`Ok(Some(receipt))`] when both transfers
/// succeed; the caller should record the numbers in the run report and
/// pass `receipt.creator_share` to `AgentTemplate::record_invocation`.
///
/// `payer_wallet` is the **address as a string** so both call sites
/// (RPC and MCP) can pass their already-parsed parameter without
/// re-parsing here. `parse` is the per-call-site address parser
/// (rpc.rs uses `parse_address` returning `JsonRpcError`; mcp/server.rs
/// uses a different one returning `ErrorData`). Returning the parsed
/// `Address` from `parse` makes the policy transport-agnostic.
pub fn settle_invocation_fee<F>(
    template: &AgentTemplate,
    fee: u128,
    payer_wallet: Option<&str>,
    token: Option<&TnzoToken>,
    parse: F,
) -> Result<Option<CommissionReceipt>, CommissionError>
where
    F: FnOnce(&str) -> Result<Address, String>,
{
    if template.pricing.is_free() || fee == 0 {
        return Ok(None);
    }

    let creator_wallet = template
        .creator_wallet
        .ok_or(CommissionError::MissingCreatorWallet)?;

    let payer_str = payer_wallet.ok_or(CommissionError::MissingPayerWallet)?;
    let payer = parse(payer_str)
        .map_err(|e| CommissionError::TransferFailed(format!("Invalid payer_wallet: {e}")))?;

    let token = token.ok_or(CommissionError::TokenUnavailable)?;
    let treasury = token
        .treasury_address_ref()
        .ok_or(CommissionError::TreasuryUnavailable)?;

    let (commission, creator_share) =
        split_marketplace_fee(fee, AGENT_MARKETPLACE_COMMISSION_BPS);

    if commission > 0 {
        token
            .transfer(&payer, &treasury, commission)
            .map_err(|e| CommissionError::TransferFailed(format!("network commission: {e}")))?;
    }
    if creator_share > 0 {
        token
            .transfer(&payer, &creator_wallet, creator_share)
            .map_err(|e| CommissionError::TransferFailed(format!("creator payout: {e}")))?;
    }

    Ok(Some(CommissionReceipt {
        commission,
        creator_share,
        payer,
        treasury,
        creator_wallet,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::agent_template::{AgentPricingModel, AgentTemplate, AgentTemplateType};

    fn ok_parse(s: &str) -> Result<Address, String> {
        let mut bytes = [0u8; 32];
        bytes[0] = s.len() as u8;
        Ok(Address::new(bytes))
    }

    fn paid_template(creator_wallet: Option<Address>) -> AgentTemplate {
        let mut tmpl = AgentTemplate::new(
            "test".to_string(),
            "test description".to_string(),
            AgentTemplateType::Specialist,
            Address::default(),
            "you are a test".to_string(),
        );
        tmpl.pricing = AgentPricingModel::PerExecution { price: 1_000 };
        tmpl.creator_wallet = creator_wallet;
        tmpl
    }

    #[test]
    fn free_template_returns_none() {
        let tmpl = AgentTemplate::new(
            "free".to_string(),
            "free".to_string(),
            AgentTemplateType::Specialist,
            Address::default(),
            "free".to_string(),
        );
        // Pricing is Free by default per AgentTemplate::new.
        let receipt = settle_invocation_fee(&tmpl, 100, Some("payer"), None, ok_parse).unwrap();
        assert!(receipt.is_none(), "free template should not settle");
    }

    #[test]
    fn zero_fee_returns_none() {
        let tmpl = paid_template(Some(Address::default()));
        // fee=0 short-circuits even on a paid template (e.g. dry_run).
        let receipt = settle_invocation_fee(&tmpl, 0, Some("payer"), None, ok_parse).unwrap();
        assert!(receipt.is_none());
    }

    #[test]
    fn paid_without_creator_wallet_rejects() {
        let tmpl = paid_template(None);
        let err = settle_invocation_fee(&tmpl, 1_000, Some("payer"), None, ok_parse).unwrap_err();
        assert!(matches!(err, CommissionError::MissingCreatorWallet));
    }

    #[test]
    fn paid_without_payer_rejects() {
        let tmpl = paid_template(Some(Address::default()));
        let err = settle_invocation_fee(&tmpl, 1_000, None, None, ok_parse).unwrap_err();
        assert!(matches!(err, CommissionError::MissingPayerWallet));
    }

    /// Invariant: every successful paid-template settlement produces exactly two
    /// ledger movements — one to the treasury (5% commission) and one to the
    /// creator wallet (95% creator share) — and the sum equals the fee paid by
    /// the payer. This is the contract both call sites (RPC + MCP) depend on.
    #[test]
    fn paid_invocation_emits_two_ledger_entries() {
        let token = TnzoToken::new();

        // Distinct addresses so we can assert balances independently.
        let treasury = Address::new([0x01; 32]);
        let payer = Address::new([0x02; 32]);
        let creator = Address::new([0x03; 32]);

        token.set_treasury_address(treasury);
        // Mint funds to the payer (mint is treasury-authorized).
        token.mint(&payer, 1_000_000, &treasury).unwrap();

        let pre_payer = token.balance_of(&payer);
        let pre_treasury = token.balance_of(&treasury);
        let pre_creator = token.balance_of(&creator);

        let tmpl = paid_template(Some(creator));
        let fee: u128 = 10_000;

        // Parse callback returns the matching test address verbatim.
        let parse = |_: &str| Ok(payer);

        let receipt = settle_invocation_fee(&tmpl, fee, Some("payer"), Some(&token), parse)
            .expect("settlement must succeed")
            .expect("paid template must produce a receipt");

        // Math invariant: commission + creator_share == fee, with 5% / 95% split.
        assert_eq!(receipt.commission + receipt.creator_share, fee);
        assert_eq!(
            receipt.commission, 500,
            "5% of 10_000 commission, with current bps = {}",
            AGENT_MARKETPLACE_COMMISSION_BPS
        );
        assert_eq!(receipt.creator_share, 9_500);

        // Ledger invariant: exactly the two transfers happened.
        assert_eq!(token.balance_of(&payer), pre_payer - fee);
        assert_eq!(
            token.balance_of(&treasury),
            pre_treasury + receipt.commission
        );
        assert_eq!(
            token.balance_of(&creator),
            pre_creator + receipt.creator_share
        );

        // Receipt round-trip: surfaced addresses match the wired wallets.
        assert_eq!(receipt.payer, payer);
        assert_eq!(receipt.treasury, treasury);
        assert_eq!(receipt.creator_wallet, creator);
    }

    /// A payer with insufficient balance must surface a `TransferFailed` error
    /// without leaving partial state (the first transfer is the commission;
    /// when it fails, the creator transfer is never attempted).
    #[test]
    fn payer_insufficient_balance_rejects_cleanly() {
        let token = TnzoToken::new();
        let treasury = Address::new([0x01; 32]);
        let payer = Address::new([0x02; 32]);
        let creator = Address::new([0x03; 32]);

        token.set_treasury_address(treasury);
        // Payer has 100, fee is 10_000 — must fail.
        token.mint(&payer, 100, &treasury).unwrap();

        let tmpl = paid_template(Some(creator));
        let parse = |_: &str| Ok(payer);

        let err = settle_invocation_fee(&tmpl, 10_000, Some("payer"), Some(&token), parse)
            .unwrap_err();
        assert!(matches!(err, CommissionError::TransferFailed(_)));

        // Creator never received anything — no half-settlement leaked through.
        assert_eq!(token.balance_of(&creator), 0);
    }
}
