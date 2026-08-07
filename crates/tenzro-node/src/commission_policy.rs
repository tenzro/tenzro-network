//! Marketplace commission policy.
//!
//! Single source of truth for paid-invocation fee splits across all
//! three Tenzro marketplaces (agent templates, skills, tools): the
//! marketplace commission goes to the treasury, the remainder goes to the
//! creator's `creator_wallet`. Used by the JSON-RPC handlers
//! (`tenzro_runAgentTemplate`, `tenzro_useSkill`, `tenzro_useTool`)
//! and the MCP `run_agent_template` tool — before this module they
//! each held their own near-identical inline split + transfer
//! sequence, which made it easy for the paths to drift apart.
//!
//! The split itself stays in `tenzro_types::marketplace`
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

use crate::app_registry::AppRecord;
use tenzro_token::TnzoToken;
use tenzro_types::agent_template::AgentTemplate;
use tenzro_types::fees::apply_developer_margin;
use tenzro_types::marketplace::split_marketplace_fee;
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
    /// Payer that funded the transfers.
    pub payer: Address,
    /// Treasury address that received the commission.
    pub treasury: Address,
    /// Creator wallet that received the creator share.
    pub creator_wallet: Address,
    /// App the invocation was attributed to, when the caller passed an
    /// `app_id` that resolved to an active [`AppRecord`].
    pub app_id: Option<String>,
    /// Developer margin applied on top of the network fee, in basis
    /// points. Zero when no app was attributed.
    pub margin_bps: u32,
    /// Amount transferred to the app wallet as developer margin (in
    /// TNZO base units). Zero when no app was attributed. The payer's
    /// total debit is `commission + creator_share + margin_amount`.
    pub margin_amount: u128,
    /// App wallet that received the margin, when one was attributed.
    pub app_wallet: Option<Address>,
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
    /// One of the transfers failed. The original `TokenError` is
    /// flattened into a string because callers across the codebase
    /// already render it as a string and this avoids leaking the
    /// `tenzro-token` error type through the `tenzro-node` boundary.
    #[error("Commission transfer failed: {0}")]
    TransferFailed(String),
    /// The attributed app's margin could not be applied. Registration
    /// already caps `margin_bps` at the protocol constant, so this only
    /// fires on a corrupt record or arithmetic overflow — an internal
    /// invariant violation, not a caller mistake.
    #[error("Developer margin rejected: {0}")]
    MarginRejected(String),
}

/// Marketplace-agnostic settlement primitive. Splits `fee` using
/// `commission_bps` — read from the live economic policy by the caller, so a
/// governance change reaches the marketplace at the same moment it reaches
/// every other charging path — and moves the two halves on the live
/// TNZO ledger. Used by all three marketplace surfaces (agent
/// templates, skills, tools) via thin wrappers.
///
/// Returns [`Ok(None)`] for a zero `fee` — the caller should treat
/// that as "no settlement happened, proceed with execution." Returns
/// [`Ok(Some(receipt))`] when both transfers succeed; the caller
/// should record the numbers in its per-marketplace report.
///
/// `payer_wallet` is the **address as a string** so each call site can
/// pass its already-parsed parameter without re-parsing here. `parse`
/// is the per-call-site address parser (rpc.rs uses `parse_address`
/// returning `JsonRpcError`; mcp/server.rs uses one returning
/// `ErrorData`). Returning the parsed `Address` from `parse` makes the
/// policy transport-agnostic.
///
/// `app` is the resolved app attribution for developer-margin billing.
/// When present, the payer's total debit becomes
/// `fee × (1 + margin_bps/10000)` and the margin on top of `fee` is
/// transferred to the app's `app_wallet` in the same settlement. The
/// margin never enters the network fee split — commission and creator
/// share are computed over `fee` alone, so the burn/reward accounting
/// is unaffected by attribution. When `app` is `None` the behavior is
/// byte-identical to an unattributed invocation.
pub fn settle_paid_invocation<F>(
    creator_wallet: Option<Address>,
    fee: u128,
    commission_bps: u16,
    payer_wallet: Option<&str>,
    token: Option<&TnzoToken>,
    app: Option<&AppRecord>,
    parse: F,
) -> Result<Option<CommissionReceipt>, CommissionError>
where
    F: FnOnce(&str) -> Result<Address, String>,
{
    if fee == 0 {
        return Ok(None);
    }

    let creator_wallet = creator_wallet.ok_or(CommissionError::MissingCreatorWallet)?;

    let payer_str = payer_wallet.ok_or(CommissionError::MissingPayerWallet)?;
    let payer = parse(payer_str)
        .map_err(|e| CommissionError::TransferFailed(format!("Invalid payer_wallet: {e}")))?;

    let token = token.ok_or(CommissionError::TokenUnavailable)?;
    let treasury = token
        .treasury_address_ref()
        .ok_or(CommissionError::TreasuryUnavailable)?;

    let (margin_amount, margin_bps, app_id, app_wallet) = match app {
        Some(record) => {
            let user_pays = apply_developer_margin(fee, record.margin_bps).ok_or_else(|| {
                CommissionError::MarginRejected(format!(
                    "app {} margin_bps {} exceeds protocol cap or overflows on fee {}",
                    record.app_id, record.margin_bps, fee
                ))
            })?;
            (
                user_pays - fee,
                record.margin_bps,
                Some(record.app_id.clone()),
                Some(record.app_wallet),
            )
        }
        None => (0u128, 0u32, None, None),
    };

    let (commission, creator_share) = split_marketplace_fee(fee, commission_bps);

    if commission > 0 {
        token
            .transfer(&payer, &treasury, commission)
            .map_err(|e| CommissionError::TransferFailed(format!("marketplace commission: {e}")))?;
    }
    if creator_share > 0 {
        token
            .transfer(&payer, &creator_wallet, creator_share)
            .map_err(|e| CommissionError::TransferFailed(format!("creator payout: {e}")))?;
    }
    if margin_amount > 0 {
        let wallet = app_wallet.expect("margin_amount > 0 implies an attributed app");
        token
            .transfer(&payer, &wallet, margin_amount)
            .map_err(|e| CommissionError::TransferFailed(format!("developer margin: {e}")))?;
    }

    Ok(Some(CommissionReceipt {
        commission,
        creator_share,
        payer,
        treasury,
        creator_wallet,
        app_id,
        margin_bps,
        margin_amount,
        app_wallet,
    }))
}

/// Settle the commission split for a paid template invocation. Thin
/// wrapper around [`settle_paid_invocation`] that short-circuits free
/// templates (whose pricing is encoded as `AgentPricingModel::Free`
/// rather than a zero numeric fee, so we need the type-level check).
pub fn settle_invocation_fee<F>(
    template: &AgentTemplate,
    fee: u128,
    commission_bps: u16,
    payer_wallet: Option<&str>,
    token: Option<&TnzoToken>,
    app: Option<&AppRecord>,
    parse: F,
) -> Result<Option<CommissionReceipt>, CommissionError>
where
    F: FnOnce(&str) -> Result<Address, String>,
{
    if template.pricing.is_free() {
        return Ok(None);
    }
    settle_paid_invocation(
        template.creator_wallet,
        fee,
        commission_bps,
        payer_wallet,
        token,
        app,
        parse,
    )
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
        let receipt =
            settle_invocation_fee(&tmpl, 100, 500, Some("payer"), None, None, ok_parse).unwrap();
        assert!(receipt.is_none(), "free template should not settle");
    }

    #[test]
    fn zero_fee_returns_none() {
        let tmpl = paid_template(Some(Address::default()));
        // fee=0 short-circuits even on a paid template (e.g. dry_run).
        let receipt =
            settle_invocation_fee(&tmpl, 0, 500, Some("payer"), None, None, ok_parse).unwrap();
        assert!(receipt.is_none());
    }

    #[test]
    fn paid_without_creator_wallet_rejects() {
        let tmpl = paid_template(None);
        let err = settle_invocation_fee(&tmpl, 1_000, 500, Some("payer"), None, None, ok_parse)
            .unwrap_err();
        assert!(matches!(err, CommissionError::MissingCreatorWallet));
    }

    #[test]
    fn paid_without_payer_rejects() {
        let tmpl = paid_template(Some(Address::default()));
        let err = settle_invocation_fee(&tmpl, 1_000, 500, None, None, None, ok_parse).unwrap_err();
        assert!(matches!(err, CommissionError::MissingPayerWallet));
    }

    /// Invariant: every successful paid-template settlement produces exactly two
    /// ledger movements — one to the treasury (the governance-set marketplace
    /// commission) and one to the
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

        let receipt =
            settle_invocation_fee(&tmpl, fee, 500, Some("payer"), Some(&token), None, parse)
                .expect("settlement must succeed")
                .expect("paid template must produce a receipt");

        // Math invariant: commission + creator_share == fee, with 5% / 95% split.
        assert_eq!(receipt.commission + receipt.creator_share, fee);
        assert_eq!(
            receipt.commission, 500,
            "5% of 10_000 commission, with current bps = {}",
            500
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

        // Unattributed invocation carries zeroed margin fields.
        assert_eq!(receipt.app_id, None);
        assert_eq!(receipt.margin_bps, 0);
        assert_eq!(receipt.margin_amount, 0);
        assert_eq!(receipt.app_wallet, None);
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

        let err =
            settle_invocation_fee(&tmpl, 10_000, 500, Some("payer"), Some(&token), None, parse)
                .unwrap_err();
        assert!(matches!(err, CommissionError::TransferFailed(_)));

        // Creator never received anything — no half-settlement leaked through.
        assert_eq!(token.balance_of(&creator), 0);
    }

    fn app_record(margin_bps: u32, app_wallet: Address) -> crate::app_registry::AppRecord {
        crate::app_registry::AppRecord {
            app_id: "app-test".to_string(),
            developer_did: "did:tenzro:human:dev".to_string(),
            app_wallet,
            signing_pubkeys: Vec::new(),
            margin_bps,
            min_balance: 0,
            created_at: 0,
            active: true,
        }
    }

    /// Invariant: an attributed invocation debits the payer
    /// `fee × (1 + margin_bps/10000)` and routes the margin to the app
    /// wallet, while commission + creator share stay computed over the
    /// network fee alone — attribution never changes the network split
    /// (so burn/reward accounting is untouched).
    #[test]
    fn attributed_invocation_routes_margin_to_app_wallet() {
        let token = TnzoToken::new();
        let treasury = Address::new([0x01; 32]);
        let payer = Address::new([0x02; 32]);
        let creator = Address::new([0x03; 32]);
        let app_wallet = Address::new([0x04; 32]);

        token.set_treasury_address(treasury);
        token.mint(&payer, 1_000_000, &treasury).unwrap();
        let pre_payer = token.balance_of(&payer);
        let pre_treasury = token.balance_of(&treasury);

        let tmpl = paid_template(Some(creator));
        let fee: u128 = 10_000;
        // 10% margin → user pays 11_000, margin 1_000.
        let app = app_record(1_000, app_wallet);
        let parse = |_: &str| Ok(payer);

        let receipt = settle_invocation_fee(
            &tmpl,
            fee,
            500,
            Some("payer"),
            Some(&token),
            Some(&app),
            parse,
        )
        .expect("settlement must succeed")
        .expect("paid template must produce a receipt");

        assert_eq!(receipt.margin_bps, 1_000);
        assert_eq!(receipt.margin_amount, 1_000);
        assert_eq!(receipt.app_id.as_deref(), Some("app-test"));
        assert_eq!(receipt.app_wallet, Some(app_wallet));
        // Network split is unchanged by attribution.
        assert_eq!(receipt.commission, 500);
        assert_eq!(receipt.creator_share, 9_500);

        // Ledger: payer debited fee + margin; margin landed on app wallet.
        assert_eq!(token.balance_of(&payer), pre_payer - fee - 1_000);
        assert_eq!(token.balance_of(&app_wallet), 1_000);
        assert_eq!(token.balance_of(&treasury), pre_treasury + 500);
        assert_eq!(token.balance_of(&creator), 9_500);
    }

    /// Zero-margin apps settle identically to unattributed invocations
    /// on the ledger, but the receipt still records the attribution.
    #[test]
    fn zero_margin_app_settles_like_unattributed() {
        let token = TnzoToken::new();
        let treasury = Address::new([0x01; 32]);
        let payer = Address::new([0x02; 32]);
        let creator = Address::new([0x03; 32]);
        let app_wallet = Address::new([0x04; 32]);

        token.set_treasury_address(treasury);
        token.mint(&payer, 1_000_000, &treasury).unwrap();
        let pre_payer = token.balance_of(&payer);

        let tmpl = paid_template(Some(creator));
        let app = app_record(0, app_wallet);
        let parse = |_: &str| Ok(payer);

        let receipt = settle_invocation_fee(
            &tmpl,
            10_000,
            500,
            Some("payer"),
            Some(&token),
            Some(&app),
            parse,
        )
        .unwrap()
        .unwrap();

        assert_eq!(receipt.margin_amount, 0);
        assert_eq!(receipt.app_id.as_deref(), Some("app-test"));
        assert_eq!(token.balance_of(&payer), pre_payer - 10_000);
        assert_eq!(token.balance_of(&app_wallet), 0);
    }

    /// A corrupt record whose margin exceeds the protocol cap is
    /// rejected before any transfer happens.
    #[test]
    fn over_cap_margin_rejects_before_transfers() {
        let token = TnzoToken::new();
        let treasury = Address::new([0x01; 32]);
        let payer = Address::new([0x02; 32]);
        let creator = Address::new([0x03; 32]);
        let app_wallet = Address::new([0x04; 32]);

        token.set_treasury_address(treasury);
        token.mint(&payer, 1_000_000, &treasury).unwrap();
        let pre_payer = token.balance_of(&payer);

        let tmpl = paid_template(Some(creator));
        // Above MAX_DEVELOPER_MARGIN_BPS — registration would never
        // persist this, so it models a corrupt record.
        let app = app_record(tenzro_types::fees::MAX_DEVELOPER_MARGIN_BPS + 1, app_wallet);
        let parse = |_: &str| Ok(payer);

        let err = settle_invocation_fee(
            &tmpl,
            10_000,
            500,
            Some("payer"),
            Some(&token),
            Some(&app),
            parse,
        )
        .unwrap_err();
        assert!(matches!(err, CommissionError::MarginRejected(_)));

        // No transfer happened at all.
        assert_eq!(token.balance_of(&payer), pre_payer);
        assert_eq!(token.balance_of(&creator), 0);
        assert_eq!(token.balance_of(&app_wallet), 0);
    }
}
