//! Payment protocol commands for the Tenzro CLI
//!
//! Payment challenges, credential verification and direct settlement.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Payment commands
#[derive(Debug, Subcommand)]
pub enum PaymentCommand {
    /// Create a payment challenge for a resource
    Challenge(PaymentChallengeCmd),
    /// Verify a payment credential
    Verify(PaymentVerifyCmd),
    /// Settle a payment on-chain
    Settle(PaymentSettleCmd),
    /// Show a payment's consensus record
    Record(PaymentRecordCmd),
    /// List consensus payment records from the event index
    History(PaymentHistoryCmd),
    /// List the paid calls a node served or routed, with how each settled
    Settlements(PaymentSettlementsCmd),
    /// An account's statement of the payment legs paid to it (as operator,
    /// reseller or platform), verifiable against the chain
    Statement(PaymentStatementCmd),
    /// List the provider legs a node owes for calls it forwarded
    Legs(PaymentLegsCmd),
    /// Drive a failed provider leg again under its payment id (operator)
    RetryLeg(PaymentRetryLegCmd),
    /// Sign a delegated agent's next voucher on its channel (serving node)
    AgentVoucher(PaymentAgentVoucherCmd),
    /// Return part or all of a payment you received to its payer
    Refund(PaymentRefundCmd),
    /// Set the standing split rule every payment you receive is divided by
    SetSplit(PaymentSetSplitCmd),
    /// Show a payee's standing split rule from consensus
    Split(PaymentSplitCmd),
    /// Record a payment a delegated agent's account made on another chain,
    /// from the account's report proven through that chain's route
    Prove(PaymentProveCmd),
    /// Price a USD amount in each accepted asset, with its fee in kind
    Quote(PaymentQuoteCmd),
    /// Have the agent's serving node sign a voucher on a channel its account
    /// holds on another chain
    RemoteVoucher(PaymentRemoteVoucherCmd),
}

impl PaymentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Challenge(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Settle(cmd) => cmd.execute().await,
            Self::Record(cmd) => cmd.execute().await,
            Self::History(cmd) => cmd.execute().await,
            Self::Settlements(cmd) => cmd.execute().await,
            Self::Statement(cmd) => cmd.execute().await,
            Self::Legs(cmd) => cmd.execute().await,
            Self::RetryLeg(cmd) => cmd.execute().await,
            Self::AgentVoucher(cmd) => cmd.execute().await,
            Self::Refund(cmd) => cmd.execute().await,
            Self::SetSplit(cmd) => cmd.execute().await,
            Self::Split(cmd) => cmd.execute().await,
            Self::Prove(cmd) => cmd.execute().await,
            Self::Quote(cmd) => cmd.execute().await,
            Self::RemoteVoucher(cmd) => cmd.execute().await,
        }
    }
}

/// Create a payment challenge for a resource
#[derive(Debug, Parser)]
pub struct PaymentChallengeCmd {
    /// Resource URI (e.g. /api/inference/gemma4-9b)
    resource: String,

    /// Amount in smallest unit
    #[arg(long)]
    amount: u64,

    /// Asset (e.g. USDC, TNZO)
    #[arg(long, default_value = "USDC")]
    asset: String,

    /// Protocol: mpp or x402
    #[arg(long, default_value = "mpp")]
    protocol: String,

    /// Recipient DID or address
    #[arg(long)]
    recipient: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentChallengeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create Payment Challenge");

        let spinner = output::create_spinner("Creating challenge...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc
            .call(
                "tenzro_createPaymentChallenge",
                serde_json::json!({
                    "resource": self.resource,
                    "amount": self.amount.to_string(),
                    "asset": self.asset,
                    "protocol": self.protocol,
                    "recipient": self.recipient.as_deref().unwrap_or("")
                }),
            )
            .await?;

        spinner.finish_and_clear();

        output::print_success("Payment challenge created!");
        println!();

        if let Some(challenge_id) = result.get("challenge_id").and_then(|v| v.as_str()) {
            output::print_field("Challenge ID", challenge_id);
        }
        output::print_field("Protocol", &self.protocol.to_uppercase());
        output::print_field("Resource", &self.resource);
        output::print_field("Amount", &format!("{} {}", self.amount, self.asset));

        if let Some(recipient) = &self.recipient {
            output::print_field("Recipient", recipient);
        }

        println!();
        output::print_info("Pay it with: tenzro payment pay --challenge '<the JSON below>'");
        println!("{}", serde_json::to_string(&result)?);

        Ok(())
    }
}

/// Verify a payment credential
#[derive(Debug, Parser)]
pub struct PaymentVerifyCmd {
    /// Payment credential (JSON); it names the challenge it answers
    #[arg(long)]
    credential: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Verify Payment");
        let spinner = output::create_spinner("Verifying...");
        let rpc = RpcClient::new(&self.rpc);
        let credential: serde_json::Value = serde_json::from_str(&self.credential)
            .map_err(|e| anyhow::anyhow!("the credential is not JSON: {e}"))?;
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyPayment",
                serde_json::json!({ "credential": credential }),
            )
            .await?;
        spinner.finish_and_clear();
        let valid = result
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if valid {
            output::print_success("Payment verified!");
        } else {
            output::print_error("Verification failed.");
            if let Some(reason) = result.get("reason").and_then(|v| v.as_str()) {
                output::print_field("Reason", reason);
            }
        }
        Ok(())
    }
}

/// Settle a payment on the ledger from the client account: a `PayerSettle`
/// carrying an authorization signed in hardware for this payee and amount
#[derive(Debug, Parser)]
pub struct PaymentSettleCmd {
    /// Payee address (hex)
    #[arg(long)]
    payee: String,
    /// Amount in wei (decimal)
    #[arg(long)]
    amount: String,
    /// Payment id, the idempotency key the authorization signs
    #[arg(long)]
    payment_id: String,
    /// The resource paid for; its digest is the request the payment binds
    #[arg(long)]
    request: String,
    /// The payee's quote digest (hex), when the payment pays a quote
    #[arg(long)]
    quote_digest: Option<String>,
    /// The quoted USD price in micro-units, when the payment is USD-priced
    #[arg(long, default_value_t = 0)]
    usd_e6: u64,
    /// Wallet an application's developer margin is paid to (hex); signed
    /// with the payment, together with --margin-bps
    #[arg(long, requires = "margin_bps")]
    app_wallet: Option<String>,
    /// The developer margin in basis points, carved out of --amount and paid
    /// to --app-wallet
    #[arg(long, requires = "app_wallet")]
    margin_bps: Option<u32>,
    /// The paying account's hardware key namespace
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

/// The binding a payment signs: the digest of `request` (as the payee's
/// challenge names the resource), the quote digest, the USD price and the
/// application margin, if any.
pub fn payment_binding(
    request: &str,
    quote_digest: Option<&str>,
    usd_e6: u64,
    app_margin: Option<tenzro_types::payment_authorization::AppMargin>,
) -> Result<tenzro_types::payment_authorization::PaymentBinding> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/request");
    h.update(request.as_bytes());
    let quote_digest = match quote_digest {
        None => [0u8; 32],
        Some(q) => hex::decode(q.trim_start_matches("0x"))
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("--quote-digest is 32 bytes of hex"))?,
    };
    Ok(tenzro_types::payment_authorization::PaymentBinding {
        request_digest: h.finalize().into(),
        quote_digest,
        usd_e6,
        app_margin,
    })
}

impl PaymentSettleCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Settle Payment");
        let rpc = RpcClient::new(&self.rpc);
        let amount: u128 = self
            .amount
            .parse()
            .map_err(|_| anyhow::anyhow!("--amount must be a wei decimal"))?;
        let payee = tenzro_types::primitives::Address::parse(&self.payee)
            .map_err(|e| anyhow::anyhow!("--payee: {e}"))?;
        let chain_id = crate::rpc::fetch_chain_id(&rpc).await?;
        // Any developer margin is signed with the payment and carved out of
        // the amount, so the ceiling is the amount itself.
        let app_margin = match (&self.app_wallet, self.margin_bps) {
            (Some(wallet), Some(margin_bps)) => {
                Some(tenzro_types::payment_authorization::AppMargin {
                    app_wallet: tenzro_types::primitives::Address::parse(wallet)
                        .map_err(|e| anyhow::anyhow!("--app-wallet: {e}"))?,
                    margin_bps,
                })
            }
            _ => None,
        };
        let binding = payment_binding(
            &self.request,
            self.quote_digest.as_deref(),
            self.usd_e6,
            app_margin,
        )?;
        let payment = crate::keystore::sign_payment(
            &self.key_namespace,
            chain_id,
            &self.payment_id,
            &payee,
            amount,
            &binding,
        )?;
        let spinner = output::create_spinner("Settling...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_settle",
                serde_json::json!({
                    "payee": self.payee,
                    "amount": self.amount,
                    "payment": payment,
                }),
            )
            .await?;
        spinner.finish_and_clear();
        output::print_success("Payment settled!");
        for key in ["tx_hash", "status", "network_fee", "payee_credit"] {
            if let Some(v) = result.get(key).and_then(|v| v.as_str()) {
                output::print_field(key, v);
            }
        }
        Ok(())
    }
}

/// Show a payment's consensus record: native, proven on another chain or
/// attested on another rail, with the request, quote and receipts it binds
#[derive(Debug, Parser)]
pub struct PaymentRecordCmd {
    /// The record's reference (hex)
    #[arg(long, conflicts_with = "payment_id")]
    pay_ref: Option<String>,
    /// The payment id a native payment settled under
    #[arg(long)]
    payment_id: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

/// List consensus payment records in chain order, read from the event
/// index; pass the printed cursor back with --from-cursor to continue
#[derive(Debug, Parser)]
pub struct PaymentHistoryCmd {
    /// Only payments to this payee (32-byte hex address)
    #[arg(long)]
    payee: Option<String>,
    /// Only payments from this payer
    #[arg(long)]
    payer: Option<String>,
    /// Only payments made by this delegated agent
    #[arg(long)]
    agent_did: Option<String>,
    /// Only this record class: native, proven or attested
    #[arg(long)]
    class: Option<String>,
    /// Only this asset
    #[arg(long)]
    asset: Option<String>,
    /// Continue after this event cursor
    #[arg(long, conflicts_with = "from_height")]
    from_cursor: Option<String>,
    /// Start at this block height
    #[arg(long)]
    from_height: Option<u64>,
    /// Most records
    #[arg(long)]
    limit: Option<u64>,
    /// Include each record's event proof
    #[arg(long)]
    proofs: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentHistoryCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listPayments",
                serde_json::json!({
                    "payee": self.payee, "payer": self.payer, "agent_did": self.agent_did,
                    "class": self.class, "asset": self.asset, "from_cursor": self.from_cursor,
                    "from_height": self.from_height, "limit": self.limit, "proofs": self.proofs,
                }),
            )
            .await?;
        output::print_json(&result)
    }
}

/// List the paid calls a node served or routed, newest first: the work
/// (model, units, serving node, hardware tier, latency) as the node recorded
/// it, and the fee, burn and treasury leg from the chain
#[derive(Debug, Parser)]
pub struct PaymentSettlementsCmd {
    /// Only this work class (inference_served, ...)
    #[arg(long)]
    work_class: Option<String>,
    /// Only calls paid to this provider account
    #[arg(long)]
    provider: Option<String>,
    /// Only calls paid by this account
    #[arg(long)]
    payer: Option<String>,
    /// Only calls served at or after this time, unix ms
    #[arg(long)]
    from_ms: Option<u64>,
    /// Only calls served before this time, unix ms
    #[arg(long)]
    to_ms: Option<u64>,
    /// Continue from this cursor (the previous page's `cursor`)
    #[arg(long)]
    cursor: Option<String>,
    /// Most entries (at most 200)
    #[arg(long)]
    limit: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentSettlementsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listSettlements",
                serde_json::json!({
                    "work_class": self.work_class, "provider": self.provider, "payer": self.payer,
                    "from_ms": self.from_ms, "to_ms": self.to_ms, "cursor": self.cursor,
                    "limit": self.limit,
                }),
            )
            .await?;
        output::print_json(&result)
    }
}

impl PaymentRecordCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        if self.pay_ref.is_none() && self.payment_id.is_none() {
            anyhow::bail!("--pay-ref or --payment-id is required");
        }
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getPayment",
                serde_json::json!({ "pay_ref": self.pay_ref, "payment_id": self.payment_id }),
            )
            .await?;
        if result.is_null() {
            output::print_error("No payment is recorded there.");
            return Ok(());
        }
        output::print_json(&result)
    }
}

/// Have the agent's serving node sign its next cumulative voucher on a
/// channel the agent's wallet funded
#[derive(Debug, Parser)]
pub struct PaymentAgentVoucherCmd {
    /// The channel's escrow id (hex)
    #[arg(long)]
    channel_id: String,
    /// The cumulative amount the payee may have claimed in total
    #[arg(long)]
    cumulative_amount: String,
    /// RPC endpoint of one of the agent's serving nodes
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentAgentVoucherCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_agentVoucher",
                serde_json::json!({
                    "channel_id": self.channel_id,
                    "cumulative_amount": self.cumulative_amount,
                }),
            )
            .await?;
        output::print_json(&result)
    }
}

/// What a USD price costs in each accepted asset now, with the fee it pays in kind
#[derive(Debug, Parser)]
pub struct PaymentQuoteCmd {
    /// The price in USD micro-units (1 USD = 1000000)
    #[arg(long)]
    usd_e6: u64,
    /// Assets to price it in (`TNZO` or a `0x` token id); TNZO when none
    #[arg(long)]
    accept: Vec<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentQuoteCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_quotePayment",
                if self.accept.is_empty() {
                    serde_json::json!({ "usd_e6": self.usd_e6 })
                } else {
                    serde_json::json!({ "usd_e6": self.usd_e6, "accept": self.accept })
                },
            )
            .await?;
        output::print_json(&result)
    }
}

/// Have the agent's serving node sign a voucher paying `cumulative_amount`
/// on a channel the agent's account holds on another chain
#[derive(Debug, Parser)]
pub struct PaymentRemoteVoucherCmd {
    /// The chain the account holds the channel on (CAIP-2)
    #[arg(long)]
    chain: String,
    /// The channel's id on the account
    #[arg(long)]
    channel_id: u64,
    /// The cumulative amount the payee may have claimed in total
    #[arg(long)]
    cumulative_amount: String,
    /// RPC endpoint of one of the agent's serving nodes
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentRemoteVoucherCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_signRemoteChannelVoucher",
                serde_json::json!({
                    "chain": self.chain,
                    "channel_id": self.channel_id,
                    "cumulative_amount": self.cumulative_amount,
                }),
            )
            .await?;
        output::print_json(&result)
    }
}

/// Return part or all of a native payment to its payer, signed by the payee
/// in hardware. Refunds on one record never exceed what it paid; the
/// settlement fee is not returned
#[derive(Debug, Parser)]
pub struct PaymentRefundCmd {
    /// The payment record's reference (hex)
    #[arg(long)]
    pay_ref: String,
    /// Amount to return, in the asset's smallest unit (decimal)
    #[arg(long)]
    amount: String,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl PaymentRefundCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Payment Refund");
        let pay_ref: [u8; 32] = hex::decode(self.pay_ref.trim_start_matches("0x"))
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("--pay-ref must be 32 bytes of hex"))?;
        let amount: u128 = self
            .amount
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("--amount must be a decimal integer"))?;
        if amount == 0 {
            anyhow::bail!("--amount must be positive");
        }
        let op = tenzro_types::settlement::PaymentOp::Refund { pay_ref, amount };
        self.signer
            .send_tx(
                tenzro_types::transaction::TransactionType::Payment { op },
                "Payment",
            )
            .await
    }
}

/// Record a payment an agent's account made on another chain. Anyone may
/// submit it: the route's proof of the account's report is the authority,
/// and the account is the payer
#[derive(Debug, Parser)]
pub struct PaymentProveCmd {
    /// The paying agent's DID
    #[arg(long)]
    agent_did: String,
    /// The chain its account paid on (CAIP-2)
    #[arg(long)]
    chain: String,
    /// The route delivery carrying the account's payment report (hex)
    #[arg(long)]
    delivery: String,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl PaymentProveCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Proven Payment");
        let delivery = hex::decode(self.delivery.trim().trim_start_matches("0x"))
            .map_err(|_| anyhow::anyhow!("--delivery must be hex"))?;
        let op = tenzro_types::settlement::PaymentOp::Proven {
            agent_did: self.agent_did.clone(),
            chain: self.chain.clone(),
            delivery,
        };
        self.signer
            .send_tx(
                tenzro_types::transaction::TransactionType::Payment { op },
                "Payment",
            )
            .await
    }
}

/// Set the standing split rule every payment you receive is divided by,
/// signed by the payee in hardware. The rule is the split engine's (lines of
/// a role, a recipient and basis points, a fixed amount or the remainder),
/// applied after the fee in the same asset and execution
#[derive(Debug, Parser)]
pub struct PaymentSetSplitCmd {
    /// The rule as JSON, or `@<path>` to read it from a file
    #[arg(long, conflicts_with = "clear")]
    rule: Option<String>,
    /// Clear the standing rule
    #[arg(long)]
    clear: bool,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl PaymentSetSplitCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Payment Split");
        let rule = match (&self.rule, self.clear) {
            (None, true) => None,
            (Some(text), false) => {
                let text = match text.strip_prefix('@') {
                    Some(path) => std::fs::read_to_string(path)?,
                    None => text.clone(),
                };
                let rule: tenzro_types::split::SplitRule = serde_json::from_str(&text)
                    .map_err(|e| anyhow::anyhow!("--rule is not a split rule: {e}"))?;
                tenzro_types::settlement::validate_standing_split(&rule)
                    .map_err(|e| anyhow::anyhow!(e))?;
                Some(rule)
            }
            _ => anyhow::bail!("give --rule or --clear"),
        };
        let op = tenzro_types::settlement::PaymentOp::SetSplit { rule };
        self.signer
            .send_tx(
                tenzro_types::transaction::TransactionType::Payment { op },
                "Payment",
            )
            .await
    }
}

/// Show a payee's standing split rule, from consensus state
#[derive(Debug, Parser)]
pub struct PaymentSplitCmd {
    /// The payee's address (hex)
    #[arg(long)]
    payee: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentSplitCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getPayeeSplit",
                serde_json::json!({ "payee": self.payee }),
            )
            .await?;
        output::print_json(&result)
    }
}

/// The provider legs a node owes for calls it forwarded: queued, pending,
/// settled or failed, each with its attempts
#[derive(Debug, Parser)]
pub struct PaymentLegsCmd {
    /// Only legs in this state (`queued`, `pending`, `settled`, `failed`)
    #[arg(long)]
    status: Option<String>,
    /// Only legs owed to this provider account
    #[arg(long)]
    provider: Option<String>,
    /// Most entries
    #[arg(long)]
    limit: Option<u64>,
    /// Continue from this cursor (the previous page's `cursor`)
    #[arg(long)]
    cursor: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentLegsCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listNetworkLegs",
                serde_json::json!({
                    "status": self.status, "provider": self.provider,
                    "limit": self.limit, "cursor": self.cursor,
                }),
            )
            .await?;
        output::print_json(&result)
    }
}

/// Drive a failed provider leg again under the same payment id, so it can
/// never pay twice; the node's operator only
#[derive(Debug, Parser)]
pub struct PaymentRetryLegCmd {
    /// The leg's payment id
    #[arg(long)]
    payment_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentRetryLegCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_retryNetworkLeg",
                serde_json::json!({ "payment_id": self.payment_id }),
            )
            .await?;
        output::print_json(&result)
    }
}

/// An account's statement of the payment legs paid to it: an operator's
/// shows its operator legs, a reseller's its commission legs, never another
/// party's; totals per asset
#[derive(Debug, Parser)]
pub struct PaymentStatementCmd {
    /// The account (32 bytes of hex)
    #[arg(long)]
    account: String,
    /// Most payments read (pages of 200)
    #[arg(long, default_value_t = 2_000)]
    max: usize,
    /// Re-read every payment from this endpoint and report each difference
    /// (`--verify` alone uses `--rpc`)
    #[arg(long)]
    verify: bool,
    /// The endpoint the statement is checked against
    #[arg(long)]
    verify_rpc: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentStatementCmd {
    pub async fn execute(&self) -> Result<()> {
        use tenzro_types::leg_statement::{Statement, verify};
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let mut records: Vec<serde_json::Value> = Vec::new();
        let mut cursor: Option<String> = None;
        while records.len() < self.max {
            let page: serde_json::Value = rpc
                .call(
                    "tenzro_listPayments",
                    serde_json::json!({
                        "leg_account": self.account, "exact": true,
                        "limit": 200, "from_cursor": cursor,
                    }),
                )
                .await?;
            let payments = page["payments"].as_array().cloned().unwrap_or_default();
            records.extend(payments.iter().map(|p| p["record"].clone()));
            cursor = page["cursor"].as_str().map(str::to_string);
            if payments.is_empty() || cursor.is_none() {
                break;
            }
        }
        let statement = Statement::for_account(&self.account, &records);
        let differences = if self.verify || self.verify_rpc.is_some() {
            let checker =
                crate::rpc::RpcClient::new(self.verify_rpc.as_deref().unwrap_or(&self.rpc));
            let mut fetched = std::collections::BTreeMap::new();
            for line in &statement.lines {
                if fetched.contains_key(&line.pay_ref) {
                    continue;
                }
                let r: serde_json::Value = checker
                    .call(
                        "tenzro_getPayment",
                        serde_json::json!({ "pay_ref": line.pay_ref, "exact": true }),
                    )
                    .await?;
                fetched.insert(line.pay_ref.clone(), r);
            }
            Some(verify(&statement, |p| {
                fetched.get(p).filter(|v| !v.is_null()).cloned()
            }))
        } else {
            None
        };
        output::print_json(
            &serde_json::json!({ "statement": statement, "differences": differences }),
        )
    }
}
