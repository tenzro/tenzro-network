//! Payment protocol commands for the Tenzro CLI
//!
//! Supports MPP (Machine Payments Protocol), x402, and direct settlement.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output::{self, colors};

/// Payment protocol commands (MPP / x402)
#[derive(Debug, Subcommand)]
pub enum PaymentCommand {
    /// Create a payment challenge for a resource
    Challenge(PaymentChallengeCmd),
    /// Pay for a resource using MPP or x402
    Pay(PaymentPayCmd),
    /// List active MPP sessions
    Sessions(PaymentSessionsCmd),
    /// Show payment receipt details
    Receipt(PaymentReceiptCmd),
    /// Show supported payment protocols and configuration
    Info(PaymentInfoCmd),
    /// List supported payment protocols
    Protocols(PaymentProtocolsCmd),
    /// Verify a payment credential
    Verify(PaymentVerifyCmd),
    /// Settle a payment on-chain
    Settle(PaymentSettleCmd),
    /// Pay via Visa tap-to-pay
    VisaTap(PaymentVisaTapCmd),
    /// Pay via Mastercard
    Mastercard(PaymentMastercardCmd),
}

impl PaymentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Challenge(cmd) => cmd.execute().await,
            Self::Pay(cmd) => cmd.execute().await,
            Self::Sessions(cmd) => cmd.execute().await,
            Self::Receipt(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
            Self::Protocols(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Settle(cmd) => cmd.execute().await,
            Self::VisaTap(cmd) => cmd.execute().await,
            Self::Mastercard(cmd) => cmd.execute().await,
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

        let result: serde_json::Value = rpc.call("tenzro_createPaymentChallenge", serde_json::json!([{
            "resource": self.resource,
            "amount": self.amount,
            "asset": self.asset,
            "protocol": self.protocol,
            "recipient": self.recipient.as_deref()
        }])).await?;

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

        if self.protocol == "mpp" {
            output::print_field("HTTP Status", "402 Payment Required");
            output::print_field("Content-Type", "application/json");
        } else {
            output::print_field("Header", "X-PAYMENT-REQUIRED");
        }

        Ok(())
    }
}

/// Pay for a resource using MPP or x402
#[derive(Debug, Parser)]
pub struct PaymentPayCmd {
    /// Resource URL to pay for
    url: String,

    /// Payer DID
    #[arg(long)]
    payer_did: Option<String>,

    /// Wallet ID to use for payment
    #[arg(long)]
    wallet: Option<String>,

    /// Protocol: mpp or x402
    #[arg(long, default_value = "mpp")]
    protocol: String,

    /// Maximum amount willing to pay
    #[arg(long)]
    max_amount: Option<u64>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentPayCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Pay for Resource");

        let spinner = output::create_spinner("Negotiating payment...");

        let rpc = RpcClient::new(&self.rpc);

        spinner.set_message("Fetching 402 challenge...");

        let method = if self.protocol == "mpp" {
            "tenzro_payMpp"
        } else {
            "tenzro_payX402"
        };

        spinner.set_message("Signing payment credential...");

        let result: serde_json::Value = rpc.call(method, serde_json::json!([{
            "url": self.url,
            "payer_did": self.payer_did.as_deref(),
            "wallet": self.wallet.as_deref(),
            "max_amount": self.max_amount
        }])).await?;

        spinner.set_message("Submitting payment...");

        spinner.finish_and_clear();

        output::print_success("Payment successful!");
        println!();
        output::print_field("URL", &self.url);
        output::print_field("Protocol", &self.protocol.to_uppercase());

        if let Some(amount) = result.get("amount_paid").and_then(|v| v.as_str()) {
            output::print_field("Amount Paid", amount);
        }
        if let Some(receipt_id) = result.get("receipt_id").and_then(|v| v.as_str()) {
            output::print_field("Receipt ID", receipt_id);
        }

        if self.protocol == "mpp" {
            if let Some(session_id) = result.get("session_id").and_then(|v| v.as_str()) {
                output::print_field("Session ID", session_id);
            }
            output::print_info("MPP session established for streaming micropayments");
        }

        Ok(())
    }
}

/// List active MPP sessions
#[derive(Debug, Parser)]
pub struct PaymentSessionsCmd {
    /// Show closed sessions too
    #[arg(long)]
    all: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentSessionsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Payment Sessions");

        let spinner = output::create_spinner("Loading sessions...");

        let rpc = RpcClient::new(&self.rpc);

        let sessions: Vec<serde_json::Value> = rpc.call("tenzro_listPaymentSessions", serde_json::json!([{
            "include_closed": self.all
        }])).await?;

        spinner.finish_and_clear();

        let headers = vec!["Session ID", "Protocol", "Resource", "Spent", "Status"];
        let mut rows = Vec::new();

        for session in &sessions {
            let session_id = session.get("session_id").and_then(|v| v.as_str()).unwrap_or("unknown");
            let protocol = session.get("protocol").and_then(|v| v.as_str()).unwrap_or("unknown");
            let resource = session.get("resource").and_then(|v| v.as_str()).unwrap_or("unknown");
            let spent = session.get("spent").and_then(|v| v.as_str()).unwrap_or("0");
            let status = session.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");

            rows.push(vec![
                session_id.to_string(),
                protocol.to_uppercase(),
                resource.to_string(),
                spent.to_string(),
                status.to_string(),
            ]);
        }

        if rows.is_empty() {
            output::print_info("No payment sessions found");
        } else {
            output::print_table(&headers, &rows);
        }

        Ok(())
    }
}

/// Show payment receipt details
#[derive(Debug, Parser)]
pub struct PaymentReceiptCmd {
    /// Receipt ID
    receipt_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentReceiptCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Payment Receipt");

        let spinner = output::create_spinner("Fetching receipt...");

        let rpc = RpcClient::new(&self.rpc);

        let receipt: serde_json::Value = rpc.call("tenzro_getPaymentReceipt", serde_json::json!([self.receipt_id])).await?;

        spinner.finish_and_clear();

        println!();
        output::print_field("Receipt ID", &self.receipt_id);

        if let Some(protocol) = receipt.get("protocol").and_then(|v| v.as_str()) {
            output::print_field("Protocol", &protocol.to_uppercase());
        }
        if let Some(amount) = receipt.get("amount").and_then(|v| v.as_str()) {
            output::print_field("Amount", amount);
        }
        if let Some(payer) = receipt.get("payer_did").and_then(|v| v.as_str()) {
            output::print_field("Payer DID", payer);
        }
        if let Some(recipient) = receipt.get("recipient").and_then(|v| v.as_str()) {
            output::print_field("Recipient", recipient);
        }
        if let Some(resource) = receipt.get("resource").and_then(|v| v.as_str()) {
            output::print_field("Resource", resource);
        }
        if let Some(timestamp) = receipt.get("timestamp").and_then(|v| v.as_str()) {
            output::print_field("Timestamp", timestamp);
        }
        if let Some(settlement) = receipt.get("settlement").and_then(|v| v.as_str()) {
            output::print_field("Settlement", settlement);
        }

        Ok(())
    }
}

/// Show supported payment protocols and configuration
#[derive(Debug, Parser)]
pub struct PaymentInfoCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Payment Gateway Info");

        let spinner = output::create_spinner("Fetching payment info...");

        let rpc = RpcClient::new(&self.rpc);

        let info: serde_json::Value = rpc.call("tenzro_paymentGatewayInfo", serde_json::json!([])).await?;

        spinner.finish_and_clear();

        println!();

        if let Some(status) = info.get("status").and_then(|v| v.as_str()) {
            output::print_field("Gateway Status", status);
        } else {
            output::print_field("Gateway Status", "active");
        }

        println!();

        println!("  {}Supported Protocols:{}", colors::BOLD, colors::RESET);
        if let Some(protocols) = info.get("protocols").and_then(|v| v.as_array()) {
            for protocol in protocols {
                if let Some(name) = protocol.get("name").and_then(|v| v.as_str()) {
                    let desc = protocol.get("description").and_then(|v| v.as_str()).unwrap_or("");
                    output::print_field(&format!("  {}", name), desc);
                }
            }
        } else {
            output::print_field("  MPP", "Machine Payments Protocol (Stripe/Tempo)");
            output::print_field("  x402", "HTTP 402 Payment Protocol (Coinbase)");
            output::print_field("  Direct", "Direct on-chain settlement");
        }
        println!();

        println!("  {}Settlement Networks:{}", colors::BOLD, colors::RESET);
        if let Some(networks) = info.get("networks").and_then(|v| v.as_array()) {
            for network in networks {
                if let Some(name) = network.get("name").and_then(|v| v.as_str()) {
                    let desc = network.get("description").and_then(|v| v.as_str()).unwrap_or("");
                    output::print_field(&format!("  {}", name), desc);
                }
            }
        } else {
            output::print_field("  Tenzro", "Native chain settlement");
            output::print_field("  Tempo", "Chain ID 42431 (TIP-20 stablecoins)");
        }
        println!();

        println!("  {}Supported Assets:{}", colors::BOLD, colors::RESET);
        if let Some(assets) = info.get("assets").and_then(|v| v.as_array()) {
            for asset in assets {
                if let Some(symbol) = asset.get("symbol").and_then(|v| v.as_str()) {
                    let desc = asset.get("description").and_then(|v| v.as_str()).unwrap_or("");
                    output::print_field(&format!("  {}", symbol), desc);
                }
            }
        } else {
            output::print_field("  USDC", "USD Coin (TIP-20 on Tempo)");
            output::print_field("  USDT", "Tether USD (TIP-20 on Tempo)");
            output::print_field("  TNZO", "Tenzro Network Token");
        }

        Ok(())
    }
}

/// List supported payment protocols
#[derive(Debug, Parser)]
pub struct PaymentProtocolsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentProtocolsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Payment Protocols");
        let spinner = output::create_spinner("Fetching...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_listPaymentProtocols", serde_json::json!([])).await?;
        spinner.finish_and_clear();
        if let Some(protocols) = result.as_array() {
            for p in protocols {
                output::print_field(
                    p.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                    p.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                );
            }
        } else { output::print_json(&result)?; }
        Ok(())
    }
}

/// Verify a payment credential
#[derive(Debug, Parser)]
pub struct PaymentVerifyCmd {
    /// Challenge ID
    #[arg(long)]
    challenge_id: String,
    /// Payment credential (JSON or hex)
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
        let result: serde_json::Value = rpc.call("tenzro_verifyPayment", serde_json::json!({
            "challenge_id": self.challenge_id, "credential": self.credential,
        })).await?;
        spinner.finish_and_clear();
        let valid = result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        if valid { output::print_success("Payment verified!"); } else { output::print_error("Verification failed."); }
        Ok(())
    }
}

/// Settle a payment on-chain
#[derive(Debug, Parser)]
pub struct PaymentSettleCmd {
    /// Payment or session ID
    #[arg(long)]
    payment_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentSettleCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Settle Payment");
        let spinner = output::create_spinner("Settling...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_settlePayment", serde_json::json!({ "payment_id": self.payment_id })).await?;
        spinner.finish_and_clear();
        output::print_success("Payment settled!");
        if let Some(v) = result.get("tx_hash").and_then(|v| v.as_str()) { output::print_field("Tx Hash", v); }
        Ok(())
    }
}

/// Pay via Visa tap-to-pay
#[derive(Debug, Parser)]
pub struct PaymentVisaTapCmd {
    /// Resource URL
    url: String,
    /// Amount
    #[arg(long)]
    amount: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentVisaTapCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Visa Tap-to-Pay");
        let spinner = output::create_spinner("Processing...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_payVisaTap", serde_json::json!({ "url": self.url, "amount": self.amount })).await?;
        spinner.finish_and_clear();
        output::print_success("Payment processed!");
        if let Some(v) = result.get("receipt_id").and_then(|v| v.as_str()) { output::print_field("Receipt", v); }
        Ok(())
    }
}

/// Pay via Mastercard
#[derive(Debug, Parser)]
pub struct PaymentMastercardCmd {
    /// Resource URL
    url: String,
    /// Amount
    #[arg(long)]
    amount: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PaymentMastercardCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Mastercard Payment");
        let spinner = output::create_spinner("Processing...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_payMastercard", serde_json::json!({ "url": self.url, "amount": self.amount })).await?;
        spinner.finish_and_clear();
        output::print_success("Payment processed!");
        if let Some(v) = result.get("receipt_id").and_then(|v| v.as_str()) { output::print_field("Receipt", v); }
        Ok(())
    }
}
