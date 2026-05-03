//! ERC-3643 compliance commands for the Tenzro CLI
//!
//! Register compliance rules, check transfer compliance, manage frozen addresses,
//! recover tokens, and administer identity claims and trusted issuers.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// ERC-3643 compliance management commands
#[derive(Debug, Subcommand)]
pub enum ComplianceCommand {
    /// Register compliance rules for a token
    Register(ComplianceRegisterCmd),
    /// Check if a transfer is compliant
    Check(ComplianceCheckCmd),
    /// Freeze an address for a token
    Freeze(ComplianceFreezeCmd),
    /// Unfreeze an address for a token
    Unfreeze(ComplianceUnfreezeCmd),
    /// Force-recover tokens for compliance
    Recover(ComplianceRecoverCmd),
    /// Add an identity claim to an address
    AddClaim(ComplianceAddClaimCmd),
    /// Register a trusted claim issuer
    AddIssuer(ComplianceAddIssuerCmd),
    /// Add address to whitelist for a token
    Whitelist(ComplianceWhitelistCmd),
    /// Set country restriction for a token
    SetCountry(ComplianceSetCountryCmd),
}

impl ComplianceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::Check(cmd) => cmd.execute().await,
            Self::Freeze(cmd) => cmd.execute().await,
            Self::Unfreeze(cmd) => cmd.execute().await,
            Self::Recover(cmd) => cmd.execute().await,
            Self::AddClaim(cmd) => cmd.execute().await,
            Self::AddIssuer(cmd) => cmd.execute().await,
            Self::Whitelist(cmd) => cmd.execute().await,
            Self::SetCountry(cmd) => cmd.execute().await,
        }
    }
}

/// Register compliance rules for a token
#[derive(Debug, Parser)]
pub struct ComplianceRegisterCmd {
    /// Token ID (hex)
    #[arg(long)]
    token: String,
    /// Require KYC verification for holders
    #[arg(long)]
    require_kyc: bool,
    /// Minimum KYC tier required (0-3)
    #[arg(long, default_value = "1")]
    min_kyc_tier: u8,
    /// Require accredited investor status
    #[arg(long)]
    require_accreditation: bool,
    /// Maximum number of token holders
    #[arg(long)]
    max_holders: Option<u64>,
    /// Maximum transfer amount per transaction
    #[arg(long)]
    max_transfer_amount: Option<String>,
    /// Enable country-based transfer restrictions
    #[arg(long)]
    country_check: bool,
    /// Require explicit whitelist approval for holders
    #[arg(long)]
    require_whitelist: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComplianceRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register Compliance Rules");
        let spinner = output::create_spinner("Registering compliance rules...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "token_id": self.token,
            "require_kyc": self.require_kyc,
            "min_kyc_tier": self.min_kyc_tier,
            "require_accreditation": self.require_accreditation,
            "country_check": self.country_check,
            "require_whitelist": self.require_whitelist,
        });

        if let Some(max_holders) = self.max_holders {
            params["max_holders"] = serde_json::json!(max_holders);
        }
        if let Some(ref max_amount) = self.max_transfer_amount {
            params["max_transfer_amount"] = serde_json::json!(max_amount);
        }

        let result: serde_json::Value = rpc.call("tenzro_registerCompliance", params).await?;

        spinner.finish_and_clear();

        output::print_success("Compliance rules registered successfully!");
        output::print_field("Token", result.get("token_id").and_then(|v| v.as_str()).unwrap_or(&self.token));

        let mut rules = Vec::new();
        if self.require_kyc {
            rules.push(format!("KYC required (min tier {})", self.min_kyc_tier));
        }
        if self.require_accreditation {
            rules.push("Accredited investor required".to_string());
        }
        if let Some(max_holders) = self.max_holders {
            rules.push(format!("Max holders: {}", max_holders));
        }
        if let Some(ref max_amount) = self.max_transfer_amount {
            rules.push(format!("Max transfer: {}", max_amount));
        }
        if self.country_check {
            rules.push("Country restrictions enabled".to_string());
        }
        if self.require_whitelist {
            rules.push("Whitelist required".to_string());
        }
        if rules.is_empty() {
            rules.push("No restrictions".to_string());
        }
        output::print_field("Rules", &rules.join(", "));

        Ok(())
    }
}

/// Check if a transfer is compliant
#[derive(Debug, Parser)]
pub struct ComplianceCheckCmd {
    /// Token ID (hex)
    #[arg(long)]
    token: String,
    /// Sender address (hex)
    #[arg(long)]
    from: String,
    /// Recipient address (hex)
    #[arg(long)]
    to: String,
    /// Transfer amount
    #[arg(long)]
    amount: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComplianceCheckCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Compliance Check");
        let spinner = output::create_spinner("Checking compliance...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_checkCompliance", serde_json::json!({
            "token_id": self.token,
            "from": self.from,
            "to": self.to,
            "amount": self.amount,
        })).await?;

        spinner.finish_and_clear();

        let compliant = result.get("compliant").and_then(|v| v.as_bool()).unwrap_or(false);
        if compliant {
            output::print_success("Transfer is COMPLIANT");
        } else {
            output::print_error("Transfer is NOT COMPLIANT");
        }

        output::print_field("Compliant", if compliant { "Yes" } else { "No" });

        if let Some(violations) = result.get("violations").and_then(|v| v.as_array()) {
            if !violations.is_empty() {
                output::print_field("Violations", "");
                for v in violations {
                    if let Some(msg) = v.as_str() {
                        output::print_field("  -", msg);
                    }
                }
            }
        }

        if let Some(rules) = result.get("checked_rules").and_then(|v| v.as_array()) {
            let rule_names: Vec<String> = rules
                .iter()
                .filter_map(|r| r.as_str().map(|s| s.to_string()))
                .collect();
            if !rule_names.is_empty() {
                output::print_field("Checked Rules", &rule_names.join(", "));
            }
        }

        Ok(())
    }
}

/// Freeze an address for a token
#[derive(Debug, Parser)]
pub struct ComplianceFreezeCmd {
    /// Token ID (hex)
    #[arg(long)]
    token: String,
    /// Address to freeze (hex)
    #[arg(long)]
    address: String,
    /// Reason for freezing
    #[arg(long)]
    reason: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComplianceFreezeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Freeze Address");
        let spinner = output::create_spinner("Freezing address...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_freezeAddress", serde_json::json!({
            "token_id": self.token,
            "address": self.address,
            "reason": self.reason,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Address frozen successfully!");
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(&self.address));
        output::print_field("Reason", result.get("reason").and_then(|v| v.as_str()).unwrap_or(&self.reason));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("frozen"));

        Ok(())
    }
}

/// Unfreeze an address for a token
#[derive(Debug, Parser)]
pub struct ComplianceUnfreezeCmd {
    /// Token ID (hex)
    #[arg(long)]
    token: String,
    /// Address to unfreeze (hex)
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComplianceUnfreezeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Unfreeze Address");
        let spinner = output::create_spinner("Unfreezing address...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_unfreezeAddress", serde_json::json!({
            "token_id": self.token,
            "address": self.address,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Address unfrozen successfully!");
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(&self.address));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("unfrozen"));

        Ok(())
    }
}

/// Force-recover tokens for compliance
#[derive(Debug, Parser)]
pub struct ComplianceRecoverCmd {
    /// Token ID (hex)
    #[arg(long)]
    token: String,
    /// Source address to recover from (hex)
    #[arg(long)]
    from: String,
    /// Destination address to recover to (hex)
    #[arg(long)]
    to: String,
    /// Amount to recover
    #[arg(long)]
    amount: String,
    /// Reason for recovery
    #[arg(long)]
    reason: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComplianceRecoverCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Recover Tokens");
        let spinner = output::create_spinner("Recovering tokens...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_recoverTokens", serde_json::json!({
            "token_id": self.token,
            "from": self.from,
            "to": self.to,
            "amount": self.amount,
            "reason": self.reason,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Tokens recovered successfully!");
        output::print_field("From", result.get("from").and_then(|v| v.as_str()).unwrap_or(&self.from));
        output::print_field("To", result.get("to").and_then(|v| v.as_str()).unwrap_or(&self.to));
        output::print_field("Amount", result.get("amount").and_then(|v| v.as_str()).unwrap_or(&self.amount));
        output::print_field("Reason", result.get("reason").and_then(|v| v.as_str()).unwrap_or(&self.reason));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("recovered"));

        Ok(())
    }
}

/// Add an identity claim to an address
#[derive(Debug, Parser)]
pub struct ComplianceAddClaimCmd {
    /// Address to add claim to (hex)
    #[arg(long)]
    address: String,
    /// Claim topic (e.g. 1=KYC, 2=ACCREDITED, 3=COUNTRY, 4=QUALIFIED_INVESTOR)
    #[arg(long)]
    topic: u64,
    /// Issuer DID (e.g. did:tenzro:human:...)
    #[arg(long)]
    issuer: String,
    /// Claim data (hex-encoded)
    #[arg(long)]
    data: String,
    /// Valid from (ISO 8601 date, e.g. 2026-01-01T00:00:00Z)
    #[arg(long)]
    valid_from: String,
    /// Valid to (ISO 8601 date, e.g. 2027-01-01T00:00:00Z)
    #[arg(long)]
    valid_to: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComplianceAddClaimCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Add Identity Claim");
        let spinner = output::create_spinner("Adding identity claim...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_addIdentityClaim", serde_json::json!({
            "address": self.address,
            "topic": self.topic,
            "issuer": self.issuer,
            "data": self.data,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Identity claim added successfully!");
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(&self.address));

        let topic_label = match self.topic {
            1 => "KYC (1)",
            2 => "ACCREDITED (2)",
            3 => "COUNTRY (3)",
            4 => "QUALIFIED_INVESTOR (4)",
            other => {
                // Avoid allocation in common path; fall through to print raw
                let _ = other;
                ""
            }
        };
        if topic_label.is_empty() {
            output::print_field("Topic", &self.topic.to_string());
        } else {
            output::print_field("Topic", topic_label);
        }

        output::print_field("Issuer", result.get("issuer").and_then(|v| v.as_str()).unwrap_or(&self.issuer));
        output::print_field("Valid From", result.get("valid_from").and_then(|v| v.as_str()).unwrap_or(&self.valid_from));
        output::print_field("Valid To", result.get("valid_to").and_then(|v| v.as_str()).unwrap_or(&self.valid_to));

        Ok(())
    }
}

/// Register a trusted claim issuer
#[derive(Debug, Parser)]
pub struct ComplianceAddIssuerCmd {
    /// Issuer DID (e.g. did:tenzro:human:...)
    #[arg(long)]
    issuer_did: String,
    /// Issuer display name
    #[arg(long)]
    name: String,
    /// Comma-separated claim topics this issuer is trusted for (e.g. "1,2")
    #[arg(long)]
    topics: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComplianceAddIssuerCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Add Trusted Claim Issuer");
        let spinner = output::create_spinner("Registering trusted issuer...");
        let rpc = RpcClient::new(&self.rpc);

        let topics: Vec<u64> = self
            .topics
            .split(',')
            .filter_map(|s| s.trim().parse::<u64>().ok())
            .collect();

        let result: serde_json::Value = rpc.call("tenzro_addTrustedIssuer", serde_json::json!({
            "issuer_did": self.issuer_did,
            "name": self.name,
            "topics": topics,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Trusted issuer registered successfully!");
        output::print_field("Issuer DID", result.get("issuer_did").and_then(|v| v.as_str()).unwrap_or(&self.issuer_did));
        output::print_field("Name", result.get("name").and_then(|v| v.as_str()).unwrap_or(&self.name));

        let topic_strs: Vec<String> = topics.iter().map(|t| t.to_string()).collect();
        output::print_field("Topics", &topic_strs.join(", "));

        Ok(())
    }
}

/// Add address to whitelist for a token
#[derive(Debug, Parser)]
pub struct ComplianceWhitelistCmd {
    /// Token ID (hex)
    #[arg(long)]
    token: String,
    /// Address to whitelist (hex)
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComplianceWhitelistCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Whitelist Address");
        let spinner = output::create_spinner("Adding to whitelist...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_whitelistAddress", serde_json::json!({
            "token_id": self.token,
            "address": self.address,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Address whitelisted successfully!");
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(&self.address));
        output::print_field("Token", result.get("token_id").and_then(|v| v.as_str()).unwrap_or(&self.token));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("whitelisted"));

        Ok(())
    }
}

/// Set country restriction for a token
#[derive(Debug, Parser)]
pub struct ComplianceSetCountryCmd {
    /// Token ID (hex)
    #[arg(long)]
    token: String,
    /// ISO 3166-1 numeric country code (e.g. 840 for US, 826 for UK)
    #[arg(long)]
    country: u16,
    /// Whether the country is allowed (true) or blocked (false)
    #[arg(long)]
    allowed: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComplianceSetCountryCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Set Country Restriction");
        let spinner = output::create_spinner("Setting country restriction...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_setCountryRestriction", serde_json::json!({
            "token_id": self.token,
            "country_code": self.country,
            "allowed": self.allowed,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Country restriction updated!");
        output::print_field("Token", result.get("token_id").and_then(|v| v.as_str()).unwrap_or(&self.token));
        output::print_field("Country Code", &self.country.to_string());
        output::print_field("Status", if self.allowed { "Allowed" } else { "Blocked" });

        Ok(())
    }
}
