//! `tenzro device` — the devices bound to an identity, and machine ownership.
//!
//! A Tenzro identity links devices the way a platform account does, except the
//! link is not a platform account: what is trusted is a WebAuthn attestation
//! verified against a vendor root the network pins, not an Apple, Google or
//! Microsoft sign-in.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Device binding and machine ownership.
#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    /// List the devices bound to an identity.
    List(ListCmd),
    /// Check whether a wallet may be created yet, and why not.
    #[command(name = "wallet-readiness")]
    WalletReadiness(ReadinessCmd),
    /// Unbind a device and end every session it authorised.
    Revoke(RevokeCmd),
    /// Move a machine to another identity.
    Transfer(TransferCmd),
}

impl DeviceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(c) => c.execute().await,
            Self::WalletReadiness(c) => c.execute().await,
            Self::Revoke(c) => c.execute().await,
            Self::Transfer(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct ListCmd {
    /// Identity whose devices to list.
    did: String,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_listBoundDevices",
                serde_json::json!({ "identity_did": self.did }),
            )
            .await?;
        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Bound devices");
        output::print_field("Identity", &self.did);
        output::print_field("Devices", &result["count"].to_string());
        output::print_field(
            "Hardware-bound",
            &result["hardware_bound_count"].to_string(),
        );
        println!();
        for d in result["devices"].as_array().unwrap_or(&vec![]) {
            let bound = if d["hardware_bound"].as_bool().unwrap_or(false) {
                "hardware-bound"
            } else {
                "NOT hardware-bound"
            };
            output::print_field(
                d["label"].as_str().unwrap_or("(unlabelled)"),
                &format!(
                    "{bound} — {} / {}, chain {}",
                    d["attestation_format"].as_str().unwrap_or("?"),
                    d["key_protection"].as_str().unwrap_or("?"),
                    if d["chain_verified"].as_bool().unwrap_or(false) {
                        "verified"
                    } else {
                        "unverified"
                    }
                ),
            );
        }
        println!();
        match result["wallet_blocker"].as_str() {
            Some(why) => output::print_warning(why),
            None => output::print_field("Wallet", "ready"),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ReadinessCmd {
    did: String,
    /// Credential id of the device you are on, when it is one of the bound
    /// ones. Supplying it is what lets the check notice that every bound
    /// device is this same machine.
    #[arg(long)]
    this_device: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ReadinessCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_walletReadiness",
                serde_json::json!({
                    "identity_did": self.did,
                    "this_device_credential_id": self.this_device,
                }),
            )
            .await?;

        output::print_header("Wallet readiness");
        output::print_field("Identity", &self.did);
        output::print_field(
            "Bound devices",
            &format!(
                "{} ({} hardware-bound)",
                result["bound_devices"], result["hardware_bound_devices"]
            ),
        );
        if result["ready"].as_bool().unwrap_or(false) {
            output::print_field("Status", "ready — a wallet may be created");
        } else {
            output::print_warning(result["blocker"].as_str().unwrap_or("not ready"));
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RevokeCmd {
    did: String,
    /// Credential id of the device to unbind.
    credential_id: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RevokeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_revokeBoundDevice",
                serde_json::json!({
                    "identity_did": self.did,
                    "credential_id": self.credential_id,
                }),
            )
            .await?;
        output::print_header("Device revoked");
        output::print_field("Removed", &result["removed"].to_string());
        output::print_field("Sessions ended", &result["sessions_ended"].to_string());
        output::print_field(
            "Devices remaining",
            &result["devices_remaining"].to_string(),
        );
        if !result["wallet_ready"].as_bool().unwrap_or(true) {
            output::print_warning(
                "This identity can no longer create a wallet — bind another device.",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TransferCmd {
    /// Machine being transferred.
    machine_did: String,
    /// Identity taking ownership.
    new_owner_did: String,
    /// `controller` for a machine a party delegated, `hardware_root` for one
    /// nobody delegated. The two are not interchangeable.
    #[arg(long, default_value = "controller")]
    authority: String,
    /// The controlling DID, for a controller-authorised transfer.
    #[arg(long)]
    controller_did: Option<String>,
    /// The machine root proven, for a hardware-authorised transfer.
    #[arg(long)]
    hardware_root_hex: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TransferCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_transferMachineOwnership",
                serde_json::json!({
                    "machine_did": self.machine_did,
                    "new_owner_did": self.new_owner_did,
                    "authority": self.authority,
                    "controller_did": self.controller_did,
                    "hardware_root_hex": self.hardware_root_hex,
                }),
            )
            .await?;
        output::print_header("Machine ownership transferred");
        output::print_field("Machine", &self.machine_did);
        output::print_field(
            "Previous owner",
            result["previous_owner"].as_str().unwrap_or("(none)"),
        );
        output::print_field("New owner", result["new_owner"].as_str().unwrap_or("?"));
        output::print_field(
            "Authorised by",
            result["authorised_by"].as_str().unwrap_or("?"),
        );
        Ok(())
    }
}
