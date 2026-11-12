//! `tenzro wallet outflow`: an account's opt-in outflow policy. A cap per
//! window, a hold (the cancel window) and an optional guardian on different
//! hardware; larger payments are queued and can be cancelled before they are
//! paid. Every command shows, in plain language, what it will do before the
//! hardware is asked to sign.

use crate::output;
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use tenzro_types::account_outflow_ui::{OutflowRequest, PolicyView, ReleaseView, describe_state};

const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
const GAS: u64 = 100_000;

/// Outflow policy commands.
#[derive(Debug, Subcommand)]
pub enum OutflowCommand {
    /// Show an account's policy and its queued payments
    Show(ShowCmd),
    /// Set or change the policy (a loosening is queued for the hold)
    Set(SetCmd),
    /// Remove the policy (queued for the hold)
    Remove(Common),
    /// Cancel a queued change to the policy (the account or its guardian)
    CancelPending(Common),
    /// Queue a payment of any size; it can be paid after the hold
    Release(ReleaseCmd),
    /// Cancel a queued payment (the account or its guardian)
    CancelRelease(IdCmd),
    /// Pay a queued payment (the account after the hold, the guardian at once)
    Claim(IdCmd),
    /// Check a delegation target before signing a delegation to it
    DelegateCheck(DelegateCheckCmd),
    /// Print the bytes a guardian's passkey signs for one action
    ApprovalTarget(ApprovalTargetCmd),
}

impl OutflowCommand {
    /// Run the command.
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Show(c) => c.execute().await,
            Self::Set(c) => c.execute().await,
            Self::Remove(c) => submit(c, OutflowRequest::Remove).await,
            Self::CancelPending(c) => {
                submit(
                    c,
                    OutflowRequest::CancelPending {
                        approval: load_approval(c)?,
                    },
                )
                .await
            }
            Self::Release(c) => {
                let to = crate::keystore::address32(&c.to)?.to_vec();
                submit(
                    &c.common,
                    OutflowRequest::RequestRelease {
                        to,
                        amount: parse_tnzo(&c.amount)?,
                    },
                )
                .await
            }
            Self::CancelRelease(c) => {
                submit(
                    &c.common,
                    OutflowRequest::CancelRelease {
                        id: c.id,
                        approval: load_approval(&c.common)?,
                    },
                )
                .await
            }
            Self::Claim(c) => {
                submit(
                    &c.common,
                    OutflowRequest::ClaimRelease {
                        id: c.id,
                        approval: load_approval(&c.common)?,
                    },
                )
                .await
            }
            Self::DelegateCheck(c) => c.execute().await,
            Self::ApprovalTarget(c) => c.execute().await,
        }
    }
}

/// Arguments every sending command shares.
#[derive(Debug, Parser)]
pub struct Common {
    /// The account the policy belongs to, hex. Default: this machine's client
    /// account. A guardian names the account it guards and signs as itself.
    #[arg(long)]
    account: Option<String>,
    /// The signing account's hardware key namespace
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Sign without typing `yes` at the prompt (the preview is still shown)
    #[arg(long)]
    yes: bool,
    /// The guardian's passkey approval (JSON file), needed when the account's
    /// guardian cancels or pays early. `approval-target` prints what it signs.
    #[arg(long)]
    approval_file: Option<std::path::PathBuf>,
}

fn load_approval(c: &Common) -> Result<Option<serde_json::Value>> {
    match &c.approval_file {
        Some(p) => Ok(Some(serde_json::from_slice(&std::fs::read(p)?)?)),
        None => Ok(None),
    }
}

/// `outflow show`.
#[derive(Debug, Parser)]
pub struct ShowCmd {
    /// The account, hex. Default: this machine's client account.
    #[arg(long)]
    account: Option<String>,
    /// The key namespace used to find the default account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

/// `outflow set`.
#[derive(Debug, Parser)]
pub struct SetCmd {
    #[command(flatten)]
    common: Common,
    /// Most the account may send per window, in TNZO
    #[arg(long)]
    cap: String,
    /// The window the cap counts over, in hours
    #[arg(long, default_value_t = 24)]
    window_hours: u64,
    /// How long a queued payment waits, in hours
    #[arg(long, default_value_t = 24)]
    hold_hours: u64,
    /// The guardian: a person's identity (DID) whose passkey approves a cancel
    /// or an early payment, ideally on different hardware from this account
    #[arg(long)]
    guardian: Option<String>,
}

/// `outflow release`.
#[derive(Debug, Parser)]
pub struct ReleaseCmd {
    #[command(flatten)]
    common: Common,
    /// Recipient address
    to: String,
    /// Amount in TNZO
    amount: String,
}

/// `outflow approval-target`.
#[derive(Debug, Parser)]
pub struct ApprovalTargetCmd {
    /// cancel_pending, cancel_release or claim_release
    action: String,
    /// The queued payment's number (0 for cancel_pending)
    #[arg(long, default_value_t = 0)]
    id: u64,
    /// The guarded account, hex
    #[arg(long)]
    account: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ApprovalTargetCmd {
    async fn execute(&self) -> Result<()> {
        if !matches!(
            self.action.as_str(),
            "cancel_pending" | "cancel_release" | "claim_release"
        ) {
            bail!("action is cancel_pending, cancel_release or claim_release");
        }
        let account = crate::keystore::address32(&self.account)?.to_vec();
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_getAccountOutflow",
                serde_json::json!({ "account": hex::encode(&account) }),
            )
            .await?;
        let step = v.get("approval_step").and_then(|s| s.as_u64()).unwrap_or(0);
        let bytes = tenzro_types::account_outflow_ui::approval_target(
            &account,
            &self.action,
            self.id,
            step,
        );
        output::print_field("Approval counter", &step.to_string());
        output::print_field("Guardian signs", &format!("0x{}", hex::encode(bytes)));
        output::print_info(
            "The approval is good for this one action only; once used the counter moves.",
        );
        Ok(())
    }
}

/// `outflow delegate-check`.
#[derive(Debug, Parser)]
pub struct DelegateCheckCmd {
    /// The delegate's address (hex)
    target: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DelegateCheckCmd {
    async fn execute(&self) -> Result<()> {
        output::print_header("Delegation Target");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_checkDelegateTarget",
                serde_json::json!({ "address": self.target }),
            )
            .await?;
        let status = tenzro_types::delegation_ui::DelegateStatus::from_rpc(&v)
            .ok_or_else(|| anyhow::anyhow!("the node did not answer the delegate check"))?;
        let warning = status.warning(&self.target);
        if warning.is_empty() {
            output::print_success(
                "This delegate is recognised (or the request clears a delegation).",
            );
        }
        for line in warning {
            output::print_warning(&line);
        }
        Ok(())
    }
}

/// A command that names a queued payment.
#[derive(Debug, Parser)]
pub struct IdCmd {
    #[command(flatten)]
    common: Common,
    /// The queued payment's number (see `outflow show`)
    id: u64,
}

/// A decimal TNZO amount in wei, exactly.
fn parse_tnzo(s: &str) -> Result<u128> {
    let t = s.trim();
    let (whole, frac) = t.split_once('.').unwrap_or((t, ""));
    if whole.is_empty() && frac.is_empty()
        || frac.len() > 18
        || !whole.chars().all(|c| c.is_ascii_digit())
        || !frac.chars().all(|c| c.is_ascii_digit())
    {
        bail!("{s} is not an amount in TNZO");
    }
    let w: u128 = if whole.is_empty() { 0 } else { whole.parse()? };
    let f: u128 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<18}").parse()?
    };
    w.checked_mul(ONE_TNZO)
        .and_then(|x| x.checked_add(f))
        .ok_or_else(|| anyhow::anyhow!("{s} is too large"))
}

fn account_bytes(account: &Option<String>, namespace: &str) -> Result<Vec<u8>> {
    let hex = match account {
        Some(a) => a.clone(),
        None => crate::keystore::client_account(namespace)?.0,
    };
    Ok(crate::keystore::address32(&hex)?.to_vec())
}

async fn read_state(
    rpc: &crate::rpc::RpcClient,
    account: &[u8],
) -> Result<(Option<PolicyView>, Vec<ReleaseView>, i64)> {
    let v: serde_json::Value = rpc
        .call(
            "tenzro_getAccountOutflow",
            serde_json::json!({ "account": hex::encode(account) }),
        )
        .await?;
    let policy = v.get("policy").and_then(PolicyView::from_rpc);
    let releases = v
        .get("releases")
        .and_then(|r| r.as_array())
        .map(|a| a.iter().filter_map(ReleaseView::from_rpc).collect())
        .unwrap_or_default();
    let now = v.get("now_ms").and_then(|n| n.as_i64()).unwrap_or(0);
    Ok((policy, releases, now))
}

impl ShowCmd {
    async fn execute(&self) -> Result<()> {
        output::print_header("Outflow Policy");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let account = account_bytes(&self.account, &self.key_namespace)?;
        let (policy, releases, now) = read_state(&rpc, &account).await?;
        output::print_field("Account", &format!("0x{}", hex::encode(&account)));
        for line in describe_state(policy.as_ref(), &releases, now) {
            output::print_info(&line);
        }
        Ok(())
    }
}

impl SetCmd {
    async fn execute(&self) -> Result<()> {
        let guardian = self.guardian.clone();
        let req = OutflowRequest::Set {
            window_ms: self.window_hours.saturating_mul(3_600_000),
            cap: parse_tnzo(&self.cap)?,
            hold_ms: self.hold_hours.saturating_mul(3_600_000),
            guardian,
        };
        submit(&self.common, req).await
    }
}

/// Preview the request, ask for confirmation, then sign it in hardware and send.
async fn submit(c: &Common, req: OutflowRequest) -> Result<()> {
    use std::io::IsTerminal;
    output::print_header("Outflow Policy");
    let rpc = crate::rpc::RpcClient::new(&c.rpc);
    let account = account_bytes(&c.account, &c.key_namespace)?;
    let (policy, _releases, now) = read_state(&rpc, &account).await?;
    output::print_field("Account", &format!("0x{}", hex::encode(&account)));
    for line in req.describe(policy.as_ref(), now) {
        output::print_info(&line);
    }
    if !c.yes {
        if !std::io::stdin().is_terminal() {
            bail!("pass --yes to sign without a prompt; nothing was signed");
        }
        println!("Type yes to sign this in hardware:");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if line.trim() != "yes" {
            bail!("not confirmed; nothing was signed");
        }
    }
    let to: [u8; 32] = account
        .clone()
        .try_into()
        .map_err(|_| anyhow::anyhow!("account is not 32 bytes"))?;
    let result =
        crate::keystore::send_as_client(&rpc, &c.key_namespace, to, req.tx_type(&account), GAS)
            .await?;
    output::print_success("Signed in hardware and submitted");
    output::print_field(
        "Transaction Hash",
        &result
            .as_str()
            .map_or_else(|| result.to_string(), str::to_string),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_exact_and_strict() {
        assert_eq!(parse_tnzo("10").unwrap(), 10 * ONE_TNZO);
        assert_eq!(parse_tnzo("0.5").unwrap(), ONE_TNZO / 2);
        assert_eq!(parse_tnzo("1.000000000000000001").unwrap(), ONE_TNZO + 1);
        assert!(parse_tnzo("1,5").is_err());
        assert!(parse_tnzo("").is_err());
        assert!(parse_tnzo("1.0000000000000000001").is_err());
        assert!(parse_tnzo("-1").is_err());
    }
}
