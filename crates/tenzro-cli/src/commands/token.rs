//! Token management commands for the Tenzro CLI
//!
//! Create, query, and manage tokens across VMs on the Tenzro Ledger.

use crate::output;
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use tenzro_types::token_op::TokenOp;
use tenzro_types::token_policy::{
    IssuerAction, KeySet, PowerManifest, ReserveBacking, TokenPolicy,
};
use tenzro_types::transaction::TransactionType;

use super::signer::Signer;

/// Token management commands
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    #[command(flatten)]
    Rpc(TokenRpcCommand),
    /// Create a token issued by the client account (signed in hardware)
    Create(TokenCreateCmd),
    /// Issue more of a token (by its mint authority)
    Mint(TokenMintCmd),
    /// Retire part of the client account's balance
    Burn(TokenBurnCmd),
    /// Move part of the client account's balance
    Transfer(TokenTransferCmd),
    /// Freeze part of a holder's balance (freeze authority; zero unfreezes)
    Freeze(TokenFreezeCmd),
    /// Halt or resume holder transfers (halt authority)
    Halt(TokenHaltCmd),
    /// Move a holder's balance past a halt or a freeze (force authority)
    ForceTransfer(TokenForceTransferCmd),
    /// Narrow who holds an issuer power (never widens)
    Renounce(TokenRenounceCmd),
    /// Queue a new eligibility policy (applies after the policy timelock)
    SetPolicy(TokenSetPolicyCmd),
    /// Queue new reserve backing (applies after the policy timelock)
    SetReserveBacking(TokenSetReserveBackingCmd),
    /// Apply a queued policy or reserve-backing change whose timelock has passed
    ExecutePolicy(TokenIdCmd),
    /// Record a claim about an account (a claim issuer the token names)
    Claim(TokenClaimCmd),
    /// Withdraw a claim the client account made
    RevokeClaim(TokenRevokeClaimCmd),
    /// Approve an issuer operation as an issuer-council member
    Approve(TokenApproveCmd),
    /// Check whether the token's rules allow a transfer now
    CanTransfer(TokenCanTransferCmd),
    /// Get information about a token
    Info(TokenInfoCmd),
    /// List registered tokens
    List(TokenListCmd),
    /// Get token balance across all VMs
    Balance(TokenBalanceCmd),
}

impl TokenCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Create(cmd) => cmd.execute().await,
            Self::Mint(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::Burn(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::Transfer(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::Freeze(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::Halt(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::ForceTransfer(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::Renounce(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::SetPolicy(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::SetReserveBacking(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::ExecutePolicy(cmd) => {
                let op = TokenOp::ExecutePolicy {
                    token_id: token_id(&cmd.token_id)?,
                };
                cmd.signer.send_tx(token_tx(op), "Token").await
            }
            Self::Claim(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::RevokeClaim(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::Approve(cmd) => cmd.signer.send_tx(token_tx(cmd.op()?), "Token").await,
            Self::CanTransfer(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Balance(cmd) => cmd.execute().await,
        }
    }
}

fn token_tx(op: TokenOp) -> TransactionType {
    TransactionType::Token { op }
}

fn token_id(hex_id: &str) -> Result<[u8; 32]> {
    hex::decode(hex_id.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| anyhow!("a token id is 32 bytes of hex"))
}

fn account(hex_account: &str) -> Result<Vec<u8>> {
    hex::decode(hex_account.trim_start_matches("0x"))
        .ok()
        .filter(|b| b.len() == 20 || b.len() == 32)
        .ok_or_else(|| anyhow!("an account is 20 or 32 bytes of hex"))
}

fn amount(s: &str) -> Result<u128> {
    s.parse()
        .map_err(|_| anyhow!("an amount is a decimal in the token's smallest unit"))
}

/// Create a token issued by the client account, as a `Token` transaction
/// signed in hardware. The power manifest names who may mint, freeze, halt,
/// force and change the policy; it only ever narrows afterwards.
#[derive(Debug, Parser)]
pub struct TokenCreateCmd {
    /// Token name (e.g. "My Token")
    #[arg(long)]
    name: String,
    /// Token symbol (e.g. "MTK")
    #[arg(long)]
    symbol: String,
    /// Initial supply credited to the issuer (smallest units)
    #[arg(long)]
    supply: String,
    /// Token decimals
    #[arg(long, default_value = "18")]
    decimals: u8,
    /// Ceiling on the supply (smallest units)
    #[arg(long)]
    max_supply: Option<String>,
    /// Power manifest JSON, e.g. '{"mint":"issuer","freeze":"disabled",...}'
    #[arg(long)]
    powers: String,
    /// Eligibility policy JSON: '{"eligibility":[...],"policy_timelock_ms":604800000}'
    #[arg(long)]
    policy: String,
    /// Issuer council JSON '{"k":2,"members":["<hex>",...]}', when a power names one
    #[arg(long)]
    council: Option<String>,
    /// For a token backed one to one by reserves: the bonded attestor stake,
    /// whole TNZO, each mint's reserve attestations must hold between them.
    /// Any bonded attestor may attest
    #[arg(long)]
    reserve_attestor_stake: Option<u64>,
    #[command(flatten)]
    signer: Signer,
}

impl TokenCreateCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Create Token");
        let op = TokenOp::Create {
            name: self.name.clone(),
            symbol: self.symbol.clone(),
            decimals: self.decimals,
            initial_supply: amount(&self.supply)?,
            max_supply: self.max_supply.as_deref().map(amount).transpose()?,
            powers: serde_json::from_str::<PowerManifest>(&self.powers)?,
            policy: serde_json::from_str::<TokenPolicy>(&self.policy)?,
            council: self
                .council
                .as_deref()
                .map(serde_json::from_str::<KeySet>)
                .transpose()?,
            reserve_backing: self.reserve_attestor_stake.map(|t| ReserveBacking {
                min_attestor_stake_tnzo: t,
            }),
        };
        op.validate().map_err(|e| anyhow!(e))?;
        self.signer.send_tx(token_tx(op), "Token").await
    }
}

/// Issue more of a token (by its mint authority)
#[derive(Debug, Parser)]
pub struct TokenMintCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Recipient account (hex)
    #[arg(long)]
    to: String,
    /// Amount (smallest units)
    #[arg(long)]
    amount: String,
    /// JSON files holding the reserve attestations a reserve-backed token
    /// needs (one per attestor)
    #[arg(long)]
    reserve: Vec<std::path::PathBuf>,
    #[command(flatten)]
    signer: Signer,
}

impl TokenMintCmd {
    fn op(&self) -> Result<TokenOp> {
        let reserves = self
            .reserve
            .iter()
            .map(|path| Ok(serde_json::from_slice(&std::fs::read(path)?)?))
            .collect::<Result<Vec<_>>>()?;
        Ok(TokenOp::Mint {
            token_id: token_id(&self.token_id)?,
            to: account(&self.to)?,
            amount: amount(&self.amount)?,
            reserves,
        })
    }
}

/// Retire part of the client account's balance
#[derive(Debug, Parser)]
pub struct TokenBurnCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Amount (smallest units)
    #[arg(long)]
    amount: String,
    #[command(flatten)]
    signer: Signer,
}

impl TokenBurnCmd {
    fn op(&self) -> Result<TokenOp> {
        Ok(TokenOp::Burn {
            token_id: token_id(&self.token_id)?,
            amount: amount(&self.amount)?,
        })
    }
}

/// Move part of the client account's balance
#[derive(Debug, Parser)]
pub struct TokenTransferCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Recipient account (hex)
    #[arg(long)]
    to: String,
    /// Amount (smallest units)
    #[arg(long)]
    amount: String,
    #[command(flatten)]
    signer: Signer,
}

impl TokenTransferCmd {
    fn op(&self) -> Result<TokenOp> {
        Ok(TokenOp::Transfer {
            token_id: token_id(&self.token_id)?,
            to: account(&self.to)?,
            amount: amount(&self.amount)?,
        })
    }
}

/// Freeze part of a holder's balance (issuer only; zero unfreezes)
#[derive(Debug, Parser)]
pub struct TokenFreezeCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Holder account (hex)
    #[arg(long)]
    account: String,
    /// Amount frozen (smallest units)
    #[arg(long)]
    amount: String,
    #[command(flatten)]
    action: ActionArgs,
    #[command(flatten)]
    signer: Signer,
}

impl TokenFreezeCmd {
    fn op(&self) -> Result<TokenOp> {
        Ok(TokenOp::SetFrozen {
            token_id: token_id(&self.token_id)?,
            account: account(&self.account)?,
            amount: amount(&self.amount)?,
            action: self.action.action()?,
        })
    }
}

/// Halt or resume holder transfers (issuer only)
#[derive(Debug, Parser)]
pub struct TokenHaltCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Resume transfers instead of halting them
    #[arg(long)]
    resume: bool,
    #[command(flatten)]
    action: ActionArgs,
    #[command(flatten)]
    signer: Signer,
}

impl TokenHaltCmd {
    fn op(&self) -> Result<TokenOp> {
        Ok(TokenOp::SetHalted {
            token_id: token_id(&self.token_id)?,
            halted: !self.resume,
            action: self.action.action()?,
        })
    }
}

/// Move a holder's balance past a halt or a freeze (force authority)
#[derive(Debug, Parser)]
pub struct TokenForceTransferCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Holder debited (hex)
    #[arg(long)]
    from: String,
    /// Account credited (hex)
    #[arg(long)]
    to: String,
    /// Amount (smallest units)
    #[arg(long)]
    amount: String,
    #[command(flatten)]
    action: ActionArgs,
    #[command(flatten)]
    signer: Signer,
}

impl TokenForceTransferCmd {
    fn op(&self) -> Result<TokenOp> {
        Ok(TokenOp::ForcedTransfer {
            token_id: token_id(&self.token_id)?,
            from: account(&self.from)?,
            to: account(&self.to)?,
            amount: amount(&self.amount)?,
            action: self.action.action()?,
        })
    }
}

/// The reason and evidence every freeze, halt and forced transfer carries.
#[derive(Debug, clap::Args)]
pub struct ActionArgs {
    /// Issuer reason code (non-zero)
    #[arg(long)]
    reason_code: u16,
    /// SHA-256 of the evidence held off-chain (hex)
    #[arg(long)]
    evidence: String,
}

impl ActionArgs {
    fn action(&self) -> Result<IssuerAction> {
        let action = IssuerAction {
            reason_code: self.reason_code,
            evidence_hash: token_id(&self.evidence)?,
        };
        action.validate().map_err(|e| anyhow!(e))?;
        Ok(action)
    }
}

/// Narrow who holds an issuer power
#[derive(Debug, Parser)]
pub struct TokenRenounceCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// The power: mint, freeze, halt, force or policy_change
    #[arg(long)]
    power: String,
    /// Who holds it afterwards, JSON: '"disabled"' or '{"issuer_council":{"k":3}}'
    #[arg(long)]
    to: String,
    #[command(flatten)]
    signer: Signer,
}

impl TokenRenounceCmd {
    fn op(&self) -> Result<TokenOp> {
        Ok(TokenOp::RenouncePower {
            token_id: token_id(&self.token_id)?,
            power: serde_json::from_value(serde_json::Value::String(self.power.clone()))?,
            to: serde_json::from_str(&self.to)?,
        })
    }
}

/// Queue a new eligibility policy
#[derive(Debug, Parser)]
pub struct TokenSetPolicyCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Policy JSON: '{"eligibility":[...],"policy_timelock_ms":604800000}'
    #[arg(long)]
    policy: String,
    #[command(flatten)]
    signer: Signer,
}

impl TokenSetPolicyCmd {
    fn op(&self) -> Result<TokenOp> {
        let policy: TokenPolicy = serde_json::from_str(&self.policy)?;
        policy.validate().map_err(|e| anyhow!(e))?;
        Ok(TokenOp::SetPolicy {
            token_id: token_id(&self.token_id)?,
            policy,
        })
    }
}

/// Queue new reserve backing
#[derive(Debug, Parser)]
pub struct TokenSetReserveBackingCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Bonded attestor stake, whole TNZO, each mint's reserve attestations
    /// must hold between them; omit to remove the backing
    #[arg(long)]
    attestor_stake: Option<u64>,
    #[command(flatten)]
    signer: Signer,
}

impl TokenSetReserveBackingCmd {
    fn op(&self) -> Result<TokenOp> {
        Ok(TokenOp::SetReserveBacking {
            token_id: token_id(&self.token_id)?,
            backing: self.attestor_stake.map(|t| ReserveBacking {
                min_attestor_stake_tnzo: t,
            }),
        })
    }
}

/// A token id and a signer
#[derive(Debug, Parser)]
pub struct TokenIdCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    #[command(flatten)]
    signer: Signer,
}

/// Record a claim about an account
#[derive(Debug, Parser)]
pub struct TokenClaimCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Account the claim is about (hex)
    #[arg(long)]
    subject: String,
    /// Claim kind (kyc, accredited, jurisdiction, ...)
    #[arg(long)]
    kind: String,
    /// Claim value (a jurisdiction code, a level, ...)
    #[arg(long, default_value = "")]
    value: String,
    /// Block time (Unix ms) the claim lapses at
    #[arg(long)]
    expires_ms: i64,
    #[command(flatten)]
    signer: Signer,
}

impl TokenClaimCmd {
    fn op(&self) -> Result<TokenOp> {
        Ok(TokenOp::AddClaim {
            token_id: token_id(&self.token_id)?,
            subject: account(&self.subject)?,
            kind: self.kind.clone(),
            value: self.value.clone(),
            expires_ms: self.expires_ms,
        })
    }
}

/// Withdraw a claim
#[derive(Debug, Parser)]
pub struct TokenRevokeClaimCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Account the claim is about (hex)
    #[arg(long)]
    subject: String,
    /// Claim kind
    #[arg(long)]
    kind: String,
    #[command(flatten)]
    signer: Signer,
}

impl TokenRevokeClaimCmd {
    fn op(&self) -> Result<TokenOp> {
        Ok(TokenOp::RevokeClaim {
            token_id: token_id(&self.token_id)?,
            subject: account(&self.subject)?,
            kind: self.kind.clone(),
        })
    }
}

/// Approve an issuer operation as a council member
#[derive(Debug, Parser)]
pub struct TokenApproveCmd {
    /// The issuer operation as TokenOp JSON (for example a set_frozen op)
    #[arg(long)]
    op: String,
    #[command(flatten)]
    signer: Signer,
}

impl TokenApproveCmd {
    fn op(&self) -> Result<TokenOp> {
        let op = TokenOp::Approve {
            op: Box::new(serde_json::from_str(&self.op)?),
        };
        op.validate().map_err(|e| anyhow!(e))?;
        Ok(op)
    }
}

/// Check whether a transfer is allowed now
#[derive(Debug, Parser)]
pub struct TokenCanTransferCmd {
    /// Token id (hex)
    #[arg(long)]
    token_id: String,
    /// Sender (hex)
    #[arg(long)]
    from: String,
    /// Recipient (hex)
    #[arg(long)]
    to: String,
    /// Amount (smallest units)
    #[arg(long)]
    amount: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenCanTransferCmd {
    async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_canTransfer",
                serde_json::json!({ "token_id": self.token_id, "from": self.from, "to": self.to, "amount": self.amount }),
            )
            .await?;
        output::print_header("Can Transfer");
        output::print_field("Allowed", &result["allowed"].to_string());
        if let Some(reason) = result.get("reason").and_then(|r| r.as_str()) {
            output::print_field("Code", &result["code"].to_string());
            output::print_field("Reason", reason);
        }
        Ok(())
    }
}

/// Get information about a token
#[derive(Debug, Parser)]
pub struct TokenInfoCmd {
    /// Token symbol (e.g. "TNZO")
    #[arg(long)]
    symbol: Option<String>,
    /// EVM contract address
    #[arg(long)]
    address: Option<String>,
    /// Token ID (hex)
    #[arg(long)]
    id: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Token Info");
        let spinner = output::create_spinner("Querying token...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::Map::new();
        if let Some(ref s) = self.symbol {
            params.insert("symbol".into(), serde_json::json!(s));
        }
        if let Some(ref a) = self.address {
            params.insert("evm_address".into(), serde_json::json!(a));
        }
        if let Some(ref i) = self.id {
            params.insert("token_id".into(), serde_json::json!(i));
        }

        let result: serde_json::Value = rpc
            .call("tenzro_getToken", serde_json::Value::Object(params))
            .await?;

        spinner.finish_and_clear();

        output::print_field(
            "Token ID",
            result
                .get("token_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
        );
        output::print_field(
            "Name",
            result.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Symbol",
            result.get("symbol").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Decimals",
            &result
                .get("decimals")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        output::print_field(
            "Total Supply",
            result
                .get("total_supply")
                .and_then(|v| v.as_str())
                .unwrap_or("0"),
        );
        output::print_field(
            "Type",
            result
                .get("token_type")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        output::print_field(
            "EVM Address",
            result
                .get("evm_address")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A"),
        );
        output::print_field(
            "SVM Mint",
            result
                .get("svm_mint")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A"),
        );
        output::print_field(
            "Tempo Address",
            result
                .get("tempo_address")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A"),
        );
        output::print_field(
            "Creator",
            result.get("creator").and_then(|v| v.as_str()).unwrap_or(""),
        );

        Ok(())
    }
}

/// List registered tokens
#[derive(Debug, Parser)]
pub struct TokenListCmd {
    /// Filter by VM type: evm, svm, native
    #[arg(long)]
    vm: Option<String>,
    /// Maximum tokens to list
    #[arg(long, default_value = "50")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Registered Tokens");
        let spinner = output::create_spinner("Loading tokens...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({ "limit": self.limit });
        if let Some(ref vm) = self.vm {
            params["vm_type"] = serde_json::json!(vm);
        }

        let result: serde_json::Value = rpc.call("tenzro_listTokens", params).await?;

        spinner.finish_and_clear();

        if let Some(tokens) = result.get("tokens").and_then(|v| v.as_array()) {
            if tokens.is_empty() {
                output::print_info("No tokens registered.");
            } else {
                let headers = vec!["Symbol", "Name", "Decimals", "Supply", "EVM Address"];
                let mut rows = Vec::new();
                for t in tokens {
                    rows.push(vec![
                        t.get("symbol")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        t.get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        t.get("decimals")
                            .and_then(|v| v.as_u64())
                            .map(|v| v.to_string())
                            .unwrap_or_default(),
                        t.get("total_supply")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0")
                            .to_string(),
                        t.get("evm_address")
                            .and_then(|v| v.as_str())
                            .unwrap_or("N/A")
                            .to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// Get token balance across all VMs
#[derive(Debug, Parser)]
pub struct TokenBalanceCmd {
    /// Address to query (hex)
    address: String,
    /// Token symbol (default: TNZO)
    #[arg(long, default_value = "TNZO")]
    token: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenBalanceCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Token Balance (Cross-VM)");
        let spinner = output::create_spinner("Querying balances...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc
            .call(
                "tenzro_getTokenBalance",
                serde_json::json!({
                    "address": self.address,
                    "token": self.token,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        output::print_field("Address", &self.address);

        if let Some(native) = result.get("native") {
            output::print_field(
                "Native (18 dec)",
                native
                    .get("display")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0"),
            );
        }
        if let Some(evm) = result.get("evm_wtnzo") {
            output::print_field(
                "EVM wTNZO (18 dec)",
                evm.get("balance").and_then(|v| v.as_str()).unwrap_or("0"),
            );
        }
        if let Some(svm) = result.get("svm_wtnzo") {
            output::print_field(
                "SVM wTNZO (9 dec)",
                svm.get("balance").and_then(|v| v.as_str()).unwrap_or("0"),
            );
        }

        Ok(())
    }
}

/// Token commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum TokenRpcCommand {
    /// Call tenzro_readPorReserve (read por reserve) and print the node's answer
    PorReserve(TokenPorReserveRpcCmd),
    /// Call tenzro_getReserveFeed: the reserve feed governance installed for an asset
    ReserveFeed(TokenReserveFeedRpcCmd),
    /// Call tenzro_buildReserveAttestationFromPor (build reserve attestation from por) and print the node's answer
    BuildReserveAttestationFromPor(TokenBuildReserveAttestationFromPorRpcCmd),
}

impl TokenRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::PorReserve(cmd) => cmd.execute().await,
            Self::ReserveFeed(cmd) => cmd.execute().await,
            Self::BuildReserveAttestationFromPor(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_readPorReserve (read por reserve)
#[derive(Debug, clap::Parser)]
pub struct TokenPorReserveRpcCmd {
    /// asset id
    #[arg(long)]
    asset_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenPorReserveRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_readPorReserve",
                serde_json::json!({ "asset_id": self.asset_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getReserveFeed: the Proof-of-Reserve feed a SetReserveFeed vote installed
#[derive(Debug, clap::Parser)]
pub struct TokenReserveFeedRpcCmd {
    /// asset id (`tnzo:<route key>` for a bridge route)
    #[arg(long)]
    asset_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenReserveFeedRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getReserveFeed",
                serde_json::json!({ "asset_id": self.asset_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_buildReserveAttestationFromPor (build reserve attestation from por)
#[derive(Debug, clap::Parser)]
pub struct TokenBuildReserveAttestationFromPorRpcCmd {
    /// asset id
    #[arg(long)]
    asset_id: String,
    /// attestor did
    #[arg(long)]
    attestor_did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenBuildReserveAttestationFromPorRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_buildReserveAttestationFromPor",
                serde_json::json!({ "asset_id": self.asset_id, "attestor_did": self.attestor_did }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}
