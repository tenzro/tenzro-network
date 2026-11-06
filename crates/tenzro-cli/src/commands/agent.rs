//! Agent management commands for the Tenzro CLI
//!
//! Register, list, and message AI agents on the Tenzro Network.

use crate::output;
use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};

/// Agent management commands
#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    #[command(flatten)]
    Rpc(AgentRpcCommand),
    /// Fund an agent's wallet
    Fund(AgentFundCmd),
    /// Pause an agent via kill-switch (reversible). Freezes payments, allows
    /// reward distribution + stake withdrawals.
    Pause(AgentPauseCmd),
    /// Quarantine an agent via kill-switch (reversible). Freezes payments,
    /// reward distribution, and stake withdrawals; stake remains intact.
    Quarantine(AgentQuarantineCmd),
    /// Lift an agent's quarantine. Only the owner or controller the
    /// quarantine names may, signing with the wallet its identity is
    /// registered with
    LiftQuarantine(AgentLiftQuarantineCmd),
    /// Terminate an agent via kill-switch (irreversible). Slashes stake by
    /// `slash_bps`, optionally cascades to descendants.
    Terminate(AgentTerminateCmd),
    /// The audit trail a node keeps of an agent's actions: fetch an entry
    /// and check it against the root committed on chain
    #[command(subcommand)]
    Audit(AgentAuditCommand),
    /// Agents a human delegates with their passkey: approve terms, change
    /// them, revoke
    #[command(subcommand)]
    Delegation(super::agent_delegation::AgentDelegationCommand),
    /// The agent's account on every other chain the network configures
    Accounts(super::agent_accounts::AccountsCmd),
    /// Issue a grant on another chain, as the agent
    Grant(super::agent_accounts::GrantCmd),
    /// The agent's grant on a chain and its state proof
    GrantProof(super::agent_accounts::GrantProofCmd),
    /// The serving node's signature over an action on another chain
    Act(super::agent_accounts::ActCmd),
    /// What a relayer installs with the account's sync on its chain
    Sync(super::agent_accounts::SyncCmd),
    /// The consent that makes the agent's EVM account its ERC-8004 agentWallet
    WalletConsent(super::agent_accounts::WalletConsentCmd),
}

impl AgentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Accounts(cmd) => cmd.execute().await,
            Self::Grant(cmd) => cmd.execute().await,
            Self::GrantProof(cmd) => cmd.execute().await,
            Self::Act(cmd) => cmd.execute().await,
            Self::Sync(cmd) => cmd.execute().await,
            Self::WalletConsent(cmd) => cmd.execute().await,
            Self::Fund(cmd) => cmd.execute().await,
            Self::Pause(cmd) => cmd.execute().await,
            Self::Quarantine(cmd) => cmd.execute().await,
            Self::LiftQuarantine(cmd) => cmd.execute().await,
            Self::Terminate(cmd) => cmd.execute().await,
            Self::Audit(cmd) => cmd.execute().await,
            Self::Delegation(cmd) => cmd.execute().await,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Agent wallet commands
// ─────────────────────────────────────────────────────────────

/// Fund an agent's wallet: a TNZO transfer to it, signed as this machine's
/// client account
#[derive(Debug, Parser)]
pub struct AgentFundCmd {
    /// The agent's DID; its wallet is the one its consensus Terms name
    #[arg(long)]
    agent_did: String,
    /// Amount to fund, in wei (1 TNZO = 10^18 wei)
    #[arg(long)]
    amount_wei: u128,
    /// The paying client identity's hardware key namespace
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentFundCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Fund Agent");
        let rpc = RpcClient::new(&self.rpc);
        let to = tenzro_types::agent_terms::agent_wallet(&self.agent_did);
        let wallet = format!("0x{}", hex::encode(to));
        let tx_type = serde_json::json!({ "Transfer": { "amount": self.amount_wei.to_string() } });
        let result =
            crate::keystore::send_as_client(&rpc, &self.key_namespace, to, tx_type, 21_000).await?;
        output::print_success("Agent funding signed in hardware and submitted");
        output::print_field("Agent DID", &self.agent_did);
        output::print_field("Agent wallet", &wallet);
        output::print_field("Amount (wei)", &self.amount_wei.to_string());
        output::print_field(
            "Tx Hash",
            &result
                .as_str()
                .map_or_else(|| result.to_string(), str::to_string),
        );
        Ok(())
    }
}

// ── Kill-switch commands ────────────────────────────
//
// All three submit a typed transaction (`PauseAgent` / `QuarantineAgent` /
// `TerminateAgent`) via `tenzro_sendRawTransaction`. The node-side
// post-execute scan in `event_loop.rs::process_kill_switch_logs` drives the
// lifecycle FSM, freezes/slashes stake, and (for terminate-cascade) walks
// the spawn tree.

const DEFAULT_KILLSWITCH_PAUSE_GAS: u64 = 60_000;
const DEFAULT_KILLSWITCH_QUARANTINE_GAS: u64 = 90_000;
const DEFAULT_KILLSWITCH_TERMINATE_GAS: u64 = 120_000;

/// Pause an agent via the kill-switch (tier 1).
#[derive(Debug, Parser)]
pub struct AgentPauseCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// Controller address (hex, must match the signing key)
    #[arg(long)]
    controller: String,
    /// Controller DID (e.g. `did:tenzro:human:...`)
    #[arg(long)]
    controller_did: String,
    /// Agent DID to pause (`did:tenzro:machine:...`)
    #[arg(long)]
    agent_did: String,
    /// Reason code (canonical kill-switch spec §"Reason codes")
    #[arg(long, default_value_t = 0u16)]
    reason_code: u16,
    /// Optional human reason text (capped at 256 bytes)
    #[arg(long)]
    reason_text: Option<String>,
    /// Optional pause expiry as Unix timestamp in milliseconds
    #[arg(long)]
    until: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentPauseCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Pause Agent");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Preparing transaction...");
        spinner.set_message("Signing PauseAgent transaction...");

        let tx_type = serde_json::json!({
            "PauseAgent": {
                "agent_did": self.agent_did,
                "controller_did": self.controller_did,
                "reason_code": self.reason_code,
                "reason_text": self.reason_text,
                "until": self.until,
            }
        });

        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            crate::keystore::address32(&self.controller)?,
            tx_type,
            DEFAULT_KILLSWITCH_PAUSE_GAS,
        )
        .await?;
        spinner.finish_and_clear();

        let tx_hash = result
            .get("tx_hash")
            .or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        output::print_success("PauseAgent transaction submitted");
        println!();
        output::print_field("Controller", &self.controller);
        output::print_field("Agent DID", &self.agent_did);
        output::print_field("Reason Code", &self.reason_code.to_string());
        output::print_field("Transaction Hash", tx_hash);
        Ok(())
    }
}

/// Quarantine an agent via the kill-switch (tier 2).
#[derive(Debug, Parser)]
pub struct AgentQuarantineCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// Controller address (hex, must match the signing key)
    #[arg(long)]
    controller: String,
    /// Controller DID
    #[arg(long)]
    controller_did: String,
    /// Agent DID to quarantine
    #[arg(long)]
    agent_did: String,
    /// Reason code
    #[arg(long, default_value_t = 0u16)]
    reason_code: u16,
    /// Optional human reason text
    #[arg(long)]
    reason_text: Option<String>,
    /// Optional 32-byte SHA-256 evidence hash (hex)
    #[arg(long)]
    evidence_hash: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentQuarantineCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Quarantine Agent");

        let evidence_hash_bytes: Option<[u8; 32]> = match self.evidence_hash.as_ref() {
            None => None,
            Some(h) => {
                let bytes = hex::decode(h.trim_start_matches("0x"))
                    .map_err(|e| anyhow::anyhow!("invalid evidence_hash hex: {}", e))?;
                if bytes.len() != 32 {
                    anyhow::bail!(
                        "evidence_hash must be 32 bytes (64 hex chars), got {}",
                        bytes.len()
                    );
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes);
                Some(a)
            }
        };

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Preparing transaction...");
        spinner.set_message("Signing QuarantineAgent transaction...");

        let tx_type = serde_json::json!({
            "QuarantineAgent": {
                "agent_did": self.agent_did,
                "controller_did": self.controller_did,
                "reason_code": self.reason_code,
                "reason_text": self.reason_text,
                "evidence_hash": evidence_hash_bytes,
            }
        });

        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            crate::keystore::address32(&self.controller)?,
            tx_type,
            DEFAULT_KILLSWITCH_QUARANTINE_GAS,
        )
        .await?;
        spinner.finish_and_clear();

        let tx_hash = result
            .get("tx_hash")
            .or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        output::print_success("QuarantineAgent transaction submitted");
        println!();
        output::print_field("Controller", &self.controller);
        output::print_field("Agent DID", &self.agent_did);
        output::print_field("Reason Code", &self.reason_code.to_string());
        output::print_field("Transaction Hash", tx_hash);
        Ok(())
    }
}

/// Terminate an agent via the kill-switch (tier 3).
#[derive(Debug, Parser)]
pub struct AgentTerminateCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// Controller address (hex, must match the signing key)
    #[arg(long)]
    controller: String,
    /// Controller DID
    #[arg(long)]
    controller_did: String,
    /// Agent DID to terminate
    #[arg(long)]
    agent_did: String,
    /// Reason code
    #[arg(long, default_value_t = 0u16)]
    reason_code: u16,
    /// Basis points of stake to slash (0..=10000)
    #[arg(long, default_value_t = 0u16)]
    slash_bps: u16,
    /// Recursively terminate descendants under children:<parent_id>
    #[arg(long)]
    cascade: bool,
    /// Optional human reason text
    #[arg(long)]
    reason_text: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentTerminateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Terminate Agent");

        if self.slash_bps > 10_000 {
            anyhow::bail!("slash_bps must be in 0..=10000, got {}", self.slash_bps);
        }

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Preparing transaction...");
        spinner.set_message("Signing TerminateAgent transaction...");

        let tx_type = serde_json::json!({
            "TerminateAgent": {
                "agent_did": self.agent_did,
                "controller_did": self.controller_did,
                "reason_code": self.reason_code,
                "slash_bps": self.slash_bps,
                "cascade": self.cascade,
                "reason_text": self.reason_text,
            }
        });

        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            crate::keystore::address32(&self.controller)?,
            tx_type,
            DEFAULT_KILLSWITCH_TERMINATE_GAS,
        )
        .await?;
        spinner.finish_and_clear();

        let tx_hash = result
            .get("tx_hash")
            .or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        output::print_success("TerminateAgent transaction submitted");
        println!();
        output::print_field("Controller", &self.controller);
        output::print_field("Agent DID", &self.agent_did);
        output::print_field("Slash bps", &self.slash_bps.to_string());
        output::print_field("Cascade", &self.cascade.to_string());
        output::print_field("Transaction Hash", tx_hash);
        Ok(())
    }
}

/// Audit trail reads.
#[derive(Debug, Subcommand)]
pub enum AgentAuditCommand {
    /// Verify one entry's proof from the agent's recorder: the recorder's
    /// signature, the path to the session root and the epoch root, and that
    /// root against the one recorded on chain
    Verify(AgentAuditVerifyCmd),
    /// Check the hardware attestation a committer recorded with its audit
    /// root: the TPM quote binding the root to its measured boot state and
    /// machine identity
    Attestation(AgentAuditAttestationCmd),
    /// Whether an agent is quarantined, as chain state records it
    Quarantine(AgentAuditQuarantineCmd),
    /// Compliance and dispute evidence packs
    #[command(subcommand)]
    Evidence(super::evidence::EvidenceCommand),
}

impl AgentAuditCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Verify(cmd) => cmd.execute().await,
            Self::Attestation(cmd) => cmd.execute().await,
            Self::Quarantine(cmd) => cmd.execute().await,
            Self::Evidence(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct AgentAuditVerifyCmd {
    /// File holding the entry's proof (JSON), as the recorder exported it
    #[arg(long)]
    proof: std::path::PathBuf,
    /// The recorder's hardware identity key: its P-256 point (hex, x || y)
    #[arg(long)]
    signer: String,
    /// The recorder's ML-DSA-65 identity key (hex), when its identity has one
    #[arg(long)]
    signer_pq: Option<String>,
    /// RPC endpoint to read chain state from. Any node answers it, so pass
    /// one you trust.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentAuditVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use anyhow::{anyhow, bail};
        use tenzro_types::agent_audit::{AuditProof, parse_digest};

        let proof: AuditProof = serde_json::from_slice(&std::fs::read(&self.proof)?)?;
        let root = proof
            .verify()
            .map_err(|e| anyhow!("proof does not verify: {e}"))?;

        let identity = tenzro_crypto::composite::CompositePublicKey::new(
            hex::decode(self.signer.trim_start_matches("0x"))?,
            self.signer_pq
                .as_deref()
                .map(|pq| hex::decode(pq.trim_start_matches("0x")))
                .transpose()?,
        )?;
        let signature: tenzro_crypto::session::SessionSignature =
            serde_json::from_slice(&proof.entry.signature)?;
        let entry = proof.entry.entry().map_err(|e| anyhow!(e))?;
        let mut message = b"tenzro/agent-audit/entry".to_vec();
        message.extend_from_slice(&proof.entry.body);
        signature
            .verify(&identity, &message, entry.at_ms)
            .map_err(|e| anyhow!("entry signature does not verify: {e}"))?;

        let commit: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_getAgentAuditCommit",
                serde_json::json!({ "committer": proof.committer, "epoch": proof.epoch }),
            )
            .await?;
        let onchain = commit["record"]["root"]
            .as_str()
            .ok_or_else(|| anyhow!("no root is recorded on chain for this committer and epoch"))?;
        if parse_digest(onchain).map_err(|e| anyhow!(e))? != root {
            bail!(
                "the entry reaches {}, but chain state records {onchain}",
                hex::encode(root)
            );
        }

        output::print_header("Agent audit entry verified");
        output::print_field("Agent", &entry.agent);
        output::print_field(
            "Action",
            &format!("{} {}", entry.kind.as_str(), entry.action),
        );
        output::print_field("Outcome", &format!("{:?}", entry.outcome));
        output::print_field("Sequence", &entry.seq.to_string());
        if let Some(tx) = &entry.linked_tx {
            output::print_field("Linked transaction", tx);
        }
        output::print_field("Epoch", &proof.epoch.to_string());
        output::print_field("Committer", &proof.committer);
        output::print_field("Epoch root", &hex::encode(root));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AgentAuditAttestationCmd {
    /// Ledger account that committed (0x hex)
    #[arg(long)]
    committer: String,
    /// Epoch of the commitment
    #[arg(long)]
    epoch: u64,
    /// RPC endpoint to read chain state from
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentAuditAttestationCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let got: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_verifyAgentAuditAttestation",
                serde_json::json!({ "committer": self.committer, "epoch": self.epoch }),
            )
            .await?;
        let a = &got["attestation"];
        output::print_header("Audit and telemetry commitment");
        output::print_field("Committer", got["committer"].as_str().unwrap_or_default());
        output::print_field("Epoch", &got["epoch"].to_string());
        output::print_field("Root", got["root"].as_str().unwrap_or_default());
        output::print_field("Sessions", &got["sessions"].to_string());
        if a["attested"].as_bool() == Some(true) {
            output::print_field("Machine", a["machine_did"].as_str().unwrap_or_default());
            output::print_field("PCR digest", a["pcr_digest"].as_str().unwrap_or_default());
            output::print_field(
                "Endorsement key name",
                a["ek_name"].as_str().unwrap_or_default(),
            );
        } else {
            output::print_field("Attested", a["reason"].as_str().unwrap_or("no"));
        }
        Ok(())
    }
}

/// Lift an agent's quarantine.
#[derive(Debug, Parser)]
pub struct AgentLiftQuarantineCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// Controller address (hex, must match the signing key)
    #[arg(long)]
    controller: String,
    /// Agent DID whose quarantine to lift
    #[arg(long)]
    agent_did: String,
    /// Optional human reason text
    #[arg(long)]
    reason_text: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentLiftQuarantineCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Lift Agent Quarantine");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            crate::keystore::address32(&self.controller)?,
            serde_json::json!({
                "LiftAgentQuarantine": {
                    "agent_did": self.agent_did,
                    "reason_text": self.reason_text,
                }
            }),
            DEFAULT_KILLSWITCH_QUARANTINE_GAS,
        )
        .await?;
        let tx_hash = result
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        output::print_success("LiftAgentQuarantine transaction submitted");
        output::print_field("Agent DID", &self.agent_did);
        output::print_field("Transaction Hash", tx_hash);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AgentAuditQuarantineCmd {
    /// Agent DID
    #[arg(long)]
    agent_did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentAuditQuarantineCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let got: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_getAgentQuarantine",
                serde_json::json!({ "agent_did": self.agent_did }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&got)?);
        Ok(())
    }
}

/// Agent commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum AgentRpcCommand {
    /// Call tenzro_getAgentTerms: the agent's full consensus Terms, root kind, status and spend so far
    Terms(AgentTermsRpcCmd),
    /// Call tenzro_flagAgentAudit (flag agent audit) and print the node's answer
    FlagAudit(AgentFlagAuditRpcCmd),
    /// Call tenzro_recordAgentAuditSession: report an audit session's latest line for this node to commit
    RecordAuditSession(AgentRecordAuditSessionRpcCmd),
    /// Call tenzro_getBridgeCircuit (get bridge circuit) and print the node's answer
    BridgeCircuit(AgentBridgeCircuitRpcCmd),
    /// Call tenzro_resolveAgentKey (resolve agent key) and print the node's answer
    ResolveKey(AgentResolveKeyRpcCmd),
    /// Call tenzro_getKillSwitchReceipt (get kill switch receipt) and print the node's answer
    KillSwitchReceipt(AgentKillSwitchReceiptRpcCmd),
    /// Call tenzro_listKillSwitchByAgent (list kill switch by agent) and print the node's answer
    KillSwitchByAgent(AgentKillSwitchByAgentRpcCmd),
    /// Call tenzro_listKillSwitchByController (list kill switch by controller) and print the node's answer
    KillSwitchByController(AgentKillSwitchByControllerRpcCmd),
    /// Call tenzro_getToolCallRecords (the tool-call records this node signed for an agent (`agent_did`, `limit`), and whether it records) and print the node's answer
    ToolCallRecords(AgentToolCallRecordsRpcCmd),
    /// Call tenzro_agentNodePqKey (this node's ML-DSA-65 key for an agent (`agent_did`) and its proof of possession) and print the node's answer
    NodePqKey(AgentNodePqKeyRpcCmd),
}

impl AgentRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::Terms(cmd) => cmd.execute().await,
            Self::FlagAudit(cmd) => cmd.execute().await,
            Self::RecordAuditSession(cmd) => cmd.execute().await,
            Self::BridgeCircuit(cmd) => cmd.execute().await,
            Self::ResolveKey(cmd) => cmd.execute().await,
            Self::KillSwitchReceipt(cmd) => cmd.execute().await,
            Self::KillSwitchByAgent(cmd) => cmd.execute().await,
            Self::KillSwitchByController(cmd) => cmd.execute().await,
            Self::ToolCallRecords(cmd) => cmd.execute().await,
            Self::NodePqKey(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_getAgentTerms (the agent's Terms and spend against them)
#[derive(Debug, clap::Parser)]
pub struct AgentTermsRpcCmd {
    /// agent did
    #[arg(long)]
    agent_did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentTermsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getAgentTerms",
                serde_json::json!({ "agent_did": self.agent_did }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_flagAgentAudit (flag agent audit)
#[derive(Debug, clap::Parser)]
pub struct AgentFlagAuditRpcCmd {
    /// agent did
    #[arg(long)]
    agent_did: String,
    /// epoch
    #[arg(long)]
    epoch: u64,
    /// findings (JSON)
    #[arg(long)]
    findings: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentFlagAuditRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let findings: serde_json::Value =
            serde_json::from_str(&self.findings).context("--findings is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_flagAgentAudit", serde_json::json!({ "agent_did": self.agent_did, "epoch": self.epoch, "findings": findings })).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_recordAgentAuditSession: report an audit session's latest line
#[derive(Debug, clap::Parser)]
pub struct AgentRecordAuditSessionRpcCmd {
    /// The session id (32-byte hex)
    #[arg(long)]
    session_id: String,
    /// The session's MMR root (32-byte hex)
    #[arg(long)]
    mmr_root: String,
    /// Entries the root covers
    #[arg(long)]
    count: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentRecordAuditSessionRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_recordAgentAuditSession",
                serde_json::json!({ "session_id": self.session_id, "mmr_root": self.mmr_root, "count": self.count }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getBridgeCircuit (get bridge circuit)
#[derive(Debug, clap::Parser)]
pub struct AgentBridgeCircuitRpcCmd {
    /// source chain
    #[arg(long)]
    source_chain: String,
    /// adapter
    #[arg(long)]
    adapter: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentBridgeCircuitRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getBridgeCircuit",
                serde_json::json!({ "source_chain": self.source_chain, "adapter": self.adapter }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_resolveAgentKey (resolve agent key)
#[derive(Debug, clap::Parser)]
pub struct AgentResolveKeyRpcCmd {
    /// agent did
    #[arg(long)]
    agent_did: String,
    /// keyid
    #[arg(long)]
    keyid: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentResolveKeyRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_resolveAgentKey",
                serde_json::json!({ "agent_did": self.agent_did, "keyid": self.keyid }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getKillSwitchReceipt (get kill switch receipt)
#[derive(Debug, clap::Parser)]
pub struct AgentKillSwitchReceiptRpcCmd {
    /// receipt id
    #[arg(long)]
    receipt_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentKillSwitchReceiptRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getKillSwitchReceipt",
                serde_json::json!({ "receipt_id": self.receipt_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_listKillSwitchByAgent (list kill switch by agent)
#[derive(Debug, clap::Parser)]
pub struct AgentKillSwitchByAgentRpcCmd {
    /// agent did
    #[arg(long)]
    agent_did: String,
    /// cursor
    #[arg(long)]
    cursor: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentKillSwitchByAgentRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listKillSwitchByAgent",
                serde_json::json!({ "agent_did": self.agent_did, "cursor": self.cursor }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_listKillSwitchByController (list kill switch by controller)
#[derive(Debug, clap::Parser)]
pub struct AgentKillSwitchByControllerRpcCmd {
    /// controller did
    #[arg(long)]
    controller_did: String,
    /// cursor
    #[arg(long)]
    cursor: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentKillSwitchByControllerRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listKillSwitchByController",
                serde_json::json!({ "controller_did": self.controller_did, "cursor": self.cursor }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getToolCallRecords: the tool-call records this node signed for an agent (`agent_did`, `limit`), and whether it records
#[derive(Debug, clap::Parser)]
pub struct AgentToolCallRecordsRpcCmd {
    /// Parameters as a JSON object
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentToolCallRecordsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .map_err(|e| anyhow::anyhow!("--params is not valid JSON: {e}"))?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_getToolCallRecords", params).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_agentNodePqKey: this node's ML-DSA-65 key for an agent (`agent_did`) and its proof of possession
#[derive(Debug, clap::Parser)]
pub struct AgentNodePqKeyRpcCmd {
    /// Parameters as a JSON object
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentNodePqKeyRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .map_err(|e| anyhow::anyhow!("--params is not valid JSON: {e}"))?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_agentNodePqKey", params).await?;
        crate::output::print_json(&result)
    }
}
