//! Delegated agents approved by their root: a human's passkey or an
//! autonomous machine's TPM or Secure Enclave key.
//!
//! Each change is two steps: `challenge` asks the node for the digest to sign
//! (for a new agent or a terms change it also returns the completed terms,
//! with every serving node's key filled in); the root signs it and the
//! authorization JSON goes to `onboard`, `update` or `revoke`. A passkey lives
//! in the controller's wallet client, which writes `challenge_id`,
//! `credential_id_hex`, `assertion` and `ml_dsa_signature_hex`. A machine
//! root signs here with `sign`, which writes `challenge_id` and the composite
//! `signature` from this machine's hardware key.

use crate::output;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Delegated-agent commands.
#[derive(Debug, Subcommand)]
pub enum AgentDelegationCommand {
    /// Ask the node for the challenge the controller's passkey signs
    Challenge(ChallengeCmd),
    /// Create the agent from the completed terms and the signed approval
    Onboard(OnboardCmd),
    /// Replace the agent's terms with newly approved ones
    Update(UpdateCmd),
    /// Revoke the agent; every node refuses it from then on
    Revoke(RevokeCmd),
    /// Sign a challenge (custody or step-up) as a machine root, with this
    /// machine's hardware key
    Sign(SignCmd),
    /// Create an agent rooted in this machine's hardware key: register the
    /// machine's identity on chain if it is not yet, then challenge, sign and
    /// onboard in one go
    CreateAsMachine(CreateAsMachineCmd),
    /// Take one action as the agent, with its access token; the serving node
    /// refuses anything outside the terms
    Act(ActCmd),
}

impl AgentDelegationCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Challenge(cmd) => cmd.execute().await,
            Self::Onboard(cmd) => cmd.execute().await,
            Self::Update(cmd) => cmd.execute().await,
            Self::Revoke(cmd) => cmd.execute().await,
            Self::Sign(cmd) => cmd.execute(),
            Self::CreateAsMachine(cmd) => cmd.execute().await,
            Self::Act(cmd) => cmd.execute().await,
        }
    }
}

/// Which change the challenge authorizes.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DelegationOp {
    /// Create an agent
    Delegate,
    /// Replace an agent's terms
    Update,
    /// Revoke an agent
    Revoke,
}

fn read_json(path: &PathBuf) -> Result<serde_json::Value> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

#[derive(Debug, Parser)]
pub struct ChallengeCmd {
    /// The change to authorize
    #[arg(value_enum)]
    op: DelegationOp,
    /// The account the root approves from, hex: a human's smart account, or
    /// the account a machine root's hardware key names
    #[arg(long)]
    account: String,
    /// JSON file with the agent's terms (delegate, update)
    #[arg(long)]
    terms: Option<PathBuf>,
    /// The agent (update, revoke)
    #[arg(long)]
    agent_did: Option<String>,
    /// Also withdraw the agent's live access tokens (update)
    #[arg(long)]
    rotate_tokens: bool,
    /// Reason the revocation records (revoke); the approval covers it, so
    /// pass the same reason to `revoke`
    #[arg(long)]
    reason: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ChallengeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let params = match self.op {
            DelegationOp::Delegate => serde_json::json!({
                "account_address": self.account,
                "operation": "delegate_agent",
                "delegation": read_json(self.terms.as_ref().context("--terms is required")?)?,
            }),
            DelegationOp::Update => serde_json::json!({
                "account_address": self.account,
                "operation": "update_agent_terms",
                "agent_did": self.agent_did.as_ref().context("--agent-did is required")?,
                "delegation": read_json(self.terms.as_ref().context("--terms is required")?)?,
                "rotate_tokens": self.rotate_tokens,
            }),
            DelegationOp::Revoke => serde_json::json!({
                "account_address": self.account,
                "operation": "revoke_identity",
                "target_hex": hex::encode(tenzro_types::identity::revocation_target(
                    self.agent_did.as_ref().context("--agent-did is required")?,
                    self.reason
                        .as_deref()
                        .unwrap_or(tenzro_types::identity::DEFAULT_REVOCATION_REASON),
                )),
            }),
        };
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_createCustodyChallenge", params)
            .await?;
        output::print_json(&result)
    }
}

#[derive(Debug, Parser)]
pub struct SignCmd {
    /// JSON file with the challenge: a `challenge` result, or the `step_up`
    /// error data `act` returned for a held action
    #[arg(long)]
    challenge: PathBuf,
    /// The hardware key namespace of the machine root's account
    #[arg(long, default_value = "client")]
    key_namespace: String,
}

impl SignCmd {
    /// A custody challenge becomes `{challenge_id, signature}` for
    /// `onboard`, `update` or `revoke`; a step-up challenge becomes the
    /// `step_up` object `act` takes. Both legs sign the challenge digest
    /// under the account-owner context.
    pub fn execute(&self) -> Result<()> {
        let challenge = read_json(&self.challenge)?;
        let step_up = challenge.get("step_up").unwrap_or(&challenge);
        let digest_hex = step_up
            .get("challenge_hex")
            .and_then(serde_json::Value::as_str)
            .context("the challenge carries no challenge_hex")?;
        let digest = hex::decode(digest_hex.trim_start_matches("0x")).context("challenge_hex")?;
        let (public_key, signature) = crate::keystore::sign_composite(
            &self.key_namespace,
            tenzro_crypto::composite::SignatureContext::AccountOwner,
            &digest,
        )?;
        let out = if step_up.get("controller_operation").is_some() {
            serde_json::json!({
                "account": step_up["account"],
                "nonce": step_up["nonce"],
                "root_public_key": public_key,
                "signature": signature,
            })
        } else {
            serde_json::json!({
                "challenge_id": challenge
                    .get("challenge_id")
                    .context("the challenge carries no challenge_id")?,
                "signature": signature,
            })
        };
        output::print_json(&out)
    }
}

#[derive(Debug, Parser)]
pub struct CreateAsMachineCmd {
    /// JSON file with the agent's terms; `controller_did` is set to this
    /// machine's DID, and absent `serving_nodes` become the node at `--rpc`
    #[arg(long)]
    terms: PathBuf,
    /// The hardware key namespace of the machine root's account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// Post this bond (wei) against the agent from the machine root's
    /// account before its terms, which need a bond sized by their spend
    /// ceiling (`tenzro bond get` shows an existing one)
    #[arg(long)]
    bond: Option<u128>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

/// Post `amount` wei as `agent`'s bond from the client account under
/// `namespace`, unless the agent already holds one, and wait until it is in
/// state: the terms are checked against the bond when they are recorded.
async fn post_bond(
    rpc: &crate::rpc::RpcClient,
    namespace: &str,
    agent: &str,
    controller: &str,
    amount: u128,
) -> Result<()> {
    let bonded = || {
        rpc.call::<serde_json::Value>(
            "tenzro_getAgentBond",
            serde_json::json!({ "agent_did": agent }),
        )
    };
    if !bonded().await?.is_null() {
        return Ok(());
    }
    let tx = serde_json::json!({
        "PostAgentBond": { "agent_did": agent, "controller_did": controller, "amount": amount.to_string() }
    });
    crate::keystore::send_as_client(
        rpc,
        namespace,
        [0u8; 32],
        tx,
        tenzro_types::constants::bond_gas::AGENT_BOND_POST,
    )
    .await
    .context("posting the agent's bond")?;
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if !bonded().await?.is_null() {
            return Ok(());
        }
    }
    anyhow::bail!("the bond for {agent} was not in state within two minutes")
}

impl CreateAsMachineCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use tenzro_crypto::composite::SignatureContext;
        let rpc = RpcClient::new(&self.rpc);
        let (account, _) = crate::keystore::client_account(&self.key_namespace)?;
        let signer = crate::keystore::client_signer(&self.key_namespace)?;
        let wallet = crate::keystore::address32(&account)?;
        let (did, register) = crate::keystore::machine_identity_registration(&signer, wallet)?;
        if !crate::keystore::identity_registered(&rpc, &did).await {
            crate::keystore::send_as_client(
                &rpc,
                &self.key_namespace,
                [0u8; 32],
                register,
                200_000,
            )
            .await
            .context("registering this machine's identity")?;
            crate::keystore::await_identity(&rpc, &did).await?;
        }

        let mut terms = read_json(&self.terms)?;
        terms["controller_did"] = did.clone().into();
        if terms
            .get("serving_nodes")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            let status: serde_json::Value = rpc
                .call("tenzro_getNodeStatus", serde_json::json!({}))
                .await?;
            terms["serving_nodes"] = serde_json::json!([{
                "machine_did": status["machine_did"],
                "operator_did": status["operator_did"],
            }]);
        }
        if let Some(bond) = self.bond {
            let name = terms["agent_name"]
                .as_str()
                .context("the terms name no agent_name")?;
            let agent =
                tenzro_types::agent_terms::agent_did(&did, name).context("the agent's DID")?;
            post_bond(&rpc, &self.key_namespace, &agent, &did, bond).await?;
        }
        let challenge: serde_json::Value = rpc
            .call(
                "tenzro_createCustodyChallenge",
                serde_json::json!({ "account_address": account, "operation": "delegate_agent", "delegation": terms }),
            )
            .await?;
        let digest_hex = challenge["challenge_hex"]
            .as_str()
            .context("the challenge carries no challenge_hex")?;
        let digest = hex::decode(digest_hex.trim_start_matches("0x")).context("challenge_hex")?;
        let (_, signature) = crate::keystore::sign_composite(
            &self.key_namespace,
            SignatureContext::AccountOwner,
            &digest,
        )?;
        let result: serde_json::Value = rpc
            .call(
                "tenzro_onboardDelegatedAgent",
                serde_json::json!({
                    "delegation": challenge["delegation"],
                    "authorization": { "challenge_id": challenge["challenge_id"], "signature": signature },
                }),
            )
            .await?;
        output::print_json(&result)
    }
}

#[derive(Debug, Parser)]
pub struct OnboardCmd {
    /// JSON file with the completed terms the challenge returned, unchanged
    #[arg(long)]
    terms: PathBuf,
    /// JSON file with the controller's signed authorization
    #[arg(long)]
    authorization: PathBuf,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl OnboardCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_onboardDelegatedAgent",
                serde_json::json!({
                    "delegation": read_json(&self.terms)?,
                    "authorization": read_json(&self.authorization)?,
                }),
            )
            .await?;
        output::print_header("Agent delegated");
        output::print_field(
            "Agent DID",
            result["identity"]["did"].as_str().unwrap_or(""),
        );
        output::print_field("Wallet", result["wallet"]["address"].as_str().unwrap_or(""));
        output::print_json(&serde_json::json!({
            "serving_nodes": result["serving_nodes"],
            "token_delivery": result["token_delivery"],
        }))
    }
}

#[derive(Debug, Parser)]
pub struct UpdateCmd {
    /// The agent
    #[arg(long)]
    agent_did: String,
    /// JSON file with the completed terms the challenge returned, unchanged
    #[arg(long)]
    terms: PathBuf,
    /// JSON file with the controller's signed authorization
    #[arg(long)]
    authorization: PathBuf,
    /// Also withdraw the agent's live access tokens; must match the challenge
    #[arg(long)]
    rotate_tokens: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UpdateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_updateAgentTerms",
                serde_json::json!({
                    "agent_did": self.agent_did,
                    "delegation": read_json(&self.terms)?,
                    "rotate_tokens": self.rotate_tokens,
                    "authorization": read_json(&self.authorization)?,
                }),
            )
            .await?;
        output::print_header("Agent terms updated");
        if let Some(n) = result["tokens_revoked"].as_u64() {
            output::print_field("Access tokens withdrawn", &n.to_string());
        }
        output::print_json(&result["delegation"])
    }
}

#[derive(Debug, Parser)]
pub struct RevokeCmd {
    /// The agent
    #[arg(long)]
    agent_did: String,
    /// The controller that approves, as the agent's terms name it
    #[arg(long)]
    controller_did: String,
    /// JSON file with the controller's approval of the revoke_identity
    /// challenge: {account, nonce, root_public_key, signature}
    #[arg(long)]
    approval: PathBuf,
    /// Reason the challenge was issued for
    #[arg(long)]
    reason: Option<String>,
    /// Hardware key namespace of the account that sends the transaction
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RevokeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let op = crate::commands::identity::revocation_op(
            &self.agent_did,
            self.reason.as_deref(),
            &self.controller_did,
            &self.approval,
        )?;
        let result = crate::keystore::send_revocation(
            &RpcClient::new(&self.rpc),
            &self.key_namespace,
            &op,
            crate::keystore::DEFAULT_REVOCATION_GAS,
        )
        .await?;
        output::print_success("Agent revocation admitted");
        output::print_json(&result)
    }
}

#[derive(Debug, Parser)]
pub struct ActCmd {
    /// The operation, as the agent's terms name it
    #[arg(long)]
    operation: String,
    /// Recipient address, hex, when the action moves value
    #[arg(long)]
    counterparty: Option<String>,
    /// Value moved, wei
    #[arg(long)]
    amount: Option<String>,
    /// Chain
    #[arg(long, default_value = "tenzro")]
    chain: String,
    /// Payment protocol
    #[arg(long)]
    payment_protocol: Option<String>,
    /// Model
    #[arg(long)]
    model: Option<String>,
    /// Asset moved other than TNZO: a token id (0x hex)
    #[arg(long)]
    asset: Option<String>,
    /// USD price of the value moved, micro-units (required with --asset)
    #[arg(long, default_value_t = 0)]
    usd_e6: u64,
    /// For `pay`: the payment id the record is keyed by
    #[arg(long)]
    payment_id: Option<String>,
    /// For `pay`: the resource paid for
    #[arg(long)]
    request: Option<String>,
    /// For `pay`: the payee's quote digest (hex)
    #[arg(long)]
    quote_digest: Option<String>,
    /// The controller's step-up of this action, JSON: `account`, `nonce`
    /// and `root_public_key` (hex, from the refused attempt's `step_up` data
    /// and the root's P-256 key `x || y`) and `signature`, the root's
    /// composite signature (a passkey's WebAuthn assertion, or a machine
    /// root's TPM or Secure Enclave signature) over that data's challenge.
    /// Sent with the same action, unchanged, when its terms hold it
    #[arg(long)]
    step_up: Option<PathBuf>,
    /// RPC endpoint of one of the agent's serving nodes
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ActCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let payment = match (&self.payment_id, &self.request) {
            (Some(id), Some(request)) => {
                let b = super::payment::payment_binding(
                    request,
                    self.quote_digest.as_deref(),
                    self.usd_e6,
                    None,
                )?;
                Some(serde_json::json!({
                    "payment_id": id,
                    "request_digest": hex::encode(b.request_digest),
                    "quote_digest": hex::encode(b.quote_digest),
                }))
            }
            (None, None) => None,
            _ => anyhow::bail!("--payment-id and --request go together"),
        };
        let mut params = serde_json::json!({
            "operation": self.operation,
            "counterparty": self.counterparty,
            "amount": self.amount,
            "asset": self.asset,
            "usd_e6": self.usd_e6,
            "payment": payment,
            "chain": self.chain,
            "payment_protocol": self.payment_protocol,
            "model": self.model,
        });
        if let Some(path) = &self.step_up {
            params["step_up"] = read_json(path)?;
        }
        let result: serde_json::Value = rpc.call("tenzro_agentAct", params).await?;
        output::print_success("Action submitted");
        output::print_json(&result)
    }
}
