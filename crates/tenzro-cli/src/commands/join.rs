//! Join command: provisions this machine's identity and wallet on Tenzro Network.
//!
//! Calls the node's `tenzro_joinAsMicroNode` RPC to provision a TDIP identity
//! and a wallet bound to a key this machine holds. It runs no node.
//!
//! With `--provider`, continues past identity provisioning into the full
//! provider path against the local node: hardware detection, testnet funding,
//! compute bond, provider registration, default pricing, automatic model
//! selection + download + serving, and TEE detection where hardware exists.

use crate::config;
use crate::onboarding::ceremony::{self, CeremonyResult};
use crate::output;
use crate::rpc::RpcClient;
use anyhow::Result;
use clap::Parser;

/// The display name a join uses when none is given.
pub(crate) const DEFAULT_NAME: &str = "Tenzro User";

/// The identity and wallet a join made, as this machine keeps them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Joined {
    pub did: String,
    pub display_name: String,
    pub wallet_id: String,
    pub wallet_address: String,
}

impl Joined {
    /// Read them from the node's answer. `name` stands in for a display name
    /// the node did not return.
    pub(crate) fn read(result: &serde_json::Value, name: &str) -> Self {
        let text = |part: &str, field: &str, or: &str| {
            result
                .get(part)
                .and_then(|p| p.get(field))
                .and_then(|v| v.as_str())
                .unwrap_or(or)
                .to_string()
        };
        Self {
            did: text("identity", "did", "unknown"),
            display_name: text("identity", "display_name", name),
            wallet_id: text("wallet", "wallet_id", "unknown"),
            wallet_address: text("wallet", "address", "unknown"),
        }
    }

    /// Write them into the CLI's configuration, with the node they were made
    /// on.
    pub(crate) fn keep(self, cfg: &mut config::PersistedConfig, rpc_url: &str) {
        cfg.endpoint = Some(rpc_url.to_string());
        cfg.wallet_id = Some(self.wallet_id);
        cfg.wallet_address = Some(self.wallet_address);
        cfg.did = Some(self.did);
        cfg.display_name = Some(self.display_name);
    }
}

/// Register the passkey a ceremony made as a person's identity on the node.
pub(crate) async fn enrol(
    rpc: &RpcClient,
    made: &CeremonyResult,
    name: &str,
) -> Result<serde_json::Value> {
    rpc.call(
        "tenzro_onboardHuman",
        ceremony::build_onboard_params(made, name),
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "The node refused the passkey enrolment: {e}\n\
                 The passkey was created but no identity exists yet."
        )
    })
}

/// Provision this machine's identity and wallet on the Tenzro Network.
///
/// No node is installed or run: the command provisions a TDIP DID and a
/// wallet that can pay for and call the network's services.
/// Pass `--provider` on a machine running `tenzro-node` to also become
/// an inference provider in the same command.
#[derive(Debug, Parser)]
pub struct JoinCmd {
    /// RPC endpoint. Defaults to https://rpc.tenzro.com, or to the
    /// local node (http://127.0.0.1:8545) when --provider is set.
    #[arg(long)]
    pub rpc: Option<String>,

    /// Display name
    #[arg(long, default_value = DEFAULT_NAME)]
    pub name: String,

    /// Origin hint (e.g. "cli", "sdk", "app", "mcp", "a2a")
    #[arg(long, default_value = "cli")]
    pub origin: String,

    /// Participant type: human, agent, or bot
    #[arg(long, default_value = "human")]
    pub r#type: String,

    /// Also become an inference provider: detect hardware, post the
    /// compute bond, register, set default pricing, and pull + serve the
    /// largest catalog model that fits this machine. Requires a running
    /// local tenzro-node (or --rpc pointing at your node).
    #[arg(long)]
    pub provider: bool,

    /// With --provider, become a provider as this machine's node: its node
    /// account posts the bonds and its operator DID is the provider, with no
    /// new identity provisioned. On a machine with no TPM of its own the
    /// node account signs through the key holder (--tpm-key-holder and
    /// --tpm-label, or the one `tenzro setup` recorded).
    #[arg(long, requires = "provider")]
    pub node_account: bool,

    #[command(flatten)]
    pub delegated: crate::keystore::DelegatedKey,

    /// Show where your application for a staked role stands and the next
    /// step: validator, edge, tee, rpc, attestor, wallet, catalog, ai,
    /// compute or storage. Run it again at any time; it continues from
    /// wherever you are.
    #[arg(long)]
    pub role: Option<String>,

    /// Wallet address to check with --role (defaults to this machine's)
    #[arg(long, requires = "role")]
    pub wallet: Option<String>,
}

impl JoinCmd {
    /// The node account the provider steps sign as with `--node-account`,
    /// or `None` for the client account that joins. A key holder serves a
    /// node's keys, so naming one without `--node-account` is refused.
    fn node_signing(&self) -> Result<Option<crate::keystore::SigningAccount>> {
        let account = crate::keystore::SigningAccount {
            key_namespace: None,
            node_account: self.node_account,
            delegated: self.delegated.clone(),
        };
        Ok(match account.signer()? {
            crate::keystore::AccountSigner::Node(_) => Some(account),
            crate::keystore::AccountSigner::Client(_) => None,
        })
    }

    /// This machine's preflight checklist: the hardware key store its node's
    /// keys live in, and what fixes each missing piece.
    async fn checklist() -> Vec<crate::commands::preflight::Check> {
        let hw = crate::commands::hardware::detect_hardware_profile().await;
        crate::commands::preflight::evaluate(&crate::commands::preflight::Facts::probe(
            crate::commands::setup::has_secure_enclave(&hw),
        ))
    }

    /// The error for an endpoint that did not answer. For provider mode
    /// against the local node it carries the machine's preflight checklist, so
    /// a node that cannot start says why and what fixes it.
    async fn connect_error(&self, rpc_url: &str, e: anyhow::Error) -> anyhow::Error {
        if !(self.provider && self.rpc.is_none()) {
            if e.downcast_ref::<crate::friendly::Unreachable>().is_some() {
                return e;
            }
            return anyhow::anyhow!("Cannot connect to {}: {}", rpc_url, e);
        }
        let checklist = crate::commands::preflight::report_text(&Self::checklist().await);
        anyhow::anyhow!(
            "Cannot connect to your local node at {}: {}\n\
             Provider mode registers on your own node. This machine's readiness to run one:\n\
             {}\
             Start the node first, with `tenzro setup --apply` or directly:\n\
             \n    tenzro-node --roles model-provider\n\
             \nor point at a node you operate with --rpc <url>.",
            rpc_url,
            e,
            checklist
        )
    }

    pub async fn execute(&self) -> Result<()> {
        if let Some(role) = &self.role {
            let role = crate::onboarding::role::JoinRole::parse(role).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown role `{role}`; use one of: validator, edge, tee, rpc, attestor, wallet, catalog, ai, compute, storage"
                )
            })?;
            let rpc_url = self
                .rpc
                .clone()
                .unwrap_or_else(|| crate::endpoint::resolve().0);
            return crate::onboarding::flow::run_join_role(role, &rpc_url, self.wallet.clone())
                .await;
        }
        let rpc_url = self.rpc.clone().unwrap_or_else(|| {
            if self.provider {
                "http://127.0.0.1:8545".to_string()
            } else {
                "https://rpc.tenzro.com".to_string()
            }
        });

        // A provider runs its node on this machine, and the node's keys live
        // only in its TPM 2.0 or Secure Enclave: say so before anything else
        // rather than after a node that cannot start.
        if self.provider && self.rpc.is_none() {
            let checks = Self::checklist().await;
            // Only the key store decides here; a node binary run elsewhere,
            // in a container for one, still answers on the local port.
            let no_key_store = checks.iter().any(|c| {
                c.level == crate::commands::preflight::Level::Fail
                    && matches!(c.label, "TPM 2.0" | "TPM access" | "Secure Enclave")
            });
            if no_key_store {
                anyhow::bail!(
                    "Provider mode runs a node on this machine, and a node keeps its keys only \
                     in a TPM 2.0 or a Secure Enclave. This machine is not ready:\n{}\
                     Fix the items marked FAIL and run this command again, or join without \
                     --provider (a human identity needs only a passkey) or against a node you \
                     operate with --rpc <url>.",
                    crate::commands::preflight::report_text(&checks)
                );
            }
        }

        output::print_header("Join Tenzro Network");

        println!();
        output::print_field("Endpoint", &rpc_url);
        output::print_field("Display Name", &self.name);
        output::print_field("Type", &self.r#type);
        output::print_field("Origin", &self.origin);
        if self.provider {
            output::print_field("Mode", "provider");
        }
        println!();

        // Step 1: Verify endpoint is reachable
        let spinner = output::create_spinner("Connecting to network...");

        let rpc = RpcClient::new(&rpc_url);
        let chain_id_hex: String = match rpc.call("eth_chainId", serde_json::json!([])).await {
            Ok(v) => v,
            Err(e) => return Err(self.connect_error(&rpc_url, e).await),
        };
        let chain_id = crate::rpc::parse_hex_u64(&chain_id_hex);

        spinner.finish_and_clear();
        output::print_success(&format!("Connected to network (Chain ID: {})", chain_id));

        let clean_name = self.name.trim_start_matches('@').to_string();

        if self.provider
            && let Some(account) = self.node_signing()?
        {
            return join_node_as_provider(&rpc, &rpc_url, &account, &clean_name, chain_id).await;
        }

        // Step 2: provision the MicroNode identity + wallet.
        let spinner = output::create_spinner("Provisioning identity and wallet...");

        let result: serde_json::Value = if self.r#type == "human" {
            // A human identity is rooted in a passkey the node cannot mint:
            // the wallet page runs the ceremony and this process relays the
            // public key material to `tenzro_onboardHuman`.
            spinner.finish_and_clear();
            let made = ceremony::run(&rpc_url, &clean_name, ceremony::DEFAULT_TIMEOUT).await?;
            let spinner = output::create_spinner("Registering your identity...");
            let onboarded = enrol(&rpc, &made, &clean_name).await.map_err(|e| {
                anyhow::anyhow!(
                    "{e} Run `tenzro join` again; the challenge expires after a few minutes."
                )
            })?;
            spinner.finish_and_clear();
            onboarded
        } else {
            // A participant that is not a person is this machine: its wallet
            // key is the CLI's own hardware account key, and the node is given
            // the public half.
            let (account, public) = crate::keystore::client_account("client")?;
            rpc.call(
                "tenzro_joinAsMicroNode",
                serde_json::json!([{
                    "display_name": clean_name,
                    "origin": self.origin,
                    "participant_type": self.r#type,
                    "public_key": hex::encode(&public.p256),
                    "machine_id": account,
                }]),
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to join network: {}", e))?
        };
        spinner.finish_and_clear();
        output::print_success("Identity provisioned on Tenzro Network");
        let is_micro_node = true;

        // Extract identity from RPC response
        let joined = Joined::read(&result, &clean_name);
        let Joined {
            did,
            display_name,
            wallet_id,
            wallet_address,
        } = joined.clone();
        let identity = result.get("identity").cloned().unwrap_or_default();
        let identity_type = identity
            .get("identity_type")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.r#type)
            .to_string();

        // Extract wallet from RPC response
        let wallet = result.get("wallet").cloned().unwrap_or_default();

        // Display identity
        println!();
        output::print_header("Identity");
        println!();
        output::print_field("DID", &did);
        output::print_field("Display Name", &display_name);
        output::print_field("Type", &identity_type);
        output::print_field(
            "Role",
            result
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("MicroNode"),
        );
        output::print_field(
            "Status",
            identity
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("active"),
        );

        // Display wallet
        println!();
        output::print_header("Wallet");
        println!();
        output::print_field("Wallet ID", &wallet_id);
        output::print_field("Address", &wallet_address);
        if let Some(pk) = wallet.get("public_key").and_then(|v| v.as_str())
            && !pk.is_empty()
        {
            let truncated = if pk.len() > 20 {
                format!("{}...", &pk[..20])
            } else {
                pk.to_string()
            };
            output::print_field("Public Key", &truncated);
        }

        // Display MicroNode capabilities (only when joinAsMicroNode is supported)
        if is_micro_node {
            if let Some(caps) = result.get("capabilities") {
                println!();
                output::print_header("Network Capabilities");
                println!();
                let cap_names = [
                    ("inference", "AI Model Inference"),
                    ("payments", "TNZO Payments"),
                    ("agent_collaboration", "Agent Collaboration (A2A)"),
                    ("mcp_tools", "MCP Tools (24 tools)"),
                    ("chain_query", "Chain State Queries"),
                    ("smart_contracts", "Smart Contracts (EVM/SVM)"),
                    ("tee_services", "TEE Confidential Compute"),
                    ("bridge", "Cross-Chain Bridge"),
                    ("governance", "Governance & Voting"),
                ];
                for (key, label) in &cap_names {
                    let enabled = caps.get(key).and_then(|v| v.as_bool()).unwrap_or(false);
                    let status = if enabled { "enabled" } else { "disabled" };
                    output::print_field(label, status);
                }
            }

            if let Some(network) = result.get("network") {
                println!();
                output::print_header("Network Endpoints");
                println!();
                if let Some(rpc_url) = network.get("rpc").and_then(|v| v.as_str()) {
                    output::print_field("JSON-RPC", rpc_url);
                }
                if let Some(mcp_url) = network.get("mcp").and_then(|v| v.as_str()) {
                    output::print_field("MCP Server", mcp_url);
                }
                if let Some(a2a_url) = network.get("a2a").and_then(|v| v.as_str()) {
                    output::print_field("A2A Protocol", a2a_url);
                }
            }

            if let Some(msg) = result.get("message").and_then(|v| v.as_str()) {
                println!();
                output::print_info(msg);
            }
        } else {
            // The hardware profile the node reported.
            let hardware = result.get("hardware").cloned().unwrap_or_default();
            if !hardware.is_null() {
                println!();
                output::print_header("Hardware Profile");
                println!();
                if let Some(cpu) = hardware.get("cpu_model").and_then(|v| v.as_str()) {
                    let cores = hardware
                        .get("cpu_cores")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let threads = hardware
                        .get("cpu_threads")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    output::print_field(
                        "CPU",
                        &format!("{} ({} cores, {} threads)", cpu, cores, threads),
                    );
                }
                if let Some(ram) = hardware.get("total_ram_gb").and_then(|v| v.as_f64()) {
                    output::print_field("RAM", &format!("{:.1} GB", ram));
                }
                if let Some(gpus) = hardware.get("gpus").and_then(|v| v.as_array()) {
                    if gpus.is_empty() {
                        output::print_field("GPUs", "None detected");
                    } else {
                        for (i, gpu) in gpus.iter().enumerate() {
                            let name = gpu
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown");
                            let mem = gpu.get("memory_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                            output::print_field(
                                &format!("GPU {}", i + 1),
                                &format!("{} ({:.1} GB)", name, mem),
                            );
                        }
                    }
                }
            }
        }

        // `tenzro_joinAsMicroNode` provisions the identity + wallet + hardware
        // profile. To acquire an authenticated bearer, call one of
        // `tenzro_onboardHuman` / `tenzro_onboardDelegatedAgent` /
        // `tenzro_onboardAutonomousAgent` — each returns an OAuth 2.1 +
        // DPoP-bound JWT. `tenzro_onboardHuman` only accepts a caller that
        // proves it holds the passkey and ML-DSA-65 key it presents, by
        // signing an `enroll_passkey` custody challenge, so it runs from the
        // client that holds the passkey. Export the result as
        // `TENZRO_BEARER_JWT` + `TENZRO_DPOP_PROOF` for subsequent privileged
        // calls.
        if self.r#type != "human" {
            println!();
            output::print_info(
                "To mint a DPoP-bound JWT for a human identity, onboard from the client that holds your passkey: tenzro_onboardHuman takes the passkey public key, its ML-DSA-65 key and an `authorization` signed by both over a tenzro_createCustodyChallenge `enroll_passkey` challenge. Then export TENZRO_BEARER_JWT + TENZRO_DPOP_PROOF for privileged calls.",
            );
        }

        if self.r#type != "human" {
            output::print_info(
                "This account sends transactions once its identity is on chain: fund it, \
                 then run `tenzro identity register-account`.",
            );
        }

        // Provider path: hardware detection → funding → compute bond →
        // registration → default pricing → model pull + serve → TEE check.
        let provider_result = if self.provider {
            Some(
                run_provider_flow(
                    &rpc,
                    crate::keystore::AccountSigner::Client(
                        crate::keystore::DEFAULT_CLIENT_KEY_NAMESPACE,
                    ),
                    &did,
                    &wallet_address,
                    &clean_name,
                )
                .await?,
            )
        } else {
            None
        };

        let spinner = output::create_spinner("Saving configuration...");

        let mut cfg = config::load_config();
        joined.keep(&mut cfg, &rpc_url);
        if let Some(pricing) = provider_result {
            cfg.pricing = Some(pricing);
        }

        config::save_config(&cfg)?;

        spinner.finish_and_clear();

        output::print_success(&format!(
            "Configuration saved to: {}",
            config::config_path().display()
        ));

        println!();
        if self.provider {
            output::print_success("You are now a Tenzro Network provider!");
            output::print_info(
                "Your node advertises its capacity on the provider gossip topic; inference demand routes to you automatically and settles in TNZO.",
            );
        } else {
            output::print_success("You are now part of the Tenzro Network!");
        }
        output::print_info(&format!("Chain ID: {}", chain_id));

        Ok(())
    }
}

/// `join --provider --node-account`: this machine's node becomes a provider
/// as itself. Its node account (through the key holder on a machine with no
/// TPM) posts the bonds, and the DID the node operates as is the provider;
/// the node registers that identity itself, so none is provisioned here.
async fn join_node_as_provider(
    rpc: &RpcClient,
    rpc_url: &str,
    account: &crate::keystore::SigningAccount,
    name: &str,
    chain_id: u64,
) -> Result<()> {
    if !names_this_machine(rpc_url) {
        anyhow::bail!(
            "--node-account signs the provider bond for the DID the node at {rpc_url} names, and \
             nothing here checks that DID against this machine's key: run it against this \
             machine's own node (--rpc http://127.0.0.1:8545)"
        );
    }
    let (signer, address) = account.open()?;
    let status: serde_json::Value = rpc
        .call("tenzro_getNodeStatus", serde_json::json!([]))
        .await
        .map_err(|e| anyhow::anyhow!("Reading the node's status failed: {e}"))?;
    let did = status
        .get("operator_did")
        .and_then(|v| v.as_str())
        .filter(|d| !d.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the node at {rpc_url} names no operator DID yet; it names its machine DID once it \
                 has a hardware identity key. Run this again when `tenzro node status` shows one."
            )
        })?
        .to_string();
    let wallet = format!("0x{}", hex::encode(address));
    output::print_field("Provider DID", &did);
    output::print_field("Node account", &wallet);

    let pricing = run_provider_flow(rpc, signer, &did, &wallet, name).await?;

    let mut cfg = config::load_config();
    cfg.endpoint = Some(rpc_url.to_string());
    cfg.pricing = Some(pricing);
    config::save_config(&cfg)?;
    output::print_success(&format!(
        "Configuration saved to: {}",
        config::config_path().display()
    ));
    println!();
    output::print_success("This node is now a Tenzro Network provider!");
    output::print_info(&format!("Chain ID: {chain_id}"));
    Ok(())
}

/// Whether `rpc_url` names this machine (`localhost` or a loopback address).
fn names_this_machine(rpc_url: &str) -> bool {
    let rest = rpc_url.split_once("://").map_or(rpc_url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The compute bond minimum in force, a governed parameter, read from the
/// node: the bond `join --provider` posts for the provider DID, which
/// inference faults and SLA verdicts are slashed from.
async fn compute_bond_min_wei(rpc: &RpcClient) -> Result<u128> {
    let params: serde_json::Value = rpc
        .call("tenzro_computeBondParams", serde_json::json!([]))
        .await?;
    params
        .get("min_bond_wei")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("the node did not report the compute bond minimum"))
}

/// The `ai` role's bond in force, a governed parameter, read from the node.
async fn ai_role_stake_wei(rpc: &RpcClient) -> Result<u128> {
    let param: serde_json::Value = rpc
        .call(
            "tenzro_getNetworkParams",
            serde_json::json!({ "key": "stake.ai_tnzo" }),
        )
        .await?;
    let tnzo: u64 = param
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("the node did not report the ai role's bond amount"))?;
    Ok(u128::from(tnzo) * tenzro_types::constants::ONE_TNZO)
}

/// Gas budget for a `PostComputeBond` transaction.
const COMPUTE_BOND_POST_GAS: u64 = tenzro_types::constants::bond_gas::COMPUTE_BOND_POST;

/// Automatic provider provisioning against the node at `rpc`.
///
/// The provider steps of a joined identity: registration, bond, pricing and
/// the first model, saved to the config. `tenzro setup` runs this after its
/// role and funding steps, once the identity and wallet exist.
pub(crate) async fn provider_setup(rpc_url: &str, name: &str) -> Result<()> {
    let mut cfg = config::load_config();
    let (Some(did), Some(wallet)) = (cfg.did.clone(), cfg.wallet_address.clone()) else {
        anyhow::bail!(
            "provider setup needs the identity and wallet the previous step creates, and none is recorded. \
             Fix: run `tenzro setup --restart`."
        );
    };
    let rpc = RpcClient::new(rpc_url);
    let pricing = run_provider_flow(
        &rpc,
        crate::keystore::AccountSigner::Client(crate::keystore::DEFAULT_CLIENT_KEY_NAMESPACE),
        &did,
        &wallet,
        name,
    )
    .await?;
    cfg.pricing = Some(pricing);
    config::save_config(&cfg)
}

/// Returns the pricing that was set on the node.
async fn run_provider_flow(
    rpc: &RpcClient,
    signer: crate::keystore::AccountSigner<'_>,
    did: &str,
    wallet_address: &str,
    name: &str,
) -> Result<config::ProviderPricing> {
    println!();
    output::print_header("Provider Setup");
    println!();

    // 1. Hardware detection (local, no RPC).
    let spinner = output::create_spinner("Detecting hardware...");
    let hw = crate::commands::hardware::detect_hardware_profile().await;
    spinner.finish_and_clear();

    output::print_field(
        "CPU",
        &format!(
            "{} ({} cores, {} threads)",
            hw.cpu_model, hw.cpu_cores, hw.cpu_threads
        ),
    );
    output::print_field(
        "RAM",
        &format!(
            "{:.1} GB{}",
            hw.total_ram_gb,
            if hw.unified_memory { " (unified)" } else { "" }
        ),
    );
    if hw.gpus.is_empty() {
        output::print_field("GPU", "None detected (CPU inference)");
    } else {
        for (i, gpu) in hw.gpus.iter().enumerate() {
            output::print_field(
                &format!("GPU {}", i + 1),
                &format!("{} ({:.1} GB)", gpu.name, gpu.memory_gb),
            );
        }
    }
    output::print_field(
        "TEE",
        if hw.tee_available {
            hw.tee_type.as_deref().unwrap_or("available")
        } else {
            "not available"
        },
    );

    // Memory budget for model selection: discrete GPU VRAM when present,
    // otherwise a conservative share of system RAM (covers unified-memory
    // machines and CPU-only inference).
    let gpu_vram = hw.gpus.iter().map(|g| g.memory_gb).fold(0.0_f64, f64::max);
    let budget_gb = if gpu_vram > 0.0 && !hw.unified_memory {
        gpu_vram
    } else {
        hw.total_ram_gb * 0.7
    };
    let max_concurrent: u32 = if gpu_vram > 0.0 { 4 } else { 2 };
    output::print_field("Model memory budget", &format!("{:.1} GB", budget_gb));
    println!();

    // 2. Funding: the wallet holds at least the compute bond minimum. It has
    // to be funded by a transfer before joining.
    let spinner = output::create_spinner("Checking wallet balance...");
    let bond_wei = compute_bond_min_wei(rpc).await?;
    let balance_wei = get_balance_wei(rpc, wallet_address).await;
    spinner.finish_and_clear();
    output::print_field("Balance", &crate::rpc::format_tnzo(balance_wei));
    if balance_wei < bond_wei {
        // Ask the website where the application stands so the message below
        // continues from there (the record is kept in the CLI config).
        let _ = crate::onboarding::flow::snapshot(
            rpc,
            &crate::onboarding::flow::AnySource::from_env(),
            crate::onboarding::role::JoinRole::ComputeProvider.slug(),
            Some(crate::onboarding::role::JoinRole::ComputeProvider),
            wallet_address,
            bond_wei,
        )
        .await;
        let need = crate::commands::stake_options::StakeNeed {
            role: "compute provider".to_string(),
            required_wei: bond_wei,
            balance_wei: Some(balance_wei),
            account: wallet_address.to_string(),
        };
        need.print_plain();
        need.remember()?;
        anyhow::bail!(
            "wallet {} holds less than the {} compute bond minimum; run `tenzro join --provider` again once it is funded",
            wallet_address,
            crate::rpc::format_tnzo(bond_wei)
        );
    }
    crate::commands::stake_options::forget()?;

    // 3. Compute bond (skip when one is already posted for this DID).
    let existing_bond: serde_json::Value = rpc
        .call(
            "tenzro_getComputeBond",
            serde_json::json!([{ "provider_did": did }]),
        )
        .await
        .unwrap_or(serde_json::Value::Null);
    if existing_bond.is_null() {
        let spinner = output::create_spinner(&format!(
            "Posting compute bond ({})...",
            crate::rpc::format_tnzo(bond_wei)
        ));
        crate::keystore::SigningAccount::send(
            rpc,
            signer,
            [0u8; 32],
            serde_json::json!({
                "PostComputeBond": {
                    "provider_did": did,
                    "amount": bond_wei.to_string(),
                }
            }),
            COMPUTE_BOND_POST_GAS,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Compute bond failed: {}", e))?;
        spinner.finish_and_clear();
        output::print_success(&format!(
            "Compute bond posted ({})",
            crate::rpc::format_tnzo(bond_wei)
        ));
    } else {
        output::print_success("Compute bond already posted for this DID");
    }

    // 4. The `ai` role's stake, bonded in consensus from the same wallet. A
    // node serves the role only while this bond stands.
    let ai_stake_wei = ai_role_stake_wei(rpc).await?;
    let spinner = output::create_spinner(&format!(
        "Bonding the ai role ({})...",
        crate::rpc::format_tnzo(ai_stake_wei)
    ));
    let op = tenzro_types::token::StakeOp::Bond {
        role: tenzro_types::NetworkRole::ModelProvider,
        amount: ai_stake_wei,
        capacity: tenzro_types::token::StakeCapacity::None,
    };
    crate::keystore::SigningAccount::send(
        rpc,
        signer,
        [0u8; 32],
        serde_json::to_value(tenzro_types::TransactionType::Stake { op })?,
        COMPUTE_BOND_POST_GAS,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Bonding the ai role failed: {}", e))?;
    spinner.finish_and_clear();
    output::print_success(&format!(
        "ai role bonded for {name} (up to {max_concurrent} concurrent requests)"
    ));

    // 5. Pricing: the node starts with its default card; read it so
    // `tenzro provider pricing show` and the saved config agree.
    let spinner = output::create_spinner("Reading the node's price card...");
    let pricing: config::ProviderPricing = rpc
        .call("tenzro_getProviderPricing", serde_json::json!([]))
        .await
        .map_err(|e| anyhow::anyhow!("Reading pricing failed: {}", e))?;
    spinner.finish_and_clear();
    output::print_success(
        "Pricing: the node's default card (change it with `tenzro provider pricing set`)",
    );

    // 6. Model selection: largest catalog model that fits the memory
    // budget, preferring one that is already downloaded.
    let models: Vec<serde_json::Value> = rpc
        .call("tenzro_listModels", serde_json::json!({}))
        .await
        .map_err(|e| anyhow::anyhow!("Listing models failed: {}", e))?;

    let mut best: Option<(&serde_json::Value, bool, u64)> = None;
    for m in &models {
        let min_ram = m
            .get("min_ram_gb")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        if (min_ram as f64) > budget_gb {
            continue;
        }
        let downloaded = m
            .get("downloaded")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let size = m.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let better = match &best {
            None => true,
            Some((_, best_dl, best_size)) => (downloaded, size) > (*best_dl, *best_size),
        };
        if better {
            best = Some((m, downloaded, size));
        }
    }

    let Some((model, _, size)) = best else {
        output::print_warning(&format!(
            "No catalog model fits within {:.1} GB — provider is registered but not serving. \
             Serve one manually with `tenzro model serve <model-id> --rpc {}`.",
            budget_gb,
            rpc.url()
        ));
        return Ok(pricing);
    };
    let model_id = model
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let model_name = model
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(&model_id);
    output::print_field(
        "Selected model",
        &format!("{} ({:.1} GB)", model_name, size as f64 / 1e9),
    );

    // 8. Serve on the network.
    let spinner = output::create_spinner(&format!("Serving {} to the network...", model_id));
    let serve: serde_json::Value = rpc
        .call(
            "tenzro_serveModel",
            serde_json::json!({
                "model_id": model_id,
                "user_forced": false,
                "force_single": false,
            }),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Serve request failed: {}", e))?;
    spinner.finish_and_clear();
    output::print_success(&format!(
        "Model {} is serving ({})",
        model_id,
        serve
            .get("visibility")
            .and_then(|v| v.as_str())
            .unwrap_or("public")
    ));
    if let Some(ep) = serve.get("endpoint_id").and_then(|v| v.as_str()) {
        output::print_field("Endpoint ID", ep);
    }

    // 9. TEE detection on the node — attestation enrollment is node-side;
    // report what the node sees so the operator knows the confidential
    // tier is (or is not) in play.
    if hw.tee_available {
        match rpc
            .call::<serde_json::Value>("tenzro_detectTee", serde_json::json!([]))
            .await
        {
            Ok(tee) => {
                let available = tee
                    .get("available")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if available {
                    let vendor = tee
                        .get("vendor")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    output::print_success(&format!(
                        "TEE detected on node: {} — attestation is announced with your capacity",
                        vendor
                    ));
                } else {
                    output::print_info(
                        "TEE hardware detected locally but not visible to the node — confidential-tier serving stays off until the node runs on the TEE host.",
                    );
                }
            }
            Err(e) => output::print_warning(&format!("TEE detection on node failed: {}", e)),
        }
    }

    Ok(pricing)
}

async fn get_balance_wei(rpc: &RpcClient, address: &str) -> u128 {
    match rpc
        .call::<serde_json::Value>("eth_getBalance", serde_json::json!([address, "latest"]))
        .await
    {
        Ok(v) => {
            let hex = v.as_str().unwrap_or("0x0");
            u128::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0)
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn only_a_loopback_endpoint_names_this_machine() {
        for url in [
            "http://127.0.0.1:8545",
            "http://localhost:8545/",
            "https://LOCALHOST",
            "http://[::1]:8545",
            "http://user@127.0.0.1:8545/rpc",
        ] {
            assert!(names_this_machine(url), "{url}");
        }
        for url in [
            "https://rpc.tenzro.com",
            "http://10.0.0.5:8545",
            "http://localhost.example.com:8545",
            "http://127.0.0.1.example.com",
            "http://example.com/127.0.0.1",
            "http://127.0.0.1@evil.example:8545",
        ] {
            assert!(!names_this_machine(url), "{url}");
        }
    }
    use super::*;
    use crate::keystore::AccountSigner;

    fn join(args: &[&str]) -> JoinCmd {
        let mut all = vec!["join"];
        all.extend(args);
        let mut cmd = JoinCmd::try_parse_from(all).expect("the join arguments parse");
        if !args.contains(&"--tpm-key-holder") {
            cmd.delegated = crate::keystore::DelegatedKey::default();
        }
        cmd
    }

    #[test]
    fn a_provider_joins_from_the_client_account_unless_the_node_account_is_asked_for() {
        assert!(join(&["--provider"]).node_signing().unwrap().is_none());
        let node = join(&["--provider", "--node-account"])
            .node_signing()
            .unwrap()
            .expect("the node account signs");
        assert_eq!(node.signer().unwrap(), AccountSigner::Node(None));
        assert!(
            JoinCmd::try_parse_from(["join", "--node-account"]).is_err(),
            "--node-account applies to --provider"
        );
    }

    #[test]
    fn a_machine_without_a_tpm_joins_as_a_provider_through_the_key_holder() {
        let holder = ["--tpm-key-holder", "/run/holder.sock", "--tpm-label", "m1"];
        let mut args = vec!["--provider", "--node-account"];
        args.extend(holder);
        let node = join(&args)
            .node_signing()
            .unwrap()
            .expect("the node account signs");
        assert_eq!(node.signer().unwrap(), AccountSigner::Node(None));
        assert_eq!(node.delegated.tpm_label.as_deref(), Some("m1"));

        let mut args = vec!["--provider"];
        args.extend(holder);
        let refused = join(&args).node_signing().unwrap_err().to_string();
        assert!(refused.contains("--node-account"), "{refused}");
    }
}
