//! Validator commands for the Tenzro CLI (dynamic validator set).
//!
//! Permissionless validator join/exit with mandatory hybrid PQ keying. Writes
//! (`RegisterValidator`, `ExitValidator`, `UpdateValidatorMetadata`) are
//! consensus-mediated typed transactions submitted via
//! `tenzro_sendRawTransaction`. Reads (`tenzro_getValidatorState`,
//! `tenzro_listValidators`, `tenzro_listActiveValidators`) hit the node's
//! in-process `ValidatorRegistry` cache.

use crate::keystore::{AccountSigner, SigningAccount};
use crate::output;
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};

/// Validator set commands (Dynamic Validator Set)
#[derive(Debug, Subcommand)]
pub enum ValidatorCommand {
    /// Register a new validator candidate (signed RegisterValidator transaction)
    Register(ValidatorRegisterCmd),
    /// Voluntarily exit the validator set (signed ExitValidator transaction)
    Exit(ValidatorExitCmd),
    /// Add to this validator's self-stake (signed IncreaseValidatorStake)
    IncreaseStake(ValidatorIncreaseStakeCmd),
    /// Update validator metadata / TEE attestation commitment
    UpdateMetadata(ValidatorUpdateMetadataCmd),
    /// Inspect a single validator entry by address (read-only)
    Get(ValidatorGetCmd),
    /// List validators (optionally filter by status) (read-only)
    List(ValidatorListCmd),
    /// List currently-Active validators (read-only)
    ListActive(ValidatorListActiveCmd),
    /// Print this node's genesis `[[validators]]` entry
    Keys(ValidatorKeysCmd),
    /// Register this machine's identity on chain with the node account as its
    /// wallet and its TPM attestation, so the validator votes, attests and
    /// serves agents as its machine root
    RegisterMachine(ValidatorRegisterMachineCmd),
    /// Attach this machine's TPM attestation to its machine root, when the
    /// root was registered without one
    AttachAttestation(ValidatorAttachAttestationCmd),
}

impl ValidatorCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::Exit(cmd) => cmd.execute().await,
            Self::IncreaseStake(cmd) => cmd.execute().await,
            Self::UpdateMetadata(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::ListActive(cmd) => cmd.execute().await,
            Self::Keys(cmd) => cmd.execute().await,
            Self::RegisterMachine(cmd) => cmd.execute().await,
            Self::AttachAttestation(cmd) => cmd.execute().await,
        }
    }
}

const DEFAULT_REGISTER_GAS: u64 = 200_000;
/// Gas an attach is sent with: a composite signature, a quote check and
/// three records.
const DEFAULT_ATTACH_GAS: u64 = 300_000;
const DEFAULT_EXIT_GAS: u64 = 80_000;
const DEFAULT_UPDATE_METADATA_GAS: u64 = 80_000;

/// Decode a 0x-prefixed (or bare) hex string into a fixed-size byte array.
fn hex_to_fixed<const N: usize>(s: &str, label: &str) -> Result<[u8; N]> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("invalid hex for {}: {}", label, e))?;
    if bytes.len() != N {
        return Err(anyhow!(
            "{} must be {} bytes ({} hex chars), got {}",
            label,
            N,
            N * 2,
            bytes.len()
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decode a 0x-prefixed (or bare) hex string into a variable-length Vec<u8>.
fn hex_to_vec(s: &str, label: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim().trim_start_matches("0x");
    hex::decode(trimmed).map_err(|e| anyhow!("invalid hex for {}: {}", label, e))
}

fn extract_tx_hash(result: &serde_json::Value) -> String {
    result
        .get("tx_hash")
        .or_else(|| result.get("transaction_hash"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| result.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// Register a new validator candidate.
///
/// The `RegisterValidator` typed transaction records the candidate as
/// `Candidate`; the next validator-set boundary promotes it to
/// `PendingActive` (subject to the churn budget) and the boundary after that
/// makes it `Active`.
///
/// The registration proofs bind the account that sends it. `tenzro validator
/// keys` signs them over the node account, so they are sent with
/// `--node-account`; proofs that do not bind the sending account are refused
/// before anything is signed. The command waits for the receipt and fails
/// with the revert reason when the chain refused the registration.
#[derive(Debug, Parser)]
pub struct ValidatorRegisterCmd {
    #[command(flatten)]
    account: SigningAccount,

    /// 1952-byte ML-DSA-65 verifying key of the hardware consensus key (hex),
    /// as printed by `tenzro validator keys`
    #[arg(long)]
    ml_dsa_public_key: String,

    /// 65-byte uncompressed P-256 key, the classical half of the same
    /// composite key (hex)
    #[arg(long)]
    p256_public_key: String,

    /// 32-byte Ed25519 node key of the node that runs the validator (hex),
    /// as printed by `tenzro validator keys`
    #[arg(long)]
    node_key: String,

    /// Composite proof of possession the hardware signed over the sending
    /// account, both key halves and the node key (hex), as printed by
    /// `tenzro validator keys` (which binds it to the node account).
    /// Registration is refused without a valid one.
    #[arg(long)]
    proof_of_possession: String,

    /// The node key's Ed25519 signature over the same registration (hex),
    /// as printed by `tenzro validator keys`
    #[arg(long)]
    node_key_proof: String,

    /// 32-byte VRF key of the node that runs the validator (hex), a key of
    /// its own apart from the node key, as printed by `tenzro validator keys`
    #[arg(long)]
    vrf_key: String,

    /// The VRF key's 80-byte proof over the same registration (hex), as
    /// printed by `tenzro validator keys`
    #[arg(long)]
    vrf_key_proof: String,

    /// Withdrawal address — rewards / unbonded principal settle here (hex; 32 bytes)
    #[arg(long)]
    withdrawal_address: String,

    /// Self-stake committed to the candidate: TNZO (`10000`, `10000 TNZO`)
    /// or wei with its suffix. Must be at least the registry's
    /// `min_self_stake` (default 10,000 TNZO).
    #[arg(long, value_parser = crate::units::parse_amount_wei)]
    self_stake: u128,

    /// Optional ≤256-byte off-chain pointer (moniker / website / contact)
    #[arg(long, default_value = "")]
    metadata_uri: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register Validator");

        // Validate + decode keys client-side so the user gets a clear error
        // rather than a server-side serde failure.
        let ml_dsa: [u8; 1952] = hex_to_fixed(&self.ml_dsa_public_key, "ml_dsa_public_key")?;
        let p256: [u8; 65] = hex_to_fixed(&self.p256_public_key, "p256_public_key")?;
        let key = tenzro_consensus::ValidatorPublicKey::new(ml_dsa.to_vec(), p256.to_vec())
            .map_err(|e| anyhow!("consensus key: {e}"))?;
        let node_key: [u8; 32] = hex_to_fixed(&self.node_key, "node_key")?;
        let proof = hex_to_vec(&self.proof_of_possession, "proof_of_possession")?;
        let node_key_proof: [u8; 64] = hex_to_fixed(&self.node_key_proof, "node_key_proof")?;
        let vrf_key: [u8; 32] = hex_to_fixed(&self.vrf_key, "vrf_key")?;
        let vrf_key_proof: [u8; 80] = hex_to_fixed(&self.vrf_key_proof, "vrf_key_proof")?;
        let withdrawal_bytes: [u8; 32] =
            hex_to_fixed(&self.withdrawal_address, "withdrawal_address")?;

        let (signer, from) = self.account.open()?;
        // The VM verifies the proof against the sending account; one that
        // binds another account would only revert after paying gas.
        check_proof_binds_sender(signer, &from, &key, &node_key, &proof)?;
        let account = account_hex(&from);

        let rpc = RpcClient::new(&self.rpc);

        // Initial phase: a wallet below the stake minimum gets the plain
        // application message, not a rejected transaction.
        let required = self
            .self_stake
            .max(crate::onboarding::role::JoinRole::Validator.stake_minimum_wei());
        // While validator admission is closed, say so before anything is
        // signed; the chain refuses the registration either way.
        let admission =
            crate::commands::setup::read_admission(&self.rpc, Some(account.as_str())).await;
        if admission.refuses_validator() {
            anyhow::bail!("{}", crate::onboarding::wizard::admission_refusal());
        }
        crate::onboarding::flow::gate(
            &self.rpc,
            &account,
            "validator",
            Some(crate::onboarding::role::JoinRole::Validator),
            required,
        )
        .await?;

        // The Address / Vec<u8> fields serde-derive to JSON arrays of numbers.
        let tx_type = serde_json::json!({
            "RegisterValidator": {
                "ml_dsa_pubkey": key.ml_dsa,
                "p256_pubkey": key.p256,
                "node_key": node_key,
                "proof_of_possession": proof,
                "node_key_proof": node_key_proof.to_vec(),
                "vrf_key": vrf_key,
                "vrf_key_proof": vrf_key_proof.to_vec(),
                "withdrawal_address": withdrawal_bytes,
                "self_stake": self.self_stake.to_string(),
                "metadata_uri": self.metadata_uri,
            }
        });

        let spinner = output::create_spinner("Signing RegisterValidator transaction...");
        let result =
            SigningAccount::send(&rpc, signer, [0u8; 32], tx_type, DEFAULT_REGISTER_GAS).await;
        spinner.finish_and_clear();
        let result = result.map_err(|e| {
            crate::onboarding::flow::plain_send_error(
                e,
                "validator",
                Some(crate::onboarding::role::JoinRole::Validator),
                required,
                &account,
            )
        })?;

        output::print_success("RegisterValidator transaction submitted");
        println!();
        output::print_field("From", &account);
        output::print_field("Node key", &self.node_key);
        output::print_field("Withdrawal address", &self.withdrawal_address);
        output::print_field("Self-stake (wei)", &self.self_stake.to_string());
        if !self.metadata_uri.is_empty() {
            output::print_field("Metadata URI", &self.metadata_uri);
        }
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        crate::keystore::confirm_executed(&rpc, &result, "RegisterValidator").await?;
        output::print_warning(
            "The validator is a Candidate. The next validator-set boundary promotes it to \
             PendingActive (subject to the churn budget) and the boundary after that makes it \
             Active: keep the node running and check `tenzro validator get <address>`.",
        );
        Ok(())
    }
}

/// Refuses, before anything is signed, a proof of possession that does not
/// bind `from`, the account the registration would be sent from: the VM
/// verifies the proof over the sending account and would revert it.
fn check_proof_binds_sender(
    signer: AccountSigner<'_>,
    from: &[u8; 32],
    key: &tenzro_consensus::ValidatorPublicKey,
    node_key: &[u8; 32],
    proof: &[u8],
) -> Result<()> {
    if tenzro_consensus::validator_key::verify_registration(from, key, node_key, proof).is_ok() {
        return Ok(());
    }
    let from = account_hex(from);
    Err(match signer {
        AccountSigner::Client(ns) => anyhow!(
            "the proof of possession does not bind the client account {from} (key namespace \
             `{ns}`) this registration would be sent from, so the chain would refuse it. \
             `tenzro validator keys` signs the proofs over this machine's node account: \
             register with --node-account (with --key-namespace naming the node's \
             hardware_key_namespace when it has one)."
        ),
        AccountSigner::Node(_) => anyhow!(
            "the proof of possession does not bind the node account {from} this registration \
             would be sent from, so the chain would refuse it. Take the proofs from `tenzro \
             validator keys` on the node whose account signs, with --key-namespace naming that \
             node's hardware_key_namespace when it has one."
        ),
    })
}

/// Add to an already-registered validator's self-stake.
///
/// The registry could create a stake and end one, and nothing in between:
/// registration refuses an address that has not exited, and exiting to
/// re-register costs the cooldown and the validator's place in the set. So a
/// validator set had no way to rebalance — which matters most on a network
/// bootstrapped from one heavily-funded genesis validator, where nothing could
/// dilute it and every block stayed dependent on that single node.
#[derive(Debug, Parser)]
pub struct ValidatorIncreaseStakeCmd {
    #[command(flatten)]
    account: SigningAccount,

    /// Additional self-stake: TNZO (`500`, `500 TNZO`) or wei with its
    /// suffix. Only ever adds; reducing a stake is unbonding, which has its
    /// own path and delay.
    #[arg(long, value_parser = crate::units::parse_amount_wei)]
    additional: u128,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorIncreaseStakeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Increase Validator Stake");

        if self.additional == 0 {
            anyhow::bail!("--additional must be greater than zero");
        }

        let rpc = RpcClient::new(&self.rpc);
        let (signer, from) = self.account.open()?;

        let spinner = output::create_spinner("Signing IncreaseValidatorStake transaction...");

        let tx_type = serde_json::json!({
            "IncreaseValidatorStake": {
                "additional": self.additional.to_string(),
            }
        });

        let result = SigningAccount::send(&rpc, signer, from, tx_type, 100_000u64).await;
        spinner.finish_and_clear();
        let result = result?;

        output::print_success("IncreaseValidatorStake transaction submitted");
        println!();
        output::print_field("From", &account_hex(&from));
        output::print_field(
            "Additional",
            &format!("{} TNZO", self.additional / 1_000_000_000_000_000_000),
        );
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        crate::keystore::confirm_executed(&rpc, &result, "IncreaseValidatorStake").await
    }
}

/// `0x` hex of a 32-byte account address.
fn account_hex(address: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(address))
}

/// Voluntarily exit the validator set.
///
/// The exit is signed by the account the validator is bonded under. A
/// validator is keyed by the account that registered it: one registered from
/// `tenzro validator keys`, of the genesis set, or registered by its own node
/// (`--validator-self-stake`) is bonded under the node account and signs with
/// `--node-account`; one registered from a client account signs under its
/// `--key-namespace`.
#[derive(Debug, Parser)]
pub struct ValidatorExitCmd {
    #[command(flatten)]
    account: SigningAccount,

    /// Return once the transaction is submitted, without waiting for it to be
    /// executed
    #[arg(long)]
    no_wait: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorExitCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Exit Validator");

        let rpc = RpcClient::new(&self.rpc);
        let (signer, from) = self.account.open()?;

        let spinner = output::create_spinner("Signing ExitValidator transaction...");
        // Unit variant: externally-tagged serde renders it as a bare string.
        let tx_type = serde_json::json!("ExitValidator");
        let result = SigningAccount::send(&rpc, signer, from, tx_type, DEFAULT_EXIT_GAS).await;
        spinner.finish_and_clear();
        let result = result?;

        output::print_success("ExitValidator transaction submitted");
        println!();
        output::print_field("From", &account_hex(&from));
        output::print_field("Transaction Hash", &extract_tx_hash(&result));

        if !self.no_wait {
            crate::keystore::confirm_executed(&rpc, &result, "ExitValidator")
                .await
                .map_err(|e| {
                    if e.to_string().contains("was executed and reverted") {
                        anyhow!(
                            "{e}\nAn exit is accepted only from the account the validator is \
                             bonded under: --node-account for a validator registered from \
                             `tenzro validator keys`, of the genesis set or one its node \
                             registered itself, --key-namespace for one registered from a \
                             client account."
                        )
                    } else {
                        e
                    }
                })?;
        }

        output::print_warning(
            "The validator leaves the set after the next epoch boundary, if the exit limit \
             allows it: keep the node signing until `tenzro validator get <address>` shows it \
             Exited. The bond is held in unbonding; after the unbonding period, send the same \
             exit again from the same account to pay it out. Registering again is refused for \
             some epochs after leaving.",
        );

        Ok(())
    }
}

/// Update validator metadata or TEE attestation commitment.
#[derive(Debug, Parser)]
pub struct ValidatorUpdateMetadataCmd {
    #[command(flatten)]
    account: SigningAccount,

    /// New off-chain pointer (≤256 bytes); omit to skip
    #[arg(long)]
    metadata_uri: Option<String>,

    /// New 32-byte SHA-256 TEE attestation commitment (hex); omit to skip
    #[arg(long)]
    tee_attestation_hash: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorUpdateMetadataCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Update Validator Metadata");

        if self.metadata_uri.is_none() && self.tee_attestation_hash.is_none() {
            return Err(anyhow!(
                "At least one of --metadata-uri or --tee-attestation-hash must be provided"
            ));
        }

        let tee_hash_bytes: Option<[u8; 32]> = match self.tee_attestation_hash.as_deref() {
            Some(hex_s) => Some(hex_to_fixed(hex_s, "tee_attestation_hash")?),
            None => None,
        };

        let rpc = RpcClient::new(&self.rpc);
        let (signer, from) = self.account.open()?;

        let spinner = output::create_spinner("Signing UpdateValidatorMetadata transaction...");

        let mut data = serde_json::Map::new();
        match &self.metadata_uri {
            Some(uri) => data.insert(
                "metadata_uri".to_string(),
                serde_json::Value::String(uri.clone()),
            ),
            None => data.insert("metadata_uri".to_string(), serde_json::Value::Null),
        };
        match tee_hash_bytes {
            Some(arr) => data.insert(
                "tee_attestation_hash".to_string(),
                serde_json::to_value(arr).unwrap(),
            ),
            None => data.insert("tee_attestation_hash".to_string(), serde_json::Value::Null),
        };

        let tx_type = serde_json::json!({
            "UpdateValidatorMetadata": serde_json::Value::Object(data),
        });

        let result =
            SigningAccount::send(&rpc, signer, from, tx_type, DEFAULT_UPDATE_METADATA_GAS).await;
        spinner.finish_and_clear();
        let result = result?;

        output::print_success("UpdateValidatorMetadata transaction submitted");
        println!();
        output::print_field("From", &account_hex(&from));
        if let Some(uri) = &self.metadata_uri {
            output::print_field("Metadata URI", uri);
        }
        if let Some(h) = &self.tee_attestation_hash {
            output::print_field("TEE attestation hash", h);
        }
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        crate::keystore::confirm_executed(&rpc, &result, "UpdateValidatorMetadata").await
    }
}

/// Print this node's genesis `[[validators]]` entry.
///
/// `tenzro_validatorPublicKeys` has existed for some time with nothing calling
/// it, which meant assembling a genesis file involved reading three keys out of
/// an RPC response by hand, for every validator, and pasting them into TOML
/// without transposing a character. That is the sort of task a person does
/// correctly four times out of five, and a genesis that differs by one byte
/// produces a different chain. `timestamp = 0` is the one to watch: it takes
/// the "use the current time" branch, so the genesis *block* differs per node
/// and the divergence only surfaces at the first block the two disagree on.
///
/// So this prints the entry rather than the keys: the output is meant to be
/// appended to a genesis file verbatim, and the stake is asked for rather than
/// assumed because equal stake across founding validators is a decision, not a
/// default. The previous genesis on this network gave one validator 99.8% of
/// the stake and made every later attempt at fault tolerance a chase.
#[derive(Debug, Parser)]
pub struct ValidatorKeysCmd {
    /// Stake for this entry, in whole TNZO units.
    #[arg(long)]
    stake: u64,

    /// A comment written above the entry, so a reader can tell which machine
    /// it came from.
    #[arg(long)]
    name: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorKeysCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_validatorPublicKeys", serde_json::json!({}))
            .await?;

        let field = |k: &str| -> Result<String> {
            result
                .get(k)
                .and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches("0x").to_string())
                .ok_or_else(|| anyhow::anyhow!("node did not return `{k}`"))
        };

        // Written to stdout alone so `>> genesis.toml` produces a valid file.
        // Logs go to stderr for the same reason -- see `init_logging`.
        if let Some(name) = &self.name {
            println!("# {name}");
        }
        println!("[[validators]]");
        println!("address = \"{}\"", field("address")?);
        println!("ml_dsa_public_key = \"{}\"", field("ml_dsa_public_key")?);
        println!("p256_public_key = \"{}\"", field("p256_public_key")?);
        println!("node_key = \"{}\"", field("node_key")?);
        println!(
            "proof_of_possession = \"{}\"",
            field("proof_of_possession")?
        );
        println!("node_key_proof = \"{}\"", field("node_key_proof")?);
        println!("vrf_key = \"{}\"", field("vrf_key")?);
        println!("vrf_key_proof = \"{}\"", field("vrf_key_proof")?);
        println!("stake = {}", self.stake);
        Ok(())
    }
}

/// Inspect a single validator entry by address.
#[derive(Debug, Parser)]
pub struct ValidatorGetCmd {
    /// Validator address (32-byte hex; with or without 0x prefix)
    address: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Validator Entry");

        // Validate the address format client-side.
        let _: [u8; 32] = hex_to_fixed(&self.address, "address")?;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getValidatorState",
                serde_json::json!({ "address": self.address }),
            )
            .await?;

        println!();
        if result.is_null() {
            output::print_warning("No validator entry found for this address.");
            return Ok(());
        }

        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}

/// List validators (optionally filtered by status).
#[derive(Debug, Parser)]
pub struct ValidatorListCmd {
    /// Filter by status: Active | Candidate | PendingActive | PendingExit | Exited | Jailed
    #[arg(long)]
    status: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Validators");

        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::Map::new();
        if let Some(s) = &self.status {
            params.insert("status".to_string(), serde_json::Value::String(s.clone()));
        }
        let result: serde_json::Value = rpc
            .call("tenzro_listValidators", serde_json::Value::Object(params))
            .await?;

        println!();
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let validators = result
            .get("validators")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        output::print_field("Total", &count.to_string());
        if validators.is_empty() {
            output::print_warning("No validators match the filter.");
            return Ok(());
        }
        println!();
        for (i, v) in validators.iter().enumerate() {
            println!("Validator #{}", i + 1);
            for (key, val) in v.as_object().unwrap_or(&serde_json::Map::new()) {
                output::print_field(key, val.to_string().trim_matches('"'));
            }
            println!();
        }
        Ok(())
    }
}

/// List currently-Active validators.
#[derive(Debug, Parser)]
pub struct ValidatorListActiveCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorListActiveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Active Validators");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listActiveValidators", serde_json::json!({}))
            .await?;

        println!();
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let validators = result
            .get("validators")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        output::print_field("Active count", &count.to_string());
        if validators.is_empty() {
            output::print_warning("No active validators.");
            return Ok(());
        }
        println!();
        for (i, v) in validators.iter().enumerate() {
            println!("Validator #{}", i + 1);
            for (key, val) in v.as_object().unwrap_or(&serde_json::Map::new()) {
                output::print_field(key, val.to_string().trim_matches('"'));
            }
            println!();
        }
        Ok(())
    }
}

/// Register this machine's identity on chain, with the node account as its
/// wallet.
///
/// A validator that is an autonomous machine acts through the identity its
/// consensus key derives (`did:tenzro:machine:...`, as `tenzro-node tpm
/// provision` prints it): its governance ballots carry that machine root's
/// approval (`governance vote --machine-root`), and the chain finds the root
/// of a validator account through the identity whose wallet it is. This
/// registers that identity with the node account (the validator account) as
/// its wallet: the identity key signs the registration, the node account
/// submits it and pays the gas. Nothing is sent when the identity already
/// resolves.
///
/// The registration records the machine's TPM attestation (credential
/// activation and a quote over the admission challenge for the DID and the
/// identity key), so the TPM is admitted under this one identity: a node
/// serving agents has its key certifications accepted from that TPM. A
/// machine holds one identity; a second admission of the same machine as an
/// autonomous identity is refused.
#[derive(Debug, Parser)]
pub struct ValidatorRegisterMachineCmd {
    /// The node's `hardware_key_namespace` (default: the machine's default
    /// node)
    #[arg(long)]
    key_namespace: Option<String>,

    #[command(flatten)]
    delegated: crate::keystore::DelegatedKey,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorRegisterMachineCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let ns = self.key_namespace.as_deref();
        let delegated = self.delegated.install()?;
        let signer = crate::keystore::machine_identity_signer(ns)?;
        let wallet = crate::keystore::node_account(ns)?;
        let (did, register) = crate::keystore::machine_identity_registration(&signer, wallet)?;
        output::print_header("Register Machine Identity");
        output::print_field("Machine DID", &did);
        output::print_field("Wallet", &format!("0x{}", hex::encode(wallet)));
        if delegated {
            output::print_info(
                "keys delegated to the key holder: signing through it; this machine's own \
                 TPM does not attest for them",
            );
        }
        if crate::keystore::identity_registered(&rpc, &did).await {
            output::print_info("already registered");
            return Ok(());
        }
        let (result, _) =
            crate::keystore::send_as_node(&rpc, ns, [0u8; 32], register, DEFAULT_REGISTER_GAS)
                .await?;
        let tx_hash = result
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .or_else(|| result.as_str())
            .unwrap_or_default();
        output::print_field("Transaction Hash", tx_hash);
        crate::keystore::confirm_executed(&rpc, &result, "RegisterIdentity").await?;
        crate::keystore::await_identity(&rpc, &did).await?;
        output::print_success("machine identity registered");
        Ok(())
    }
}

/// Attach this machine's TPM attestation to its machine root, for a root
/// registered before machine roots recorded their TPM: the same evidence
/// `register-machine` records (credential activation and a quote), with the
/// quote answering the chain challenge of the node account's current nonce.
/// The identity key signs the attach, the node account sends it and pays the
/// gas. The chain refuses it when the root already carries an attestation,
/// when the quote does not verify, and when the TPM is already admitted
/// under another identity. Nothing is sent when the root already carries
/// one.
#[derive(Debug, Parser)]
pub struct ValidatorAttachAttestationCmd {
    /// The node's `hardware_key_namespace` (default: the machine's default
    /// node)
    #[arg(long)]
    key_namespace: Option<String>,

    #[command(flatten)]
    delegated: crate::keystore::DelegatedKey,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorAttachAttestationCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let ns = self.key_namespace.as_deref();
        self.delegated.install()?;
        let signer = crate::keystore::machine_identity_signer(ns)?;
        let wallet = crate::keystore::node_account(ns)?;
        let did = crate::keystore::machine_root_did(&signer);
        output::print_header("Attach Machine Attestation");
        output::print_field("Machine DID", &did);
        output::print_field("Wallet", &format!("0x{}", hex::encode(wallet)));
        let record = rpc
            .call::<serde_json::Value>("tenzro_resolveIdentity", serde_json::json!({ "did": did }))
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "{did} does not resolve ({e}); register it with `tenzro validator register-machine`"
                )
            })?;
        if crate::keystore::carries_tpm_attestation(&record) {
            output::print_info("the machine root already carries a TPM attestation");
            return Ok(());
        }
        // The quote answers the chain challenge of the account nonce, so a
        // nonce that moved needs a new quote, not just a new transaction:
        // the whole attach is built again.
        let (result, _) = crate::keystore::retry_stale_nonce(|| async {
            let (account_nonce, _) = crate::rpc::fetch_nonce_and_chain_id(
                &rpc,
                &format!("0x{}", hex::encode(wallet)),
                None,
                None,
            )
            .await?;
            let attach =
                crate::keystore::machine_attestation_attachment(&signer, wallet, account_nonce)?;
            crate::keystore::send_as_node_once(&rpc, ns, [0u8; 32], attach, DEFAULT_ATTACH_GAS)
                .await
        })
        .await?;
        let tx_hash = result
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .or_else(|| result.as_str())
            .unwrap_or_default();
        output::print_field("Transaction Hash", tx_hash);
        crate::keystore::confirm_executed(&rpc, &result, "machine attestation").await
    }
}

#[cfg(test)]
mod account_tests {
    use super::*;

    fn exit(args: &[&str]) -> ValidatorExitCmd {
        let mut cmd =
            ValidatorExitCmd::try_parse_from(std::iter::once("exit").chain(args.iter().copied()))
                .expect("the exit arguments parse");
        // No key holder, whatever the environment of the test run names.
        cmd.account.delegated = crate::keystore::DelegatedKey::default();
        cmd
    }

    /// The register arguments with placeholder values, the signer flags
    /// `args` added.
    fn register(args: &[&str]) -> ValidatorRegisterCmd {
        let mut all = vec![
            "register",
            "--ml-dsa-public-key",
            "00",
            "--p256-public-key",
            "00",
            "--node-key",
            "00",
            "--proof-of-possession",
            "00",
            "--node-key-proof",
            "00",
            "--vrf-key",
            "00",
            "--vrf-key-proof",
            "00",
            "--withdrawal-address",
            "00",
            "--self-stake",
            "10000",
        ];
        all.extend(args);
        let mut cmd =
            ValidatorRegisterCmd::try_parse_from(all).expect("the register arguments parse");
        cmd.account.delegated = crate::keystore::DelegatedKey::default();
        cmd
    }

    #[test]
    fn a_transaction_is_signed_by_the_client_account_unless_the_node_account_is_asked_for() {
        assert_eq!(
            exit(&[]).account.signer().unwrap(),
            AccountSigner::Client("client")
        );
        assert_eq!(
            exit(&["--key-namespace", "ops"]).account.signer().unwrap(),
            AccountSigner::Client("ops")
        );
    }

    #[test]
    fn a_node_account_signs_under_the_nodes_namespace_and_the_default_node_without_one() {
        assert_eq!(
            exit(&["--node-account"]).account.signer().unwrap(),
            AccountSigner::Node(None)
        );
        assert_eq!(
            exit(&["--node-account", "--key-namespace", "node-a"])
                .account
                .signer()
                .unwrap(),
            AccountSigner::Node(Some("node-a"))
        );
    }

    #[test]
    fn a_client_account_refuses_a_key_holder_and_a_node_account_takes_one() {
        let holder = ["--tpm-key-holder", "/run/holder.sock", "--tpm-label", "m1"];
        let parse = |args: &[&str]| {
            ValidatorExitCmd::try_parse_from(std::iter::once("exit").chain(args.iter().copied()))
                .expect("the exit arguments parse")
        };
        let refused = parse(&holder).account.signer().unwrap_err().to_string();
        assert!(refused.contains("--node-account"), "{refused}");

        let mut args = vec!["--node-account"];
        args.extend(holder);
        assert_eq!(
            parse(&args).account.signer().unwrap(),
            AccountSigner::Node(None)
        );
    }

    #[test]
    fn an_exit_waits_for_its_receipt_unless_told_not_to() {
        assert!(!exit(&[]).no_wait);
        assert!(exit(&["--no-wait"]).no_wait);
    }

    #[test]
    fn register_takes_the_same_signer_choice_as_exit() {
        assert_eq!(
            register(&[]).account.signer().unwrap(),
            AccountSigner::Client("client")
        );
        assert_eq!(
            register(&["--node-account"]).account.signer().unwrap(),
            AccountSigner::Node(None)
        );
        assert_eq!(
            register(&["--node-account", "--key-namespace", "node-a"])
                .account
                .signer()
                .unwrap(),
            AccountSigner::Node(Some("node-a"))
        );
    }

    #[test]
    fn increase_stake_and_update_metadata_take_the_same_signer_choice() {
        let increase = ValidatorIncreaseStakeCmd::try_parse_from([
            "increase-stake",
            "--node-account",
            "--additional",
            "1",
        ])
        .unwrap();
        assert!(increase.account.node_account);
        let update = ValidatorUpdateMetadataCmd::try_parse_from([
            "update-metadata",
            "--node-account",
            "--metadata-uri",
            "x",
        ])
        .unwrap();
        assert!(update.account.node_account);
    }

    /// A proof signed the way `tenzro validator keys` signs it: over the
    /// node account.
    fn proof_over(address: &[u8; 32]) -> (tenzro_consensus::ValidatorPublicKey, [u8; 32], Vec<u8>) {
        use tenzro_consensus::ValidatorSigner as _;
        let signer = tenzro_consensus::validator_key::test_signer::SoftwareTestSigner::from_seed(7);
        let node_key = [9u8; 32];
        let proof =
            tenzro_consensus::validator_key::prove_registration(&signer, address, &node_key)
                .unwrap();
        (signer.public_key().clone(), node_key, proof)
    }

    #[test]
    fn a_proof_over_the_node_account_is_sent_by_the_node_account() {
        let node = [1u8; 32];
        let (key, node_key, proof) = proof_over(&node);
        check_proof_binds_sender(AccountSigner::Node(None), &node, &key, &node_key, &proof)
            .expect("the proof binds the sending node account");
    }

    #[test]
    fn a_client_account_sending_a_proof_over_the_node_account_is_refused_before_signing() {
        let node = [1u8; 32];
        let client = [2u8; 32];
        let (key, node_key, proof) = proof_over(&node);
        let refused = check_proof_binds_sender(
            AccountSigner::Client("client"),
            &client,
            &key,
            &node_key,
            &proof,
        )
        .unwrap_err()
        .to_string();
        assert!(refused.contains("--node-account"), "{refused}");
        assert!(refused.contains(&account_hex(&client)), "{refused}");
    }

    #[test]
    fn a_node_account_sending_a_proof_over_another_account_is_refused() {
        let (key, node_key, proof) = proof_over(&[3u8; 32]);
        let refused = check_proof_binds_sender(
            AccountSigner::Node(Some("node-a")),
            &[1u8; 32],
            &key,
            &node_key,
            &proof,
        )
        .unwrap_err()
        .to_string();
        assert!(refused.contains("tenzro validator keys"), "{refused}");
    }
}
