//! Validator commands for the Tenzro CLI (Dynamic Validator Set, task #413).
//!
//! Permissionless validator join/exit with mandatory hybrid PQ keying. Writes
//! (`RegisterValidator`, `ExitValidator`, `UpdateValidatorMetadata`) are
//! consensus-mediated typed transactions submitted via
//! `tenzro_signAndSendTransaction`. Reads (`tenzro_getValidatorState`,
//! `tenzro_listValidators`, `tenzro_listActiveValidators`) hit the node's
//! in-process `ValidatorRegistry` cache.

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
    /// Rotate validator consensus + PQ + BLS keys via tenzro_rotateValidatorKey
    /// (signed by the *current* consensus key)
    RotateKeys(ValidatorRotateKeysCmd),
    /// Inspect a single validator entry by address (read-only)
    Get(ValidatorGetCmd),
    /// List validators (optionally filter by status) (read-only)
    List(ValidatorListCmd),
    /// List currently-Active validators (read-only)
    ListActive(ValidatorListActiveCmd),
}

impl ValidatorCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::Exit(cmd) => cmd.execute().await,
            Self::IncreaseStake(cmd) => cmd.execute().await,
            Self::UpdateMetadata(cmd) => cmd.execute().await,
            Self::RotateKeys(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::ListActive(cmd) => cmd.execute().await,
        }
    }
}

const DEFAULT_REGISTER_GAS: u64 = 200_000;
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
/// The `RegisterValidator` typed transaction stages the candidate under
/// `PendingActive`; the next epoch boundary admits it (subject to churn budget)
/// and the `EpochManager` activates it `ACTIVATION_EFFECTIVE_DELAY_BLOCKS` after
/// that boundary.
#[derive(Debug, Parser)]
pub struct ValidatorRegisterCmd {
    /// Stake-owning wallet address (hex; must match the signing key)
    #[arg(long)]
    from: String,

    /// 32-byte Ed25519 BFT consensus signing public key (hex; with or without 0x prefix)
    #[arg(long)]
    consensus_pubkey: String,

    /// 1952-byte ML-DSA-65 PQ verifying key (hex; FIPS 204)
    #[arg(long)]
    pq_pubkey: String,

    /// 48-byte BLS12-381 G1-compressed verifying key (hex; `min_pk` scheme).
    /// Used by HotStuff-2 to aggregate per-vote signatures into a single QC-level aggregate.
    #[arg(long)]
    bls_pubkey: String,

    /// Withdrawal address — rewards / unbonded principal settle here (hex; 32 bytes)
    #[arg(long)]
    withdrawal_address: String,

    /// Self-stake committed to the candidate, in wei (1 TNZO = 10^18 wei).
    /// Must be ≥ the registry's `min_self_stake` (default 10,000 TNZO).
    #[arg(long)]
    self_stake: u128,

    /// Optional ≤256-byte off-chain pointer (moniker / website / contact)
    #[arg(long, default_value = "")]
    metadata_uri: String,

    /// Sign locally with the self-custody hybrid key and submit a pre-signed
    /// transaction, instead of asking the node to sign. Required for
    /// permissionless / first-boot onboarding where no DPoP bearer exists.
    /// The stake-owning `from` is the local key's Ed25519 pubkey. The key
    /// password is read from TENZRO_KEYSTORE_PASSWORD, else prompted.
    #[arg(long)]
    self_custody: bool,

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
        let consensus_bytes: [u8; 32] = hex_to_fixed(&self.consensus_pubkey, "consensus_pubkey")?;
        let pq_bytes = hex_to_vec(&self.pq_pubkey, "pq_pubkey")?;
        if pq_bytes.len() != 1952 {
            return Err(anyhow!(
                "pq_pubkey must be 1952 bytes (ML-DSA-65 FIPS 204), got {}",
                pq_bytes.len()
            ));
        }
        let bls_bytes = hex_to_vec(&self.bls_pubkey, "bls_pubkey")?;
        if bls_bytes.len() != 48 {
            return Err(anyhow!(
                "bls_pubkey must be 48 bytes (BLS12-381 G1-compressed, min_pk), got {}",
                bls_bytes.len()
            ));
        }
        let withdrawal_bytes: [u8; 32] =
            hex_to_fixed(&self.withdrawal_address, "withdrawal_address")?;

        // Self-custody: sign locally and submit a pre-signed tx (no DPoP).
        if self.self_custody {
            return self
                .execute_self_custody(consensus_bytes, pq_bytes, bls_bytes, withdrawal_bytes)
                .await;
        }

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = crate::rpc::fetch_nonce_and_chain_id(&rpc, &self.from).await;
        spinner.set_message("Signing RegisterValidator transaction...");

        // The Address / Vec<u8> fields serde-derive to JSON arrays of numbers.
        let tx_type = serde_json::json!({
            "RegisterValidator": {
                "consensus_pubkey": consensus_bytes.to_vec(),
                "pq_pubkey": pq_bytes,
                "bls_pubkey": bls_bytes,
                "withdrawal_address": withdrawal_bytes,
                "self_stake": self.self_stake.to_string(),
                "metadata_uri": self.metadata_uri,
            }
        });

        let result: serde_json::Value = rpc
            .send_tx_clearing_fee_floor(
                "tenzro_signAndSendTransaction",
                serde_json::json!({
                    "from": self.from,
                    "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "value": 0u64,
                    "gas_limit": DEFAULT_REGISTER_GAS,
                    "gas_price": 1_000_000_000u64,
                    "nonce": nonce,
                    "chain_id": chain_id,
                    "tx_type": tx_type,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        output::print_success("RegisterValidator transaction submitted");
        println!();
        output::print_field("From", &self.from);
        output::print_field("Consensus pubkey", &self.consensus_pubkey);
        output::print_field("PQ pubkey (len)", &format!("{} bytes", pq_bytes.len()));
        output::print_field("Withdrawal address", &self.withdrawal_address);
        output::print_field("Self-stake (wei)", &self.self_stake.to_string());
        if !self.metadata_uri.is_empty() {
            output::print_field("Metadata URI", &self.metadata_uri);
        }
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        output::print_warning(
            "Candidate is staged under PendingActive. The next epoch boundary \
             admits it (subject to churn budget); activation is effective \
             ACTIVATION_EFFECTIVE_DELAY_BLOCKS after that boundary.",
        );
        Ok(())
    }

    /// Self-custody register: unlock the local hybrid key, build the
    /// RegisterValidator transaction, sign both legs locally, and submit it
    /// pre-signed via `eth_sendRawTransaction`. The node reconstructs the same
    /// typed transaction from the `tx_type` + `timestamp` fields, so its
    /// recomputed hash matches the local signature bit-for-bit. `from` is the
    /// local key's Ed25519 pubkey — the stake-owning account the VM debits.
    async fn execute_self_custody(
        &self,
        consensus_bytes: [u8; 32],
        pq_bytes: Vec<u8>,
        bls_bytes: Vec<u8>,
        withdrawal_bytes: [u8; 32],
    ) -> Result<()> {
        use crate::rpc::RpcClient;
        use tenzro_types::primitives::{Address, ChainId, Nonce};
        use tenzro_types::transaction::{Transaction, TransactionType};

        // Password: env for non-interactive (first-boot / automation), else prompt.
        let password = match std::env::var("TENZRO_KEYSTORE_PASSWORD") {
            Ok(p) if !p.is_empty() => p,
            _ => dialoguer::Password::new()
                .with_prompt("Self-custody key password")
                .interact()?,
        };
        let signer = crate::keystore::unlock_local_key(&password)?;
        let from_hex = signer.from_address_hex();
        let from_address = Address::from_bytes(signer.ed25519_public_key())
            .ok_or_else(|| anyhow!("local Ed25519 pubkey is not a valid 32-byte address"))?;
        let to_address = Address::from_bytes(&[0u8; 32])
            .ok_or_else(|| anyhow!("zero address invalid"))?;

        let rpc = RpcClient::new(&self.rpc);
        let (nonce, chain_id) = crate::rpc::fetch_nonce_and_chain_id(&rpc, &from_hex).await;

        let tx_type = TransactionType::RegisterValidator {
            consensus_pubkey: consensus_bytes.to_vec(),
            pq_pubkey: pq_bytes,
            bls_pubkey: bls_bytes,
            withdrawal_address: Address::from_bytes(&withdrawal_bytes)
                .ok_or_else(|| anyhow!("withdrawal address invalid"))?,
            self_stake: self.self_stake,
            metadata_uri: self.metadata_uri.clone(),
        };

        // Gas price must already clear the open-lane fee floor (4 gwei): a
        // pre-signed tx cannot be re-priced server-side without breaking the
        // signature, so we sign over a price above the floor.
        let gas_price: u64 = 5_000_000_000;
        let tx = Transaction::new(
            ChainId::new(chain_id),
            from_address,
            to_address,
            Nonce::new(nonce),
            tx_type.clone(),
            DEFAULT_REGISTER_GAS,
            gas_price,
            signer.ml_dsa_verifying_key().to_vec(),
        );
        let hash = tx.hash();
        let (ed_sig, ml_dsa_sig) = signer.sign_hybrid(hash.as_bytes())?;

        let result: serde_json::Value = rpc
            .call(
                "eth_sendRawTransaction",
                serde_json::json!({
                    "from": from_hex,
                    "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "value": "0",
                    "gas_limit": DEFAULT_REGISTER_GAS,
                    "gas_price": gas_price,
                    "nonce": nonce,
                    "chain_id": chain_id,
                    "timestamp": tx.timestamp.0,
                    "tx_type": serde_json::to_value(&tx_type)?,
                    "public_key": hex::encode(signer.ed25519_public_key()),
                    "signature": hex::encode(&ed_sig),
                    "pq_public_key": hex::encode(signer.ml_dsa_verifying_key()),
                    "pq_signature": hex::encode(&ml_dsa_sig),
                }),
            )
            .await?;

        output::print_success("RegisterValidator (self-custody) submitted");
        println!();
        output::print_field("From (self-custody)", &from_hex);
        output::print_field("Self-stake (wei)", &self.self_stake.to_string());
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        output::print_warning(
            "Candidate is staged under PendingActive. The next epoch boundary \
             admits it (subject to churn budget + min self-stake).",
        );
        Ok(())
    }
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
    /// Validator stake-owning wallet address (hex; must match the signing key)
    #[arg(long)]
    from: String,

    /// Additional self-stake in wei (1 TNZO = 10^18). Only ever adds —
    /// reducing a stake is unbonding, which has its own path and delay.
    #[arg(long)]
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

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = crate::rpc::fetch_nonce_and_chain_id(&rpc, &self.from).await;
        spinner.set_message("Signing IncreaseValidatorStake transaction...");

        let tx_type = serde_json::json!({
            "IncreaseValidatorStake": {
                "additional": self.additional.to_string(),
            }
        });

        let result: serde_json::Value = rpc
            .send_tx_clearing_fee_floor(
                "tenzro_signAndSendTransaction",
                serde_json::json!({
                    "from": self.from,
                    "to": self.from,
                    "value": 0u64,
                    "gas_limit": 100_000u64,
                    "gas_price": 1_000_000_000u64,
                    "nonce": nonce,
                    "chain_id": chain_id,
                    "tx_type": tx_type,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        output::print_success("IncreaseValidatorStake transaction submitted");
        println!();
        output::print_field("From", &self.from);
        output::print_field(
            "Additional",
            &format!("{} TNZO", self.additional / 1_000_000_000_000_000_000),
        );
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        Ok(())
    }
}

/// Voluntarily exit the validator set.
#[derive(Debug, Parser)]
pub struct ValidatorExitCmd {
    /// Validator stake-owning wallet address (hex; must match the signing key)
    #[arg(long)]
    from: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorExitCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Exit Validator");

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = crate::rpc::fetch_nonce_and_chain_id(&rpc, &self.from).await;
        spinner.set_message("Signing ExitValidator transaction...");

        // ExitValidator is a unit variant — `data` field omitted entirely.
        // Unit variant — externally-tagged serde renders it as a bare string.
        let tx_type = serde_json::json!("ExitValidator");

        let result: serde_json::Value = rpc
            .send_tx_clearing_fee_floor(
                "tenzro_signAndSendTransaction",
                serde_json::json!({
                    "from": self.from,
                    "to": self.from,
                    "value": 0u64,
                    "gas_limit": DEFAULT_EXIT_GAS,
                    "gas_price": 1_000_000_000u64,
                    "nonce": nonce,
                    "chain_id": chain_id,
                    "tx_type": tx_type,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        output::print_success("ExitValidator transaction submitted");
        println!();
        output::print_field("From", &self.from);
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        output::print_warning(
            "Validator transitions to PendingExit. Removal is effective \
             ACTIVATION_EFFECTIVE_DELAY_BLOCKS after the next epoch boundary. \
             Re-registration is blocked for `reentry_cooldown_epochs` (default 4) \
             following voluntary exit.",
        );
        Ok(())
    }
}

/// Update validator metadata or TEE attestation commitment.
#[derive(Debug, Parser)]
pub struct ValidatorUpdateMetadataCmd {
    /// Validator stake-owning wallet address (hex; must match the signing key)
    #[arg(long)]
    from: String,

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

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = crate::rpc::fetch_nonce_and_chain_id(&rpc, &self.from).await;
        spinner.set_message("Signing UpdateValidatorMetadata transaction...");

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

        let result: serde_json::Value = rpc
            .send_tx_clearing_fee_floor(
                "tenzro_signAndSendTransaction",
                serde_json::json!({
                    "from": self.from,
                    "to": self.from,
                    "value": 0u64,
                    "gas_limit": DEFAULT_UPDATE_METADATA_GAS,
                    "gas_price": 1_000_000_000u64,
                    "nonce": nonce,
                    "chain_id": chain_id,
                    "tx_type": tx_type,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        output::print_success("UpdateValidatorMetadata transaction submitted");
        println!();
        output::print_field("From", &self.from);
        if let Some(uri) = &self.metadata_uri {
            output::print_field("Metadata URI", uri);
        }
        if let Some(h) = &self.tee_attestation_hash {
            output::print_field("TEE attestation hash", h);
        }
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        Ok(())
    }
}

/// Rotate validator consensus + PQ + BLS keys.
///
/// This calls `tenzro_rotateValidatorKey` against the configured RPC. The
/// signature is produced offline by the operator with the *current*
/// consensus key over the canonical preimage; this command only marshals
/// the request. See `tools/deploy/rotate-validator-key.sh` for the
/// fan-out script that broadcasts the rotation to every active validator
/// (required until the consensus-mediated `RotateValidatorKey` typed
/// transaction lands).
#[derive(Debug, Parser)]
pub struct ValidatorRotateKeysCmd {
    /// Validator operator address (32-byte hex)
    #[arg(long)]
    address: String,

    /// New Ed25519 consensus pubkey (32-byte hex)
    #[arg(long)]
    new_consensus_pubkey: String,

    /// New ML-DSA-65 verifying key (1952-byte hex)
    #[arg(long)]
    new_pq_pubkey: String,

    /// New BLS12-381 G1 (min_pk) verifying key (48-byte hex)
    #[arg(long)]
    new_bls_pubkey: String,

    /// Monotonic rotation nonce (must strictly increase per-address)
    #[arg(long)]
    nonce: u64,

    /// Ed25519 signature over the canonical preimage (64-byte hex)
    #[arg(long)]
    signature: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorRotateKeysCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Rotate Validator Keys");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Submitting tenzro_rotateValidatorKey ...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_rotateValidatorKey",
                serde_json::json!({
                    "address": self.address,
                    "new_consensus_pubkey": self.new_consensus_pubkey,
                    "new_pq_pubkey": self.new_pq_pubkey,
                    "new_bls_pubkey": self.new_bls_pubkey,
                    "nonce": self.nonce,
                    "signature": self.signature,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if status == "pending_epoch_activation" {
            output::print_success("Rotation accepted — pending epoch activation");
        } else {
            return Err(anyhow!("Rotation returned unexpected status: {}", status));
        }
        output::print_field("Address", &self.address);
        output::print_field(
            "New consensus pubkey",
            result
                .get("new_consensus_pubkey")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
        );
        output::print_field("Nonce", &self.nonce.to_string());
        eprintln!(
            "\nNote: this rotation has been recorded on the receiving node only.\n\
             Until the consensus-mediated RotateValidatorKey transaction lands,\n\
             operators must broadcast the same rotation to every active validator —\n\
             see tools/deploy/rotate-validator-key.sh for the fan-out script."
        );
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
