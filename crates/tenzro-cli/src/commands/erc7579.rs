//! ERC-7579 modular validator-module commands for the Tenzro CLI.
//!
//! Install / uninstall / query ERC-7579 validator modules on a smart account.
//! The three standard module precompiles ship with Tenzro:
//!
//! - `SocialRecoveryValidator`  at `0x101d` — N-of-M guardian quorum (composite Ed25519+ML-DSA-65)
//! - `SessionKeyValidator`      at `0x101e` — time/target/selector/value-scoped session keys
//! - `SpendingLimitValidator`   at `0x101f` — per-tx and rolling-window daily ceilings
//!
//! Per the on-chain `installModule` / `uninstallModule` / `isModuleInstalled`
//! ABI (selectors byte-identical to Safe / Biconomy Nexus / ZeroDev Kernel /
//! Rhinestone), this CLI builds standard calldata and dispatches it via
//! `tenzro_signAndSendTransaction` — there is no separate `tenzro_*7579*` RPC
//! namespace, the validator modules are an on-chain control surface.
//!
//! Subcommands:
//!
//! - `tenzro erc7579 install   --account 0x.. --type-id 1 --module 0x101d --init-data 0x..`
//! - `tenzro erc7579 uninstall --account 0x.. --type-id 1 --module 0x101d --deinit-data 0x..`
//! - `tenzro erc7579 is-installed --account 0x.. --type-id 1 --module 0x101d`

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use crate::output;

/// ERC-7579 standard selectors (byte-identical to Safe / Nexus / Kernel / Rhinestone).
const SELECTOR_INSTALL_MODULE: [u8; 4] = [0x95, 0x17, 0xe2, 0x9f];
const SELECTOR_UNINSTALL_MODULE: [u8; 4] = [0xa7, 0x17, 0x63, 0xa8];
const SELECTOR_IS_MODULE_INSTALLED: [u8; 4] = [0x11, 0x2d, 0x3a, 0x7d];

/// ERC-7579 modular validator-module commands
#[derive(Debug, Subcommand)]
pub enum Erc7579Command {
    /// installModule(typeId, module, initData) — dispatched via signAndSendTransaction
    Install(Erc7579InstallCmd),
    /// uninstallModule(typeId, module, deinitData) — dispatched via signAndSendTransaction
    Uninstall(Erc7579UninstallCmd),
    /// isModuleInstalled(typeId, module, context) — eth_call (no transaction)
    IsInstalled(Erc7579IsInstalledCmd),
}

impl Erc7579Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Install(cmd) => cmd.execute().await,
            Self::Uninstall(cmd) => cmd.execute().await,
            Self::IsInstalled(cmd) => cmd.execute().await,
        }
    }
}

/// Decode 0x-prefixed (or bare) hex into bytes.
fn parse_hex(s: &str, label: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim().trim_start_matches("0x");
    hex::decode(trimmed).with_context(|| format!("decode hex {label}"))
}

/// Decode a 20-byte EVM address.
fn parse_address(s: &str, label: &str) -> Result<[u8; 20]> {
    let bytes = parse_hex(s, label)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be exactly 20 bytes"))
}

/// ABI-encode `installModule(uint256 typeId, address module, bytes initData)`.
fn encode_install(type_id: u64, module: [u8; 20], init_data: &[u8]) -> Vec<u8> {
    encode_three_arg(SELECTOR_INSTALL_MODULE, type_id, module, init_data)
}

/// ABI-encode `uninstallModule(uint256 typeId, address module, bytes deinitData)`.
fn encode_uninstall(type_id: u64, module: [u8; 20], deinit_data: &[u8]) -> Vec<u8> {
    encode_three_arg(SELECTOR_UNINSTALL_MODULE, type_id, module, deinit_data)
}

/// ABI-encode `isModuleInstalled(uint256 typeId, address module, bytes context)`.
fn encode_is_installed(type_id: u64, module: [u8; 20], context: &[u8]) -> Vec<u8> {
    encode_three_arg(SELECTOR_IS_MODULE_INSTALLED, type_id, module, context)
}

/// Shared ABI encoder for `(uint256, address, bytes)` — used by all three
/// ERC-7579 entry points. Bytes is dynamic, so its offset is `0x60` (3
/// head words: uint256 + address-padded + offset).
fn encode_three_arg(
    selector: [u8; 4],
    type_id: u64,
    module: [u8; 20],
    dyn_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 3 + 32 + dyn_bytes.len() + 32);
    out.extend_from_slice(&selector);

    // arg0: uint256 typeId (right-aligned)
    let mut type_id_word = [0u8; 32];
    type_id_word[24..].copy_from_slice(&type_id.to_be_bytes());
    out.extend_from_slice(&type_id_word);

    // arg1: address module (left-padded to 32)
    let mut addr_word = [0u8; 32];
    addr_word[12..].copy_from_slice(&module);
    out.extend_from_slice(&addr_word);

    // arg2: bytes offset (after 3 head words = 0x60)
    let mut offset_word = [0u8; 32];
    offset_word[24..].copy_from_slice(&(0x60u64).to_be_bytes());
    out.extend_from_slice(&offset_word);

    // dynamic bytes length (32 bytes)
    let mut len_word = [0u8; 32];
    len_word[24..].copy_from_slice(&(dyn_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(&len_word);

    // dynamic bytes payload (right-padded to 32 if non-empty)
    out.extend_from_slice(dyn_bytes);
    let pad = (32 - (dyn_bytes.len() % 32)) % 32;
    out.extend(std::iter::repeat(0u8).take(pad));

    out
}

#[derive(Debug, Parser)]
pub struct Erc7579InstallCmd {
    /// SmartAccount address (target of the installModule call)
    #[arg(long)]
    account: String,

    /// Module type id (ERC-7579 §3.1 — 1 = validator)
    #[arg(long, default_value_t = 1u64)]
    type_id: u64,

    /// Module precompile address (e.g. 0x101d for SocialRecoveryValidator)
    #[arg(long)]
    module: String,

    /// Opaque module init data (hex)
    #[arg(long, default_value = "0x")]
    init_data: String,

    /// Signing account (derives `from` for signAndSendTransaction)
    #[arg(long)]
    from: String,

    /// Gas limit override
    #[arg(long, default_value_t = 250_000u64)]
    gas_limit: u64,

    /// Gas price override (wei)
    #[arg(long, default_value_t = 1_000_000_000u64)]
    gas_price: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Erc7579InstallCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("ERC-7579 — installModule");

        let module = parse_address(&self.module, "module")?;
        let init = parse_hex(&self.init_data, "init_data")?;
        let calldata = encode_install(self.type_id, module, &init);

        let rpc = RpcClient::new(&self.rpc);
        let tx = serde_json::json!({
            "from": self.from,
            "to": self.account,
            "value": "0",
            "gas_limit": self.gas_limit,
            "gas_price": self.gas_price,
            "data": format!("0x{}", hex::encode(&calldata)),
        });
        let tx_hash: String = rpc.call("tenzro_signAndSendTransaction", tx).await?;
        output::print_success("Submitted");
        output::print_field("tx_hash", &tx_hash);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct Erc7579UninstallCmd {
    /// SmartAccount address
    #[arg(long)]
    account: String,

    /// Module type id
    #[arg(long, default_value_t = 1u64)]
    type_id: u64,

    /// Module precompile address
    #[arg(long)]
    module: String,

    /// Opaque module deinit data (hex)
    #[arg(long, default_value = "0x")]
    deinit_data: String,

    /// Signing account
    #[arg(long)]
    from: String,

    /// Gas limit override
    #[arg(long, default_value_t = 150_000u64)]
    gas_limit: u64,

    /// Gas price override (wei)
    #[arg(long, default_value_t = 1_000_000_000u64)]
    gas_price: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Erc7579UninstallCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("ERC-7579 — uninstallModule");

        let module = parse_address(&self.module, "module")?;
        let deinit = parse_hex(&self.deinit_data, "deinit_data")?;
        let calldata = encode_uninstall(self.type_id, module, &deinit);

        let rpc = RpcClient::new(&self.rpc);
        let tx = serde_json::json!({
            "from": self.from,
            "to": self.account,
            "value": "0",
            "gas_limit": self.gas_limit,
            "gas_price": self.gas_price,
            "data": format!("0x{}", hex::encode(&calldata)),
        });
        let tx_hash: String = rpc.call("tenzro_signAndSendTransaction", tx).await?;
        output::print_success("Submitted");
        output::print_field("tx_hash", &tx_hash);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct Erc7579IsInstalledCmd {
    /// SmartAccount address
    #[arg(long)]
    account: String,

    /// Module type id
    #[arg(long, default_value_t = 1u64)]
    type_id: u64,

    /// Module precompile address
    #[arg(long)]
    module: String,

    /// Opaque context bytes for the query (hex)
    #[arg(long, default_value = "0x")]
    context: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Erc7579IsInstalledCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("ERC-7579 — isModuleInstalled");

        let module = parse_address(&self.module, "module")?;
        let ctx = parse_hex(&self.context, "context")?;
        let calldata = encode_is_installed(self.type_id, module, &ctx);

        let rpc = RpcClient::new(&self.rpc);
        let call = serde_json::json!({
            "to": self.account,
            "data": format!("0x{}", hex::encode(&calldata)),
        });
        let result_hex: String = rpc.call("eth_call", serde_json::json!([call, "latest"])).await?;
        // bool return: last byte non-zero → true
        let installed = result_hex
            .trim_start_matches("0x")
            .chars()
            .last()
            .map(|c| c != '0')
            .unwrap_or(false);
        output::print_field("installed", &installed.to_string());
        output::print_field("raw", &result_hex);
        Ok(())
    }
}
