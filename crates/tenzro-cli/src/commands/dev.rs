//! `tenzro dev`: a local developer chain.
//!
//! One validator on this machine, with one-minute epochs, quarter-second
//! rounds and the full RPC, and the developer's accounts funded at genesis.
//! Every key is held by this machine's hardware: the validator and node
//! identity in the node's TPM or Secure Enclave keys, the funded client
//! account in the CLI's own hardware key. No key is generated in software or
//! written to a file, so a machine with neither a TPM nor a Secure Enclave is
//! refused before anything starts.

use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::Parser;

use crate::output;

/// Why `tenzro dev` refuses on a machine without a hardware key store.
pub const NEEDS_HARDWARE: &str = "tenzro dev keeps every key in this machine's hardware key store \
     (a TPM 2.0 on Linux or Windows, the Secure Enclave on macOS), and none was found. \
     Keys are never held in software or in files. Use a machine with a TPM 2.0 or a Mac, \
     or use the public network with a passkey: tenzro setup --path network";

/// Start a local single-validator chain for development
#[derive(Debug, Parser)]
pub struct DevCmd {
    /// Data directory of the developer chain. A fresh directory starts a new
    /// chain; an existing one resumes it.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// RPC listen address
    #[arg(long, default_value = "127.0.0.1:8545")]
    rpc_addr: String,
    /// Hardware key namespace of the client account funded at genesis (the
    /// account the other commands sign with by default)
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// Another account to fund at genesis, 32-byte hex: an account whose key
    /// is a passkey or another machine's hardware. Repeatable.
    #[arg(long = "fund", value_name = "ADDRESS")]
    fund: Vec<String>,
}

impl DevCmd {
    /// The `tenzro-node` arguments for this chain, funding `client` and every
    /// `--fund` account.
    pub fn node_args(&self, client: &str, data_dir: &std::path::Path) -> Vec<String> {
        let mut args = vec![
            "--dev".to_string(),
            "--roles".to_string(),
            "validator".to_string(),
            "--boot-nodes".to_string(),
            String::new(),
            "--rpc-addr".to_string(),
            self.rpc_addr.clone(),
            "--data-dir".to_string(),
            data_dir.display().to_string(),
            "--fund".to_string(),
            client.to_string(),
        ];
        for account in &self.fund {
            args.push("--fund".to_string());
            args.push(account.clone());
        }
        args
    }

    pub async fn execute(&self) -> Result<()> {
        if tenzro_device_key::signer::platform_backend().is_none() {
            return Err(anyhow!(NEEDS_HARDWARE));
        }
        for account in &self.fund {
            crate::keystore::address32(account)?;
        }
        let (client, _) = crate::keystore::client_account(&self.key_namespace)?;
        let data_dir = self
            .data_dir
            .as_ref()
            .map(tenzro_types::paths::expand_tilde)
            .unwrap_or_else(|| tenzro_types::paths::default_data_dir().join("dev"));

        output::print_header("Tenzro developer chain");
        output::print_field("RPC", &format!("http://{}", self.rpc_addr));
        output::print_field("Chain id", "1337");
        output::print_field("Data directory", &data_dir.display().to_string());
        output::print_field("Funded client account", &client);
        for account in &self.fund {
            output::print_field("Funded account", account);
        }
        output::print_info("Keys stay in this machine's hardware. Press Ctrl+C to stop.");

        // The node installed beside this program first (an unpacked archive, or
        // through the installer's links), then PATH.
        let node = crate::commands::setup::locate_node_binary().ok_or_else(|| {
            anyhow!(
                "tenzro-node was not found next to tenzro or on PATH. \
                 Install the Tenzro package for this machine; it puts both programs together."
            )
        })?;
        let status = tokio::process::Command::new(node)
            .args(self.node_args(&client, &data_dir))
            .status()
            .await
            .map_err(|e| anyhow!("starting tenzro-node: {e}"))?;
        if !status.success() {
            return Err(anyhow!("tenzro-node exited with {status}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_runs_a_local_dev_chain_funding_the_client_and_each_listed_account() {
        let cmd = DevCmd::parse_from(["dev", "--fund", "0xab", "--fund", "0xcd"]);
        let args = cmd.node_args("0x11", std::path::Path::new("/d"));
        assert_eq!(
            &args[..5],
            ["--dev", "--roles", "validator", "--boot-nodes", ""]
        );
        let funded: Vec<_> = args
            .windows(2)
            .filter(|w| w[0] == "--fund")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(funded, ["0x11", "0xab", "0xcd"]);
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--rpc-addr" && w[1] == "127.0.0.1:8545")
        );
    }

    /// On a machine with no TPM or Secure Enclave the command refuses with
    /// the reason, before it starts anything.
    #[tokio::test]
    async fn without_a_hardware_key_store_it_refuses_and_says_why() {
        if tenzro_device_key::signer::platform_backend().is_some() {
            return;
        }
        let err = DevCmd::parse_from(["dev"])
            .execute()
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(err, NEEDS_HARDWARE);
    }
}
