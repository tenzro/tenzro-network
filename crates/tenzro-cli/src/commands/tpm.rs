//! `tenzro tpm ...`: the node's TPM commands under the name people type.
//!
//! The commands that create, serve and delegate a machine's keys belong to
//! `tenzro-node` (`tpm provision`, `tpm serve`, `tpm key-holder`,
//! `tpm grant-request`, `tpm grant-install`, `tpm remote-check`). This hands
//! the arguments to it unchanged, so the runbooks and the setup screens use
//! one spelling and one set of options.

use anyhow::{Result, anyhow};
use clap::Parser;

/// TPM commands of the node: provision, serve, key-holder, grant-request, grant-install, remote-check
#[derive(Debug, Parser)]
pub struct TpmCmd {
    /// The arguments of `tenzro-node tpm`, for example: provision
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    args: Vec<String>,
}

impl TpmCmd {
    pub async fn execute(self) -> Result<()> {
        let node = crate::commands::setup::locate_node_binary().ok_or_else(|| {
            anyhow!("tenzro-node was not found next to tenzro or on PATH; install the Tenzro package for this machine")
        })?;
        let status = tokio::process::Command::new(node)
            .arg("tpm")
            .args(&self.args)
            .status()
            .await
            .map_err(|e| anyhow!("starting tenzro-node: {e}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}
