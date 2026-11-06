//! Two-step submission for RPCs whose envelope binds the whole request.
//!
//! `tenzro_registerMachineIdentity` requires a DID envelope whose `params_hash`
//! covers every parameter ([`tenzro_identity::envelope::request_binding`]). The
//! request is only known once the CLI has assembled it, so the envelope cannot
//! be made in advance. Instead:
//!
//! 1. `--request-out <file>` prepares the request, writes it to `<file>`, and
//!    prints the method and `params_hash` to sign with the owner's key;
//! 2. `--request-in <file> --did-envelope <hex>` sends exactly that request
//!    with the envelope attached.

use anyhow::{Context, Result};
use std::path::Path;

use crate::output;
use crate::rpc::RpcClient;

/// Write the prepared request for signing and print what to sign.
pub(crate) fn write_for_signing(
    method: &str,
    params: &serde_json::Value,
    out: &Path,
) -> Result<()> {
    let json = serde_json::to_string_pretty(params)?;
    std::fs::write(out, json).with_context(|| format!("writing {}", out.display()))?;
    let binding = tenzro_identity::envelope::request_binding(params);
    let hash = tenzro_identity::envelope::params_hash(&binding);
    output::print_success("Request prepared for signing");
    output::print_field("Request file", &out.display().to_string());
    output::print_field("Method", method);
    output::print_field("params_hash", &hex::encode(hash));
    println!(
        "Sign a DID envelope for this method and params_hash, then run the same command \
         with --request-in {} --did-envelope <hex>.",
        out.display()
    );
    Ok(())
}

/// Load a request written by [`write_for_signing`], attach `did_envelope`, and
/// send it.
pub(crate) async fn submit(
    rpc: &RpcClient,
    method: &str,
    request: &Path,
    did_envelope: &str,
) -> Result<serde_json::Value> {
    let raw = std::fs::read_to_string(request)
        .with_context(|| format!("reading {}", request.display()))?;
    let mut params: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", request.display()))?;
    params["did_envelope"] = serde_json::json!(did_envelope);
    rpc.call(method, params).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_printed_hash_is_the_hash_the_node_checks() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("req.json");
        let params =
            serde_json::json!({"machine_id": "m1", "owner_did": "did:key:z1", "attestation": {}});
        write_for_signing("tenzro_registerMachineIdentity", &params, &out).unwrap();
        let back: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(
            tenzro_identity::envelope::request_binding(&back),
            tenzro_identity::envelope::request_binding(&params)
        );
    }
}
