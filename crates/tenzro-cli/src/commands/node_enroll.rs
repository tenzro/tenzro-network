//! `tenzro node enroll` — authorise a TPM-less machine with a passkey.
//!
//! Identity is rooted in a TPM when authority is delegated to the machine and
//! in a passkey when it is delegated to a human. A machine with no TPM
//! therefore cannot start until a human has authorised the key it generated,
//! and this is the command that collects that authorisation.
//!
//! It is two steps because a WebAuthn ceremony needs a browser and an actual
//! person, neither of which a CLI can supply:
//!
//! 1. `begin` mints the node key (once) and prints the challenge the passkey
//!    must sign.
//! 2. `complete` takes the assertion back, checks it authorises *this* node,
//!    and installs it.
//!
//! The challenge commits to the node's public key, so the assertion cannot be
//! moved onto a different key afterwards — which is what makes this a
//! delegation rather than a bearer token.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use tenzro_network::node_delegation::{MAX_DELEGATION_SECS, NodeDelegation};

#[derive(Debug, Subcommand)]
pub enum NodeEnrollCommand {
    /// Mint this node's key and print the challenge a passkey must sign
    Begin(EnrollBeginCmd),
    /// Install a collected passkey assertion as this node's authorisation
    Complete(EnrollCompleteCmd),
    /// Show the current delegation and when it expires
    Status(EnrollStatusCmd),
}

impl NodeEnrollCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Begin(cmd) => cmd.execute(),
            Self::Complete(cmd) => cmd.execute(),
            Self::Status(cmd) => cmd.execute(),
        }
    }
}

/// What `begin` writes and `complete` reads back.
///
/// Persisted rather than merely printed so the two halves of the ceremony
/// cannot drift: `complete` recomputes nothing the operator could mistype.
#[derive(Debug, Serialize, Deserialize)]
struct EnrollmentRequest {
    /// Ed25519 public key of the node being authorised, hex.
    node_pubkey_hex: String,
    /// The base64url challenge the passkey must sign.
    challenge_b64url: String,
    /// The data-directory path this delegation is scoped to.
    scope: String,
    /// Unix seconds after which the resulting delegation is void.
    not_after: i64,
    /// Unix seconds this request was created.
    issued_at: i64,
}

/// The shape `complete` expects back from the browser ceremony.
///
/// Field names follow the WebAuthn `AuthenticatorAssertionResponse` so a page
/// can hand back what `navigator.credentials.get()` gave it, base64url-encoded,
/// without inventing a mapping.
#[derive(Debug, Deserialize)]
struct AssertionResponse {
    /// Credential ID, base64url.
    credential_id: String,
    /// The passkey's P-256 public key as uncompressed `x || y`, base64url.
    public_key_xy: String,
    /// `authenticatorData`, base64url.
    authenticator_data: String,
    /// `clientDataJSON`, base64url.
    client_data_json: String,
    /// The authenticator's signature, base64url.
    signature: String,
    /// Origin or RP ID the ceremony ran under.
    relying_party: String,
    /// Whether `relying_party` is a registrable RP ID rather than an origin.
    #[serde(default)]
    relying_party_is_rp_id: bool,
}

const REQUEST_FILE: &str = "passkey_enrollment_request.json";

fn now_unix() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the epoch")?
        .as_secs() as i64)
}

fn b64(input: &str, field: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input.trim()))
        .with_context(|| format!("`{field}` is not valid base64"))
}

/// Mint this node's key and print the challenge a passkey must sign.
#[derive(Debug, Parser)]
pub struct EnrollBeginCmd {
    /// Node data directory. The delegation is scoped to this exact path.
    #[arg(long)]
    data_dir: PathBuf,

    /// How long the authorisation should last, in days.
    #[arg(long, default_value_t = 30)]
    days: u32,
}

impl EnrollBeginCmd {
    fn execute(&self) -> Result<()> {
        let requested = i64::from(self.days) * 24 * 60 * 60;
        if requested > MAX_DELEGATION_SECS {
            bail!(
                "a delegation may run at most {} days; asked for {}. \
                 The node key has no hardware protection, so the authorisation over it \
                 is deliberately short-lived — re-enrol rather than extending it.",
                MAX_DELEGATION_SECS / 86_400,
                self.days
            );
        }

        let node_pubkey = tenzro_network::service::mint_delegated_node_key(&self.data_dir)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let issued_at = now_unix()?;
        let not_after = issued_at + requested;
        let scope = self.data_dir.display().to_string();
        let challenge = tenzro_network::node_delegation::delegation_challenge_b64url(
            &node_pubkey,
            &scope,
            not_after,
        );

        let request = EnrollmentRequest {
            node_pubkey_hex: hex::encode(node_pubkey),
            challenge_b64url: challenge.clone(),
            scope: scope.clone(),
            not_after,
            issued_at,
        };
        let path = self.data_dir.join(REQUEST_FILE);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&request).context("serialising the enrolment request")?,
        )
        .with_context(|| format!("writing {}", path.display()))?;

        println!("Node key:  0x{}", hex::encode(node_pubkey));
        println!("Scope:     {scope}");
        println!("Expires:   {not_after} (unix), in {} days", self.days);
        println!();
        println!("Have a passkey sign this challenge, with user verification:");
        println!();
        println!("  {challenge}");
        println!();
        println!("The challenge commits to the node key above, so the signature cannot");
        println!("be moved onto another key. Save the ceremony's response, then run:");
        println!();
        println!(
            "  tenzro node enroll complete --data-dir {} --assertion <response.json>",
            self.data_dir.display()
        );
        Ok(())
    }
}

/// Install a collected passkey assertion as this node's authorisation.
#[derive(Debug, Parser)]
pub struct EnrollCompleteCmd {
    /// Node data directory — must match the one passed to `begin`.
    #[arg(long)]
    data_dir: PathBuf,

    /// JSON file holding the WebAuthn assertion from the ceremony.
    #[arg(long)]
    assertion: PathBuf,
}

impl EnrollCompleteCmd {
    fn execute(&self) -> Result<()> {
        let request_path = self.data_dir.join(REQUEST_FILE);
        let request: EnrollmentRequest = serde_json::from_slice(
            &std::fs::read(&request_path)
                .with_context(|| format!("reading {}", request_path.display()))?,
        )
        .with_context(|| format!("parsing {}", request_path.display()))?;

        let response: AssertionResponse = serde_json::from_slice(
            &std::fs::read(&self.assertion)
                .with_context(|| format!("reading {}", self.assertion.display()))?,
        )
        .with_context(|| format!("parsing {}", self.assertion.display()))?;

        let node_pubkey = hex::decode(&request.node_pubkey_hex)
            .context("the saved enrolment request has a malformed node key")?;

        let delegation = NodeDelegation {
            node_pubkey,
            credential_id: b64(&response.credential_id, "credential_id")?,
            passkey_pubkey_xy: b64(&response.public_key_xy, "public_key_xy")?,
            not_after: request.not_after,
            issued_at: request.issued_at,
            scope: request.scope,
            relying_party: response.relying_party,
            relying_party_is_rp_id: response.relying_party_is_rp_id,
            authenticator_data: b64(&response.authenticator_data, "authenticator_data")?,
            client_data_json: b64(&response.client_data_json, "client_data_json")?,
            signature: b64(&response.signature, "signature")?,
        };

        // Verified here, while the human is still present. A delegation that
        // only fails at the next restart fails at the worst possible moment.
        tenzro_network::service::install_delegation(&self.data_dir, &delegation)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        // The request has served its purpose; leaving it invites a second
        // `complete` against a stale challenge.
        let _ = std::fs::remove_file(&request_path);

        println!("Enrolled. This node is authorised until {}.", delegation.not_after);
        println!("Re-run `tenzro node enroll begin` before then, or it will refuse to start.");
        Ok(())
    }
}

/// Show the current delegation and when it expires.
#[derive(Debug, Parser)]
pub struct EnrollStatusCmd {
    /// Node data directory.
    #[arg(long)]
    data_dir: PathBuf,
}

impl EnrollStatusCmd {
    fn execute(&self) -> Result<()> {
        let path = self.data_dir.join("passkey_delegation.json");
        let Ok(raw) = std::fs::read(&path) else {
            println!("No passkey delegation at {}.", path.display());
            println!("If this machine has no TPM, it will refuse to start until enrolled.");
            return Ok(());
        };
        let delegation: NodeDelegation =
            serde_json::from_slice(&raw).with_context(|| format!("parsing {}", path.display()))?;

        let now = now_unix()?;
        let remaining = delegation.not_after - now;
        println!("Scope:   {}", delegation.scope);
        println!("Expires: {} (unix)", delegation.not_after);
        if remaining <= 0 {
            println!("Status:  EXPIRED — this node will refuse to start. Re-enrol.");
        } else {
            println!("Status:  valid for {} more days", remaining / 86_400);
        }

        // Report whether it actually authorises the key on disk, not merely
        // that a file is present and unexpired.
        match tenzro_network::service::delegated_node_pubkey(&self.data_dir) {
            Ok(public) => {
                let scope = self.data_dir.display().to_string();
                match delegation.verify(&public, &scope, now) {
                    Ok(()) => println!("Check:   authorises the node key on disk"),
                    Err(e) => println!("Check:   DOES NOT authorise this node — {e}"),
                }
            }
            Err(e) => println!("Check:   cannot read the node key — {e}"),
        }
        Ok(())
    }
}
