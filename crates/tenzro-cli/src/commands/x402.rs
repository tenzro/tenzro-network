//! x402 (HTTP-402 micropayment protocol) commands.
//!
//! Tenzro is an x402 facilitator: clients send a one-shot payment header
//! against an `HTTP 402 Payment Required` challenge, and the node verifies
//! and (optionally) settles on-chain via the configured scheme.
//!
//! These commands are thin wrappers around the x402 RPCs:
//!
//! - `tenzro_listX402Schemes` — enumerate scheme adapters (e.g.
//!   `tenzro-hybrid`, `permit2`, `upto`, `batch-settlement`) registered
//!   with the facilitator. The response also carries `facilitator_mode`:
//!   `self-hosted` when the operator verifies + settles EIP-3009 / Permit2
//!   against their own EVM relayer, or `cdp` when those lanes defer to the
//!   remote Coinbase facilitator.
//! - `tenzro_payX402` — submit a payment payload against a challenge.
//! - `tenzro_x402RegisterResource` / `tenzro_x402DiscoverResources` /
//!   `tenzro_x402DeregisterResource` — the Bazaar discovery surface, so
//!   sellers publish paid resources and buyers browse them.
//!
//! For the higher-level `tenzro payment pay --protocol x402` flow, see
//! `tenzro payment`. This module exists so users who think in protocol
//! terms ("I want to pay an x402 challenge") can drive the CLI by name.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// x402 (HTTP-402) operations.
#[derive(Debug, Subcommand)]
pub enum X402Command {
    /// List the x402 scheme adapters this facilitator can verify.
    ListSchemes(X402ListSchemesCmd),
    /// Submit an x402 payment payload against a challenge.
    Pay(X402PayCmd),
    /// Publish a paid resource listing to the Bazaar discovery catalog.
    RegisterResource(X402RegisterResourceCmd),
    /// Browse Bazaar resource listings (narrowed by scheme/network/etc).
    DiscoverResources(X402DiscoverResourcesCmd),
    /// Remove a Bazaar resource listing you published.
    DeregisterResource(X402DeregisterResourceCmd),
    /// Verify a server-signed offer carried in a 402 requirement.
    VerifyOffer(X402VerifyOfferCmd),
    /// Derive the deterministic `pay_<hex>` idempotency identifier.
    PaymentId(X402PaymentIdCmd),
}

impl X402Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ListSchemes(cmd) => cmd.execute().await,
            Self::Pay(cmd) => cmd.execute().await,
            Self::RegisterResource(cmd) => cmd.execute().await,
            Self::DiscoverResources(cmd) => cmd.execute().await,
            Self::DeregisterResource(cmd) => cmd.execute().await,
            Self::VerifyOffer(cmd) => cmd.execute().await,
            Self::PaymentId(cmd) => cmd.execute().await,
        }
    }
}

/// `tenzro x402 list-schemes` — enumerate registered scheme verifiers.
#[derive(Debug, Parser)]
pub struct X402ListSchemesCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl X402ListSchemesCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("x402 Schemes");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listX402Schemes", serde_json::json!({}))
            .await
            .context("calling tenzro_listX402Schemes")?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// `tenzro x402 pay` — submit a payment payload.
///
/// The payload is the `X-PAYMENT` header value the client built locally
/// (signed authorization for `exact` scheme, signed Permit2 for `permit2`,
/// etc.). The CLI does not construct or sign payloads — that is the
/// principal's job per the AP2 separation-of-duties rule.
#[derive(Debug, Parser)]
pub struct X402PayCmd {
    /// Path to a JSON file containing the x402 PaymentRequired challenge
    /// (the body of the `402` response).
    #[arg(long)]
    challenge_file: String,

    /// Path to a JSON file containing the X-PAYMENT payload (already
    /// signed by the principal's wallet).
    #[arg(long)]
    payload_file: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl X402PayCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("x402 Pay");
        let challenge: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&self.challenge_file)
                .with_context(|| format!("reading {}", self.challenge_file))?,
        )
        .context("parsing challenge JSON")?;
        let payload: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&self.payload_file)
                .with_context(|| format!("reading {}", self.payload_file))?,
        )
        .context("parsing payload JSON")?;

        let spinner = output::create_spinner("Submitting payment to facilitator...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_payX402",
                serde_json::json!({
                    "challenge": challenge,
                    "payload": payload,
                }),
            )
            .await
            .context("calling tenzro_payX402")?;
        spinner.finish_and_clear();

        output::print_json(&result)?;
        Ok(())
    }
}

/// `tenzro x402 register-resource` — publish a paid resource listing.
///
/// The seller advertises what a buyer must pay to access `resource`. The
/// listing id is derived server-side from `(seller-did, resource)`, so a
/// re-register with the same pair updates the existing listing in place.
#[derive(Debug, Parser)]
pub struct X402RegisterResourceCmd {
    /// Seller DID that owns this listing.
    #[arg(long)]
    seller_did: String,

    /// The paid resource URL (e.g. an API endpoint or content URI).
    #[arg(long)]
    resource: String,

    /// Payment scheme (e.g. `tenzro-hybrid`, `permit2`, `upto`,
    /// `batch-settlement`).
    #[arg(long)]
    scheme: String,

    /// Settlement network / chain identifier.
    #[arg(long)]
    network: String,

    /// Asset identifier the price is denominated in.
    #[arg(long)]
    asset: String,

    /// Address the buyer pays to.
    #[arg(long)]
    pay_to: String,

    /// Maximum amount required, as a base-unit string.
    #[arg(long)]
    max_amount_required: String,

    /// Human-readable description of the resource.
    #[arg(long)]
    description: Option<String>,

    /// MIME type of the resource output.
    #[arg(long)]
    mime_type: Option<String>,

    /// Payment validity window in seconds.
    #[arg(long)]
    max_timeout_seconds: Option<i64>,

    /// Comma-separated discovery tags.
    #[arg(long)]
    tags: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl X402RegisterResourceCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("x402 Register Resource");
        let mut params = serde_json::json!({
            "sellerDid": self.seller_did,
            "resource": self.resource,
            "scheme": self.scheme,
            "network": self.network,
            "asset": self.asset,
            "payTo": self.pay_to,
            "maxAmountRequired": self.max_amount_required,
        });
        let obj = params.as_object_mut().expect("json object");
        if let Some(d) = &self.description {
            obj.insert("description".into(), serde_json::json!(d));
        }
        if let Some(m) = &self.mime_type {
            obj.insert("mimeType".into(), serde_json::json!(m));
        }
        if let Some(t) = self.max_timeout_seconds {
            obj.insert("maxTimeoutSeconds".into(), serde_json::json!(t));
        }
        if let Some(tags) = &self.tags {
            let list: Vec<&str> = tags
                .split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .collect();
            obj.insert("tags".into(), serde_json::json!(list));
        }

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_x402RegisterResource", params)
            .await
            .context("calling tenzro_x402RegisterResource")?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// `tenzro x402 discover-resources` — browse the Bazaar catalog.
#[derive(Debug, Parser)]
pub struct X402DiscoverResourcesCmd {
    /// Filter by payment scheme.
    #[arg(long)]
    scheme: Option<String>,

    /// Filter by settlement network.
    #[arg(long)]
    network: Option<String>,

    /// Filter by asset identifier.
    #[arg(long)]
    asset: Option<String>,

    /// Filter by seller DID.
    #[arg(long)]
    seller_did: Option<String>,

    /// Comma-separated tags — a listing must carry every one.
    #[arg(long)]
    tags: Option<String>,

    /// Minimum seller reputation (unscored sellers are excluded when set).
    #[arg(long)]
    min_reputation: Option<u64>,

    /// Maximum listings to return.
    #[arg(long)]
    limit: Option<usize>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl X402DiscoverResourcesCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("x402 Discover Resources");
        let mut params = serde_json::Map::new();
        if let Some(s) = &self.scheme {
            params.insert("scheme".into(), serde_json::json!(s));
        }
        if let Some(n) = &self.network {
            params.insert("network".into(), serde_json::json!(n));
        }
        if let Some(a) = &self.asset {
            params.insert("asset".into(), serde_json::json!(a));
        }
        if let Some(d) = &self.seller_did {
            params.insert("sellerDid".into(), serde_json::json!(d));
        }
        if let Some(tags) = &self.tags {
            let list: Vec<&str> = tags
                .split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .collect();
            params.insert("tags".into(), serde_json::json!(list));
        }
        if let Some(mr) = self.min_reputation {
            params.insert("minReputation".into(), serde_json::json!(mr));
        }
        if let Some(l) = self.limit {
            params.insert("limit".into(), serde_json::json!(l));
        }

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_x402DiscoverResources",
                serde_json::Value::Object(params),
            )
            .await
            .context("calling tenzro_x402DiscoverResources")?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// `tenzro x402 deregister-resource` — remove a listing you published.
///
/// Seller-scoped: the `seller-did` must match the DID that registered the
/// listing, otherwise the node refuses the removal.
#[derive(Debug, Parser)]
pub struct X402DeregisterResourceCmd {
    /// The listing id returned at registration.
    #[arg(long)]
    listing_id: String,

    /// Seller DID that owns the listing.
    #[arg(long)]
    seller_did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl X402DeregisterResourceCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("x402 Deregister Resource");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_x402DeregisterResource",
                serde_json::json!({
                    "listingId": self.listing_id,
                    "sellerDid": self.seller_did,
                }),
            )
            .await
            .context("calling tenzro_x402DeregisterResource")?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// `tenzro x402 verify-offer` — verify a server-signed offer before paying.
///
/// A buyer that received a `402 Payment Required` body saves the
/// `X402PaymentRequirement` JSON (with `offerCommitment` / `offerSig` /
/// `offerSigner` in `extra`) and passes it here. The node recomputes the
/// commitment, matches it against the carried value, and verifies the Ed25519
/// signature under the carried signer key — proving the price and pay-to were
/// not tampered with in transit.
#[derive(Debug, Parser)]
pub struct X402VerifyOfferCmd {
    /// Path to a JSON file containing the full x402 payment requirement
    /// (one entry from the `402` response's `accepts` array).
    #[arg(long)]
    requirement_file: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl X402VerifyOfferCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("x402 Verify Offer");
        let requirement: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&self.requirement_file)
                .with_context(|| format!("reading {}", self.requirement_file))?,
        )
        .context("parsing requirement JSON")?;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_x402VerifyOffer",
                serde_json::json!({ "requirement": requirement }),
            )
            .await
            .context("calling tenzro_x402VerifyOffer")?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// `tenzro x402 payment-id` — derive the idempotency identifier.
///
/// The `pay_<hex>` identifier is deterministic in `(offer-commitment,
/// payer-did)`. A buyer computes it ahead of settling so a retried settlement
/// with the same identifier returns the prior receipt instead of paying twice.
/// Pass either the full requirement file (the node recomputes the commitment)
/// or a pre-computed `--offer-commitment` hex.
#[derive(Debug, Parser)]
pub struct X402PaymentIdCmd {
    /// The paying identity's DID.
    #[arg(long)]
    payer_did: String,

    /// Path to a JSON file containing the full x402 payment requirement.
    /// Mutually exclusive with `--offer-commitment`.
    #[arg(long, conflicts_with = "offer_commitment")]
    requirement_file: Option<String>,

    /// Pre-computed 32-byte offer commitment, hex-encoded.
    /// Mutually exclusive with `--requirement-file`.
    #[arg(long)]
    offer_commitment: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl X402PaymentIdCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("x402 Payment Id");
        let mut params = serde_json::Map::new();
        params.insert("payerDid".into(), serde_json::json!(self.payer_did));

        match (&self.requirement_file, &self.offer_commitment) {
            (Some(path), _) => {
                let requirement: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(path)
                        .with_context(|| format!("reading {path}"))?,
                )
                .context("parsing requirement JSON")?;
                params.insert("requirement".into(), requirement);
            }
            (None, Some(commitment)) => {
                params.insert("offerCommitment".into(), serde_json::json!(commitment));
            }
            (None, None) => {
                anyhow::bail!("one of --requirement-file or --offer-commitment is required");
            }
        }

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_x402PaymentId", serde_json::Value::Object(params))
            .await
            .context("calling tenzro_x402PaymentId")?;
        output::print_json(&result)?;
        Ok(())
    }
}
