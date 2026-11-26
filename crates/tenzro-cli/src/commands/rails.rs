//! `tenzro rails` — where a payment can settle, and where a given charge should.
//!
//! Supporting x402 on a rail and that rail being able to carry a micropayment
//! are different properties. Base speaks x402 fluently and still cannot carry a
//! one-cent charge without roughly ten percent overhead. This command shows
//! both, so an operator picking a settlement asset can see which rails carry it
//! and what the smallest worthwhile payment on each is.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Settlement rails and micropayment routing.
#[derive(Debug, Subcommand)]
pub enum RailsCommand {
    /// List every network a payment can settle on.
    List(ListCmd),
    /// Ask where a specific charge would settle.
    Route(RouteCmd),
}

impl RailsCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(c) => c.execute().await,
            Self::Route(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct ListCmd {
    /// Show only rails that can settle an x402 payment.
    #[arg(long)]
    x402_only: bool,
    /// Show only rails carrying this asset (e.g. USDC, RLUSD, pUSD).
    #[arg(long)]
    asset: Option<String>,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_settlementNetworks", serde_json::json!({}))
            .await?;
        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Settlement rails");
        output::print_field("Primary", result["primary"].as_str().unwrap_or("?"));
        output::print_field(
            "Micro-settlement floor",
            result["micro_settlement_floor_wei"].as_str().unwrap_or("?"),
        );
        println!();

        for n in result["networks"].as_array().unwrap_or(&vec![]) {
            if self.x402_only && !n["x402"].as_bool().unwrap_or(false) {
                continue;
            }
            if let Some(want) = &self.asset {
                let carries = n["native_stablecoins"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .any(|s| s.as_str().is_some_and(|s| s.eq_ignore_ascii_case(want)))
                    })
                    .unwrap_or(false)
                    || n["native_asset"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(want));
                if !carries {
                    continue;
                }
            }
            let assets: Vec<&str> = n["native_stablecoins"]
                .as_array()
                .map(|a| a.iter().filter_map(|s| s.as_str()).collect())
                .unwrap_or_default();
            output::print_field(
                n["name"].as_str().unwrap_or("?"),
                &format!(
                    "{} — {}, min {} µUSD{}{}",
                    n["caip2"].as_str().unwrap_or("?"),
                    n["family"].as_str().unwrap_or("?"),
                    n["min_payment_micro_usd"],
                    if n["x402"].as_bool().unwrap_or(false) {
                        ", x402"
                    } else {
                        ""
                    },
                    if assets.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", assets.join(", "))
                    }
                ),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RouteCmd {
    /// Charge to route, in TNZO wei.
    amount_wei: String,
    /// Asset the payee wants to hold. Omit for TNZO on the home chain.
    #[arg(long)]
    asset: Option<String>,
    /// TNZO price in micro-USD, needed to compare against a rail's fee.
    /// Without it the node settles on the home chain rather than guessing.
    #[arg(long)]
    tnzo_micro_usd: Option<u64>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RouteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_settlementNetworks",
                serde_json::json!({
                    "amount_wei": self.amount_wei,
                    "asset": self.asset,
                    "tnzo_micro_usd": self.tnzo_micro_usd,
                }),
            )
            .await?;

        let route = &result["route"];
        output::print_header("Routing decision");
        output::print_field("Amount (wei)", &self.amount_wei);
        output::print_field("Decision", route["kind"].as_str().unwrap_or("?"));
        output::print_field(
            "Settles now",
            if route["settles_now"].as_bool().unwrap_or(false) {
                "yes"
            } else {
                "no"
            },
        );
        match route["kind"].as_str() {
            Some("accumulate") => output::print_warning(
                "Below the micro-settlement floor — hold it in a micropayment channel. \
                 Settling it alone would cost more than it moves.",
            ),
            Some("no_viable_rail") => output::print_warning(
                "No rail carries this asset at this size. Accumulate, or have the payee \
                 accept another asset.",
            ),
            _ => output::print_field(
                "Rail",
                // The node names the rail; a primary route is its own chain.
                route["detail"]["caip2"]
                    .as_str()
                    .or_else(|| result["primary"].as_str())
                    .unwrap_or("(not reported by the node)"),
            ),
        }
        Ok(())
    }
}

/// Interaction receipts.
#[derive(Debug, Subcommand)]
pub enum InteractionCommand {
    /// Record a settlement, given as its interaction record, on other chains, in parallel.
    Mirror(MirrorInteractionCmd),
    /// Recompute an interaction record's digest offline and check it against one you were given.
    Verify(VerifyInteractionCmd),
}

impl InteractionCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Mirror(c) => c.execute().await,
            Self::Verify(c) => c.execute(),
        }
    }
}

#[derive(Debug, Parser)]
pub struct VerifyInteractionCmd {
    /// Path to the interaction record JSON.
    interaction_json: String,
    /// The digest the record is claimed to have (64 hex characters), as a
    /// node reported it or as it was written onto a chain.
    #[arg(long)]
    expect: Option<String>,
}

impl VerifyInteractionCmd {
    /// Needs no node: the digest is a function of the record alone
    /// (docs/standards/interaction-receipt.md).
    pub fn execute(&self) -> Result<()> {
        let raw = std::fs::read_to_string(&self.interaction_json)?;
        let digest = interaction_digest(&raw, self.expect.as_deref())?;
        output::print_header("Interaction record");
        output::print_field("Digest", &digest);
        match &self.expect {
            Some(_) => output::print_success("The record has the expected digest."),
            None => output::print_info(
                "Compare this digest with the one the node reported or the one written on chain.",
            ),
        }
        Ok(())
    }
}

/// The keys of an interaction record its digest covers, as
/// docs/standards/interaction-receipt.md lists them; `on_behalf_of` may be
/// absent.
const COVERED_KEYS: [&str; 11] = [
    "interaction_id",
    "kind",
    "payer_did",
    "on_behalf_of",
    "attester_did",
    "resource_id",
    "authority",
    "charge",
    "amount_charged",
    "settled_asset",
    "occurred_at",
];

/// A record whose uncovered fields hold placeholders: the digest never reads
/// them, so a record that carries only its covered fields is laid over this.
fn uncovered_placeholders() -> tenzro_types::provenance::InteractionProvenance {
    use tenzro_types::access_tier::{AccessTier, PayerKind};
    use tenzro_types::provenance::{Authority, ChargeRef, InboundRail, InteractionKind};
    tenzro_types::provenance::InteractionProvenance {
        interaction_id: String::new(),
        payer_did: String::new(),
        payer_kind: PayerKind::Agent,
        payer_wallet: tenzro_types::primitives::Address::default(),
        on_behalf_of: None,
        kind: InteractionKind::Inference,
        resource_id: String::new(),
        units: tenzro_types::model::BillableUnits::tokens(0, 0),
        occurred_at: tenzro_types::primitives::Timestamp::new(0),
        attester_did: String::new(),
        authority: Authority::Open,
        charge: ChargeRef::Free,
        tier: AccessTier::User,
        credential_digest: None,
        inbound_rail: InboundRail::Tenzro,
        amount_charged: 0,
        settled_asset: String::new(),
        payees: Vec::new(),
        settlement_tx: None,
        secondary_settlements: Vec::new(),
    }
}

/// The hex digest of the interaction record in `raw`, read from its covered
/// fields alone, so a record carrying only those is accepted just as the
/// independent verifier accepts it. Refuses a record that is not attestable,
/// and one whose digest is not `expect` when that is given.
fn interaction_digest(raw: &str, expect: Option<&str>) -> Result<String> {
    let given: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("not an interaction record: {e}"))?;
    let given = given
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("not an interaction record: not a JSON object"))?;
    let mut full = serde_json::to_value(uncovered_placeholders())?;
    for key in COVERED_KEYS {
        match given.get(key) {
            Some(value) => full[key] = value.clone(),
            None if key == "on_behalf_of" => full[key] = serde_json::Value::Null,
            None => anyhow::bail!("not an interaction record: `{key}` is missing"),
        }
    }
    if let Some(amount) = given["amount_charged"].as_str()
        && (amount.is_empty() || !amount.bytes().all(|b| b.is_ascii_digit()))
    {
        anyhow::bail!("not an interaction record: `amount_charged` is not a decimal string");
    }
    let record: tenzro_types::provenance::InteractionProvenance = serde_json::from_value(full)
        .map_err(|e| anyhow::anyhow!("not an interaction record: {e}"))?;
    record
        .validate_attestable()
        .map_err(|e| anyhow::anyhow!("the record cannot be attested: {e}"))?;
    let digest = record.attestation_digest_hex();
    if let Some(expect) = expect {
        let expect = expect.trim().trim_start_matches("0x").to_ascii_lowercase();
        if expect != digest {
            anyhow::bail!("the record's digest is {digest}, not the expected {expect}");
        }
    }
    Ok(digest)
}

#[derive(Debug, Parser)]
pub struct MirrorInteractionCmd {
    /// Path to the interaction record JSON of the settlement to mirror.
    interaction_json: String,
    /// Chains to mirror onto — CAIP-2 ids or adapter chain names.
    /// Repeat the flag for several.
    #[arg(long = "chain", required = true)]
    chains: Vec<String>,
    /// Hardware key namespace of the account that signs and pays for the mirror transactions
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// Write only the digest rather than the full settlement bytes.
    ///
    /// Cheaper, and it proves a payload you already hold is the one that
    /// settled — but it cannot say *what* settled, so it does not survive the
    /// Tenzro Ledger losing state.
    #[arg(long)]
    digest_only: bool,
    /// Whether the primary settlement committed.
    #[arg(long, default_value_t = true)]
    primary_committed: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MirrorInteractionCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let raw = std::fs::read_to_string(&self.interaction_json)?;
        let interaction: serde_json::Value = serde_json::from_str(&raw)?;
        let targets: Vec<serde_json::Value> = self
            .chains
            .iter()
            .map(|c| serde_json::json!({ "chain": c, "self_contained": !self.digest_only }))
            .collect();
        let r: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_mirrorSettlement",
                serde_json::json!({
                    "interaction": interaction,
                    "targets": targets,
                    "primary_committed": self.primary_committed,
                }),
            )
            .await?;

        // Sign each mirror transaction in hardware and submit it pre-signed.
        let rpc = RpcClient::new(&self.rpc);
        let (account, _) = crate::keystore::client_account(&self.key_namespace)?;
        let own = crate::keystore::address32(&account)?;
        for t in r["transactions"].as_array().cloned().unwrap_or_default() {
            crate::keystore::send_as_client(
                &rpc,
                &self.key_namespace,
                own,
                t["tx_type"].clone(),
                500_000,
            )
            .await?;
        }

        output::print_header("Settlement mirror");
        output::print_field("Interaction", r["interaction_id"].as_str().unwrap_or("?"));
        output::print_field("Digest", r["attestation_digest"].as_str().unwrap_or("?"));
        output::print_field(
            "Fully mirrored",
            if r["fully_mirrored"].as_bool().unwrap_or(false) {
                "yes"
            } else {
                "no"
            },
        );
        println!();
        for o in r["outcomes"].as_array().unwrap_or(&vec![]) {
            let state = o["state"].as_str().unwrap_or("?");
            output::print_field(
                o["chain"].as_str().unwrap_or("?"),
                &format!(
                    "{state} ({}){}",
                    o["durability"].as_str().unwrap_or("?"),
                    o["reference"]
                        .as_str()
                        .map(|s| format!(" — {s}"))
                        .or_else(|| o["reason"].as_str().map(|s| format!(" — {s}")))
                        .unwrap_or_default()
                ),
            );
        }
        println!();
        if r["durable_beyond_primary"].as_bool().unwrap_or(false) {
            output::print_field("Durability", "survives the Tenzro Ledger losing state");
        } else {
            output::print_warning(
                "This settlement does NOT survive the Tenzro Ledger losing state. A digest-only \
                 mirror proves a payload matches but cannot say what settled; mirror at least one \
                 chain with the full settlement bytes.",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::access_tier::{AccessTier, PayerKind};
    use tenzro_types::model::BillableUnits;
    use tenzro_types::primitives::{Address, Timestamp};
    use tenzro_types::provenance::{
        Authority, ChargeRef, InboundRail, InteractionKind, InteractionProvenance,
    };

    /// The digest of the worked example in docs/standards/interaction-receipt.md.
    const EXAMPLE_DIGEST: &str = "d6d89cd298efecf601be462c2a4e76878fbd021033753663db55af3728ab0bf7";

    /// The worked example of docs/standards/interaction-receipt.md.
    fn example() -> InteractionProvenance {
        InteractionProvenance {
            interaction_id: "int_1".into(),
            payer_did: "did:tenzro:machine:agent".into(),
            payer_kind: PayerKind::Agent,
            payer_wallet: Address::default(),
            on_behalf_of: Some("did:tenzro:human:alice".into()),
            kind: InteractionKind::Inference,
            resource_id: "qwen3-27b".into(),
            units: BillableUnits::tokens(1_000, 250),
            occurred_at: Timestamp::new(1_700_000_000_000),
            attester_did: "did:tenzro:machine:node".into(),
            authority: Authority::X402Payment {
                scheme: "exact".into(),
            },
            charge: ChargeRef::Settlement {
                settlement_id: "s-1".into(),
            },
            tier: AccessTier::User,
            credential_digest: None,
            inbound_rail: InboundRail::Tenzro,
            amount_charged: 1_000,
            settled_asset: "tenzro:1337/native:tnzo".into(),
            payees: Vec::new(),
            settlement_tx: None,
            secondary_settlements: Vec::new(),
        }
    }

    /// The published vectors (docs/standards/vectors/interaction-receipt.json),
    /// each a record that carries only its covered fields.
    fn vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/standards/vectors/interaction-receipt.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn a_record_of_covered_fields_alone_is_read_and_a_missing_one_refused() {
        let worked = vectors()["vectors"][0]["record"].clone();
        let covered = worked.as_object().unwrap();
        assert!(
            covered
                .keys()
                .all(|key| COVERED_KEYS.contains(&key.as_str()))
        );
        assert_eq!(
            interaction_digest(&worked.to_string(), None).unwrap(),
            EXAMPLE_DIGEST
        );
        let full = serde_json::to_string(&example()).unwrap();
        assert_eq!(interaction_digest(&full, None).unwrap(), EXAMPLE_DIGEST);
        let mut missing = worked.clone();
        missing.as_object_mut().unwrap().remove("settled_asset");
        let refused = interaction_digest(&missing.to_string(), None).unwrap_err();
        assert!(
            refused.to_string().contains("`settled_asset` is missing"),
            "{refused}"
        );
    }

    #[test]
    fn an_amount_is_read_as_a_number_or_any_decimal_string() {
        let worked = vectors()["vectors"][0]["record"].clone();
        let mut as_text = worked.clone();
        as_text["amount_charged"] = "1000".into();
        assert_eq!(
            interaction_digest(&as_text.to_string(), None).unwrap(),
            EXAMPLE_DIGEST
        );
        for refused in ["+1000", "", "1e3", "-1"] {
            as_text["amount_charged"] = refused.into();
            assert!(
                interaction_digest(&as_text.to_string(), None).is_err(),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn the_nodes_digest_is_the_published_one_for_every_vector() {
        let all = vectors();
        assert_eq!(all["vectors"][0]["digest"], EXAMPLE_DIGEST);
        for v in all["vectors"].as_array().unwrap() {
            let digest = interaction_digest(&v["record"].to_string(), None).unwrap();
            assert_eq!(digest, v["digest"].as_str().unwrap(), "{}", v["label"]);
        }
        for v in all["refused"].as_array().unwrap() {
            assert!(
                interaction_digest(&v["record"].to_string(), None).is_err(),
                "{}",
                v["label"]
            );
        }
    }

    #[test]
    fn the_offline_digest_of_the_worked_example_is_the_documented_one() {
        let raw = serde_json::to_string(&example()).unwrap();
        assert_eq!(interaction_digest(&raw, None).unwrap(), EXAMPLE_DIGEST);
    }

    #[test]
    fn an_expected_digest_is_checked_in_either_spelling() {
        let raw = serde_json::to_string(&example()).unwrap();
        assert!(interaction_digest(&raw, Some(EXAMPLE_DIGEST)).is_ok());
        let spelled = format!("0x{}", EXAMPLE_DIGEST.to_uppercase());
        assert!(interaction_digest(&raw, Some(&spelled)).is_ok());
        let wrong = "00".repeat(32);
        let refusal = interaction_digest(&raw, Some(&wrong)).unwrap_err();
        assert!(refusal.to_string().contains(EXAMPLE_DIGEST), "{refusal}");
    }

    #[test]
    fn a_changed_field_changes_the_digest_and_fails_the_check() {
        let mut changed = example();
        changed.resource_id = "another-model".into();
        let raw = serde_json::to_string(&changed).unwrap();
        assert!(interaction_digest(&raw, Some(EXAMPLE_DIGEST)).is_err());
    }

    #[test]
    fn a_record_that_cannot_be_attested_is_refused() {
        let mut unattributed = example();
        unattributed.payer_did.clear();
        let raw = serde_json::to_string(&unattributed).unwrap();
        assert!(interaction_digest(&raw, None).is_err());
        assert!(interaction_digest("{}", None).is_err());
    }
}
