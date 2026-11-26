//! End-to-end driver of a mailbox on a private network
//! (`scripts/testnet/mailbox-e2e.sh`): the recipient and the sender each run
//! it with their own hardware key, and every step reaches the mailbox the
//! recipient's DID document names. One JSON line per check on stdout; the
//! exit status is non-zero when any check failed.
//!
//!   mailbox_e2e prekeys --rpc <url> --did <recipient DID> --node-namespace <ns>
//!   mailbox_e2e send    --rpc <url> --did <recipient DID> --payer-namespace <ns> --escrow <id> --count <n> --out <file>
//!   mailbox_e2e receive --rpc <url> --did <recipient DID> --node-namespace <ns> --sent <file>

use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_device_key::HardwareHybridSigner;
use tenzro_mailbox::{DepositRequest, MailboxClient, Terms, mailboxes_in, size_class_for};
use tenzro_sdk::rpc::RpcClient;

/// Lifetime of every message the driver deposits.
const LIFETIME_S: u64 = 600;
/// Length of every message before padding.
const MESSAGE_LEN: usize = 700;

#[derive(Debug, Parser)]
struct Args {
    /// The node's JSON-RPC.
    #[arg(long)]
    rpc: String,
    /// The recipient, an autonomous machine whose DID document names the
    /// mailbox.
    #[arg(long)]
    did: String,
    /// The most the payer pays for keeping one byte for one hour, in wei.
    #[arg(long)]
    max_rate_per_byte_hour: u128,
    /// The most the payer pays for one key package, in wei.
    #[arg(long)]
    max_prekey_price: u128,
    #[command(subcommand)]
    step: Step,
}

#[derive(Debug, Subcommand)]
enum Step {
    /// The recipient uploads two one-time key packages and a last-resort one.
    Prekeys {
        /// The recipient node's hardware key namespace.
        #[arg(long)]
        node_namespace: String,
    },
    /// The sender fetches a key package and deposits `count` messages, paid
    /// from `escrow`.
    Send {
        /// The payer's client account namespace.
        #[arg(long)]
        payer_namespace: String,
        /// The escrow that pays the mailbox, hex.
        #[arg(long)]
        escrow: String,
        #[arg(long, default_value_t = 3)]
        count: usize,
        /// Where the deposits are recorded for `receive`.
        #[arg(long)]
        out: String,
    },
    /// The recipient lists, collects and acknowledges what `send` deposited.
    Receive {
        /// The recipient node's hardware key namespace.
        #[arg(long)]
        node_namespace: String,
        /// The record `send` wrote.
        #[arg(long)]
        sent: String,
    },
}

struct Checks(bool);

impl Checks {
    fn check(&mut self, name: &str, ok: bool, detail: Value) {
        println!("{}", json!({ "check": name, "ok": ok, "detail": detail }));
        self.0 &= ok;
    }
}

/// The recipient node's identity key, the one its machine DID derives from.
fn recipient_signer(namespace: &str) -> Result<HardwareHybridSigner> {
    tenzro_device_key::set_label_namespace(namespace)?;
    Ok(HardwareHybridSigner::open_or_create(
        tenzro_types::did_derivation::MACHINE_KEY_LABEL,
    )?)
}

async fn mailbox(args: &Args) -> Result<MailboxClient> {
    let rpc = RpcClient::new(&args.rpc, Duration::from_secs(30), None)?;
    let did = &args.did;
    let chain: String = rpc.call("eth_chainId", json!([])).await?;
    let terms = Terms {
        chain_id: u64::from_str_radix(chain.trim_start_matches("0x"), 16)?,
        max_rate_per_byte_hour: args.max_rate_per_byte_hour,
        max_prekey_price: args.max_prekey_price,
    };
    let document: Value = rpc
        .call("tenzro_resolveDidDocument", json!({ "did": did }))
        .await?;
    let entry = mailboxes_in(&document)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("{did}'s DID document names no mailbox"))?;
    Ok(MailboxClient::connect(&entry, terms).await?)
}

fn message(i: usize) -> Vec<u8> {
    (0..MESSAGE_LEN)
        .map(|j| Sha256::digest(format!("mailbox e2e {i} {}", j / 32))[j % 32])
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let client = mailbox(&args).await?;
    let mut checks = Checks(true);
    match args.step {
        Step::Prekeys { node_namespace } => {
            let signer = recipient_signer(&node_namespace)?;
            let kept = client
                .upload_prekeys(
                    &signer,
                    &args.did,
                    &[vec![1u8; 200], vec![2u8; 200]],
                    Some(&[3u8; 200][..]),
                )
                .await?;
            checks.check("prekeys uploaded", kept == 2, json!({ "kept": kept }));
        }
        Step::Send {
            payer_namespace,
            escrow,
            count,
            out,
        } => {
            let payer = HardwareHybridSigner::open_or_create(&format!("client/{payer_namespace}"))?;
            let escrow_id: [u8; 32] = hex::decode(escrow.trim_start_matches("0x"))?
                .try_into()
                .map_err(|_| anyhow!("an escrow id is 32 bytes"))?;
            let info = client.info().await?;
            let config = tenzro_mailbox::MailboxConfig::new(info.chain_id, info.rate_per_byte_hour);
            let mut paid = 0u128;

            paid += info.prekey_price;
            let prekey = client
                .fetch_prekey(&payer, escrow_id, paid, &args.did)
                .await?;
            checks.check(
                "a one-time key package is served",
                !prekey.last_resort && [vec![1u8; 200], vec![2u8; 200]].contains(&prekey.package),
                json!({ "last_resort": prekey.last_resort }),
            );

            let mut sent = Vec::new();
            for i in 0..count {
                let mut sealed = message(i);
                let class = size_class_for(sealed.len(), &info.size_classes)
                    .ok_or_else(|| anyhow!("no size class takes {} bytes", sealed.len()))?;
                sealed.resize(class as usize, 0);
                let charge = config
                    .charge(class, LIFETIME_S)
                    .ok_or_else(|| anyhow!("the charge overflows"))?;
                paid += charge;
                let digest = sha256_hex(&sealed);
                let receipt = client
                    .deposit(
                        &payer,
                        DepositRequest {
                            escrow_id,
                            cumulative_amount: paid,
                            recipient_did: &args.did,
                            sealed,
                            lifetime_s: LIFETIME_S,
                            sender: None,
                            capability: None,
                        },
                    )
                    .await?;
                checks.check(
                    "deposit receipted",
                    receipt.sealed_sha256 == digest && receipt.charge == charge,
                    json!({ "id": receipt.id, "charge": charge.to_string() }),
                );
                sent.push(json!({ "id": receipt.id, "sha256": digest }));
            }

            // A voucher already spent is refused.
            let mut again = message(0);
            again.resize(info.size_classes[0] as usize, 0);
            let replay = client
                .deposit(
                    &payer,
                    DepositRequest {
                        escrow_id,
                        cumulative_amount: paid,
                        recipient_did: &args.did,
                        sealed: again,
                        lifetime_s: LIFETIME_S,
                        sender: None,
                        capability: None,
                    },
                )
                .await;
            checks.check(
                "a voucher that adds nothing is refused",
                replay.is_err(),
                json!({}),
            );

            std::fs::write(
                &out,
                serde_json::to_vec(&json!({ "paid": paid.to_string(), "messages": sent }))?,
            )
            .with_context(|| format!("writing {out}"))?;
        }
        Step::Receive {
            node_namespace,
            sent,
        } => {
            let signer = recipient_signer(&node_namespace)?;
            let sent: Value = serde_json::from_slice(&std::fs::read(&sent)?)?;
            let expected: Vec<(String, String)> = sent["messages"]
                .as_array()
                .ok_or_else(|| anyhow!("the record names no messages"))?
                .iter()
                .map(|m| {
                    (
                        m["id"].as_str().unwrap_or_default().to_string(),
                        m["sha256"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect();
            let listed = client.list(&signer, &args.did).await?;
            let mut ids: Vec<&str> = listed.iter().map(|r| r.id.as_str()).collect();
            ids.sort_unstable();
            let mut want: Vec<&str> = expected.iter().map(|(id, _)| id.as_str()).collect();
            want.sort_unstable();
            checks.check(
                "the recipient lists every deposit",
                ids == want,
                json!({ "listed": ids.len() }),
            );
            for (id, digest) in &expected {
                let got = client.collect(&signer, &args.did, id).await?;
                checks.check(
                    "collected bytes are the deposited bytes",
                    sha256_hex(&got.sealed) == *digest,
                    json!({ "id": id }),
                );
                client.ack(&signer, &args.did, id).await?;
            }
            let left = client.list(&signer, &args.did).await?;
            checks.check(
                "acknowledged mail is gone",
                left.is_empty(),
                json!({ "left": left.len() }),
            );
        }
    }
    if !checks.0 {
        bail!("a check failed");
    }
    Ok(())
}
