//! `tenzro-mailbox-service`: a store-and-forward mailbox (preview) an
//! operator runs beside its own Tenzro node.
//!
//! It listens on 127.0.0.1 and refuses any other address unless started with
//! `--public`. To offer it to the network, put it behind the operator's own
//! TLS front end (a reverse proxy holding the certificate, forwarding to the
//! loopback address), and have each recipient publish the service entry
//! printed at start (type `TenzroMailbox`, the front end's https address with
//! the digest of the service's key; pass `--address`). Its key
//! lives in this machine's TPM or Secure Enclave, the way a node's keys do;
//! on a machine without either the service does not start.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use tenzro_crypto::HybridSigner as _;
use tenzro_mailbox::{HttpLimits, Ledger, Mailbox, MailboxConfig, RpcLedger};
use tenzro_mailbox_service::{Claimer, ServiceKey, Submit, due_claims};
use tenzro_sdk::rpc::RpcClient;
use tenzro_sdk::typed_tx::{TypedTransaction, TypedTxClient};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Store-and-forward mailbox (preview) beside a Tenzro node"
)]
struct Args {
    /// Directory the mailbox keeps its messages and records in.
    #[arg(long, env = "TENZRO_MAILBOX_DIR")]
    data_dir: PathBuf,
    /// The operator's node, JSON-RPC.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    node: String,
    /// Address to serve the mailbox on. Loopback by default: the service is
    /// reachable from this machine only, behind the operator's TLS front end.
    #[arg(long, default_value = "127.0.0.1:8095")]
    listen: SocketAddr,
    /// Allow `--listen` to name an address other machines can reach. The
    /// service speaks plain HTTP; serve it this way only behind a TLS front
    /// end on a network the operator controls.
    #[arg(long)]
    public: bool,
    /// The https address recipients reach this mailbox at (the TLS front
    /// end's): the DID service endpoint to publish is printed with it.
    #[arg(long)]
    address: Option<String>,
    /// Price of keeping one byte for one hour, in wei.
    #[arg(long)]
    rate_per_byte_hour: u128,
    /// Accept a rate of zero: the mailbox then charges nothing.
    #[arg(long)]
    allow_free: bool,
    /// Label of the service's key in this machine's hardware.
    #[arg(long, default_value = "mailbox")]
    key_label: String,
    /// Seconds between claims of what the escrows owe.
    #[arg(long, default_value_t = 600)]
    claim_every_s: u64,
    /// Seconds between sweeps of mail whose lifetime ended.
    #[arg(long, default_value_t = 300)]
    sweep_every_s: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn parse_hex_u64(text: &str) -> Result<u64> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|e| anyhow!("{text}: {e}"))
}

/// The SDK's signed submission, as the claimer submits.
struct SdkSubmit {
    txs: TypedTxClient,
    key: ServiceKey,
}

impl Submit for SdkSubmit {
    async fn submit(&self, tx: &TypedTransaction) -> Result<()> {
        let answer = self.txs.send(&self.key, tx).await?;
        tracing::info!("claim sent: {answer}");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Every TLS connection in this process uses aws-lc-rs, the provider with
    // the X25519MLKEM768 hybrid key exchange, never one another dependency
    // compiled in.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("a TLS provider was installed before main"))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    if !args.listen.ip().is_loopback() && !args.public {
        return Err(anyhow!(
            "{} is reachable from other machines; serve on loopback behind a TLS front end, or pass --public",
            args.listen
        ));
    }

    let hardware = tenzro_device_key::signer::HardwareHybridSigner::open_or_create(&args.key_label)
        .context("the service key: this machine has no TPM or Secure Enclave key for it, and the mailbox does not run on a key held in software")?;
    let hardware = Arc::new(hardware);
    let rpc = Arc::new(RpcClient::new(&args.node, Duration::from_secs(30), None)?);
    let chain_id = parse_hex_u64(
        &rpc.call::<String>("eth_chainId", serde_json::json!([]))
            .await?,
    )?;

    let mut config = MailboxConfig::new(chain_id, args.rate_per_byte_hour);
    config.allow_free = args.allow_free;
    let claim_margin_ms = config.claim_margin_ms;
    let ledger = Arc::new(RpcLedger::new(&args.node));
    let mailbox = Arc::new(Mailbox::open(
        config,
        &args.data_dir,
        ledger.clone(),
        hardware.clone(),
        now_ms(),
    )?);
    let info = mailbox.info();
    tracing::info!(
        "mailbox key {} (payee account {}), chain {}",
        hex::encode(&hardware.public_key().p256),
        info.payee,
        info.chain_id
    );
    match &args.address {
        Some(address) => tracing::info!(
            "recipients publish a service of type {} with endpoint {}",
            tenzro_mailbox::MAILBOX_SERVICE_TYPE,
            tenzro_mailbox::mailbox_endpoint(address, &info.operator_key)
        ),
        None => tracing::info!(
            "recipients publish a service of type {} with endpoint <https address>#key={}",
            tenzro_mailbox::MAILBOX_SERVICE_TYPE,
            hex::encode(tenzro_mailbox::operator_key_digest(&info.operator_key))
        ),
    }

    let sweeper = mailbox.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(args.sweep_every_s));
        loop {
            every.tick().await;
            let swept = {
                let mailbox = sweeper.clone();
                tokio::task::spawn_blocking(move || mailbox.sweep(now_ms())).await
            };
            match swept {
                Ok(Ok(n)) if n > 0 => tracing::info!("swept {n} message(s)"),
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::warn!("sweep: {e}"),
                Err(e) => tracing::warn!("sweep task: {e}"),
            }
        }
    });
    let claiming = mailbox.clone();
    let submit = SdkSubmit {
        txs: TypedTxClient::new(rpc.clone()),
        key: ServiceKey(hardware.clone()),
    };
    tokio::spawn(async move {
        let mut claimer = Claimer::default();
        let mut every = tokio::time::interval(Duration::from_secs(args.claim_every_s));
        loop {
            every.tick().await;
            let due = match claiming.due() {
                Ok(due) => due,
                Err(e) => {
                    tracing::warn!("claim: {e}");
                    continue;
                }
            };
            let ledger: &dyn Ledger = ledger.as_ref();
            match due_claims(due, ledger, now_ms(), claim_margin_ms).await {
                Ok(claims) => {
                    claimer.claim(claims, &submit, now_ms()).await;
                }
                Err(e) => tracing::warn!("claim: {e}"),
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("listening on {}", args.listen))?;
    if args.listen.ip().is_loopback() {
        tracing::info!("serving the mailbox on {} (this machine only)", args.listen);
    } else {
        tracing::warn!(
            "serving the mailbox on {}, beyond this machine",
            args.listen
        );
    }
    let limits = HttpLimits::default();
    tenzro_mailbox::serve(listener, tenzro_mailbox::router(mailbox, &limits), &limits).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listener_is_loopback_unless_told_otherwise() {
        let args = Args::try_parse_from([
            "tenzro-mailbox-service",
            "--data-dir",
            "/tmp/mailbox",
            "--rate-per-byte-hour",
            "1",
        ])
        .expect("args");
        assert!(args.listen.ip().is_loopback());
        assert!(!args.public);
        assert_eq!(args.node, "http://127.0.0.1:8545");
        assert!(!args.allow_free);
    }
}
