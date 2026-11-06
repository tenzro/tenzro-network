//! Wallet operations: read an account's balances, then dry-run a TNZO
//! transfer from it.
//!
//! A transfer is signed by the account's key in the machine's TPM or Secure
//! Enclave: implement `HybridSigner` over that key (the `tenzro-device-key`
//! crate reaches it) and pass it to `client.wallet().send_self_custody(..)`.
//! The SDK never holds a private key. This example stops at the dry run,
//! which needs no key: the node encodes the signing payload and the SDK
//! checks that it is the transaction built here.
//!
//! ```text
//! cargo run --example wallet_operations
//!   TENZRO_RPC_URL   one node; unset, the client finds the preview network's operators
//!   TENZRO_ACCOUNT   the account to read (0x + 64 hex)
//! ```

use tenzro_sdk::{Address, TenzroClient, TxKind, TypedTransaction};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let client = match std::env::var("TENZRO_RPC_URL") {
        Ok(url) => TenzroClient::new(&url).await?,
        Err(_) => {
            tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default())
                .await?
        }
    };
    let account = match std::env::var("TENZRO_ACCOUNT") {
        Ok(hex) => Address::from_hex(&hex).ok_or("TENZRO_ACCOUNT must be 32 bytes of hex")?,
        Err(_) => Address::zero(),
    };
    let wallet = client.wallet();

    let balances = wallet.get_all_balances(account.clone()).await?;
    println!("account {}", balances.address);
    for balance in &balances.balances {
        println!(
            "  {}: {} (raw: {})",
            balance.symbol,
            balance.as_decimal(),
            balance.balance
        );
    }
    println!(
        "TNZO: {} base units",
        wallet.get_balance(account.clone()).await?
    );

    let tx = TypedTransaction::new(TxKind::Transfer, serde_json::json!({ "amount": 1000 }))?
        .to(Address::new([0x22; 32]));
    let prepared = client.transactions().prepare(account, &tx).await?;
    println!(
        "dry run of a transfer: nonce {}, digest {}",
        prepared.request["nonce"],
        hex::encode(prepared.digest)
    );
    Ok(())
}
