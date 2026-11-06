//! Talk to one node: read its chain id and a balance, then dry-run a TNZO
//! transfer. The dry run asks the node to encode the transaction's signing
//! payload and checks that it is the transaction built here; nothing is
//! signed or submitted, so it needs no key.
//!
//! ```text
//! cargo run --example local_node
//!   TENZRO_RPC_URL   the node (default http://127.0.0.1:8545, the chain `tenzro dev` serves)
//!   TENZRO_ACCOUNT   the account to read and send from (0x + 64 hex)
//! ```

use tenzro_sdk::{Address, TenzroClient, TxKind, TypedTransaction};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint =
        std::env::var("TENZRO_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let account = match std::env::var("TENZRO_ACCOUNT") {
        Ok(hex) => Address::from_hex(&hex).ok_or("TENZRO_ACCOUNT must be 32 bytes of hex")?,
        Err(_) => Address::new([0x11; 32]),
    };
    let client = TenzroClient::new(&endpoint).await?;

    let chain_id = client.get_chain_id().await?;
    println!(
        "chain id {chain_id}, height {}",
        client.block_number().await?
    );
    println!(
        "balance of {account}: {} wei",
        client.get_balance(account.clone()).await?
    );

    let tx = TypedTransaction::new(TxKind::Transfer, serde_json::json!({ "amount": 1000 }))?
        .to(Address::new([0x22; 32]));
    let prepared = client.transactions().prepare(account, &tx).await?;
    println!(
        "dry run: nonce {}, chain id {}, digest {}",
        prepared.request["nonce"],
        prepared.request["chain_id"],
        hex::encode(prepared.digest)
    );
    Ok(())
}
