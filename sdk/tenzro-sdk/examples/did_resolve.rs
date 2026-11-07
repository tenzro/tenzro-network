//! Resolve a did:tenzro identifier: the identity record and the W3C DID
//! Document. Read-only; needs no key.
//!
//! The DID to resolve is `TENZRO_DID`; when unset the example resolves the DID
//! of the node it is talking to (`tenzro_nodeDidDocument`).
//!
//! Creating a DID is deliberately not shown here: the key behind a did:tenzro
//! identifier is generated in a passkey authenticator, a TPM or a Secure
//! Enclave, and registration proves possession of it (see
//! `docs/did-method-tenzro.md` section 3.1). `IdentityClient::register_human`
//! takes that proof as an argument; there is no key-less create call.
//!
//! ```text
//! cargo run --example did_resolve
//!   TENZRO_RPC_URL   the node (default http://127.0.0.1:8545)
//!   TENZRO_DID       the DID to resolve (default: first listed on the node)
//! ```

use tenzro_sdk::TenzroClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint =
        std::env::var("TENZRO_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let client = TenzroClient::new(&endpoint).await?;

    let did = match std::env::var("TENZRO_DID") {
        Ok(did) => did,
        Err(_) => {
            let list = client.identity().list_identities().await?;
            list["identities"][0]["did"]
                .as_str()
                .ok_or("this node lists no identities; set TENZRO_DID")?
                .to_string()
        }
    };
    println!("resolving {did}");

    let doc = client.identity().resolve_did_document(&did).await?;
    println!("document id: {}", doc["id"]);
    if let Some(methods) = doc["verificationMethod"].as_array() {
        for m in methods {
            println!("  key {} ({})", m["id"], m["type"]);
        }
    }
    if doc["deactivated"].as_bool() == Some(true) {
        println!("  this DID is deactivated");
    }

    // The registry record (status, type, key count) behind the document.
    match client.identity().resolve(&did).await {
        Ok(info) => println!("record: status {}, {} key(s)", info.status, info.key_count),
        Err(e) => println!("no registry record on this node: {e}"),
    }
    Ok(())
}
