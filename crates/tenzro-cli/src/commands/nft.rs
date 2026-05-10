//! NFT management commands for the Tenzro CLI
//!
//! Create collections, mint, transfer, and query NFTs across VMs on the Tenzro Ledger.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// NFT management commands
#[derive(Debug, Subcommand)]
pub enum NftCommand {
    /// Create a new NFT collection
    CreateCollection(NftCreateCollectionCmd),
    /// Mint an NFT in a collection
    Mint(NftMintCmd),
    /// Mint multiple NFTs in a batch
    MintBatch(NftMintBatchCmd),
    /// Transfer an NFT to another address
    Transfer(NftTransferCmd),
    /// Query the owner of an NFT
    Owner(NftOwnerCmd),
    /// Query NFT balance for an address
    Balance(NftBalanceCmd),
    /// Get collection info
    Info(NftInfoCmd),
    /// List NFT collections
    List(NftListCmd),
    /// Register a cross-VM pointer for an NFT collection
    RegisterPointer(NftRegisterPointerCmd),
}

impl NftCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::CreateCollection(cmd) => cmd.execute().await,
            Self::Mint(cmd) => cmd.execute().await,
            Self::MintBatch(cmd) => cmd.execute().await,
            Self::Transfer(cmd) => cmd.execute().await,
            Self::Owner(cmd) => cmd.execute().await,
            Self::Balance(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::RegisterPointer(cmd) => cmd.execute().await,
        }
    }
}

/// Create a new NFT collection
#[derive(Debug, Parser)]
pub struct NftCreateCollectionCmd {
    /// Collection name (e.g. "Tenzro Avatars")
    #[arg(long)]
    name: String,
    /// Collection symbol (e.g. "TAVT")
    #[arg(long)]
    symbol: String,
    /// Creator address (hex)
    #[arg(long)]
    creator: String,
    /// NFT standard: erc721 or erc1155
    #[arg(long, default_value = "erc721")]
    standard: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NftCreateCollectionCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create NFT Collection");
        let spinner = output::create_spinner("Creating collection...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_createNftCollection", serde_json::json!({
            "name": self.name,
            "symbol": self.symbol,
            "creator": self.creator,
            "standard": self.standard,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("NFT collection created successfully!");
        output::print_field("Collection ID", result.get("collection_id").and_then(|v| v.as_str()).unwrap_or("unknown"));
        output::print_field("Name", result.get("name").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Symbol", result.get("symbol").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Standard", result.get("standard").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Creator", result.get("creator").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Mint an NFT in a collection
#[derive(Debug, Parser)]
pub struct NftMintCmd {
    /// Collection ID (hex)
    #[arg(long)]
    collection: String,
    /// Recipient address (hex)
    #[arg(long)]
    to: String,
    /// Token ID
    #[arg(long)]
    token_id: u64,
    /// Token URI (metadata URL)
    #[arg(long)]
    uri: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NftMintCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Mint NFT");
        let spinner = output::create_spinner("Minting NFT...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_mintNft", serde_json::json!({
            "collection": self.collection,
            "to": self.to,
            "token_id": self.token_id,
            "uri": self.uri,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("NFT minted successfully!");
        output::print_field("Collection", result.get("collection").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Token ID", &result.get("token_id").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Owner", result.get("owner").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("URI", result.get("uri").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Mint multiple NFTs in a batch
#[derive(Debug, Parser)]
pub struct NftMintBatchCmd {
    /// Collection ID (hex)
    #[arg(long)]
    collection: String,
    /// Recipient address (hex)
    #[arg(long)]
    to: String,
    /// Comma-separated token IDs (e.g. "1,2,3,4")
    #[arg(long)]
    token_ids: String,
    /// Comma-separated token URIs (e.g. "uri1,uri2,uri3,uri4")
    #[arg(long)]
    uris: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NftMintBatchCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let token_ids: Vec<u64> = self.token_ids
            .split(',')
            .map(|s| s.trim().parse::<u64>())
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let uris: Vec<&str> = self.uris.split(',').map(|s| s.trim()).collect();

        if token_ids.len() != uris.len() {
            anyhow::bail!("Number of token IDs ({}) must match number of URIs ({})", token_ids.len(), uris.len());
        }

        output::print_header("Mint NFT Batch");
        let spinner = output::create_spinner(&format!("Minting {} NFTs...", token_ids.len()));
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_mintNftBatch", serde_json::json!({
            "collection": self.collection,
            "to": self.to,
            "token_ids": token_ids,
            "uris": uris,
        })).await?;

        spinner.finish_and_clear();

        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(token_ids.len() as u64);
        output::print_success(&format!("{} NFTs minted successfully!", count));

        Ok(())
    }
}

/// Transfer an NFT to another address
#[derive(Debug, Parser)]
pub struct NftTransferCmd {
    /// Collection ID (hex)
    #[arg(long)]
    collection: String,
    /// Sender address (hex)
    #[arg(long)]
    from: String,
    /// Recipient address (hex)
    #[arg(long)]
    to: String,
    /// Token ID
    #[arg(long)]
    token_id: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NftTransferCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Transfer NFT");
        let spinner = output::create_spinner("Transferring NFT...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_transferNft", serde_json::json!({
            "collection": self.collection,
            "from": self.from,
            "to": self.to,
            "token_id": self.token_id,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("NFT transferred successfully!");
        output::print_field("From", result.get("from").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("To", result.get("to").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Token ID", &result.get("token_id").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Query the owner of an NFT
#[derive(Debug, Parser)]
pub struct NftOwnerCmd {
    /// Collection ID (hex)
    #[arg(long)]
    collection: String,
    /// Token ID
    #[arg(long)]
    token_id: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NftOwnerCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("NFT Owner");
        let spinner = output::create_spinner("Querying owner...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_nftOwnerOf", serde_json::json!({
            "collection": self.collection,
            "token_id": self.token_id,
        })).await?;

        spinner.finish_and_clear();

        output::print_field("Owner", result.get("owner").and_then(|v| v.as_str()).unwrap_or("unknown"));

        Ok(())
    }
}

/// Query NFT balance for an address
#[derive(Debug, Parser)]
pub struct NftBalanceCmd {
    /// Collection ID (hex)
    #[arg(long)]
    collection: String,
    /// Address to query (hex)
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NftBalanceCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("NFT Balance");
        let spinner = output::create_spinner("Querying balance...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_nftBalanceOf", serde_json::json!({
            "collection": self.collection,
            "address": self.address,
        })).await?;

        spinner.finish_and_clear();

        output::print_field("Address", &self.address);
        output::print_field("Balance", &result.get("balance").and_then(|v| v.as_u64()).unwrap_or(0).to_string());

        Ok(())
    }
}

/// Get NFT collection info
#[derive(Debug, Parser)]
pub struct NftInfoCmd {
    /// Collection ID (hex)
    #[arg(long)]
    collection: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NftInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("NFT Collection Info");
        let spinner = output::create_spinner("Querying collection...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_getNftCollection", serde_json::json!({
            "collection": self.collection,
        })).await?;

        spinner.finish_and_clear();

        output::print_field("Collection ID", result.get("collection_id").and_then(|v| v.as_str()).unwrap_or("unknown"));
        output::print_field("Name", result.get("name").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Symbol", result.get("symbol").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Total Supply", &result.get("total_supply").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Standard", result.get("standard").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Creator", result.get("creator").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// List NFT collections
#[derive(Debug, Parser)]
pub struct NftListCmd {
    /// Maximum collections to list
    #[arg(long, default_value = "50")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NftListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("NFT Collections");
        let spinner = output::create_spinner("Loading collections...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_listNftCollections", serde_json::json!({
            "limit": self.limit,
        })).await?;

        spinner.finish_and_clear();

        if let Some(collections) = result.get("collections").and_then(|v| v.as_array()) {
            if collections.is_empty() {
                output::print_info("No NFT collections found.");
            } else {
                let headers = vec!["Collection ID", "Name", "Symbol", "Supply", "Standard"];
                let mut rows = Vec::new();
                for c in collections {
                    let id = c.get("collection_id").and_then(|v| v.as_str()).unwrap_or("");
                    let truncated_id = if id.len() > 16 {
                        format!("{}...", &id[..16])
                    } else {
                        id.to_string()
                    };
                    rows.push(vec![
                        truncated_id,
                        c.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        c.get("symbol").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        c.get("total_supply").and_then(|v| v.as_u64()).map(|v| v.to_string()).unwrap_or_default(),
                        c.get("standard").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// Register a cross-VM pointer for an NFT collection
#[derive(Debug, Parser)]
pub struct NftRegisterPointerCmd {
    /// Collection ID (hex)
    #[arg(long)]
    collection: String,
    /// Target VM: evm or svm
    #[arg(long)]
    vm: String,
    /// Pointer contract address (EVM) or mint address (SVM)
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NftRegisterPointerCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register NFT Cross-VM Pointer");
        let spinner = output::create_spinner("Registering pointer...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_registerNftPointer", serde_json::json!({
            "collection": self.collection,
            "vm": self.vm,
            "address": self.address,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("NFT pointer registered successfully!");
        output::print_field("Collection", result.get("collection").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("VM", result.get("vm").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Pointer Address", result.get("pointer_address").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}
