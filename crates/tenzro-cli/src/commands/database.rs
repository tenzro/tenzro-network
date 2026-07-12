//! Distributed-database commands. Manage databases the node serves across the
//! local → LAN-cluster → network continuum, adjudicate access, mint managed
//! connection credentials, and run engine-dialect queries.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum DatabaseCommand {
    /// List the database engines this node can serve (Postgres, Qdrant, Milvus,
    /// Valkey, Dgraph, embedded Lance + Tantivy) with their data models,
    /// license, and native-cluster topology
    Engines(EnginesCmd),
    /// Register a database, computing and persisting its partition placement
    /// over the live cluster membership
    Create(CreateCmd),
    /// Show one database descriptor by id
    Get(GetCmd),
    /// List every database this node serves
    List(ListCmd),
    /// List the partition placements of a database
    Partitions(PartitionsCmd),
    /// Grow or shrink a database in place along local → lan_cluster → network
    Rescale(RescaleCmd),
    /// Remove a database and all its partition placements
    Drop(DropCmd),
    /// Check whether a caller may read a database under its access policy
    Authorize(AuthorizeCmd),
    /// Mint a managed-database connection credential scoped to one database
    Connect(ConnectCmd),
    /// Run an engine-dialect query against a database partition
    Query(QueryCmd),
    /// Show per-query pricing and cumulative usage counters for a database
    Usage(UsageCmd),
}

impl DatabaseCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::Engines(cmd) => cmd.execute().await,
            Self::Create(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Partitions(cmd) => cmd.execute().await,
            Self::Rescale(cmd) => cmd.execute().await,
            Self::Drop(cmd) => cmd.execute().await,
            Self::Authorize(cmd) => cmd.execute().await,
            Self::Connect(cmd) => cmd.execute().await,
            Self::Query(cmd) => cmd.execute().await,
            Self::Usage(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct EnginesCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EnginesCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Database Engines");
        let spinner = output::create_spinner("Reading engine catalog...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_listDatabaseEngines", serde_json::json!({})).await;
        spinner.finish_and_clear();

        let value = match result {
            Ok(v) => v,
            Err(e) => {
                output::print_error(&format!("Failed to list engines: {}", e));
                return Ok(());
            }
        };

        println!();
        if let Some(engines) = value.get("engines").and_then(|v| v.as_array()) {
            output::print_field("Engines", &engines.len().to_string());
            for e in engines {
                let id = e.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let name = e.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let version = e.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                let kind = e.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                let license = e.get("license").and_then(|v| v.as_str()).unwrap_or("?");
                let sharding = e.get("sharding").and_then(|v| v.as_str()).unwrap_or("?");
                let models = e
                    .get("data_models")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter().filter_map(|m| m.as_str()).collect::<Vec<_>>().join(", ")
                    })
                    .unwrap_or_default();
                println!();
                output::print_field(id, &format!("{} {}", name, version));
                output::print_field("  Kind", &format!("{} · sharding {}", kind, sharding));
                output::print_field("  Data Models", &models);
                output::print_field("  License", license);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CreateCmd {
    /// Database id (unique within the node)
    database_id: String,
    /// Engine id (postgres | qdrant | milvus | valkey | dgraph | lance | tantivy)
    #[arg(long)]
    engine: String,
    /// Owner DID (sets an owner-only access policy unless --access-policy is given)
    #[arg(long)]
    owner_did: String,
    /// Placement tier
    #[arg(long, default_value = "local")]
    placement: String,
    /// Partition count (forced to 1 for local placement)
    #[arg(long, default_value_t = 1)]
    partitions: usize,
    /// Replica count (forced to 1 for local placement)
    #[arg(long, default_value_t = 1)]
    replicas: usize,
    /// Path to a JSON file with the engine-native config surface
    #[arg(long)]
    engine_config: Option<String>,
    /// Path to a JSON file with a full access-policy object (overrides --owner-did)
    #[arg(long)]
    access_policy: Option<String>,
    /// Path to a JSON file with a confidential seal (network-tier encryption-at-rest)
    #[arg(long)]
    confidential: Option<String>,
    /// Price a non-owner caller pays per query, in the asset's base units
    /// (decimal string; omit for a free database)
    #[arg(long)]
    price_per_query: Option<String>,
    /// Asset the per-query price is denominated in
    #[arg(long, default_value = "TNZO")]
    asset: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CreateCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Create Database: {}", self.database_id));

        let mut params = serde_json::json!({
            "database_id": self.database_id,
            "engine_id": self.engine,
            "owner_did": self.owner_did,
            "placement": self.placement,
            "partitions": self.partitions,
            "replicas": self.replicas,
        });
        if let Some(path) = &self.engine_config {
            params["engine_config"] = read_json_file(path, "engine_config")?;
        }
        if let Some(path) = &self.access_policy {
            params["access_policy"] = read_json_file(path, "access_policy")?;
        }
        if let Some(path) = &self.confidential {
            params["confidential"] = read_json_file(path, "confidential")?;
        }
        if let Some(price) = &self.price_per_query {
            params["pricing"] = serde_json::json!({
                "asset_id": self.asset,
                "price_per_query": price,
            });
        }

        let spinner = output::create_spinner("Computing placement...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_createDatabase", params).await;
        spinner.finish_and_clear();

        match result {
            Ok(value) => {
                println!();
                print_database(value.get("database"));
                print_partitions(value.get("partitions"));
            }
            Err(e) => output::print_error(&format!("Failed to create database: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct GetCmd {
    /// Database id
    database_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GetCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Database: {}", self.database_id));
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> = rpc
            .call("tenzro_getDatabase", serde_json::json!({ "database_id": self.database_id }))
            .await;
        match result {
            Ok(value) => {
                println!();
                print_database(Some(&value));
            }
            Err(e) => output::print_error(&format!("Failed to get database: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Databases");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_listDatabases", serde_json::json!({})).await;
        match result {
            Ok(value) => {
                println!();
                if let Some(n) = value.get("count").and_then(|v| v.as_u64()) {
                    output::print_field("Total", &n.to_string());
                }
                if let Some(dbs) = value.get("databases").and_then(|v| v.as_array()) {
                    for db in dbs {
                        println!();
                        print_database(Some(db));
                    }
                }
            }
            Err(e) => output::print_error(&format!("Failed to list databases: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct PartitionsCmd {
    /// Database id
    database_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PartitionsCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Partitions: {}", self.database_id));
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> = rpc
            .call(
                "tenzro_listDatabasePartitions",
                serde_json::json!({ "database_id": self.database_id }),
            )
            .await;
        match result {
            Ok(value) => {
                println!();
                if let Some(n) = value.get("count").and_then(|v| v.as_u64()) {
                    output::print_field("Partitions", &n.to_string());
                }
                print_partitions(value.get("partitions"));
            }
            Err(e) => output::print_error(&format!("Failed to list partitions: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RescaleCmd {
    /// Database id
    database_id: String,
    /// Owner DID (or a caller holding the write-action capability)
    #[arg(long)]
    caller_did: String,
    /// New placement tier
    #[arg(long)]
    placement: String,
    /// New partition count (defaults to current)
    #[arg(long)]
    partitions: Option<usize>,
    /// New replica count (defaults to current)
    #[arg(long)]
    replicas: Option<usize>,
    /// Write-action AAP capability JWT (for CapabilityRequired policies)
    #[arg(long)]
    capability: Option<String>,
    /// Hex-encoded signed DID envelope proving control of --caller-did
    #[arg(long)]
    envelope: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RescaleCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Rescale Database: {}", self.database_id));

        let mut params = serde_json::json!({
            "database_id": self.database_id,
            "caller_did": self.caller_did,
            "placement": self.placement,
        });
        if let Some(p) = self.partitions {
            params["partitions"] = serde_json::json!(p);
        }
        if let Some(r) = self.replicas {
            params["replicas"] = serde_json::json!(r);
        }
        if let Some(cap) = &self.capability {
            params["capability"] = serde_json::json!(cap);
        }
        if let Some(env) = &self.envelope {
            params["envelope"] = serde_json::json!(env);
        }

        let spinner = output::create_spinner("Recomputing placement...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_rescaleDatabase", params).await;
        spinner.finish_and_clear();

        match result {
            Ok(value) => {
                println!();
                print_database(value.get("database"));
                print_partitions(value.get("partitions"));
            }
            Err(e) => output::print_error(&format!("Failed to rescale database: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DropCmd {
    /// Database id
    database_id: String,
    /// Owner DID (or a caller holding the write-action capability)
    #[arg(long)]
    caller_did: String,
    /// Write-action AAP capability JWT (for CapabilityRequired policies)
    #[arg(long)]
    capability: Option<String>,
    /// Hex-encoded signed DID envelope proving control of --caller-did
    #[arg(long)]
    envelope: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DropCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Drop Database: {}", self.database_id));

        let mut params = serde_json::json!({
            "database_id": self.database_id,
            "caller_did": self.caller_did,
        });
        if let Some(cap) = &self.capability {
            params["capability"] = serde_json::json!(cap);
        }
        if let Some(env) = &self.envelope {
            params["envelope"] = serde_json::json!(env);
        }

        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> = rpc.call("tenzro_dropDatabase", params).await;
        match result {
            Ok(value) => {
                let dropped = value.get("dropped").and_then(|v| v.as_str()).unwrap_or("?");
                output::print_success(&format!("Dropped {}", dropped));
            }
            Err(e) => output::print_error(&format!("Failed to drop database: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AuthorizeCmd {
    /// Database id
    database_id: String,
    /// Caller DID to adjudicate
    #[arg(long)]
    caller_did: String,
    /// AAP capability JWT (for CapabilityRequired policies)
    #[arg(long)]
    capability: Option<String>,
    /// Hex-encoded signed DID envelope proving control of --caller-did
    #[arg(long)]
    envelope: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AuthorizeCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Authorize Read: {}", self.database_id));

        let mut params = serde_json::json!({
            "database_id": self.database_id,
            "caller_did": self.caller_did,
        });
        if let Some(cap) = &self.capability {
            params["capability"] = serde_json::json!(cap);
        }
        if let Some(env) = &self.envelope {
            params["envelope"] = serde_json::json!(env);
        }

        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_authorizeDatabaseRead", params).await;
        match result {
            Ok(value) => {
                println!();
                let authorized =
                    value.get("authorized").and_then(|v| v.as_bool()).unwrap_or(false);
                output::print_field("Authorized", &authorized.to_string());
                if let Some(reason) = value.get("reason").and_then(|v| v.as_str()) {
                    output::print_field("Reason", reason);
                }
            }
            Err(e) => output::print_error(&format!("Failed to authorize: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ConnectCmd {
    /// Database id
    database_id: String,
    /// Owner DID (or a caller holding the write-action capability)
    #[arg(long)]
    caller_did: String,
    /// DID the credential is minted for (defaults to caller_did)
    #[arg(long)]
    bearer_did: Option<String>,
    /// Mint a read-write connection (default read-only)
    #[arg(long)]
    write: bool,
    /// Token time-to-live in seconds
    #[arg(long)]
    ttl_secs: Option<u64>,
    /// Write-action AAP capability JWT (for CapabilityRequired policies)
    #[arg(long)]
    capability: Option<String>,
    /// Hex-encoded signed DID envelope proving control of --caller-did
    #[arg(long)]
    envelope: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ConnectCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Connect Database: {}", self.database_id));

        let mut params = serde_json::json!({
            "database_id": self.database_id,
            "caller_did": self.caller_did,
            "write": self.write,
        });
        if let Some(b) = &self.bearer_did {
            params["bearer_did"] = serde_json::json!(b);
        }
        if let Some(ttl) = self.ttl_secs {
            params["ttl_secs"] = serde_json::json!(ttl);
        }
        if let Some(cap) = &self.capability {
            params["capability"] = serde_json::json!(cap);
        }
        if let Some(env) = &self.envelope {
            params["envelope"] = serde_json::json!(env);
        }

        let spinner = output::create_spinner("Issuing connection credential...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_issueDatabaseConnection", params).await;
        spinner.finish_and_clear();

        match result {
            Ok(value) => {
                println!();
                output::print_field(
                    "Database",
                    value.get("database_id").and_then(|v| v.as_str()).unwrap_or("?"),
                );
                output::print_field(
                    "Engine",
                    value.get("engine_id").and_then(|v| v.as_str()).unwrap_or("?"),
                );
                output::print_field(
                    "Bearer DID",
                    value.get("bearer_did").and_then(|v| v.as_str()).unwrap_or("?"),
                );
                output::print_field(
                    "Mode",
                    value.get("mode").and_then(|v| v.as_str()).unwrap_or("?"),
                );
                if let Some(ttl) = value.get("ttl_secs").and_then(|v| v.as_u64()) {
                    output::print_field("TTL (s)", &ttl.to_string());
                }
                output::print_field(
                    "Query Method",
                    value.get("query_method").and_then(|v| v.as_str()).unwrap_or("?"),
                );
                if let Some(token) = value.get("capability").and_then(|v| v.as_str()) {
                    println!();
                    output::print_field("Capability", token);
                }
            }
            Err(e) => output::print_error(&format!("Failed to issue connection: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct QueryCmd {
    /// Database id
    database_id: String,
    /// Caller DID
    #[arg(long)]
    caller_did: String,
    /// Path to a JSON file with the engine-dialect query body
    #[arg(long)]
    body: String,
    /// Partition index to target
    #[arg(long, default_value_t = 0)]
    partition: usize,
    /// Run as a write (requires the admin action)
    #[arg(long)]
    write: bool,
    /// AAP capability JWT (from `tenzro db connect`)
    #[arg(long)]
    capability: Option<String>,
    /// Hex-encoded signed DID envelope proving control of --caller-did
    #[arg(long)]
    envelope: Option<String>,
    /// Path to a JSON file with a payment credential answering a prior
    /// 402 challenge (paid databases only)
    #[arg(long)]
    payment_credential: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl QueryCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Query Database: {}", self.database_id));

        let body = read_json_file(&self.body, "body")?;
        let mut params = serde_json::json!({
            "database_id": self.database_id,
            "caller_did": self.caller_did,
            "body": body,
            "partition_index": self.partition,
            "write": self.write,
        });
        if let Some(cap) = &self.capability {
            params["capability"] = serde_json::json!(cap);
        }
        if let Some(env) = &self.envelope {
            params["envelope"] = serde_json::json!(env);
        }
        if let Some(path) = &self.payment_credential {
            params["payment_credential"] = read_json_file(path, "payment_credential")?;
        }

        let spinner = output::create_spinner("Running query...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_databaseQuery", params).await;
        spinner.finish_and_clear();

        match result {
            Ok(value) => {
                println!();
                let served = value.get("served_here").and_then(|v| v.as_bool()).unwrap_or(false);
                output::print_field("Served Here", &served.to_string());
                if served {
                    if let Some(res) = value.get("result") {
                        output::print_json(res)?;
                    }
                } else {
                    output::print_info(
                        "This node does not hold the partition. Dial one of its holders:",
                    );
                    if let Some(holders) = value.get("holders").and_then(|v| v.as_array()) {
                        for h in holders {
                            if let Some(s) = h.as_str() {
                                output::print_field("  Holder", s);
                            }
                        }
                    }
                }
            }
            Err(e) => output::print_error(&format!("Query failed: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UsageCmd {
    /// Database id
    database_id: String,
    /// Owner DID (or a caller holding the write-action capability)
    #[arg(long)]
    caller_did: String,
    /// Write-action AAP capability JWT (for CapabilityRequired policies)
    #[arg(long)]
    capability: Option<String>,
    /// Hex-encoded signed DID envelope proving control of --caller-did
    #[arg(long)]
    envelope: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UsageCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Database Usage: {}", self.database_id));

        let mut params = serde_json::json!({
            "database_id": self.database_id,
            "caller_did": self.caller_did,
        });
        if let Some(cap) = &self.capability {
            params["capability"] = serde_json::json!(cap);
        }
        if let Some(env) = &self.envelope {
            params["envelope"] = serde_json::json!(env);
        }

        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> = rpc.call("tenzro_databaseUsage", params).await;
        match result {
            Ok(value) => {
                println!();
                if let Some(pricing) = value.get("pricing") {
                    let asset = pricing.get("asset_id").and_then(|v| v.as_str()).unwrap_or("?");
                    let price =
                        pricing.get("price_per_query").and_then(|v| v.as_str()).unwrap_or("0");
                    output::print_field("Price / Query", &format!("{} {}", price, asset));
                }
                match value.get("usage").filter(|u| !u.is_null()) {
                    Some(usage) => {
                        let g = |k: &str| {
                            usage.get(k).and_then(|v| v.as_u64()).unwrap_or(0).to_string()
                        };
                        output::print_field("Queries", &g("query_count"));
                        output::print_field("Writes", &g("write_count"));
                        output::print_field("Bytes In", &g("bytes_in"));
                        output::print_field("Bytes Out", &g("bytes_out"));
                        output::print_field(
                            "Billed Total",
                            usage.get("billed_total").and_then(|v| v.as_str()).unwrap_or("0"),
                        );
                        output::print_field("Last Query (ms)", &g("last_query_ms"));
                    }
                    None => output::print_info("No queries recorded yet."),
                }
            }
            Err(e) => output::print_error(&format!("Failed to read usage: {}", e)),
        }
        Ok(())
    }
}

fn read_json_file(path: &str, label: &str) -> Result<serde_json::Value> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {} file '{}': {}", label, path, e))?;
    serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("parsing {} file '{}' as JSON: {}", label, path, e))
}

fn print_database(db: Option<&serde_json::Value>) {
    let Some(db) = db else { return };
    let id = db.get("database_id").and_then(|v| v.as_str()).unwrap_or("?");
    let engine = db.get("engine_id").and_then(|v| v.as_str()).unwrap_or("?");
    let placement = db.get("placement").and_then(|v| v.as_str()).unwrap_or("?");
    let partitions = db.get("partitions").and_then(|v| v.as_u64()).unwrap_or(0);
    let replicas = db.get("replicas").and_then(|v| v.as_u64()).unwrap_or(0);
    output::print_field("Database", id);
    output::print_field("  Engine", engine);
    output::print_field(
        "  Placement",
        &format!("{} · {} partitions · {} replicas", placement, partitions, replicas),
    );
    if let Some(policy) = db.get("access_policy") {
        let kind = policy.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
        let owner = policy.get("owner_did").and_then(|v| v.as_str()).unwrap_or("?");
        output::print_field("  Access", &format!("{} · owner {}", kind, owner));
    }
    if let Some(pricing) = db.get("pricing") {
        let asset = pricing.get("asset_id").and_then(|v| v.as_str()).unwrap_or("?");
        let price = pricing.get("price_per_query").and_then(|v| v.as_str()).unwrap_or("0");
        let label = if price == "0" {
            "free".to_string()
        } else {
            format!("{} {} / query", price, asset)
        };
        output::print_field("  Pricing", &label);
    }
    if let Some(conf) = db.get("confidential") {
        if !conf.is_null() {
            let alg = conf.get("wrap_alg").and_then(|v| v.as_str()).unwrap_or("?");
            output::print_field("  Confidential", &format!("sealed · {}", alg));
        }
    }
}

fn print_partitions(partitions: Option<&serde_json::Value>) {
    let Some(arr) = partitions.and_then(|v| v.as_array()) else { return };
    if arr.is_empty() {
        return;
    }
    println!();
    for p in arr {
        let idx = p.get("partition_index").and_then(|v| v.as_u64()).unwrap_or(0);
        let role = p.get("role").and_then(|v| v.as_str()).unwrap_or("?");
        let holders = p
            .get("local_holders")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
            + p.get("network_holders").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        output::print_field(
            &format!("Partition {}", idx),
            &format!("{} · {} holders", role, holders),
        );
    }
}
