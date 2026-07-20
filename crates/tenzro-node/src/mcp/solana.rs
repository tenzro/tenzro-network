use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_handler, tool_router, Json, ServerHandler,
};
use serde::Deserialize;

use super::server::RpcPassthroughOutput;

// ─── Tool parameter structs ───

// DeFi Tools

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SwapParams {
    #[schemars(description = "Input token mint address (e.g. 'So11111111111111111111111111111111111111112' for SOL)")]
    pub input_mint: String,
    #[schemars(description = "Output token mint address (e.g. 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' for USDC)")]
    pub output_mint: String,
    #[schemars(description = "Amount in smallest unit (lamports for SOL, base units for SPL tokens)")]
    pub amount: String,
    #[schemars(description = "Slippage tolerance in basis points (default 50 = 0.5%)")]
    pub slippage_bps: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetPriceParams {
    #[schemars(description = "Token mint address (e.g. 'So11111111111111111111111111111111111111112' for SOL, 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' for USDC)")]
    pub token_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StakeParams {
    #[schemars(description = "Amount of SOL to stake (e.g. 1.5 for 1.5 SOL)")]
    pub amount_sol: f64,
    #[schemars(description = "Validator vote account address to delegate to")]
    pub validator_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetYieldParams {
    #[schemars(description = "Optional protocol filter: 'marinade', 'jito', 'blaze', 'lido', or omit for all")]
    pub protocol: Option<String>,
}

// Token Tools

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetBalanceParams {
    #[schemars(description = "Solana wallet address (base58-encoded public key)")]
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTokenAccountsParams {
    #[schemars(description = "Owner wallet address (base58-encoded public key)")]
    pub owner_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TransferParams {
    #[schemars(description = "Sender wallet address (base58-encoded)")]
    pub from: String,
    #[schemars(description = "Recipient wallet address (base58-encoded)")]
    pub to: String,
    #[schemars(description = "Amount in lamports (1 SOL = 1_000_000_000 lamports)")]
    pub amount_lamports: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTokenInfoParams {
    #[schemars(description = "SPL token mint address")]
    pub mint_address: String,
}

// NFT Tools

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetNftParams {
    #[schemars(description = "NFT mint address")]
    pub mint_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetNftsByOwnerParams {
    #[schemars(description = "Owner wallet address (base58-encoded)")]
    pub owner_address: String,
    #[schemars(description = "Maximum number of results (default 20, max 1000)")]
    pub limit: Option<u32>,
    #[schemars(description = "Page number for pagination (default 1)")]
    pub page: Option<u32>,
}

// Network Tools

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTransactionParams {
    #[schemars(description = "Transaction signature (base58-encoded)")]
    pub signature: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ResolveDomainParams {
    #[schemars(description = "SNS domain to resolve (e.g. 'toly.sol')")]
    pub domain: String,
}

// ─── MCP Server ───

/// Solana MCP server providing 14 tools across 4 categories:
///   - DeFi: swap (Jupiter), price, stake, yield
///   - Tokens: balance, token accounts, transfer, token info
///   - NFTs: get NFT, get NFTs by owner
///   - Network: slot, TPS, transaction, domain resolution

#[derive(Clone)]
pub struct SolanaMcpServer {
    http: reqwest::Client,
    rpc_url: String,
    _tool_router: ToolRouter<SolanaMcpServer>,
}

impl std::fmt::Debug for SolanaMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolanaMcpServer")
            .field("rpc_url", &self.rpc_url)
            .finish()
    }
}

fn err_internal(msg: impl Into<String>) -> ErrorData {
    ErrorData::internal_error(msg.into(), None)
}

fn json_result(value: serde_json::Value) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
    Ok(Json(RpcPassthroughOutput { result: value }))
}

fn text_result(text: impl Into<String>) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
    Ok(Json(RpcPassthroughOutput {
        result: serde_json::json!({ "message": text.into() }),
    }))
}

#[tool_router]
impl SolanaMcpServer {
    pub fn new(rpc_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            rpc_url,
            _tool_router: Self::tool_router(),
        }
    }

    // ─── Helper: Solana JSON-RPC call ───

    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| err_internal(format!("Solana RPC request failed: {}", e)))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read RPC response body: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Solana RPC returned HTTP {}: {}",
                status,
                &text[..text.len().min(500)]
            )));
        }

        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| err_internal(format!("Invalid JSON from Solana RPC: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(err_internal(format!("Solana RPC error: {}", error)));
        }
        Ok(json)
    }

    // ─── DeFi Tools ───

    #[tool(description = "Get a swap quote from Jupiter aggregator for trading between two Solana tokens. Returns route, price impact, and estimated output amount.")]
    async fn solana_swap(
        &self,
        Parameters(params): Parameters<SwapParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let slippage = params.slippage_bps.unwrap_or(50);
        let url = format!(
            "https://api.jup.ag/swap/v1/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}",
            params.input_mint, params.output_mint, params.amount, slippage
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Jupiter quote request failed: {}", e)))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err_internal(format!("Failed to parse Jupiter response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Jupiter API error ({}): {}",
                status, body
            )));
        }

        let result = serde_json::json!({
            "source": "jupiter_swap_v1",
            "input_mint": params.input_mint,
            "output_mint": params.output_mint,
            "input_amount": params.amount,
            "output_amount": body.get("outAmount"),
            "other_amount_threshold": body.get("otherAmountThreshold"),
            "price_impact_pct": body.get("priceImpactPct"),
            "slippage_bps": slippage,
            "route_plan": body.get("routePlan"),
            "swap_mode": body.get("swapMode"),
            "note": "This is a quote only. To execute, sign and submit the swap transaction using the Jupiter swap API with your wallet."
        });
        json_result(result)
    }

    #[tool(description = "Get the current USD price of a Solana token from Jupiter Price API v3. Requires the token mint address (e.g. 'So11111111111111111111111111111111111111112' for SOL).")]
    async fn solana_get_price(
        &self,
        Parameters(params): Parameters<GetPriceParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let url = format!(
            "https://api.jup.ag/price/v3?ids={}",
            params.token_id
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Jupiter price request failed: {}", e)))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err_internal(format!("Failed to parse price response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Jupiter Price API error ({}): {}",
                status, body
            )));
        }

        // v3 response format: { "data": { "<mint_address>": { "price": "123.45", ... } } }
        let data = body.get("data").cloned().unwrap_or(serde_json::json!({}));
        let price = data
            .get(&params.token_id)
            .and_then(|entry| entry.get("price"))
            .cloned();

        let result = serde_json::json!({
            "source": "jupiter_price_v3",
            "token_id": params.token_id,
            "price": price,
            "data": data,
        });
        json_result(result)
    }

    #[tool(description = "Get instructions for staking SOL with a validator. Returns the step-by-step process (does not execute the transaction).")]
    async fn solana_stake(
        &self,
        Parameters(params): Parameters<StakeParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let lamports = (params.amount_sol * 1_000_000_000.0) as u64;
        let result = serde_json::json!({
            "action": "stake_sol",
            "amount_sol": params.amount_sol,
            "amount_lamports": lamports,
            "validator_vote_account": params.validator_address,
            "instructions": [
                {
                    "step": 1,
                    "action": "Create stake account",
                    "program": "Stake11111111111111111111111111111111111111",
                    "description": "Create a new stake account with the specified amount of SOL using StakeInstruction::Initialize"
                },
                {
                    "step": 2,
                    "action": "Delegate stake",
                    "program": "Stake11111111111111111111111111111111111111",
                    "description": format!(
                        "Delegate the stake account to validator {} using StakeInstruction::DelegateStake",
                        params.validator_address
                    )
                },
                {
                    "step": 3,
                    "action": "Wait for activation",
                    "description": "Stake becomes active at the start of the next epoch (typically 2-3 days). Use getStakeActivation RPC to check status."
                }
            ],
            "notes": [
                "Minimum stake amount is 0.01 SOL (rent-exempt minimum for stake account)",
                "Staking rewards are distributed every epoch (~2 days)",
                "To unstake, call StakeInstruction::Deactivate, then Withdraw after cooldown",
                "Consider liquid staking via Marinade (mSOL) or Jito (JitoSOL) for instant liquidity"
            ]
        });
        json_result(result)
    }

    #[tool(description = "Get a static reference table of typical APY ranges for Solana staking protocols (Marinade, Jito, BlazeStake, native staking). These are reference ranges, not a live rate query — verify current rates on each protocol before acting.")]
    async fn solana_get_yield(
        &self,
        Parameters(params): Parameters<GetYieldParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let protocols = serde_json::json!([
            {
                "protocol": "marinade",
                "token": "mSOL",
                "mint": "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So",
                "type": "liquid_staking",
                "estimated_apy_pct": "7.0-8.5",
                "description": "Liquid staking via Marinade Finance. Stake SOL, receive mSOL. Instant unstake available with ~0.3% fee.",
                "website": "https://marinade.finance"
            },
            {
                "protocol": "jito",
                "token": "JitoSOL",
                "mint": "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn",
                "type": "liquid_staking_mev",
                "estimated_apy_pct": "7.5-9.5",
                "description": "Liquid staking with MEV rewards via Jito. Validators run Jito-Solana client for MEV extraction, boosting yields.",
                "website": "https://www.jito.network"
            },
            {
                "protocol": "blaze",
                "token": "bSOL",
                "mint": "bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1",
                "type": "liquid_staking",
                "estimated_apy_pct": "6.5-8.0",
                "description": "Liquid staking via BlazeStake. Custom validator delegation, SolBlaze governance.",
                "website": "https://stake.solblaze.org"
            },
            {
                "protocol": "native_staking",
                "token": "SOL",
                "mint": "So11111111111111111111111111111111111111112",
                "type": "native_staking",
                "estimated_apy_pct": "6.0-7.5",
                "description": "Native SOL staking directly to a validator. No liquid token. Epoch-based rewards, ~2 day unstake cooldown.",
                "website": "https://solana.com/staking"
            },
            {
                "protocol": "lido",
                "token": "stSOL",
                "mint": "7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj",
                "type": "liquid_staking",
                "estimated_apy_pct": "6.5-7.5",
                "description": "Lido on Solana liquid staking (winding down — check status before use).",
                "website": "https://solana.lido.fi"
            }
        ]);

        let filtered = if let Some(ref protocol_filter) = params.protocol {
            let filter_lower = protocol_filter.to_lowercase();
            let arr = protocols.as_array().unwrap();
            let filtered_vec: Vec<&serde_json::Value> = arr
                .iter()
                .filter(|p| {
                    p.get("protocol")
                        .and_then(|v| v.as_str())
                        .map(|s| s.contains(&filter_lower))
                        .unwrap_or(false)
                })
                .collect();
            serde_json::json!(filtered_vec)
        } else {
            protocols
        };

        let result = serde_json::json!({
            "source": "static_reference_table",
            "note": "The APY ranges are a static reference, not a live query. Actual yield fluctuates with network conditions, validator performance, and MEV revenue — verify the current rate on each protocol's website before acting on it.",
            "protocols": filtered,
        });
        json_result(result)
    }

    // ─── Token Tools ───

    #[tool(description = "Get the native SOL balance of a Solana wallet address")]
    async fn solana_get_balance(
        &self,
        Parameters(params): Parameters<GetBalanceParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_result = self
            .rpc_call("getBalance", serde_json::json!([params.address]))
            .await?;

        let value = rpc_result
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let sol = value as f64 / 1_000_000_000.0;

        let result = serde_json::json!({
            "address": params.address,
            "balance_lamports": value,
            "balance_sol": sol,
        });
        json_result(result)
    }

    #[tool(description = "Get all SPL token accounts owned by a Solana wallet address, including balances and mint addresses")]
    async fn solana_get_token_accounts(
        &self,
        Parameters(params): Parameters<GetTokenAccountsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_result = self
            .rpc_call(
                "getTokenAccountsByOwner",
                serde_json::json!([
                    params.owner_address,
                    { "programId": "TokenkegQEqKkvXjBaGR7mN8rHTJRNijDCGkjJqLFNMYbga" },
                    { "encoding": "jsonParsed" }
                ]),
            )
            .await?;

        let accounts = rpc_result
            .get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(serde_json::json!([]));

        let count = accounts.as_array().map(|a| a.len()).unwrap_or(0);

        let result = serde_json::json!({
            "owner": params.owner_address,
            "token_accounts": accounts,
            "count": count,
        });
        json_result(result)
    }

    #[tool(description = "Get instructions for transferring SOL between two addresses. Returns the transaction structure (does not execute).")]
    async fn solana_transfer(
        &self,
        Parameters(params): Parameters<TransferParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let lamports: u64 = params
            .amount_lamports
            .parse()
            .map_err(|e| err_internal(format!("Invalid amount_lamports: {}", e)))?;
        let sol = lamports as f64 / 1_000_000_000.0;

        let result = serde_json::json!({
            "action": "transfer_sol",
            "from": params.from,
            "to": params.to,
            "amount_lamports": lamports,
            "amount_sol": sol,
            "instruction": {
                "program": "11111111111111111111111111111111",
                "type": "SystemProgram::Transfer",
                "accounts": [
                    { "pubkey": params.from, "is_signer": true, "is_writable": true },
                    { "pubkey": params.to, "is_signer": false, "is_writable": true }
                ],
                "data_description": "Transfer instruction with u64 lamport amount in little-endian"
            },
            "estimated_fee_lamports": 5000,
            "note": "To execute, build a Transaction with this instruction, sign with the sender's keypair, and submit via sendTransaction RPC."
        });
        json_result(result)
    }

    #[tool(description = "Get metadata for an SPL token by its mint address, including name, symbol, decimals, and logo from the Jupiter token list")]
    async fn solana_get_token_info(
        &self,
        Parameters(params): Parameters<GetTokenInfoParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let url = "https://token.jup.ag/strict";
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Jupiter token list request failed: {}", e)))?;

        let tokens: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err_internal(format!("Failed to parse token list: {}", e)))?;

        let mint_lower = params.mint_address.to_lowercase();
        let found = tokens
            .as_array()
            .and_then(|arr| {
                arr.iter().find(|t| {
                    t.get("address")
                        .and_then(|a| a.as_str())
                        .map(|a| a.to_lowercase() == mint_lower)
                        .unwrap_or(false)
                })
            })
            .cloned();

        match found {
            Some(token) => {
                let result = serde_json::json!({
                    "source": "jupiter_token_list_strict",
                    "mint": params.mint_address,
                    "name": token.get("name"),
                    "symbol": token.get("symbol"),
                    "decimals": token.get("decimals"),
                    "logo_uri": token.get("logoURI"),
                    "tags": token.get("tags"),
                    "extensions": token.get("extensions"),
                });
                json_result(result)
            }
            None => {
                // Fall back to on-chain mint account data
                let rpc_result = self
                    .rpc_call(
                        "getAccountInfo",
                        serde_json::json!([
                            params.mint_address,
                            { "encoding": "jsonParsed" }
                        ]),
                    )
                    .await?;

                let account = rpc_result
                    .get("result")
                    .and_then(|r| r.get("value"))
                    .cloned()
                    .unwrap_or(serde_json::json!(null));

                let result = serde_json::json!({
                    "source": "solana_rpc_on_chain",
                    "mint": params.mint_address,
                    "note": "Token not found in Jupiter strict list. Showing raw on-chain account data.",
                    "account_info": account,
                });
                json_result(result)
            }
        }
    }

    // ─── NFT Tools ───

    #[tool(description = "Get NFT metadata using the Metaplex DAS (Digital Asset Standard) API. Requires a Helius API key set via HELIUS_API_KEY env var, or returns the call pattern for manual use.")]
    async fn solana_get_nft(
        &self,
        Parameters(params): Parameters<GetNftParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let api_key = std::env::var("HELIUS_API_KEY").unwrap_or_default();
        if api_key.is_empty() {
            let result = serde_json::json!({
                "error": "HELIUS_API_KEY environment variable not set",
                "mint_address": params.mint_address,
                "call_pattern": {
                    "method": "POST",
                    "url": "https://mainnet.helius-rpc.com/?api-key=<YOUR_API_KEY>",
                    "body": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getAsset",
                        "params": { "id": params.mint_address }
                    }
                },
                "note": "Set HELIUS_API_KEY env var to enable direct NFT lookups, or use the call pattern above with your own API key."
            });
            return json_result(result);
        }

        let das_url = format!("https://mainnet.helius-rpc.com/?api-key={}", api_key);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAsset",
            "params": { "id": params.mint_address }
        });

        let resp = self
            .http
            .post(&das_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| err_internal(format!("Helius DAS request failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err_internal(format!("Failed to parse DAS response: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(err_internal(format!("DAS API error: {}", error)));
        }

        let asset = json.get("result").cloned().unwrap_or(serde_json::json!(null));
        let result = serde_json::json!({
            "source": "helius_das_api",
            "mint_address": params.mint_address,
            "asset": asset,
        });
        json_result(result)
    }

    #[tool(description = "Get all NFTs (compressed and standard) owned by a Solana address using the Metaplex DAS API. Requires HELIUS_API_KEY env var.")]
    async fn solana_get_nfts_by_owner(
        &self,
        Parameters(params): Parameters<GetNftsByOwnerParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let api_key = std::env::var("HELIUS_API_KEY").unwrap_or_default();
        if api_key.is_empty() {
            let limit = params.limit.unwrap_or(20);
            let page = params.page.unwrap_or(1);
            let result = serde_json::json!({
                "error": "HELIUS_API_KEY environment variable not set",
                "owner_address": params.owner_address,
                "call_pattern": {
                    "method": "POST",
                    "url": "https://mainnet.helius-rpc.com/?api-key=<YOUR_API_KEY>",
                    "body": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getAssetsByOwner",
                        "params": {
                            "ownerAddress": params.owner_address,
                            "page": page,
                            "limit": limit
                        }
                    }
                },
                "note": "Set HELIUS_API_KEY env var to enable direct NFT lookups."
            });
            return json_result(result);
        }

        let das_url = format!("https://mainnet.helius-rpc.com/?api-key={}", api_key);
        let limit = params.limit.unwrap_or(20).min(1000);
        let page = params.page.unwrap_or(1);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAssetsByOwner",
            "params": {
                "ownerAddress": params.owner_address,
                "page": page,
                "limit": limit
            }
        });

        let resp = self
            .http
            .post(&das_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| err_internal(format!("Helius DAS request failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err_internal(format!("Failed to parse DAS response: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(err_internal(format!("DAS API error: {}", error)));
        }

        let result_data = json.get("result").cloned().unwrap_or(serde_json::json!(null));
        let total = result_data
            .get("total")
            .and_then(|t| t.as_u64())
            .unwrap_or(0);
        let items = result_data
            .get("items")
            .cloned()
            .unwrap_or(serde_json::json!([]));

        let result = serde_json::json!({
            "source": "helius_das_api",
            "owner": params.owner_address,
            "total": total,
            "page": page,
            "limit": limit,
            "items": items,
        });
        json_result(result)
    }

    // ─── Network Tools ───

    #[tool(description = "Get the current slot height of the Solana network")]
    async fn solana_get_slot(
        &self,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_result = self
            .rpc_call("getSlot", serde_json::json!([]))
            .await?;

        let slot = rpc_result
            .get("result")
            .and_then(|r| r.as_u64())
            .unwrap_or(0);

        let result = serde_json::json!({
            "slot": slot,
            "rpc": self.rpc_url,
        });
        json_result(result)
    }

    #[tool(description = "Get the current transactions per second (TPS) on the Solana network by sampling recent performance data")]
    async fn solana_get_tps(
        &self,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_result = self
            .rpc_call(
                "getRecentPerformanceSamples",
                serde_json::json!([5]),
            )
            .await?;

        let samples = rpc_result
            .get("result")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();

        let mut total_txs: u64 = 0;
        let mut total_secs: u64 = 0;
        for sample in &samples {
            let num_txs = sample
                .get("numTransactions")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let sample_period = sample
                .get("samplePeriodSecs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            total_txs += num_txs;
            total_secs += sample_period;
        }

        let avg_tps = if total_secs > 0 {
            total_txs as f64 / total_secs as f64
        } else {
            0.0
        };

        let result = serde_json::json!({
            "average_tps": format!("{:.1}", avg_tps),
            "samples_analyzed": samples.len(),
            "total_transactions": total_txs,
            "total_period_secs": total_secs,
            "raw_samples": samples,
        });
        json_result(result)
    }

    #[tool(description = "Get details of a Solana transaction by its signature, including status, block time, and instructions")]
    async fn solana_get_transaction(
        &self,
        Parameters(params): Parameters<GetTransactionParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let rpc_result = self
            .rpc_call(
                "getTransaction",
                serde_json::json!([
                    params.signature,
                    { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }
                ]),
            )
            .await?;

        let tx = rpc_result
            .get("result")
            .cloned()
            .unwrap_or(serde_json::json!(null));

        if tx.is_null() {
            return text_result(format!(
                "Transaction not found: {}. It may not be confirmed yet or the signature may be invalid.",
                params.signature
            ));
        }

        let result = serde_json::json!({
            "signature": params.signature,
            "slot": tx.get("slot"),
            "block_time": tx.get("blockTime"),
            "meta": tx.get("meta"),
            "transaction": tx.get("transaction"),
        });
        json_result(result)
    }

    #[tool(description = "Resolve a .sol (Solana Name Service) domain to its owner wallet address using the Bonfida SNS proxy")]
    async fn solana_resolve_domain(
        &self,
        Parameters(params): Parameters<ResolveDomainParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let domain = params.domain.trim_end_matches(".sol");
        let url = format!(
            "https://sns-sdk-proxy.bonfida.workers.dev/resolve/{}",
            domain
        );

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("SNS resolve request failed: {}", e)))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err_internal(format!("Failed to parse SNS response: {}", e)))?;

        if !status.is_success() {
            return text_result(format!(
                "Domain '{}.sol' could not be resolved. It may not be registered. API response: {}",
                domain, body
            ));
        }

        let result = serde_json::json!({
            "source": "bonfida_sns_proxy",
            "domain": format!("{}.sol", domain),
            "result": body,
        });
        json_result(result)
    }
}

// ─── ServerHandler ───

#[tool_handler]
impl ServerHandler for SolanaMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let mut impl_info = Implementation::default();
        impl_info.name = "tenzro-solana".into();
        impl_info.title = Some("Tenzro Solana MCP Server".into());
        impl_info.version = env!("CARGO_PKG_VERSION").into();
        impl_info.description = Some(
            "Solana blockchain tools — DeFi (Jupiter), tokens (SPL), NFTs (Metaplex), network queries"
                .into(),
        );
        impl_info.website_url = Some("https://tenzro.com".into());
        info.server_info = impl_info;
        info.instructions = Some(
            "Tenzro Solana MCP Server — interact with the Solana blockchain.\n\n\
             TOOLS BY CATEGORY:\n\n\
             DeFi (Jupiter):\n\
             - solana_swap — Get swap quote from Jupiter aggregator\n\
             - solana_get_price — Get token USD price from Jupiter\n\
             - solana_stake — Get SOL staking instructions for a validator\n\
             - solana_get_yield — Get yield/APY for Solana DeFi protocols\n\n\
             Tokens (SPL):\n\
             - solana_get_balance — Get native SOL balance\n\
             - solana_get_token_accounts — Get all SPL token accounts for an owner\n\
             - solana_transfer — Get SOL transfer instruction details\n\
             - solana_get_token_info — Get token metadata from Jupiter token list\n\n\
             NFTs (Metaplex DAS):\n\
             - solana_get_nft — Get NFT metadata by mint address\n\
             - solana_get_nfts_by_owner — Get all NFTs owned by an address\n\n\
             Network:\n\
             - solana_get_slot — Get current slot height\n\
             - solana_get_tps — Get current network TPS\n\
             - solana_get_transaction — Get transaction details by signature\n\
             - solana_resolve_domain — Resolve .sol domain to wallet address"
                .to_string(),
        );
        info
    }
}

// ─── Server startup ───

/// Start the Solana MCP server on the given address using Streamable HTTP transport.
/// This is a standalone server (no OAuth, no Tenzro node dependency) that proxies
/// Solana JSON-RPC calls and aggregates DeFi/NFT data from public APIs.
pub fn default_solana_rpc_url() -> String {
    let key = std::env::var("DRPC_API_KEY").unwrap_or_default();
    if key.is_empty() {
        "https://api.mainnet-beta.solana.com".to_string()
    } else {
        format!("https://lb.drpc.live/solana/{}", key)
    }
}

pub async fn start_solana_mcp_server(
    listen_addr: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| default_solana_rpc_url());
    let (_keep_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    start_solana_mcp_server_with_rpc_and_shutdown(listen_addr, rpc_url, shutdown_rx).await
}

/// Start the Solana MCP server with a custom RPC URL.
pub async fn start_solana_mcp_server_with_rpc(
    listen_addr: String,
    rpc_url: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_keep_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    start_solana_mcp_server_with_rpc_and_shutdown(listen_addr, rpc_url, shutdown_rx).await
}

/// Start the Solana MCP server with a custom RPC URL and graceful-shutdown
/// channel. When the broadcast sender fires, axum stops accepting new
/// connections and lets in-flight requests drain.
pub async fn start_solana_mcp_server_with_rpc_and_shutdown(
    listen_addr: String,
    rpc_url: String,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpService, StreamableHttpServerConfig,
    };

    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "0.0.0.0".to_string(),
            "solana-mcp.tenzro.xyz".to_string(),
        ]);

    let rpc = rpc_url.clone();
    let service = StreamableHttpService::new(
        move || Ok(SolanaMcpServer::new(rpc.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(tower::limit::ConcurrencyLimitLayer::new(100))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(2 * 1024 * 1024));
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        addr = %listen_addr,
        tools = 14,
        rpc = %rpc_url,
        mode = "stateless-json",
        "Solana MCP Server listening (endpoint: /mcp)"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            tracing::info!("Solana MCP server shutting down gracefully");
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_parameter_schemas() {
        let _schema = schemars::schema_for!(SwapParams);
        let _schema = schemars::schema_for!(GetPriceParams);
        let _schema = schemars::schema_for!(StakeParams);
        let _schema = schemars::schema_for!(GetYieldParams);
        let _schema = schemars::schema_for!(GetBalanceParams);
        let _schema = schemars::schema_for!(GetTokenAccountsParams);
        let _schema = schemars::schema_for!(TransferParams);
        let _schema = schemars::schema_for!(GetTokenInfoParams);
        let _schema = schemars::schema_for!(GetNftParams);
        let _schema = schemars::schema_for!(GetNftsByOwnerParams);
        let _schema = schemars::schema_for!(GetTransactionParams);
        let _schema = schemars::schema_for!(ResolveDomainParams);
    }

    #[test]
    fn test_server_creation() {
        let url = default_solana_rpc_url();
        let server = SolanaMcpServer::new(url.clone());
        assert_eq!(server.rpc_url, url);
    }

    #[test]
    fn test_server_info() {
        let server = SolanaMcpServer::new(default_solana_rpc_url());
        let info = server.get_info();
        assert_eq!(info.server_info.name, "tenzro-solana");
        assert_eq!(
            info.server_info.title.as_deref(),
            Some("Tenzro Solana MCP Server")
        );
    }
}
