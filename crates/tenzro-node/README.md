# Tenzro Node

Full node implementation for Tenzro Network — the AI-Native, Agentic Settlement Protocol. Tenzro Ledger is the L1 settlement layer powered by the TNZO governance token.

## Overview

The `tenzro-node` crate provides the complete node binary that integrates all Tenzro Network subsystems into a unified node capable of participating in the network in various roles.

## Features

- **Multi-Role Support**: Configure as Validator, ModelProvider, TeeProvider, or LightClient
- **Modular Architecture**: Clean separation of concerns across subsystems
- **Health Monitoring**: Real-time health tracking for all subsystems
- **Metrics Collection**: Performance metrics and statistics
- **JSON-RPC API**: Standard API for querying and interacting with the node (490+ methods across 28+ namespaces: blockchain, EVM-compat, accounts, token, models, inference, forecast, vision, text-embedding, segmentation, detection, audio, video, settlement, escrow, agents, identity, network, governance, payments, x402 bazaar, ap2, staking, canton, task marketplace, agent marketplace, token registry, databases, bridge/crosschain, deBridge, wormhole, cct, erc8004, NFT, compliance, events, TEE, ZK, VRF, skill/tool registry, onboarding)
- **MCP Server**: Model Context Protocol server with 414 tools (base + 29 multi-modal AI + 3 AgentBond/insurance + 3 agent-memory) on `rmcp` Streamable HTTP transport at `/mcp`, port 3001
- **A2A Server**: Agent-to-Agent protocol server with 41 skills (JSON-RPC 2.0, SSE streaming, Agent Card at port 3002)
- **Web Verification API**: REST endpoints for ZK proof, TEE attestation, and transaction verification (port 8080)
- **Graceful Shutdown**: Clean shutdown sequence for all subsystems
- **TEE Integration**: Optional Trusted Execution Environment support (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)
- **AI Infrastructure**: Built-in model registry, inference routing, and agent runtime with durable persistence

## Node Roles

### Validator
Participates in consensus and block production using HotStuff-2 BFT consensus.

```bash
tenzro-node --role validator --data-dir ./data/validator
```

### ModelProvider
Serves AI model inference requests to the network.

```bash
tenzro-node --role model-provider --data-dir ./data/provider
```

### TeeProvider
Provides confidential computing services with hardware-rooted attestation.

```bash
tenzro-node --role tee-provider --data-dir ./data/tee
```

### LightClient
Participates in the network without providing services.

```bash
tenzro-node --role light-client --data-dir ./data/light
```

## Installation

From the repository root:

```bash
cargo build --release -p tenzro-node
```

The binary will be available at `target/release/tenzro-node`.

## Usage

### Command-Line Options

```
USAGE:
    tenzro-node [OPTIONS]

OPTIONS:
    -c, --config <FILE>         Path to configuration file
    -d, --data-dir <DIR>        Data directory
    -r, --role <ROLE>           Node role (validator, model-provider, tee-provider, light-client)
    -l, --listen-addr <ADDR>    Network listen address
    -b, --boot-nodes <NODES>    Bootstrap nodes (comma-separated multiaddrs)
        --log-level <LEVEL>     Log level [default: info]
        --rpc-addr <ADDR>       RPC listen address [default: 0.0.0.0:8545]
        --web-addr <ADDR>       Web API listen address [default: 0.0.0.0:8080]
        --mcp-addr <ADDR>       MCP server listen address [default: 0.0.0.0:3001]
        --a2a-addr <ADDR>       A2A server listen address [default: 0.0.0.0:3002]
        --solana-mcp-addr <ADDR>     Solana MCP server [default: 0.0.0.0:3003]
        --ethereum-mcp-addr <ADDR>   Ethereum MCP server [default: 0.0.0.0:3004]
        --canton-mcp-addr <ADDR>     Canton MCP server [default: 0.0.0.0:3005]
        --layerzero-mcp-addr <ADDR>  LayerZero MCP server [default: 0.0.0.0:3006]
        --chainlink-mcp-addr <ADDR>  Chainlink MCP server [default: 0.0.0.0:3007]
        --lifi-mcp-addr <ADDR>       LI.FI MCP server [default: 0.0.0.0:3008]
        --log-format <FMT>      Log format (text, json) [default: text]
        --log-filter <FILTER>   Log filter (e.g. "tenzro_node=debug,tenzro_vm=trace")
    -h, --help                  Print help
    -V, --version               Print version
```

### Configuration File

Create a configuration file (config.toml):

```toml
role = "Validator"
data_dir = "./data/validator"
log_level = "info"
rpc_addr = "0.0.0.0:8545"
web_addr = "0.0.0.0:8080"
mcp_addr = "0.0.0.0:3001"
a2a_addr = "0.0.0.0:3002"
tee_enabled = false
metrics_enabled = true
health_enabled = true

[network]
# Network configuration...

[consensus]
# Consensus configuration (for validators)...
```

Load it with:

```bash
tenzro-node --config config.toml
```

## Architecture

The node orchestrates subsystems in the following startup order:

1. **Storage** - RocksDB-backed persistent state
2. **Network** - libp2p P2P networking layer
3. **TEE** - Trusted Execution Environment (if enabled)
4. **VM Runtime** - Multi-VM execution environment (EVM + SVM + DAML)
5. **Token Economics** - TNZO token, staking, governance, treasury
6. **Wallet** - FROST-Ed25519 threshold wallet service
7. **Consensus** - HotStuff-2 consensus (validators only)
8. **Settlement** - Payment settlement engine
9. **AI Infrastructure** - Model registry, provider management, agent runtime, and swarm manager (durable persistence via `init_ai_infrastructure()`; restored model, agent, and swarm counts logged at startup)
10. **Workflow Runtime** - Multi-party workflow engine (`WorkflowRuntime` = `WorkflowManager` + `PrivacyDomainRegistry` + `FeeRouteRegistry`); hash-chained `WorkflowReceipt` log, Canton mirror via `Tenzro.Workflow.Receipt`, kill switch, policy DSL, operational metrics — see `crates/tenzro-workflow/`
11. **Bridge** - Cross-chain bridge router

Shutdown occurs in reverse order to ensure clean resource cleanup.

### Cross-crate wiring

- **`AgentRuntimeSpendingPolicyResolver`** (`spending_policy_bridge.rs`) — the only place in the workspace that depends on both `tenzro-payments` and `tenzro-agent`. Implements `tenzro_payments::SpendingPolicyResolver::resolve(payer_did)` by looking up the per-machine `SpendingPolicy` on `AgentRuntime` and projecting it into a `SpendingPolicySnapshot`. Wired into `IdentityPaymentBinder::with_spending_policy_resolver()` at startup and consulted by `handle_ap2_validate_mandate_pair` for AP2 cart validation.
- **`StakingSlashingCallback`** — bridges consensus equivocation detection to token slashing (10% stake penalty).
- **`NodeValidatorRegistry`** — implements `tenzro_network::ValidatorRegistry` for peer authentication on validator-only topics (consensus, blocks, attestations).

## JSON-RPC API

The node exposes a JSON-RPC API on the configured RPC address (default: `0.0.0.0:8545`).

### RPC Namespaces (490+ methods, 28+ namespaces)

- **Blockchain**: blockNumber, getBlock, getBlockRange (batch fetch for catch-up sync), getTransaction (returns `status: "pending" | "finalized"` so callers can distinguish in-mempool from block-included transactions), submitBlock
- **Accounts**: createAccount, createWallet (chain-agnostic — see "Wallet model" below), getBalance, getNonce, listAccounts
- **Signing**: tenzro_signMessage, tenzro_signTransaction (server-side signing, returns `{signature, public_key, timestamp, tx_hash}`), tenzro_signAndSendTransaction (atomic sign + submit with live nonce + gas), eth_sendRawTransaction (pre-signed submission requires explicit `signature`, `public_key`, and matching `timestamp`)
- **Token**: tokenBalance, totalSupply
- **Models**: listModels, inferenceRequest, downloadModel, serveModel, stopModel, chat, deleteModel, listModelEndpoints, getModelEndpoint
- **Forecast**: listForecastCatalog, listForecastModels, loadForecastModel, unloadForecastModel, forecast
- **Vision**: listVisionCatalog, listVisionModels, loadVisionModel, unloadVisionModel, visionEmbed, visionSimilarity, visionClassify
- **TextEmbedding**: listTextEmbeddingCatalog, listTextEmbeddingModels, loadTextEmbeddingModel, unloadTextEmbeddingModel, textEmbed
- **Segmentation**: listSegmentationCatalog, listSegmentationModels, loadSegmentationModel, unloadSegmentationModel, segment
- **Detection**: listDetectionCatalog, listDetectionModels, loadDetectionModel, unloadDetectionModel, detect
- **Audio (ASR)**: listAudioCatalog, listAudioModels, loadAudioModel, unloadAudioModel, transcribe
- **Video**: listVideoCatalog, listVideoModels, loadVideoModel, unloadVideoModel, videoEmbed
- **Settlement**: settle, getSettlement
- **Agents**: registerAgent (provisioner mode → server-held FROST-Ed25519 + ML-DSA-65 hybrid wallet, returns `classical_public_key` + `pq_verifying_key_len`; BYOK mode → caller supplies `public_key` (32B Ed25519) + `pq_public_key` (1952B ML-DSA-65), `byok: true`), sendAgentMessage (optional hybrid `signature` (64B Ed25519) + `pq_signature` (3309B ML-DSA-65) — both or neither; mixed-mode rejected)
- **Identity**: registerIdentity, importIdentity, resolveDidDocument, resolveIdentity, participate, forgetIdentity (GDPR Article 17 right-to-erasure — DID must already be `Revoked`)
- **Network**: nodeInfo, peerCount, syncing, hardwareProfile, role
- **Governance**: listProposals, vote, getVotingPower
- **Payments**: createPaymentChallenge, payMpp, payX402, listPaymentSessions, paymentGatewayInfo, listX402Schemes (pluggable scheme registry: `tenzro-hybrid`, `exact-eip3009`, `permit2`, `erc7710`)
- **x402 Bazaar**: x402ProtocolInfo, x402RegisterResource, x402DiscoverResources, x402DeregisterResource, x402VerifyOffer, x402PaymentId — a discovery catalog for paid resources: sellers register listings (resource, scheme, network, asset, pay-to, max amount, tags), buyers browse before hitting a `402`, listing ids derive from `(seller_did, resource)` (re-register is idempotent), plus server-signed offer verification and deterministic `pay_<hex>` idempotency ids
- **AP2 v0.2 (Agent Payments Protocol)**: createAp2Session, ap2SignMandate (Ed25519 sign-side for `checkout` and `payment` mandates), ap2VerifyMandate, ap2ValidateMandatePair (three-axis validation: mandate constraints + DelegationScope + SpendingPolicy)
- **Stripe SPT**: sptIssue (TDIP cap-resolver enforces principal `DelegationScope` + runtime `SpendingPolicy`), sptVerify, with `granted_token.deactivated` webhook cascading into TDIP `apply_remote_revocation` and ERC-8004 ReputationRegistry cross-write on every settled outcome
- **AAP (Agent Access Protocol)**: oauthDiscovery, exchangeToken, introspectToken — OAuth 2.1 + DPoP-bound JWTs (RFC 9449) + RAR (RFC 9396) over `tenzro-auth`
- **ERC-8004 v0.6+ Trustless Agents (cross-VM trio)**: IdentityRegistry — encodeRegister (no-arg overload), encodeRegisterWithUri (`register(string)` overload), encodeRegisterWithMetadata (`register(string,(string,bytes)[])` overload), encodeGetAgent / decodeGetAgent, encodeSetAgentURI, encodeSetAgentWallet, encodeSetMetadata, encodeGetMetadata / decodeGetMetadata, encodeGetAgentURI, encodeGetAgentWallet. ReputationRegistry — encodeFeedback, encodeGetFeedback, encodeGetFeedbackCount, encodeRevokeFeedback, encodeIsFeedbackRevoked, encodeAppendResponse, encodeGetFeedbackResponses. ValidationRegistry — encodeValidationRequest, encodeValidationResponse, encodeGetValidation. All `tenzro_erc8004*`-prefixed; calldata is byte-identical to the native EVM precompiles `0x101a` / `0x101b` / `0x101c`. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — server-allocated, never derivable client-side.
  - **EVM mirror**: canonical OpenZeppelin-ERC721-upgradeable proxies deployed at genesis at `tenzro_identity::erc8004::addresses::{IDENTITY_REGISTRY, REPUTATION_REGISTRY, VALIDATION_REGISTRY}`. TDIP `register_machine_with_fee` dispatches `register(string agentURI)` via the node's `erc8004-system` secp256k1 key in a detached `tokio::spawn`; `Registered(uint256 indexed agentId, string agentURI, address indexed owner)` events flow back into the off-chain DID index in `CF_IDENTITIES` under `erc8004_did_index:` (32-byte hash → u256 agentId) via `process_erc8004_registered_logs` in `event_loop.rs`.
  - **SVM mirror**: uses QuantuLabs' Anchor implementation (`https://github.com/QuantuLabs/erc-8004-svm`). `tenzro-identity::erc8004_svm` emits Anchor-formatted instruction calldata via the `OnChainAgentSvmRegistry` trait; `NativeErc8004SvmMirror` in `crates/tenzro-node/src/erc8004_svm_mirror.rs` buffers payloads to the RocksDB pending-tx queue under `erc8004_svm_pending_tx:` and indexes DID → 32-byte Pubkey under `erc8004_svm_did_index:`. No `solana-sdk` dep is pulled into the monorepo by design — drain to a Solana RPC happens in operator-supplied infrastructure.
  - **DAML mirror**: ships as a Canton package at `vendor/erc8004-daml/daml/Tenzro/Erc8004/{Identity,Reputation,Validation}.daml` (two-party admin+controller signatory model, no `msg.sender` equivalent). `tenzro-identity::erc8004_daml` emits Canton Ledger JSON API v2 `submit-and-wait` commands via the `OnChainAgentDamlRegistry` trait; `NativeErc8004DamlMirror` in `crates/tenzro-node/src/erc8004_daml_mirror.rs` either dispatches via an installed `DamlMirrorTransport` or buffers `serde_json::Value` payloads under `erc8004_daml_pending_tx:` and indexes DID → 8-byte LE u64 agentId under `erc8004_daml_did_index:`. Wired only when `config.erc8004_daml` is present — package ids are SHA-256 of the compiled `.dar` and must be supplied at registry construction time by the operator.
- **Reputation & Approval**: getProviderReputation (provider score), listPendingApprovals / getApproval / decideApproval (out-of-scope agent operation queue)
- **Disputes & Streaming**: getDispute, listDisputesByChannel, chatStream (per-token streaming with optional `channel_id` for micropayment-channel billing)
- **EU AI Act §50 Provenance**: getProvenance — C2PA-style `ProvenanceManifest` keyed by `SHA-256(content_bytes)`, signed by validator block-signing keys (§50(1) chatbot disclosure via `aap_agent` claim, §50(2) provenance manifest, §50(4) deepfake labeling)
- **Staking**: stake, unstake, registerProvider, providerStats
- **Canton**: listCantonDomains, listDamlContracts, submitDamlCommand
- **Multi-Party Workflows**: getWorkflow, getWorkflowLifecycle, listWorkflowsByCreator, listWorkflowsByParticipant, listWorkflowsByStatus, getWorkflowReceipt, listWorkflowReceipts, getFeeRoute, listFeeRoutes, computeFeeRoutePayouts, getPrivacyDomain, listPrivacyDomainsForDid, getWorkflowOperationalMetrics — Canton-native workflow lifecycle, privileged-VM selectors `0x01000040`–`0x0100004B`, hash-chained receipts (`Inline` or `OffloadedDA`), kill-switch suspend/cancel, policy DSL combinators
- **TaskMarketplace**: postTask, listTasks, getTask, cancelTask, submitQuote
- **AgentMarketplace**: listAgentTemplates, registerAgentTemplate, getAgentTemplate, updateAgentTemplate, spawnAgentFromTemplate, runAgentTemplate, rateAgentTemplate, searchAgentTemplates, getAgentTemplateStats
- **TokenRegistry**: createToken, getToken, listTokens, crossVmTransfer, wrapTnzo, getTokenBalance, deployContract
- **Adaptive Burn**: getBurnRateConfig, getSupplyMetrics, getBurnRateRecommendation, listAdaptiveBurnProposals — dial surface plus `AutoProposalGenerator` and EIP-1559 fee-market consumer wired through the governance executor
- **SeedAgent Treasury**: getTreasuryEarmark, getSeedAgentCharter, listSeedAgentCharters, listSeedAgents, getNetworkActivity, getSeedAgentDaemonStatus — earmark, registry, off-chain `SeedAgentDaemon` (6h poll, monthly refill, charter-sunset pause, leader-gate), governance-executor mutation paths, and the `tenzro/seed-agents` gossipsub topic
- **AgentBond / Insurance**: post_agent_bond / get_agent_bond / file_insurance_claim — stake-bonding for agents and insurance pool for cart-mandate fraud
- **Training (Tenzro Train)**: tenzro_training_postTask, listRuns, getRun, getReceipt, enrollTrainer, submitOuterGradient, finalizeRound
- **Storage**: storageStatus, storageStoreObject, storageOpenDeal, storageChargeEpoch, storageDeal, storageSetPricing — content-addressed storage on the iroh data plane, billed per byte-epoch and gated on a proof of retrievability; one coverage budget shared with compute rental
- **Compute**: computeStatus, computeBookRental, computeSettleEpoch, computeGetRental, computeSetPricing — rentable compute against stake, settled per epoch on an availability proof; shares the storage coverage budget
- **MoE**: moeShardMap, moePlanDispatch, moeReplicationPolicy, moeCatalogShape — decentralized expert-shard serving: shard map, top-k dispatch planning, governance-tuned replication policy, catalog topology
- **Discovery & Clustering**: localPeers (mDNS local segment), nodeReachability (`direct` / `relay_only` / `unreachable`), nodeProfile (hardware self-profile: build commit, CPU arch, OS, devices, derived serving capacity / backend / capability key), clusterPlan (deterministic layer-wise LAN cluster placement)
- **Databases**: listDatabaseEngines, createDatabase, getDatabase, listDatabases, getDatabasePartition, listDatabasePartitions, dropDatabase, authorizeDatabaseRead, databaseQuery, rescaleDatabase, issueDatabaseConnection — managed-database protocol layer over an operator-run engine (PostgreSQL / Qdrant / Valkey as thin clients, Lance / Tantivy embedded in-process; Milvus / Dgraph catalog-only). Placement moves a database along local → lan_cluster → network; queries carry the engine's own dialect body; connections are minted as AAP capabilities scoped to a single database; access is gated by `AccessPolicy` + optional confidential seal

### Paid Agent Marketplace

The agent marketplace supports both free (community) and paid (creator-tied) templates end-to-end:

- **Creator identity binding (optional):** at registration, a creator may bind a template to any TDIP identity class — human (`did:tenzro:human:{uuid}`), delegated agent (`did:tenzro:machine:{controller}:{uuid}`), or autonomous agent (`did:tenzro:machine:{uuid}`) — via `creator_did`. The binding is immutable post-registration.
- **Creator payout wallet (mandatory for paid pricing):** any non-`Free` `pricing` requires `creator_wallet`. Registration fails if the wallet is missing. `tenzro_runAgentTemplate` routes the creator share to this address.
- **Pricing models** (`AgentPricingModel`): `Free`, `PerExecution { price }`, `PerToken { price_per_token }`, `Subscription { monthly_rate }`, `RevenueShare { creator_share_bps }`. Compact string form accepted by the RPC: `"free"`, `"per_execution:<u128>"`, `"per_token:<u128>"`, `"subscription:<u128>"`, `"revenue_share:<bps>"`.
- **Network commission:** `MARKETPLACE_COMMISSION_BPS = 500` (5%). On every paid invocation of `tenzro_runAgentTemplate`, `tenzro_useSkill`, and `tenzro_useTool`:
  - `payer_wallet` is debited the full `fee_paid`
  - `commission = fee_paid * 500 / 10_000` is credited to the network treasury
  - `creator_share = fee_paid - commission` is credited to `creator_wallet`
  - `invocation_count` and `total_revenue` on the template are incremented atomically
- **Fee-split report** returned by `tenzro_runAgentTemplate`: `{ template_id, steps_executed, steps_failed, steps_skipped_by_dry_run, fee_paid, commission_bps, network_commission, creator_share, payer_wallet, creator_wallet, treasury, invocation_count, total_revenue }`.
- **Free templates** bypass all fee collection — no commission, no creator wallet required, `fee_paid = 0`.

Reference templates under `crates/tenzro-agent-kit/reference_templates/`:
- `premium_alpha_advisor.json` — **paid** per-execution specialist (5 TNZO, 5%/95% split demonstrated end-to-end)
- 10 additional free reference templates covering payment routing, RWA custody, arbitrage, trade settlement, portfolio management, and yield rebalancing
- **EVM-compat**: eth_blockNumber, eth_getBalance, eth_getTransactionCount, eth_sendRawTransaction, eth_getBlockByNumber, eth_getBlockByHash, eth_chainId, eth_getTransactionReceipt

## Wallet Model

Tenzro wallets are **chain-agnostic by design**. `tenzro_createWallet` provisions a single 2-of-3 FROST-Ed25519 (RFC 9591) threshold wallet that projects into every supported VM (EVM, SVM, Canton/DAML) via the pointer-token model — there is no "Solana wallet" vs "Ethereum wallet" distinction at the protocol layer. One identity, one address, one set of FROST secret shares.

### How apps create wallets

```jsonc
// JSON-RPC: tenzro_createWallet
// Request body — params are ignored; pass {} or omit entirely.
{ "jsonrpc": "2.0", "method": "tenzro_createWallet", "params": {}, "id": 1 }

// Response
{
  "wallet_id": "...",
  "address": "0x...",       // canonical Tenzro address
  "public_key": "...",
  "key_type": "Ed25519",
  "threshold": "2-of-3"
}
```

The same address holds TNZO natively and is the source of truth for all VM projections. Per-chain views and operations are exposed through dedicated RPCs, not through separate wallets:

| Goal | Use |
|---|---|
| Native TNZO transfer on Tenzro Ledger | `tenzro_signAndSendTransaction` (or `eth_sendRawTransaction` for pre-signed) |
| TNZO balance across all VMs | `tenzro_getTokenBalance` |
| ERC-20 / SPL / CIP-56 balance | `tenzro_getTokenBalance` (resolved by token_id, VM-agnostic) |
| Atomic cross-VM token movement (no bridge) | `tenzro_crossVmTransfer` |
| Send to a foreign chain (Ethereum, Solana, Base, …) | `tenzro_bridgeTokens` (LayerZero V2) / `tenzro_ccipSend` (Chainlink CCIP) / deBridge / Wormhole NTT |
| Wrap native TNZO into a VM-specific representation | `tenzro_wrapTnzo` |

### Why no `chain` parameter

Adding a `chain` field would imply Tenzro keeps separate per-chain key material, which it does not. The pointer-token model (Sei V2 architecture) means wTNZO ERC-20 at `0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93`, the wTNZO SPL adapter on SVM, and the CIP-56 DAML holding on Canton all share the **same** underlying native balance through the `TnzoToken` layer. No bridge risk, no liquidity fragmentation, no per-chain wallet provisioning. Apps that prompt the user to "pick a chain" at wallet-creation time are modeling something that doesn't exist on Tenzro.

### Sending and tracking transactions

- `tenzro_signAndSendTransaction` looks up the live nonce and gas price server-side, runs FROST-Ed25519 signing with the wallet's threshold shares, and submits — clients pass `from`, `to`, and `value` (or its alias `amount`).
- The server rejects self-sends (`from == to`) with a `cannot transfer to self` validation error; the desktop wallet form pre-empts this with a client-side guard.
- After submission, `tenzro_getTransaction(hash)` returns the transaction with `status: "pending"` while it sits in the consensus mempool and flips to `status: "finalized"` once it's included in a block. Callers polling immediately after broadcast see `"pending"` rather than `null`, so retry logic can distinguish "not yet finalized" from "unknown hash."

## MCP Server

The node runs a built-in [Model Context Protocol](https://modelcontextprotocol.io) server on port 3001 (configurable via `--mcp-addr`). It uses **Streamable HTTP** transport at `/mcp` endpoint.

**Endpoint:** `POST /mcp`

### Available Tools (200+)

The main Tenzro MCP server registers 414 tools (base + 29 multi-modal AI + 3 AgentBond/insurance: `post_agent_bond`, `get_agent_bond`, `file_insurance_claim` + 3 agent-memory: `memory_grant`, `memory_recall`, `memory_archive`) across wallet, identity, payments, inference, multi-modal AI (forecast, vision, text-embed, segment, detect, transcribe, video), staking, tokens, NFTs, bridges, cross-chain, deBridge, Li.Fi, verification, agents, tasks, skills, tools, compliance, TEE, ZK, VRF, events, and administrative categories. The table below lists representative tools — consult `crates/tenzro-node/src/mcp/server.rs` for the complete authoritative inventory.

| Category | Representative Tools |
|----------|----------------------|
| **Wallet & Ledger** | `create_wallet`, `get_balance`, `send_transaction`, `request_faucet` |
| **Network & Blocks** | `get_node_status`, `get_block`, `get_transaction` |
| **Identity & Delegation** | `register_identity`, `resolve_did`, `set_delegation_scope` |
| **Payments** | `create_payment_challenge`, `verify_payment`, `list_payment_protocols` |
| **AI Models & Inference** | `list_models`, `chat_completion`, `list_model_endpoints` |
| **Multi-Modal AI** | `forecast`, `vision_embed`, `vision_similarity`, `text_embed`, `segment`, `detect`, `transcribe`, `video_embed` (plus catalog/load/unload variants per modality) |
| **Cross-Chain Bridge** | `bridge_tokens`, `get_bridge_routes`, `list_bridge_adapters` |
| **Verification** | `verify_zk_proof`, `verify_vrf_proof`, `generate_vrf_proof` |
| **Staking & Providers** | `stake_tokens`, `unstake_tokens`, `register_provider`, `get_provider_stats` |
| **Tokens & Contracts** | `create_token`, `get_token_info`, `list_tokens`, `deploy_contract`, `cross_vm_transfer`, `wrap_tnzo`, `get_token_balance` |

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "tenzro": {
      "url": "https://mcp.tenzro.network/mcp"
    }
  }
}
```

For a local node, use `http://localhost:3001/mcp`.

See [integrations/mcp/](../../integrations/mcp/) for full documentation.

## A2A Protocol Server

The node runs an [Agent-to-Agent (A2A)](https://a2a-protocol.org) protocol server on port 3002 (configurable via `--a2a-addr`).

### Endpoints

| Endpoint | URL | Description |
|----------|-----|-------------|
| Agent Card | `GET /.well-known/agent.json` | Agent capability discovery |
| A2A RPC | `POST /a2a` | JSON-RPC 2.0 task execution |
| A2A Stream | `POST /a2a/stream` | Server-Sent Events streaming |

### Agent Skills

Skills are exposed by `integrations/a2a/tenzro_a2a_server/agent_card.py` and cover wallet, identity, inference, cortex, settlement, verification, staking, task and agent marketplaces, agent spawning, swarm orchestration, lifecycle, bond/insurance, token, contract, AP2 payments, ERC-8004, Wormhole, CCT, join, NFT, bridge, compliance, crosschain, and events. Consult the agent card module for the authoritative list.

### JSON-RPC Methods

- `message/send` -- Send a message between agents
- `tasks/send` -- Send a message, create or continue a task
- `tasks/get` -- Get task by ID
- `tasks/list` -- List tasks
- `tasks/cancel` -- Cancel a running task

See [integrations/a2a/](../../integrations/a2a/) for full documentation.

## Web Verification API

The node runs a REST API on port 8080 for verification and status:

```
POST /verify/zk-proof          -- Verify ZK proof
POST /verify/tee-attestation   -- Verify TEE attestation
POST /verify/transaction       -- Verify transaction signature
POST /verify/settlement        -- Verify settlement receipt
POST /verify/inference         -- Verify inference result
GET  /verify/health            -- Health check
GET  /health                   -- Health check (alias)
GET  /status                   -- Node status
POST /faucet                   -- Request testnet TNZO tokens
```

## Ecosystem MCP Servers

Five additional MCP servers provide direct blockchain interaction:

| Server | Port | Description |
|--------|------|-------------|
| Solana MCP | 3003 | 14 tools: Jupiter, SPL, Metaplex, Bonfida SNS |
| Ethereum MCP | 3004 | 17 tools: Chainlink, ENS, ERC-20, ERC-8004, EAS |
| Canton MCP | 3005 | 15 tools: DAML, CIP-56, DvP, tokenization |
| LayerZero MCP | 3006 | 21 tools: V2 messaging, OFT, Value Transfer API, Stargate V2 |
| Chainlink MCP | 3007 | 21 tools: CCIP, data feeds, VRF v2.5, PoR, automation |
| LI.FI MCP | 3008 | Cross-chain bridge aggregation |

## Health & Metrics

The node tracks health for all subsystems:

- **Healthy**: All systems operational
- **Degraded**: Some systems experiencing issues but functional
- **Unhealthy**: Critical systems down

Access health status via the `tenzro_nodeInfo` RPC method.

Metrics tracked:
- Blocks processed
- Transactions processed
- Inference requests handled
- Settlements completed
- Peer connections
- Uptime

## Development

### Running Tests

```bash
cargo test -p tenzro-node
```

### Building from Source

```bash
cargo build -p tenzro-node
```

### Running in Development

```bash
cargo run -p tenzro-node -- --role validator --log-level debug
```

## Production Deployment

For production deployment:

1. Build in release mode:
   ```bash
   cargo build --release -p tenzro-node
   ```

2. Create a dedicated user:
   ```bash
   sudo useradd -r -s /bin/false tenzro
   ```

3. Set up data directories:
   ```bash
   sudo mkdir -p /var/lib/tenzro
   sudo chown tenzro:tenzro /var/lib/tenzro
   ```

4. Create a systemd service (see `tenzro-node.service` example)

5. Start the service:
   ```bash
   sudo systemctl start tenzro-node
   sudo systemctl enable tenzro-node
   ```

## License

Licensed under Apache License 2.0.
