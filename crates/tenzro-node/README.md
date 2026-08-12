# Tenzro Node

Full node implementation for Tenzro Network — the AI-Native, Agentic Settlement Protocol. Tenzro Ledger is the settlement layer powered by the TNZO governance token.

## Overview

The `tenzro-node` crate provides the complete node binary that integrates all Tenzro Network subsystems into a unified node capable of participating in the network in various roles.

## Features

- **Multi-Role Support**: Configure as Validator, ModelProvider, TeeProvider, or LightClient
- **Modular Architecture**: Clean separation of concerns across subsystems
- **Health Monitoring**: Real-time health tracking for all subsystems
- **Metrics Collection**: Performance metrics and statistics
- **JSON-RPC API**: Standard API for querying and interacting with the node (855 methods across 31+ namespaces: blockchain, EVM-compat, accounts, token, models, inference, forecast, vision, text-embedding, segmentation, detection, audio, video, generative media, settlement, escrow, agents, identity, network, governance, payments, x402 bazaar, ap2, staking, canton, task marketplace, agent marketplace, token registry, databases, app hosting (sites, functions, machines, leases), bridge/crosschain, deBridge, wormhole, cct, erc8004, NFT, compliance, events, TEE, ZK, VRF, skill/tool registry, onboarding)
- **OpenAI-compatible HTTP**: mounted on the same port as the JSON-RPC surface — `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/images/generations`, `/v1/images/edits`, `/v1/videos`, `/v1/audio/transcriptions`, plus the Tenzro-modality routes `/v1/tenzro/{forecasts,detections,segmentations,video/embeddings}` and the rich-shape stream at `/chat-stream`. All of them sit behind the HTTP 402 payment gate when payments are enabled
- **MCP Server**: Model Context Protocol server with 526 tools (base + 29 multi-modal AI + 6 generative media + 8 distributed MoE serving + 29 app hosting + 3 AgentBond/insurance + 3 agent-memory) on `rmcp` Streamable HTTP transport at `/mcp`, port 3001
- **A2A Server**: Agent-to-Agent protocol server with 40 skills (JSON-RPC 2.0, SSE streaming, Agent Card at port 3002)
- **Web Verification API**: REST endpoints for ZK proof, TEE attestation, and transaction verification (port 8080)
- **Graceful Shutdown**: Clean shutdown sequence for all subsystems
- **TEE Integration**: Optional Trusted Execution Environment support (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)
- **AI Infrastructure**: Built-in model registry, inference routing, and agent runtime with durable persistence
- **Fail-closed access hardening**: HTTP RPC / web / MCP-sidecar binds default to loopback (off-box access is opt-in); the iroh overlay is credential-gated per ALPN (MCP allowlist, `moe/execute` gate, `tenzro/infer` admission). Inference admission (`inference_admission.rs`) classifies each request by subscription api-key / rental service-key / model visibility before the x402 charge; database and storage resources share one per-resource `ResourceAccess` (Open / Gated / Private) authorization gate (`resource_authz.rs`). The node-level firewall backstop is documented in [`docs/NODE-FIREWALL.md`](../../docs/NODE-FIREWALL.md)

## Node Roles

`--roles` takes a comma-separated list. A node serves any combination of
roles under a single stake.

### Validator
Participates in consensus and block production using HotStuff-2 BFT consensus.

```bash
tenzro-node --roles validator --data-dir ./data/validator
```

### ModelProvider
Serves AI model inference requests to the network.

```bash
tenzro-node --roles model-provider --data-dir ./data/provider
```

### TeeProvider
Provides confidential computing services with hardware-rooted attestation.

```bash
tenzro-node --roles tee-provider --data-dir ./data/tee
```

### LightClient
Participates in the network without providing services.

```bash
tenzro-node --roles light-client --data-dir ./data/light
```

### Combined
A single node can validate, serve inference, and hold storage at once.

```bash
tenzro-node --roles validator,ai,storage --data-dir ./data/node
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
    -r, --roles <ROLES>         Node roles, comma-separated (validator, ai/model-provider,
                                compute/gpu, storage, cloud, tee/tee-provider,
                                edge/ingress, fullnode, archive, bootstrap/seed,
                                micro/user, light)
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
12. **App Hosting** - App registry (`app_registry`), static sites (`sites`), `wasi:http` functions (`functions`), Firecracker machines (`machines`), the `ingress` router that resolves a hostname to whichever of the three answers, and the `placement` engine that decides which nodes hold a lease
13. **Databases** - `db_engine_registry` + `db_engines` + `db_holder_dispatch`, the node-side surface over `tenzro-database`
14. **Storage & Compute Rental** - `storage_provider_runtime` (content-addressed artifact holding and hash recording), `compute_rental_runtime` (accelerator leases), `cluster_serving_runtime` (LAN pipeline serving over `tenzro-cluster`)
15. **Inference Dispatch** - `infer` and `moe` — the request path into `tenzro-model`, including distributed mixture-of-experts dispatch — plus `network_catalog`, the gossiped view of which models the network can serve
16. **DA Committee** - `da_committee` + `da_committee_surface`, the sampling committee over offloaded receipt payloads

Shutdown occurs in reverse order to ensure clean resource cleanup.

### Cross-crate wiring

- **`AgentRuntimeSpendingPolicyResolver`** (`spending_policy_bridge.rs`) — the only place in the workspace that depends on both `tenzro-payments` and `tenzro-agent`. Implements `tenzro_payments::SpendingPolicyResolver::resolve(payer_did)` by looking up the per-machine `SpendingPolicy` on `AgentRuntime` and projecting it into a `SpendingPolicySnapshot`. Wired into `IdentityPaymentBinder::with_spending_policy_resolver()` at startup and consulted by `handle_ap2_validate_mandate_pair` for AP2 cart validation.
- **`StakingSlashingCallback`** — bridges consensus equivocation detection to token slashing (10% stake penalty).
- **`NodeValidatorRegistry`** — implements `tenzro_network::ValidatorRegistry` for peer authentication on validator-only topics (consensus, blocks, attestations).

## JSON-RPC API

The node exposes a JSON-RPC API on the configured RPC address (default: `0.0.0.0:8545`).

### RPC Namespaces (855 methods, 31+ namespaces)

- **Blockchain**: blockNumber, getBlock, getBlockRange (batch fetch for catch-up sync), getTransaction (returns `status: "pending" | "finalized"` so callers can distinguish in-mempool from block-included transactions), submitBlock
- **Accounts**: createAccount, createWallet (chain-agnostic — see "Wallet model" below), getBalance, getNonce, listAccounts
- **Signing**: tenzro_signMessage, tenzro_signTransaction (server-side signing, returns `{signature, public_key, timestamp, tx_hash}`), tenzro_signAndSendTransaction (atomic sign + submit with live nonce + gas), eth_sendRawTransaction (pre-signed submission requires explicit `signature`, `public_key`, and matching `timestamp`)
- **Token**: tokenBalance, totalSupply
- **Models**: listModels, inferenceRequest, downloadModel, serveModel, stopModel, chat, deleteModel, listModelEndpoints, getModelEndpoint
- **Intent Routing**: routeIntent, recordRouteOutcome, routeDifficultyStats, getRouterMetrics — a caller states what it wants (use case, budget, quality floor, token estimates) and the `MetaRouter` picks the model. Candidates come from both the operator's own catalog and `network_catalog`, the gossiped set of signed offers other providers are serving, so the winning offer names its own payee and the settlement split follows from it. `routeIntent` clusters the prompt and scores each candidate against that cluster's observed outcome history, giving cold models an optimism bonus so they are tried rather than starved; `recordRouteOutcome` feeds the result back
- **Forecast**: listForecastCatalog, listForecastModels, loadForecastModel, unloadForecastModel, forecast
- **Vision**: listVisionCatalog, listVisionModels, loadVisionModel, unloadVisionModel, visionEmbed, visionSimilarity, visionClassify
- **TextEmbedding**: listTextEmbeddingCatalog, listTextEmbeddingModels, loadTextEmbeddingModel, unloadTextEmbeddingModel, textEmbed
- **Segmentation**: listSegmentationCatalog, listSegmentationModels, loadSegmentationModel, unloadSegmentationModel, segment
- **Detection**: listDetectionCatalog, listDetectionModels, loadDetectionModel, unloadDetectionModel, detect
- **Audio (ASR)**: listAudioCatalog, listAudioModels, loadAudioModel, unloadAudioModel, transcribe
- **Video**: listVideoCatalog, listVideoModels, loadVideoModel, unloadVideoModel, videoEmbed
- **Generative Media**: tenzro_mediaGen_listCatalog, quote, postJob, getJob, listJobs, cancelJob, enrollWorker, listWorkers, claimJob, markRunning, failJob, recordHandoff, submitReceipt, getReceipt, fetchInput, publishOutput, fetchOutput, fetchLatent — image and video generation priced by the pixel-step (`width × height × steps × frames`). The node owns the job queue, the worker registry, the pricing, and the signed receipts; the denoising loop runs in the Python worker at `integrations/media_gen/`, so no tensor library enters the Rust workspace. A model whose catalog entry carries an `expert_pair` splits at a timestep boundary: the high-noise worker renders the prefix, commits to one intermediate latent via `recordHandoff`, and its partner finishes and decodes — two 48 GB accelerators serve a model needing 80 GB, with payment split by the steps each half completed. Enrollment is where media-gen license terms are held, because the node never loads the weights
- **Settlement**: settle, getSettlement
- **Agents**: registerAgent (provisioner mode → server-held FROST-Ed25519 + ML-DSA-65 hybrid wallet, returns `classical_public_key` + `pq_verifying_key_len`; BYOK mode → caller supplies `public_key` (32B Ed25519) + `pq_public_key` (1952B ML-DSA-65), `byok: true`), sendAgentMessage (optional hybrid `signature` (64B Ed25519) + `pq_signature` (3309B ML-DSA-65) — both or neither; mixed-mode rejected)
- **Identity**: registerIdentity, importIdentity, resolveDidDocument, resolveIdentity, participate, forgetIdentity (GDPR Article 17 right-to-erasure — DID must already be `Revoked`)
- **Interaction receipts**: recordInteraction (admin — the node is the attester, so an open endpoint would let anyone forge receipts in the operator's name), getInteraction, verifyInteraction (both open). One record and one content address for every interaction kind — access, inference, storage, marketplace — so an audit is a lookup rather than a reconciliation across per-surface logs. Verification compares content addresses rather than signatures, so it does not depend on trusting the verifying node
- **Settlement rails**: settlementNetworks — the rails a payment can settle on, each with an indicative fee floor and the smallest worthwhile payment on it; pass `amount_wei` + `asset` to get the routing decision for a specific charge (accumulate / primary / secondary / no viable rail). Open
- **Device binding**: bindDevice, listBoundDevices, walletReadiness, revokeBoundDevice, transferMachineOwnership — the devices that can authenticate as an identity, what each one's attestation proved about the hardware holding its key, and the authority under which a machine changes hands. `bindDevice` / `revokeBoundDevice` / `transferMachineOwnership` are admin-token gated; `listBoundDevices` / `walletReadiness` are open. Params are a **bare object**, not a one-element array
- **Network**: nodeInfo, peerCount, syncing, hardwareProfile, role
- **Governance**: listProposals, vote, getVotingPower
- **Payments**: createPaymentChallenge, payMpp, payX402, listPaymentSessions, paymentGatewayInfo, listX402Schemes (pluggable scheme registry: `tenzro-hybrid`, `exact-eip3009`, `permit2`, `erc7710`). An operator that sets `[payments.x402_facilitator]` facilitates the EIP-3009 and Permit2 schemes itself: the node runs the exact/EVM verification checks against its own `evm_rpc_url` and broadcasts the buyer's signed `transferWithAuthorization` through a relayer key, so the buyer pays no gas and the settlement path depends on no third-party facilitator. Without that block those two schemes resolve through the remote verifier
- **x402 Bazaar**: x402ProtocolInfo, x402RegisterResource, x402DiscoverResources, x402DeregisterResource, x402VerifyOffer, x402PaymentId — a discovery catalog for paid resources: sellers register listings (resource, scheme, network, asset, pay-to, max amount, tags), buyers browse before hitting a `402`, listing ids derive from `(seller_did, resource)` (re-register is idempotent), plus server-signed offer verification and deterministic `pay_<hex>` idempotency ids
- **AP2 v0.2 (Agent Payments Protocol)**: ap2SignMandate (Ed25519 sign-side for `checkout` and `payment` mandates), ap2VerifyMandate, ap2ValidateMandatePair (mandate constraints + DelegationScope + SpendingPolicy + on-chain escrow + Stripe SPT usage limits), listMandates, ap2ProtocolInfo
- **Stripe SPT**: sptIssue (TDIP cap-resolver enforces principal `DelegationScope` + runtime `SpendingPolicy`), sptVerify, with `granted_token.deactivated` webhook cascading into TDIP `apply_remote_revocation` and ERC-8004 ReputationRegistry cross-write on every settled outcome
- **AAP (Agent Access Protocol)**: oauthDiscovery, exchangeToken, introspectToken — OAuth 2.1 + DPoP-bound JWTs (RFC 9449) + RAR (RFC 9396) over `tenzro-auth`
- **App Registry & Developer-Signed Settlement**: registerApp, setAppStatus, getApp, listApps, settleAuthorized, getSettleAuthorizedOutcome — a permissionless registry where a developer registers an app under their own DID and settles authorized charges against a payment-provider account they alone control. The developer signs the settlement authorization; the node routes the charge and records the outcome but never holds the payment-provider secret. Distinct from **App Hosting** (which serves the app's site/function/machine): this is the payments surface for apps that collect from their own users. CLI: `tenzro app {register,set-status,get,list,settle-authorized,get-outcome}`
- **ERC-8004 (Jan 2026 revision) Trustless Agents (cross-VM trio)**: IdentityRegistry — encodeRegister (no-arg overload), encodeRegisterWithUri (`register(string)` overload), encodeRegisterWithMetadata (`register(string,(string,bytes)[])` overload), encodeGetAgent / decodeGetAgent, encodeSetAgentURI, encodeSetAgentWallet, encodeSetMetadata, encodeGetMetadata / decodeGetMetadata, encodeGetAgentURI, encodeGetAgentWallet. ReputationRegistry — encodeFeedback, encodeGetFeedback, encodeGetFeedbackCount, encodeRevokeFeedback, encodeIsFeedbackRevoked, encodeAppendResponse, encodeGetFeedbackResponses. ValidationRegistry — encodeValidationRequest, encodeValidationResponse, encodeGetValidation. All `tenzro_erc8004*`-prefixed; calldata is byte-identical to the native EVM precompiles `0x101a` / `0x101b` / `0x101c`. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — server-allocated, never derivable client-side.
  - **EVM mirror**: canonical OpenZeppelin-ERC721-upgradeable proxies deployed at genesis at `tenzro_identity::erc8004::addresses::{IDENTITY_REGISTRY, REPUTATION_REGISTRY, VALIDATION_REGISTRY}`. TDIP `register_machine_with_fee` dispatches `register(string agentURI)` via the node's `erc8004-system` secp256k1 key in a detached `tokio::spawn`; `Registered(uint256 indexed agentId, string agentURI, address indexed owner)` events flow back into the off-chain DID index in `CF_IDENTITIES` under `erc8004_did_index:` (32-byte hash → u256 agentId) via `process_erc8004_registered_logs` in `event_loop.rs`.
  - **SVM mirror**: uses QuantuLabs' Anchor implementation (`https://github.com/QuantuLabs/erc-8004-svm`). `tenzro-identity::erc8004_svm` emits Anchor-formatted instruction calldata via the `OnChainAgentSvmRegistry` trait; `NativeErc8004SvmMirror` in `crates/tenzro-node/src/erc8004_svm_mirror.rs` buffers payloads to the RocksDB pending-tx queue under `erc8004_svm_pending_tx:` and indexes DID → 32-byte Pubkey under `erc8004_svm_did_index:`. No `solana-sdk` dep is pulled into the monorepo by design — drain to a Solana RPC happens in operator-supplied infrastructure.
  - **DAML mirror**: is distributed as a Canton package at `vendor/erc8004-daml/daml/Tenzro/Erc8004/{Identity,Reputation,Validation}.daml` (two-party admin+controller signatory model, no `msg.sender` equivalent). `tenzro-identity::erc8004_daml` emits Canton Ledger JSON API v2 `submit-and-wait` commands via the `OnChainAgentDamlRegistry` trait; `NativeErc8004DamlMirror` in `crates/tenzro-node/src/erc8004_daml_mirror.rs` either dispatches via an installed `DamlMirrorTransport` or buffers `serde_json::Value` payloads under `erc8004_daml_pending_tx:` and indexes DID → 8-byte LE u64 agentId under `erc8004_daml_did_index:`. Wired only when `config.erc8004_daml` is present — package ids are SHA-256 of the compiled `.dar` and must be supplied at registry construction time by the operator.
- **Reputation & Approval**: getProviderReputation (provider score), listPendingApprovals / getApproval / decideApproval (out-of-scope agent operation queue)
- **Disputes & Streaming**: getDispute, listDisputesByChannel, chatStream (per-token streaming with optional `channel_id` for micropayment-channel billing). When a proxied upstream provider drops mid-generation, the streaming layer records the emitted prefix and sampling state (`SamplingState` in `streaming/failover.rs`) and asks a continuation-capable provider to deterministically re-prefill the identical prefix before resuming sampling, so a mid-stream failover produces one coherent completion rather than a truncated-plus-restarted one
- **EU AI Act §50 Provenance**: getProvenance — C2PA-style `ContentProvenanceManifest` keyed by `SHA-256(content_bytes)`, signed by validator block-signing keys (§50(1) chatbot disclosure via `aap_agent` claim, §50(2) provenance manifest, §50(4) deepfake labeling)
- **Staking**: stake, unstake, registerProvider, providerStats
- **Canton**: listCantonDomains, listDamlContracts, submitDamlCommand
- **Multi-Party Workflows**: getWorkflow, getWorkflowLifecycle, listWorkflowsByCreator, listWorkflowsByParticipant, listWorkflowsByStatus, getWorkflowReceipt, listWorkflowReceipts, getFeeRoute, listFeeRoutes, computeFeeRoutePayouts, getPrivacyDomain, listPrivacyDomainsForDid, getWorkflowOperationalMetrics — Canton-native workflow lifecycle, privileged-VM selectors `0x01000040`–`0x0100004B`, hash-chained receipts (`Inline` or `OffloadedDA`), kill-switch suspend/cancel, policy DSL combinators
- **TaskMarketplace**: postTask, listTasks, getTask, cancelTask, submitQuote
- **AgentMarketplace**: listAgentTemplates, registerAgentTemplate, getAgentTemplate, updateAgentTemplate, spawnAgentFromTemplate, runAgentTemplate, rateAgentTemplate, searchAgentTemplates, getAgentTemplateStats
- **TokenRegistry**: createToken, getToken, listTokens, crossVmTransfer, wrapTnzo, getTokenBalance, deployContract
- **Adaptive Burn**: getBurnRateConfig, getSupplyMetrics, getBurnRateRecommendation, listAdaptiveBurnProposals — dial surface plus `AutoProposalGenerator` and EIP-1559 fee-market consumer wired through the governance executor
- **SeedAgent Treasury**: getTreasuryEarmark, getSeedAgentCharter, listSeedAgentCharters, listSeedAgents, getNetworkActivity, getSeedAgentDaemonStatus — earmark, registry, off-chain `SeedAgentDaemon` (6h poll, monthly refill, charter-sunset pause, leader-gate), governance-executor mutation paths, and the `tenzro/seed-agents` gossipsub topic
- **AgentBond / Insurance**: post_agent_bond / get_agent_bond / file_insurance_claim — stake-bonding for agents and insurance pool for payment-mandate fraud
- **Training (Tenzro Train)**: tenzro_training_postTask, listRuns, getRun, getReceipt, enrollTrainer, submitOuterGradient, finalizeRound
- **Storage**: storageStatus, storageStoreObject, storageOpenDeal, storageChargeEpoch, storageDeal, storageSetPricing — content-addressed storage on the iroh data plane, billed per byte-epoch and gated on a proof of retrievability; one coverage budget shared with compute rental
- **Compute**: computeStatus, computeBookRental, computeSettleEpoch, computeGetRental, computeSetPricing — rentable compute against stake, settled per epoch on an availability proof; shares the storage coverage budget
- **MoE**: moeShardMap, moePlanDispatch, moeReplicationPolicy, moeCatalogShape — decentralized expert-shard serving: shard map, top-k dispatch planning, governance-tuned replication policy, catalog topology
- **Discovery & Clustering**: localPeers (mDNS local segment), nodeReachability (`direct` / `relay_only` / `unreachable`), nodeProfile (hardware self-profile: build commit, CPU arch, OS, devices, derived serving capacity / backend / capability key), clusterPlan (deterministic layer-wise LAN cluster placement)
- **Databases**: listDatabaseEngines, createDatabase, getDatabase, listDatabases, getDatabasePartition, listDatabasePartitions, dropDatabase, authorizeDatabaseRead, databaseQuery, rescaleDatabase, issueDatabaseConnection — managed-database protocol layer over an operator-run engine (PostgreSQL / Qdrant / Valkey as thin clients, Lance / Tantivy embedded in-process; Milvus / Dgraph catalog-only). Placement moves a database along local → lan_cluster → network; queries carry the engine's own dialect body; connections are minted as AAP capabilities scoped to a single database; access is gated by `AccessPolicy` + optional confidential seal
- **App Hosting**: sitePublish, siteGet, listSites, siteRemove, siteSetAlias, siteGetAlias, listSiteAliases, siteRemoveAlias, siteSetPlacement, siteGetPlacement, listSitePlacements, siteRemovePlacement, siteClaimDomain, siteVerifyDomain, siteGetDomain, listSiteDomains, siteRemoveDomain, functionDeploy, functionGet, listFunctions, functionRemove, machineDeploy, machineGet, listMachines, machineRemove, machineStatus, machineSealingKey, listLeases, getLeasesForApp — publish a static site (signed route map of content-addressed blobs), a `wasi:http` function (wasmtime sandbox), or a resident server (Firecracker microVM) and serve it over the public internet behind the in-node HTTPS edge (an `edge`-role node terminates TLS in-process with `rustls` and mints Let's Encrypt certs on demand via ACME TLS-ALPN-01, per hostname, gated by `sni_allowed` — no external Caddy/nginx), host-routed to serving nodes over the `tenzro/http` ALPN. Mutations are DID-owner-authenticated via a signed `did_envelope`; machine env secrets are sealed to the assigned node's key; placement follows a bid/lease model with `tenzro/sla` heartbeat failover; per-request pricing is x402-gated

### Paid Agent Marketplace

The agent marketplace supports both free (community) and paid (creator-tied) templates, from registration through payout:

- **Creator identity binding (optional):** at registration, a creator may bind a template to any TDIP identity class — human (`did:tenzro:human:{uuid}`), delegated agent (`did:tenzro:machine:{controller}:{uuid}`), or autonomous agent (`did:tenzro:machine:{uuid}`) — via `creator_did`. The binding is immutable post-registration.
- **Creator payout wallet (mandatory for paid pricing):** any non-`Free` `pricing` requires `creator_wallet`. Registration fails if the wallet is missing. `tenzro_runAgentTemplate` routes the creator share to this address.
- **Pricing models** (`AgentPricingModel`): `Free`, `PerExecution { price }`, `PerToken { price_per_token }`, `Subscription { monthly_rate }`, `RevenueShare { creator_share_bps }`. Compact string form accepted by the RPC: `"free"`, `"per_execution:<u128>"`, `"per_token:<u128>"`, `"subscription:<u128>"`, `"revenue_share:<bps>"`.
- **Marketplace commission:** the governance-set `EconomicPolicy::marketplace_commission_bps`, read live from the node (`tenzro_getEconomicPolicy`) rather than a constant. On every paid invocation of `tenzro_runAgentTemplate`, `tenzro_useSkill`, and `tenzro_useTool`:
  - `payer_wallet` is debited the full `fee_paid`
  - `commission = fee_paid * 500 / 10_000` is credited to the network treasury
  - `creator_share = fee_paid - commission` is credited to `creator_wallet`
  - `invocation_count` and `total_revenue` on the template are incremented atomically
- **Fee-split report** returned by `tenzro_runAgentTemplate`: `{ template_id, steps_executed, steps_failed, steps_skipped_by_dry_run, fee_paid, commission_bps, network_commission, creator_share, payer_wallet, creator_wallet, treasury, invocation_count, total_revenue }`.
- **Free templates** bypass all fee collection — no commission, no creator wallet required, `fee_paid = 0`.
- **Controller oversight:** before a paid invocation of `tenzro_useSkill`, `tenzro_useTool`, `tenzro_useKnowledge`, or `tenzro_useResource` settles, the node checks the calling agent's own authority. A `resource_invocation` grant in the bearer's `authorization_details` caps spend per call and may narrow to one resource `class` and a set of `allowed_resource_ids`; an uncovered invocation returns `-32001`. A controller that lists `resource.invoke` in its AAP oversight claim's `requires_human_approval_for` instead parks every paid invocation, returning `-32002` with `data.approval_id`. The same check runs on the skill and tool steps a `tenzro_orchestrate` plan executes. Requests carrying no authorization headers pass — there is no bearer identity, so no controller to consult — and remain bound by the presenting API key's own allow-lists.

Reference templates under `crates/tenzro-agent-kit/reference_templates/`:
- `premium_alpha_advisor.json` — **paid** per-execution specialist (5 TNZO, 5%/95% split demonstrated from invocation through payout)
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

### Available Tools (526)

The main Tenzro MCP server registers 526 tools (base + 29 multi-modal AI + 8 distributed MoE serving: `moe_shard_map`, `moe_plan_dispatch`, `moe_replication_policy`, `moe_catalog_shape`, `moe_prepare_experts`, `moe_prepare_status`, `moe_expert_status`, `moe_forward` + 29 app hosting: `site_publish`, `site_get`, `list_sites`, `site_remove`, `site_set_alias`, `site_get_alias`, `list_site_aliases`, `site_remove_alias`, `site_set_placement`, `site_get_placement`, `list_site_placements`, `site_remove_placement`, `site_claim_domain`, `site_verify_domain`, `site_get_domain`, `list_site_domains`, `site_remove_domain`, `function_deploy`, `function_get`, `list_functions`, `function_remove`, `machine_deploy`, `machine_get`, `list_machines`, `machine_remove`, `machine_status`, `machine_sealing_key`, `list_leases`, `get_leases_for_app` + 3 AgentBond/insurance: `post_agent_bond`, `get_agent_bond`, `file_insurance_claim` + 3 agent-memory: `memory_grant`, `memory_recall`, `memory_archive`) across wallet, identity, payments, inference, multi-modal AI (forecast, vision, text-embed, segment, detect, transcribe, video), distributed MoE serving, app hosting (static sites, functions, machines, placement leases), staking, tokens, NFTs, bridges, cross-chain, deBridge, Li.Fi, verification, agents, tasks, skills, tools, compliance, TEE, ZK, VRF, events, and administrative categories. The table below lists representative tools — consult `crates/tenzro-node/src/mcp/server.rs` for the complete authoritative inventory.

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
      "url": "https://mcp.tenzro.xyz/mcp"
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

Six additional MCP servers provide direct blockchain interaction:

| Server | Port | Description |
|--------|------|-------------|
| Solana MCP | 3003 | 14 tools: Jupiter, SPL, Metaplex, Bonfida SNS |
| Ethereum MCP | 3004 | 17 tools: Chainlink, ENS, ERC-20, ERC-8004, EAS |
| Canton MCP | 3005 | 23 tools: DAML, CIP-56, DvP, tokenization |
| LayerZero MCP | 3006 | 21 tools: V2 messaging, OFT, Value Transfer API, Stargate V2 |
| Chainlink MCP | 3007 | 21 tools: CCIP, data feeds, VRF v2.5, PoR, automation |
| LI.FI MCP | 3008 | 9 tools: cross-chain bridge aggregation, quotes, routes |

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
cargo run -p tenzro-node -- --roles validator --log-level debug
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

## `single_instance` — one node per data directory

An advisory `flock` on the canonicalised data directory, taken in `main.rs`
*before* RocksDB opens, and held for the process lifetime. Two nodes sharing a
data directory is not a degraded configuration but a corrupt one; RocksDB does
catch it, but deep inside storage initialisation and with an error naming a path
rather than a process.

The refusal names the holding PID and its command line and offers the three ways
out (`graceful-exit`, `kill`, or `--data-dir` for a separate instance). Listen
addresses are probed in the same pass, so every port conflict is reported at once
rather than one restart at a time.

The lock lives on a file descriptor, so the kernel releases it however the
process dies — a crash never leaves a stale claim, which is the failure that
trains operators to delete lockfiles reflexively.

## `device_rpc` — devices bound to an identity

A Tenzro identity links devices the way a platform account does, except the link
is not a platform account. **No Apple, Google or Microsoft sign-in is an identity
authority here**: what the node trusts is a WebAuthn attestation it verifies
against a vendor root the operator pinned, so "hardware-bound" is a fact the
device proved rather than a claim the same software making every other claim made
about itself.

A device is hardware-bound only when **both** hold: the credential cannot be
replicated off the device, and the attestation says its key lives in a TEE or
secure element. Backup-eligibility is disqualifying rather than informational — a
credential that *may* sync proves control of a cloud account, not possession of a
device. Where the chain cannot be verified the grade is degraded
(`chain_verified: false`) instead of the parse failing, so an operator who has
pinned no roots gets an honest answer rather than a silent pass.

The roots are `webauthn_trusted_roots` in the node config — base64 DER, one per
entry. An entry that does not decode is dropped rather than trusted, so a typo
narrows what the node accepts instead of widening it.

**A wallet cannot sit behind one device.** The machine the user is on is the
first; a genuinely separate hardware-bound device must exist before there is
anything to lose. `walletReadiness` names the blocker and its remedy so a UI can
say "scan the pairing QR with your phone" rather than offer a button that fails.

**Revoking a device unbinds it and ends every session it authorised, in one
action.** Doing only the first would leave a lost phone's access live, which is
the exact situation the user is trying to fix — which is why every session names
the bound device that authorised it, not only the identity.

**Machine ownership moves on whatever anchors the machine**, and the two
authorities are not interchangeable: `controller` for a machine some party
delegated, `hardware_root` for a machine nobody did. Holding the hardware cannot
take a machine that has an accountable party — that is a compromise, not an
acquisition. The authorisation is TTL-bounded (5 minutes by default) so it cannot
be replayed against a machine that has since changed hands.

Attestation parsing and chain verification live in
`tenzro-auth::webauthn_attestation`; the types and the grading rules live in
`tenzro-types::device_binding`. Records persist under `bound_device:` and
`device_session:` in `CF_IDENTITIES`.
