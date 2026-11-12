# Tenzro Node

Full node implementation for Tenzro Network — the AI-Native, Agentic Settlement Protocol. Tenzro Ledger is the settlement layer powered by the TNZO governance token.

## Overview

The `tenzro-node` crate provides the complete node binary that integrates all Tenzro Network subsystems into a unified node capable of participating in the network in various roles.

## Features

- **Multi-Role Support**: Configure as Validator, ModelProvider, TeeProvider, or LightClient
- **Modular Architecture**: Clean separation of concerns across subsystems
- **Health Monitoring**: Real-time health tracking for all subsystems
- **Metrics Collection**: Performance metrics and statistics
- **JSON-RPC API**: `eth_*`, `net_*`, `web3_*` and `solana_*` compatibility methods plus the `tenzro_*` methods; the full generated list is `docs/RPC.md`. Writes are client-signed typed transactions built by the SDKs.
- **OpenAI-compatible HTTP**: mounted on the same port as the JSON-RPC surface — `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/models`, `/v1/files`, `/v1/audio/transcriptions`, `/v1/audio/speech`, plus the Tenzro-modality routes `/tenzro/{forecasts,detections,segmentations,rerank,video/embeddings,realtime/turn,realtime/transcribe}`. There are no `/v1/images` or `/v1/videos` routes; image and video generation is the `tenzro_mediaGen_render` RPC method. The inference routes sit behind the HTTP 402 payment gate when payments are enabled
- **MCP Server**: Model Context Protocol server on `rmcp` Streamable HTTP transport at `/mcp`, port 3001
- **A2A Server**: Agent-to-Agent protocol server with 21 skills (JSON-RPC 2.0, SSE streaming, Agent Card at port 3002)
- **Web Verification API**: REST endpoints for ZK proof, TEE attestation, and transaction verification (port 8080)
- **Graceful Shutdown**: Clean shutdown sequence for all subsystems
- **TEE Integration**: Optional Trusted Execution Environment support (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)
- **AI Infrastructure**: Built-in model registry, inference routing, and agent runtime with durable persistence
- **Fail-closed access hardening**: HTTP RPC / web / MCP-sidecar binds default to loopback (off-box access is opt-in); the iroh overlay is credential-gated per ALPN (MCP allowlist, `moe/execute` gate, `tenzro/infer` admission). Inference admission (`inference_admission.rs`) classifies each request by the caller the access policy names and the model's visibility before the x402 charge. Inbound, a node needs only its iroh endpoint (`9001/udp`) reachable; a host firewall can drop everything else.

## Node Roles

`--roles` takes a comma-separated list. A node serves any combination of
roles under a single stake.

### Validator
Orders blocks and signs checkpoints with a hardware-held consensus key (TDC). A node without one follows the chain, importing blocks under checkpoint certificates.

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
                                compute/gpu, storage, tee/tee-provider,
                                edge/ingress, fullnode, archive, bootstrap/seed,
                                micro/user, light)
    -b, --boot-nodes <IDS>      Boot identities, did:tenzro:machine:<id>[@<relay url>]
        --relay-listen <ADDR>   Serve the relay role on this address (with --relay-url)
        --relay-url <URL>       URL the relay is published at, announced by identity
        --log-level <LEVEL>     Log level [default: info]
        --rpc-addr <ADDR>       RPC listen address [config rpc_addr, else 127.0.0.1:8545]
        --web-addr <ADDR>       Web API listen address [config web_addr, else 127.0.0.1:8080]
        --mcp-addr <ADDR>       MCP server listen address [config mcp_addr, else 127.0.0.1:3001]
        --a2a-addr <ADDR>       A2A server listen address [config a2a_addr, else 127.0.0.1:3002]
        --log-format <FMT>      Log format (text, json) [default: text]
    -h, --help                  Print help
    -V, --version               Print version
```

### Configuration File

Create a configuration file (config.toml):

```toml
roles = ["validator"]
data_dir = "./data/validator"
log_level = "info"
rpc_addr = "127.0.0.1:8545"
web_addr = "127.0.0.1:8080"
mcp_addr = "127.0.0.1:3001"
a2a_addr = "127.0.0.1:3002"
tee_enabled = false
metrics_enabled = true
health_enabled = true

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
2. **Network** - iroh gossip, identity endpoint records and relays
3. **TEE** - Trusted Execution Environment (if enabled)
4. **VM Runtime** - Multi-VM execution environment (EVM + SVM)
5. **Token Economics** - TNZO token, staking, governance, treasury
6. **Wallet** - hardware-rooted wallet service
7. **Consensus** - TDC: certificates on every node, the protocol core on validators
8. **Settlement** - Payment settlement engine
9. **AI Infrastructure** - Model registry, provider management, agent runtime, and swarm manager (durable persistence via `init_ai_infrastructure()`; restored model, agent, and swarm counts logged at startup)
10. **Bridge** - Cross-chain bridge router
11. **Storage** - `storage_provider_runtime` (content-addressed artifact holding and hash recording; compute rental is a stream escrow, see `docs/COMPUTE.md`)
12. **Inference Dispatch** - `infer` and `moe` — the request path into `tenzro-model`, including distributed mixture-of-experts dispatch — plus `network_catalog`, the gossiped view of which models the network can serve
13. **DA Committee** - `da_committee` + `da_committee_surface`, the sampling committee over offloaded receipt payloads

Shutdown occurs in reverse order to ensure clean resource cleanup.

### Cross-crate wiring

- **`terms_gate`** — the one payment-authority check: a delegated payer is held to its consensus Terms over chain state (`check_agent_payment`). Installed on the payment gateway at startup and used by AP2, ACP, paid invocations, intent routing and template agent steps.
- **`EquivocationJailer`** — drops and jails a validator whose checkpoint equivocation consensus recorded; consensus state slashes its bond into the insurance pool.
- **`NodeValidatorRegistry`** — answers whether an Ed25519 node key belongs to an active validator (live epoch set, genesis set before consensus runs); gates compute-market observations.

## JSON-RPC API

The node exposes a JSON-RPC API on the configured RPC address (default: `127.0.0.1:8545`).

### RPC Namespaces

- **Blockchain**: blockNumber, getBlock, getBlockRange (batch fetch for catch-up sync), getTransaction (returns `status: "pending" | "finalized"` so callers can distinguish in-mempool from block-included transactions), submitBlock
- **Token**: tokenBalance, totalSupply
- **Models**: listModels, inferenceRequest, serveModel, stopModel, chat, deleteModel, listModelEndpoints, getModelEndpoint
- **Model loads**: every load (`loadForecastModel`, `loadVisionModel`, `loadTextEmbeddingModel`, `loadSegmentationModel`, `loadTextSegmentationModel`, `loadDetectionModel`, `loadAudioModel`, `loadMediaModel`, `loadSpeechModel`) takes `{ model_id, visibility? }` and nothing else: the node fetches and verifies the files the signed catalog entry names and takes every shape from the entry. The served record keeps the model id, the loader and the visibility override (access follows from visibility and the operator's price), and a restart reloads each model with exactly those. `loadVideoModel` composes a clip encoder over a loaded image encoder (`{ model_id, vision_model_id, num_frames?, visibility? }`). `listModels { loaded: true }` lists every loaded model of every type with its engine, visibility, access and loaded/serving state
- **Intent Routing**: routeIntent, recordRouteOutcome, routeDifficultyStats, getRouterMetrics — a caller states what it wants (use case, budget, quality floor, token estimates) and the the inference router's intent tier picks the model. Candidates come from both the operator's own catalog and `network_catalog`, the gossiped set of signed offers other providers are serving, so the winning offer names its own payee and the settlement split follows from it. An announcement is smaller than the model it describes — it carries one category tag — so a gossiped offer has its capability tags recovered from the local catalog by model id before it is tiered, the same claim a locally served model gets. Everything the provider is actually asserting (price, endpoint, schedule, liveness) is taken from the announcement and never from the catalog; a model the catalog does not know keeps exactly what was announced. `routeIntent` clusters the prompt and scores each candidate against that cluster's observed outcome history, giving cold models an optimism bonus so they are tried rather than starved; `recordRouteOutcome` feeds the result back
- **Forecast**: listForecastCatalog, loadForecastModel, unloadForecastModel, forecast
- **Vision**: listVisionCatalog, loadVisionModel, unloadVisionModel
- **TextEmbedding**: listTextEmbeddingCatalog, loadTextEmbeddingModel, unloadTextEmbeddingModel, textEmbed
- **Segmentation**: listSegmentationCatalog, loadSegmentationModel, unloadSegmentationModel, segment
- **Detection**: listDetectionCatalog, loadDetectionModel, unloadDetectionModel, detect
- **Audio (ASR)**: listAudioCatalog, loadAudioModel, unloadAudioModel, transcribe
- **Video**: listVideoCatalog, loadVideoModel, unloadVideoModel, videoEmbed
- **Generative Media**: tenzro_mediaGen_listCatalog, quote, postJob, getJob, listJobs, cancelJob, listWorkers, getReceipt, fetchOutput; tenzro_loadMediaModel / tenzro_unloadMediaModel — image and video generation priced by the pixel-step (`width × height × steps × frames`). The node owns the job queue, the worker registry, the pricing, and the signed receipts, and renders the jobs for the media models it loads: FLUX.2 klein on the in-process Praecise diffusion engine, other families in a confined runtime host it starts. A model whose catalog entry carries an `expert_pair` splits at a timestep boundary: the node holding the high-noise half renders the prefix and commits to one intermediate latent, and its partner finishes and decodes, with payment split by the steps each half completed. Licence terms are checked when the model is loaded
- **Settlement**: settle
- **Identity**: registerIdentity, resolveDidDocument, resolveIdentity, forgetIdentity (GDPR Article 17 right-to-erasure — DID must already be `Revoked`)
- **Settlement rails**: settlementNetworks — the rails a payment can settle on, each with an indicative fee floor and the smallest worthwhile payment on it; pass `amount_wei` + `asset` to get the routing decision for a specific charge (accumulate / primary / secondary / no viable rail). Open
- **Device binding**: bindDevice, listBoundDevices, walletReadiness, revokeBoundDevice, transferMachineOwnership — the devices that can authenticate as an identity, what each one's attestation proved about the hardware holding its key, and the authority under which a machine changes hands. `bindDevice` / `revokeBoundDevice` / `transferMachineOwnership` are admin-token gated; `listBoundDevices` / `walletReadiness` are open. Params are a **bare object**, not a one-element array
- **Network**: peerCount, syncing
- **Governance**: listProposals, getVotingPower
- **Payments**: createPaymentChallenge, verifyPayment (checks a credential against its challenge without settling; reports the account it would debit and never reports success for a credential that would not pay). A receipt exists only after the settlement executed: TNZO settles with a payer-signed `PayerSettle` the VM verifies (10% network share), stablecoins on the optional Bridge rail. An operator that sets `[payments.x402_facilitator]` verifies EIP-3009 itself against its own `evm_rpc_url`; the node holds no EVM key, so the broadcast goes through the settlement facilitator it names and the node confirms on its own RPC that the transaction executed. Without that block those schemes resolve through the default facilitator
- **Payment channels**: openPaymentChannel, updatePaymentChannel, closePaymentChannel — channels over an escrow the payer funded on the ledger, paid with cumulative payer-signed vouchers and claimed on-chain with `ClaimEscrow`; closing requires a request signed by the payer
- **AAP (Agent Access Protocol)**: oauthDiscovery, exchangeToken, introspectToken — OAuth 2.1 + DPoP-bound JWTs (RFC 9449) + RAR (RFC 9396) over `tenzro-auth`
- **ERC-8004 registries**
  - **EVM mirror**: canonical OpenZeppelin-ERC721-upgradeable proxies deployed at genesis at `tenzro_identity::erc8004::addresses::{IDENTITY_REGISTRY, REPUTATION_REGISTRY, VALIDATION_REGISTRY}`. TDIP `register_machine_with_fee` dispatches `register(string agentURI)` via the node's `erc8004-system` secp256k1 key in a detached `tokio::spawn`; `Registered(uint256 indexed agentId, string agentURI, address indexed owner)` events flow back into the off-chain DID index in `CF_IDENTITIES` under `erc8004_did_index:` (32-byte hash → u256 agentId) via `process_erc8004_registered_logs` in `event_loop.rs`.
- **Streaming**: `/v1/chat/completions` with `stream: true` (per-token streaming). When a proxied upstream provider drops mid-generation, the streaming layer records the emitted prefix and sampling state (`SamplingState` in `streaming/failover.rs`) and asks a continuation-capable provider to deterministically re-prefill the identical prefix before resuming sampling, so a mid-stream failover produces one coherent completion rather than a truncated-plus-restarted one
- **Stakes**: getRoleStakes, getWalletProvider (bonding, unbonding and withdrawal are signed `Stake` transactions; a node refuses to boot with a bonded role its operator has not bonded)
- **Duties and evidence**: listDuties, getDuty, verifyEvidence
- **TokenRegistry**: getToken, listTokens, getTokenBalance, deployContract
- **Adaptive Burn**: getBurnRateConfig, getSupplyMetrics, getBurnRateRecommendation — dial surface; validators submit the `AutoProposalGenerator` drafts as on-chain `policy_update` proposals and every node applies enacted changes to the EIP-1559 fee-market consumer
- **AgentBond / Insurance**: get_agent_bond / get_insurance_pool — stake-bonding for agents, and the insurance pool that pays losses chain state proves
- **Storage**: storageStatus, storageStoreObject, storageSetPricing — content-addressed storage on the iroh data plane; renters pay through storage compute claims that commit the object's descriptor digest and settle hourly on SLA verdicts that require a possession proof
- **Compute**: computeGetClaim, computeListClaims (capacity is rented as physical compute claims) — rentable compute against stake, settled per elapsed epoch on an availability proof by the provider's billing loop; shares the storage coverage budget
- **MoE**: moeShardMap, moePlanDispatch, moeReplicationPolicy, moeCatalogShape — decentralized expert-shard serving: shard map, top-k dispatch planning, governance-tuned replication policy, catalog topology
- **Discovery & Clustering**: nodeProfile (hardware self-profile: build commit, CPU arch, OS, devices, derived serving capacity / backend / capability key), clusterPlan (deterministic layer-wise LAN cluster placement)
- **EVM-compat**: eth_blockNumber, eth_getBalance, eth_getTransactionCount, tenzro_sendRawTransaction, eth_getBlockByNumber, eth_getBlockByHash, eth_chainId, eth_getTransactionReceipt

## Wallet Model

### Where wallets come from

A wallet is created on the holder's device, its key in a passkey authenticator, TPM or Secure Enclave. The node never creates a wallet or holds a wallet key; it verifies the signatures it is sent.

The same address holds TNZO natively and is the source of truth for all VM projections. Per-chain views and operations are exposed through dedicated RPCs, not through separate wallets:

| Goal | Use |
|---|---|
| TNZO balance across all VMs | `tenzro_getTokenBalance` |
| ERC-20 / SPL token balance | `tenzro_getTokenBalance` (resolved by token_id, VM-agnostic) |
| Send TNZO to a foreign chain (Ethereum, Base, Arbitrum, Solana) | A holder-signed `Bridge` outbound transaction over the governed route (`tenzro bridge send`) |

### Why no `chain` parameter

Adding a `chain` field would imply Tenzro keeps separate per-chain key material, which it does not. The pointer-token model (Sei V2 architecture) means wTNZO ERC-20 at `0x1001`, and the wTNZO SPL adapter on SVM both share the **same** underlying native balance through the `TnzoToken` layer. No bridge risk, no liquidity fragmentation, no per-chain wallet provisioning. Apps that prompt the user to "pick a chain" at wallet-creation time are modeling something that doesn't exist on Tenzro.

### Sending and tracking transactions

- The server rejects self-sends (`from == to`) with a `cannot transfer to self` validation error; the desktop wallet form pre-empts this with a client-side guard.
- After submission, `tenzro_getTransaction(hash)` returns the transaction with `status: "pending"` while it sits in the consensus mempool and flips to `status: "finalized"` once it's included in a block. Callers polling immediately after broadcast see `"pending"` rather than `null`, so retry logic can distinguish "not yet finalized" from "unknown hash."

## MCP Server

The node runs a built-in [Model Context Protocol](https://modelcontextprotocol.io) server on port 3001 (configurable via `--mcp-addr`). It uses **Streamable HTTP** transport at `/mcp` endpoint.

**Endpoint:** `POST /mcp`

Every tool's output is typed. `/mcp/compact` serves the same tools behind `search` and `call`, on the same path as `/mcp`. Each call made with a valid access token through `/mcp`, `/mcp/compact` or A2A leaves a tool-call record the node signs and commits on chain (`src/tool_call_record.rs`, [docs/AGENT_TRUST.md](../../docs/AGENT_TRUST.md#tool-call-records)).

### Available Tools

Every JSON-RPC method the node serves has a tool (typed, or mirrored from `crates/tenzro-node/src/mcp/rpc_tools.rs`), across wallet, identity, payments, inference, multi-modal AI (forecast, vision, text-embed, segment, detect, transcribe, video), distributed MoE serving, stakes, tokens, governed bridge routes, verification, agents, tasks, TEE, ZK, VRF, events, and administrative categories. The table below lists representative tools — consult `crates/tenzro-node/src/mcp/server.rs` for the complete authoritative inventory.

| Category | Representative Tools |
|----------|----------------------|
| **Wallet & Ledger** | `get_balance` |
| **Network & Blocks** | `get_node_status`, `get_block`, `get_transaction` |
| **Identity & Delegation** | `register_identity`, `resolve_did` |
| **Payments** | `create_payment_challenge`, `verify_payment` |
| **AI Models & Inference** | `list_models`, `list_model_endpoints` |
| **Multi-Modal AI** | `forecast`, `vision_embed`, `vision_similarity`, `text_embed`, `segment`, `detect`, `transcribe`, `video_embed` (plus catalog/load/unload variants per modality) |
| **Verification** | `verify_zk_proof`, `verify_vrf_proof` |
| **Stakes & Providers** | `get_role_stakes`, `get_provider_stats` |
| **Tokens & Contracts** | `get_token_info`, `list_tokens`, `deploy_contract`, `get_token_balance` |

### MCP clients

```json
{
  "mcpServers": {
    "tenzro": {
      "url": "https://mcp.tenzro.com/mcp"
    }
  }
}
```

For a local node, use `http://localhost:3001/mcp`.


## A2A Protocol Server

The node runs an [Agent-to-Agent (A2A)](https://a2a-protocol.org) protocol server on port 3002 (configurable via `--a2a-addr`).

### Endpoints

| Endpoint | URL | Description |
|----------|-----|-------------|
| Agent Card | `GET /.well-known/agent.json` | Agent capability discovery |
| A2A RPC | `POST /a2a` | JSON-RPC 2.0 task execution |
| A2A Stream | `POST /a2a/stream` | Server-Sent Events streaming |

### Agent Skills

Skills are listed on the node's Agent Card (`crates/tenzro-node/src/a2a/agent_card.rs`).

### JSON-RPC Methods

- `message/send` -- Send a message between agents
- `tasks/send` -- Send a message, create or continue a task
- `tasks/get` -- Get task by ID
- `tasks/list` -- List tasks
- `tasks/cancel` -- Cancel a running task


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
```

## Health & Metrics

The node tracks health for all subsystems:

- **Healthy**: All systems operational
- **Degraded**: Some systems experiencing issues but functional
- **Unhealthy**: Critical systems down

Access health status via the `tenzro_getNodeStatus` RPC method.

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
