# Tenzro Network CLI

The official command-line interface for operating Tenzro Network nodes, managing wallets, models, staking, and governance. Interact with Tenzro Ledger (the settlement layer) and earn TNZO tokens.

## Features

- **Network Onboarding**: One-click participation via `join` command
- **Node Management**: Monitor node status
- **Wallet Operations**: Create FROST-Ed25519 threshold wallets, check balances, send transactions (real reqwest RPC client)
- **Model Management**: List, download, serve AI models (local + remote RPC)
- **Multi-Modal Inference**: Forecasting, image/text/video embedding, point-and-box and text-promptable segmentation, object detection, and audio transcription — each a subcommand group with `catalog` / `list` / `load` / `unload` / `run`
- **Distributed MoE**: Expert-shard maps, dispatch planning, expert/gate weight loading, and distributed layer forwards via `tenzro moe`
- **Tenzro Train**: Post training tasks, enroll trainers, submit outer gradients, finalize rounds, and manage sealed manifests via `tenzro train`
- **Tenzro Media Gen**: Post diffusion image/video jobs, enroll render workers, claim either half of a split-expert model, and fetch outputs via `tenzro media-gen`
- **Staking**: Stake TNZO tokens as validator or provider
- **Governance**: Participate in on-chain governance and voting
- **Provider Tools**: Register and manage inference/TEE providers
- **Identity Management**: Register human/machine DIDs via TDIP
- **Payments**: MPP/x402 payment protocol support
- **Canton Integration**: DAML contract interaction
- **Agent Operations**: Register agents, spawn from templates, manage swarms
- **VRF Operations**: RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI prove/verify/keygen
- **AP2 / x402 / AAP**: Mandate validation, x402 facilitator payments, OAuth 2.1 + DPoP + RAR auth (with `aap` alias)
- **ERC-8004 Registry (cross-VM trio)**: Trustless agent registration, reputation feedback, validation requests across EVM (canonical OZ-ERC721 proxies at genesis), SVM (QuantuLabs Anchor mirror), and DAML (Tenzro-authored Canton package). One TDIP `tenzro identity register --type machine ...` fans out to all three backing registries (with `8004` alias)
- **Approvals & Disputes**: Inspect pending out-of-scope approvals; read channel-dispute lifecycle records
- **Provenance**: Fetch C2PA-style manifests for AI-generated content (EU AI Act §50(2))
- **Chat Interface**: Interactive REPL with local llama.cpp + RPC fallback (output prefixed `[AI]` per EU AI Act §50(1))

## Installation

```bash
# From source
cargo install --path crates/tenzro-cli

# Or build and run directly
cargo run -p tenzro-cli -- --help
```

## Quick Start

```bash
# Guided setup — join the network, provide, validate, or bootstrap a private network
tenzro setup

# One-click network participation (provisions identity, wallet, hardware profile)
tenzro join

# Check your balance
tenzro wallet balance

# List available models
tenzro model list

# Interactive chat with session history
tenzro chat
```

## Commands (103 command modules)

All commands use real JSON-RPC calls via reqwest. No artificial delays.

### Network Onboarding

```bash
# Guided setup wizard: pick a path (join the public network, create a local or
# sovereign network, or join an existing private network). Every prompt has a
# matching flag for non-interactive use:
#   --path {network,local,private}  --mode {consume,provide,validate}
#   --network-name --chain-id --data-dir --stake --bootstrap --genesis
#   --name --rpc --yes
tenzro setup

# Create a self-contained network: generates the validator keyset
# (Ed25519 + ML-DSA-65 + BLS12-381), assembles a schema-v3 genesis.toml,
# writes a service unit, and prints the start command plus the exact
# join command for each peer
tenzro setup --path local --network-name lab --yes

# One-click join: provisions identity, wallet, hardware profile
tenzro join
```

### Node Management

```bash
# Start a Tenzro Network node (forwards to the tenzro-node binary)
tenzro node start --roles validator --data-dir ~/.tenzro/data

# Stop the running node
tenzro node stop

# Check node status
tenzro node status

# Show connected peer count (calls net_peerCount)
tenzro node peers

# Show sync status (calls eth_syncing)
tenzro node syncing

# Inspect a contiguous range of blocks (read-only catch-up probe).
# Calls tenzro_getBlockRange — returns up to 256 blocks per request,
# with nextHeight + moreAvailable for pagination across pruning gaps.
tenzro node sync-range --start 0 --end 255

# Inspect the EIP-1559 fee market: current base fee, suggested priority tip,
# and recent fee history.
tenzro node fee-market

# Spec-2 admission-controller mempool stats: per-lane admit/reject counters
# and lane configuration.
tenzro node mempool-stats

# Resolve which admission lane an address falls in, plus its current
# token-bucket state.
tenzro node mempool-lane --address 0xabc...
```

### Local Discovery

```bash
# Peers currently discovered on this node's local segment via mDNS
# (calls tenzro_localPeers).
tenzro discover local-peers

# This node's sustained connectivity tier (calls tenzro_nodeReachability).
tenzro discover reachability

# This node's hardware self-profile from the ggml device API: build commit,
# CPU arch, OS, serving VRAM, and backend (calls tenzro_nodeProfile).
tenzro discover profile
```

### LAN Clustering

```bash
# Deterministic cluster placement for a model across a set of candidate
# members. Computes the fit decision and, when a cluster forms, the
# VRAM-weighted contiguous layer assignment ordered to minimize pipeline
# transfer cost (calls tenzro_clusterPlan). --members is a JSON file holding
# the candidate member array; --force requests a cluster even when one
# member fits the whole model.
tenzro cluster plan --layers 64 --hidden-dim 8192 --total-vram-gb 180 \
  --members ./members.json

# Model-independent discovery: list this node plus every LAN/gossip member it
# can pool, with their serving memory and reachability, and the pooled total
# (calls tenzro_clusterMembers). Answers "who's on my network right now?"
tenzro cluster members
```

`cluster plan` is the explicit, inspect-the-plan path. To actually serve a
model across a cluster you do not need to compute or pass a plan: `tenzro
model serve` reads the model shape from the GGUF and auto-discovers members
over local gossip (see the Model Management section above and AI.md §3.5).

### Decentralized App Hosting

Publish a static site, a `wasi:http` function, or a long-lived server to
Tenzro nodes and serve it over the public internet — no manual TLS, DNS, or
reverse-proxy setup. See [`docs/HOSTING.md`](../../docs/HOSTING.md) for the
full RPC and CLI surface.

All mutations take a `--did-envelope` (a signed header value proving control
of `--owner-did`).

```bash
# Static sites — deploy a build-output directory: upload files,
# build the route map of content-addressed blobs, publish.
tenzro site deploy --name myapp --dir ./dist \
  --owner-did did:tenzro:machine:... --did-envelope <hex>
tenzro site get --site-id site-...
tenzro site list --owner-did did:tenzro:machine:...
tenzro site remove --site-id site-... \
  --owner-did did:tenzro:machine:... --did-envelope <hex>

# Point a hostname (a subdomain of your operator's app domain) at a site.
tenzro site set-alias --hostname myapp.apps.tenzro.xyz --site-id site-... \
  --owner-did did:tenzro:machine:... --did-envelope <hex>
tenzro site list-aliases --owner-did did:tenzro:machine:...

# Bring your own custom domain: claim, publish the printed DNS records,
# then verify to trigger certificate issuance.
tenzro site domain add --hostname www.example.com --site-id site-... \
  --owner-did did:tenzro:machine:... --did-envelope <hex>
tenzro site domain verify --hostname www.example.com \
  --owner-did did:tenzro:machine:... --did-envelope <hex>

# Pin a site to specific serving nodes (repeat --serving-node per node);
# omit placement to serve locally.
tenzro site set-placement --site-id site-... --serving-node <EndpointId> \
  --owner-did did:tenzro:machine:... --did-envelope <hex>

# Functions — a wasi:http component answers requests in a wasmtime sandbox.
tenzro function deploy --name myfn --wasm ./component.wasm \
  --owner-did did:tenzro:machine:... --did-envelope <hex>
tenzro function list --owner-did did:tenzro:machine:...

# Machines — an unmodified server in a Firecracker microVM (operator nodes
# with KVM + nested-virt). --env secrets are sealed client-side to the
# assigned node's sealing key before upload.
tenzro machine deploy --name mysrv --image ./rootfs.ext4 --internal-port 8080 \
  --owner-did did:tenzro:machine:... --did-envelope <hex>
tenzro machine status --id machine-...

# Placement leases across all three runtime classes.
tenzro lease list
tenzro lease get --app-id site-...
```

### Managed Databases

```bash
# List the engines this node can serve, with their data models, license, and
# native-cluster topology (calls tenzro_listDatabaseEngines). Five engines
# have a driver — PostgreSQL, Qdrant, Valkey as thin clients to an
# operator-run engine, Lance and Tantivy embedded in-process. Milvus and
# Dgraph are cataloged but need a driver linked before a create succeeds.
tenzro database engines

# Register a database, computing and persisting its partition placement over
# the live cluster membership. --placement moves it along the
# local → lan_cluster → network continuum; --config is opaque per-engine JSON
# validated against the engine before placement.
tenzro database create --id <id> --engine <engine> \
  --placement <local|lan_cluster|network> \
  --partitions <n> [--min-replication <n>] [--max-replication <n>] \
  --owner-did <did> [--config <json>]

# Mint a managed-database connection credential scoped to a single database
# (calls tenzro_issueDatabaseConnection). Returns an AAP capability pinned to
# that database id, a read_only / read_write mode, a TTL, and the query method.
tenzro database connect --id <id> --caller-did <did> [--write] [--ttl <secs>]

# Run an engine-dialect query against a partition (calls tenzro_databaseQuery).
# --body is the engine's own payload: SQL for Postgres, a vector search for
# Qdrant or Lance, a full-text search for Tantivy, a command for Valkey.
# --consistency sets the write acknowledgement level (quorum | all).
tenzro database query --id <id> --caller-did <did> --body <json> [--write] \
  [--consistency <quorum|all>]

# Grow or shrink a database in place along the continuum (calls
# tenzro_rescaleDatabase); a network-tier result is re-gossiped so peers
# converge on the new shape. --min-replication/--max-replication must be
# supplied together.
tenzro database rescale --id <id> --caller-did <did> --placement <mode> \
  [--partitions <n>] [--min-replication <n> --max-replication <n>]

tenzro database get --id <id>
tenzro database list
tenzro database partitions --id <id>
tenzro database authorize --id <id> --caller-did <did>
tenzro database drop --id <id> --caller-did <did>
```

### Wallet Operations

```bash
# Create a chain-agnostic 2-of-3 FROST-Ed25519 (RFC 9591) threshold wallet (calls tenzro_createWallet).
# A single wallet projects into EVM, SVM, and Canton via the pointer-token
# model — there is no per-chain wallet. Use `tenzro token cross-vm-transfer` /
# `tenzro token wrap-tnzo` for VM-specific operations, and `tenzro bridge` /
# `tenzro debridge` / `tenzro lifi` / `tenzro wormhole` for external chains.
tenzro wallet create

# Import existing wallet (calls tenzro_importIdentity RPC)
tenzro wallet import <seed-phrase|private-key>

# Check balance (calls eth_getBalance)
tenzro wallet balance --address <address>

# Send tokens (server-custodial path). The CLI calls tenzro_signAndSendTransaction;
# the node looks up the live nonce and gas price, computes Transaction::hash() with
# the canonical timestamp-inclusive preimage, signs with Ed25519 + ML-DSA-65,
# verifies both legs synchronously, and returns -32003 on a bad signature. `value`
# and `amount` are accepted aliases. Self-sends (to == from) return a
# `cannot transfer to self` validation error.
tenzro wallet send <to-address> <amount> --asset TNZO --private-key <hex>

# List all wallets (calls tenzro_listAccounts)
tenzro wallet list
```

#### Self-Custody (client-side hybrid signing)

The node never holds the secret. A local sealed key at `~/.tenzro/hybrid_key.json`
holds the Ed25519 + ML-DSA-65 keypair; the raw 32-byte Ed25519 public key is the
account address. `wallet send` builds the canonical `Transaction::hash()` preimage
(nonce + chain id fetched from the node, PQ verifying key included), signs both legs
locally, and submits via `eth_sendRawTransaction` — the node verifies the Ed25519
and ML-DSA-65 signatures against the hash and rejects a raw send that omits either.

```bash
# Generate a local self-custody hybrid key (prompts for a password to seal it).
tenzro wallet create-local

# Import an existing Ed25519 secret (32-byte hex); a fresh ML-DSA-65 leg is derived.
tenzro wallet import-local <ed25519-secret-hex>

# Send self-custody. --self-custody forces the local path; it is also selected
# automatically whenever a local key exists at ~/.tenzro/hybrid_key.json.
tenzro wallet send <to-address> <amount> --self-custody
```

### Model Management

The `tenzro` CLI is the full node surface: it downloads weights and serves
models so your node becomes a provider. If you only want to *use* a model —
send a prompt to a provider that already serves it, with no node and no weights
— reach for the simpler Tenzro Labs client instead:

```bash
npm install -g @tenzro/labs-cli
tzlabs login tnz_...
tzlabs chat qwen3-4b "explain content addressing in one line"
```

The rest of this section is for running the model yourself.

```bash
# List all available models
tenzro model list

# Filter by modality
tenzro model list --modality text
tenzro model list --modality image

# Show model details
tenzro model info gemma4-9b --providers

# Download a model (local HuggingFace + remote RPC)
tenzro model download gemma4-9b

# Start serving a model locally, or on a remote node with --rpc (calls
# tenzro_serveModel). The node reads the model's shape from the GGUF header
# and, if it does not fit one machine, auto-forms a LAN pipeline cluster from
# the cluster-willing providers it has discovered over local gossip — no
# member list to hand-maintain. See AI.md §3.5.
tenzro model serve gemma4-9b --rpc http://127.0.0.1:8545

# Force a cluster even when the model fits one machine, or never cluster:
tenzro model serve gemma4-235b --rpc http://127.0.0.1:8545 --cluster
tenzro model serve gemma4-235b --rpc http://127.0.0.1:8545 --force-single

# Stop serving (local + remote tenzro_stopModel RPC)
tenzro model stop gemma4-9b

# List model endpoints (tenzro_listModelEndpoints)
tenzro model endpoints

# Get specific endpoint (tenzro_getModelEndpoint)
tenzro model endpoint <model_id>

# Delete model
tenzro model delete gemma4-9b
```

#### Download and run a model end to end

```bash
# 1. Find a model.
tenzro model list --modality text

# 2. Download the weights. Peer-first over the network (BLAKE3-verified),
#    falling back to HuggingFace. --source pins one path.
tenzro model download qwen3-4b
tenzro model download qwen3-4b --source network
tenzro model download qwen3-4b --source huggingface

# 3. Serve it. If the model does not fit one machine, the node auto-forms a
#    LAN pipeline cluster from cluster-willing providers it discovers over
#    local gossip.
tenzro model serve qwen3-4b --rpc http://127.0.0.1:8545

# 4. Chat against your local copy.
tenzro chat qwen3-4b
```

Serving a model also makes you a provider: register with
`tenzro provider register --type inference` so the network routes hosted
inference to you.

### Chat Interface

```bash
# Interactive REPL with session history
tenzro chat

# Local llama.cpp inference with RPC fallback (tenzro_chat)
# Commands: /history, /load <session_id>, /exit

# Stream a single chat completion via tenzro_chatStream, optionally billing
# the streamed tokens to a micropayment channel.
tenzro inference stream gemma4-9b "summarize this paragraph" --max-tokens 256
tenzro inference stream gemma4-9b "summarize this paragraph" --channel <channel_id>
```

All chat output (REPL, single-shot, streaming) is prefixed with `[AI]` per
EU AI Act Article 50(1). The literal lives in
`tenzro_node::eu_ai_disclosure::render_cli_chat_chunk` so the workspace can
audit the disclosure string in one place.

### Multi-Modal Inference

Each modality is a subcommand group with the same five arms: `catalog` lists the
curated entries, `list` shows what the node currently has loaded, `load`
registers a model, `unload` drops it, and `run` performs inference.

`load` takes `--catalog-id`, which inherits every structural parameter (input
size, embedding dimension, decoder ABI, class count) from the catalog entry and
applies its license tier. Without it you must supply those parameters yourself,
and no license check runs.

`embed-text load` and `text-segment load` fetch their artifacts from HuggingFace
onto the node's models directory. The other groups register ONNX files that are
already on the node's filesystem, so `--path` (or `--encoder-path` /
`--decoder-path`) is a node-side path, not a local one.

```bash
# Timeseries forecasting (tenzro_forecast)
# Catalog: timesfm-2.5-200m, tirex-35m
tenzro forecast catalog
tenzro forecast load --model fc --path /models/timesfm.onnx --catalog-id timesfm-2.5-200m
tenzro forecast run --model fc --context 1,2,3,4,5 --horizon 64

# Text embedding (tenzro_textEmbed)
# Catalog: qwen3-embedding-0.6b/-4b/-8b, embeddinggemma-300m, bge-m3,
#          modernbert-embed-base/-large
tenzro embed-text load --model qwen3-embedding-0.6b
tenzro embed-text run --model qwen3-embedding-0.6b --input "hello world"

# Image embedding / similarity (tenzro_imageEmbed, tenzro_imageTextSimilarity)
# Catalog: clip-vit-b32/-l14, siglip-base-224, siglip2-base-224/-large-256/-so400m-384,
#          dinov3-vits16/-vitb16/-vitl16
tenzro embed-image load --model img --path /models/siglip2.onnx --catalog-id siglip2-base-224
tenzro embed-image run --model img --image ./photo.png --normalize
tenzro embed-image similarity --image-embedding ./img.json --text-embedding ./txt.json

# Point/box segmentation (tenzro_segment)
# Catalog: sam2-base, sam2-large, edgesam, mobilesam
tenzro segment load --model seg --encoder-path /models/enc.onnx \
  --decoder-path /models/dec.onnx --catalog-id sam2-base
tenzro segment run --model seg --image ./photo.png --prompts ./prompts.json

# Open-vocabulary text-promptable segmentation (tenzro_textSegment)
# Catalog: sam3-vit-h
tenzro text-segment load --model sam3-vit-h
tenzro text-segment run --model sam3-vit-h --image ./photo.png --text "a red bicycle"

# Object detection (tenzro_detect)
# Catalog: rf-detr-nano/-small/-medium/-base/-large/-2xl, d-fine-n/-s/-m/-l/-x
tenzro detect load --model det --path /models/rfdetr.onnx --catalog-id rf-detr-medium
tenzro detect run --model det --image ./photo.png --score-threshold 0.5

# Audio transcription (tenzro_transcribe)
# Catalog: moonshine-tiny/-base, distil-whisper-small-en/-medium-en/-large-v3,
#          whisper-large-v3-turbo, parakeet-tdt-0.6b-v3, canary-1b-flash
tenzro transcribe load --model asr --encoder-path /models/enc.onnx \
  --decoder-path /models/dec.onnx --preprocessor-path /models/pre.onnx \
  --vocab-path /models/vocab.txt --catalog-id parakeet-tdt-0.6b-v3
tenzro transcribe run --model asr --audio ./clip.wav --timestamps

# Video embedding (tenzro_videoEmbed)
# The native video catalog is empty — no permissive ONNX-shippable encoder-only
# video model exists yet. Register a vision-pooled fallback instead: it samples
# evenly-spaced frames with ffmpeg, embeds each through a loaded image encoder,
# and mean-pools. Requires ffmpeg on the node.
tenzro embed-video load --model vid --vision-model img --num-frames 8
tenzro embed-video run --model vid --video ./clip.mp4 --normalize
```

License-tier gating applies at load time. CommercialCustom models (DINOv3, SAM,
Gemma) need the node operator to have started `tenzro-node` with
`--accept-license <id>`; non-commercial models need `--accept-non-commercial`.
Those are node flags, not CLI flags — a `load` against a node that lacks the
acceptance is refused with a license error.

### Staking

```bash
# Stake TNZO tokens (tenzro_stake)
tenzro stake deposit 10000

# Stake as specific provider type
tenzro stake deposit 10000 --provider-type validator

# Withdraw staked tokens (tenzro_unstake)
tenzro stake withdraw 5000

# View staking information (queries tenzro_getVotingPower)
tenzro stake info
```

### Governance

```bash
# List active proposals
tenzro governance list --active --detailed

# Create a new proposal (tenzro_createProposal)
tenzro governance propose \
  "Increase validator rewards" \
  "This proposal increases validator rewards by 10%" \
  --type parameter \
  --duration-days 14

# Vote on a proposal (queries tenzro_getVotingPower + calls tenzro_vote)
tenzro governance vote prop_001 yes
```

### Provider Management

```bash
# Register as inference provider (tenzro_registerProvider)
tenzro provider register --type inference --stake 10000

# Check provider status (tenzro_providerStats)
tenzro provider status --detailed

# List models you're serving
tenzro provider models

# Set pricing
tenzro provider pricing set <model_id> <price>
tenzro provider pricing show

# List all providers
tenzro provider list
```

### Schedule Management

```bash
# Set provider availability schedule
tenzro schedule set --days mon,tue,wed --hours 9-17

# Show current schedule
tenzro schedule show

# Enable/disable schedule
tenzro schedule enable
tenzro schedule disable
```

### Identity Management

```bash
# Register human identity (tenzro_registerIdentity)
tenzro identity register --type human --name "Alice"

# Register machine identity
tenzro identity register --type machine --controller <did>

# Resolve DID
tenzro identity resolve <did>

# List identities
tenzro identity list

# Get DID document
tenzro identity document <did>

# Add credential
tenzro identity add-credential <did> <credential>

# Add service
tenzro identity add-service <did> <service>
```

### Payment Operations

```bash
# Create payment challenge (tenzro_createPaymentChallenge)
tenzro payment challenge --protocol mpp --amount 100

# Pay resource (dispatches to tenzro_payMpp/tenzro_payX402)
tenzro payment pay --credential <credential>

# List payment sessions
tenzro payment sessions

# Get receipt
tenzro payment receipt <session_id>

# Get payment info
tenzro payment info
```

### x402 (Coinbase HTTP-402) Operations

Tenzro is an x402 facilitator: clients build the `X-PAYMENT` header from a
`402 Payment Required` challenge, and the node verifies and settles via the
configured scheme adapter (`exact`, `permit2`, ...).

```bash
# Enumerate scheme adapters registered with the facilitator
# (calls tenzro_listX402Schemes)
tenzro x402 list-schemes

# Submit an X-PAYMENT payload against a challenge
# (calls tenzro_payX402). The CLI does not sign payloads — that is the
# principal's job per the AP2 separation-of-duties rule.
tenzro x402 pay --challenge-file ./challenge.json --payload-file ./payment.json
```

The **Bazaar** is the discovery catalog for paid resources: a seller publishes
what a buyer must pay to reach a resource, and buyers browse listings before
they ever hit a `402`.

```bash
# Publish a paid resource listing. The listing id is derived from
# (seller-did, resource), so re-registering the same pair updates it in place
# (calls tenzro_x402RegisterResource).
tenzro x402 register-resource --seller-did <did> --resource <url> \
  --scheme <tenzro-hybrid|permit2|exact-eip3009|erc7710> \
  --network <chain-id> --asset <asset> --pay-to <address> \
  --max-amount-required <base-units> [--description <text>] [--tags a,b,c]

# Browse the catalog, narrowed by scheme / network / tags
# (calls tenzro_x402DiscoverResources).
tenzro x402 discover-resources [--scheme <s>] [--network <n>] [--tags a,b]

# Remove a listing you published (calls tenzro_x402DeregisterResource).
tenzro x402 deregister-resource --seller-did <did> --resource <url>

# Verify a server-signed offer carried in a 402 requirement
# (calls tenzro_x402VerifyOffer).
tenzro x402 verify-offer --offer-file ./offer.json

# Derive the deterministic pay_<hex> idempotency id for a payment
# (calls tenzro_x402PaymentId).
tenzro x402 payment-id --scheme <s> --network <n> --payload-file ./payment.json
```

For the higher-level `tenzro payment pay --protocol x402` flow, see the
"Payment Operations" section above.

### AAP (Agent Access Protocol)

`tenzro aap` is an alias for `tenzro auth`. AAP is the agent-facing layering
on top of OAuth 2.1 + DPoP + RAR; the underlying RPCs are the same
`tenzro_*Token*` and wallet-link methods exposed by `auth`. Both names work
identically — pick the one that matches how you think about the operation.

```bash
# Refresh an access token (works under either name)
tenzro auth refresh --refresh-token <token>
tenzro aap refresh --refresh-token <token>

# Link a wallet for auth (works under either name)
tenzro auth link-wallet --did <did> --wallet <addr>
tenzro aap link-wallet --did <did> --wallet <addr>
```

### ERC-8004 Trustless Agents Registry

`tenzro 8004` is an alias for `tenzro erc8004` with the canonical short name
from EIP-8004. Both names hit the same registry RPCs (`tenzro_8004*`).

```bash
# Register an agent in the registry
tenzro 8004 register --did <did> --domain <agent.example.com>
tenzro erc8004 register --did <did> --domain <agent.example.com>

# Submit reputation feedback for an agent
tenzro 8004 submit-feedback --agent-id <id> --score <0-100> --reason "..."

# Look up an agent
tenzro 8004 get-agent --agent-id <id>

# Validation request / submission (verifiable agent work)
tenzro 8004 request-validation --agent-id <id> --task <task>
tenzro 8004 submit-validation --validation-id <id> --result <result>
```

These commands hit the **EVM** surface. `agentId` is a sequential
`uint256` (1-indexed) allocated by the canonical OZ-ERC721-upgradeable
proxy at `register*()` time — server-allocated, never derivable
client-side. Calldata is byte-identical against either the native
Tenzro registry (proxies deployed at genesis at
`tenzro_identity::erc8004::addresses::*`) or an Ethereum mirror.

The same ERC-8004 semantic is automatically mirrored to two non-EVM
backends from a single TDIP write — invoke via
`tenzro identity register --type machine ...` rather than the
`erc8004 register` subcommand to drive the full fanout:

- **SVM mirror**: QuantuLabs Anchor program. Node buffers Anchor
  calldata under `erc8004_svm_pending_tx:` in RocksDB; operator
  drains to a Solana RPC.
- **DAML mirror**: Tenzro-authored Canton package at
  `vendor/erc8004-daml/daml/Tenzro/Erc8004/`. Node buffers
  Canton Ledger JSON API v2 `submit-and-wait` commands under
  `erc8004_daml_pending_tx:`. Opt-in: wired only when the node's
  `erc8004_daml` config block is present (package id = SHA-256 of
  compiled `.dar`, supplied by operator).

Each backing registry allocates its own id shape: `uint256` on EVM,
32-byte Pubkey on SVM, 8-byte LE u64 on DAML.

### Reputation

```bash
# Read the current score for a provider address
# (calls tenzro_getProviderReputation; integer 0-1000).
# Reputation update rule: +1 per successful inference (saturating to 1000),
# -5 per failure (saturating to 0). Durable in RocksDB across restarts.
tenzro reputation get 0xabc...
```

### AgentBond and Insurance

```bash
# Post a stake bond for an agent (refundable on clean exit, slashable on fraud).
tenzro bond post --agent-id <id> --amount <tnzo>
tenzro bond increase --agent-id <id> --amount <tnzo>
tenzro bond withdraw --agent-id <id>
tenzro bond get --agent-id <id>
tenzro bond list

# File a claim against the insurance pool for a fraudulent payment mandate / failed
# settlement. Surfaces the AgentBond stake as the first loss tranche.
tenzro insurance claim --agent-id <id> --evidence <path>
tenzro insurance list
tenzro insurance get --claim-id <id>
tenzro insurance pool
```

### Tenzro Train

`tenzro train` is the CLI surface for the Tenzro Train protocol layer
(`tenzro_training_*` RPCs). The Rust crate is protocol-only — the inner
training loop runs in the Python reference trainer at `integrations/trainer/`.

```bash
tenzro train post-task --task-spec ./task.json
tenzro train list-runs
tenzro train get-run --run-id <id>
tenzro train get-receipt --run-id <id> --round <r>
tenzro train enroll-trainer --run-id <id>
tenzro train submit-gradient --run-id <id> --round <r> --payload ./grad.bin
tenzro train finalize-round --run-id <id> --round <r>
tenzro train install-sealed-manifest --manifest ./manifest.json
tenzro train get-sealed-manifest --manifest-hash <64-hex>
tenzro train daemon-status
```

`daemon-status` reports the trainer auto-provisioning daemon on the target
node (`tenzro_getTrainerDaemonStatus`): whether it is running, its trainer
DID, the count of live trainer subprocesses, and the concurrent-trainer
ceiling. Enable the daemon with `[training] enabled = true` in the node
config.

### Distributed MoE

`tenzro moe` is the CLI surface for distributed Mixture-of-Experts serving
(`tenzro_moe*` RPCs) — shard-map planning plus expert/gate weight loading and
distributed forward execution on the node's expert runtime. The runtime keeps
experts in a byte-bounded memory-tier LRU (budget auto-sized from host memory)
over a disk tier that decodes spilled experts back on demand, so a holder can
serve more experts than fit in memory; `tenzro moe status` reports each
expert's tier and the memory budget. Expert projection math runs on CPU by
default (`ndarray`, plus a runtime-detected AVX-512-VNNI path) or on GPU when
the node was built with the `moe-cuda` / `moe-wgpu` features; a GPU holder
advertises `moe_gpu` so the router biases dispatch toward it. `prepare-experts`
slices a catalog checkpoint into per-expert blobs, optionally block-quantizes
them (`q8_0` / `q4_k` / `q6_k`, or the `q4_k_m` preset — gate/up Q4_K, down
Q6_K), and publishes them for holders to load.

```bash
# Planning
tenzro moe shard-map --model-id <id>            # live expert → holder map
tenzro moe plan-dispatch --model-id <id> --routing ./routing.json
tenzro moe replication-policy                   # governance-tuned policy
tenzro moe catalog-shape --model-id <id>        # catalog MoE topology

# Preparation (slice + optional quantize + publish)
tenzro moe prepare-experts --model-id <id> --layer <l> --quant q4_k_m
tenzro moe prepare-experts --model-id <id> --layer <l> --experts 0,3,7 \
  --quant-json '{"gate":"q4_k","up":"q4_k","down":"q6_k"}'

# Execution
tenzro moe load-expert --model-id <id> --layer <l> --expert <e> --file ./expert.safetensors
tenzro moe load-expert --model-id <id> --layer <l> --expert <e> --uri tenzro://blob/<hash>
tenzro moe load-gate --model-id <id> --layer <l> --file ./gate.safetensors
tenzro moe unload-expert --model-id <id> --layer <l> --expert <e>
tenzro moe unload-gate --model-id <id> --layer <l>
tenzro moe status                               # resident experts + gates, per-expert tier + memory budget
tenzro moe forward --model-id <id> --layer <l> --d-model <dim> --hidden ./hidden.f32
```

### Tenzro Media Gen

`tenzro media-gen` is the CLI surface for diffusion image and video generation
(`tenzro_mediaGen_*` RPCs). Like Tenzro Train, the Rust crate is protocol-only —
the denoising loop runs in the Python reference worker at
`integrations/media_gen/`. Four job kinds: `text2image`, `image2image`,
`text2video`, `image2video`.

Catalog rows carrying an `expert_pair` split the denoising schedule across two
machines at a fixed noise level: one worker renders the high-noise prefix, hands
a single intermediate latent to its partner, and the partner renders the
low-noise remainder and decodes. `catalog` marks those rows `[split]`. One
expert of Wan 2.2 A14B needs 48 GB where the whole model needs 80, so two
commodity accelerators render what one could not. The payment split follows the
step count in the signed handoff.

```bash
# Discovery and pricing
tenzro media-gen catalog                            # all rows; [split] marks expert pairs
tenzro media-gen catalog --kind text2video
tenzro media-gen quote --kind text2image --params ./params.json

# Requester
tenzro media-gen post-job --spec ./spec.json
tenzro media-gen list-jobs --status pending
tenzro media-gen get-job --job-id <id>              # assignments, roles, unclaimed halves
tenzro media-gen cancel-job --job-id <id> --requester-did <did>
tenzro media-gen get-receipt --job-id <id>
tenzro media-gen fetch-output --job-id <id> --out ./render.png
tenzro media-gen fetch-input --job-id <id> --out ./conditioning.png

# Worker
tenzro media-gen enroll-worker --capability ./capability.json
tenzro media-gen list-workers
tenzro media-gen claim-job --job-id <id> --worker-did <did>
tenzro media-gen claim-job --job-id <id> --worker-did <did> --role high_noise
tenzro media-gen mark-running --job-id <id> --worker-did <did>
tenzro media-gen publish-output --file ./render.png  # returns output_hash + locator
tenzro media-gen record-handoff --handoff ./handoff.json
tenzro media-gen submit-receipt --receipt ./receipt.json
tenzro media-gen fail-job --job-id <id> --worker-did <did> --error "<reason>"
tenzro media-gen fetch-latent --job-id <id> --out ./latent.safetensors
```

`--role` is only meaningful on a split job; omit it and the node assigns the
whole job. `publish-output` returns both hashes the two stores use: the SHA-256
`output_hash` the receipt commits to, and the BLAKE3 `locator` the content
store fetches by. `quote` prices from the same figures the runtime charges
against, so `max_price` in the posted spec need not be a guess.

`enroll-worker` checks every model the capability names — whole models and
expert halves alike — against the node's catalog and against the licenses the
operator has accepted. A capability naming a model outside the catalog, or one
whose terms the node was not started with (`--accept-license <id>`,
`--accept-non-commercial`), is refused. The node never loads media-gen weights,
so enrollment is where those terms are held.

Operators running the Python worker do not need these subcommands — `serve` in
`integrations/media_gen/` drives the same RPCs. They are the inspection and
manual-recovery path, and the reference for anyone writing another worker.

### Approval Flow

When a delegated machine attempts an operation outside its `DelegationScope`
(value cap, daily-spend cap, restricted contract, etc.), the auth engine
parks the request as a pending approval keyed to the controller's DID. These
commands are the controller's review surface; each maps 1:1 to an existing
RPC.

```bash
# List approvals waiting on this controller DID
# (calls tenzro_listPendingApprovals; node lazily expires stale entries)
tenzro approval list --approver-did <did>

# Inspect a single approval record
# (calls tenzro_getApproval)
tenzro approval get <approval_id>

# Apply a decision. --approver-did is optional but recommended:
# supplying it makes the node verify the caller matches the record's
# approver, returning -32001 (Forbidden) on mismatch.
# (calls tenzro_decideApproval)
tenzro approval decide --approval-id <id> --decision approved --approver-did <did>
tenzro approval decide --approval-id <id> --decision denied
```

The parked attempt itself returns `-32002` with the new id under
`data.approval_id`, so the requesting agent learns which record to watch.
Once the controller approves, the agent retries the same call with
`approval_id` in its params: the engine spends the approval against that
exact action and the call executes instead of parking a second time. An
approval only covers the action it was raised for — a retry carrying a
mismatched amount, counterparty, or action type parks again.

`--deny-reason` on a denial is carried verbatim back to the requester. A
retry against a denied approval returns `-32001` with the controller's
reason in the message, so the agent can act on *why* it was refused rather
than only that it was:

```bash
tenzro approval decide --approval-id <id> --decision denied \
  --deny-reason "counterparty not on the approved vendor list"
```

### Channel Disputes

Micropayment-channel disputes are stored records in the settlement
engine. These read-only commands inspect dispute lifecycle records;
open/respond/resolve transitions happen via on-chain settlement
transactions, not here.

```bash
# Show the current state of a dispute by id
# (calls tenzro_getDispute; -32004 if no record)
tenzro dispute status <dispute_id>

# List every dispute (open or historical) attached to a channel
# (calls tenzro_listDisputesByChannel; empty list, not error, if none)
tenzro dispute list-by-channel --channel-id <channel_id>
```

### Provenance (EU AI Act §50(2))

Tenzro records a C2PA-style `ProvenanceManifest` per AI-generated content,
keyed by `content_hash` (SHA-256 of the output bytes). Validators sign and
persist these manifests; this command fetches one back.

```bash
# Fetch the cached manifest for a 32-byte content hash
# (calls tenzro_getProvenance; -32004 if no manifest exists for this hash)
tenzro provenance get 0x<sha256_hex>
```

### Agent Operations

```bash
# Register agent (server-provisioned hybrid wallet: FROST-Ed25519 + ML-DSA-65)
# Capabilities: nlp,vision,code,data,blockchain,smart_contract,api_integration,coordination
tenzro agent register --name "MyAgent" --creator <address> --capabilities nlp,data

# List agents
tenzro agent list

# Send agent message (tenzro_sendAgentMessage)
tenzro agent send --from <agent_id> --to <agent_id> <message>

# Spawn new agent
tenzro agent spawn --parent <parent_id>

# Run task
tenzro agent run-task <agent_id> <task>

# Create swarm
tenzro agent create-swarm --agents <agent_ids>

# Get swarm
tenzro agent get-swarm <swarm_id>

# Terminate swarm
tenzro agent terminate-swarm <swarm_id>

# List templates (tenzro_listAgentTemplates)
tenzro agent list-templates

# Get template (tenzro_getAgentTemplate)
tenzro agent get-template <template_id>

# Spawn from template
tenzro agent spawn-template <template_id>

# Run template
tenzro agent run-template <template_id> <params>

# Delegate a task to an agent with a maximum budget
tenzro agent delegate --agent-id <id> --task <description> --max-budget <tnzo>

# Discover agents on the network, optionally filtered by capability
tenzro agent discover --capability inference --max 50

# Fund an agent's wallet with TNZO
tenzro agent fund --agent-id <id> --amount <tnzo>

# Spawn an agent from a template (alternate flow with skill wiring)
tenzro agent spawn-from-template --template-id <id> --name "MyAgent"

# Spawn an agent equipped with a specific skill
tenzro agent spawn-with-skill --skill-id <id> --name "MyAgent"

# Pay for inference on behalf of an agent
tenzro agent pay-for-inference --agent-id <id> --model-id <model> --max-amount <tnzo>

# Reconcile the agent registry — auto-suspend idle agents (1h TTL)
tenzro agent prune
```

#### Kill-switch (Spec 9)

The kill-switch trio is a controller-signed safety primitive: pause is
reversible (freezes payments, allows reward distribution + stake withdrawals);
quarantine is reversible (freezes payments, rewards, and stake withdrawals);
terminate is irreversible and slashes stake by `slash_bps`, optionally
cascading to descendants under `children:<parent_id>`.

```bash
# Pause an agent (reversible). Optional pause_until expiry.
tenzro agent pause \
  --controller-address 0xabc... \
  --controller-did <did> \
  --agent-did <did:tenzro:machine:...> \
  --reason-code <code> \
  --pause-until <unix_ms>

# Quarantine an agent (reversible). Optional 32-byte SHA-256 evidence hash.
tenzro agent quarantine \
  --controller-address 0xabc... \
  --controller-did <did> \
  --agent-did <did:tenzro:machine:...> \
  --reason-code <code> \
  --evidence-hash 0x<sha256_hex>

# Terminate an agent (irreversible). Slashes stake by slash_bps (0..=10000).
tenzro agent terminate \
  --controller-address 0xabc... \
  --controller-did <did> \
  --agent-did <did:tenzro:machine:...> \
  --reason-code <code> \
  --slash-bps 5000 \
  --cascade
```

### Operator API Key Management

`tenzro admin api-key` wraps the RPCs behind `X-Tenzro-Admin-Token`. Every
node operator holds their own token for their own node's state — there is
no network-wide token, and these commands grant no authority over the
validator set, treasury, fee schedule, or protocol params, all of which
flow through on-chain governance. Developers request a key out of band
from whichever operator runs the node they want to use.

```bash
# Mint a key. --scope repeats; defaults to `canton`.
# --tier is free (default, read-only) | standard | priority.
# --canton-network repeats; a key naming none reaches no Canton ledger.
tenzro admin api-key create \
    --label "acme-devnet" \
    --subject did:tenzro:machine:... \
    --scope canton \
    --tier standard \
    --canton-network devnet \
    --canton-user-id acme@clients

# The plaintext tnz_... key is returned exactly once, at issuance.
# Only its SHA-256 hash is stored; a lost key must be revoked and reissued.

# List issued keys (active + revoked)
tenzro admin api-key list

# Revoke by non-secret key_id (the 8-byte hex prefix shown in `list`)
tenzro admin api-key revoke --key-id <key_id>
```

`--class` picks the revocation model: `subject` (default — the subject can
self-revoke), `operator_internal` (operator-only, admin-revokable), or
`operator_protected` (operator-only and not revokable over RPC; rotate by
changing the operator secret and restarting, and pass
`--confirm-operator-protected` to acknowledge that).

All three commands read `TENZRO_ADMIN_TOKEN` when `--admin-token` is
omitted, and target `http://127.0.0.1:8545` unless `--rpc` says otherwise.

### Developer API Key Self-Service

`tenzro key` is the developer half. It authenticates with the `tnz_...`
key itself (`--api-key` or `TENZRO_API_KEY`), needs no admin token, and
never exposes another subject's keys.

```bash
# What am I entitled to?
tenzro key list-mine

# Revoke one of your own keys by its non-secret key_id
tenzro key revoke-mine --key-id <key_id>
```

`list-mine` is the entitlement self-read. Each row carries the scopes,
tier ceiling, Canton networks, and Canton party binding the node
enforces, so you can answer "what may I do here" without asking the
operator:

```
Key ID            Label       Scopes  Class    Canton Networks  Canton User            Active
a1b2c3d4e5f60718  acme-prod   canton  subject  mainnet          acme@clients           yes
c8f90338f6a167b7  acme-probe  canton  subject  mainnet          — (no ledger access)   yes
```

A `Canton User` of `— (no ledger access)` alongside a non-empty
`Canton Networks` is the important case: the key authenticates and can
call the node, but it is bound to no Canton party, so command submission
is refused. Two ways forward — ask the operator to reissue the key with
`--canton-user-id`, after which the node mints the tenant JWT
server-side, or present your own JWT from your own issuer in the
`X-Canton-Auth` header.

Only `subject`-class keys are self-revokable. `operator_internal` and
`operator_protected` keys return `-32004`. The error for "no such key"
and "not your key" is deliberately identical so ownership of keys you
don't hold cannot be probed.

### Canton Integration (Canton 3.5+ JSON Ledger API)

All `tenzro canton ...` subcommands route through the local Tenzro node,
which proxies to its configured Canton participant. Callers never see the
operator's OAuth client secret.

The surface splits by entitlement. Party-scoped work — DAML submission,
contract queries, participant status — takes an API key with scope
`canton` (`--api-key` or `TENZRO_API_KEY`). Participant administration —
DAR upload, party allocation, rights grants, and reads spanning every
tenant — takes the operator's admin token (`--admin-token` or
`TENZRO_ADMIN_TOKEN`), because a key holder rents party-scoped access to a
participant rather than administering it. Passing the wrong credential
returns `-32001` (admin gate) or `-32004` (api-key gate) rather than
silently falling back.

The node serves Canton per network. `devnet` and `mainnet` are configured
independently — a network counts as served only when its
`CANTON_<NET>_LEDGER_API_HOST` is set — and a key is authorized for a
subset of them. Name the target with `--canton-network`, falling back to
`TENZRO_CANTON_NETWORK`. A key authorizing exactly one network needs
neither; a key authorizing both and given neither gets a `-32004` naming
the authorized set. Admin-token calls are unbounded by any key but still
have to name a network, since there is no key to infer one from.

Each key carries a tier bounding its request budget over a sliding
60-second window:

| Tier | Requests/min | Writes |
|---|---|---|
| `free` | 60 | refused |
| `standard` | 600 | allowed |
| `priority` | 6,000 | allowed |

Exceeding the budget returns `-32005` with `retry_after_ms`,
`requests_per_minute`, and `tier`.

API keys gate operator-brokered resources like Canton, where the operator
supplies upstream credentials of its own. They do not gate the
marketplace: publishing an agent, skill, workflow, or MCP server is
permissionless, priced by the provider in TNZO or offered free, and needs
no operator approval.

```bash
# Existing core commands
tenzro canton domains                              # tenzro_listCantonDomains
tenzro canton contracts --template '<tid>'         # tenzro_listDamlContracts
tenzro canton submit <command>                     # tenzro_submitDamlCommand

# Naming the network on a key authorized for more than one
tenzro canton contracts --template '<tid>' --canton-network mainnet

# Canton 3.5+ extension surface
tenzro canton health                               # /livez + /readyz + /v2/version
tenzro canton version                              # /v2/version + CIP feature flags
tenzro canton my-user                              # GET /v2/users/<client_id>@clients (CIP-26)
tenzro canton parties                              # GET /v2/parties/known
tenzro canton packages                             # GET /v2/packages — installed DAR ids
tenzro canton coin-balance                         # CIP-56 Canton Coin balance
tenzro canton fee-schedule                         # latest Splice.AmuletRules:AmuletRules
tenzro canton connected-synchronizers              # GET /v2/state/connected-synchronizers
tenzro canton get-transaction --update-id <hex>    # GET /v2/updates/transaction-tree-by-id
tenzro canton upload-dar --file path/to/my.dar     # POST /v2/packages (single Content-Type)
```

### Bridge Fee in TNZO + Chainlink Integration

Cross-chain bridge fees payable in TNZO instead of destination-native
gas. The protocol-side fee oracle quotes the destination-native fee in
TNZO; the `BridgeFeeSponsor` debits the user and credits a
deterministic per-adapter sponsorship-pool vault.

Two oracle backings:

- **`GovernanceSetFeeOracle`** — manual rate table written by the
  operator via `tenzro_setBridgeFeeRate` (admin-token-gated). Testnet
  default.
- **`ChainlinkFeedFeeOracle`** — live `eth_call` against
  `AggregatorV3Interface.latestRoundData()` on the operator's
  configured Ethereum mainnet RPC. Requires the operator's bridge
  config to set `chainlink_feeds.enabled = true` + `rpc_url` + per-
  adapter feed addresses. Falls back to governance when a feed isn't
  configured or is stale.

The upstream Ethereum mainnet RPC quota is operator-paid, so methods
that consult it are gated by the `chainlink` API key scope (same
pattern as `canton`). The operator mints `tnz_...` keys with the
`chainlink` scope and tracks per-tenant Compute Unit consumption in
`CF_BRIDGE_ANALYTICS`. Per-tenant rate-limiting uses GCRA (10 req/sec
sustained, burst 100 by default).

```bash
# Read paths — require X-Tenzro-Api-Key with `chainlink` scope
tenzro bridge-fee quote --adapter layerzero --dest-chain eip155:1 \
    --native-fee 1000000
tenzro bridge-fee list-pools

# Asset prices from the node price oracle (price_usd_8dp is USD x 1e8).
# Requires bridge.prices.enabled on the node.
tenzro bridge-fee price --symbol TNZO
tenzro bridge-fee price --symbols TNZO,ETH,USDC
tenzro bridge-fee sponsor \
    --quote-id-hex 0x... --adapter layerzero --dest-chain eip155:1 \
    --native-fee-smallest-unit 1000000 --tnzo-amount-wei 5100000 \
    --rate-q18-hex 0x... --issued-at-ms 1781030000000 \
    --valid-until-ms 1781030060000 --payer-did did:tn:human:alice

# Subject self-read of own CU consumption + call counters
tenzro bridge-fee analytics  # uses TENZRO_API_KEY env var

# Admin paths — require X-Tenzro-Admin-Token
tenzro bridge-fee set-rate --adapter layerzero --dest-chain eip155:1 \
    --rate-q18 2000000000000000000 --markup-bps 100
tenzro bridge-fee set-refill --adapter layerzero --refill-threshold-bps 500
tenzro bridge-fee list-analytics  # operator cross-tenant read
```

Rate-limit rejections surface as JSON-RPC error code `-32005` with a
`data: { retry_after_ms, rate_per_second, burst }` envelope so SDKs
can implement client-side backoff.

### Escrow Operations

Escrow `create` / `release` / `refund` are consensus-mediated typed transactions
(`CreateEscrow`, `ReleaseEscrow`, `RefundEscrow`) signed with the payer's
Ed25519 key and submitted via `tenzro_signAndSendTransaction`. Funds are locked
in a deterministically-derived vault address by the Native VM; only the
original payer can release or refund.

```bash
# Create on-chain escrow (signed CreateEscrow tx, gas: 75,000)
tenzro escrow create \
  --payer 0xabc... \
  --payee 0xdef... \
  --amount 1000000000000000000 \
  --asset TNZO \
  --expires-at 1735689600000 \
  --release timeout \
  --private-key 0x...   # or omit to be prompted

# Release escrowed funds to the payee (signed ReleaseEscrow tx, gas: 60,000)
tenzro escrow release <escrow_id> --payer 0xabc... --proof 0x... --private-key 0x...

# Refund escrowed funds back to the payer (signed RefundEscrow tx, gas: 50,000)
# Requires expiry passed OR release condition is Timeout/Custom.
tenzro escrow refund <escrow_id> --payer 0xabc... --private-key 0x...

# Inspect an escrow record by id (read RPC, no signing)
tenzro escrow get <escrow_id>

# Open payment channel
tenzro escrow open-channel --counterparty <address> --deposit <amount>

# Close channel
tenzro escrow close-channel <channel_id>

# Delegate voting power
tenzro escrow delegate --from <addr> --to <validator> --amount <stake>

# Settle payment (tenzro_settle)
tenzro escrow settle <settlement_id>

# Get settlement (tenzro_getSettlement)
tenzro escrow get-settlement <settlement_id>
```

`--release` accepts: `timeout` | `provider` | `consumer` | `both` | `verifier` | `custom`.
The `escrow_id` is derived deterministically by the VM as
`SHA-256("tenzro/escrow/id" || payer || nonce_le)` and emitted in the
receipt log of the `CreateEscrow` transaction.

### ZK Proofs (Plonky3 STARKs over KoalaBear)

```bash
# List available AIRs
tenzro zk circuits

# Generate a Plonky3 STARK proof
tenzro zk prove \
  --circuit-id inference \
  --witness '{"model_checksum":1,"input_checksum":2,"computed_output":3}'

# Verify a proof
tenzro zk verify \
  --circuit-id inference \
  --inputs '["0x01000000","0x02000000","0x03000000"]' \
  --proof <hex>
```

Public inputs are passed as a JSON array of hex strings, each a 4-byte little-endian KoalaBear field-element chunk. Plonky3 STARKs require no trusted setup — there is no ceremony or keygen command.

### Task Marketplace

```bash
# List tasks
tenzro task list

# Post task
tenzro task post --description <desc> --reward <amount>

# Get task
tenzro task get <task_id>

# Cancel task
tenzro task cancel <task_id>

# Quote task (tenzro_quoteTask)
tenzro task quote <task_id>

# Assign task (tenzro_assignTask)
tenzro task assign <task_id> <agent_id>

# Complete task (tenzro_completeTask)
tenzro task complete <task_id>
```

### Agent Marketplace

```bash
# List agent templates (tenzro_listAgentTemplates)
tenzro marketplace list

# Get template (tenzro_getAgentTemplate)
tenzro marketplace get <template_id>

# Register template (tenzro_registerAgentTemplate)
tenzro marketplace register <template>
```

### Skill Management

A skill is either an *endpoint* the node calls on your behalf or a *bundle* —
a content-addressed WASI 0.2 component the node fetches and runs inside its
own sandbox, under a fuel and deadline budget, with no ambient filesystem or
network. Publishing is permissionless: you set the price in TNZO base units
(`0` for free) and the wallet that receives your share.

```bash
# List skills (tenzro_listSkills)
tenzro skill list
tenzro skill list --bundled-only          # only skills a caller can pin
tenzro skill list --all                   # include inactive and deprecated

# Search skills (tenzro_searchSkills)
tenzro skill search <query>

# Get skill (tenzro_getSkill) and its usage counters (tenzro_getSkillUsage)
tenzro skill get <skill_id>
tenzro skill usage <skill_id>

# Register an endpoint skill (tenzro_registerSkill)
tenzro skill register --name summarize --description "Summarize a document" \
  --capabilities nlp --creator-did did:tenzro:human:... \
  --endpoint https://example.com/mcp --price-per-call 0

# Register a bundled skill — all three artifact flags are required together
tenzro skill register --name summarize --description "Summarize a document" \
  --capabilities nlp --creator-did did:tenzro:human:... \
  --bundle-uri tenzro://blob/<blake3-hex> \
  --bundle-sha256 <sha256-hex> --bundle-size 262144

# Use skill (tenzro_useSkill)
tenzro skill use <skill_id> --input '{"prompt":"hello"}'

# Pin the invocation — either flag, or both
tenzro skill use <skill_id> --input '{}' \
  --expected-version 1.0.0 --expected-sha256 <sha256-hex>

# Update or republish (tenzro_updateSkill)
tenzro skill update <skill_id> --version 1.1.0 \
  --bundle-uri tenzro://blob/<blake3-hex> \
  --bundle-sha256 <sha256-hex> --bundle-size 264192

# Reconcile the registry — purge inactive and deprecated rows
tenzro skill prune
```

`--bundle-sha256` is the digest of the artifact bytes, and it is what callers
pin against. Republishing a bundle under a new digest fails every pin on the
old one closed rather than silently serving different code, so a caller that
pinned gets a refusal it can act on instead of a substituted implementation.

### Tool Management

```bash
# List tools (tenzro_listTools)
tenzro tool list
tenzro tool list --tool-type mcp --category search

# Search tools (tenzro_searchTools)
tenzro tool search <query>

# Get tool (tenzro_getTool) and its usage counters (tenzro_getToolUsage)
tenzro tool get <tool_id>
tenzro tool usage <tool_id>

# Register tool (tenzro_registerTool)
tenzro tool register --name web-search --description "Web search over MCP" \
  --endpoint https://tools.example.org/mcp --capabilities web-search

# Use tool (tenzro_useTool) — --tool-name is the MCP tool on that server
tenzro tool use <tool_id> --tool-name web_search --params '{"query":"hello"}'

# Update (tenzro_updateTool) and reconcile the registry
tenzro tool update <tool_id> --version 1.1.0
tenzro tool prune
```

### Token Operations

```bash
# Create token (tenzro_createToken)
tenzro token create --name "MyToken" --symbol "MTK" --decimals 18 --supply 1000000

# Get token info (tenzro_getToken)
tenzro token info --address <address>

# List tokens (tenzro_listTokens)
tenzro token list

# Get balance (tenzro_getTokenBalance)
tenzro token balance <token_id> <address>

# Wrap TNZO (tenzro_wrapTnzo)
tenzro token wrap --amount <amount> --to-vm evm

# Transfer (tenzro_crossVmTransfer)
tenzro token transfer --token <token_id> --to <address> --amount <amount>

# Swap tokens via DEX
tenzro token swap --from <token_id> --to <token_id> --amount <amount>

# Inspect the dual-rail gas burn quota (Agent-Swarm Spec 3)
tenzro token burn-quota
```

### Stable-Asset Issuance

Issuer-agnostic stable-unit policies layered on the Secure-Mint reserve floor.
An issuer registers a unit, then mints/redeems against it; mints are hard-gated
so circulating supply can never exceed the attested reserve. Register requires
an API key with the `issuer` scope.

```bash
# Register an issuer's stable-asset policy (tenzro_registerStableAsset)
tenzro stable-asset register \
  --issuer <issuer-32b-hex> \
  --unit-token <token-20b-hex> \
  --symbol USDX \
  --reserve-kind custodial \
  --attester-did did:tenzro:... \
  --asset-caip19 iso4217:USD \
  --por-feed-id <feed-id> \
  --rail x402 --rail ap2 \
  --settlement-dst <dst-32b-hex>

# Read a policy (tenzro_getStableAsset)
tenzro stable-asset get --issuer <issuer-32b-hex> --unit-token <token-20b-hex>

# Mint units, gated by the reserve floor (tenzro_mintStableAsset)
tenzro stable-asset mint --issuer <issuer-32b-hex> --unit-token <token-20b-hex> --amount 1000000

# Redeem (burn) units (tenzro_redeemStableAsset)
tenzro stable-asset redeem --issuer <issuer-32b-hex> --unit-token <token-20b-hex> --amount 500000
```

### Contract Operations

```bash
# Deploy contract (tenzro_deployContract)
tenzro contract deploy --bytecode <bytecode> --vm evm
```

### Bridge Operations

```bash
# Bridge tokens
tenzro bridge transfer --from-chain <chain> --to-chain <chain> --amount <amount>
```

### DeBridge Operations

```bash
# DeBridge cross-chain operations
tenzro debridge quote --from-chain <chain> --to-chain <chain> --amount <amount>
tenzro debridge transfer <params>
```

### LI.FI Operations

```bash
# LI.FI bridge aggregation
tenzro lifi quote --from-chain <chain> --to-chain <chain> --amount <amount>
tenzro lifi transfer <params>
```

### NFT Operations

```bash
# NFT operations
tenzro nft mint --collection <id> --to <address>
tenzro nft transfer --token-id <id> --to <address>
```

### Compliance Operations

```bash
# Compliance operations
tenzro compliance check --address <address>
```

### Cross-Chain Operations

```bash
# Cross-chain operations
tenzro crosschain transfer --from <chain> --to <chain> --amount <amount>
```

### Event Monitoring

```bash
# Event monitoring
tenzro events subscribe --topics <topics>
tenzro events list
```

### Crypto Operations

```bash
# Crypto operations
tenzro crypto keygen --type ed25519
tenzro crypto sign --message <message> --key <key>
tenzro crypto verify --message <message> --signature <sig> --pubkey <key>
```

### TEE Operations

```bash
# TEE operations
tenzro tee attest
tenzro tee verify --attestation <attestation>
```

### ZK Operations

```bash
# ZK operations
tenzro zk prove --circuit <circuit> --inputs <inputs>
tenzro zk verify --proof <proof>
```

### VRF Operations

```bash
# RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
# 80-byte proofs, 64-byte outputs, Ed25519-key-compatible

# Generate a fresh VRF secret key (hex)
tenzro vrf keygen

# Generate a VRF proof from a secret key and input (tenzro_generateVrfProof)
tenzro vrf prove --secret-key 0x... --alpha 0xdeadbeef

# Verify a VRF proof (tenzro_verifyVrfProof)
tenzro vrf verify --pubkey 0x... --proof 0x... --alpha 0xdeadbeef
```

### Custody Operations

```bash
# Custody operations
tenzro custody create --type multisig
tenzro custody approve --tx-id <id>
```

### App Operations

```bash
# App operations
tenzro app install <app>
tenzro app list
```

### Hardware Detection

```bash
# Detect hardware capabilities
tenzro hardware
```

### Username Management

```bash
# Set username
tenzro set-username <username>
```

### Faucet

```bash
# Request testnet TNZO (tenzro_faucet RPC)
tenzro faucet
```

### Info & Version

```bash
# Show network stats
tenzro info

# Show version
tenzro version --detailed
```

## Global Options

```bash
# Enable verbose logging
tenzro --verbose <command>

# JSON output format
tenzro --format json <command>
```

## Configuration

The CLI stores configuration and wallet data in:
- Linux: `~/.tenzro/`
- macOS: `~/.tenzro/`
- Windows: `%USERPROFILE%\.tenzro\`

### Directory Structure

```
~/.tenzro/
├── config.toml          # CLI configuration
├── wallets/             # Wallet keystores
│   ├── wallet_1.json
│   └── wallet_2.json
├── data/                # Node data (if running a node)
│   ├── db/
│   └── keystore/
└── models/              # Downloaded models
    └── gemma4-9b/
```

## Examples

### Running a Validator Node

```bash
# Guided: generates the validator keyset, writes a service unit, and prints
# the start + stake commands
tenzro setup --mode validate

# Or step by step:
# 1. Join network (provisions identity + wallet)
tenzro join

# 2. Stake tokens
tenzro stake deposit 100000 --provider-type validator

# 3. Start validator node (via tenzro-node binary)
tenzro-node --roles validator --data-dir ~/.tenzro/validator
```

### Becoming an Inference Provider

```bash
# 1. Register as provider
tenzro provider register --type inference --stake 10000

# 2. Download models
tenzro model download gemma4-9b

# 3. Start serving models (local or remote)
tenzro model serve gemma4-9b --gpus 0

# 4. Monitor provider status
tenzro provider status --detailed
```

### Participating in Governance

```bash
# 1. Check your voting power
tenzro stake info

# 2. List active proposals
tenzro governance list --active --detailed

# 3. Vote on proposals
tenzro governance vote prop_001 yes --reason "Good for the network"

# 4. Create your own proposal
tenzro governance propose \
  "Add new stablecoin support" \
  "Proposal to add DAI as supported stablecoin" \
  --type parameter
```

## Development

### Building from Source

```bash
# Build debug version
cargo build -p tenzro-cli

# Build release version
cargo build -p tenzro-cli --release

# Run tests
cargo test -p tenzro-cli
```

### Architecture

The CLI is organized into several modules:

- `main.rs` - Entry point and command routing
- `output.rs` - Output formatting utilities (tables, progress bars, colors)
- `rpc.rs` - Real JSON-RPC client (reqwest)
- `config.rs` - Configuration management
- `commands/` - Command implementations (103 modules: adaptive_burn, admin, agent, ap2, app, approval, attested_clock, auth, axelar, babylon, bitvm2, bond, bridge, bridge_fee, caip, canton, capability, capital, ccip, cct, cluster, compliance, contract, cortex, crosschain, crypto, custody, da, database, debridge, discover, dispute, eip7702, erc7579, erc7683, erc8004, escrow, events, function, global_supply, governance, hardware, hyperbridge, hyperlane, ibc_eureka, identity, inference, institution, insurance, interop, iroh, ivms101, join, keri, key, lease, lifi, machine, marketplace, mcp, media_gen, memory, model, moe, multimodal, near_chain_sig, nft, node, passkey, payment, permit2, pq_hybrid, presign, provenance, provider, reputation, resources, schedule, secure_mint, seed_agent, setup, site, siwt, skill, stable_asset, stake, stargate_v2, task, tee, token, tool, train, treasury, urwa, username, validator, vrf, wallet, workflow, wormhole, wormhole_ntt, x402, zk)

All commands use real JSON-RPC calls to tenzro-node RPC endpoints. No simulated calls, no artificial delays.

## License

Licensed under Apache License 2.0.
