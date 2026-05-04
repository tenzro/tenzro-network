# Tenzro Network CLI

The official command-line interface for operating Tenzro Network nodes, managing wallets, models, staking, and governance. Interact with Tenzro Ledger (the L1 settlement layer) and earn TNZO tokens.

## Features

- **Network Onboarding**: One-click participation via `join` command
- **Node Management**: Monitor node status
- **Wallet Operations**: Create MPC wallets, check balances, send transactions (real reqwest RPC client)
- **Model Management**: List, download, serve AI models (local + remote RPC)
- **Multi-Modal Inference**: Forecast, vision/text/video embedding, segmentation, detection, audio transcription via dedicated CLI commands
- **Staking**: Stake TNZO tokens as validator or provider
- **Governance**: Participate in on-chain governance and voting
- **Provider Tools**: Register and manage inference/TEE providers
- **Identity Management**: Register human/machine DIDs via TDIP
- **Payments**: MPP/x402 payment protocol support
- **Canton Integration**: DAML contract interaction
- **Agent Operations**: Register agents, spawn from templates, manage swarms
- **VRF Operations**: RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI prove/verify/keygen
- **AP2 / x402 / AAP**: Mandate validation, x402 facilitator payments, OAuth 2.1 + DPoP + RAR auth (with `aap` alias)
- **ERC-8004 Registry**: Trustless agent registration, reputation feedback, validation requests (with `8004` alias)
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
# One-click network participation (provisions identity, wallet, hardware profile)
tenzro join

# Check your balance
tenzro wallet balance

# List available models
tenzro model list

# Interactive chat with session history
tenzro chat
```

## Commands (48 top-level)

All commands use real JSON-RPC calls via reqwest. No artificial delays.

### Network Onboarding

```bash
# One-click join: provisions identity, wallet, hardware profile
tenzro join
```

### Node Management

```bash
# Check node status
tenzro node status

# Inspect a contiguous range of blocks (read-only catch-up probe).
# Calls tenzro_getBlockRange — returns up to 256 blocks per request,
# with nextHeight + moreAvailable for pagination across pruning gaps.
tenzro node sync-range --start 0 --end 255
```

### Wallet Operations

```bash
# Create a chain-agnostic 2-of-3 Ed25519 MPC wallet (calls tenzro_createWallet).
# A single wallet projects into EVM, SVM, and Canton via the pointer-token
# model — there is no per-chain wallet. Use `tenzro token cross-vm-transfer` /
# `tenzro token wrap-tnzo` for VM-specific operations, and `tenzro bridge` /
# `tenzro debridge` / `tenzro lifi` / `tenzro wormhole` for external chains.
tenzro wallet create

# Import existing wallet (calls tenzro_importIdentity RPC)
tenzro wallet import <seed-phrase|private-key>

# Check balance (calls eth_getBalance)
tenzro wallet balance --address <address>

# Send tokens. The CLI calls tenzro_signAndSendTransaction; the node looks up
# the live nonce and gas price, computes Transaction::hash() with the canonical
# timestamp-inclusive preimage, signs with Ed25519 + ML-DSA-65, verifies both
# legs synchronously, and returns -32003 on a bad signature. `value` and
# `amount` are accepted aliases. Self-sends (to == from) return a
# `cannot transfer to self` validation error.
tenzro wallet send <to-address> <amount> --asset TNZO --private-key <hex>

# List all wallets (calls tenzro_listAccounts)
tenzro wallet list
```

### Model Management

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

# Start serving a model (local llama.cpp + remote tenzro_serveModel RPC)
tenzro model serve gemma4-9b --gpus 0,1 --port 8080

# Stop serving (local + remote tenzro_stopModel RPC)
tenzro model stop gemma4-9b

# List model endpoints (tenzro_listModelEndpoints)
tenzro model endpoints

# Get specific endpoint (tenzro_getModelEndpoint)
tenzro model endpoint <model_id>

# Delete model
tenzro model delete gemma4-9b
```

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

```bash
# Timeseries forecasting (tenzro_forecast)
# Catalog: Chronos-2, Chronos-Bolt small/base, TimesFM 2.5 200M, Granite-TTM-r2
tenzro forecast --model chronos-bolt-small --context <values> --horizon 64

# Text embedding (tenzro_textEmbed)
# Catalog: Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M, BGE-M3, Snowflake Arctic
tenzro embed-text --model qwen3-embedding-0.6b --text "hello world"

# Image embedding / similarity (tenzro_visionEmbed, tenzro_visionSimilarity)
# Catalog: CLIP ViT-B/32 + L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16
tenzro embed-image --model siglip2-base --image ./photo.png

# Segmentation (tenzro_segment)
# Catalog: SAM 3 / 3.1, SAM 2 base/large, EdgeSAM, MobileSAM
tenzro segment --model sam-2-base --image ./photo.png --points "320,240"

# Object detection (tenzro_detect)
# Catalog: RF-DETR n/s/m/b/l/2xl, D-FINE n/s/m/l/x
tenzro detect --model rf-detr-medium --image ./photo.png --threshold 0.5

# Audio transcription (tenzro_transcribe)
# Catalog: Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT-v3, Canary-1B-Flash
tenzro transcribe --model whisper-large-v3-turbo --audio ./clip.wav

# Video embedding (tenzro_videoEmbed)
# Wave 1: catalog empty, scaffolding only
tenzro embed-video --model <pending> --video ./clip.mp4
```

License-tier gating applies on first load: CommercialCustom models (DINOv3, SAM, Gemma) require `--accept-license <id>`; non-commercial models require `--accept-non-commercial`.

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

`agentId = keccak256(utf8(did_string))` matches the native Tenzro
identity registry, so the same calldata works against either surface.

### Reputation

```bash
# Read the current score for a provider address
# (calls tenzro_getProviderReputation; integer 0-1000).
# Reputation update rule: +1 per successful inference (saturating to 1000),
# -5 per failure (saturating to 0). Durable in RocksDB across restarts.
tenzro reputation get 0xabc...
```

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

### Channel Disputes

Micropayment-channel disputes are first-class records in the settlement
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
# Register agent
tenzro agent register --name "MyAgent" --capabilities inference,trading

# List agents
tenzro agent list

# Send agent message (tenzro_sendAgentMessage)
tenzro agent send <agent_id> <message>

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
```

### Canton Integration

```bash
# List Canton domains (tenzro_listCantonDomains)
tenzro canton domains

# List DAML contracts (tenzro_listDamlContracts)
tenzro canton contracts

# Submit DAML command (tenzro_submitDamlCommand)
tenzro canton submit <command>
```

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
`SHA-256("tenzro/escrow/id/v1" || payer || nonce_le)` and emitted in the
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

```bash
# List skills (tenzro_listSkills)
tenzro skill list

# Register skill (tenzro_registerSkill)
tenzro skill register <skill>

# Search skills (tenzro_searchSkills)
tenzro skill search <query>

# Use skill (tenzro_useSkill)
tenzro skill use <skill_id> <params>

# Get skill (tenzro_getSkill)
tenzro skill get <skill_id>
```

### Tool Management

```bash
# List tools (tenzro_listTools)
tenzro tool list

# Register tool (tenzro_registerTool)
tenzro tool register <tool>

# Search tools (tenzro_searchTools)
tenzro tool search <query>

# Use tool (tenzro_useTool)
tenzro tool use <tool_id> <params>

# Get tool (tenzro_getTool)
tenzro tool get <tool_id>
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
# 1. Join network (provisions identity + wallet)
tenzro join

# 2. Stake tokens
tenzro stake deposit 100000 --provider-type validator

# 3. Start validator node (via tenzro-node binary)
tenzro-node --role validator --data-dir ~/.tenzro/validator
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
- `commands/` - Command implementations (48 modules)

All commands use real JSON-RPC calls to tenzro-node RPC endpoints. No simulated calls, no artificial delays.

## License

Licensed under Apache License 2.0.
