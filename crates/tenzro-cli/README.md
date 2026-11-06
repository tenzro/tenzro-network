# Tenzro Network CLI

The official command-line interface for operating Tenzro Network nodes, managing wallets, models, staking, and governance. Interact with Tenzro Ledger (the settlement layer) and earn TNZO tokens.

## Features

- **Network Onboarding**: One-click participation via `join` command
- **Node Management**: Monitor node status
- **Live Status**: `tenzro status` — memory, accelerators, loaded models and traffic in one readout, with `--watch` for a continuous refresh and `--json` for scripting
- **Node Visibility**: `tenzro visibility` — advertise or withhold individual capabilities (ai, storage, database, hosting, rpc, tee, compute) without unloading them; consensus stays advertised so a validator can still vote
- **Storage**: `tenzro node storage` — on a storage provider, store and read back erasure-coded objects, set pricing, show status
- **Raw RPC Access**: `tenzro rpc` — discover every method the node serves along with how each is gated, and call any of them by name
- **Wallet Operations**: Create hardware-rooted wallets, check balances, send transactions (real reqwest RPC client)
- **Model Management**: List, download, serve AI models (local + remote RPC)
- **Multi-Modal Inference**: Forecasting, image/text/video embedding, point-and-box and text-promptable segmentation, object detection, and audio transcription — each a subcommand group with `catalog` / `list` / `load` / `unload` / `run`
- **Distributed MoE**: Expert-shard maps, dispatch planning, expert/gate weight loading, and distributed layer forwards via `tenzro moe`
- **Generative media**: List the media catalog and render images, video and audio via `tenzro media-gen`
- **Staking**: Stake TNZO tokens as validator or provider
- **Governance**: Participate in on-chain governance and voting
- **Provider Tools**: Register and manage inference/TEE providers
- **Identity Management**: Register human/machine DIDs via TDIP
- **Payments**: MPP/x402 payment protocol support
- **VRF Operations**: RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI prove/verify/keygen
- **x402 / AAP**: x402 facilitator payments, OAuth 2.1 + DPoP + RAR auth
- **Provenance**: Fetch C2PA-style manifests for AI-generated content (EU AI Act §50(2))
- **Chat Interface**: Interactive REPL against the node (output prefixed `[AI]` per EU AI Act §50(1))

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

## Commands

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
# (Ed25519 + ML-DSA-65) from this machine's hardware, assembles a schema-v3 genesis.toml,
# writes a service unit, and prints the start command plus the exact
# join command for each peer
tenzro setup --path local --network-name lab --yes

# One-click join: provisions identity, wallet, hardware profile
tenzro join
```

### Node Management

```bash
# Start a Tenzro Network node (forwards to the tenzro-node binary)
tenzro node start --roles validator

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

# admission-controller mempool stats: per-lane admit/reject counters
# and lane configuration.
tenzro node mempool-stats

# Resolve which admission lane an address falls in, plus its current
# token-bucket state.
tenzro node mempool-lane --address 0xabc...
```

### Live Status

```bash
# One frame of the node's resource and traffic readout: memory, accelerators,
# loaded models, and request throughput.
tenzro status

# Refresh continuously until interrupted. The floor is 500 ms — each frame is
# four RPCs, and polling faster than that measures the node's response to being
# polled rather than its actual load.
tenzro status --watch 2000

# One JSON object instead of the formatted readout, for scripting.
tenzro status --json
```

A panel that fails is reported as `null` rather than aborting the frame: a node
that is not serving models still has traffic and memory worth looking at, and an
operator diagnosing a half-up node is precisely who needs the half that works.
The readout also calls out whether a Hugging Face token is present — without one,
half the image catalog fails at download time with a 401 and nothing
otherwise connects that to a missing credential.

### Model Visibility and Access

Who may call a model is a property of the **model**, on top of the node's
access policy. A node whose policy is closed for everything else can still
publish models to the network, as long as its policy leaves `inference` open.

```bash
# Network (default) — announced on tenzro/models and reachable by ANY caller
# who pays. No prior relationship: a peer that found the offer over gossip
# has no way to sign in first, so requiring it would make the offer a lie.
tenzro model serve timesfm-2.5-200m

# Gated — servable only to callers your access policy names.
tenzro model serve partner-model --gated

# Private — never announced, never served off-node.
tenzro model serve house-model --private
```

`--gated` and `--private` are mutually exclusive; omitting both publishes.

The operator is the admin of their node and makes every gating decision on it:
the access policy (`tenzro-node access`, `tenzro access set`) and each model's
visibility. See [`docs/ACCESS.md`](../../docs/ACCESS.md) for the full model.

### Node Visibility

What this node advertises to the network, independent of what it can actually do.
Hiding a capability stops it being announced; it does not unload or disable it.

```bash
# Each capability and whether it is currently advertised.
tenzro visibility show

```

Administrator commands present the access token `tenzro access sign-in`
stored.

### Local Discovery

```bash

# This node's hardware self-profile from the ggml device API: build commit,
# CPU arch, OS, serving VRAM, and backend (calls tenzro_nodeProfile).
tenzro discover profile
```

### LAN Clustering

```bash

# List the verified members of this node's cluster, with the serving memory of
# those found on the local network and the pooled total (calls
# tenzro_clusterMembers). Pass --cluster-did to list another cluster.
tenzro cluster members

# Create a cluster (seq 1) or change its members (a higher seq): derive the
# cluster DID and the digests the operator's passkey and each member sign,
# have each member accept, then submit the approved list.
tenzro cluster derive --operator-did did:tenzro:human:<id> --name lab --seq 1 \
  --member did:tenzro:machine:<a> --member did:tenzro:machine:<b>
tenzro cluster accept --cluster-did did:tenzro:cluster:<id> --seq 1
tenzro cluster set --membership ./membership.json --challenge-id <id>
```

`cluster plan` is the explicit, inspect-the-plan path. To actually serve a
model across a cluster you do not need to compute or pass a plan: `tenzro
model serve` reads the model shape from the GGUF and auto-discovers members
over local gossip (see the Model Management section above and AI.md §3.5).

### Storage

```bash
# On a storage provider, as its operator: store an object, read it back.
tenzro node storage store --object-id corpus-1 --owner 0x... --file ./corpus.jsonl
tenzro node storage retrieve --object-id corpus-1 --out ./restored.jsonl
```

### Wallet Operations

```bash

# Check balance (calls eth_getBalance)
tenzro wallet balance --address <address>

# the node looks up the live nonce and gas price, computes Transaction::hash() with
# the canonical timestamp-inclusive preimage, signs with Ed25519 + ML-DSA-65,
# verifies both legs synchronously, and returns -32003 on a bad signature. `value`
# and `amount` are accepted aliases. Self-sends (to == from) return a
# `cannot transfer to self` validation error.
tenzro wallet send <to-address> <amount> --asset TNZO --private-key <hex>

```

#### Self-Custody (client-side hybrid signing)

The node never signs for the account. Its Ed25519 and ML-DSA-65 keys are derived
from this machine's TPM or Secure Enclave under a client key namespace
(`--key-namespace`, default `client`), used for one signature and wiped; nothing is
stored. The account address commits to both public keys. `wallet send
--self-custody` builds the canonical `Transaction::hash()` preimage (nonce and
chain id fetched from the node, PQ verifying key included), signs both legs locally,
and submits via `tenzro_sendRawTransaction`; the node verifies both signatures and that
they derive the `from` account. A machine with neither a TPM nor a Secure Enclave
is refused.

```bash
# Show the client account (fund it before sending from it).
tenzro wallet create-local --key-namespace payer-1

# Send TNZO signed as that account.
tenzro wallet send <to-account> <amount> --self-custody --key-namespace payer-1
```

### Model Management

The `tenzro` CLI is the full node surface: it downloads weights and serves
models so your node becomes a provider. If you only want to _use_ a model —
send a prompt to a provider that already serves it, with no node and no weights
— call a provider's public RPC through one of the SDKs (TypeScript, Python or
Rust) instead.

The rest of this section is for running the model yourself.

None of these models are Tenzro's own — they are third-party checkpoints the
node supports. Serving is model-agnostic: llama.cpp reads the architecture from
the GGUF's own metadata, and a model with no catalog entry serves on documented
defaults. A catalog entry exists to carry the per-model configuration that
actually varies — a multimodal projector, a paired drafter, a MoE shape, sampling
defaults, a replacement chat template — each of them optional, so a model
declares only what applies to it.

Listing a model does not mean it has been verified end to end. The registry is
broader than what has been exercised on real hardware. As models are tested and
issues surface they get fixed, and where a model needs something the generic path
does not give it, that becomes a new optional slot added as needed to run that
model — left unset for every model that does not need it. If one misbehaves,
report it.

**Gated models.** Some strong checkpoints are gated: their origin makes each
user accept a licence before fetching them. Their catalog entries say so and
name the licence. Read it and accept it with
`tenzro-node --accept-license <id>`; the node then fetches the weights from
other nodes by content hash, only from nodes whose operators accepted the same
licence. Without the acceptance the fetch is refused before any byte moves, and
the error names the flag. An operator with their own Hugging Face account can
also let their node fetch gated weights from the origin:
`tenzro-node credentials set huggingface` reads the account's token from stdin
and seals it to the machine's TPM or Secure Enclave (or, unsealed at the
operator's own risk, set `TENZRO_HUGGINGFACE_CREDENTIAL` in the node's
environment or `huggingface_credential` in its configuration). The network ships
no token; see docs/GUIDE.md 9.12.

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

Serving a model makes this node a provider once it holds the `ai` role
stake (`tenzro stake bond`), so the network routes hosted inference to it.

### Chat Interface

```bash
# Interactive REPL with session history
tenzro chat

# REPL commands: /history, /load <session_id>, /exit

# Pay for a turn from an open payment channel with the payer's signed
# `channel_voucher` (see docs/chat-api.md); the CLI does not sign vouchers.
tenzro chat gemma4-9b --channel-voucher voucher.json
```

All chat output (REPL, single-shot, streaming) is prefixed with `[AI]` per
EU AI Act Article 50(1). The literal lives in
`tenzro_node::eu_ai_disclosure::render_cli_chat_chunk` so the workspace can
audit the disclosure string in one place.

### Multi-Modal Inference

Each modality is a subcommand group with the same arms: `catalog` lists the
curated entries, `load` brings a model online, `unload` drops it, and `run`
performs inference. `tenzro model list --loaded` lists every model the node
holds, of every type, with its engine, visibility, access and state.

`load` is the same for every catalog modality: `--model <catalog id>` and an
optional `--visibility public|gated|private` (omitted follows the node). The
node fetches and verifies the files the signed catalog entry names, takes every
structural parameter (input size, embedding dimension, decoder ABI, class
count) from the entry, and applies its licence tier. A loaded model is served
under its catalog id, and survives a restart with the same visibility.

```bash
# Every loaded model, of every type
tenzro model list --loaded

# Timeseries forecasting (tenzro_forecast)
# Catalog: timesfm-2.5-200m, chronos-2, tirex-2, toto-2.0-22m, toto-2.0-313m
tenzro forecast catalog
tenzro forecast load --model timesfm-2.5-200m --visibility gated
tenzro forecast run --model timesfm-2.5-200m --context 1,2,3,4,5 --horizon 64

# Text embedding (tenzro_textEmbed)
# Catalog: qwen3-embedding-0.6b/-4b/-8b, embeddinggemma-300m, bge-m3,
#          modernbert-embed-base/-large, harrier-oss-v1-270m,
#          nemotron-3-embed-1b, qwen3-vl-embedding-2b (text, pictures, video)
tenzro embed-text load --model qwen3-embedding-0.6b
tenzro embed-text run --model qwen3-embedding-0.6b --input "hello world"
# A vision-language embedder also takes pictures and video frames; each
# --image / --video-frames is one input (--media-text joins text to it)
tenzro embed-text run --model qwen3-vl-embedding-2b --image ./photo.png --media-text "a red bicycle"
tenzro embed-text run --model qwen3-vl-embedding-2b --video-frames f1.png,f2.png,f3.png

# Image embedding / similarity (tenzro_imageEmbed, tenzro_imageTextSimilarity)
# Catalog: clip-vit-b32/-l14, siglip-base-224, siglip2-base-224/-large-256/-so400m-384,
#          dinov3-vits16/-vitb16/-vitl16
tenzro embed-image load --model siglip2-base-224
tenzro embed-image run --model siglip2-base-224 --image ./photo.png --normalize
tenzro embed-image similarity --image-embedding ./img.json --text-embedding ./txt.json

# Point/box segmentation (tenzro_segment)
# Catalog: sam2-base, sam2-large, edgesam, mobilesam
tenzro segment load --model sam2-base
tenzro segment run --model sam2-base --image ./photo.png --prompts ./prompts.json

# Open-vocabulary text-promptable segmentation (tenzro_textSegment)
# Catalog: sam3-vit-h
tenzro text-segment load --model sam3-vit-h
tenzro text-segment run --model sam3-vit-h --image ./photo.png --text "a red bicycle"

# Object detection (tenzro_detect)
# Catalog: rf-detr-nano/-small/-medium/-base/-large/-2xl, d-fine-n/-s/-m/-l/-x
tenzro detect load --model rf-detr-medium
tenzro detect run --model rf-detr-medium --image ./photo.png --score-threshold 0.5

# Speak text into a WAV file (tenzro_speak)
tenzro speech load --model qwen3-tts-1.7b
tenzro speech speak --model qwen3-tts-1.7b --text "Hello from Tenzro" --language en --seed 7 --out hello.wav

# Rerank documents against a query (tenzro_rerank), best first
# Catalog: qwen3-reranker-0.6b/-4b/-8b (text), qwen3-vl-reranker-2b (text, pictures, video)
tenzro rerank load --model qwen3-reranker-0.6b
tenzro rerank run --model qwen3-reranker-0.6b --query "what is a validator" \
  --document "A validator signs blocks." --document "Bread is baked." --top-n 1 --verification receipt
tenzro rerank run --model qwen3-vl-reranker-2b --query "a red bicycle" \
  --document-image ./bike.jpg --document-video-frames f1.png,f2.png,f3.png --document "A blue car."

# Answer typed questions about a text with a decision model (tenzro_decide)
# Catalog: laya (English, 512-token prompts, up to 64 questions per request)
tenzro decide load --model laya
tenzro decide run --model laya --state "WIN A FREE IPHONE now, click to claim" --yes-no "spam=Is this message spam?"
tenzro decide run --model laya --state-file ticket.json --questions @questions.json --verification receipt

# Audio transcription (tenzro_transcribe)
# Catalog: moonshine-tiny/-base, distil-whisper-small-en/-medium-en/-large-v3,
#          whisper-large-v3-turbo, parakeet-tdt-0.6b-v3, canary-1b-flash
tenzro transcribe load --model parakeet-tdt-0.6b-v3
tenzro transcribe run --model parakeet-tdt-0.6b-v3 --audio ./clip.wav --timestamps

# Video embedding (tenzro_videoEmbed)
# The native video catalog is empty — no permissive ONNX-shippable encoder-only
# video model exists yet. Register a vision-pooled fallback instead: it samples
# evenly-spaced frames in process, embeds each through a loaded image encoder,
# and mean-pools.
tenzro embed-video load --model vid --vision-model siglip2-base-224 --num-frames 8
tenzro embed-video run --model vid --video ./clip.mp4 --normalize
```

License-tier gating applies at load time. CommercialCustom models (DINOv3, SAM,
Gemma) need the node operator to have started `tenzro-node` with
`--accept-license <id>`; non-commercial models need `--accept-non-commercial`.
Those are node flags, not CLI flags — a `load` against a node that lacks the
acceptance is refused with a license error.

### Staking

```bash
# Bond stake for a role, signed in hardware (a Stake transaction). A node
# serves a bonded role only while its operator holds that role's bond; the
# validator role bonds through RegisterValidator.
tenzro stake bond --role rpc --amount 100000000000000000000000
tenzro stake bond --role storage --amount 50000000000000000000000 --terabytes 4
tenzro stake bond --role compute --amount 1000000000000000000000 --accelerators consumer,datacentre

# A wallet provider bonds for the passkey domain it serves; the domain must
# serve /.well-known/tenzro-provider naming the bonding account
tenzro stake bond --role wallet --amount 1000000000000000000000 --domain wallet.example
tenzro stake wallet-provider wallet.example

# Start unbonding, then withdraw once the unbonding period has passed
tenzro stake unbond --role rpc --amount 100000000000000000000000
tenzro stake withdraw --role rpc

# Stake per role (tenzro_getRoleStakes)
tenzro stake info --address <address>
```

### Governance

Proposals, votes, enactment and vetoes are signed transactions decided in
consensus; voting weight is bonded stake.

```bash
# List proposals, newest first (tenzro_listProposals)
tenzro governance list --kind policy_update

# Show one proposal and its tally (tenzro_getProposal)
tenzro governance show <proposal_id>

# List the governed network parameters, their bounds and any waiting change
tenzro governance params

# Propose a new value for one of them (applies from the next epoch if enacted)
tenzro governance propose-param --key dispute.max_rounds --value 4 --memo "why"

# Open any other proposal (a GovernancePropose transaction)
tenzro governance propose --from <address> \
  --action '{"action":"treasury_grant", ...}'

# Vote, enact once the timelock has run, or veto as a guardian
tenzro governance vote <proposal_id> --from <address> --yes
tenzro governance execute <proposal_id> --from <address>
tenzro governance veto <proposal_id> --from <address>

# Voting power and enacted network policy
tenzro governance voting-power <address>
tenzro governance policy economic_policy
```

### Provider Management

```bash
# Check provider status (tenzro_getProviderStats)
tenzro provider status --detailed

# List models you're serving
tenzro provider models

# Set pricing
tenzro provider pricing set <model_id> <price>
tenzro provider pricing show

# List all providers
tenzro provider list
```

### Model Stacks

```bash
# Show the model stack serving now and the next one
tenzro schedule stacks
```

### Identity Management

```bash
# Register human identity (tenzro_registerIdentity)
tenzro identity register --identity-type human --name "Alice"

# Register a machine under a controller (tenzro_registerMachineIdentity).
# The controller signs the request with its hardware key (--key-namespace);
# the node refuses a machine registration its controller did not sign.
tenzro identity register --identity-type machine --name kiosk \
  --controller <did> --public-key <machine x||y hex> --capabilities inference
# A controller whose key is a passkey prepares the request, signs its
# params_hash on the passkey device, then sends it:
tenzro identity register-machine --controller <did> --public-key <hex> \
  --capabilities inference --request-out req.json
tenzro identity register-machine --request-in req.json --did-envelope <hex>

# Resolve DID
tenzro identity resolve <did>

# List identities
tenzro identity list

# Get DID document
tenzro identity document <did>

```

### Device Binding and Machine Ownership

A Tenzro identity links devices the way a platform account does, except the link
is not a platform account. What the node trusts is a WebAuthn attestation it
verifies against a vendor root it pins — no Apple, Google or Microsoft sign-in is
an identity authority here. A device counts as hardware-bound only when its
credential cannot sync **and** the attestation says the key is in a TEE or secure
element.

```bash
# What can authenticate as this identity, and what each device proved
tenzro device list <did>
tenzro device list <did> --json

# May a wallet be created yet? If not, what is the remedy?
# A wallet cannot sit behind one device; --this-device is what lets the
# check notice that every bound device is the same machine.
tenzro device wallet-readiness <did> [--this-device <credential-id>]

# Lost phone: unbind it and end every session it authorised, in one action
tenzro device revoke <did> <credential-id>

# Hand a machine to another identity. The two authorities are not
# interchangeable: holding the hardware cannot take a machine that has an
# accountable party.
tenzro device transfer <machine-did> <new-owner-did> \
  --authority controller --controller-did <did>
tenzro device transfer <machine-did> <new-owner-did> \
  --authority hardware_root --hardware-root-hex <64-hex>
```

Binding a device (`tenzro_bindDevice`) happens through the browser ceremony
rather than the CLI — the attestation object comes from
`navigator.credentials.create()`. `bind`, `revoke` and `transfer` are
for node administrators; `list` and `wallet-readiness` are open.

### Interaction Receipts (the accounting layer)

An edge gateway can meter a request and charge for it; it cannot answer
afterwards, to somebody who trusts neither party, which party consumed what
under whose authority. Every interaction — a fetch, an inference, a storage
read, a marketplace call — shares one record and one content address.

The CLI takes the receipt as a JSON file; the one command today mirrors a
settlement record onto other chains, below.

### Parallel Settlement

```bash
# Mirror an anchored settlement onto several chains at once.
# Each target is dispatched independently — partial success is normal.
tenzro interaction mirror ./interaction.json --chain eip155:8453 --chain eip155:1

# Adapter chain names work too; both forms are accepted.
tenzro interaction mirror ./interaction.json --chain base --chain xrpl

# Digest-only: cheaper, but the record then does NOT survive the
# Tenzro Ledger losing state.
tenzro interaction mirror ./interaction.json --chain eip155:8453 --digest-only
```

The command reports `durable_beyond_primary` — whether the settlement survives
a testnet reset or a mainnet cutover — and warns when it does not.

### Settlement Rails and Micropayment Routing

Supporting x402 and being able to carry a micropayment are different properties.
Base speaks x402 fluently and still cannot carry a one-cent charge without
roughly 10% overhead, so a rail chosen on protocol support alone loses money on
every metered call.

```bash
# Every rail, cheapest-first, with the smallest worthwhile payment on each
tenzro rails list
tenzro rails list --x402-only
tenzro rails list --asset RLUSD
tenzro rails list --json

# Where would this charge settle? Four possible answers:
#   accumulate     — below the micro-settlement floor; hold it in a channel
#   primary        — the Tenzro Ledger
#   secondary      — the cheapest rail carrying the payee's asset
#   no_viable_rail — clears the floor, but nothing carries that asset this small
tenzro rails route 1000000000000000000 --asset USDC --tnzo-micro-usd 1000000
```

Omitting `--tnzo-micro-usd` settles on the home chain rather than routing real
money on a guessed exchange rate.

### Payment Operations

```bash
# Create payment challenge (tenzro_createPaymentChallenge); prints the challenge JSON
tenzro payment challenge /api/resource --protocol mpp --amount 100

# Verify a payment credential against its challenge (tenzro_verifyPayment)
tenzro payment verify --credential '<credential JSON>'
```

### AAP (Agent Access Protocol)

`tenzro auth` is the agent-facing layering on top of OAuth 2.1 + DPoP + RAR;
the underlying RPCs are the `tenzro_*Token*` and wallet-link methods.

```bash
# Refresh an access token
tenzro auth refresh --refresh-token <token>
```

### AgentBond and Insurance

```bash
# Post a stake bond for an agent (refundable on clean exit, slashable on fraud).
tenzro bond post --agent-id <id> --amount <tnzo>
tenzro bond increase --agent-id <id> --amount <tnzo>
tenzro bond withdraw --agent-id <id>
tenzro bond get --agent-id <id>
tenzro bond list

# Claim a leg's value a reconciliation mismatch of an attested route cost you.
# Signed in hardware as the harmed account. (An hour a provider was judged
# unavailable is never paid out of your stream, so there is nothing to claim.)
tenzro insurance claim --recon-adapter <adapter> --recon-chain <chain> --recon-position <n>
tenzro insurance list
tenzro insurance get <claim-id>
tenzro insurance pool

# Rent compute: a stream escrow to the provider, with a reference your
# application chose
tenzro escrow create --payee <addr> --amount <wei> --expires-at <ms> \
  --release stream --rate-per-epoch <wei> --epoch-ms 3600000 --reference <hex32>
```

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

### Generative media

`tenzro media-gen` lists the media catalog and renders one output
(`tenzro_mediaGen_listCatalog`, `tenzro_mediaGen_render`). The node renders on
its in-process Praecise diffusion engine with the media models it has loaded
(`tenzro model load-media-model`, which checks the model against the catalog
and the licences the operator accepted with `--accept-license <id>` or
`--accept-non-commercial`).

```bash
tenzro media-gen catalog                            # all rows; [split] marks expert pairs
tenzro media-gen catalog --kind text2video
tenzro media-gen render --model z-image-turbo --kind text2image \
  --params ./params.json --out ./render.png
```

`params.json` is a `MediaGenParams` object with a `seed`. The answer carries
the signed receipt over the output's SHA-256 and perceptual fingerprint and the
price the node metered it at.

### Step-up of a held action

An agent acts only within its consensus Terms. When the Terms hold an action
for the root (`step_up_above`, `step_up_new_counterparty`, a tainted action),
`tenzro agent delegation act` is refused with a `step_up` challenge in the error data.
The root's passkey signs that challenge, and the agent sends
the same action again with the assertion:

```bash
tenzro agent delegation act --operation transfer --counterparty <hex> --amount <wei> \
  --step-up step-up.json
```

The step-up covers that one action (its digest includes the agent's action
nonce), so it cannot be replayed or reused for a different amount or
counterparty. Without it, or once the nonce has moved on, the action is
refused. The VM checks the step-up again at execution.

### Evidence packs and trained-model provenance

```bash
# Export an agent's evidence pack, with this node's signed tool-call records
tenzro agent audit evidence export --agent <did> --audit audit.json --out pack.json
# Write its EU AI Act profile: which records support Art. 12 and Art. 14
tenzro agent audit evidence profile --file pack.json --out profile.json
# Verify both offline from the chain's genesis anchor
tenzro agent audit evidence verify --file pack.json --profile profile.json \
  --chain-id <id> --genesis-hash <hex> --genesis-committee-root <hex>
# Verify where a trained model came from, and that the weights are the ones named
tenzro provenance model --file pack.json --chain-id <id> --genesis-hash <hex> \
  --genesis-committee-root <hex> --weights adapter.gguf
```

A profile lists evidence; it is not a legal assessment. See
[docs/AGENT_TRUST.md](../../docs/AGENT_TRUST.md) and [docs/AI.md](../../docs/AI.md).

### Provenance (EU AI Act §50(2))

Tenzro records a C2PA-style `ContentProvenanceManifest` per AI-generated content,
keyed by `content_hash` (SHA-256 of the output bytes). Validators sign and
persist these manifests; this command fetches one back.

```bash
# Fetch the cached manifest for a 32-byte content hash
# (calls tenzro_getContentProvenance; -32004 if no manifest exists for this hash)
tenzro provenance get 0x<sha256_hex>
```

### Agent Operations

```bash

# Fund an agent's wallet: a transfer signed as this machine's client account
tenzro agent fund --agent-id <id> --amount-wei <wei>

```

#### Kill-switch

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

### Node Access

Who may use a node is its access policy (`access.toml`; see
[`docs/ACCESS.md`](../../docs/ACCESS.md)). The operator sets it on the machine
with `tenzro-node access` (a wizard, or `--preset` / `--admin` flags, or
`--page` for the loopback admin page); administrators change it remotely here.

```bash
# Sign in with this machine's hardware key; the access token is stored and
# presented, with a fresh DPoP proof, by every later command.
tenzro access sign-in --rpc http://127.0.0.1:8545

# Administrators: the policy, a dry run, and the live tokens.
tenzro access show
tenzro access set ./access.toml
tenzro access preview --surface rpc --method tenzro_chat --did did:tenzro:human:...
tenzro access tokens
tenzro access revoke --jti <jti>
tenzro access revoke --did did:tenzro:human:...
```

There are no API keys, service keys or admin token. A passkey signs in through
the same two RPCs (`tenzro_accessChallenge`, `tenzro_issueAccessToken`) from a
browser or an SDK.

### Bridge Fee in TNZO

Converts a destination-native bridge fee into TNZO at the USD rates
validators commit on chain (the stake-weighted median of their per-symbol
`FeeRateSubmit` reports). A quote is refused while the destination's native
asset is unpriced.

```bash
tenzro bridge-fee quote --adapter ccip --dest-chain eip155:1 \
    --native-fee 1000000
```

Rate-limit rejections surface as JSON-RPC error code `-32005` with a
`data: { retry_after_ms, rate_per_second, burst }` envelope so SDKs
can implement client-side backoff.

### Escrow Operations

Escrow `create` / `release` / `refund` are consensus-mediated typed transactions
(`CreateEscrow`, `ReleaseEscrow`, `RefundEscrow`) signed with the payer's
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

### Network Duties and Evidence

Task markets run in harnesses over the public RPC; the chain holds their
escrows and checks their evidence. Work the chain pays for itself is a duty.

```bash
# Open duties (a route's reconciliation, a voided grant's install)
tenzro duty list
tenzro duty get <duty-id>

# Check evidence items against chain state before releasing an escrow
tenzro agent audit evidence check --items items.json
```

### Token Operations

```bash
# Create token (a signed Token transaction)
tenzro token create --name "MyToken" --symbol "MTK" --decimals 18 --supply 1000000

# Get token info (tenzro_getToken)
tenzro token info --address <address>

# List tokens (tenzro_listTokens)
tenzro token list

# Get balance (tenzro_getTokenBalance)
tenzro token balance <token_id> <address>

# Calls across VMs as one all-or-nothing transaction (a token moves between
# VMs through its interface in the sending VM)
tenzro contract call --from <address> \
  --call evm:<contract hex>:<calldata hex> \
  --call svm:<program hex>:<instruction hex>
```

### Contract Operations

```bash
# Deploy an EVM contract: a ContractDeploy transaction signed in hardware
tenzro contract deploy --bytecode <hex> [--args <hex>]
```

### Bridge Operations

```bash
# Governed routes, with caps, usage and supply
tenzro bridge routes
tenzro bridge route --adapter ccip --chain ethereum

# Send TNZO out: prepare, sign the printed bytes with the holder's key, send
tenzro bridge send --from <addr> --amount <amount> --to-chain base \
  --recipient <hex> --nonce 1 --chain-id 133801 --request-out send.json
tenzro bridge send --request-in send.json --public-key <hex> --signature <hex>

# Deliver a committee-attested inbound transfer
tenzro bridge deliver --adapter ccip --from-chain ethereum --delivery <hex>
```

### Event Monitoring

```bash
# Event monitoring
tenzro events subscribe --topics <topics>
```

### Crypto Operations

```bash
# Crypto operations
tenzro crypto verify --message <message> --signature <sig> --key <pubkey>
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

# Verify a VRF proof (tenzro_verifyVrfProof)
tenzro vrf verify --pubkey 0x... --proof 0x... --alpha 0xdeadbeef
```

### Hardware Detection

```bash
# Detect hardware capabilities
tenzro hardware
```

### Info & Version

```bash
# Show network stats
tenzro info

# Show version
tenzro version --detailed
```

### Raw RPC Access

Discover and call any JSON-RPC method the node serves, including ones with no
dedicated subcommand. Useful for a method added since your CLI build.

```bash
# Every method this node serves, with how each one is gated.
tenzro rpc methods

# Narrow it down.
tenzro rpc methods --namespace eth
tenzro rpc methods --contains serve

# List the namespaces rather than the methods.
tenzro rpc methods --namespaces

# Call anything by name. --params takes a JSON object, default {}.
tenzro rpc call tenzro_previewServe --params '{"model_id":"qwen3-8b"}'
```

`tenzro rpc methods` reports each method's gate, so it doubles as the reference
for what a call needs: an `admin` method needs an administrator signed in with
`tenzro access sign-in`, and every method passes the node's access policy.

## Global Options

```bash
# Enable verbose logging
tenzro --verbose <command>

# JSON output format
tenzro --format json <command>
```

## Configuration

Everything Tenzro writes on a machine lives under one root: `$TENZRO_HOME`, or
`~/.tenzro` when that is unset. The CLI, the node and the desktop app all
resolve it the same way, so a model you download with `tenzro model download`
is the one your node serves.

### Directory structure

```
$TENZRO_HOME                 (default: ~/.tenzro)
├── models/                  # shared — GGUF weights, ONNX bundles
├── hf/                      # shared — HuggingFace cache (exported as HF_HOME)
├── instances/               # per-instance node state
│   ├── default/             #   RocksDB, keys, wallets, snapshots, iroh blobs
│   └── validator/           #   a second node started with --data-dir
├── networks/<name>/         # named local networks (genesis.toml + data)
├── config.json              # CLI configuration and tokens
├── passkey/                 # ML-DSA passkey companion seeds
└── logs/                    # node logs from the service wrappers
```

### Shared versus per-instance

Model weights, the HuggingFace cache and dataset shards are **shared** across
every Tenzro process on the machine — content-addressed and read-only once
written, so two nodes have no reason to hold separate copies of the same tens
of gigabytes.

Chain state is **per-instance**, because RocksDB cannot be shared: the second
process to open the same directory fails on its lock file. A single-node
machine never has to think about this; the default instance is
`instances/default/`.

### Running two nodes on one machine

```bash
tenzro node start --data-dir "$TENZRO_HOME/instances/alpha"
tenzro node start --data-dir "$TENZRO_HOME/instances/beta"
```

Both resolve the same `models/` and `hf/`, so weights download once and serve
from both. Their chain state is separate.

### Running an isolated install

```bash
TENZRO_HOME="$HOME/tenzro-scratch" tenzro node start
```

Everything moves together — models, caches, instance data, CLI config. This is
the supported way to run a second environment without touching your real state.

### Overrides

| Setting                         | Effect                                                  |
| ------------------------------- | ------------------------------------------------------- |
| `--data-dir <DIR>`              | per-instance directory; a leading `~` is expanded       |
| `models_dir` in the node config | shared model store, e.g. weights on a separate NVMe     |
| `HF_HOME`                       | HuggingFace cache, for a site-wide cache outside Tenzro |
| `TENZRO_TRAINER_CACHE`          | dataset shard cache                                     |

## Examples

### Running a Validator Node

```bash
# Guided: generates the validator keyset, writes a service unit, and prints
# the start + stake commands
tenzro setup --mode validate

# Or step by step:
# 1. Join network (provisions identity + wallet)
tenzro join

# 3. Start validator node (via tenzro-node binary)
tenzro-node --roles validator --data-dir ~/.tenzro/validator
```

### Becoming an Inference Provider

```bash

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
- `commands/` - Command implementations (73 modules: `access`, `adaptive_burn`, `agent`, `agent_accounts`, `agent_delegation`, `auth`, `beacon`, `bond`, `bridge`, `bridge_attest`, `bridge_fee`, `bridge_ibc`, `bridge_withdrawal`, `catalog`, `cluster`, `contract`, `crypto`, `da`, `dev`, `device`, `discover`, `duty`, `escrow`, `events`, `evidence`, `fee_market`, `finality`, `funding`, `governance`, `hardware`, `identity`, `inference`, `insurance`, `iroh`, `join`, `machine_access`, `media_gen`, `model`, `moe`, `multimodal`, `node`, `node_upgrade`, `org`, `passkey`, `payment`, `permit2`, `pq_hybrid`, `provenance`, `provider`, `rails`, `reserve`, `rpc_cmd`, `schedule`, `settle`, `setup`, `signed_request`, `signer`, `stake`, `status_bar`, `tee`, `token`, `trust`, `tx`, `urwa`, `validator`, `visibility`, `vrf`, `wallet`, `x402`, `zk`)

All commands use real JSON-RPC calls to tenzro-node RPC endpoints. No simulated calls, no artificial delays.

## License

Licensed under Apache License 2.0.
