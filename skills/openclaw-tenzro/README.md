# TenzroClaw

[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://python.org)

The official [OpenClaw](https://github.com/openclaw/openclaw) skill for interacting with [Tenzro Network](https://tenzro.com) — a full blockchain and multi-chain toolkit for AI agents.

## Overview

TenzroClaw gives AI agents direct access to the Tenzro blockchain and the Chainlink MCP server (plus external 1inch) through a single Python script. Agents can manage identities, build transactions for their holders to sign, deploy contracts, bridge TNZO over governed routes, read Chainlink price feeds, run multi-modal AI inference, read AgentBonds, and more.

**Preview network:** `https://rpc.tenzro.com`

## Quick Start

```bash
# Tenzro blockchain
python3 tools/tenzro_rpc.py status
python3 tools/tenzro_rpc.py register_identity human Alice
python3 tools/tenzro_rpc.py list_models
python3 tools/tenzro_rpc.py join_network Alice

# Chainlink
python3 tools/tenzro_rpc.py chainlink_get_price ETH/USD
python3 tools/tenzro_rpc.py chainlink_list_feeds
```

## Installation

No installation required. Just clone and run:

```bash
git clone https://github.com/tenzro/TenzroClaw.git
cd TenzroClaw
python3 tools/tenzro_rpc.py --help
```

Optional: install `requests` for better HTTP handling (falls back to `urllib` if not available):

```bash
pip install requests
```

## Configuration

```bash
# Tenzro endpoints
export TENZRO_RPC_URL=https://rpc.tenzro.com
export TENZRO_API_URL=https://api.tenzro.com
export TENZRO_RPC_TIMEOUT=120

# A signed-in caller's access token and a fresh DPoP proof, where the node's
# access policy requires sign-in.
export TENZRO_BEARER_JWT=...
export TENZRO_DPOP_PROOF=...

# Chainlink MCP endpoint (optional — defaults to the preview network's endpoint)
export CHAINLINK_MCP_URL=https://chainlink-mcp.tenzro.com/mcp
```

## Capabilities

### Tenzro Blockchain

**Authentication (OAuth 2.1 + DPoP):** `onboard_human`, `onboard_delegated_agent`, `onboard_autonomous_agent` (each provisions a TDIP identity, hardware-rooted wallet, and access + refresh tokens), `refresh_token` (exchange refresh → fresh access token), `revoke_jwt`, `revoke_did`. Tokens follow RFC 6749 + RFC 9449 — pass `dpop_jkt` (RFC 7638 thumbprint of the holder's Ed25519 key) to bind the token to a holder key.

**Identity (TDIP):** `register_identity`, `resolve_did`, `list_identities`

**Device Binding & Machine Ownership:** `bind_device`, `list_bound_devices`, `wallet_readiness`, `revoke_bound_device`, `transfer_machine_ownership`. A Tenzro identity links devices the way a platform account does, except the link is not a platform account — no Apple, Google or Microsoft sign-in is an identity authority here; what is trusted is a WebAuthn attestation verified against a vendor root the node pins. A device counts as hardware-bound only when its credential cannot sync **and** the attestation says the key is in a TEE or secure element, so backup-eligibility is disqualifying rather than informational. `wallet_readiness` exists because a wallet cannot sit behind one device: it names the blocker and its remedy so an agent tells the user to scan the pairing QR instead of retrying a call that will keep failing. `revoke_bound_device` unbinds and ends every session that device authorised in one action — doing only the first would leave a lost phone's access live. `transfer_machine_ownership` takes one of two non-interchangeable authorities, `controller` (a party delegated the machine) or `hardware_root` (nobody did), so holding the hardware cannot take a machine that has an accountable party.

**AI Models & Inference:** `list_models`, `chat`, `inference_request`, `route_intent`, `chat_by_intent`, `record_route_outcome`, `route_difficulty_stats`, `serve_model`, `stop_model`, `get_model_provenance`, `submit_trust_record`, `list_model_endpoints`, `get_provenance`. Intent routing replaces naming a model with stating a use case plus a budget, a quality floor and a cost-quality knob: `route_intent` returns the selection and its reasoning without dispatching, `chat_by_intent` selects and runs in one call with dispatch pinned to the offer that was scored, so the price quoted is the price settled and the provider share goes to the address that offer named. Selection also accounts for how hard the prompt is — the decision carries the difficulty cluster it landed in and the chosen model's observed error rate there. `record_route_outcome` reports an escalation back so those rates reflect what happened; `route_difficulty_stats` reads the cluster map as an operator diagnostic. `serve_model` auto-clusters a model that exceeds one host — it reads the GGUF header for shape, discovers LAN members from gossiped `ClusterProfile` announcements, and runs a layer-wise pipeline; pass `force_cluster` to split even when it fits one host, `force_single` to pin it to one host, or set `visibility` to choose who may call it — `"network"` (the default) announces it and makes it reachable by any caller who pays, with no prior relationship; `"gated"` serves it only to callers the node's access policy names; `"private"` keeps it local/LAN-only. Model weights are content-addressed: a node fetches them peer-first over iroh blobs (BLAKE3-verified on transfer), and checks them against the catalog pins and the model's verified manifest before load; `get_model_provenance` reads a model's content-addressed manifests, the origins that observed them and whether they agree. `list_model_endpoints` returns each service's `iroh_endpoint_id` (the serving node's iroh `EndpointId`, empty for local-only); cross-node inference routes to it over the `tenzro/infer` ALPN. `get_provenance` resolves the cached synthetic-content manifest (EU AI Act Art. 50(2)) for generated output by its `content_hash`.

**Multi-Modal Inference (17 wrappers across 7 modalities):**

- **Forecast** — `list_forecast_catalog`, `load_forecast_model`, `forecast` (TimesFM 2.5)

Every `load_*_model` takes a catalog `model_id` and an optional `visibility`; `list_models` with `true` lists every loaded model of every type with its engine, visibility, access and state.
- **Vision** — `list_vision_catalog`, `vision_embed`, `vision_similarity` (CLIP, SigLIP2, DINOv3)
- **Text Embedding** — `list_text_embedding_catalog`, `text_embed` (Qwen3-Embedding, EmbeddingGemma, BGE-M3, Snowflake Arctic)
- **Segmentation** — `list_segmentation_catalog`, `segment` (SAM 3 / 3.1, SAM 2, EdgeSAM, MobileSAM)
- **Detection** — `list_detection_catalog`, `detect` (RF-DETR, D-FINE)
- **Audio (ASR)** — `list_audio_catalog`, `transcribe` (Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT, Canary)
- **Video** — `list_video_catalog`, `video_embed` (encoder scaffolding — catalog currently empty)

**Token Registry:** `list_tokens`, `get_token_info`, `get_token_balance`, `deploy_contract` (signed ContractDeploy)

**Network Duties:** `list_duties`, `get_duty`: work the chain pays the first prover for.

**Staking & Governance:** `role_stakes`, `list_proposals`, `governance_get`, `get_voting_power`. Bonding, proposals and votes are signed transactions.

**Bridge (governed routes):** `list_bridge_routes`, `get_bridge_route`. Outbound and inbound transfers are signed `Bridge` transactions. TNZO moves only over governed routes: a CCIP-compatible envelope for Ethereum, Base, Arbitrum and Solana, IBC, Bitcoin deposits and contract routes.

**Proof-of-Reserve:** `submit_reserve_attestation`, `get_reserve`.

**EVM Primitives (Permit2):** `permit2_verify_and_consume`, `permit2_nonce_used` (Permit2 `SignatureTransfer` with optional witness binding).

**AgentBond & Insurance:** `get_agent_bond`, `list_agent_bonds_by_controller`, `get_insurance_claim`, `list_insurance_claims`, `get_insurance_pool_balance`

**Network & Node:** `get_status`, `node_info`, `block_height`, `get_block`, `peer_count`, `syncing`, `node_did_document` — `node_did_document` resolves the node's DID Document, which carries every way of reaching it: its identifiers (TDIP DID, Ed25519 public key, iroh `EndpointId`, relays) plus its JSON-RPC / MCP / A2A / web service URLs, so a caller holding any one of them can get the rest. It is also served at `/.well-known/did.json` for generic DID resolvers.

**Universal RPC Gateway:** `list_rpc_methods`, `call_rpc`, `supports` — the escape hatch for anything without a named wrapper above. `list_rpc_methods` enumerates every method the node serves, each entry carrying how it is gated (`admin`, `owner`, `open` or `reserved`) and its method class, so you can tell what a call needs without provoking the error first; narrow with `namespace` or `contains`, since unfiltered it is ~900 rows. `call_rpc` invokes one by name. `supports` asks the node whether it serves a method rather than checking a list in this file, so it stays correct against a node newer than this skill. Authorization is unchanged — a gateway call passes the same gates as a direct request and reaches exactly what your credentials already allow.


**Decentralized Storage:** `storage_store_object`, `storage_set_pricing`, `storage_status` — content-addressed objects on the data plane, paid through storage compute claims that settle on possession-gated SLA verdicts.

**Compute Rental:** a rental is a stream escrow to the provider's bonded address (signed `CreateEscrow` with release `Stream`): it pays the provider by the epoch until its expiry, and an epoch validators judged unavailable is paid back to the renter from the insurance pool.

**Distributed MoE Serving:** planning — `moe_shard_map`, `moe_plan_dispatch`, `moe_replication_policy`, `moe_catalog_shape` — expert-shard placement, top-k dispatch planning, and replication policy across providers. Execution — `moe_prepare_experts` (slice + block-quantize a layer's experts for holders; `quant` is a preset string `q4_k_m`/`q8_0`/`q4_k`/`q6_k` or a per-projection object `{gate,up,down}`), `moe_prepare_status` (poll a prepare job by `job_id`), `moe_expert_status` (resident experts with residency tier — `Warm` in memory / `Cold` on disk — byte footprint, memory budget, and whether a GPU backend is active), `moe_forward` (run one distributed MoE layer across holders). Compute defaults to CPU (dense f32 + runtime-detected AVX-512-VNNI Q8_0) with an optional CUDA or cross-vendor GPU backend; cross-holder execution overlaps compressed activations, warm-first backup redispatch, and a pipelined gate-weighted combine.

**Local Discovery:** `node_profile` — the node's hardware self-profile.

**Cryptography:** `verify_signature`

**TEE Security:** `detect_tee`, `get_tee_attestation`, `verify_tee_attestation`, `list_tee_providers`

### Chainlink MCP Server

**Chainlink (13 tools):** `chainlink_get_price`, `chainlink_list_feeds`, `ds_get_report`, `ds_list_feeds`, `vrf_request_random`, `vrf_get_subscription`, `por_get_reserve`, `por_list_feeds`, `chainlink_check_upkeep`, `chainlink_get_upkeep_info`, `chainlink_estimate_functions_cost`, `chainlink_get_subscription`, `chainlink_broadcast_signed_tx`.

See [SKILL.md](SKILL.md) for the complete reference with all commands and curl examples.

## Using with OpenClaw

```yaml
skills:
  - name: tenzroclaw
    source: github.com/tenzro/TenzroClaw
    tools:
      - tools/tenzro_rpc.py
```

## Tests

```bash
python3 -m unittest tools/test_tenzro_rpc.py -v
```

The tests cover the wrappers' request shapes and the command table.

## Architecture

```
Your Agent
    |
    |-- python3 tenzro_rpc.py <command> [args...]
    |
    v
tenzro_rpc.py
    |
    |-- JSON-RPC POST ---------> rpc.tenzro.com    (Tenzro blockchain)
    |-- HTTP POST/GET ---------> api.tenzro.com    (verification)
    |-- MCP Streamable HTTP ---> chainlink-mcp.tenzro.com (Chainlink)
    |
    v
Tenzro Network (decentralized) + External Chains
```

## Related

| Resource       | URL                                                                                |
| -------------- | ---------------------------------------------------------------------------------- |
| Tenzro Network | [tenzro.com](https://tenzro.com)                                                   |
| JSON-RPC       | `https://rpc.tenzro.com`                                                           |
| Web API        | `https://api.tenzro.com`                                                           |

## Contact

- Website: [tenzro.com](https://tenzro.com)
- Engineering: [eng@tenzro.com](mailto:eng@tenzro.com)
- GitHub: [github.com/tenzro](https://github.com/tenzro)

## Owner-proof on resource mutations

Several tools take an identifier and also require a signed
DID envelope proving control of the resource. An identifier is not a credential:
a `jti` travels in every audit row, and a `session_id` is a handle the node hands back.

| Tool                                   | Proof required                                                                    |
| -------------------------------------- | --------------------------------------------------------------------------------- |
| `revoke_did`                           | node administrator **and** an envelope from the DID (or a machine's controller) |

Each envelope is bound to the method name and to that call's parameters, so one
produced for a given action cannot be replayed as another.

## License

Apache 2.0. See [LICENSE](LICENSE).
