"""Agent Card builder — serves at /.well-known/agent.json for A2A discovery."""


def build_agent_card(base_url: str = "https://a2a.tenzro.network") -> dict:
    """Build the A2A Agent Card with all 31 skills."""
    return {
        "name": "Tenzro Network Agent",
        "description": (
            "Tenzro Network -- AI-native agentic tokenized settlement layer. "
            "Provides wallet operations, identity management, inference routing, "
            "settlement, and blockchain interaction."
        ),
        "url": f"{base_url}/a2a",
        "version": "0.1.0",
        "protocolVersion": "0.2.0",
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "skills": [
            {
                "id": "wallet",
                "name": "Wallet Operations",
                "description": (
                    "Create wallets, check balances, and send TNZO transactions "
                    "on the Tenzro network."
                ),
                "tags": ["blockchain", "wallet", "payments"],
                "examples": [
                    "Check my TNZO balance",
                    "Send 10 TNZO to 0xabc...",
                    "Create a new wallet",
                ],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain", "application/json"],
            },
            {
                "id": "identity",
                "name": "Identity Management",
                "description": (
                    "Register and resolve decentralized identities (DIDs) "
                    "on the Tenzro Decentralized Identity Protocol (TDIP). "
                    "Manage human-readable usernames with set_username and "
                    "resolve_username for easy identity lookup."
                ),
                "tags": ["identity", "did", "credentials", "username"],
                "examples": [
                    "Register a new identity",
                    "Resolve DID did:tenzro:human:abc123",
                    "Set my username to alice",
                    "Resolve username bob",
                ],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain", "application/json"],
            },
            {
                "id": "inference",
                "name": "AI Inference",
                "description": (
                    "Route AI inference requests to model providers on the "
                    "Tenzro network, with settlement in TNZO."
                ),
                "tags": ["ai", "inference", "models"],
                "examples": [
                    "List available AI models",
                    "Run inference on model X",
                ],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain", "application/json"],
            },
            {
                "id": "cortex",
                "name": "Cortex Reasoning Workers",
                "description": (
                    "Tenzro Cortex reasoning-tier inference via signed receipts. "
                    "Dispatch requests to local or remote cortex workers with a "
                    "reasoning budget (Fast/Standard/Deep), MoE (rdt-moe) model "
                    "family constraints, and per-request max_cost_wei cap. "
                    "Every response carries a verifiable receipt bound to the "
                    "worker DID, loops_used, tokens_in/out, weights_hash, "
                    "runtime_hash, and Ed25519 signature. Discover remote "
                    "workers advertised on the tenzro/cortex gossip topic via "
                    "tenzro_listRemoteCortexWorkers, and observe live throughput "
                    "through the shared CortexMetrics exporter on /metrics."
                ),
                "tags": [
                    "cortex", "reasoning", "inference", "ai", "moe",
                    "receipts", "verifiable", "gossip", "metrics",
                ],
                "examples": [
                    "List remote cortex workers on the network",
                    "Run Standard-tier reasoning on mythos-3b (metadata.input, max_cost_wei)",
                    "Run Fast-tier cortex inference with budget 1e18 wei (1 TNZO)",
                    "Verify a cortex receipt (metadata.receipt)",
                    "Get cortex worker metrics from /metrics",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "settlement",
                "name": "Settlement & Payments",
                "description": (
                    "Settle payments for AI services using micropayment channels, "
                    "escrow, and batch settlement on the Tenzro ledger."
                ),
                "tags": ["settlement", "payments", "escrow"],
                "examples": [
                    "Check settlement status",
                    "Open a micropayment channel",
                ],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain", "application/json"],
            },
            {
                "id": "verification",
                "name": "Proof Verification",
                "description": (
                    "Verify ZK proofs, TEE attestations, and transaction signatures "
                    "on the Tenzro network."
                ),
                "tags": ["verification", "zk-proofs", "tee"],
                "examples": [
                    "Verify a ZK proof",
                    "Check TEE attestation",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "staking",
                "name": "Staking & Provider Management",
                "description": (
                    "Stake TNZO tokens, manage validator/provider registration, "
                    "and query provider performance statistics."
                ),
                "tags": ["staking", "provider", "validator"],
                "examples": [
                    "How much TNZO is staked?",
                    "Register as a model provider",
                    "Get provider statistics",
                ],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain", "application/json"],
            },
            {
                "id": "task_marketplace",
                "name": "Task Marketplace",
                "description": (
                    "Post tasks to the decentralized AI task marketplace, browse "
                    "open tasks, submit quotes, and track task completion with "
                    "TNZO escrow-based payment."
                ),
                "tags": ["tasks", "marketplace", "ai", "escrow"],
                "examples": [
                    "Post a code review task for 50 TNZO",
                    "List open inference tasks",
                    "Get task status for task-id-123",
                    "Cancel my pending task",
                    "Submit a quote for task-id-456",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "agent_marketplace",
                "name": "Agent Marketplace",
                "description": (
                    "Publish, discover, rate, and spawn reusable AI agent templates on "
                    "the Tenzro decentralized agent marketplace. Search templates "
                    "by capability, type, and pricing model. Rate templates, view "
                    "template stats, and spawn running agents from templates."
                ),
                "tags": ["agents", "marketplace", "templates", "ai", "rating"],
                "examples": [
                    "List available agent templates",
                    "Register a new coding agent template",
                    "Search for autonomous agent templates",
                    "Get agent template details for template-id-789",
                    "Rate template template-id-789 with 5 stars",
                    "Spawn an agent from template template-id-789",
                    "Get stats for agent template template-id-789",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "agent_spawning",
                "name": "Agent Spawning",
                "description": (
                    "Dynamically spawn autonomous sub-agents with specific capabilities. "
                    "Parent agents can create up to 50 children, each with its own DID "
                    "and MPC wallet. Supports hierarchical agent topologies."
                ),
                "tags": ["agents", "spawning", "autonomous", "orchestration"],
                "examples": [
                    "Spawn a sub-agent with coding capabilities",
                    "List my child agents",
                    "Run an autonomous agent task",
                    "Spawn an agent named 'researcher' with web-search capability",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "swarm_orchestration",
                "name": "Swarm Orchestration",
                "description": (
                    "Create and manage agent swarms for parallel task execution. "
                    "An orchestrator agent can create a swarm of specialized sub-agents, "
                    "broadcast tasks to all members simultaneously, collect results, "
                    "and terminate the swarm when done."
                ),
                "tags": ["swarm", "orchestration", "parallel", "agents"],
                "examples": [
                    "Create a swarm with 3 research agents",
                    "Get swarm status for swarm-id-123",
                    "Terminate swarm swarm-id-456",
                    "Broadcast 'analyze this dataset' to my swarm",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "lifecycle",
                "name": "Agent Lifecycle Kill-Switch",
                "description": (
                    "Three-tier intervention for spawned agents: pause (reversible halt), "
                    "quarantine (halt + freeze stake), terminate (irreversible, optional "
                    "stake slash, optional cascade to descendants). Backed by on-chain "
                    "kill-switch precompiles with full receipt audit trail. EU AI Act "
                    "Article 14 / Article 16 compliant — controllers retain hard-stop "
                    "authority over their machine identities."
                ),
                "tags": ["lifecycle", "kill-switch", "governance", "compliance", "safety"],
                "examples": [
                    "Pause agent did:tenzro:machine:abc123",
                    "Quarantine agent did:tenzro:machine:xyz789 with evidence hash",
                    "Terminate agent did:tenzro:machine:def456 with 50% slash and cascade",
                    "List kill-switch receipts for controller did:tenzro:human:ctrl-1",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "bond-insurance",
                "name": "AgentBond & Insurance",
                "description": (
                    "Surety primitive for autonomous agents (Agent-Swarm Spec 9). "
                    "Controllers (or autonomous machines) post TNZO bonds as "
                    "skin-in-the-game; an Active bond above the promotion threshold "
                    "elevates a Machine identity into the Delegated admission lane "
                    "even without a verified human controller. Bonds back insurance "
                    "claims: harmed parties file claims with receipts, governance "
                    "adjudicates, and approved payouts settle from a deterministic "
                    "insurance pool. Lifecycle: Active → Cooldown → Returned, or "
                    "Active → Frozen → Slashed under quarantine/termination."
                ),
                "tags": ["bond", "insurance", "surety", "delegation", "governance", "spec-9"],
                "examples": [
                    "Post a 1000 TNZO bond on agent did:tenzro:machine:abc123",
                    "Increase the bond on did:tenzro:machine:abc123 by 500 TNZO",
                    "Get the bond state for agent did:tenzro:machine:abc123",
                    "List all bonds posted by did:tenzro:human:ctrl-1",
                    "File an insurance claim against did:tenzro:machine:abc123 for 200 TNZO",
                    "Show insurance pool balance and open claim count",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "token",
                "name": "Token Management",
                "description": (
                    "Create ERC-20 tokens, query token info and balances, "
                    "transfer tokens across VMs (EVM, SVM, DAML), and wrap "
                    "native TNZO to VM representations via the unified token registry."
                ),
                "tags": ["token", "erc20", "cross-vm", "registry"],
                "examples": [
                    "Create a new token called MyToken (MTK) with 1M supply",
                    "Get token info for TNZO",
                    "List all registered tokens",
                    "Get my TNZO balance across all VMs",
                    "Transfer 100 TNZO from EVM to SVM",
                    "Wrap 50 TNZO for EVM",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "contract",
                "name": "Smart Contract Deployment",
                "description": (
                    "Deploy smart contracts to the Tenzro multi-VM runtime "
                    "(EVM, SVM, DAML). Submit bytecode with constructor arguments "
                    "and receive the deployed contract address."
                ),
                "tags": ["contract", "deploy", "evm", "svm", "daml"],
                "examples": [
                    "Deploy an EVM contract with bytecode 0x6080...",
                    "Deploy a Solana program",
                    "What VMs are supported for contract deployment?",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "ap2-payments",
                "name": "AP2 Payments & Mandates",
                "description": (
                    "Agent Payments Protocol (AP2) session lifecycle plus "
                    "Google-spec mandate verification. Create sessions, "
                    "authorize/execute/cancel payments, verify Checkout/Payment "
                    "Verifiable Digital Credentials (VDCs), validate Checkout+Payment pairs "
                    "for consistency, and fetch protocol metadata."
                ),
                "tags": [
                    "payments", "ap2", "agentic", "settlement", "mandates",
                    "vdc", "checkout", "payment", "verifiable-credentials",
                ],
                "examples": [
                    "AP2 protocol info",
                    "Create AP2 session (metadata.agent_did, provider_did, max_amount)",
                    "Authorize 100 TNZO on session <id>",
                    "Execute session <id> (metadata.authorization_id)",
                    "Cancel session <id>",
                    "Verify AP2 mandate (metadata.vdc)",
                    "Validate AP2 checkout/payment pair (metadata.checkout_vdc, payment_vdc)",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "erc8004",
                "name": "ERC-8004 Trustless Agents",
                "description": (
                    "On-chain agent identity and reputation via ERC-8004. "
                    "Derive deterministic agent IDs, encode registry calldata "
                    "(register, getAgent, feedback, validationRequest, "
                    "validationResponse), and decode getAgent returndata for "
                    "integration with any EVM-compatible registry contract."
                ),
                "tags": [
                    "erc-8004", "agents", "reputation", "identity",
                    "registry", "calldata",
                ],
                "examples": [
                    "Derive agent id (metadata.owner, metadata.salt)",
                    "Register agent (metadata.agent_id, registration_data_uri, owner)",
                    "Get agent <id> (metadata.agent_id)",
                    "Submit feedback (agent_id, score, feedback_auth_id, feedback_uri)",
                    "Request validation (agent_id, validator_id, request_uri, data_hash)",
                    "Submit validation (data_hash, response, response_uri, tag)",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "wormhole",
                "name": "Wormhole Cross-Chain",
                "description": (
                    "Wormhole cross-chain messaging and token transfers. "
                    "Look up numeric chain ids, parse canonical VAA identifiers, "
                    "and bridge tokens through the Wormhole adapter registered "
                    "on the node's BridgeRouter."
                ),
                "tags": [
                    "wormhole", "bridge", "cross-chain", "vaa",
                    "ethereum", "solana", "base", "arbitrum", "optimism",
                ],
                "examples": [
                    "Wormhole chain id for ethereum",
                    "Wormhole chain id for solana",
                    "Parse VAA 2/0x00000000000000000000.../12345",
                    "Bridge 100 TNZO from ethereum to solana (metadata.sender/recipient)",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "cct",
                "name": "TNZO CCT Pool Registry",
                "description": (
                    "Chainlink Cross-Chain Token (CCT) pool registry for TNZO. "
                    "Ethereum uses a LockRelease pool; Base, Arbitrum, Optimism, "
                    "and Solana use BurnMint pools. Query pool addresses, chain "
                    "selectors, and per-chain rate-limiter configuration."
                ),
                "tags": [
                    "cct", "chainlink", "cross-chain", "ccip",
                    "lockrelease", "burnmint", "pool", "rate-limit",
                ],
                "examples": [
                    "List CCT pools",
                    "Get CCT pool on ethereum",
                    "Get CCT pool on base",
                    "Get CCT pool on solana",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "auth",
                "name": "Authentication (OAuth 2.1 + DPoP)",
                "description": (
                    "OAuth 2.1 + DPoP auth flows: onboard humans and agents, "
                    "refresh expired access tokens, and link an existing MPC "
                    "wallet to a new auth session. Issues HS256 access tokens "
                    "(1h TTL) and opaque UUID refresh tokens (30-day TTL). "
                    "Pass metadata.dpop_jkt -- the RFC 7638 SHA-256 thumbprint "
                    "of a client-held P-256/Ed25519 public key -- to bind the "
                    "issued access token to a key the client controls."
                ),
                "tags": [
                    "auth", "oauth", "dpop", "onboarding", "refresh-token",
                    "wallet", "rfc-9449", "rfc-7638",
                ],
                "examples": [
                    "Onboard human Alice",
                    "Onboard delegated agent (metadata.controller_did, capabilities, delegation_scope)",
                    "Onboard autonomous agent (metadata.bond_funding_address)",
                    "Refresh my access token (metadata.refresh_token, optional dpop_jkt)",
                    "Link wallet for auth (metadata.wallet_id)",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "join",
                "name": "Join as MicroNode",
                "description": (
                    "Join the Tenzro Network as a full MicroNode participant -- "
                    "zero-install. Auto-provisions a TDIP DID, MPC wallet, and "
                    "10 network capabilities (inference, payments, agent collaboration, "
                    "MCP tools, task execution, chain queries, smart contracts, "
                    "TEE compute, cross-chain bridge, governance)."
                ),
                "tags": ["join", "onboarding", "micronode", "identity", "wallet"],
                "examples": [
                    "Join the Tenzro Network as Alice",
                    "Create a new identity on Tenzro",
                    "Onboard to Tenzro with username Bob",
                    "Join as a MicroNode",
                ],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain", "application/json"],
            },
            {
                "id": "nft",
                "name": "NFT Management",
                "description": (
                    "Create and manage NFT collections (ERC-721/1155), mint tokens, "
                    "transfer, query ownership, cross-VM pointers."
                ),
                "tags": ["nft", "erc721", "erc1155", "collectibles", "cross-vm"],
                "examples": [
                    "Create a new ERC-721 NFT collection",
                    "Mint an NFT in collection 0xabc...",
                    "Transfer NFT #42 to 0xdef...",
                    "Query ownership of NFT #7",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "bridge",
                "name": "Cross-Chain Bridge",
                "description": (
                    "Cross-chain bridge operations via LI.FI aggregator (58+ chains), "
                    "LayerZero, CCIP v1.6, deBridge with hooks."
                ),
                "tags": ["bridge", "cross-chain", "lifi", "layerzero", "ccip", "debridge"],
                "examples": [
                    "Bridge 100 TNZO from Ethereum to Solana",
                    "Get bridge routes from Tenzro to Base",
                    "Estimate bridge fee for 500 USDC to Arbitrum",
                    "List available bridge adapters",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "compliance",
                "name": "Compliance & KYC",
                "description": (
                    "ERC-3643 T-REX compliance: KYC verification, accreditation, "
                    "country restrictions, freeze/recover, trusted issuers."
                ),
                "tags": ["compliance", "kyc", "erc3643", "t-rex", "accreditation"],
                "examples": [
                    "Verify KYC status for address 0xabc...",
                    "Check accreditation for investor 0xdef...",
                    "List country restrictions for token XYZ",
                    "Freeze token holdings for 0x123...",
                    "Add a trusted issuer to the registry",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "crosschain",
                "name": "Cross-Chain Token Standard",
                "description": (
                    "ERC-7802 cross-chain token standard: authorized bridge mint/burn "
                    "with rate limits and audit trail."
                ),
                "tags": ["crosschain", "erc7802", "mint", "burn", "rate-limit"],
                "examples": [
                    "Authorize a bridge for cross-chain minting",
                    "Set rate limit for bridge 0xabc... to 10000 TNZO/day",
                    "Query audit trail for cross-chain token transfers",
                    "Revoke bridge authorization for 0xdef...",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "events",
                "name": "Event Streaming",
                "description": (
                    "Real-time event streaming via WebSocket (eth_subscribe), gRPC, "
                    "webhooks with HMAC signatures, historical queries."
                ),
                "tags": ["events", "websocket", "streaming", "webhooks", "grpc"],
                "examples": [
                    "Subscribe to new block events via WebSocket",
                    "Register a webhook for transfer events on 0xabc...",
                    "Query historical events for contract 0xdef...",
                    "Stream pending transactions in real time",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json", "text/event-stream"],
            },
            {
                "id": "forecast",
                "name": "Timeseries Forecasting",
                "description": (
                    "Probabilistic timeseries forecasting via Tenzro-served "
                    "foundation models (Chronos-2, Chronos-Bolt, TimesFM 2.5, "
                    "Granite-TTM). Returns quantile bands and supports "
                    "multivariate inputs with covariates."
                ),
                "tags": ["timeseries", "forecasting", "ai", "chronos", "timesfm"],
                "examples": [
                    "List available forecast models",
                    "Forecast next 24 steps of [1.0, 1.2, 1.4, ...] with chronos-2",
                    "Quantile forecast (p10/p50/p90) horizon=12 on chronos-bolt-small",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "vision-embed",
                "name": "Image Embeddings",
                "description": (
                    "Compute high-quality image embeddings via Tenzro-served "
                    "vision encoders (DINOv3, SigLIP2, CLIP). Supports "
                    "zero-shot classification by cosine similarity against "
                    "natural-language label prompts."
                ),
                "tags": ["vision", "embedding", "dinov3", "siglip2", "clip", "ai"],
                "examples": [
                    "List available vision models",
                    "Embed a base64 image with dinov3-vitb16",
                    "Zero-shot classify image against [cat, dog, lion]",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "text-embed",
                "name": "Text Embeddings",
                "description": (
                    "Compute dense text embeddings via Tenzro-served "
                    "encoders (Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M, "
                    "BGE-M3). Supports Matryoshka truncation (e.g. 512/256/128 "
                    "dims for EmbeddingGemma) and batch inputs."
                ),
                "tags": ["text", "embedding", "qwen3", "embeddinggemma", "bge", "ai"],
                "examples": [
                    "List available text embedding models",
                    "Embed [\"hello\", \"world\"] with qwen3-embedding-0.6b",
                    "Embed with embeddinggemma-300m at requested_dim=256",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "segmentation",
                "name": "Image Segmentation",
                "description": (
                    "Promptable image segmentation via Tenzro-served encoders "
                    "(SAM 3, SAM 2, EdgeSAM, MobileSAM). Accepts point and "
                    "box prompts, returns per-prompt mask geometry and scores."
                ),
                "tags": ["vision", "segmentation", "sam", "edgesam", "ai"],
                "examples": [
                    "List available segmentation models",
                    "Segment image with SAM 3 given point prompts",
                    "Segment image with EdgeSAM given a box prompt",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "detection",
                "name": "Object Detection",
                "description": (
                    "Open-vocabulary and closed-set object detection via "
                    "Tenzro-served encoders (RF-DETR nano/small/medium/base/"
                    "large/2x-large, D-FINE). Returns bbox + label + score "
                    "lists with optional score threshold."
                ),
                "tags": ["vision", "detection", "rf-detr", "d-fine", "ai"],
                "examples": [
                    "List available detection models",
                    "Detect objects in image with rf-detr-base, threshold 0.5",
                    "Detect objects with d-fine-l, threshold 0.3",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "audio-transcribe",
                "name": "Audio Transcription (ASR)",
                "description": (
                    "Speech-to-text transcription via Tenzro-served ASR models "
                    "(Moonshine v2 tiny/base, Distil-Whisper small/medium/large, "
                    "Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash). "
                    "Supports language hints and word/segment-level timestamps."
                ),
                "tags": ["audio", "asr", "speech-to-text", "whisper", "ai"],
                "examples": [
                    "List available audio models",
                    "Transcribe a base64 WAV with whisper-large-v3-turbo",
                    "Transcribe Spanish audio with canary-1b-flash with timestamps",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "video-embed",
                "name": "Video Embeddings",
                "description": (
                    "Video embedding scaffolding via Tenzro-served encoders. "
                    "Wave 1 ships the runtime + RPC surface; the catalog is "
                    "intentionally empty until a permissive ONNX-shippable "
                    "video encoder lands. Until then, agents fall back to "
                    "pooling vision-encoder embeddings over sampled frames."
                ),
                "tags": ["video", "embedding", "vjepa", "videomae", "ai"],
                "examples": [
                    "List available video models",
                    "Embed a base64 video clip with frame_stride=30",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "workflow",
                "name": "Canton-Native Workflows",
                "description": (
                    "Multi-party workflows: typed Workflow records with "
                    "Participants, Obligations (Pay/Deliver/Attest/Settle/"
                    "Custom), ApprovalGates (Single/Threshold/Role/"
                    "Delegated approver sets), composite PolicyExpr DSL "
                    "(amount/counterparty/time/asset/chain/role gates), "
                    "lifecycle history, fee routes (basis-point splits), "
                    "and privacy domains (X25519-sealed envelopes). "
                    "Reads are exposed via tenzro_getWorkflow / "
                    "list_workflows_by_creator|participant|status, "
                    "tenzro_getObligation / Approval{Gate,Request}, "
                    "tenzro_listWorkflowReceipts (chain walk), "
                    "tenzro_listFeeRoutes / computeFeeRoutePayouts, "
                    "tenzro_getPrivacyDomain / listPrivacyDomainsForDid, "
                    "tenzro_getWorkflowOperationalMetrics. Writes flow "
                    "through signed transactions against the privileged-VM "
                    "workflow selectors 0x01000040–0x0100004B. Workflows "
                    "may optionally mirror to a Canton synchronizer via "
                    "tenzro_mirrorWorkflowToCanton for enterprise "
                    "interoperability with DAML 3.x."
                ),
                "tags": [
                    "workflow", "canton", "daml", "multi-party",
                    "obligations", "approvals", "policy", "fee-route",
                    "privacy-domain", "receipts", "audit",
                ],
                "examples": [
                    "Get workflow 0x… (creator, participants, obligations, status)",
                    "List workflows where did:tenzro:human:alice is a participant",
                    "List workflows in status awaiting_signatures",
                    "Get the lifecycle history for workflow 0x…",
                    "Get obligation 0x… (kind, amount, status, discharge_proof)",
                    "Get approval request 0x… (decisions collected, threshold progress)",
                    "List receipts for workflow 0x… max=100",
                    "List all fee routes",
                    "Compute payouts for fee route 0x… given gross_wei=50000000",
                    "Get privacy domain 0x… (members, frozen, envelope policy)",
                    "Snapshot of workflow operational metrics (statuses, sigs, mirror count)",
                    "Mirror workflow 0x… to canton synchronizer canton-mainnet",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
        ],
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
    }
