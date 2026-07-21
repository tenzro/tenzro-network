"""Agent Card builder — serves at /.well-known/agent.json for A2A discovery."""


def build_agent_card(base_url: str = "https://a2a.tenzro.xyz") -> dict:
    """Build the A2A Agent Card with the full skill catalog."""
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
                "id": "passkey-wallet",
                "name": "Passkey-First Custody",
                "description": (
                    "Passkey-first wallet onboarding and custody (Coinbase / "
                    "Daimo / Argent pattern). Enroll a passkey-bound ERC-4337 "
                    "smart account, add social-recovery guardians, initiate / "
                    "finalize guardian-quorum recovery to rotate to a new "
                    "passkey, grant scoped session keys to agents, install "
                    "hardware signers (Ledger / Trezor / GridPlus / YubiKey), "
                    "and query installed validators. Signing keys never leave "
                    "the user's hardware secure element."
                ),
                "tags": [
                    "wallet",
                    "custody",
                    "passkey",
                    "webauthn",
                    "erc-4337",
                    "erc-7579",
                    "social-recovery",
                    "session-key",
                ],
                "examples": [
                    "Enroll a passkey-bound smart account",
                    "Add a guardian to my account",
                    "Initiate a recovery ceremony to rotate my passkey",
                    "Grant a session key to my trading agent for 30 days",
                    "Install my Ledger as a hardware signer",
                    "Show my smart account's installed validators",
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
                    "Tenzro network, with settlement in TNZO. Supports intent "
                    "routing: state a use case (chat/code/reasoning/summarize/"
                    "extract/embed) plus budget and quality floor in metadata "
                    "to have the network select a model instead of naming one. "
                    "Model weights are content-addressed: download is peer-first "
                    "over iroh blobs (BLAKE3-verified end-to-end on transfer), "
                    "falling back to HuggingFace, and the weights are checked "
                    "against the canonical hash record before load. Read that "
                    "record (BLAKE3 + SHA-256 + per-file manifest hash, recorder "
                    "DID, record epoch) with a model_id, or list every recorded "
                    "hash."
                ),
                "tags": [
                    "ai", "inference", "models", "intent-routing",
                    "content-addressed", "blake3",
                ],
                "examples": [
                    "List available AI models",
                    "Run inference on model X",
                    "Route by intent for a reasoning use case",
                    "Chat by intent with budget 1000000000000000000",
                    "Get the content hash for model qwen3-4b",
                    "List every recorded model hash",
                    "Download model qwen3-4b (peer-first, BLAKE3-verified)",
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
                    "escrow, prepaid streaming balances, and batch settlement on "
                    "the Tenzro ledger."
                ),
                "tags": ["settlement", "payments", "escrow", "prepaid", "streaming"],
                "examples": [
                    "Check settlement status",
                    "Open a micropayment channel",
                    "Pre-fund a streaming storage or compute rental",
                    "Check a prepaid streaming balance",
                ],
                "inputModes": ["text/plain"],
                "outputModes": ["text/plain", "application/json"],
            },
            {
                "id": "dvp-netting",
                "name": "Delivery-versus-Payment & Netting",
                "description": (
                    "Bundle delivery and payment legs into an all-or-compensate "
                    "delivery-versus-payment saga backed by on-chain escrow, and "
                    "collapse a set of bilateral obligations into a minimal net "
                    "settlement instruction set via multilateral netting."
                ),
                "tags": ["dvp", "netting", "escrow", "saga", "settlement"],
                "examples": [
                    "Open a DvP saga for a two-leg atomic swap",
                    "Execute a DvP saga with per-leg release proofs",
                    "Compute a multilateral netting batch over a set of obligations",
                    "Settle a netting batch",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
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
                "id": "validator-lifecycle",
                "name": "Validator Lifecycle",
                "description": (
                    "Operate the validator registry: query a single entry, "
                    "list candidates / active / jailed validators, and rotate "
                    "consensus + ML-DSA-65 + BLS12-381 keys via the "
                    "tenzro_rotateValidatorKey RPC. The rotation must be "
                    "signed offline with the *current* consensus key and "
                    "fanned out to every active validator before the next "
                    "epoch boundary (see tools/deploy/rotate-validator-key.sh)."
                ),
                "tags": ["validator", "consensus", "key-rotation", "operator"],
                "examples": [
                    "List the active validators",
                    "Get the registry entry for validator 0xabc...",
                    "Rotate keys for validator 0xabc... with new pubkeys",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
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
                    "and FROST-Ed25519 threshold wallet. Supports hierarchical agent topologies."
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
                "name": "AP2 & x402 Payments",
                "description": (
                    "Agent Payments Protocol (AP2) session lifecycle plus "
                    "Google-spec mandate verification. Create sessions, "
                    "authorize/execute/cancel payments, verify Checkout/Payment "
                    "Verifiable Digital Credentials (VDCs), validate Checkout+Payment pairs "
                    "for consistency, and fetch protocol metadata. Also covers the "
                    "x402 Bazaar: sellers register HTTP-402 monetized resources "
                    "(scheme tenzro-hybrid / exact-eip3009 / permit2 / erc7710), "
                    "buyers discover them by scheme / network / asset / tags, and "
                    "either side verifies an offer or derives a deterministic "
                    "payment id."
                ),
                "tags": [
                    "payments", "ap2", "x402", "bazaar", "agentic", "settlement",
                    "mandates", "vdc", "checkout", "payment", "verifiable-credentials",
                    "resource-discovery", "monetization",
                ],
                "examples": [
                    "AP2 protocol info",
                    "Create AP2 session (metadata.agent_did, provider_did, max_amount)",
                    "Authorize 100 TNZO on session <id>",
                    "Execute session <id> (metadata.authorization_id)",
                    "Cancel session <id>",
                    "Verify AP2 mandate (metadata.vdc)",
                    "Validate AP2 checkout/payment pair (metadata.checkout_vdc, payment_vdc)",
                    "List AP2 mandates (metadata.controller_did)",
                    "x402 protocol info",
                    "x402 register resource (metadata: sellerDid, resource, payTo, "
                    "maxAmountRequired, scheme, network, asset, tags)",
                    "x402 discover resources (metadata: scheme, network, asset, tags, limit)",
                    "x402 deregister resource (metadata: listingId, sellerDid)",
                    "x402 verify offer (metadata: requirement)",
                    "x402 payment id (metadata: payerDid, requirement|offerCommitment)",
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
                "id": "ccip",
                "name": "Chainlink CCIP",
                "description": (
                    "Chainlink CCIP cross-chain messaging. OCR commit-store "
                    "committee + RMN ARM co-attest every inbound message. "
                    "Quote fees via Router.getFee(), prepare ccipSend() "
                    "envelopes, track OffRamp execution state, inspect "
                    "CCT v1.6+ token pools and their inbound/outbound "
                    "rate-limiter state, and bridge tokens through the "
                    "BridgeRouter with the CCIP adapter pinned."
                ),
                "tags": [
                    "ccip", "chainlink", "bridge", "cross-chain", "cct", "rmn",
                    "ethereum", "arbitrum", "base", "polygon",
                ],
                "examples": [
                    "Quote CCIP fee from ethereum to arbitrum",
                    "Track CCIP message 0xabc... on arbitrum",
                    "List CCIP lanes for mainnet",
                    "Get CCT pool rate limits on base for arbitrum",
                    "Bridge 100 TNZO from ethereum to arbitrum via CCIP",
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
                    "refresh expired access tokens, and link an existing "
                    "FROST-Ed25519 threshold wallet to a new auth session. "
                    "Issues HS256 access tokens "
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
                "id": "approval",
                "name": "Auth-Engine Approval Workflow",
                "description": (
                    "Asynchronous request -> review -> decide loop for sensitive "
                    "actions that need out-of-band human (or higher-privilege "
                    "machine) signoff. List pending approval requests for an "
                    "approver DID, fetch a single approval record by id, or "
                    "apply a final decision (approved / denied). Lazy expiry "
                    "runs on every read path so callers never see stale "
                    "pending records. When approver_did is supplied on decide, "
                    "the engine refuses to apply the decision unless the "
                    "record's approver_did matches (cross-approver tampering "
                    "defence -- mismatch returns JSON-RPC -32001 forbidden)."
                ),
                "tags": [
                    "approval", "auth-engine", "out-of-band", "human-in-the-loop",
                    "workflow", "decision",
                ],
                "examples": [
                    "List pending approvals for did:tenzro:human:alice",
                    "Fetch approval record by id (metadata.approval_id)",
                    "Approve request (metadata.approval_id, decision=approved, approver_did)",
                    "Deny request (metadata.approval_id, decision=denied, approver_did)",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "join",
                "name": "Join as MicroNode",
                "description": (
                    "Join the Tenzro Network as a full MicroNode participant -- "
                    "zero-install. Auto-provisions a TDIP DID, FROST-Ed25519 threshold wallet, and "
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
                    "foundation models (TimesFM 2.5). Returns quantile bands."
                ),
                "tags": ["timeseries", "forecasting", "ai", "timesfm"],
                "examples": [
                    "List available forecast models",
                    "Quantile forecast (p10/p50/p90) horizon=64 on timesfm-2.5-200m",
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
                    "(SAM 2, EdgeSAM, MobileSAM). Accepts point and box "
                    "prompts, returns per-prompt mask geometry and scores."
                ),
                "tags": ["vision", "segmentation", "sam", "edgesam", "ai"],
                "examples": [
                    "List available segmentation models",
                    "Segment image with SAM 2 given point prompts",
                    "Segment image with EdgeSAM given a box prompt",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "text-segmentation",
                "name": "Open-Vocabulary Text-Promptable Segmentation",
                "description": (
                    "Open-vocabulary text-promptable image segmentation via "
                    "Tenzro-served SAM 3 / SAM 3.1. Accepts a free-text label "
                    "(e.g. 'person', 'sofa', 'dog') and an image; optionally "
                    "narrowed with a normalized cxcywh box. Returns variable-N "
                    "detections with bbox, score, and full-resolution mask."
                ),
                "tags": ["vision", "segmentation", "sam3", "open-vocabulary", "text-promptable", "ai"],
                "examples": [
                    "List available text-promptable segmentation models",
                    "Segment all 'people' in image with sam3-vit-h",
                    "Segment 'dog' restricted to box (0.4,0.4,0.3,0.5)",
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
                    "Video embedding via Tenzro-served encoders. The native "
                    "video catalog is empty (no permissive ONNX-shippable "
                    "encoder available); the runtime ships a "
                    "VisionFallbackVideoEncoder that samples frames via ffmpeg, "
                    "embeds each through a registered vision encoder "
                    "(DINOv3 / SigLIP2 / CLIP), and mean-pools the result."
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
                "id": "capital",
                "name": "Capital Intent (regulated capital allocation)",
                "description": (
                    "Capital Intents are the capital-markets analog of an "
                    "AP2 Intent Mandate — a signed, expiring authorization "
                    "to acquire / exit / rebalance / hedge / yield a basket "
                    "of tokenized assets subject to regulatory regime, KYA "
                    "ceilings, and per-leg constraints. Solvers bid via "
                    "tenzro_capitalIntentQuote; an assigner (principal or "
                    "delegate) picks via tenzro_capitalIntentAssign (auto "
                    "rank by ERC-8004 reputation + price + eta). Lifecycle: "
                    "Open → Quote → Assign → Execute → Verify (or "
                    "Compensate) → Settle. 1:1 asset backing flows through "
                    "tenzro_submitReserveAttestation / tenzro_getReserve, "
                    "gating tenzro_attestedMint."
                ),
                "tags": [
                    "capital-intent", "regulated", "tokenized-assets",
                    "reserve", "attested-mint", "ap2", "erc8004",
                ],
                "examples": [
                    "Open a Capital Intent to acquire a basket of tokenized treasuries",
                    "Submit a solver bid against intent_id=0x…",
                    "Auto-assign intent_id=0x… by reputation + price + eta",
                    "Execute leg {venue, asset_id, side, quantity, unit_price}",
                    "Submit a reserve attestation for asset_id=0x… (source=custody)",
                    "Get current reserve for asset_id=0x…",
                ],
                "inputModes": ["text/plain", "application/json"],
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
            {
                "id": "canton",
                "name": "Canton / DAML (3.5+ JSON Ledger API)",
                "description": (
                    "Canton 3.5+ JSON Ledger API surface proxied through the "
                    "Tenzro node — the caller never sees the upstream Auth0 "
                    "secret. Reads: list synchronizer domains, query active "
                    "DAML contracts (with the live ledger-end offset attached "
                    "automatically and the participant's fully-qualified party "
                    "id resolved via CIP-26 User Management), list parties + "
                    "installed packages, combined health probe "
                    "(/livez + /readyz + /v2/version), CIP-56 Canton Coin "
                    "balance, AmuletRules fee schedule, connected "
                    "synchronizers, transaction-tree lookup, OAuth principal's "
                    "user record, list user rights. Writes: submit-and-wait "
                    "DAML create / exercise commands (auto-scoped to the "
                    "presenting API key's bound canton_user_id when set), "
                    "allocate party, grant CanActAs / CanReadAs rights on a "
                    "party to a user (CIP-26), upload DAR via POST /v2/packages "
                    "with a single Content-Type header (Canton 3.5+ rejects "
                    "duplicates; the legacy /admin/packages/upload-dar path "
                    "is gRPC-only and NOT exposed on the Tenzro-operated "
                    "DevNet). Per-tenant analytics: self-read of API-key call "
                    "counters (calls_total, errors_total, per-method buckets) "
                    "and operator admin-read across every tenant. Requires "
                    "an API key with the `canton` scope at the Tenzro node."
                ),
                "tags": [
                    "canton", "daml", "3.5", "json-ledger-api",
                    "cip-26", "cip-56", "amulet", "splice",
                    "dar-upload", "fee-schedule", "synchronizer",
                    "active-contracts", "submit-and-wait", "participant",
                    "multi-tenant", "act-as", "user-rights", "analytics",
                ],
                "examples": [
                    "Canton health",
                    "Canton version",
                    "Canton my user",
                    "List Canton parties",
                    "List Canton installed packages",
                    "Canton coin balance",
                    "Canton fee schedule",
                    "Canton connected synchronizers",
                    "List DAML contracts for template #splice-amulet:Splice.Amulet:Amulet",
                    "Get Canton transaction <hex-update-id>",
                    "Allocate Canton party party_id_hint=tenzro-labs",
                    "Grant Canton user rights party=tenzro-labs::<hash> user_id=tenzro-labs@clients can_act_as=true",
                    "List Canton user rights for tenzro-labs@clients",
                    "Canton my analytics",
                    "Upload DAR <base64-bytes>",
                    "Submit DAML create on template …",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "agent-memory",
                "name": "Agent Memory Tier",
                "description": (
                    "Persistent, queryable memory for Tenzro agents. Lance "
                    "vector kNN + Tantivy BM25 with Reciprocal Rank Fusion "
                    "(k=60) hybrid recall. Memories can be granted to an "
                    "agent, recalled by natural-language query, and archived "
                    "to the configured DA backend (frees hot search budget; "
                    "payload remains fetchable via the returned DaPointer). "
                    "Operations: memory.grant, memory.recall, memory.archive."
                ),
                "tags": [
                    "memory", "vector-search", "bm25", "rrf", "lance",
                    "tantivy", "agent-state", "rag", "da-archive",
                ],
                "examples": [
                    "Grant memory: 'remember that the deploy host is gke-tc' to did:tenzro:machine:ops-1",
                    "Recall (hybrid mode, k=10) memories about 'deploy host' for did:tenzro:machine:ops-1",
                    "Recall (vector mode) semantically-similar memories for did:tenzro:machine:ops-1",
                    "Recall (text mode) BM25-matched memories for did:tenzro:machine:ops-1",
                    "Archive memory 9f3c…a0 to free hot index budget",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "adaptive-burn",
                "name": "Adaptive Burn-Rate Governance Dial",
                "description": (
                    "Read-side surface for the adaptive burn-rate dial "
                    "(Spec 7). Exposes the current BurnRateConfig (base / "
                    "local / paymaster bps with treasury complements; "
                    "paymaster locked at 100% burn), the latest "
                    "SupplyMetricsSnapshot (rolling-window epoch delta, "
                    "burn + emission breakdowns), and the pure-function "
                    "BurnRateRecommendation (NoChange / IncreaseBurnPct / "
                    "DecreaseBurnPct / AlarmHighInflation / "
                    "AlarmHighDeflation with magnitude bps capped at the "
                    "normal / alarm ceiling). The dial moves only via "
                    "on-chain governance proposals; the auto-proposal "
                    "generator + EIP-1559 fee-market consumer wiring "
                    "lands in a follow-up wave."
                ),
                "tags": [
                    "adaptive-burn", "governance", "tokenomics",
                    "supply", "burn-rate", "eip-1559", "spec-7",
                ],
                "examples": [
                    "Get the current burn-rate config and target band",
                    "Get the latest supply-metrics snapshot",
                    "Get the current burn-rate recommendation (action + magnitude bps)",
                    "List pending adaptive-burn governance proposals",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "seed-agent",
                "name": "SeedAgent Treasury Earmark",
                "description": (
                    "SeedAgent treasury allocation surface (Spec 10). "
                    "Exposes the genesis-funded TreasuryEarmark singleton "
                    "(initial / remaining / drawn TNZO, decay schedule, "
                    "sunset surplus burn bps), the governance-signed "
                    "Charter registry (OperationKind set + spend caps + "
                    "counterparty filter + throughput target + sunset), "
                    "the per-DID SeedAgentRecord roster (status: Active / "
                    "Paused / Quarantined / Terminated; allocation drawn; "
                    "optional bond id), and the network-activity counters "
                    "with `exclude_seed` filter to isolate organic flows "
                    "from protocol-owned bootstrap traffic during the "
                    "12-month earmark window."
                ),
                "tags": [
                    "seed-agent", "treasury", "earmark", "charter",
                    "bootstrap", "spec-10", "governance",
                ],
                "examples": [
                    "Show the SeedAgent treasury earmark (allocation remaining, decay schedule, agent count)",
                    "List every SeedAgent governance charter",
                    "Fetch SeedAgent charter 0x… (operations, spend caps, sunset)",
                    "List provisioned seed agents under charter 0x…",
                    "Get 24h network activity with exclude_seed=true",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "erc7683",
                "name": "ERC-7683 Cross-Chain Intents",
                "description": (
                    "ERC-7683 cross-chain intent settler surface (Spec "
                    "4). Origin-side reads against the Tenzro7683Order "
                    "envelope persisted under the `7683_origin:` "
                    "keyspace, with the OrderState machine Open → "
                    "AwaitingProof → Settled / Refunded / "
                    "ForceRefundEligible. Destination-side commit of "
                    "FillRecord (single-shot per order_id; duplicate "
                    "returns JSON-RPC -32010 OrderAlreadyFilled) plus "
                    "fill read endpoints. ProofRoute is one of "
                    "LayerZero / Wormhole / DeBridge / Hyperlane."
                ),
                "tags": [
                    "erc-7683", "cross-chain", "intent", "settler",
                    "fill", "spec-4", "layerzero", "wormhole",
                    "debridge", "hyperlane",
                ],
                "examples": [
                    "Get ERC-7683 order 0x… (state, dest_chain, outputs)",
                    "List open ERC-7683 orders bound for dest_chain=8453",
                    "Record fill for order 0x… (origin_chain, filler, proof_route, outputs[])",
                    "Get fill record for order 0x… origin_chain=1",
                    "List every recorded ERC-7683 fill on this node",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "eip7702",
                "name": "EIP-7702 (Set EOA Account Code)",
                "description": (
                    "Pectra Type-4 delegation registry helper surface. "
                    "Stateless helpers: compute the secp256k1 signing "
                    "hash over MAGIC(0x05) || rlp([chain_id, "
                    "delegate_address, nonce]), build the 23-byte "
                    "designator (0xef0100 || delegate_address) written "
                    "into the EOA's code slot once an authorization is "
                    "accepted, and decode arbitrary code to extract a "
                    "delegate when it is a valid 7702 designator. "
                    "Sign the returned hash with the EOA's secp256k1 "
                    "private key out of band."
                ),
                "tags": [
                    "eip-7702", "pectra", "delegation", "eoa", "evm",
                    "secp256k1", "smart-account",
                ],
                "examples": [
                    "Compute the EIP-7702 signing hash for (chain_id, delegate_address, nonce)",
                    "Build the 23-byte designator for delegate_address=0x…",
                    "Decode code 0xef0100… and return the delegate address",
                    "Read EIP-7702 protocol info (tx type, magic, signing scheme)",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "permit2",
                "name": "Permit2 SignatureTransfer",
                "description": (
                    "Permit2 EIP-712 SignatureTransfer surface on the "
                    "canonical Tenzro Permit2 verifying contract "
                    "(0x0000…00001023). Read the per-chain domain "
                    "separator, compute the digest a user signs "
                    "(with optional witness binding — used by ERC-7683 "
                    "origin opens to bind the permit to a specific "
                    "cross-chain order), atomically verify a signed "
                    "permit and consume its (owner, nonce) bitmap "
                    "slot, and read nonce-consumption state. Nonce "
                    "bitmap follows the Uniswap word/bit layout so "
                    "users can sign multiple permits in parallel."
                ),
                "tags": [
                    "permit2", "signature-transfer", "eip-712",
                    "gasless", "uniswap", "witness", "erc-7683",
                ],
                "examples": [
                    "Read the Permit2 domain separator for chain_id=1337",
                    "Compute the EIP-712 digest for a permit (owner, token, amount, spender, nonce, deadline)",
                    "Compute the digest for a permit with a 32-byte ERC-7683 witness",
                    "Verify and consume a signed permit",
                    "Check whether (owner, nonce) has been consumed",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "secure-mint",
                "name": "Secure-Mint Registry",
                "description": (
                    "Per-token 1:1 reserve-attestation invariant for "
                    "tokenized real-world assets (tokenized-equity-class "
                    "assets, treasuries, stablecoins). Enforces "
                    "`circulating + amount ≤ reserve` at every mint. "
                    "Policies carry the PoR feed id, attester DID, "
                    "attestation hash, attested_at timestamp, and "
                    "ttl_secs; the read-only check is non-mutating "
                    "while apply atomically updates `circulating`. "
                    "Reserved EVM precompile slot at 0x0000…00001024."
                ),
                "tags": [
                    "secure-mint", "rwa", "tokenized-assets",
                    "reserve-attestation", "1-to-1", "tokenized-equities", "por",
                ],
                "examples": [
                    "Set a Secure-Mint policy for asset_id=0x… (reserve, por_feed_id, attester_did, …)",
                    "Read the current Secure-Mint policy for asset_id=0x…",
                    "Read-only check whether a mint of 1000 units of asset_id=0x… is allowed",
                    "Atomically apply a mint of 1000 units (increment circulating)",
                    "Record a burn of 250 units (decrement circulating)",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "treasury",
                "name": "Treasury Multisig Withdrawals",
                "description": (
                    "Network treasury multisig withdrawal flow. "
                    "Approvals are signed over the "
                    "`tenzro/treasury/withdrawal-approval` preimage "
                    "(withdrawal_id || asset_id || amount LE) with the "
                    "approver's Ed25519 or Secp256k1 key; execution "
                    "requires the configured approval threshold. "
                    "Withdrawer-set and threshold mutations are "
                    "admin-token-gated operator RPCs."
                ),
                "tags": [
                    "treasury", "multisig", "withdrawal", "approval",
                    "threshold",
                ],
                "examples": [
                    "Show pending treasury withdrawal wd-1",
                    "Approve treasury withdrawal wd-1 (signed approval via metadata)",
                    "Execute treasury withdrawal wd-1 once threshold is reached",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "stable-asset",
                "name": "Stable-Asset Issuance",
                "description": (
                    "Issuer-agnostic stable-unit issuance layered on the "
                    "Secure-Mint reserve floor. An issuer registers a unit, "
                    "then mints and redeems against it; mints are hard-gated "
                    "so circulating supply can never exceed the attested "
                    "reserve. Policies carry a reserve source (custodial "
                    "attester or on-chain vault), a PoR feed id, the allowed "
                    "settlement rails, and a settlement destination. "
                    "Registration requires the `issuer` API-key scope."
                ),
                "tags": [
                    "stable-asset", "stablecoin", "issuance", "stable-unit",
                    "reserve-floor", "issuer",
                ],
                "examples": [
                    "Register a stable-asset policy for issuer=0x… unit_token=0x… symbol=USDX",
                    "Read the stable-asset policy for issuer=0x… unit_token=0x…",
                    "Mint 1000000 units of unit_token=0x… for issuer=0x…",
                    "Redeem 500000 units of unit_token=0x… for issuer=0x…",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "hyperlane",
                "name": "Hyperlane V3 (Sovereign Tenzro-ISM)",
                "description": (
                    "Permissionless interchain messaging over the "
                    "Hyperlane V3 Mailbox with a sovereign "
                    "Tenzro-validator-set Interchain Security Module. "
                    "Inbound messages are verified against the active "
                    "Tenzro validator BLS / ML-DSA set; outbound "
                    "messages dispatch through the canonical Mailbox. "
                    "Coverage: Ethereum, Polygon, Arbitrum, Optimism, "
                    "Base, Avalanche, BSC, Mantle, Blast, Scroll, "
                    "Linea, Manta, zkSync, Celo, Moonbeam, Mode, "
                    "Fraxtal, and Tenzro."
                ),
                "tags": [
                    "hyperlane", "v3", "ism", "messaging", "mailbox",
                    "cross-chain", "tenzro-ism",
                ],
                "examples": [
                    "List supported Hyperlane chains and their domain ids",
                    "Quote interchain gas for dispatch to destination_domain=10",
                    "Dispatch a Hyperlane message (origin, dest, recipient, body_hex)",
                    "Look up a Hyperlane message by message_id",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "axelar",
                "name": "Axelar GMP",
                "description": (
                    "Axelar General Message Passing surface — reach "
                    "into 30+ chains spanning EVM, Cosmos (Osmosis, "
                    "Cosmos Hub, Juno, Neutron, Injective, Kujira, "
                    "Crescent, Evmos), Move (Aptos, Sui), Stellar, "
                    "XRP Ledger, Hyperliquid, Filecoin EVM, and Kava. "
                    "Uses the canonical call_contract entrypoint with "
                    "a Gas Service pre-pay; correlation id is "
                    "keccak256(payload)."
                ),
                "tags": [
                    "axelar", "gmp", "cosmos", "move", "stellar",
                    "xrpl", "cross-chain",
                ],
                "examples": [
                    "List supported Axelar chains and their gateway addresses",
                    "Dispatch an Axelar call_contract (source, destination, destination_address, payload_hex)",
                    "Pre-pay Axelar gas for an already-dispatched message",
                    "Look up an Axelar GMP message by payload_hash",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "babylon",
                "name": "Babylon Bitcoin Staking",
                "description": (
                    "Babylon finality-providers protocol surface so "
                    "Tenzro validators can be BTC-secured. Register a "
                    "Tenzro validator as a Babylon finality provider, "
                    "look up registered providers, sum BTC delegations, "
                    "submit EOTS (Extractable One-Time Signatures) over "
                    "Tenzro block hashes (slashable on equivocation), "
                    "and list BTC delegations per provider."
                ),
                "tags": [
                    "babylon", "bitcoin-staking", "finality-providers",
                    "eots", "btc", "staking", "shared-security",
                ],
                "examples": [
                    "Register a Tenzro validator as a Babylon finality provider",
                    "List every registered Babylon finality provider",
                    "Read total BTC stake for finality provider 0x…",
                    "Submit an EOTS over a Tenzro block hash",
                    "List BTC delegations for finality provider 0x…",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "caip",
                "name": "Chain-Agnostic Discovery (CAIP)",
                "description": (
                    "Tenzro CAIP namespace identifiers per the "
                    "submitted `ChainAgnostic/namespaces#184`. CAIP-2 "
                    "chain id is `tenzro:<lowercase hex of first 16 "
                    "bytes of the genesis state root>` with an "
                    "EVM-compatible `evm_chain_id` sidecar. CAIP-10 "
                    "account ids accept hex or base58btc on input and "
                    "normalise to canonical 64-hex Tenzro addresses. "
                    "CAIP-19 supports `slip44` (SLIP-44 coin index "
                    "1414421071), `token`, and `nft` asset namespaces."
                ),
                "tags": [
                    "caip", "caip-2", "caip-10", "caip-19",
                    "chain-agnostic", "casa", "slip-44", "discovery",
                ],
                "examples": [
                    "Get the CAIP-2 chain id for this node",
                    "Get the CAIP-10 account id for an address (hex or base58btc)",
                    "Get the CAIP-19 asset id for kind=slip44 (native TNZO)",
                    "Get the CAIP-19 asset id for kind=token, token_id=0x…",
                    "Get the CAIP-19 asset id for kind=nft, collection_id=0x…, nft_token_id=42",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "oracle",
                "name": "Price Oracle",
                "description": (
                    "Read asset prices from the node's price oracle "
                    "(tenzro_getPrice). Pass a single `symbol` or a "
                    "`symbols` list. `price_usd_8dp` is the USD price as "
                    "an integer scaled by 1e8. Symbols with no live feed "
                    "are returned under `unavailable` rather than failing "
                    "the whole request. Requires bridge.prices.enabled on "
                    "the node."
                ),
                "tags": [
                    "oracle", "price", "usd", "feed", "asset-price",
                ],
                "examples": [
                    "Get the price of TNZO (metadata.symbol)",
                    "Get prices for TNZO, ETH, USDC (metadata.symbols)",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "operability",
                "name": "Operability Inspection",
                "description": (
                    "Read-only inspection surface for SREs, operator "
                    "dashboards, and monitoring agents. Validator "
                    "registry reads (get_validator_state by address, "
                    "list_validators with optional status filter, "
                    "list_active_validators for the current committee — "
                    "each entry carries base58 address, Ed25519 + "
                    "ML-DSA-65 + BLS12-381 pubkeys, self_stake u128 "
                    "decimal, registered/activated/exited/jailed "
                    "epoch markers, optional tee_attestation_hash). "
                    "Tenzro Train inspection (training_list_runs, "
                    "training_get_run, training_get_receipt, "
                    "training_get_sealed_manifest, training_decide_round, "
                    "get_trainer_daemon_status) "
                    "— read-side view of every active run, sealed "
                    "receipts for finalized runs, Confidential-tier "
                    "sealed-shard manifests, the syncer's live round "
                    "decision (finalize / wait with remaining grace-window "
                    "ms / no-quorum carry-forward), and the trainer "
                    "auto-provisioning daemon's running state and live "
                    "trainer count. Inference router "
                    "observability (get_router_metrics) — total requests "
                    "routed, hedges dispatched, hedges won, and requests "
                    "abandoned on the whole-request deadline. SLA "
                    "fault-detector inspection "
                    "(sla_get_params for the slash threshold, slash "
                    "amount in wei, and validator VRF public key; "
                    "sla_list_outstanding_probes for every in-flight "
                    "probe awaiting a response, used to spot probes "
                    "whose deadline has elapsed without a matching "
                    "response). Validator nodes can additionally issue "
                    "VRF-bound liveness probes (sla_issue_probe) "
                    "against ModelProvider / TeeProvider DIDs. "
                    "State-sync snapshot inspection (list_snapshots, "
                    "get_snapshot_manifest by height, get_snapshot_chunk "
                    "by (height, chunk_index)) for operators bootstrapping "
                    "new nodes or auditing state-root continuity; the "
                    "offer/apply write surface is also exposed but the "
                    "caller MUST verify state_root_hex against a trusted "
                    "QC at the same height before invoking. Safe to "
                    "expose to monitoring agents — no key material "
                    "returned."
                ),
                "tags": [
                    "operability", "sre", "monitoring", "validator",
                    "registry", "training", "tenzro-train", "inspection",
                    "sla", "fault-detector", "probe", "snapshot",
                    "state-sync", "read-only", "router-metrics",
                    "tail-latency",
                ],
                "examples": [
                    "Show the current active validator set with stake",
                    "Get validator state for address 0x…",
                    "List jailed validators",
                    "List every active Tenzro Train run",
                    "Get Tenzro Train run task-abc123 (status, current_round, state_root)",
                    "Fetch the sealed receipt for finalized run task-abc123",
                    "Fetch the sealed-shard manifest for Confidential-tier run task-xyz789",
                    "Ask the syncer whether Tenzro Train run task-abc123 should finalize, wait, or advance on no-quorum",
                    "Read the inference router metrics (requests routed, hedges dispatched, hedges won, deadline-exceeded)",
                    "Show this validator's SLA fault-detector parameters (slash threshold, slash amount, VRF pubkey)",
                    "List every in-flight SLA probe across the network",
                    "Issue an SLA liveness probe to provider did:tenzro:machine:abc for epoch 42 round 3 with deadline +5s",
                    "List local state-sync snapshots",
                    "Fetch the snapshot manifest at height 5000 (state_root_hex, chunk_hashes_hex)",
                    "Fetch chunk 0 of the snapshot at height 5000",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "urwa",
                "name": "ERC-7943 (uRWA) Compliance",
                "description": (
                    "Universal Real-World Asset compliance: kill-switch, "
                    "per-account freeze, forced-transfer for tokenized RWAs."
                ),
                "tags": ["urwa", "erc7943", "rwa", "kill-switch", "freeze"],
                "examples": [
                    "Check if token 0xabc is kill-switched",
                    "Get frozen amount for account 0xdef on token 0xabc",
                    "Freeze 1000 tokens on account 0xdef pending KYC refresh",
                    "Activate the kill-switch on token 0xabc citing sanctions update",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "ivms101",
                "name": "IVMS101 Travel Rule",
                "description": (
                    "FATF Travel Rule envelope: canonical SHA-256 binding hash for "
                    "an originator + beneficiary + VASP + transfer-data record."
                ),
                "tags": ["ivms101", "travel-rule", "fatf", "compliance", "trp"],
                "examples": [
                    "Hash an IVMS101 envelope binding originator + beneficiary VASPs",
                    "Anchor a settlement receipt to an off-chain Travel Rule envelope",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "attested-clock",
                "name": "TEE-Attested Clock",
                "description": (
                    "Hardware-attested wall-clock + monotonic counter for long-running "
                    "workflows that cannot trust any single replica's wall-clock."
                ),
                "tags": ["attested-clock", "tee", "workflow", "deadline"],
                "examples": [
                    "Return the current AttestedTimestamp envelope",
                    "Anchor an AP2 mandate expiry to a hardware-signed timestamp",
                    "Bind a margin-call grace deadline to an attested wall_ms",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "signed-agent-card",
                "name": "A2A v1.0 Signed Agent Cards",
                "description": (
                    "Compute the canonical hash for an A2A v1.0 SignedAgentCard "
                    "envelope so domain owners JWS-sign and relying parties verify."
                ),
                "tags": ["a2a", "signed-agent-card", "jws", "did-web"],
                "examples": [
                    "Compute the canonical hash for an AgentCard JSON payload",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "wormhole-ntt",
                "name": "Wormhole NTT",
                "description": (
                    "Native Token Transfers — Wormhole's 2026 multi-chain native-token "
                    "primitive with per-chain NttManager + quorum-aggregated Transceivers."
                ),
                "tags": ["wormhole", "ntt", "cross-chain", "native-token"],
                "examples": [
                    "List the Wormhole NTT chain catalog + transceiver kinds",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "bridge-fee-in-tnzo",
                "name": "Bridge Fee in TNZO",
                "description": (
                    "Pay cross-chain bridge fees in TNZO instead of destination-chain "
                    "gas. Cosmos ICS-29 / Hyperlane IGP / Polkadot AssetHub pattern."
                ),
                "tags": [
                    "bridge-fee", "tnzo", "cross-chain", "sponsorship", "ics-29",
                ],
                "examples": [
                    "Quote the CCIP fee to eip155:1 in TNZO for a 1M-wei native fee",
                    "Enumerate per-adapter sponsorship-pool vault addresses",
                ],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "storage",
                "name": "Decentralized Storage",
                "description": (
                    "Content-addressed storage on the iroh data plane, billed per "
                    "byte-epoch and held to a proof of retrievability. Store an "
                    "object with an erasure-coded redundancy scheme, open a "
                    "streaming deal (the renter pre-funds total epochs from their "
                    "deposit), run a retrievability-gated charge epoch, look up a "
                    "deal, set the byte-epoch pricing policy (fixed or "
                    "network-dynamic), and read this node's storage-provider "
                    "status. Storage and compute rental register against one "
                    "shared coverage budget per provider — a single stake backs "
                    "both."
                ),
                "tags": [
                    "storage", "por", "byte-epoch", "iroh", "redundancy",
                    "deal", "provider",
                ],
                "examples": [
                    "Store an object with a 4+2 redundancy scheme",
                    "Open a storage deal for object <id> over 100 epochs",
                    "Charge one retrievability-gated epoch on deal <id>",
                    "Look up storage deal <id>",
                    "Set dynamic byte-epoch pricing with capacity 1e12",
                    "Show this node's storage-provider status",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "database",
                "name": "Managed Databases",
                "description": (
                    "Register and query owned databases the node serves across "
                    "external engines (PostgreSQL, Qdrant, Valkey) and embedded "
                    "engines (Lance, Tantivy). Compute partition placement over "
                    "the live cluster along a local → LAN-cluster → network "
                    "continuum, gate reads and writes behind an owner-or-capability "
                    "access policy, mint a bearer connection credential for a "
                    "developer, run an engine-dialect query against the partition a "
                    "node holds (or receive the holder endpoints when it does not), "
                    "rescale a database in place, and drop it. Databases may be "
                    "marked confidential for encryption at rest."
                ),
                "tags": [
                    "database", "sql", "vector", "kv", "search", "partition",
                    "access-policy", "capability", "confidential",
                ],
                "examples": [
                    "List database engines",
                    "Create database (metadata: database_id, engine_id=qdrant, "
                    "owner_did, placement=lan_cluster, partitions=3, "
                    "min_replication=2, max_replication=4)",
                    "List databases",
                    "List database partitions (metadata: database_id)",
                    "Issue database connection (metadata: database_id, caller_did, "
                    "bearer_did, write=true, ttl_secs=3600)",
                    "Database query (metadata: database_id, caller_did, body)",
                    "Authorize database read (metadata: database_id, caller_did)",
                    "Rescale database (metadata: database_id, caller_did, "
                    "placement=network, partitions=6)",
                    "Drop database (metadata: database_id)",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "compute",
                "name": "Compute Rental",
                "description": (
                    "Rent this node's compute against its stake. Book a rental "
                    "(the renter pre-funds total epochs from their deposit), "
                    "settle one epoch gated on the provider's availability proof "
                    "(a valid proof streams the epoch slice to the provider; an "
                    "invalid or missing proof makes the renter whole from stake), "
                    "look up a rental, set the per-epoch pricing policy (fixed or "
                    "network-dynamic), and read this node's compute-rental "
                    "status. Shares one coverage budget with storage."
                ),
                "tags": [
                    "compute", "rental", "availability-proof", "epoch",
                    "pricing", "provider",
                ],
                "examples": [
                    "Book a compute rental over 50 epochs",
                    "Settle epoch 7 of rental <id>",
                    "Look up compute rental <id>",
                    "Set dynamic compute pricing with capacity 1e9",
                    "Show this node's compute-rental status",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "moe",
                "name": "Distributed MoE Serving",
                "description": (
                    "Decentralized mixture-of-experts expert-shard serving. Read "
                    "the shard map for a model (which providers hold each "
                    "(layer, expert), per-expert replication, under-replicated "
                    "and hot experts, role counts), build a dispatch plan from "
                    "per-token top-k routing decisions, read the "
                    "governance-tuned replication policy, read the "
                    "catalog-side MoE topology (num_experts, experts_per_token, "
                    "shared_experts), load per-expert and gating weight blobs "
                    "into the local expert runtime, and run distributed layer "
                    "forwards that fan hidden states out to expert holders over "
                    "local, iroh, or HTTP transports and gather gate-weighted "
                    "outputs. Prepare experts for holders by slicing a catalog "
                    "checkpoint into per-expert blobs, optionally block-quantizing "
                    "each projection (q4_k_m / q8_0 / q4_k / q6_k preset or a "
                    "per-projection gate/up/down mix) so a holder loads a smaller "
                    "footprint. The runtime tiers experts across a byte-bounded "
                    "memory LRU and a disk tier that decodes spilled experts on "
                    "demand, so a holder can serve more experts than fit in "
                    "memory; runtime status reports each expert's residency tier "
                    "(memory / disk), byte footprint, memory budget, and whether "
                    "GPU compute is active. Expert compute runs on CPU by default "
                    "(dense f32 plus a runtime-detected AVX-512-VNNI Q8_0 path) "
                    "and on an optional CUDA or cross-vendor GPU backend where "
                    "built; holders advertise GPU compute so routing can bias "
                    "toward them. Cross-holder forwards overlap by compressing "
                    "activations, dispatching warm-first backups for slow holders, "
                    "and pipelining the gate-weighted combine as contributions "
                    "arrive."
                ),
                "tags": [
                    "moe", "expert-shard", "dispatch", "replication",
                    "routing", "inference", "expert-execution",
                    "quantization", "gpu",
                ],
                "examples": [
                    "Show the MoE shard map for model <id>",
                    "Plan dispatch for top-k routings on model <id>",
                    "Read the current MoE replication policy",
                    "Read the catalog MoE topology for model <id>",
                    "Prepare layer 4 experts quantized q4_k_m for holders",
                    "Load an expert weight blob for layer 4 expert 17",
                    "Report resident experts with their residency tier",
                    "Run a distributed MoE forward for one layer",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "discovery",
                "name": "Local Discovery & LAN Clustering",
                "description": (
                    "Local-segment discovery and LAN cluster planning. List "
                    "peers discovered on this node's local segment via mDNS, "
                    "read this node's sustained connectivity tier (direct / "
                    "relay_only / unreachable) — the same tier the node acts on "
                    "automatically to promote its Kademlia role to server once "
                    "directly reachable and to book a relay reservation while "
                    "still behind NAT — read this node's hardware "
                    "self-profile (runtime build commit, CPU architecture, OS, "
                    "detected compute devices, derived serving capacity / "
                    "backend / capability key), and compute a deterministic "
                    "layer-wise cluster placement for a model across candidate "
                    "members — the fit decision and, when a cluster forms, the "
                    "VRAM-weighted per-member layer assignment ordered to "
                    "minimize pipeline transfer cost. Or preview placement for a "
                    "downloaded model from the node's live view, deriving the "
                    "model shape from the GGUF header and discovering LAN "
                    "members automatically — no manual dimensions required."
                ),
                "tags": [
                    "discovery", "mdns", "lan-cluster", "reachability",
                    "hardware-profile", "pipeline-parallel",
                ],
                "examples": [
                    "List peers on my local segment",
                    "What is this node's connectivity tier?",
                    "Show this node's hardware profile",
                    "Plan a LAN cluster for a 32-layer model across these members",
                    "Preview the cluster placement for gemma3-large",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "hosting",
                "name": "Decentralized App Hosting",
                "description": (
                    "Publish and serve apps under *.apps.tenzro.xyz behind "
                    "wildcard TLS, host-routed to any serving node in the "
                    "fleet over the tenzro/http ALPN. Three runtime classes: "
                    "static sites (any framework's static export — a route "
                    "map of BLAKE3 blob hashes served by any node), functions "
                    "(a wasi:http WebAssembly component run under wasmtime "
                    "with capability, fuel, and per-request deadline limits), "
                    "and machines (a Firecracker microVM from a "
                    "content-addressed image, placed only on KVM + "
                    "nested-virt nodes, optionally TEE-sealed). Site surface: "
                    "publish / get / list / remove, hostname aliases "
                    "(set / get / list / remove), serving-node placement "
                    "(set / get / list / remove), and custom domains "
                    "(claim → publish DNS TXT proof → verify → activate). "
                    "Function surface: deploy / get / list / remove. Machine "
                    "surface: deploy / get / list / remove / status, plus "
                    "machine_sealing_key to fetch the node's X25519 key for "
                    "wrapping env-var ciphertext (alg "
                    "x25519-envelope-aes-256-gcm) before deploy. Placement "
                    "leases (list_leases, get_leases_for_app) surface the "
                    "bid/lease bindings and tenzro/sla heartbeat failover. "
                    "Requests can be x402-gated per request. All mutations "
                    "require a signed did_envelope whose did equals owner_did."
                ),
                "tags": [
                    "hosting", "apps", "static-site", "function",
                    "wasi-http", "wasm", "microvm", "firecracker",
                    "iroh", "tenzro-http", "custom-domain", "x402",
                    "placement", "lease", "tee",
                ],
                "examples": [
                    "Publish a static site 'my-app' with these routes for owner did:tenzro:human:…",
                    "Map my-app.apps.tenzro.xyz to site site-abc123",
                    "Claim custom domain app.example.com for site site-abc123 and give me the DNS TXT proof",
                    "Verify custom domain app.example.com now that the TXT record is published",
                    "Pin site site-abc123 to serving nodes [endpoint1, endpoint2]",
                    "Deploy a wasi:http function 'edge-fn' from wasm blob 0x… with a 1s deadline",
                    "Fetch this node's machine sealing key",
                    "Deploy a TEE-sealed microVM 'api-vm' from artifact caid… on internal port 8080",
                    "Show the live status of machine machine-xyz",
                    "List the placement leases bound to app site-abc123",
                ],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"],
            },
        ],
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
    }
