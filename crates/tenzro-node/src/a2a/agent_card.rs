//! Agent Card — A2A protocol discovery via /.well-known/agent.json
//!
//! As of A2A v1.0 the agent card MAY be served wrapped in a `SignedAgentCard`
//! envelope carrying a JWS signature over the canonical card JSON. Relying
//! parties verify the signature against the public key of the domain
//! (typically `did:web:<host>` resolution or a `.well-known/jwks.json`
//! published by the domain owner). This stops a hostile reverse proxy or
//! intermediate cache from rewriting the card's `url`, `skills`, or
//! `securitySchemes` without detection — the conformance bar set by the
//! A2A 2026 spec.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A2A Agent Card per the Google A2A specification.
/// Served at `GET /.well-known/agent.json` for agent discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// Agent name
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// A2A endpoint URL (where JSON-RPC requests are sent)
    pub url: String,
    /// Agent version
    pub version: String,
    /// Protocol version supported
    pub protocol_version: String,
    /// Agent capabilities
    pub capabilities: AgentCapabilities,
    /// Skills this agent provides
    pub skills: Vec<AgentSkill>,
    /// Authentication requirements
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub security_schemes: Vec<SecurityScheme>,
    /// Default input content types
    pub default_input_modes: Vec<String>,
    /// Default output content types
    pub default_output_modes: Vec<String>,
}

/// Capabilities the agent supports
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// Whether the agent supports streaming responses via SSE
    pub streaming: bool,
    /// Whether the agent supports push notifications
    pub push_notifications: bool,
    /// Whether the agent supports multi-turn conversations
    pub state_transition_history: bool,
}

/// A skill advertised by the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    /// Skill identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this skill does
    pub description: String,
    /// Tags for discovery
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tags: Vec<String>,
    /// Example prompts
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub examples: Vec<String>,
    /// Input content types
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub input_modes: Vec<String>,
    /// Output content types
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub output_modes: Vec<String>,
}

/// Authentication scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityScheme {
    /// Scheme type (e.g., "bearer", "apiKey")
    #[serde(rename = "type")]
    pub scheme_type: String,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Build an Agent Card from node configuration.
///
/// `a2a_addr` is the listen address (e.g. `0.0.0.0:3002`). The advertised URL
/// prefers the `TENZRO_A2A_PUBLIC_URL` environment variable when set —
/// otherwise it falls back to `http://<a2a_addr>/a2a`. Setting the env var to
/// e.g. `https://a2a.tenzro.xyz` produces a card pointing at the public
/// endpoint instead of the internal bind address.
pub fn build_agent_card(a2a_addr: &str, node_role: &str) -> AgentCard {
    let url = match std::env::var("TENZRO_A2A_PUBLIC_URL") {
        Ok(public) if !public.is_empty() => {
            let trimmed = public.trim_end_matches('/');
            // Allow either a bare host ("https://a2a.tenzro.xyz") or a full
            // path ("https://a2a.tenzro.xyz/a2a"). Append /a2a only if the
            // caller didn't already supply a path component beyond `://`.
            if trimmed.split_once("://").map(|(_, rest)| rest.contains('/')).unwrap_or(false) {
                trimmed.to_string()
            } else {
                format!("{}/a2a", trimmed)
            }
        }
        _ => format!("http://{}/a2a", a2a_addr),
    };

    AgentCard {
        name: "Tenzro Network Agent".to_string(),
        description: format!(
            "Tenzro Network node ({}) — AI-native agentic tokenized settlement layer. \
             Provides wallet operations, identity management, inference routing, \
             settlement, and blockchain interaction.",
            node_role
        ),
        url,
        version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: "0.2.0".to_string(),
        capabilities: AgentCapabilities {
            streaming: true,
            push_notifications: false,
            state_transition_history: true,
        },
        skills: vec![
            AgentSkill {
                id: "wallet".to_string(),
                name: "Wallet Operations".to_string(),
                description: "Create wallets, check balances, and send TNZO transactions \
                              on the Tenzro network."
                    .to_string(),
                tags: vec![
                    "blockchain".to_string(),
                    "wallet".to_string(),
                    "payments".to_string(),
                ],
                examples: vec![
                    "Check my TNZO balance".to_string(),
                    "Send 10 TNZO to 0xabc...".to_string(),
                    "Create a new wallet".to_string(),
                ],
                input_modes: vec!["text/plain".to_string()],
                output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            },
            AgentSkill {
                id: "identity".to_string(),
                name: "Identity Management".to_string(),
                description: "Register and resolve decentralized identities (DIDs) \
                              on the Tenzro Decentralized Identity Protocol (TDIP). \
                              Manage human-readable usernames with set_username and \
                              resolve_username for easy identity lookup."
                    .to_string(),
                tags: vec![
                    "identity".to_string(),
                    "did".to_string(),
                    "credentials".to_string(),
                    "username".to_string(),
                ],
                examples: vec![
                    "Register a new identity".to_string(),
                    "Resolve DID did:tenzro:human:abc123".to_string(),
                    "Set my username to alice".to_string(),
                    "Resolve username bob".to_string(),
                ],
                input_modes: vec!["text/plain".to_string()],
                output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            },
            AgentSkill {
                id: "inference".to_string(),
                name: "AI Inference".to_string(),
                description: "Route AI inference requests to model providers on the \
                              Tenzro network, with settlement in TNZO."
                    .to_string(),
                tags: vec![
                    "ai".to_string(),
                    "inference".to_string(),
                    "models".to_string(),
                ],
                examples: vec![
                    "List available AI models".to_string(),
                    "Run inference on model X".to_string(),
                ],
                input_modes: vec!["text/plain".to_string()],
                output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            },
            AgentSkill {
                id: "settlement".to_string(),
                name: "Settlement & Payments".to_string(),
                description: "Settle payments for AI services using micropayment channels, \
                              escrow, and batch settlement on the Tenzro ledger."
                    .to_string(),
                tags: vec![
                    "settlement".to_string(),
                    "payments".to_string(),
                    "escrow".to_string(),
                ],
                examples: vec![
                    "Check settlement status".to_string(),
                    "Open a micropayment channel".to_string(),
                ],
                input_modes: vec!["text/plain".to_string()],
                output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            },
            AgentSkill {
                id: "workflow-coordination".to_string(),
                name: "Multi-Agent Saga Workflow Coordination".to_string(),
                description: "Durable, identity-bound, settlement-aware checkpoint substrate \
                              for multi-agent workflows (the 'Temporal for trusted multi-agent \
                              workflows' tier). Open a saga of steps, then per step: Execute \
                              (optionally lock per-step escrow), Verify (release escrow + write \
                              ERC-8004 reputation), or Compensate (refund escrow, optionally \
                              cascading rollback in reverse order). Finalize records a receipt. \
                              Frameworks (LangGraph / CrewAI / AutoGen Magentic-One / ADK) keep \
                              their runtime; Tenzro is the wire + on-chain anchor per \
                              multi-agent-workflow-coordination.md."
                    .to_string(),
                tags: vec![
                    "workflow".to_string(),
                    "saga".to_string(),
                    "compensation".to_string(),
                    "escrow".to_string(),
                    "orchestration".to_string(),
                ],
                examples: vec![
                    "Open workflow wf_abc with steps [research, quote, pay, receipt]".to_string(),
                    "Execute step 2 (pay) locking 30 TNZO in escrow".to_string(),
                    "Verify step 2 with the supplier's signed receipt".to_string(),
                    "Compensate step 2 and refund the escrow".to_string(),
                ],
                input_modes: vec!["application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "verification".to_string(),
                name: "Proof Verification".to_string(),
                description: "Verify Plonky3 STARK proofs over the KoalaBear field (one of the registered AIRs: \
                              inference, settlement, identity), VRF proofs \
                              (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI), TEE attestations, \
                              and transaction signatures on the Tenzro network."
                    .to_string(),
                tags: vec![
                    "verification".to_string(),
                    "zk-proofs".to_string(),
                    "vrf".to_string(),
                    "randomness".to_string(),
                    "tee".to_string(),
                ],
                examples: vec![
                    "Verify a ZK proof".to_string(),
                    "Verify a VRF proof for NFT mint randomness".to_string(),
                    "Generate a VRF proof from a block hash".to_string(),
                    "Check TEE attestation".to_string(),
                ],
                input_modes: vec!["application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "staking".to_string(),
                name: "Staking & Provider Management".to_string(),
                description: "Stake TNZO tokens, manage validator/provider registration, \
                              and query provider performance statistics."
                    .to_string(),
                tags: vec![
                    "staking".to_string(),
                    "provider".to_string(),
                    "validator".to_string(),
                ],
                examples: vec![
                    "How much TNZO is staked?".to_string(),
                    "Register as a model provider".to_string(),
                    "Get provider statistics".to_string(),
                ],
                input_modes: vec!["text/plain".to_string()],
                output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            },
            AgentSkill {
                id: "task_marketplace".to_string(),
                name: "Task Marketplace Lifecycle".to_string(),
                description: "Post → Quote → Escrow+Assign → Complete → Settle+Reputation. \
                              Hand a unit of work to the network without picking a provider: \
                              post a task with structured acceptance criteria, collect quotes \
                              (optionally with TEE attestation + ERC-8004 reputation proof), \
                              assign with on-chain escrow, and settle on proof-verified \
                              completion with ERC-8004 reputation feedback. Disputes are \
                              oracle/governance-arbitrated."
                    .to_string(),
                tags: vec![
                    "task".to_string(),
                    "marketplace".to_string(),
                    "escrow".to_string(),
                    "reputation".to_string(),
                    "erc8004".to_string(),
                ],
                examples: vec![
                    "Post a task: 3-page market analysis, max 50 TNZO, 24h deadline".to_string(),
                    "Quote task abc with price 30 TNZO and a reputation proof".to_string(),
                    "Assign task abc to provider 0x… and fund escrow".to_string(),
                    "Complete task abc with a TEE-attested result".to_string(),
                    "List open inference tasks".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "agent_marketplace".to_string(),
                name: "Agent Marketplace".to_string(),
                description: "Publish, discover, rate, and spawn reusable AI agent templates on \
                              the Tenzro decentralized agent marketplace. Search templates \
                              by capability, type, and pricing model. Rate templates, view \
                              template stats, and spawn running agents from templates."
                    .to_string(),
                tags: vec![
                    "agents".to_string(),
                    "marketplace".to_string(),
                    "templates".to_string(),
                    "ai".to_string(),
                    "rating".to_string(),
                ],
                examples: vec![
                    "List available agent templates".to_string(),
                    "Register a new coding agent template".to_string(),
                    "Search for autonomous agent templates".to_string(),
                    "Get agent template details for template-id-789".to_string(),
                    "Rate template template-id-789 with 5 stars".to_string(),
                    "Spawn an agent from template template-id-789".to_string(),
                    "Get stats for agent template template-id-789".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "agent_spawning".to_string(),
                name: "Agent Spawning".to_string(),
                description: "Dynamically spawn autonomous sub-agents with specific capabilities. \
                              Parent agents can create up to 50 children, each with its own DID \
                              and MPC wallet. Supports hierarchical agent topologies."
                    .to_string(),
                tags: vec![
                    "agents".to_string(),
                    "spawning".to_string(),
                    "autonomous".to_string(),
                    "orchestration".to_string(),
                ],
                examples: vec![
                    "Spawn a sub-agent with coding capabilities".to_string(),
                    "List my child agents".to_string(),
                    "Run an autonomous agent task".to_string(),
                    "Spawn an agent named 'researcher' with web-search capability".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "swarm_orchestration".to_string(),
                name: "Swarm Orchestration".to_string(),
                description: "Create and manage agent swarms for parallel task execution. \
                              An orchestrator agent can create a swarm of specialized sub-agents, \
                              broadcast tasks to all members simultaneously, collect results, \
                              and terminate the swarm when done."
                    .to_string(),
                tags: vec![
                    "swarm".to_string(),
                    "orchestration".to_string(),
                    "parallel".to_string(),
                    "agents".to_string(),
                ],
                examples: vec![
                    "Create a swarm with 3 research agents".to_string(),
                    "Get swarm status for swarm-id-123".to_string(),
                    "Terminate swarm swarm-id-456".to_string(),
                    "Broadcast 'analyze this dataset' to my swarm".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "token".to_string(),
                name: "Token Management".to_string(),
                description: "Create ERC-20 tokens, query token info and balances, \
                              transfer tokens across VMs (EVM, SVM, DAML), and wrap \
                              native TNZO to VM representations via the unified token registry."
                    .to_string(),
                tags: vec![
                    "token".to_string(),
                    "erc20".to_string(),
                    "cross-vm".to_string(),
                    "registry".to_string(),
                ],
                examples: vec![
                    "Create a new token called MyToken (MTK) with 1M supply".to_string(),
                    "Get token info for TNZO".to_string(),
                    "List all registered tokens".to_string(),
                    "Get my TNZO balance across all VMs".to_string(),
                    "Transfer 100 TNZO from EVM to SVM".to_string(),
                    "Wrap 50 TNZO for EVM".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "contract".to_string(),
                name: "Smart Contract Deployment".to_string(),
                description: "Deploy smart contracts to the Tenzro multi-VM runtime \
                              (EVM, SVM, DAML). Submit bytecode with constructor arguments \
                              and receive the deployed contract address."
                    .to_string(),
                tags: vec![
                    "contract".to_string(),
                    "deploy".to_string(),
                    "evm".to_string(),
                    "svm".to_string(),
                    "daml".to_string(),
                ],
                examples: vec![
                    "Deploy an EVM contract with bytecode 0x6080...".to_string(),
                    "Deploy a Solana program".to_string(),
                    "What VMs are supported for contract deployment?".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "ap2-payments".to_string(),
                name: "AP2 Payments".to_string(),
                description: "Agent Payments Protocol (AP2) for autonomous financial \
                              transactions. Create, authorize, execute, check status, \
                              and cancel payments between agents."
                    .to_string(),
                tags: vec![
                    "payments".to_string(),
                    "ap2".to_string(),
                    "agentic".to_string(),
                    "settlement".to_string(),
                ],
                examples: vec![
                    "Create payment for 100 TNZO".to_string(),
                    "Authorize spending limit of 1000 TNZO".to_string(),
                    "Execute payment pay-id-123".to_string(),
                    "Check payment status for pay-id-456".to_string(),
                    "Cancel pending payment pay-id-789".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "join".to_string(),
                name: "Join as MicroNode".to_string(),
                description: "Join the Tenzro Network as a full MicroNode participant — \
                              zero-install. Auto-provisions a TDIP DID, MPC wallet, and \
                              10 network capabilities (inference, payments, agent collaboration, \
                              MCP tools, task execution, chain queries, smart contracts, \
                              TEE compute, cross-chain bridge, governance)."
                    .to_string(),
                tags: vec![
                    "join".to_string(),
                    "onboarding".to_string(),
                    "micronode".to_string(),
                    "identity".to_string(),
                    "wallet".to_string(),
                ],
                examples: vec![
                    "Join the Tenzro Network as Alice".to_string(),
                    "Create a new identity on Tenzro".to_string(),
                    "Onboard to Tenzro with username Bob".to_string(),
                    "Join as a MicroNode".to_string(),
                ],
                input_modes: vec!["text/plain".to_string()],
                output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            },
            AgentSkill {
                id: "nft".to_string(),
                name: "NFT Management".to_string(),
                description: "Create and manage NFT collections (ERC-721/1155), mint tokens, \
                              transfer, query ownership, cross-VM pointers."
                    .to_string(),
                tags: vec![
                    "nft".to_string(),
                    "erc721".to_string(),
                    "erc1155".to_string(),
                    "collectibles".to_string(),
                    "cross-vm".to_string(),
                ],
                examples: vec![
                    "Create a new ERC-721 NFT collection".to_string(),
                    "Mint an NFT in collection 0xabc...".to_string(),
                    "Transfer NFT #42 to 0xdef...".to_string(),
                    "Query ownership of NFT #7".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "bridge".to_string(),
                name: "Cross-Chain Bridge".to_string(),
                description: "Cross-chain bridge operations via LI.FI aggregator (58+ chains), \
                              LayerZero, CCIP v1.6, deBridge with hooks."
                    .to_string(),
                tags: vec![
                    "bridge".to_string(),
                    "cross-chain".to_string(),
                    "lifi".to_string(),
                    "layerzero".to_string(),
                    "ccip".to_string(),
                    "debridge".to_string(),
                ],
                examples: vec![
                    "Bridge 100 TNZO from Ethereum to Solana".to_string(),
                    "Get bridge routes from Tenzro to Base".to_string(),
                    "Estimate bridge fee for 500 USDC to Arbitrum".to_string(),
                    "List available bridge adapters".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "compliance".to_string(),
                name: "Compliance & KYC".to_string(),
                description: "ERC-3643 T-REX compliance: KYC verification, accreditation, \
                              country restrictions, freeze/recover, trusted issuers."
                    .to_string(),
                tags: vec![
                    "compliance".to_string(),
                    "kyc".to_string(),
                    "erc3643".to_string(),
                    "t-rex".to_string(),
                    "accreditation".to_string(),
                ],
                examples: vec![
                    "Verify KYC status for address 0xabc...".to_string(),
                    "Check accreditation for investor 0xdef...".to_string(),
                    "List country restrictions for token XYZ".to_string(),
                    "Freeze token holdings for 0x123...".to_string(),
                    "Add a trusted issuer to the registry".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "crosschain".to_string(),
                name: "Cross-Chain Token Standard".to_string(),
                description: "ERC-7802 cross-chain token standard: authorized bridge mint/burn \
                              with rate limits and audit trail."
                    .to_string(),
                tags: vec![
                    "crosschain".to_string(),
                    "erc7802".to_string(),
                    "mint".to_string(),
                    "burn".to_string(),
                    "rate-limit".to_string(),
                ],
                examples: vec![
                    "Authorize a bridge for cross-chain minting".to_string(),
                    "Set rate limit for bridge 0xabc... to 10000 TNZO/day".to_string(),
                    "Query audit trail for cross-chain token transfers".to_string(),
                    "Revoke bridge authorization for 0xdef...".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "events".to_string(),
                name: "Event Streaming".to_string(),
                description: "Real-time event streaming via WebSocket (eth_subscribe), gRPC, \
                              webhooks with HMAC signatures, historical queries."
                    .to_string(),
                tags: vec![
                    "events".to_string(),
                    "websocket".to_string(),
                    "streaming".to_string(),
                    "webhooks".to_string(),
                    "grpc".to_string(),
                ],
                examples: vec![
                    "Subscribe to new block events via WebSocket".to_string(),
                    "Register a webhook for transfer events on 0xabc...".to_string(),
                    "Query historical events for contract 0xdef...".to_string(),
                    "Stream pending transactions in real time".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string(), "text/event-stream".to_string()],
            },
            AgentSkill {
                id: "erc8004".to_string(),
                name: "ERC-8004 Trustless Agents".to_string(),
                description: "On-chain agent identity and reputation via ERC-8004. \
                              Derive deterministic agent IDs, encode registry calldata \
                              (register, getAgent, feedback, validationRequest, \
                              validationResponse), and decode getAgent returndata for \
                              integration with any EVM-compatible registry contract."
                    .to_string(),
                tags: vec![
                    "erc-8004".to_string(),
                    "agents".to_string(),
                    "reputation".to_string(),
                    "identity".to_string(),
                    "registry".to_string(),
                    "calldata".to_string(),
                ],
                examples: vec![
                    "Derive agent id (metadata.owner, metadata.salt)".to_string(),
                    "Register agent (metadata.agent_id, registration_data_uri, owner)".to_string(),
                    "Get agent <id> (metadata.agent_id)".to_string(),
                    "Submit feedback (agent_id, score, feedback_auth_id, feedback_uri)".to_string(),
                    "Request validation (agent_id, validator_id, request_uri, data_hash)".to_string(),
                    "Submit validation (data_hash, response, response_uri, tag)".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "wormhole".to_string(),
                name: "Wormhole Cross-Chain".to_string(),
                description: "Wormhole cross-chain messaging and token transfers. \
                              Look up numeric chain ids, parse canonical VAA identifiers, \
                              and bridge tokens through the Wormhole adapter registered \
                              on the node's BridgeRouter."
                    .to_string(),
                tags: vec![
                    "wormhole".to_string(),
                    "bridge".to_string(),
                    "cross-chain".to_string(),
                    "vaa".to_string(),
                    "ethereum".to_string(),
                    "solana".to_string(),
                    "base".to_string(),
                    "arbitrum".to_string(),
                    "optimism".to_string(),
                ],
                examples: vec![
                    "Wormhole chain id for ethereum".to_string(),
                    "Wormhole chain id for solana".to_string(),
                    "Parse VAA 2/0x00000000000000000000.../12345".to_string(),
                    "Bridge 100 TNZO from ethereum to solana (metadata.sender/recipient)".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "cct".to_string(),
                name: "TNZO CCT Pool Registry".to_string(),
                description: "Chainlink Cross-Chain Token (CCT) pool registry for TNZO. \
                              Ethereum uses a LockRelease pool; Base, Arbitrum, Optimism, \
                              and Solana use BurnMint pools. Query pool addresses, chain \
                              selectors, and per-chain rate-limiter configuration."
                    .to_string(),
                tags: vec![
                    "cct".to_string(),
                    "chainlink".to_string(),
                    "cross-chain".to_string(),
                    "ccip".to_string(),
                    "lockrelease".to_string(),
                    "burnmint".to_string(),
                    "pool".to_string(),
                    "rate-limit".to_string(),
                ],
                examples: vec![
                    "List CCT pools".to_string(),
                    "Get CCT pool on ethereum".to_string(),
                    "Get CCT pool on base".to_string(),
                    "Get CCT pool on solana".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "cortex".to_string(),
                name: "Cortex Reasoning Workers".to_string(),
                description: "Discover and interact with Tenzro Cortex reasoning workers — \
                              distributed inference workers advertised via gossip with \
                              Ed25519-signed receipts. List remote workers, query aggregated \
                              Cortex metrics, and route reasoning tasks to the optimal worker."
                    .to_string(),
                tags: vec![
                    "cortex".to_string(),
                    "reasoning".to_string(),
                    "inference".to_string(),
                    "workers".to_string(),
                    "gossip".to_string(),
                    "ai".to_string(),
                    "metrics".to_string(),
                    "phase2".to_string(),
                    "agentic".to_string(),
                ],
                examples: vec![
                    "List remote Cortex reasoning workers".to_string(),
                    "Get Cortex network metrics".to_string(),
                    "Find the fastest Cortex worker for reasoning".to_string(),
                    "Show Cortex worker reputation scores".to_string(),
                    "Route my reasoning task to the best Cortex worker".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "capability_registry".to_string(),
                name: "Capability Registry".to_string(),
                description: "Discover registered agent capabilities and inspect signed/TEE-backed \
                              attestations supporting capability claims. List all capabilities \
                              with agent and attestation counts, fetch attestation envelopes for \
                              a specific capability, fetch all attestations issued for a given \
                              agent ID, and pick the best (TEE-backed-preferred) agent for a \
                              capability. Eager signature verification per CRITICAL #52 means \
                              every stored attestation already passed canonical signing-data \
                              cryptographic checks."
                    .to_string(),
                tags: vec![
                    "capabilities".to_string(),
                    "attestations".to_string(),
                    "discovery".to_string(),
                    "trust".to_string(),
                    "tee".to_string(),
                    "ed25519".to_string(),
                    "agentic".to_string(),
                ],
                examples: vec![
                    "List all registered capabilities on this node".to_string(),
                    "Show attestations for the 'nlp' capability".to_string(),
                    "Show attestations issued for agent agent-id-123".to_string(),
                    "Pick the best agent for 'code' generation".to_string(),
                    "Find a TEE-backed agent for 'vision'".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "adaptive-burn".to_string(),
                name: "Adaptive Burn-Rate Governance Dial".to_string(),
                description:
                    "Read-side surface for the adaptive burn-rate dial (Spec 7). Exposes the \
                     current BurnRateConfig (base / local / paymaster bps with treasury \
                     complements; paymaster locked at 100% burn), the latest \
                     SupplyMetricsSnapshot (rolling-window epoch delta, burn + emission \
                     breakdowns), and the pure-function BurnRateRecommendation (NoChange / \
                     IncreaseBurnPct / DecreaseBurnPct / AlarmHighInflation / \
                     AlarmHighDeflation with magnitude bps capped at the normal / alarm \
                     ceiling). The dial moves only via on-chain governance proposals; the \
                     auto-proposal generator + EIP-1559 fee-market consumer wiring is \
                     not implemented yet."
                        .to_string(),
                tags: vec![
                    "adaptive-burn".to_string(),
                    "governance".to_string(),
                    "tokenomics".to_string(),
                    "supply".to_string(),
                    "burn-rate".to_string(),
                    "eip-1559".to_string(),
                    "spec-7".to_string(),
                ],
                examples: vec![
                    "Get the current burn-rate config and target band".to_string(),
                    "Get the latest supply-metrics snapshot".to_string(),
                    "Get the current burn-rate recommendation (action + magnitude bps)".to_string(),
                    "List pending adaptive-burn governance proposals".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "seed-agent".to_string(),
                name: "SeedAgent Treasury Earmark".to_string(),
                description:
                    "SeedAgent treasury allocation surface (Spec 10). Exposes the \
                     genesis-funded TreasuryEarmark singleton (initial / remaining / drawn \
                     TNZO, decay schedule, sunset surplus burn bps), the governance-signed \
                     Charter registry (OperationKind set + spend caps + counterparty filter \
                     + throughput target + sunset), the per-DID SeedAgentRecord roster \
                     (status: Active / Paused / Quarantined / Terminated; allocation drawn; \
                     optional bond id), and the network-activity counters with \
                     `exclude_seed` filter to isolate organic flows from protocol-owned \
                     bootstrap traffic during the 12-month earmark window."
                        .to_string(),
                tags: vec![
                    "seed-agent".to_string(),
                    "treasury".to_string(),
                    "earmark".to_string(),
                    "charter".to_string(),
                    "bootstrap".to_string(),
                    "spec-10".to_string(),
                    "governance".to_string(),
                ],
                examples: vec![
                    "Show the SeedAgent treasury earmark (allocation remaining, decay schedule, agent count)".to_string(),
                    "List every SeedAgent governance charter".to_string(),
                    "Fetch SeedAgent charter 0x… (operations, spend caps, sunset)".to_string(),
                    "List provisioned seed agents under charter 0x…".to_string(),
                    "Get 24h network activity with exclude_seed=true".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "erc7683".to_string(),
                name: "ERC-7683 Cross-Chain Intents".to_string(),
                description:
                    "ERC-7683 cross-chain intent settler surface (Spec 4). Origin-side \
                     reads against the Tenzro7683Order envelope persisted under the \
                     `7683_origin:` keyspace, with the OrderState machine Open → \
                     AwaitingProof → Settled / Refunded / ForceRefundEligible. \
                     Destination-side commit of FillRecord (single-shot per order_id; \
                     duplicate returns JSON-RPC -32010 OrderAlreadyFilled) plus fill read \
                     endpoints. ProofRoute is one of LayerZero / Wormhole / DeBridge / \
                     Hyperlane."
                        .to_string(),
                tags: vec![
                    "erc-7683".to_string(),
                    "cross-chain".to_string(),
                    "intent".to_string(),
                    "settler".to_string(),
                    "fill".to_string(),
                    "spec-4".to_string(),
                    "layerzero".to_string(),
                    "wormhole".to_string(),
                    "debridge".to_string(),
                    "hyperlane".to_string(),
                ],
                examples: vec![
                    "Get ERC-7683 order 0x… (state, dest_chain, outputs)".to_string(),
                    "List open ERC-7683 orders bound for dest_chain=8453".to_string(),
                    "Record fill for order 0x… (origin_chain, filler, proof_route, outputs[])".to_string(),
                    "Get fill record for order 0x… origin_chain=1".to_string(),
                    "List every recorded ERC-7683 fill on this node".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "iroh-transport".to_string(),
                name: "Iroh QUIC Transport (tenzro/a2a)".to_string(),
                description:
                    "This node also serves A2A JSON-RPC over the `tenzro/a2a` ALPN on its iroh \
                     endpoint, in addition to the HTTPS endpoint advertised by `url`. The iroh \
                     EndpointId is byte-identical to the node's TDIP Ed25519 key and is \
                     discoverable via `tenzro_iroh_getEndpointId` over the JSON-RPC namespace or \
                     `tenzro_iroh_getInfo` for the full set of bound ALPNs and Pkarr relay. \
                     Peers behind NAT can dial via Pkarr + DCUtR hole-punching, with relay \
                     fallback, when direct HTTPS reachability is unavailable."
                        .to_string(),
                tags: vec![
                    "transport".to_string(),
                    "iroh".to_string(),
                    "quic".to_string(),
                    "pkarr".to_string(),
                    "nat-traversal".to_string(),
                    "alpn".to_string(),
                ],
                examples: vec![
                    "Dial this node's A2A endpoint over iroh using the `tenzro/a2a` ALPN".to_string(),
                    "Discover the iroh EndpointId via tenzro_iroh_getEndpointId".to_string(),
                    "List bound ALPNs via tenzro_iroh_listAlpns".to_string(),
                ],
                input_modes: vec!["application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            // Institutional primitives.
            AgentSkill {
                id: "urwa".to_string(),
                name: "ERC-7943 (uRWA) Compliance".to_string(),
                description: "Universal Real-World Asset compliance: kill-switch, \
                              per-account freeze, forced-transfer for tokenized RWAs."
                    .to_string(),
                tags: vec![
                    "urwa".to_string(),
                    "erc7943".to_string(),
                    "rwa".to_string(),
                    "kill-switch".to_string(),
                    "freeze".to_string(),
                ],
                examples: vec![
                    "Check if token 0xabc is kill-switched".to_string(),
                    "Get frozen amount for account 0xdef on token 0xabc".to_string(),
                    "Freeze 1000 tokens on account 0xdef pending KYC refresh".to_string(),
                    "Activate the kill-switch on token 0xabc citing sanctions update".to_string(),
                ],
                input_modes: vec!["application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "ivms101".to_string(),
                name: "IVMS101 Travel Rule".to_string(),
                description: "FATF Travel Rule envelope: canonical SHA-256 binding hash \
                              for an originator + beneficiary + VASP + transfer-data record."
                    .to_string(),
                tags: vec![
                    "ivms101".to_string(),
                    "travel-rule".to_string(),
                    "fatf".to_string(),
                    "compliance".to_string(),
                    "trp".to_string(),
                ],
                examples: vec![
                    "Hash an IVMS101 envelope binding originator + beneficiary VASPs".to_string(),
                    "Anchor a settlement receipt to an off-chain Travel Rule envelope".to_string(),
                ],
                input_modes: vec!["application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "attested-clock".to_string(),
                name: "TEE-Attested Clock".to_string(),
                description: "Hardware-attested wall-clock + monotonic counter for long-running \
                              workflows that cannot trust any single replica's wall-clock."
                    .to_string(),
                tags: vec![
                    "attested-clock".to_string(),
                    "tee".to_string(),
                    "workflow".to_string(),
                    "deadline".to_string(),
                ],
                examples: vec![
                    "Return the current AttestedTimestamp envelope".to_string(),
                    "Anchor an AP2 mandate expiry to a hardware-signed timestamp".to_string(),
                    "Bind a margin-call grace deadline to an attested wall_ms".to_string(),
                ],
                input_modes: vec!["application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "signed-agent-card".to_string(),
                name: "A2A v1.0 Signed Agent Cards".to_string(),
                description: "Compute the canonical hash for an A2A v1.0 SignedAgentCard \
                              envelope so domain owners JWS-sign and relying parties verify."
                    .to_string(),
                tags: vec![
                    "a2a".to_string(),
                    "signed-agent-card".to_string(),
                    "jws".to_string(),
                    "did-web".to_string(),
                ],
                examples: vec![
                    "Compute the canonical hash for an AgentCard JSON payload".to_string(),
                ],
                input_modes: vec!["application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "wormhole-ntt".to_string(),
                name: "Wormhole NTT".to_string(),
                description: "Native Token Transfers — Wormhole's 2026 multi-chain native-token \
                              primitive with per-chain NttManager + quorum-aggregated Transceivers."
                    .to_string(),
                tags: vec![
                    "wormhole".to_string(),
                    "ntt".to_string(),
                    "cross-chain".to_string(),
                    "native-token".to_string(),
                ],
                examples: vec![
                    "List the Wormhole NTT chain catalog + transceiver kinds".to_string(),
                ],
                input_modes: vec!["application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "bridge-fee-in-tnzo".to_string(),
                name: "Bridge Fee in TNZO".to_string(),
                description: "Pay cross-chain bridge fees in TNZO instead of destination-chain \
                              gas. Cosmos ICS-29 / Hyperlane IGP / Polkadot AssetHub pattern."
                    .to_string(),
                tags: vec![
                    "bridge-fee".to_string(),
                    "tnzo".to_string(),
                    "cross-chain".to_string(),
                    "sponsorship".to_string(),
                    "ics-29".to_string(),
                ],
                examples: vec![
                    "Quote the CCIP fee to eip155:1 in TNZO for a 1M-wei native fee".to_string(),
                    "Enumerate per-adapter sponsorship-pool vault addresses".to_string(),
                ],
                input_modes: vec!["application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "storage".to_string(),
                name: "Decentralized Storage".to_string(),
                description: "Content-addressed storage on the iroh data plane, billed per \
                              byte-epoch and held to a proof of retrievability. Store an object \
                              with an erasure-coded redundancy scheme, open a streaming deal, run \
                              a retrievability-gated charge epoch, look up a deal, set the \
                              byte-epoch pricing policy, and read this node's storage-provider \
                              status. Storage and compute rental share one coverage budget per \
                              provider — a single stake backs both."
                    .to_string(),
                tags: vec![
                    "storage".to_string(),
                    "por".to_string(),
                    "byte-epoch".to_string(),
                    "iroh".to_string(),
                    "redundancy".to_string(),
                    "provider".to_string(),
                ],
                examples: vec![
                    "Open a storage deal for an object over 100 epochs".to_string(),
                    "Charge one retrievability-gated epoch on a deal".to_string(),
                    "Show this node's storage-provider status".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "compute".to_string(),
                name: "Compute Rental".to_string(),
                description: "Rent this node's compute against its stake. Book a rental, settle \
                              one epoch gated on the provider's availability proof, look up a \
                              rental, set the per-epoch pricing policy, and read this node's \
                              compute-rental status. Shares one coverage budget with storage."
                    .to_string(),
                tags: vec![
                    "compute".to_string(),
                    "rental".to_string(),
                    "availability-proof".to_string(),
                    "epoch".to_string(),
                    "provider".to_string(),
                ],
                examples: vec![
                    "Book a compute rental over 50 epochs".to_string(),
                    "Settle one epoch of an active rental".to_string(),
                    "Show this node's compute-rental status".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "moe".to_string(),
                name: "Distributed MoE Serving".to_string(),
                description: "Decentralized mixture-of-experts expert-shard serving. Read the \
                              shard map for a model, build a dispatch plan from per-token top-k \
                              routing decisions, read the governance-tuned replication policy, \
                              read the catalog-side MoE topology, load per-expert and gating \
                              weight blobs into the local expert runtime, and run distributed \
                              layer forwards that fan hidden states out to expert holders over \
                              local, iroh, or HTTP transports and gather gate-weighted outputs."
                    .to_string(),
                tags: vec![
                    "moe".to_string(),
                    "expert-shard".to_string(),
                    "dispatch".to_string(),
                    "replication".to_string(),
                    "inference".to_string(),
                    "expert-execution".to_string(),
                ],
                examples: vec![
                    "Show the MoE shard map for a model".to_string(),
                    "Plan dispatch for top-k routings on a model".to_string(),
                    "Read the catalog MoE topology for a model".to_string(),
                    "Load an expert weight blob for layer 4 expert 17".to_string(),
                    "Run a distributed MoE forward for one layer".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "media-gen".to_string(),
                name: "Generative Image & Video".to_string(),
                description: "Decentralized generative image and video. Read the curated \
                              diffusers catalog, price a job by pixel-step, post it to the \
                              queue, follow its status, and read the signed receipt that \
                              commits to the rendered bytes. Pipelines whose denoising \
                              schedule splits across a high-noise and a low-noise expert are \
                              served by two workers holding one half each, handing the \
                              intermediate latent over the content-addressed store."
                    .to_string(),
                tags: vec![
                    "media-gen".to_string(),
                    "image".to_string(),
                    "video".to_string(),
                    "diffusion".to_string(),
                    "expert-pair".to_string(),
                ],
                examples: vec![
                    "List the generative-media catalog".to_string(),
                    "Quote a 1328x1328 image at 50 steps".to_string(),
                    "Post a text-to-video job and follow it".to_string(),
                    "Read the receipt for a completed render".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "discovery".to_string(),
                name: "Local Discovery & LAN Clustering".to_string(),
                description: "Local-segment discovery and LAN cluster planning. List peers \
                              discovered on this node's local segment via mDNS, read this node's \
                              connectivity tier (direct / relay_only / unreachable), read its \
                              hardware self-profile, and compute a deterministic layer-wise \
                              cluster placement for a model across candidate members."
                    .to_string(),
                tags: vec![
                    "discovery".to_string(),
                    "mdns".to_string(),
                    "lan-cluster".to_string(),
                    "reachability".to_string(),
                    "hardware-profile".to_string(),
                    "pipeline-parallel".to_string(),
                ],
                examples: vec![
                    "List peers on my local segment".to_string(),
                    "What is this node's connectivity tier?".to_string(),
                    "Plan a LAN cluster for a 32-layer model across these members".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
        ],
        security_schemes: vec![SecurityScheme {
            scheme_type: "bearer".to_string(),
            description: Some(
                "Ed25519 signed JWT or API key for authenticated operations".to_string(),
            ),
        }],
        default_input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
        default_output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
    }
}

/// A2A v1.0 SignedAgentCard envelope. Carries the agent card alongside
/// a JWS signature over its canonical form so relying parties can verify
/// the card was signed by the domain owner (not rewritten by a reverse
/// proxy or intermediary cache).
///
/// Wire shape per A2A v1.0:
/// ```json
/// {
///   "agentCard": { ... },
///   "signature": "<JWS Flattened JSON Serialization>"
/// }
/// ```
///
/// We use **detached** JWS payload semantics: the `signature` field carries
/// a JWS Compact Serialization (`<base64url(header)>.<base64url(payload-hash)>.<base64url(sig)>`)
/// over `SHA-256(canonical_agent_card_json)`. Verifiers recompute the hash
/// from `agentCard` and check the JWS — this is byte-economical (no
/// duplicated card body) and aligns with the A2A 2026 spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedAgentCard {
    pub agent_card: AgentCard,
    /// JWS Compact Serialization over the canonical card hash.
    pub signature: String,
    /// Optional JWS protected header alg identifier echoed in plain text
    /// for callers that don't want to base64-decode `signature` just to
    /// know the algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Optional `iss` claim from the JWS protected header — the domain
    /// owner DID that signed the card (`did:web:tenzro.xyz` for the
    /// canonical Tenzro card).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

impl SignedAgentCard {
    /// Compute the canonical hash of an agent card. SHA-256 over the
    /// `serde_json::to_value` representation, sorted keys, no whitespace.
    /// The same algorithm runs on both producer and verifier so the JWS
    /// signature is over a stable digest regardless of which language
    /// implementation builds the card.
    pub fn canonical_card_hash(card: &AgentCard) -> [u8; 32] {
        let json = serde_json::to_value(card).unwrap_or(serde_json::Value::Null);
        let canonical = canonical_json(&json);
        let mut h = Sha256::new();
        h.update(b"tenzro/a2a/signed-agent-card/v1");
        h.update(canonical.as_bytes());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    /// Wrap an unsigned card with a caller-supplied JWS signature. The
    /// caller is responsible for producing the JWS — typically by hashing
    /// `canonical_card_hash(&card)` and signing it with the domain owner's
    /// key via the wallet/SDK.
    pub fn wrap(
        card: AgentCard,
        signature: String,
        algorithm: Option<String>,
        issuer: Option<String>,
    ) -> Self {
        Self {
            agent_card: card,
            signature,
            algorithm,
            issuer,
        }
    }
}

/// Canonical JSON serialization for hash stability. Sorted-keys, no
/// whitespace. Mirrors the `Ivms101Envelope::canonical_hash` algorithm
/// in `tenzro-identity` so the same canonicaliser is used across the
/// workspace.
fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-var-touching tests share a mutex because std::env is process-global.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_agent_card_serialization() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Ensure the env-var path doesn't bleed in from another test.
        unsafe { std::env::remove_var("TENZRO_A2A_PUBLIC_URL"); }
        let card = build_agent_card("0.0.0.0:3002", "Validator");
        let json = serde_json::to_string_pretty(&card).unwrap();

        // Verify key fields are present
        assert!(json.contains("\"name\""));
        assert!(json.contains("Tenzro Network Agent"));
        assert!(json.contains("\"url\""));
        assert!(json.contains("http://0.0.0.0:3002/a2a"));
        assert!(json.contains("\"protocolVersion\""));
        assert!(json.contains("\"skills\""));
        assert!(json.contains("\"capabilities\""));

        // Verify camelCase serialization
        assert!(json.contains("\"defaultInputModes\""));
        assert!(json.contains("\"pushNotifications\""));
        assert!(!json.contains("\"push_notifications\""));
    }

    #[test]
    fn test_agent_card_public_url_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // Bare host: should append /a2a
        unsafe { std::env::set_var("TENZRO_A2A_PUBLIC_URL", "https://a2a.tenzro.xyz"); }
        let card = build_agent_card("0.0.0.0:3002", "Validator");
        assert_eq!(card.url, "https://a2a.tenzro.xyz/a2a");

        // Trailing slash: should still work
        unsafe { std::env::set_var("TENZRO_A2A_PUBLIC_URL", "https://a2a.tenzro.xyz/"); }
        let card = build_agent_card("0.0.0.0:3002", "Validator");
        assert_eq!(card.url, "https://a2a.tenzro.xyz/a2a");

        // Full path: should NOT double-append
        unsafe { std::env::set_var("TENZRO_A2A_PUBLIC_URL", "https://a2a.tenzro.xyz/a2a"); }
        let card = build_agent_card("0.0.0.0:3002", "Validator");
        assert_eq!(card.url, "https://a2a.tenzro.xyz/a2a");

        // Empty / unset: falls back to listen address
        unsafe { std::env::set_var("TENZRO_A2A_PUBLIC_URL", ""); }
        let card = build_agent_card("0.0.0.0:3002", "Validator");
        assert_eq!(card.url, "http://0.0.0.0:3002/a2a");

        unsafe { std::env::remove_var("TENZRO_A2A_PUBLIC_URL"); }
        let card = build_agent_card("0.0.0.0:3002", "Validator");
        assert_eq!(card.url, "http://0.0.0.0:3002/a2a");
    }

    #[test]
    fn test_agent_card_has_all_skills() {
        let card = build_agent_card("localhost:3002", "LightClient");

        let skill_ids: Vec<&str> = card.skills.iter().map(|s| s.id.as_str()).collect();
        // Skill IDs must be unique — a duplicate id would shadow a skill in the
        // A2A registry. Assert de-dup rather than an exact count so adding a
        // skill doesn't require touching this test.
        let unique: std::collections::HashSet<&str> = skill_ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            skill_ids.len(),
            "duplicate skill id in agent card"
        );
        assert!(skill_ids.contains(&"wallet"));
        assert!(skill_ids.contains(&"identity"));
        assert!(skill_ids.contains(&"inference"));
        assert!(skill_ids.contains(&"settlement"));
        assert!(skill_ids.contains(&"verification"));
        assert!(skill_ids.contains(&"staking"));
        assert!(skill_ids.contains(&"task_marketplace"));
        assert!(skill_ids.contains(&"agent_marketplace"));
        assert!(skill_ids.contains(&"agent_spawning"));
        assert!(skill_ids.contains(&"swarm_orchestration"));
        assert!(skill_ids.contains(&"ap2-payments"));
        assert!(skill_ids.contains(&"join"));
        assert!(skill_ids.contains(&"token"));
        assert!(skill_ids.contains(&"contract"));
        assert!(skill_ids.contains(&"nft"));
        assert!(skill_ids.contains(&"bridge"));
        assert!(skill_ids.contains(&"compliance"));
        assert!(skill_ids.contains(&"crosschain"));
        assert!(skill_ids.contains(&"events"));
        assert!(skill_ids.contains(&"erc8004"));
        assert!(skill_ids.contains(&"wormhole"));
        assert!(skill_ids.contains(&"cct"));
        assert!(skill_ids.contains(&"cortex"));
        assert!(skill_ids.contains(&"capability_registry"));
        assert!(skill_ids.contains(&"adaptive-burn"));
        assert!(skill_ids.contains(&"seed-agent"));
        assert!(skill_ids.contains(&"erc7683"));
        assert!(skill_ids.contains(&"iroh-transport"));
        assert!(skill_ids.contains(&"media-gen"));
    }

    #[test]
    fn test_agent_card_roundtrip() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var("TENZRO_A2A_PUBLIC_URL"); }
        let card = build_agent_card("0.0.0.0:3002", "Validator");
        let json = serde_json::to_string(&card).unwrap();
        let parsed: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, card.name);
        assert_eq!(parsed.url, card.url);
        assert_eq!(parsed.skills.len(), card.skills.len());
    }

    #[test]
    fn canonical_card_hash_is_deterministic() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var("TENZRO_A2A_PUBLIC_URL"); }
        let card = build_agent_card("0.0.0.0:3002", "Validator");
        let h1 = SignedAgentCard::canonical_card_hash(&card);
        let h2 = SignedAgentCard::canonical_card_hash(&card);
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_card_hash_changes_with_url() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var("TENZRO_A2A_PUBLIC_URL"); }
        let card_a = build_agent_card("0.0.0.0:3002", "Validator");
        let mut card_b = card_a.clone();
        card_b.url = "https://attacker.example/a2a".to_string();
        assert_ne!(
            SignedAgentCard::canonical_card_hash(&card_a),
            SignedAgentCard::canonical_card_hash(&card_b),
            "rewritten URL must change the canonical hash"
        );
    }

    #[test]
    fn signed_agent_card_wraps_and_roundtrips() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var("TENZRO_A2A_PUBLIC_URL"); }
        let card = build_agent_card("0.0.0.0:3002", "Validator");
        let signed = SignedAgentCard::wrap(
            card.clone(),
            "eyJhbGciOiJFZERTQSJ9.eyJoYXNoIjoiMHhkZWFkYmVlZiJ9.fake-sig".to_string(),
            Some("EdDSA".to_string()),
            Some("did:web:tenzro.xyz".to_string()),
        );
        let json = serde_json::to_string(&signed).unwrap();
        let parsed: SignedAgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_card.name, card.name);
        assert_eq!(parsed.algorithm.as_deref(), Some("EdDSA"));
        assert_eq!(parsed.issuer.as_deref(), Some("did:web:tenzro.xyz"));
        assert!(parsed.signature.starts_with("eyJhbGciOiJFZERTQSJ9."));
    }
}
