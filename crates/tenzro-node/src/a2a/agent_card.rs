//! Agent Card — A2A 1.0 discovery at `/.well-known/agent-card.json`.
//!
//! The card is served with a detached JWS in its `signatures` array. The JWS
//! payload is the RFC 8785 canonical form of the card with `signatures`
//! removed, so a reverse proxy or cache that rewrites the interface URL, the
//! skills or the extensions invalidates the signature. The key that signs is
//! the node operator's wallet key, reached through the wallet service's
//! bound signer: the wallet service holds no private key of its own, so the
//! signature is produced by the hardware custody that wallet is bound to.
//! A node with no operator identity or no bound signer serves the card
//! without `signatures` rather than with a placeholder.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use tenzro_trust::jcs;

/// A2A protocol version this node speaks, in `Major.Minor` form.
pub const A2A_PROTOCOL_VERSION: &str = "1.0";

/// Well-known path the agent card is served at.
pub const WELL_KNOWN_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";

/// Extension URI for the Tenzro DID envelope that every mutating request
/// must carry. Declared `required` in the card so a client that does not
/// implement it learns so before its first request is refused.
pub const DID_ENVELOPE_EXTENSION_URI: &str = "https://tenzro.com/a2a/extensions/did-envelope";

/// A2A 1.0 Agent Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// Agent name
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Endpoints and the protocol binding each one speaks.
    pub supported_interfaces: Vec<AgentInterface>,
    /// Agent version
    pub version: String,
    /// Agent capabilities
    pub capabilities: AgentCapabilities,
    /// Default input content types
    pub default_input_modes: Vec<String>,
    /// Default output content types
    pub default_output_modes: Vec<String>,
    /// Skills this agent provides
    pub skills: Vec<AgentSkill>,
    /// Detached JWS signatures over the canonical card.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub signatures: Vec<AgentCardSignature>,
}

/// One endpoint of the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    /// Endpoint URL.
    pub url: String,
    /// Binding spoken at `url`: `JSONRPC`, `GRPC` or `HTTP+JSON`.
    pub protocol_binding: String,
    /// A2A version served at `url`.
    pub protocol_version: String,
}

/// Capabilities the agent supports
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// Whether `SendStreamingMessage` is served.
    pub streaming: bool,
    /// Whether push-notification configuration is served.
    pub push_notifications: bool,
    /// Protocol extensions this agent implements.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub extensions: Vec<AgentExtension>,
}

/// A protocol extension the agent implements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExtension {
    /// Extension identifier.
    pub uri: String,
    /// What the extension adds.
    pub description: String,
    /// Whether a client must implement it to be served.
    pub required: bool,
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

/// One detached JWS over the canonical card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCardSignature {
    /// Base64url JWS protected header.
    pub protected: String,
    /// Base64url signature value.
    pub signature: String,
}

/// Where peers reach this node's A2A endpoint: the URL the operator published
/// for their own edge (`external_a2a_addr`), else the node's machine identity
/// over the `tenzro/a2a` iroh ALPN, else nowhere. Never the listen address,
/// which is loopback and names nothing a peer can dial.
pub fn card_url(config: &crate::config::NodeConfig) -> Option<String> {
    crate::exposure::a2a_url(config).or_else(|| {
        crate::identity_bootstrap::machine_did().map(|did| format!("tenzro://did/{did}"))
    })
}

/// Build an Agent Card advertising `url` as its one interface; with no URL
/// the card lists no interface.
pub fn build_agent_card(url: Option<String>, node_role: &str) -> AgentCard {
    AgentCard {
        name: "Tenzro Network Agent".to_string(),
        description: format!(
            "Tenzro Network node ({}) — AI-native agentic tokenized settlement layer. \
             Provides wallet operations, identity management, inference routing, \
             settlement, and blockchain interaction.",
            node_role
        ),
        supported_interfaces: url
            .into_iter()
            .map(|url| AgentInterface {
                url,
                protocol_binding: "JSONRPC".to_string(),
                protocol_version: A2A_PROTOCOL_VERSION.to_string(),
            })
            .collect(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: AgentCapabilities {
            streaming: true,
            push_notifications: false,
            extensions: vec![AgentExtension {
                uri: DID_ENVELOPE_EXTENSION_URI.to_string(),
                description: "SendMessage, SendStreamingMessage and CancelTask carry a \
                              signature by the sender DID's wallet key over the method, \
                              task id, nonce, timestamp and the SHA-256 of the RFC 8785 \
                              canonical request params, in the tenzro.a2a.envelope.* \
                              metadata keys."
                    .to_string(),
                required: true,
            }],
        },
        default_input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
        default_output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
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
                              on the Tenzro Decentralized Identity Protocol (TDIP)."
                    .to_string(),
                tags: vec![
                    "identity".to_string(),
                    "did".to_string(),
                    "credentials".to_string(),
                ],
                examples: vec![
                    "Register a new identity".to_string(),
                    "Resolve DID did:tenzro:human:abc123".to_string(),
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
                              and query provider performance statistics. Provider registration \
                              is gated on a compute bond — admission collateral held in a vault \
                              derived from the provider DID — so the provider view also reports \
                              the node's minimum bond and withdrawal cooldown."
                    .to_string(),
                tags: vec![
                    "staking".to_string(),
                    "provider".to_string(),
                    "validator".to_string(),
                    "compute-bond".to_string(),
                ],
                examples: vec![
                    "How much TNZO is staked?".to_string(),
                    "Register as a model provider".to_string(),
                    "Get provider statistics".to_string(),
                    "What compute bond does this node require?".to_string(),
                ],
                input_modes: vec!["text/plain".to_string()],
                output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            },
            AgentSkill {
                id: "token".to_string(),
                name: "Token Management".to_string(),
                description: "Query token info and balances across VMs. Every VM reads \
                              the same balance of a token; moving it, in one VM or across \
                              several, is a signed contract-call transaction. Creating, minting \
                              and the issuer's compliance controls are a signed Token \
                              transaction."
                    .to_string(),
                tags: vec![
                    "token".to_string(),
                    "erc20".to_string(),
                    "cross-vm".to_string(),
                    "registry".to_string(),
                ],
                examples: vec![
                    "Get token info for TNZO".to_string(),
                    "List all registered tokens".to_string(),
                    "Get my TNZO balance across all VMs".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "contract".to_string(),
                name: "Smart Contract Deployment".to_string(),
                description: "How to deploy EVM contracts to Tenzro. Deployment itself \
                              is a signed ContractDeploy transaction submitted with \
                              tenzro_deployContract."
                    .to_string(),
                tags: vec![
                    "contract".to_string(),
                    "deploy".to_string(),
                    "evm".to_string(),
                    "svm".to_string(),
                ],
                examples: vec!["What VMs are supported for contract deployment?".to_string()],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string()],
            },
            AgentSkill {
                id: "join".to_string(),
                name: "Join as MicroNode".to_string(),
                description: "Join the Tenzro Network as a full MicroNode participant — \
                              zero-install. Auto-provisions a TDIP DID, permissionless wallet, and \
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
                id: "bridge".to_string(),
                name: "Cross-Chain Bridge".to_string(),
                description: "Move TNZO between Tenzro and external chains over governed \
                              routes: a CCIP-compatible envelope for Ethereum, Base, Arbitrum \
                              and Solana, IBC for Cosmos chains, Bitcoin deposits and contract \
                              routes to Stellar, Sui, Aptos and TON. Every route enforces \
                              committee attestations, caps, a circuit breaker and the supply \
                              invariant."
                    .to_string(),
                tags: vec![
                    "bridge".to_string(),
                    "cross-chain".to_string(),
                    "ccip".to_string(),
                ],
                examples: vec![
                    "List the governed bridge routes".to_string(),
                    "Show the route to base with its caps and supply".to_string(),
                    "Send 100 TNZO to a recipient on ethereum".to_string(),
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
                id: "events".to_string(),
                name: "Event Streaming".to_string(),
                description: "The chain's certified events from a cursor, gap-free across restarts. \
                              Send a data part {operation: \"readEvents\", filter, from_cursor} and \
                              keep the returned cursor; the answer carries each event's proof and \
                              the proof that the range left nothing out."
                    .to_string(),
                tags: vec![
                    "events".to_string(),
                    "streaming".to_string(),
                    "proofs".to_string(),
                    "webhooks".to_string(),
                ],
                examples: vec![
                    "Read the logs of contract 0xabc... after cursor 1200:0:0".to_string(),
                    "Register a webhook for transfer events on 0xabc...".to_string(),
                    "Query historical events for contract 0xdef... with proofs".to_string(),
                ],
                input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
                output_modes: vec!["application/json".to_string(), "text/event-stream".to_string()],
            },
            AgentSkill {
                id: "adaptive-burn".to_string(),
                name: "Adaptive Burn-Rate Governance Dial".to_string(),
                description:
                    "Read-side surface for the adaptive burn-rate dial. Exposes the \
                     current BurnRateConfig (base / local burn bps with treasury \
                     complements), the latest \
                     SupplyMetricsSnapshot (rolling-window epoch delta, burn breakdown, \
                     supply added: always 0, TNZO supply is fixed at genesis), and the \
                     pure-function BurnRateRecommendation (NoChange / \
                     IncreaseBurnPct / DecreaseBurnPct / AlarmHighInflation (a fault) / \
                     AlarmHighDeflation with magnitude bps capped at the normal / alarm \
                     ceiling). The dial moves only via on-chain governance votes: every \
                     validator's auto-proposal generator drafts an AdaptiveBurnConfigUpdate \
                     proposal from the supply metrics (expedited on an alarm), and once \
                     enacted, block fee settlement burns that share of the base fee and \
                     credits the rest to the treasury."
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
                id: "bridge-fee-in-tnzo".to_string(),
                name: "Bridge Fee in TNZO".to_string(),
                description: "Pay cross-chain bridge fees in TNZO instead of destination-chain \
                              gas."
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
                              status."
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
                description: "Rent compute with a stream escrow to the provider's bonded \
                              address: it pays the provider by the epoch until its expiry, the \
                              provider's compute bond is its SLA collateral, and an epoch \
                              validators judged unavailable is paid back to the renter from the \
                              insurance pool."
                    .to_string(),
                tags: vec![
                    "compute".to_string(),
                    "rental".to_string(),
                    "escrow".to_string(),
                    "sla".to_string(),
                    "provider".to_string(),
                ],
                examples: vec![
                    "Open a stream escrow renting one GPU over 24 epochs".to_string(),
                    "Read a provider's SLA verdict for an epoch".to_string(),
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
                description: "Generative image, video and audio. Read the media catalog and \
                              render one seeded output on this node or a provider serving \
                              the model, with a signed receipt that commits to the rendered \
                              bytes and their perceptual fingerprint."
                    .to_string(),
                tags: vec![
                    "media-gen".to_string(),
                    "image".to_string(),
                    "video".to_string(),
                    "diffusion".to_string(),
                ],
                examples: vec![
                    "List the generative-media catalog".to_string(),
                    "Render a 1024x1024 image from a prompt with seed 7".to_string(),
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
        signatures: Vec::new(),
    }
}

/// Why a card signature did not verify, or why a card could not be signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CardSignatureError {
    /// The card JSON is not an object.
    #[error("agent card is not a JSON object")]
    NotAnObject,
    /// The card carries no `signatures` entries.
    #[error("agent card carries no signatures")]
    Unsigned,
    /// The card has no canonical form.
    #[error("agent card has no canonical form: {0}")]
    Canonical(String),
    /// A signature entry is malformed or uses an algorithm this node does
    /// not verify.
    #[error("signature {index}: {reason}")]
    Malformed { index: usize, reason: String },
    /// A signature entry is well formed but does not verify.
    #[error("signature {index} does not verify over the canonical card")]
    Invalid { index: usize },
    /// The node cannot produce a signature.
    #[error("card cannot be signed: {0}")]
    Signing(String),
}

/// A signature that verified, and the key it verified under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedCardSignature {
    /// JWS `alg`.
    pub alg: String,
    /// JWS `kid`: the DID whose key signed.
    pub kid: String,
    /// P-256 public key (`x || y`) the signature verified under, hex.
    pub public_key_hex: String,
}

/// RFC 8785 canonical bytes of a card with its `signatures` removed. This is
/// the JWS payload every signature on the card covers.
pub fn canonical_payload(card: &Value) -> Result<String, CardSignatureError> {
    let mut unsigned = card.clone();
    unsigned
        .as_object_mut()
        .ok_or(CardSignatureError::NotAnObject)?
        .remove("signatures");
    jcs::canonicalize(&unsigned).map_err(|e| CardSignatureError::Canonical(e.to_string()))
}

/// SHA-256 of [`canonical_payload`].
pub fn canonical_payload_sha256(card: &Value) -> Result<[u8; 32], CardSignatureError> {
    Ok(Sha256::digest(canonical_payload(card)?.as_bytes()).into())
}

/// JWS signing input (`BASE64URL(protected) || '.' || BASE64URL(payload)`)
/// for a protected header over `card`.
fn signing_input(protected_b64: &str, card: &Value) -> Result<String, CardSignatureError> {
    let payload = canonical_payload(card)?;
    Ok(format!(
        "{}.{}",
        protected_b64,
        URL_SAFE_NO_PAD.encode(payload.as_bytes())
    ))
}

/// Protected header for an ES256 signature by `kid`. The P-256 public key
/// (`x || y`) rides in `jwk` so a relying party can check the signature
/// without a key lookup and then check separately that `kid` resolves to
/// that key.
fn es256_protected_header(kid: &str, public_key: &[u8]) -> String {
    let (x, y) = public_key.split_at(32);
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JOSE",
        "kid": kid,
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        },
    });
    let canonical = jcs::canonicalize(&header).expect("header holds only strings");
    URL_SAFE_NO_PAD.encode(canonical.as_bytes())
}

/// Verify every signature on `card`. Succeeds only when the card carries at
/// least one signature and all of them verify over the canonical card.
pub fn verify_agent_card(card: &Value) -> Result<Vec<VerifiedCardSignature>, CardSignatureError> {
    let signatures: Vec<AgentCardSignature> = match card
        .as_object()
        .ok_or(CardSignatureError::NotAnObject)?
        .get("signatures")
    {
        None => return Err(CardSignatureError::Unsigned),
        Some(v) => {
            serde_json::from_value(v.clone()).map_err(|e| CardSignatureError::Malformed {
                index: 0,
                reason: format!("signatures array: {e}"),
            })?
        }
    };
    if signatures.is_empty() {
        return Err(CardSignatureError::Unsigned);
    }

    let mut verified = Vec::with_capacity(signatures.len());
    for (index, sig) in signatures.iter().enumerate() {
        let malformed = |reason: String| CardSignatureError::Malformed { index, reason };
        let header_bytes = URL_SAFE_NO_PAD
            .decode(&sig.protected)
            .map_err(|e| malformed(format!("protected header base64url: {e}")))?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| malformed(format!("protected header JSON: {e}")))?;
        let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
        if alg != "ES256" {
            return Err(malformed(format!("unsupported alg '{alg}'")));
        }
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("protected header has no kid".to_string()))?;
        let jwk = header
            .get("jwk")
            .ok_or_else(|| malformed("protected header has no jwk".to_string()))?;
        if jwk.get("kty").and_then(Value::as_str) != Some("EC")
            || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        {
            return Err(malformed("jwk is not a P-256 EC key".to_string()));
        }
        let coord = |name: &str| -> Result<Vec<u8>, CardSignatureError> {
            let c = URL_SAFE_NO_PAD
                .decode(
                    jwk.get(name)
                        .and_then(Value::as_str)
                        .ok_or_else(|| malformed(format!("jwk has no {name}")))?,
                )
                .map_err(|e| malformed(format!("jwk {name} base64url: {e}")))?;
            if c.len() != 32 {
                return Err(malformed(format!("jwk {name} is not 32 bytes")));
            }
            Ok(c)
        };
        let pk_bytes = [coord("x")?, coord("y")?].concat();
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(&sig.signature)
            .map_err(|e| malformed(format!("signature base64url: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(malformed("signature is not 64 bytes".to_string()));
        }
        let key = tenzro_crypto::p256::P256Verifier::from_public_key_bytes(&pk_bytes)
            .map_err(|e| malformed(format!("jwk is not a P-256 point: {e}")))?;
        let signature = tenzro_crypto::p256::P256Signature::from_slice(&sig_bytes)
            .map_err(|e| malformed(format!("signature: {e}")))?;
        let input = signing_input(&sig.protected, card)?;
        let digest: [u8; 32] = Sha256::digest(input.as_bytes()).into();
        key.verify_prehash(&digest, &signature)
            .map_err(|_| CardSignatureError::Invalid { index })?;

        verified.push(VerifiedCardSignature {
            alg: alg.to_string(),
            kid: kid.to_string(),
            public_key_hex: hex::encode(pk_bytes),
        });
    }
    Ok(verified)
}

/// Sign `card` with the node operator's wallet key.
///
/// The wallet service signs only through the signer bound to the wallet, so
/// the private key stays in whatever hardware custody backs the operator's
/// wallet. The signed card is verified before it is returned, so a signer
/// that does not produce a plain ES256 signature over the input yields an error
/// here rather than a card relying parties reject.
pub(crate) async fn sign_with_operator_wallet(
    node: &crate::node::TenzroNode,
    card: &AgentCard,
) -> Result<AgentCard, CardSignatureError> {
    use tenzro_wallet::{WalletId, WalletService};

    let signing = |m: &str| CardSignatureError::Signing(m.to_string());
    let did = node
        .operator_did()
        .ok_or_else(|| signing("this node has no provisioned operator identity"))?;
    let registry = node
        .identity_registry()
        .ok_or_else(|| signing("identity registry not initialized"))?;
    let wallet_id = registry
        .find_wallet_id_for_did(&did)
        .map_err(|e| signing(&format!("no wallet for operator DID {did}: {e}")))?;
    let wallets = node
        .wallet_service()
        .ok_or_else(|| signing("wallet service not initialized"))?;
    let wid = WalletId::from_string(wallet_id);
    let wallet = wallets
        .get_wallet(&wid)
        .await
        .map_err(|e| signing(&format!("wallet lookup: {e}")))?
        .ok_or_else(|| signing("operator wallet not found"))?;
    let public_key = wallet.public_key.p256.clone();

    let mut unsigned = card.clone();
    unsigned.signatures.clear();
    let card_value =
        serde_json::to_value(&unsigned).map_err(|e| signing(&format!("card encode: {e}")))?;
    let protected = es256_protected_header(&did, &public_key);
    let input = signing_input(&protected, &card_value)?;
    // A JWS verifier checks a plain ES256 signature over the signing input.
    let classical = wallets
        .sign_external(&wid, input.as_bytes())
        .await
        .map_err(|e| signing(&format!("operator wallet signer: {e}")))?;

    unsigned.signatures.push(AgentCardSignature {
        protected,
        signature: URL_SAFE_NO_PAD.encode(&classical),
    });
    let signed_value =
        serde_json::to_value(&unsigned).map_err(|e| signing(&format!("card encode: {e}")))?;
    verify_agent_card(&signed_value)?;
    Ok(unsigned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::HybridSigner as _;
    use tenzro_crypto::testing::TestHybridSigner;

    const PUBLISHED: &str = "https://agents.example.org/a2a";

    fn published() -> Option<String> {
        Some(PUBLISHED.to_string())
    }

    #[test]
    fn test_agent_card_serialization() {
        let card = build_agent_card(published(), "Validator");
        let json = serde_json::to_string_pretty(&card).unwrap();

        // Verify key fields are present
        assert!(json.contains("\"name\""));
        assert!(json.contains("Tenzro Network Agent"));
        assert!(json.contains("\"url\""));
        assert!(json.contains(PUBLISHED));
        assert!(json.contains("\"skills\""));
        assert!(json.contains("\"capabilities\""));

        // Verify camelCase serialization
        assert!(json.contains("\"defaultInputModes\""));
        assert!(json.contains("\"pushNotifications\""));
        assert!(!json.contains("\"push_notifications\""));

        let value = serde_json::to_value(&card).unwrap();
        let iface = &value["supportedInterfaces"][0];
        assert_eq!(iface["protocolBinding"], "JSONRPC");
        assert_eq!(iface["protocolVersion"], "1.0");
        assert_eq!(
            value["capabilities"]["extensions"][0]["uri"],
            DID_ENVELOPE_EXTENSION_URI
        );
        assert_eq!(value["capabilities"]["extensions"][0]["required"], true);
        // An unsigned card carries no `signatures` member at all.
        assert!(value.get("signatures").is_none());
        // Every skill carries `tags`, which A2A 1.0 requires.
        for skill in value["skills"].as_array().unwrap() {
            assert!(skill.get("tags").is_some(), "skill without tags: {skill}");
        }
    }

    #[test]
    fn the_card_url_is_the_published_one_or_the_identity_never_the_listen_address() {
        let mut config = crate::config::NodeConfig::default_validator();
        config.external_a2a_addr = Some("https://agents.example.org".to_string());
        assert_eq!(card_url(&config).as_deref(), Some(PUBLISHED));

        config.external_a2a_addr = None;
        match card_url(&config) {
            Some(url) => assert!(url.starts_with("tenzro://did/did:tenzro:machine:"), "{url}"),
            None => assert!(crate::identity_bootstrap::machine_did().is_none()),
        }

        let card = build_agent_card(None, "Validator");
        assert!(card.supported_interfaces.is_empty(), "no URL, no interface");
        let json = serde_json::to_string(&card).unwrap();
        assert!(
            !json.contains(&config.a2a_addr),
            "the listen address is never advertised"
        );
    }

    #[test]
    fn test_agent_card_has_all_skills() {
        let card = build_agent_card(published(), "LightClient");

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
        assert!(skill_ids.contains(&"join"));
        assert!(skill_ids.contains(&"token"));
        assert!(skill_ids.contains(&"contract"));
        assert!(skill_ids.contains(&"bridge"));
        assert!(skill_ids.contains(&"compliance"));
        assert!(skill_ids.contains(&"events"));
        assert!(skill_ids.contains(&"adaptive-burn"));
        assert!(skill_ids.contains(&"iroh-transport"));
        assert!(skill_ids.contains(&"media-gen"));
    }

    #[test]
    fn test_agent_card_roundtrip() {
        let card = build_agent_card(published(), "Validator");
        let json = serde_json::to_string(&card).unwrap();
        let parsed: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, card.name);
        assert_eq!(
            parsed.supported_interfaces[0].url,
            card.supported_interfaces[0].url
        );
        assert_eq!(parsed.skills.len(), card.skills.len());
    }

    const KID: &str = "did:tenzro:machine:card-test";

    fn fixed_card() -> AgentCard {
        build_agent_card(published(), "Validator")
    }

    /// Sign the way `sign_with_operator_wallet` does, with a software key
    /// standing in for the wallet's bound signer.
    fn sign_card(card: &AgentCard, key: &TestHybridSigner) -> Value {
        let mut unsigned = card.clone();
        unsigned.signatures.clear();
        let value = serde_json::to_value(&unsigned).unwrap();
        let protected = es256_protected_header(KID, &key.public_key().p256);
        let input = signing_input(&protected, &value).unwrap();
        let sig = key.sign_external(input.as_bytes()).unwrap();
        unsigned.signatures.push(AgentCardSignature {
            protected,
            signature: URL_SAFE_NO_PAD.encode(sig),
        });
        serde_json::to_value(&unsigned).unwrap()
    }

    fn key(seed: u8) -> TestHybridSigner {
        TestHybridSigner::p256_only(seed)
    }

    #[test]
    fn signed_card_verifies_and_reports_the_signing_key() {
        let k = key(7);
        let signed = sign_card(&fixed_card(), &k);
        let verified = verify_agent_card(&signed).unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].alg, "ES256");
        assert_eq!(verified[0].kid, KID);
        assert_eq!(
            verified[0].public_key_hex,
            hex::encode(&k.public_key().p256)
        );
    }

    #[test]
    fn verification_is_over_the_canonical_form_not_the_wire_bytes() {
        let signed = sign_card(&fixed_card(), &key(7));
        // Pretty-printing reorders nothing semantically; the canonical form
        // is what the signature covers, so it still verifies.
        let pretty = serde_json::to_string_pretty(&signed).unwrap();
        let reparsed: Value = serde_json::from_str(&pretty).unwrap();
        assert!(verify_agent_card(&reparsed).is_ok());
    }

    #[test]
    fn rewritten_interface_url_breaks_the_signature() {
        let mut signed = sign_card(&fixed_card(), &key(7));
        signed["supportedInterfaces"][0]["url"] = Value::from("https://attacker.example/a2a");
        assert_eq!(
            verify_agent_card(&signed),
            Err(CardSignatureError::Invalid { index: 0 })
        );
    }

    #[test]
    fn stripped_extension_breaks_the_signature() {
        let mut signed = sign_card(&fixed_card(), &key(7));
        signed["capabilities"]["extensions"] = Value::Array(vec![]);
        assert_eq!(
            verify_agent_card(&signed),
            Err(CardSignatureError::Invalid { index: 0 })
        );
    }

    #[test]
    fn signature_by_another_key_under_the_claimed_jwk_is_rejected() {
        let card = fixed_card();
        let honest = sign_card(&card, &key(7));
        let forged = sign_card(&card, &key(9));
        // Keep the honest header (and so the honest jwk) but splice in a
        // signature made by a different key.
        let mut spliced = honest.clone();
        spliced["signatures"][0]["signature"] = forged["signatures"][0]["signature"].clone();
        assert_eq!(
            verify_agent_card(&spliced),
            Err(CardSignatureError::Invalid { index: 0 })
        );
    }

    #[test]
    fn unsigned_card_does_not_verify() {
        let value = serde_json::to_value(fixed_card()).unwrap();
        assert_eq!(verify_agent_card(&value), Err(CardSignatureError::Unsigned));
        let mut empty = value.clone();
        empty["signatures"] = Value::Array(vec![]);
        assert_eq!(verify_agent_card(&empty), Err(CardSignatureError::Unsigned));
    }

    #[test]
    fn alg_none_is_rejected() {
        let mut signed = sign_card(&fixed_card(), &key(7));
        let header = serde_json::json!({"alg": "none", "kid": KID});
        signed["signatures"][0]["protected"] =
            Value::from(URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()));
        assert!(matches!(
            verify_agent_card(&signed),
            Err(CardSignatureError::Malformed { index: 0, .. })
        ));
    }

    #[test]
    fn canonical_payload_ignores_the_signatures_member() {
        let card = fixed_card();
        let unsigned = serde_json::to_value(&card).unwrap();
        let signed = sign_card(&card, &key(7));
        assert_eq!(
            canonical_payload_sha256(&unsigned).unwrap(),
            canonical_payload_sha256(&signed).unwrap()
        );
    }
}
