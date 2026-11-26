//! Agent Card — A2A 1.0 discovery at `/.well-known/agent-card.json`.
//!
//! The card is served with a detached JWS in its `signatures` array. The JWS
//! payload is the RFC 8785 canonical form of the card with `signatures`
//! removed, so a reverse proxy or cache that rewrites the interface URL, the
//! skills or the extensions invalidates the signature. The key that signs is
//! the machine's identity key in its TPM or Secure Enclave, the key its
//! machine DID derives from, so the card needs no wallet or operator account
//! on the node. A node whose key cannot sign answers 503 rather than serving
//! an unsigned card.
//!
//! The signature says who published the card. What the card may claim is
//! decided here: a skill that needs something of the node (a role it serves,
//! which it holds the bond for; a build that can run models; a bound iroh
//! endpoint) is listed only while the node has it ([`Served`]).

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

/// Extension URI for the Tenzro DID envelope that every task request must
/// carry. Declared `required` in the card so a client that does not
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
/// What a node serves at the moment its card is built. A skill is listed
/// only when what it needs is here, so a node that follows the chain and
/// nothing else does not advertise inference, storage or compute.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Served {
    /// The node serves models: it holds the role (and so its bond) and this
    /// build can run them.
    pub models: bool,
    /// The node serves storage.
    pub storage: bool,
    /// The node rents compute.
    pub compute: bool,
    /// The node's iroh endpoint is bound, so `tenzro/a2a` is reachable.
    pub iroh: bool,
}

impl Served {
    /// Everything: the card of a node that serves every role.
    pub const ALL: Self = Self {
        models: true,
        storage: true,
        compute: true,
        iroh: true,
    };

    /// What `node` serves now. The roles are the ones it runs with, which a
    /// node holds only while it holds their bonds.
    pub fn of(node: &crate::node::TenzroNode) -> Self {
        let roles = node.runtime_roles.read().clone();
        Self {
            models: cfg!(feature = "inference") && roles.serves_ai(),
            storage: roles.serves_storage(),
            compute: roles.serves_compute(),
            iroh: node.iroh_resolver().is_some(),
        }
    }

    /// Whether the skill with `id` may be listed. A skill that reads the
    /// chain or submits what its caller signed needs nothing of the node.
    fn lists(&self, id: &str) -> bool {
        match id {
            "inference" | "moe" | "media-gen" => self.models,
            "storage" => self.storage,
            "compute" => self.compute,
            "iroh-transport" => self.iroh,
            _ => true,
        }
    }
}

/// The card of a node with `node_role` that serves `served`.
pub fn build_agent_card(url: Option<String>, node_role: &str, served: Served) -> AgentCard {
    let mut card = full_agent_card(url, node_role);
    card.skills.retain(|skill| served.lists(&skill.id));
    card
}

/// The card with every skill a node can have.
fn full_agent_card(url: Option<String>, node_role: &str) -> AgentCard {
    AgentCard {
        name: "Tenzro Network Agent".to_string(),
        description: format!(
            "Tenzro Network node ({}) — compute of every kind for the machine economy. \
             Provides wallet operations, identity management, inference routing, \
             storage and compute rental, settlement, and ledger interaction.",
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
                description: "SendMessage, SendStreamingMessage, CancelTask, GetTask and \
                              ListTasks carry a signature by the sender DID's wallet key \
                              over the method, task id, nonce, timestamp and the SHA-256 \
                              of the RFC 8785 canonical request params, in the \
                              tenzro.a2a.envelope.* metadata keys. A task is shown only \
                              to the DID that opened it."
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
                description: "Provision a TDIP DID and a wallet bound to a key the caller \
                              holds, so the identity can pay for and call the network's \
                              services. It runs no node and takes no part in consensus."
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
                     supply added: always 0, TNZO supply is fixed at genesis). The dial \
                     moves only via on-chain governance votes: every \
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
                name: "Storage".to_string(),
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
                description: "Mixture-of-experts expert-shard serving across holders. Read the \
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
    /// A signature verifies, but under a key that is not the hardware key of
    /// the machine its `kid` names.
    #[error("signature {index}: its key is not the hardware key of {kid}")]
    NotTheKidsKey { index: usize, kid: String },
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
pub(crate) fn es256_protected_header(kid: &str, public_key: &[u8]) -> String {
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

/// Verify one ES256 JWS: `protected` (base64url header carrying `kid` and a
/// P-256 `jwk`), `signature` (base64url `r || s`) over `input`, the JWS
/// signing input. Returns the algorithm, the `kid` and the key (`x || y`).
/// `Err(Some(reason))` for a malformed JWS, `Err(None)` for a well-formed
/// signature that does not verify.
pub(crate) fn verify_es256_jws(
    protected: &str,
    signature: &str,
    input: &str,
) -> Result<(String, String, Vec<u8>), Option<String>> {
    let malformed = |reason: String| Some(reason);
    let header_bytes = URL_SAFE_NO_PAD
        .decode(protected)
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
    let coord = |name: &str| -> Result<Vec<u8>, Option<String>> {
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
        .decode(signature)
        .map_err(|e| malformed(format!("signature base64url: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(malformed("signature is not 64 bytes".to_string()));
    }
    let key = tenzro_crypto::p256::P256Verifier::from_public_key_bytes(&pk_bytes)
        .map_err(|e| malformed(format!("jwk is not a P-256 point: {e}")))?;
    let sig = tenzro_crypto::p256::P256Signature::from_slice(&sig_bytes)
        .map_err(|e| malformed(format!("signature: {e}")))?;
    let digest: [u8; 32] = Sha256::digest(input.as_bytes()).into();
    key.verify_prehash(&digest, &sig).map_err(|_| None)?;
    Ok((alg.to_string(), kid.to_string(), pk_bytes))
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
        let input = signing_input(&sig.protected, card)?;
        let (alg, kid, pk_bytes) = verify_es256_jws(&sig.protected, &sig.signature, &input)
            .map_err(|e| match e {
                Some(reason) => CardSignatureError::Malformed { index, reason },
                None => CardSignatureError::Invalid { index },
            })?;
        // A machine DID derives from its hardware key, the key its DID
        // Document lists under `#hardware-key`: the key must be the one the
        // `kid` names, not merely the one the header carries.
        let sec1 = [&[0x04][..], &pk_bytes].concat();
        let did = tenzro_types::did_derivation::machine_did(&sec1);
        if kid != format!("{did}{}", crate::node_did_document::HARDWARE_KEY_FRAGMENT) {
            return Err(CardSignatureError::NotTheKidsKey {
                index,
                kid: kid.to_string(),
            });
        }

        verified.push(VerifiedCardSignature {
            alg: alg.to_string(),
            kid: kid.to_string(),
            public_key_hex: hex::encode(pk_bytes),
        });
    }
    Ok(verified)
}

/// Sign `card` with this machine's identity key, the P-256 key in its TPM or
/// Secure Enclave that its machine DID derives from.
///
/// The `kid` is `<machine DID>#hardware-key`, the method the node's DID
/// Document lists for that key, and the protected header carries the key as
/// a `jwk`; since the DID derives from the key, a relying party checks the
/// binding without trusting this node. The signed card is verified before it
/// is returned, so a signer that does not produce a plain ES256 signature over
/// the input yields an error here rather than a card relying parties reject.
pub(crate) fn sign_with_machine_key(
    signer: &dyn tenzro_device_key::signer::HardwareSigner,
    card: &AgentCard,
) -> Result<AgentCard, CardSignatureError> {
    let signing = |m: &str| CardSignatureError::Signing(m.to_string());
    let sec1 = signer
        .public_key_sec1()
        .map_err(|e| signing(&format!("machine key: {e}")))?;
    let did = tenzro_types::did_derivation::machine_did(&sec1);
    let kid = format!("{did}{}", crate::node_did_document::HARDWARE_KEY_FRAGMENT);

    let mut unsigned = card.clone();
    unsigned.signatures.clear();
    let card_value =
        serde_json::to_value(&unsigned).map_err(|e| signing(&format!("card encode: {e}")))?;
    let protected = es256_protected_header(&kid, &sec1[1..]);
    let input = signing_input(&protected, &card_value)?;
    let digest: [u8; 32] = Sha256::digest(input.as_bytes()).into();
    let signature = signer
        .sign_prehash(&digest)
        .map_err(|e| signing(&format!("machine key signer: {e}")))?;

    unsigned.signatures.push(AgentCardSignature {
        protected,
        signature: URL_SAFE_NO_PAD.encode(signature),
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
        let card = build_agent_card(published(), "Validator", Served::ALL);
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

        let card = build_agent_card(None, "Validator", Served::ALL);
        assert!(card.supported_interfaces.is_empty(), "no URL, no interface");
        let json = serde_json::to_string(&card).unwrap();
        assert!(
            !json.contains(&config.a2a_addr),
            "the listen address is never advertised"
        );
    }

    #[test]
    fn test_agent_card_has_all_skills() {
        let card = build_agent_card(published(), "LightClient", Served::ALL);

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

    /// A skill that needs a role, a model-running build or the iroh
    /// endpoint is listed only on a node that has it; the rest always are.
    #[test]
    fn a_skill_is_listed_only_when_the_node_serves_what_it_needs() {
        let ids = |served: Served| -> Vec<String> {
            build_agent_card(published(), "Validator", served)
                .skills
                .into_iter()
                .map(|s| s.id)
                .collect()
        };
        let all = ids(Served::ALL);
        let none = ids(Served::default());
        let gated = [
            "inference",
            "moe",
            "media-gen",
            "storage",
            "compute",
            "iroh-transport",
        ];
        for id in gated {
            assert!(all.iter().any(|s| s == id), "{id} on a node that serves it");
            assert!(
                !none.iter().any(|s| s == id),
                "{id} on a node that does not"
            );
        }
        assert_eq!(none.len() + gated.len(), all.len());
        for id in ["wallet", "identity", "verification", "events", "join"] {
            assert!(
                none.iter().any(|s| s == id),
                "{id} needs nothing of the node"
            );
        }

        let models_only = ids(Served {
            models: true,
            ..Served::default()
        });
        for id in ["inference", "moe", "media-gen"] {
            assert!(models_only.iter().any(|s| s == id), "{id}");
        }
        for id in ["storage", "compute", "iroh-transport"] {
            assert!(!models_only.iter().any(|s| s == id), "{id}");
        }
        let storage_only = ids(Served {
            storage: true,
            ..Served::default()
        });
        assert!(storage_only.iter().any(|s| s == "storage"));
        assert!(!storage_only.iter().any(|s| s == "inference"));
        assert!(!storage_only.iter().any(|s| s == "compute"));
    }

    /// Dropping a skill changes what is signed: a card that claims more than
    /// the node signed for does not verify.
    #[test]
    fn a_skill_added_to_a_signed_card_breaks_the_signature() {
        let narrow = build_agent_card(published(), "Validator", Served::default());
        let mut signed = sign_card(&narrow, &key(3));
        assert!(verify_agent_card(&signed).is_ok());
        let full =
            serde_json::to_value(build_agent_card(published(), "Validator", Served::ALL)).unwrap();
        signed["skills"] = full["skills"].clone();
        assert!(verify_agent_card(&signed).is_err());
    }

    #[test]
    fn test_agent_card_roundtrip() {
        let card = build_agent_card(published(), "Validator", Served::ALL);
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
        build_agent_card(published(), "Validator", Served::ALL)
    }

    /// The `kid` of `key`'s machine: its DID's hardware key.
    fn kid_of(key: &TestHybridSigner) -> String {
        let sec1 = [&[0x04][..], &key.public_key().p256].concat();
        format!(
            "{}#hardware-key",
            tenzro_types::did_derivation::machine_did(&sec1)
        )
    }

    /// Sign an ES256 card with a software key under its own machine's `kid`.
    fn sign_card(card: &AgentCard, key: &TestHybridSigner) -> Value {
        sign_card_as(card, key, &kid_of(key))
    }

    /// Sign an ES256 card with a software key, naming `kid` as the signer.
    fn sign_card_as(card: &AgentCard, key: &TestHybridSigner, kid: &str) -> Value {
        let mut unsigned = card.clone();
        unsigned.signatures.clear();
        let value = serde_json::to_value(&unsigned).unwrap();
        let protected = es256_protected_header(kid, &key.public_key().p256);
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
    fn the_machine_key_signs_under_the_did_it_derives() {
        use tenzro_device_key::signer::HardwareSigner as _;
        let signer = crate::data_integrity::tests::test_signer(9);
        let sec1 = signer.public_key_sec1().unwrap();
        let card = sign_with_machine_key(&signer, &fixed_card()).unwrap();
        let verified = verify_agent_card(&serde_json::to_value(&card).unwrap()).unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].alg, "ES256");
        let did = verified[0].kid.strip_suffix("#hardware-key").unwrap();
        assert!(tenzro_types::did_derivation::did_derives_from_key(
            did, &sec1
        ));
        assert_eq!(verified[0].public_key_hex, hex::encode(&sec1[1..]));
        // Signing again replaces the signature instead of adding one.
        let again = sign_with_machine_key(&signer, &card).unwrap();
        assert_eq!(again.signatures.len(), 1);
    }

    /// A card signed by one machine's key under another machine's `kid` is
    /// refused: the header's key is not the key the named DID derives from.
    #[test]
    fn a_card_signed_by_another_key_than_its_kid_names_is_refused() {
        let ours = key(7);
        let theirs = key(8);
        let forged = sign_card_as(&fixed_card(), &theirs, &kid_of(&ours));
        assert_eq!(
            verify_agent_card(&forged).unwrap_err(),
            CardSignatureError::NotTheKidsKey {
                index: 0,
                kid: kid_of(&ours),
            }
        );
        let unbound = sign_card_as(&fixed_card(), &ours, KID);
        assert!(matches!(
            verify_agent_card(&unbound),
            Err(CardSignatureError::NotTheKidsKey { .. })
        ));
    }

    #[test]
    fn signed_card_verifies_and_reports_the_signing_key() {
        let k = key(7);
        let signed = sign_card(&fixed_card(), &k);
        let verified = verify_agent_card(&signed).unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].alg, "ES256");
        assert_eq!(verified[0].kid, kid_of(&k));
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
