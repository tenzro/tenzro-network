//! Governed bridge routes.
//!
//! A route states, for one transport and one external chain:
//!
//! - which chain family the external chain belongs to (its message format),
//! - which contract on the external chain (the token pool) may send value to
//!   Tenzro, and through which transport contract (the ramp) it is emitted,
//! - which Tenzro-side endpoint those deliveries must be addressed to,
//! - which committee attests a delivery, and how many of its members must
//!   sign, plus an independent blessing committee where the transport has one,
//! - whether a light-client proof of the source chain is required as well,
//! - how much value may be minted through the route, per mint and per
//!   epoch,
//! - and, for a CCIP route, the on-ramp version the lane runs (which fixes
//!   the message layout read from it) and the lane's token-bucket rate
//!   limits in each direction, the same values the external chain's token
//!   pool enforces.
//!
//! Routes live in consensus state under [`bridge_route_storage_key`], written
//! only by an enacted governance proposal. Every node therefore applies the
//! same routes, and anyone can read them back from state.
//!
//! [`BridgeRoute::validate`] is the single rule set. Governance runs it when a
//! proposal is submitted and again when it is enacted; the route framework
//! runs it again each time it loads a route. A route that no longer passes is
//! treated as absent, so traffic on it is refused.
//!
//! # Committee rules
//!
//! Governance sets a committee's size and threshold, never its members: a
//! route is proposed with empty committees ([`BridgeRoute::validate_proposal`])
//! and its members are drawn on chain from the accounts bonded as attestors
//! that declared a bridge signing key, weighted by stake, with the randomness
//! beacon. A route whose committees are not drawn carries no traffic.
//!
//! A drawn verifier quorum has at least [`MIN_VERIFIER_SET_SIZE`] members and a
//! threshold of at least a strict majority (`floor(n/2) + 1`). No single
//! account and no single RPC provider may back `threshold` or more members:
//! a quorum that one operator or one compromised RPC endpoint can satisfy
//! on its own is a single point of failure however many signatures it carries.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::primitives::u128_serde;

/// Prefix of every route key in consensus state (under the system address).
pub const BRIDGE_ROUTE_KEY_PREFIX: &str = "bridge_route:";

/// Smallest verifier committee a route may declare.
pub const MIN_VERIFIER_SET_SIZE: usize = 3;

/// Largest verifier committee a route may declare. Signature sets carry a
/// one-byte count.
pub const MAX_VERIFIER_SET_SIZE: usize = 255;

/// Longest operator or RPC provider label.
pub const MAX_LABEL_LEN: usize = 128;

/// Longest external chain name.
pub const MAX_CHAIN_NAME_LEN: usize = 64;

/// Storage key of the route for `(adapter, source_chain)`.
pub fn bridge_route_storage_key(adapter: BridgeRouteAdapter, source_chain: &str) -> String {
    format!(
        "{BRIDGE_ROUTE_KEY_PREFIX}{}:{}",
        adapter.as_str(),
        source_chain.to_ascii_lowercase()
    )
}

/// What a route may carry, as governance (or a validator finding) set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeRouteMode {
    /// Carries traffic both ways.
    Open,
    /// Winding down: nothing new leaves Tenzro over it and nothing new is
    /// credited on a deposit route, while TNZO already sent out over a
    /// lock-and-mint route can still come back, so no transfer in flight is
    /// stranded.
    Disabled,
    /// Stopped: carries nothing at all until governance changes its mode.
    Paused,
}

impl BridgeRouteMode {
    /// Stable name.
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeRouteMode::Open => "open",
            BridgeRouteMode::Disabled => "disabled",
            BridgeRouteMode::Paused => "paused",
        }
    }
}

/// The transport a route moves messages over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BridgeRouteAdapter {
    /// The CCIP message envelope, for EVM and Solana chains.
    #[serde(rename = "ccip")]
    Ccip,
    /// IBC: ICS-20 fungible-token packets over a channel to a Cosmos chain.
    #[serde(rename = "ibc")]
    Ibc,
    /// Deposits to a governed output script on a UTXO chain (Bitcoin),
    /// proven from its proof-of-work header chain.
    #[serde(rename = "deposit")]
    Deposit,
    /// Tenzro's bridge contract on the external chain, which emits each
    /// transfer as an event in that chain's own encoding.
    #[serde(rename = "contract")]
    Contract,
}

impl BridgeRouteAdapter {
    /// Every transport.
    pub const ALL: [BridgeRouteAdapter; 4] = [
        BridgeRouteAdapter::Ccip,
        BridgeRouteAdapter::Ibc,
        BridgeRouteAdapter::Deposit,
        BridgeRouteAdapter::Contract,
    ];

    /// The transport's name, as storage keys and RPCs spell it.
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeRouteAdapter::Ccip => "ccip",
            BridgeRouteAdapter::Ibc => "ibc",
            BridgeRouteAdapter::Deposit => "deposit",
            BridgeRouteAdapter::Contract => "contract",
        }
    }

    /// Every transport's name, for messages that list them.
    pub fn names() -> String {
        Self::ALL.map(|a| a.as_str()).join(", ")
    }

    /// Parse a transport name.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.as_str().eq_ignore_ascii_case(name))
    }

    /// The chain families this transport can serve.
    pub fn families(&self) -> &'static [ChainFamily] {
        match self {
            BridgeRouteAdapter::Ccip => &[ChainFamily::Evm, ChainFamily::Solana],
            BridgeRouteAdapter::Ibc => &[ChainFamily::Cosmos],
            BridgeRouteAdapter::Deposit => &[ChainFamily::Bitcoin],
            BridgeRouteAdapter::Contract => &[
                ChainFamily::Stellar,
                ChainFamily::Sui,
                ChainFamily::Aptos,
                ChainFamily::Ton,
            ],
        }
    }
}

/// The family an external chain belongs to; it fixes the message format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainFamily {
    /// EVM chains (Ethereum, its rollups and other EVM chains).
    Evm,
    /// Solana.
    Solana,
    /// Cosmos SDK chains on CometBFT, reached over IBC.
    Cosmos,
    /// Bitcoin.
    Bitcoin,
    /// Stellar (Soroban contracts).
    Stellar,
    /// Sui.
    Sui,
    /// Aptos.
    Aptos,
    /// TON.
    Ton,
}

impl ChainFamily {
    /// Stable name.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainFamily::Evm => "evm",
            ChainFamily::Solana => "solana",
            ChainFamily::Cosmos => "cosmos",
            ChainFamily::Bitcoin => "bitcoin",
            ChainFamily::Stellar => "stellar",
            ChainFamily::Sui => "sui",
            ChainFamily::Aptos => "aptos",
            ChainFamily::Ton => "ton",
        }
    }

    /// Whether the chain's own verification of what it receives, and of the
    /// state a Tenzro light client follows, rests on classical signatures
    /// only: ECDSA on EVM chains and Bitcoin, Ed25519 on Cosmos, Solana,
    /// Stellar, Sui, Aptos and TON, BLS12-381 on Ethereum's beacon chain.
    /// Tenzro's own acceptance of a delivery requires post-quantum committee
    /// signatures on every route; this residual is the external chain's, and
    /// the network mint limits cap what it can put at risk
    /// ([`NetworkMintLimits::classical`]). Every family served today is
    /// classical; a family whose chain verified post-quantum signatures
    /// would return false and would not be held to that ceiling.
    pub fn verification_is_classical(&self) -> bool {
        match self {
            ChainFamily::Evm
            | ChainFamily::Solana
            | ChainFamily::Cosmos
            | ChainFamily::Bitcoin
            | ChainFamily::Stellar
            | ChainFamily::Sui
            | ChainFamily::Aptos
            | ChainFamily::Ton => true,
        }
    }

    /// The light client a route of this family must carry, for families
    /// whose chain publishes what one needs. Routes of the other families
    /// may name one where it applies (Ethereum's) or rest on their committee.
    pub fn required_light_client(&self) -> Option<LightClientKind> {
        match self {
            ChainFamily::Cosmos => Some(LightClientKind::Tendermint),
            ChainFamily::Bitcoin => Some(LightClientKind::BitcoinHeaders),
            ChainFamily::Stellar => Some(LightClientKind::StellarScp),
            ChainFamily::Sui => Some(LightClientKind::SuiCommittee),
            ChainFamily::Aptos => Some(LightClientKind::AptosValidators),
            ChainFamily::Ton => Some(LightClientKind::TonValidators),
            ChainFamily::Evm | ChainFamily::Solana => None,
        }
    }
}

/// The trusted starting point of a route's light client, set by the same
/// governance vote that installs the route, so anyone can audit what each
/// node's light client follows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightClientAnchor {
    /// Ethereum's beacon-chain sync committee. The light client starts from
    /// a finalized beacon block everyone can check (a weak-subjectivity
    /// checkpoint), takes the sync committee from that block's state, and
    /// follows each committee handover the committee itself signs.
    EthereumSyncCommittee {
        /// `genesis_validators_root` of the beacon chain.
        genesis_validators_root: [u8; 32],
        /// The fork version sync-committee signatures are made under.
        fork_version: [u8; 4],
        /// Root of the finalized beacon block header the light client
        /// starts from.
        trusted_block_root: [u8; 32],
    },
    /// A CometBFT (Tendermint) light client. It starts from a header
    /// everyone can check and follows headers that validators holding more
    /// than two thirds of the voting power signed, skipping ahead only where
    /// more than a third of the power it already trusts signed too.
    Tendermint {
        /// The chain id headers must name (`cosmoshub-4`).
        chain_id: String,
        /// Height of the trusted header.
        trusted_height: u64,
        /// Hash of the trusted header.
        trusted_header_hash: [u8; 32],
        /// How long a verified header may be built on, in seconds; it must
        /// be shorter than the chain's unbonding period.
        trusting_period_secs: u64,
    },
    /// A Bitcoin header-chain (SPV) client. It starts from a header at a
    /// difficulty-adjustment boundary and follows the chain with the most
    /// cumulative proof of work, checking every header's work and target.
    BitcoinHeaders {
        /// Height of the trusted header; a multiple of 2016.
        trusted_height: u64,
        /// Hash of the trusted header (double SHA-256, internal byte order).
        trusted_header_hash: [u8; 32],
        /// Blocks a deposit's block must be buried under, itself included.
        confirmations: u32,
        /// The BIP-340 keys of the deposit descriptor's signers
        /// (`tr(NUMS, multi_a(threshold, signers...))`); the SHA-256 of the
        /// descriptor's output script is the route's `peer`.
        signers: Vec<[u8; 32]>,
        /// How many of them must sign a withdrawal.
        threshold: u32,
        /// The fee rate withdrawals pay, satoshis per virtual byte.
        fee_rate: u64,
    },
    /// A Sui light client. It starts from an end-of-epoch checkpoint
    /// everyone can check and follows each next committee that the current
    /// committee announces in its own end-of-epoch checkpoint.
    SuiCommittee {
        /// Digest of the trusted end-of-epoch checkpoint summary.
        trusted_checkpoint_digest: [u8; 32],
    },
    /// An Aptos light client. It starts from an epoch-ending ledger info
    /// everyone can check and follows each validator set that the current
    /// one signs into its own epoch-ending ledger info.
    AptosValidators {
        /// Hash of the trusted epoch-ending ledger info.
        trusted_ledger_info_hash: [u8; 32],
    },
    /// A Stellar SCP client. A ledger is accepted once the governed quorum
    /// of validators signed an SCP externalize statement for the next
    /// ledger, whose transaction set names it.
    StellarScp {
        /// The network id (SHA-256 of the network passphrase).
        network_id: [u8; 32],
        /// The validators' node keys (Ed25519).
        validators: Vec<[u8; 32]>,
        /// How many of them must have externalized.
        threshold: u32,
    },
    /// A TON light client. It starts from a masterchain key block everyone
    /// can check, takes the validator set from its configuration, and
    /// follows each next key block the current set finalizes.
    TonKeyBlock {
        /// Seqno of the trusted masterchain key block.
        trusted_seqno: u32,
        /// Root hash of the trusted key block.
        trusted_root_hash: [u8; 32],
    },
}

/// The kinds of light client a route can require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LightClientKind {
    /// [`LightClientAnchor::EthereumSyncCommittee`].
    EthereumSyncCommittee,
    /// [`LightClientAnchor::Tendermint`].
    Tendermint,
    /// [`LightClientAnchor::BitcoinHeaders`].
    BitcoinHeaders,
    /// [`LightClientAnchor::SuiCommittee`].
    SuiCommittee,
    /// [`LightClientAnchor::AptosValidators`].
    AptosValidators,
    /// [`LightClientAnchor::StellarScp`].
    StellarScp,
    /// [`LightClientAnchor::TonKeyBlock`].
    TonValidators,
}

/// Longest Tendermint chain id a route may name.
pub const MAX_TENDERMINT_CHAIN_ID_LEN: usize = 50;

/// Fewest confirmations a Bitcoin deposit route may require.
pub const MIN_BITCOIN_CONFIRMATIONS: u32 = 6;

/// Most signers a deposit descriptor may name.
pub const MAX_DEPOSIT_SIGNERS: usize = 32;

/// Highest withdrawal fee rate a route may set, satoshis per virtual byte.
pub const MAX_WITHDRAWAL_FEE_RATE: u64 = 1_000;

/// Largest Stellar validator quorum a route may name.
pub const MAX_STELLAR_VALIDATORS: usize = 64;

impl LightClientAnchor {
    /// The kind of light client the anchor starts.
    pub fn kind(&self) -> LightClientKind {
        match self {
            LightClientAnchor::EthereumSyncCommittee { .. } => {
                LightClientKind::EthereumSyncCommittee
            }
            LightClientAnchor::Tendermint { .. } => LightClientKind::Tendermint,
            LightClientAnchor::BitcoinHeaders { .. } => LightClientKind::BitcoinHeaders,
            LightClientAnchor::SuiCommittee { .. } => LightClientKind::SuiCommittee,
            LightClientAnchor::AptosValidators { .. } => LightClientKind::AptosValidators,
            LightClientAnchor::StellarScp { .. } => LightClientKind::StellarScp,
            LightClientAnchor::TonKeyBlock { .. } => LightClientKind::TonValidators,
        }
    }

    /// Whether the light client keeps state started from the anchor (and so
    /// is verified only once its bootstrap, checked against the anchor, has
    /// been applied). A Stellar quorum is checked whole on every delivery.
    pub fn keeps_state(&self) -> bool {
        !matches!(self, LightClientAnchor::StellarScp { .. })
    }

    /// Where route state keeps the head of the light client started from this
    /// anchor on `route`, written by its bootstrap; any other record of it
    /// sits under this key followed by a suffix.
    pub fn store_key(&self, route: &BridgeRoute) -> String {
        format!(
            "bridge_lc:{}:{}",
            route.storage_key(),
            hex::encode(self.id())
        )
    }

    /// The anchor's stable identity: a light client restarted from a new
    /// anchor keeps nothing of the old one's state.
    pub fn id(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        match self {
            LightClientAnchor::EthereumSyncCommittee {
                trusted_block_root, ..
            } => *trusted_block_root,
            LightClientAnchor::Tendermint {
                trusted_header_hash,
                ..
            } => *trusted_header_hash,
            LightClientAnchor::BitcoinHeaders {
                trusted_header_hash,
                confirmations,
                signers,
                threshold,
                ..
            } => {
                let mut h = Sha256::new();
                h.update(trusted_header_hash);
                h.update(confirmations.to_be_bytes());
                h.update(threshold.to_be_bytes());
                for s in signers {
                    h.update(s);
                }
                h.finalize().into()
            }
            LightClientAnchor::SuiCommittee {
                trusted_checkpoint_digest,
            } => *trusted_checkpoint_digest,
            LightClientAnchor::AptosValidators {
                trusted_ledger_info_hash,
            } => *trusted_ledger_info_hash,
            LightClientAnchor::StellarScp {
                network_id,
                validators,
                threshold,
            } => {
                let mut h = Sha256::new();
                h.update(network_id);
                h.update(threshold.to_be_bytes());
                for v in validators {
                    h.update(v);
                }
                h.finalize().into()
            }
            LightClientAnchor::TonKeyBlock {
                trusted_root_hash, ..
            } => *trusted_root_hash,
        }
    }

    fn validate(&self, route: &BridgeRoute) -> Result<(), BridgeRouteError> {
        let zero = |v: &[u8; 32]| *v == [0u8; 32];
        let family = |f: ChainFamily| {
            if route.family == f {
                Ok(())
            } else {
                Err(BridgeRouteError::LightClientNotApplicable(
                    route.source_chain.clone(),
                ))
            }
        };
        let anchor = |bad: bool| {
            if bad {
                Err(BridgeRouteError::InvalidAnchor(route.source_chain.clone()))
            } else {
                Ok(())
            }
        };
        match self {
            LightClientAnchor::Tendermint {
                chain_id,
                trusted_height,
                trusted_header_hash,
                trusting_period_secs,
            } => {
                family(ChainFamily::Cosmos)?;
                anchor(
                    chain_id.is_empty()
                        || chain_id.len() > MAX_TENDERMINT_CHAIN_ID_LEN
                        || *trusted_height == 0
                        || zero(trusted_header_hash)
                        || *trusting_period_secs == 0,
                )
            }
            LightClientAnchor::BitcoinHeaders {
                trusted_height,
                trusted_header_hash,
                confirmations,
                signers,
                threshold,
                fee_rate,
            } => {
                family(ChainFamily::Bitcoin)?;
                let distinct: HashSet<&[u8; 32]> = signers.iter().collect();
                anchor(
                    trusted_height % 2016 != 0
                        || zero(trusted_header_hash)
                        || *confirmations < MIN_BITCOIN_CONFIRMATIONS
                        || signers.is_empty()
                        || signers.len() > MAX_DEPOSIT_SIGNERS
                        || distinct.len() != signers.len()
                        || signers.iter().any(zero)
                        || (*threshold as usize) <= signers.len() / 2
                        || *threshold as usize > signers.len()
                        || *fee_rate == 0
                        || *fee_rate > MAX_WITHDRAWAL_FEE_RATE,
                )
            }
            LightClientAnchor::SuiCommittee {
                trusted_checkpoint_digest,
            } => {
                family(ChainFamily::Sui)?;
                anchor(zero(trusted_checkpoint_digest))
            }
            LightClientAnchor::TonKeyBlock {
                trusted_seqno,
                trusted_root_hash,
            } => {
                family(ChainFamily::Ton)?;
                anchor(*trusted_seqno == 0 || zero(trusted_root_hash))
            }
            LightClientAnchor::AptosValidators {
                trusted_ledger_info_hash,
            } => {
                family(ChainFamily::Aptos)?;
                anchor(zero(trusted_ledger_info_hash))
            }
            LightClientAnchor::StellarScp {
                network_id,
                validators,
                threshold,
            } => {
                family(ChainFamily::Stellar)?;
                let distinct: HashSet<&[u8; 32]> = validators.iter().collect();
                let n = validators.len();
                anchor(
                    zero(network_id)
                        || !(MIN_VERIFIER_SET_SIZE..=MAX_STELLAR_VALIDATORS).contains(&n)
                        || distinct.len() != n
                        || validators.iter().any(zero)
                        || (*threshold as usize) <= n * 2 / 3
                        || *threshold as usize > n,
                )
            }
            LightClientAnchor::EthereumSyncCommittee {
                genesis_validators_root,
                trusted_block_root,
                ..
            } => {
                // The sync committee finalizes Ethereum itself. A rollup's
                // messages are final only once its own proof system settles
                // them on Ethereum, which this light client does not follow.
                if route.family != ChainFamily::Evm || route.source_chain != "ethereum" {
                    return Err(BridgeRouteError::LightClientNotApplicable(
                        route.source_chain.clone(),
                    ));
                }
                if *genesis_validators_root == [0u8; 32] || *trusted_block_root == [0u8; 32] {
                    return Err(BridgeRouteError::ZeroAddress {
                        field: "light_client",
                    });
                }
                Ok(())
            }
        }
    }
}

/// Length of an ML-DSA-65 verifying key (FIPS 204).
pub const ML_DSA_65_VERIFYING_KEY_LEN: usize = 1952;

/// One member of a verifier committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierMember {
    /// The 20-byte secp256k1 (EVM-style) address the member signs with.
    pub address: [u8; 20],
    /// The member's ML-DSA-65 verifying key, 1952 bytes. A delivery counts a
    /// member only when it carries a valid signature from this key as well
    /// as from `address`.
    #[serde(with = "hex::serde")]
    pub pq_public_key: Vec<u8>,
    /// The account, hex, holding the attestor bond that answers for this
    /// member. Members sharing an account share a failure domain.
    pub operator: String,
    /// Where this member reads the source chain from. Members sharing an RPC
    /// provider see the same view of the source chain, true or not.
    pub rpc_provider: String,
}

/// A threshold committee that attests deliveries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierQuorum {
    /// The committee's index, bumped when its membership is drawn again.
    pub set_index: u32,
    /// How many members are drawn.
    pub size: u32,
    /// The members, drawn on chain; empty until the first draw.
    pub members: Vec<VerifierMember>,
    /// Distinct valid member signatures required.
    pub threshold: u32,
}

impl VerifierQuorum {
    /// The member addresses, in order.
    pub fn addresses(&self) -> Vec<[u8; 20]> {
        self.members.iter().map(|m| m.address).collect()
    }

    /// Check the size and threshold governance sets.
    pub fn validate_shape(&self, label: &'static str) -> Result<(), BridgeRouteError> {
        let n = self.size as usize;
        if n < MIN_VERIFIER_SET_SIZE {
            return Err(BridgeRouteError::CommitteeTooSmall {
                committee: label,
                size: n,
                min: MIN_VERIFIER_SET_SIZE,
            });
        }
        if n > MAX_VERIFIER_SET_SIZE {
            return Err(BridgeRouteError::CommitteeTooLarge {
                committee: label,
                size: n,
                max: MAX_VERIFIER_SET_SIZE,
            });
        }
        let t = self.threshold as usize;
        let majority = n / 2 + 1;
        if t < majority || t > n {
            return Err(BridgeRouteError::ThresholdOutOfRange {
                committee: label,
                threshold: self.threshold,
                min: majority,
                max: n,
            });
        }
        Ok(())
    }

    /// Check a drawn committee: the shape, the full membership, and the
    /// diversity rules described in the module docs.
    pub fn validate(&self, label: &'static str) -> Result<(), BridgeRouteError> {
        self.validate_shape(label)?;
        if self.members.len() != self.size as usize {
            return Err(BridgeRouteError::CommitteeNotDrawn { committee: label });
        }
        let t = self.threshold as usize;
        let mut seen = HashSet::new();
        let mut by_operator: HashMap<&str, usize> = HashMap::new();
        let mut by_rpc: HashMap<&str, usize> = HashMap::new();
        for m in &self.members {
            if m.address == [0u8; 20] {
                return Err(BridgeRouteError::ZeroAddress { field: label });
            }
            if m.pq_public_key.len() != ML_DSA_65_VERIFYING_KEY_LEN {
                return Err(BridgeRouteError::MissingPqKey {
                    committee: label,
                    address: hex::encode(m.address),
                });
            }
            if !seen.insert(m.address) {
                return Err(BridgeRouteError::DuplicateMember {
                    committee: label,
                    address: hex::encode(m.address),
                });
            }
            let operator = m.operator.trim();
            let rpc = m.rpc_provider.trim();
            if operator.is_empty() || rpc.is_empty() {
                return Err(BridgeRouteError::MissingMemberLabel {
                    committee: label,
                    address: hex::encode(m.address),
                });
            }
            if operator.len() > MAX_LABEL_LEN || rpc.len() > MAX_LABEL_LEN {
                return Err(BridgeRouteError::LabelTooLong { committee: label });
            }
            *by_operator.entry(operator).or_default() += 1;
            *by_rpc.entry(rpc).or_default() += 1;
        }
        if let Some((operator, count)) = by_operator.iter().find(|(_, c)| **c >= t) {
            return Err(BridgeRouteError::OperatorCanReachQuorum {
                committee: label,
                operator: operator.to_string(),
                members: *count,
                threshold: self.threshold,
            });
        }
        if let Some((rpc, count)) = by_rpc.iter().find(|(_, c)| **c >= t) {
            return Err(BridgeRouteError::RpcProviderCanReachQuorum {
                committee: label,
                rpc_provider: rpc.to_string(),
                members: *count,
                threshold: self.threshold,
            });
        }
        Ok(())
    }
}

/// How much value may be minted through a route: a cap on any one mint and a
/// rate limit on the total minted in one epoch. The network-wide limits
/// governance sets bound every route as well; the tighter of the two applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRateLimit {
    /// Most one mint may carry, in the smallest unit.
    #[serde(with = "u128_serde")]
    pub per_mint: u128,
    /// Most that may be minted in one epoch, in the smallest unit.
    #[serde(with = "u128_serde")]
    pub per_epoch: u128,
}

impl MintRateLimit {
    /// The tighter of `self` and `other`, field by field.
    pub fn tightest(self, other: MintRateLimit) -> MintRateLimit {
        MintRateLimit {
            per_mint: self.per_mint.min(other.per_mint),
            per_epoch: self.per_epoch.min(other.per_epoch),
        }
    }

    /// Check a limit is usable: both non-zero, and one mint no larger than
    /// an epoch.
    pub fn validate(&self) -> Result<(), BridgeRouteError> {
        if self.per_mint == 0 || self.per_epoch == 0 {
            return Err(BridgeRouteError::ZeroMintLimit);
        }
        if self.per_mint > self.per_epoch {
            return Err(BridgeRouteError::MintCapExceedsEpochLimit);
        }
        Ok(())
    }
}

/// One direction of a CCIP lane's rate limit, in the token-bucket form a CCIP
/// token pool configures (`RateLimiter.Config` with `isEnabled` set): the
/// bucket holds at most `capacity` and refills at `rate` per second. A
/// transfer takes its amount out of the bucket and is refused when the
/// bucket holds less.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRateLimit {
    /// Most the bucket holds, in the smallest unit.
    #[serde(with = "u128_serde")]
    pub capacity: u128,
    /// Refill per second, in the smallest unit.
    #[serde(with = "u128_serde")]
    pub rate: u128,
}

impl LaneRateLimit {
    /// The rule a CCIP token pool applies to an enabled limit: a non-zero
    /// rate strictly below the capacity.
    pub fn validate(&self, direction: &'static str) -> Result<(), BridgeRouteError> {
        if self.rate == 0 || self.rate >= self.capacity {
            return Err(BridgeRouteError::InvalidLaneLimit(direction));
        }
        Ok(())
    }
}

/// The CCIP on-ramp contract version a lane runs on the external chain. It
/// fixes the event and the message layout the on-ramp emits; a lane reads
/// exactly its own version's layout and refuses every other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CcipLaneVersion {
    /// `OnRamp 2.0.0`: `CCIPMessageSent` carrying the chain-agnostic encoded
    /// message, whose keccak-256 is the message id.
    #[serde(rename = "2.0.0")]
    V2_0,
    /// `OnRamp 1.6.0`: `CCIPMessageSent` carrying `EVM2AnyRampMessage`.
    #[serde(rename = "1.6.0")]
    V1_6,
    /// `EVM2EVMOnRamp 1.5.0`: `CCIPSendRequested` carrying `EVM2EVMMessage`,
    /// one on-ramp contract per destination.
    #[serde(rename = "1.5.0")]
    V1_5,
}

impl CcipLaneVersion {
    /// Every version.
    pub const ALL: [CcipLaneVersion; 3] = [
        CcipLaneVersion::V2_0,
        CcipLaneVersion::V1_6,
        CcipLaneVersion::V1_5,
    ];

    /// The version as the on-ramp's `typeAndVersion` spells it.
    pub fn as_str(&self) -> &'static str {
        match self {
            CcipLaneVersion::V2_0 => "2.0.0",
            CcipLaneVersion::V1_6 => "1.6.0",
            CcipLaneVersion::V1_5 => "1.5.0",
        }
    }

    /// Parse a version string.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A CCIP lane: the on-ramp version it runs and its inbound rate limit. The
/// external chain's token pool is configured with this inbound limit and the
/// route's [`BridgeRoute::outflow`]; Tenzro enforces both on its side of the
/// lane, alongside the route's [`MintRateLimit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CcipLane {
    /// The lane's on-ramp version.
    pub version: CcipLaneVersion,
    /// The lane's off-ramp on the external chain: the contract that executes
    /// Tenzro's outbound messages there. A `2.0.0` message names it.
    pub off_ramp: [u8; 20],
    /// For a `2.0.0` lane, the hash over the verifier and executor set the
    /// off-ramp requires for messages from Tenzro, as the lane is configured
    /// on the external chain. Unused by the older versions (zero there).
    pub ccv_and_executor_hash: [u8; 32],
    /// Transfers arriving on Tenzro over the lane.
    pub inbound: LaneRateLimit,
}

impl CcipLane {
    /// The inbound limit is valid, and its bucket holds no more than the
    /// route may mint in one epoch, so a full bucket never exceeds the epoch
    /// limit it sits under.
    pub fn validate(&self, mint: &MintRateLimit) -> Result<(), BridgeRouteError> {
        self.inbound.validate("inbound")?;
        if self.inbound.capacity > mint.per_epoch {
            return Err(BridgeRouteError::LaneExceedsEpochLimit);
        }
        Ok(())
    }
}

/// The IBC protocol version a route speaks with its Cosmos chain. Both
/// carry the same ICS-20 packets, committed and proven the same way; they
/// differ in what a packet travels on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IbcVersion {
    /// IBC classic: packets travel a channel on a connection, both opened by
    /// handshakes (ICS-03, ICS-04) whose state each chain keeps.
    Classic,
    /// IBC v2: packets travel between the two chains' light clients of each
    /// other, each registered as the other's counterparty; there is no
    /// connection or channel.
    V2,
}

impl IbcVersion {
    /// Stable name.
    pub fn as_str(&self) -> &'static str {
        match self {
            IbcVersion::Classic => "classic",
            IbcVersion::V2 => "v2",
        }
    }
}

/// Port both ends of an IBC route bind: ICS-20 fungible-token transfer.
pub const IBC_TRANSFER_PORT: &str = "transfer";

/// Longest IBC identifier (ICS-24).
pub const MAX_IBC_IDENTIFIER_LEN: usize = 64;

/// Longest an outbound IBC packet may stay receivable, in seconds (the
/// bound IBC v2 chains apply).
pub const MAX_IBC_PACKET_TIMEOUT_SECS: u64 = 24 * 3600;

/// An IBC route's protocol settings. Tenzro's own identifiers on the route
/// are derived from the route's chain name, so no two routes share one; the
/// Cosmos chain's identifiers are the ones it assigned, set by the vote that
/// installs the route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IbcRoute {
    /// The protocol version.
    pub version: IbcVersion,
    /// The Cosmos chain's light client of Tenzro.
    pub counterparty_client_id: String,
    /// Classic: the Cosmos chain's end of the connection. None for v2.
    pub counterparty_connection_id: Option<String>,
    /// Classic: the Cosmos chain's end of the channel. None for v2.
    pub counterparty_channel_id: Option<String>,
    /// How long after it is sent an outbound packet times out, in seconds.
    pub packet_timeout_secs: u64,
}

/// Whether `s` is an ICS-24 identifier of `min` to 64 characters.
pub fn is_ibc_identifier(s: &str, min: usize) -> bool {
    (min..=MAX_IBC_IDENTIFIER_LEN).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_+#[]<>".contains(&b))
}

impl IbcRoute {
    /// The number in Tenzro's identifiers on the route to `chain`: the first
    /// eight bytes of the SHA-256 of the chain name, big-endian. IBC
    /// identifiers are `{prefix}-{number}`, and chains parse the number.
    pub fn identifier_number(chain: &str) -> u64 {
        use sha2::Digest;
        let h = sha2::Sha256::digest(chain.as_bytes());
        u64::from_be_bytes(h[..8].try_into().expect("8 bytes"))
    }

    /// Tenzro's light client of the route's chain, as IBC names it.
    pub fn tenzro_client_id(chain: &str) -> String {
        format!("07-tendermint-{}", Self::identifier_number(chain))
    }

    /// Tenzro's end of a classic route's connection.
    pub fn tenzro_connection_id(chain: &str) -> String {
        format!("connection-{}", Self::identifier_number(chain))
    }

    /// Tenzro's end of a classic route's channel.
    pub fn tenzro_channel_id(chain: &str) -> String {
        format!("channel-{}", Self::identifier_number(chain))
    }

    /// What a packet names Tenzro's end by: the channel (classic) or the
    /// client (v2).
    pub fn tenzro_packet_id(&self, chain: &str) -> String {
        match self.version {
            IbcVersion::Classic => Self::tenzro_channel_id(chain),
            IbcVersion::V2 => Self::tenzro_client_id(chain),
        }
    }

    /// What a packet names the Cosmos chain's end by.
    pub fn counterparty_packet_id(&self) -> &str {
        match self.version {
            IbcVersion::Classic => self.counterparty_channel_id.as_deref().unwrap_or_default(),
            IbcVersion::V2 => &self.counterparty_client_id,
        }
    }

    /// SHA-256 of an end, `port/id`, as a route's `peer` (the Cosmos end)
    /// and `local_endpoint` (Tenzro's end) hold it.
    pub fn end_hash(id: &str) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(format!("{IBC_TRANSFER_PORT}/{id}").as_bytes()).into()
    }

    /// TNZO's denomination trace on the Cosmos chain.
    pub fn tnzo_trace(&self) -> String {
        format!(
            "{IBC_TRANSFER_PORT}/{}/atnzo",
            self.counterparty_packet_id()
        )
    }

    /// The settings are complete for their version, and the route's `peer`,
    /// `local_endpoint` and `remote_token` name the ends and the
    /// denomination they derive.
    pub fn validate(&self, route: &BridgeRoute) -> Result<(), BridgeRouteError> {
        let bad = |why: &str| Err(BridgeRouteError::InvalidIbcRoute(why.to_string()));
        let chain = &route.source_chain;
        if !is_ibc_identifier(&Self::tenzro_client_id(chain), 9) {
            return bad("the chain name is too long for Tenzro's IBC identifiers");
        }
        if !is_ibc_identifier(&self.counterparty_client_id, 9) {
            return bad("counterparty_client_id is not an IBC client identifier");
        }
        match (
            self.version,
            &self.counterparty_connection_id,
            &self.counterparty_channel_id,
        ) {
            (IbcVersion::Classic, Some(connection), Some(channel)) => {
                if !is_ibc_identifier(connection, 10) || !is_ibc_identifier(channel, 8) {
                    return bad("the counterparty connection or channel is not an IBC identifier");
                }
            }
            (IbcVersion::Classic, ..) => {
                return bad("a classic route names the counterparty connection and channel");
            }
            (IbcVersion::V2, None, None) => {}
            (IbcVersion::V2, ..) => return bad("a v2 route has no connection or channel"),
        }
        if self.packet_timeout_secs == 0 || self.packet_timeout_secs > MAX_IBC_PACKET_TIMEOUT_SECS {
            return bad("packet_timeout_secs is 1 second to 24 hours");
        }
        use sha2::Digest;
        let trace: [u8; 32] = sha2::Sha256::digest(self.tnzo_trace().as_bytes()).into();
        if route.peer != Self::end_hash(self.counterparty_packet_id())
            || route.local_endpoint != Self::end_hash(&self.tenzro_packet_id(chain))
            || route.remote_token != trace
        {
            return bad(
                "peer, local_endpoint and remote_token must be the ends' and the trace's SHA-256",
            );
        }
        Ok(())
    }
}

/// The network-wide mint limits governance sets, by how a route proves what
/// it admits. A route with a light client proves each delivery against the
/// source chain's own consensus; a route without one (Solana) admits
/// on its committees' attestations alone, so it is held to lower limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMintLimits {
    /// Limits on routes with a light client.
    pub proven: MintRateLimit,
    /// Limits on routes without one, each strictly below `proven`.
    pub attested: MintRateLimit,
    /// A ceiling on every route whose destination verifies only classical
    /// signatures (see [`ChainFamily::verification_is_classical`]). It
    /// applies on top of `proven` or `attested`, whichever binds the route;
    /// the tighter of the two holds.
    pub classical: MintRateLimit,
}

impl NetworkMintLimits {
    /// The limits that bind `route`.
    pub fn for_route(&self, route: &BridgeRoute) -> MintRateLimit {
        let tier = if route.light_client.is_some() {
            self.proven
        } else {
            self.attested
        };
        if route.family.verification_is_classical() {
            tier.tightest(self.classical)
        } else {
            tier
        }
    }

    /// Both limits usable, and the attested ones strictly lower.
    pub fn validate(&self) -> Result<(), BridgeRouteError> {
        self.proven.validate()?;
        self.attested.validate()?;
        self.classical.validate()?;
        if self.attested.per_mint >= self.proven.per_mint
            || self.attested.per_epoch >= self.proven.per_epoch
        {
            return Err(BridgeRouteError::AttestedLimitNotLower);
        }
        Ok(())
    }
}

impl NetworkMintLimits {
    /// Refuse limits that raise any of `current`'s caps by more than
    /// `max_raise_bps` of it in one step.
    pub fn raised_within(
        &self,
        current: &NetworkMintLimits,
        max_raise_bps: u64,
    ) -> Result<(), BridgeRouteError> {
        for (what, now, proposed) in [
            (
                "proven.per_mint",
                current.proven.per_mint,
                self.proven.per_mint,
            ),
            (
                "proven.per_epoch",
                current.proven.per_epoch,
                self.proven.per_epoch,
            ),
            (
                "attested.per_mint",
                current.attested.per_mint,
                self.attested.per_mint,
            ),
            (
                "attested.per_epoch",
                current.attested.per_epoch,
                self.attested.per_epoch,
            ),
            (
                "classical.per_mint",
                current.classical.per_mint,
                self.classical.per_mint,
            ),
            (
                "classical.per_epoch",
                current.classical.per_epoch,
                self.classical.per_epoch,
            ),
        ] {
            check_raise(
                format!("network mint limit {what}"),
                now,
                proposed,
                max_raise_bps,
            )?;
        }
        Ok(())
    }
}

/// Whether moving a cap from `current` to `proposed` stays within one step:
/// a cap may be lowered freely and raised to at most `max_raise_bps` of its
/// current value (10 000 bps keeps it where it is).
pub fn raise_within(current: u128, proposed: u128, max_raise_bps: u64) -> bool {
    proposed <= current || wide_mul(proposed, 10_000) <= wide_mul(current, max_raise_bps)
}

/// `a * b` exactly, as (high, low) 128-bit halves, so products compare
/// without overflow or division.
fn wide_mul(a: u128, b: u64) -> (u128, u128) {
    let b = u128::from(b);
    let low = (a & u128::from(u64::MAX)) * b;
    let high = (a >> 64) * b;
    let (lo, carry) = low.overflowing_add(high << 64);
    ((high >> 64) + u128::from(carry), lo)
}

/// Whether moving a floor (a value whose lowering loosens, such as a delay)
/// from `current` to `proposed` stays within one step: it may be raised
/// freely and lowered to no less than `current` scaled down by
/// `max_raise_bps`.
pub fn lower_within(current: u128, proposed: u128, max_raise_bps: u64) -> bool {
    proposed >= current || raise_within(proposed, current, max_raise_bps)
}

fn check_raise(
    what: String,
    current: u128,
    proposed: u128,
    max_raise_bps: u64,
) -> Result<(), BridgeRouteError> {
    if raise_within(current, proposed, max_raise_bps) {
        return Ok(());
    }
    Err(BridgeRouteError::CapRaisedTooFar {
        what,
        current,
        proposed,
        max_raise_bps,
    })
}

/// Whether an exit of `amount` waits out the exit delay: it is larger than
/// `threshold_bps` of its outflow bucket's `capacity` (computed without
/// overflow for every capacity).
pub fn exit_waits(amount: u128, capacity: u128, threshold_bps: u64) -> bool {
    wide_mul(amount, 10_000) > wide_mul(capacity, threshold_bps.min(10_000))
}

/// The symbol of the asset a Bitcoin deposit route issues on Tenzro.
pub const BITCOIN_DEPOSIT_UNIT: &str = "BTC";

/// The symbol of the native asset a deposit route of `family` issues on
/// Tenzro, if the family has deposit routes.
pub fn deposit_unit(family: ChainFamily) -> Option<&'static str> {
    match family {
        ChainFamily::Bitcoin => Some(BITCOIN_DEPOSIT_UNIT),
        _ => None,
    }
}

/// The unit TNZO leaving Tenzro is counted in.
pub const TNZO_UNIT: &str = "TNZO";
/// Most units the network outflow limits may name.
pub const MAX_OUTFLOW_UNITS: usize = 64;

/// The most of one unit that may leave Tenzro over all bridge routes
/// together in one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutflowCap {
    /// TNZO, a deposit route's native asset or a carried asset's symbol.
    pub unit: String,
    /// Most that may leave in one epoch, in the unit's smallest denomination.
    #[serde(with = "u128_serde")]
    pub per_epoch: u128,
}

/// The network-wide outflow limits governance sets: for each unit, the most
/// that may leave Tenzro over every route together in one epoch. A unit
/// with no cap here cannot leave at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkOutflowLimits {
    /// One cap per unit.
    pub caps: Vec<OutflowCap>,
}

impl NetworkOutflowLimits {
    /// The per-epoch cap on `unit`, if it has one.
    pub fn per_epoch(&self, unit: &str) -> Option<u128> {
        self.caps
            .iter()
            .find(|c| c.unit == unit)
            .map(|c| c.per_epoch)
    }

    /// Check the limits are usable: at least one and at most
    /// [`MAX_OUTFLOW_UNITS`] units, each named like an asset symbol, named
    /// once, with a non-zero cap.
    pub fn validate(&self) -> Result<(), BridgeRouteError> {
        let bad = |reason: String| Err(BridgeRouteError::InvalidOutflowLimits(reason));
        if self.caps.is_empty() || self.caps.len() > MAX_OUTFLOW_UNITS {
            return bad(format!("name 1..={MAX_OUTFLOW_UNITS} units"));
        }
        let mut seen = HashSet::new();
        for cap in &self.caps {
            let u = cap.unit.as_str();
            if u.is_empty()
                || u.len() > MAX_ASSET_SYMBOL_LEN
                || !u
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return bad(format!(
                    "unit '{u}' is not 1..=12 ASCII uppercase letters or digits"
                ));
            }
            if !seen.insert(u) {
                return bad(format!("unit {u} is named twice"));
            }
            if cap.per_epoch == 0 {
                return bad(format!("unit {u} has a zero cap"));
            }
        }
        Ok(())
    }

    /// Refuse limits that raise any cap in `current` by more than
    /// `max_raise_bps` of it in one step. A unit `current` does not name has
    /// carried nothing yet and takes any cap.
    pub fn raised_within(
        &self,
        current: &NetworkOutflowLimits,
        max_raise_bps: u64,
    ) -> Result<(), BridgeRouteError> {
        for cap in &self.caps {
            if let Some(now) = current.per_epoch(&cap.unit) {
                check_raise(
                    format!("network outflow cap on {}", cap.unit),
                    now,
                    cap.per_epoch,
                    max_raise_bps,
                )?;
            }
        }
        Ok(())
    }
}

/// Most listed assets one route may carry.
pub const MAX_CARRIED_ASSETS: usize = 8;
/// Longest carried-asset symbol.
pub const MAX_ASSET_SYMBOL_LEN: usize = 12;
/// Longest carried-asset name.
pub const MAX_ASSET_NAME_LEN: usize = 64;

/// How a carried asset crosses between the external chain and Tenzro.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetTransfer {
    /// The external token is locked in the route's vault (the asset's
    /// `pool`) while its representation is out on Tenzro, and released from
    /// it when the representation is burned.
    LockAndMint,
    /// The issuer burns the token on the external chain and Tenzro mints the
    /// representation, and the reverse, through the issuer's own transfer
    /// protocol. The protocol is plugged into the route framework as an
    /// issuer transfer hook named `protocol`; the route runs under the
    /// relationship an account bonded as an attestor (`operator`) holds with
    /// the issuer. Without the hook installed the asset carries nothing.
    BurnAndMint {
        /// The issuer protocol's hook name.
        protocol: String,
        /// The account, 32-byte hex, bonded as an attestor, whose
        /// relationship with the issuer the route runs under.
        operator: String,
    },
}

/// A listed external token a route carries (a stablecoin such as USDC). Its
/// representation on Tenzro is one token-ledger asset per symbol, so the
/// same asset carried over routes to several chains is one fungible token
/// whose backing is spread over the routes' vaults; `max_outstanding` caps
/// how much of it any one vault backs, which bounds what an issuer freezing
/// that vault can strand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarriedAsset {
    /// Ticker (`USDC`, `OUSD`): 1..=12 ASCII uppercase letters or digits.
    pub symbol: String,
    /// Display name of the representation.
    pub name: String,
    /// Decimals of the external token; the representation uses the same.
    pub decimals: u8,
    /// The vault or token pool on the external chain that holds the token
    /// and sends it to Tenzro, left-padded to 32 bytes. For burn-and-mint,
    /// the issuer protocol's messenger.
    pub pool: [u8; 32],
    /// The token on the external chain, left-padded to 32 bytes.
    pub remote_token: [u8; 32],
    /// The token on the external chain as a CAIP-19 asset id: what an
    /// agent's terms name it by, so their limits on it hold its locked legs.
    pub caip19: String,
    /// How it crosses.
    pub transfer: AssetTransfer,
    /// Mint limits, in the asset's base units.
    pub mint_limit: MintRateLimit,
    /// The token bucket every transfer of the asset leaving Tenzro over this
    /// route draws on, in the asset's base units. Every carried asset has
    /// one: value never leaves without an outflow limit.
    pub outflow: LaneRateLimit,
    /// The pool's inbound token bucket, in the asset's base units. Required
    /// on a CCIP route, refused elsewhere.
    pub lane: Option<AssetLane>,
    /// The most of the representation this route's vault may back at once.
    #[serde(with = "u128_serde")]
    pub max_outstanding: u128,
    /// Whether the asset carries traffic. Assets ship disabled; an enacted
    /// route update enables them.
    pub enabled: bool,
}

/// A carried asset's inbound token bucket on a CCIP lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetLane {
    /// The external chain to Tenzro.
    pub inbound: LaneRateLimit,
}

impl CarriedAsset {
    /// Token-ledger id of the asset's representation on Tenzro: fixed by
    /// the symbol, so every route carrying the asset issues the same token.
    pub fn representation_id(&self) -> [u8; 32] {
        representation_id(&self.symbol)
    }

    fn validate(&self, route: &BridgeRoute) -> Result<(), String> {
        let sym = self.symbol.as_str();
        if sym.is_empty()
            || sym.len() > MAX_ASSET_SYMBOL_LEN
            || !sym
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return Err("the symbol must be 1..=12 ASCII uppercase letters or digits".into());
        }
        if sym == "TNZO" {
            return Err("TNZO is the route's own asset".into());
        }
        if self.name.is_empty() || self.name.len() > MAX_ASSET_NAME_LEN {
            return Err("the name must be 1..=64 bytes".into());
        }
        if self.decimals > 18 {
            return Err("at most 18 decimals".into());
        }
        if self.pool == [0u8; 32] || self.remote_token == [0u8; 32] {
            return Err("pool and remote_token must not be the zero address".into());
        }
        if !is_caip19(&self.caip19) {
            return Err("caip19 must be a CAIP-19 asset id".into());
        }
        if self.max_outstanding == 0 {
            return Err("max_outstanding must be positive".into());
        }
        self.mint_limit.validate().map_err(|e| e.to_string())?;
        if self.mint_limit.per_mint > self.max_outstanding {
            return Err("per_mint must not exceed max_outstanding".into());
        }
        self.outflow
            .validate("outflow")
            .map_err(|e| e.to_string())?;
        match (route.adapter, &self.lane) {
            (BridgeRouteAdapter::Ccip, None) => {
                return Err("a CCIP route needs the asset's lane limits".into());
            }
            (BridgeRouteAdapter::Ccip, Some(lane)) => {
                lane.inbound
                    .validate("inbound")
                    .map_err(|e| e.to_string())?;
                if lane.inbound.capacity > self.mint_limit.per_epoch {
                    return Err("the inbound lane capacity must not exceed per_epoch".into());
                }
            }
            (_, Some(_)) => return Err("lane limits are CCIP's; leave lane empty".into()),
            (_, None) => {}
        }
        if let AssetTransfer::BurnAndMint { protocol, operator } = &self.transfer {
            if protocol.is_empty() || protocol.len() > MAX_LABEL_LEN {
                return Err("the issuer protocol must be named".into());
            }
            if hex::decode(operator).map_or(true, |a| a.len() != 32) {
                return Err(format!(
                    "operator '{operator}' is not a 32-byte hex account"
                ));
            }
        }
        Ok(())
    }
}

/// Whether `s` has the shape of a CAIP-19 asset id,
/// `namespace:reference/asset_namespace:asset_reference`.
pub fn is_caip19(s: &str) -> bool {
    fn part(p: &str, ns_max: usize, ref_max: usize, ref_extra: &[u8]) -> bool {
        let Some((ns, r)) = p.split_once(':') else {
            return false;
        };
        (3..=ns_max).contains(&ns.len())
            && ns
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && (1..=ref_max).contains(&r.len())
            && r.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || ref_extra.contains(&b))
    }
    match s.split_once('/') {
        Some((chain, asset)) => part(chain, 8, 32, b"_") && part(asset, 8, 128, b".%:_"),
        None => false,
    }
}

/// Token-ledger id of the representation of the listed asset `symbol`.
pub fn representation_id(symbol: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(b"tenzro/bridge/representation/")
        .chain_update(symbol.to_ascii_uppercase().as_bytes())
        .finalize()
        .into()
}

/// A governed route. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRoute {
    /// The transport.
    pub adapter: BridgeRouteAdapter,
    /// The external chain's family.
    pub family: ChainFamily,
    /// The external chain's name (`"ethereum"`, `"base"`, `"solana"`).
    pub source_chain: String,
    /// The external chain's identifier as the transport carries it, such as
    /// the CCIP chain selector.
    #[serde(with = "crate::primitives::u64_serde")]
    pub source_chain_id: u64,
    /// The identifier the transport uses for Tenzro on this route (the
    /// selector assigned to the lane).
    #[serde(with = "crate::primitives::u64_serde")]
    pub local_selector: u64,
    /// The token pool on the external chain allowed to send value, left-padded
    /// to 32 bytes.
    pub peer: [u8; 32],
    /// The transport contract on the external chain that emits deliveries
    /// (the on-ramp), left-padded to 32 bytes.
    pub ramp: [u8; 32],
    /// The Tenzro-side endpoint deliveries are addressed to, left-padded to
    /// 32 bytes.
    pub local_endpoint: [u8; 32],
    /// The token on the external chain that outbound transfers mint,
    /// left-padded to 32 bytes.
    pub remote_token: [u8; 32],
    /// The committee that attests each delivery.
    pub verifiers: VerifierQuorum,
    /// A second, independent committee that must also attest. Required for
    /// CCIP, refused for every other transport.
    pub blessing: Option<VerifierQuorum>,
    /// The light client every delivery must also satisfy, with the trusted
    /// starting point it follows the external chain from. A route with one
    /// admits nothing until a verifier of that kind is installed and has been
    /// bootstrapped from the anchor.
    pub light_client: Option<LightClientAnchor>,
    /// How fast value may be minted through this route.
    pub mint_limit: MintRateLimit,
    /// The token bucket every transfer of the route's own value leaving
    /// Tenzro draws on. Every route has one: value never leaves without an
    /// outflow limit.
    pub outflow: LaneRateLimit,
    /// The CCIP lane: its on-ramp version and inbound rate limit. Required
    /// for CCIP, refused for every other transport.
    pub lane_limits: Option<CcipLane>,
    /// The IBC settings. Required for IBC, refused for every other
    /// transport.
    pub ibc: Option<IbcRoute>,
    /// The settlement lock contract on the external chain, left-padded to 32
    /// bytes: the one contract whose lock events prove a plan's remote legs
    /// on this route. None on routes that carry no locked legs.
    pub settlement_lock: Option<[u8; 32]>,
    /// Listed external tokens the route carries besides TNZO, each held on
    /// the external chain while its 1:1 representation is issued on Tenzro.
    #[serde(default)]
    pub assets: Vec<CarriedAsset>,
    /// The external chain's native coin as a CAIP-19 asset id, on routes
    /// whose locked or hash-locked legs may move it. An agent's terms name
    /// the coin by it, so their limits on it hold those legs.
    #[serde(default)]
    pub native_asset: Option<String>,
}

impl BridgeRoute {
    /// The carried asset whose symbol is `symbol` (case-insensitive).
    pub fn asset(&self, symbol: &str) -> Option<&CarriedAsset> {
        self.assets
            .iter()
            .find(|a| a.symbol.eq_ignore_ascii_case(symbol))
    }

    /// The carried asset whose pool on the external chain is `pool`.
    pub fn asset_by_pool(&self, pool: &[u8; 32]) -> Option<&CarriedAsset> {
        self.assets.iter().find(|a| &a.pool == pool)
    }

    /// The CAIP-19 id of what a leg on this route locks: the native coin
    /// for the all-zero `asset`, otherwise the carried asset whose external
    /// token it is. None when the route names no id for it.
    pub fn caip19_of(&self, asset: &[u8; 32]) -> Option<&str> {
        if *asset == [0u8; 32] {
            return self.native_asset.as_deref();
        }
        self.assets
            .iter()
            .find(|a| &a.remote_token == asset)
            .map(|a| a.caip19.as_str())
    }

    fn validate_assets(&self) -> Result<(), BridgeRouteError> {
        if let Some(native) = &self.native_asset
            && (!is_caip19(native) || self.assets.iter().any(|a| a.caip19 == *native))
        {
            return Err(BridgeRouteError::InvalidCarriedAsset {
                symbol: String::new(),
                reason: "native_asset must be a CAIP-19 asset id no carried asset uses".into(),
            });
        }
        if self.assets.len() > MAX_CARRIED_ASSETS {
            return Err(BridgeRouteError::InvalidCarriedAsset {
                symbol: String::new(),
                reason: format!("a route carries at most {MAX_CARRIED_ASSETS} assets"),
            });
        }
        if !self.assets.is_empty()
            && !matches!(
                self.adapter,
                BridgeRouteAdapter::Ccip | BridgeRouteAdapter::Contract
            )
        {
            return Err(BridgeRouteError::InvalidCarriedAsset {
                symbol: self.assets[0].symbol.clone(),
                reason: format!("the {} transport carries TNZO only", self.adapter.as_str()),
            });
        }
        let mut symbols = HashSet::new();
        let mut pools = HashSet::from([self.peer]);
        for asset in &self.assets {
            let bad = |reason: String| BridgeRouteError::InvalidCarriedAsset {
                symbol: asset.symbol.clone(),
                reason,
            };
            asset.validate(self).map_err(bad)?;
            if !symbols.insert(asset.symbol.to_ascii_uppercase()) {
                return Err(bad("listed twice on the route".into()));
            }
            if self
                .assets
                .iter()
                .filter(|a| a.caip19 == asset.caip19)
                .count()
                > 1
            {
                return Err(bad("its CAIP-19 id is another asset's".into()));
            }
            if !pools.insert(asset.pool) {
                return Err(bad(
                    "its pool is the route's TNZO pool or another asset's".into()
                ));
            }
        }
        Ok(())
    }

    /// Storage key of this route.
    pub fn storage_key(&self) -> String {
        bridge_route_storage_key(self.adapter, &self.source_chain)
    }

    /// Every cap the route sets, by name: its own limits and each carried
    /// asset's.
    fn caps(&self) -> Vec<(String, u128)> {
        let mut caps = vec![
            ("mint_limit.per_mint".to_string(), self.mint_limit.per_mint),
            (
                "mint_limit.per_epoch".to_string(),
                self.mint_limit.per_epoch,
            ),
            ("outflow.capacity".to_string(), self.outflow.capacity),
            ("outflow.rate".to_string(), self.outflow.rate),
        ];
        if let Some(lane) = &self.lane_limits {
            caps.push(("lane_limits.inbound.capacity".into(), lane.inbound.capacity));
            caps.push(("lane_limits.inbound.rate".into(), lane.inbound.rate));
        }
        for a in &self.assets {
            let s = &a.symbol;
            caps.push((format!("{s}.mint_limit.per_mint"), a.mint_limit.per_mint));
            caps.push((format!("{s}.mint_limit.per_epoch"), a.mint_limit.per_epoch));
            caps.push((format!("{s}.outflow.capacity"), a.outflow.capacity));
            caps.push((format!("{s}.outflow.rate"), a.outflow.rate));
            caps.push((format!("{s}.max_outstanding"), a.max_outstanding));
            if let Some(lane) = &a.lane {
                caps.push((format!("{s}.lane.inbound.capacity"), lane.inbound.capacity));
                caps.push((format!("{s}.lane.inbound.rate"), lane.inbound.rate));
            }
        }
        caps
    }

    /// Refuse a replacement for `current` that raises any of its caps by
    /// more than `max_raise_bps` of it in one step. Caps `current` does not
    /// set (a new asset, a new lane) have carried nothing yet and take any
    /// value; the network-wide limits still bound them.
    pub fn raised_within(
        &self,
        current: &BridgeRoute,
        max_raise_bps: u64,
    ) -> Result<(), BridgeRouteError> {
        let now: HashMap<String, u128> = current.caps().into_iter().collect();
        for (what, proposed) in self.caps() {
            if let Some(&value) = now.get(&what) {
                check_raise(
                    format!("route {} {what}", self.storage_key()),
                    value,
                    proposed,
                    max_raise_bps,
                )?;
            }
        }
        Ok(())
    }

    /// Check every rule a route that carries traffic must satisfy, its
    /// committees drawn. See the module docs.
    pub fn validate(&self) -> Result<(), BridgeRouteError> {
        self.validate_with(true)
    }

    /// Check a route as governance proposes it: every rule, with committees
    /// that name a size and threshold and no members, which are drawn on
    /// chain afterwards.
    pub fn validate_proposal(&self) -> Result<(), BridgeRouteError> {
        for (label, quorum) in [
            ("verifiers", Some(&self.verifiers)),
            ("blessing", self.blessing.as_ref()),
        ] {
            if quorum.is_some_and(|q| !q.members.is_empty()) {
                return Err(BridgeRouteError::CommitteeMembersNamed { committee: label });
            }
            if quorum.is_some_and(|q| q.set_index != 0) {
                return Err(BridgeRouteError::CommitteeIndexNamed { committee: label });
            }
        }
        self.validate_with(false)
    }

    fn validate_with(&self, drawn: bool) -> Result<(), BridgeRouteError> {
        let committee = |q: &VerifierQuorum, label: &'static str| {
            if drawn {
                q.validate(label)
            } else {
                q.validate_shape(label)
            }
        };
        let chain = self.source_chain.as_str();
        if chain.is_empty()
            || chain.len() > MAX_CHAIN_NAME_LEN
            || !chain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(BridgeRouteError::InvalidChainName(chain.to_string()));
        }
        if !self.adapter.families().contains(&self.family) {
            return Err(BridgeRouteError::FamilyNotServed {
                adapter: self.adapter,
                family: self.family,
            });
        }
        if self.source_chain_id == 0 || self.local_selector == 0 {
            return Err(BridgeRouteError::ZeroChainId);
        }
        for (field, value) in [
            ("peer", &self.peer),
            ("ramp", &self.ramp),
            ("local_endpoint", &self.local_endpoint),
            ("remote_token", &self.remote_token),
        ] {
            if *value == [0u8; 32] {
                return Err(BridgeRouteError::ZeroAddress { field });
            }
        }

        committee(&self.verifiers, "verifiers")?;

        match (self.adapter, &self.blessing) {
            (BridgeRouteAdapter::Ccip, None) => {
                return Err(BridgeRouteError::BlessingRequired);
            }
            (BridgeRouteAdapter::Ccip, Some(blessing)) => {
                committee(blessing, "blessing")?;
                let verifiers: HashSet<[u8; 20]> =
                    self.verifiers.members.iter().map(|m| m.address).collect();
                if let Some(shared) = blessing
                    .members
                    .iter()
                    .find(|m| verifiers.contains(&m.address))
                {
                    return Err(BridgeRouteError::BlessingNotIndependent(hex::encode(
                        shared.address,
                    )));
                }
            }
            (_, Some(_)) => return Err(BridgeRouteError::BlessingNotApplicable(self.adapter)),
            (_, None) => {}
        }

        if let Some(anchor) = &self.light_client {
            anchor.validate(self)?;
        }
        match (self.family.required_light_client(), &self.light_client) {
            (Some(kind), Some(anchor)) if anchor.kind() == kind => {}
            (Some(_), _) => {
                return Err(BridgeRouteError::LightClientRequired(self.family));
            }
            (None, _) => {}
        }

        self.mint_limit.validate()?;
        self.outflow.validate("outflow")?;
        match (self.adapter, &self.ibc) {
            (BridgeRouteAdapter::Ibc, None) => return Err(BridgeRouteError::IbcRouteRequired),
            (BridgeRouteAdapter::Ibc, Some(ibc)) => ibc.validate(self)?,
            (_, Some(_)) => return Err(BridgeRouteError::IbcNotApplicable(self.adapter)),
            (_, None) => {}
        }
        // A Bitcoin leg is locked in a script, not a contract.
        if self.settlement_lock.is_some() && self.family == ChainFamily::Bitcoin {
            return Err(BridgeRouteError::SettlementLockNotApplicable);
        }
        self.validate_assets()?;
        match (self.adapter, &self.lane_limits) {
            (BridgeRouteAdapter::Ccip, None) => Err(BridgeRouteError::LaneLimitsRequired),
            (BridgeRouteAdapter::Ccip, Some(lane)) => {
                if self.family == ChainFamily::Solana && lane.version != CcipLaneVersion::V1_6 {
                    return Err(BridgeRouteError::LaneVersionNotServed(lane.version));
                }
                lane.validate(&self.mint_limit)
            }
            (_, Some(_)) => Err(BridgeRouteError::LaneLimitsNotApplicable(self.adapter)),
            (_, None) => Ok(()),
        }
    }
}

/// Why a route was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BridgeRouteError {
    /// The light client cannot prove finality for this chain.
    #[error("the route's light client does not follow '{0}'")]
    LightClientNotApplicable(String),
    /// The light-client anchor is incomplete or out of bounds.
    #[error("the light-client anchor of the route to '{0}' is incomplete or out of bounds")]
    InvalidAnchor(String),
    /// The family's chain publishes what a light client needs, so its
    /// routes must carry one.
    #[error("a {0:?} route must carry its family's light client")]
    LightClientRequired(ChainFamily),
    /// A chain identifier or the local selector is zero.
    #[error("a route must name non-zero external and local chain identifiers")]
    ZeroChainId,
    /// The source chain name is empty, too long, or not lowercase ASCII.
    #[error("source chain name '{0}' must be 1..=64 lowercase ASCII letters, digits, '-' or '_'")]
    InvalidChainName(String),
    /// The transport cannot carry this chain family.
    #[error("the {adapter:?} transport does not serve {family:?} chains")]
    FamilyNotServed {
        /// The transport.
        adapter: BridgeRouteAdapter,
        /// The family.
        family: ChainFamily,
    },
    /// An address field is all zero.
    #[error("{field} must not be the zero address")]
    ZeroAddress {
        /// Which field.
        field: &'static str,
    },
    /// Too few committee members.
    #[error("{committee} has {size} members; at least {min} required")]
    CommitteeTooSmall {
        /// Which committee.
        committee: &'static str,
        /// Its size.
        size: usize,
        /// The floor.
        min: usize,
    },
    /// Too many committee members.
    #[error("{committee} has {size} members; at most {max} allowed")]
    CommitteeTooLarge {
        /// Which committee.
        committee: &'static str,
        /// Its size.
        size: usize,
        /// The ceiling.
        max: usize,
    },
    /// The threshold is below a strict majority or above the committee size.
    #[error("{committee} threshold {threshold} must be within {min}..={max}")]
    ThresholdOutOfRange {
        /// Which committee.
        committee: &'static str,
        /// The declared threshold.
        threshold: u32,
        /// Smallest acceptable threshold.
        min: usize,
        /// Largest acceptable threshold.
        max: usize,
    },
    /// A committee carries traffic only once its members are drawn.
    #[error("{committee} has not been drawn")]
    CommitteeNotDrawn {
        /// Which committee.
        committee: &'static str,
    },
    /// A proposal names committee members; members are drawn on chain.
    #[error("{committee} members are drawn from bonded attestors, never named in a proposal")]
    CommitteeMembersNamed {
        /// Which committee.
        committee: &'static str,
    },
    /// A proposal names a committee set index; the chain continues the
    /// sequence bridge contracts hold.
    #[error("{committee} set indexes are kept by the chain, never named in a proposal")]
    CommitteeIndexNamed {
        /// Which committee.
        committee: &'static str,
    },
    /// A member has no ML-DSA-65 verifying key.
    #[error("{committee} member {address} has no ML-DSA-65 verifying key; both signature legs are mandatory")]
    MissingPqKey {
        /// Which committee.
        committee: &'static str,
        /// The member's address.
        address: String,
    },
    /// A member address appears twice.
    #[error("{committee} lists member {address} twice")]
    DuplicateMember {
        /// Which committee.
        committee: &'static str,
        /// The repeated address.
        address: String,
    },
    /// A member has no operator or RPC provider label.
    #[error("{committee} member {address} must name its operator and RPC provider")]
    MissingMemberLabel {
        /// Which committee.
        committee: &'static str,
        /// The member.
        address: String,
    },
    /// A label is too long.
    #[error("{committee} has an operator or RPC provider label over 128 bytes")]
    LabelTooLong {
        /// Which committee.
        committee: &'static str,
    },
    /// One operator backs enough members to reach the threshold alone.
    #[error(
        "{committee}: operator '{operator}' runs {members} members, enough to reach the \
         threshold of {threshold} alone"
    )]
    OperatorCanReachQuorum {
        /// Which committee.
        committee: &'static str,
        /// The operator.
        operator: String,
        /// How many members it runs.
        members: usize,
        /// The threshold.
        threshold: u32,
    },
    /// One RPC provider feeds enough members to reach the threshold alone.
    #[error(
        "{committee}: RPC provider '{rpc_provider}' feeds {members} members, enough to reach \
         the threshold of {threshold} alone"
    )]
    RpcProviderCanReachQuorum {
        /// Which committee.
        committee: &'static str,
        /// The provider.
        rpc_provider: String,
        /// How many members it feeds.
        members: usize,
        /// The threshold.
        threshold: u32,
    },
    /// A CCIP route without its blessing committee.
    #[error("a CCIP route requires a blessing committee")]
    BlessingRequired,
    /// A blessing committee on a transport that has none.
    #[error("{0:?} has no blessing committee; leave blessing empty")]
    BlessingNotApplicable(BridgeRouteAdapter),
    /// The blessing committee shares a member with the verifiers.
    #[error("blessing member {0} also sits on the verifier committee")]
    BlessingNotIndependent(String),
    /// A zero per-mint cap or per-epoch limit.
    #[error("mint limit per mint and per epoch must both be non-zero")]
    ZeroMintLimit,
    /// One mint allowed more than a whole epoch.
    #[error("mint limit per mint must not exceed the per-epoch limit")]
    MintCapExceedsEpochLimit,
    /// A CCIP route without its lane rate limits.
    #[error("a CCIP route requires its lane rate limits")]
    LaneLimitsRequired,
    /// Lane rate limits on a transport that has none.
    #[error("{0:?} has no lane rate limits; leave lane_limits empty")]
    LaneLimitsNotApplicable(BridgeRouteAdapter),
    /// An IBC route without its IBC settings.
    #[error("an IBC route requires its IBC settings")]
    IbcRouteRequired,
    /// IBC settings on a transport other than IBC.
    #[error("{0:?} is not IBC; leave ibc empty")]
    IbcNotApplicable(BridgeRouteAdapter),
    /// IBC settings that are incomplete or inconsistent with the route.
    #[error("IBC route: {0}")]
    InvalidIbcRoute(String),
    /// A settlement lock on a chain family that locks legs in scripts.
    #[error("Bitcoin legs are locked in scripts, not in a settlement lock contract")]
    SettlementLockNotApplicable,
    /// A lane version the route's chain family does not run.
    #[error("CCIP lanes of this chain family do not run on-ramp {}", .0.as_str())]
    LaneVersionNotServed(CcipLaneVersion),
    /// A lane limit with a zero rate or a rate not below its capacity.
    #[error("{0} lane limit needs a non-zero rate below its capacity")]
    InvalidLaneLimit(&'static str),
    /// An inbound lane bucket larger than the route's per-epoch limit.
    #[error("the inbound lane capacity must not exceed the route's per-epoch mint limit")]
    LaneExceedsEpochLimit,
    /// Routes admitted on attestations alone are not held below routes with
    /// a light-client proof.
    #[error("the attested-route mint limits must be below the proven-route limits")]
    AttestedLimitNotLower,
    /// A carried asset that breaks the asset rules.
    #[error("carried asset '{symbol}': {reason}")]
    InvalidCarriedAsset {
        /// The asset's symbol.
        symbol: String,
        /// What is wrong.
        reason: String,
    },
    /// Network outflow limits that break the rules.
    #[error("network outflow limits: {0}")]
    InvalidOutflowLimits(String),
    /// One governance step raising a cap further than the network allows.
    #[error(
        "{what} would rise from {current} to {proposed}, past {max_raise_bps} bps of it in one step"
    )]
    CapRaisedTooFar {
        /// Which cap.
        what: String,
        /// Its value now.
        current: u128,
        /// The value proposed.
        proposed: u128,
        /// The most one step may raise a cap to, in bps of its value now.
        max_raise_bps: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(i: u8, operator: &str, rpc: &str) -> VerifierMember {
        VerifierMember {
            address: [i; 20],
            pq_public_key: vec![0u8; ML_DSA_65_VERIFYING_KEY_LEN],
            operator: operator.to_string(),
            rpc_provider: rpc.to_string(),
        }
    }

    fn committee(n: u8, threshold: u32) -> VerifierQuorum {
        VerifierQuorum {
            set_index: 0,
            size: n as u32,
            members: (1..=n)
                .map(|i| member(i, &format!("op{i}"), &format!("rpc{i}")))
                .collect(),
            threshold,
        }
    }

    fn required_anchor(family: ChainFamily) -> Option<LightClientAnchor> {
        family.required_light_client().map(|kind| match kind {
            LightClientKind::Tendermint => LightClientAnchor::Tendermint {
                chain_id: "cosmoshub-4".into(),
                trusted_height: 10,
                trusted_header_hash: [4u8; 32],
                trusting_period_secs: 1_209_600,
            },
            LightClientKind::BitcoinHeaders => LightClientAnchor::BitcoinHeaders {
                trusted_height: 2016 * 400,
                trusted_header_hash: [4u8; 32],
                confirmations: 6,
                signers: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
                threshold: 2,
                fee_rate: 5,
            },
            LightClientKind::SuiCommittee => LightClientAnchor::SuiCommittee {
                trusted_checkpoint_digest: [4u8; 32],
            },
            LightClientKind::TonValidators => LightClientAnchor::TonKeyBlock {
                trusted_seqno: 96_242_595,
                trusted_root_hash: [4u8; 32],
            },
            LightClientKind::AptosValidators => LightClientAnchor::AptosValidators {
                trusted_ledger_info_hash: [4u8; 32],
            },
            LightClientKind::StellarScp => LightClientAnchor::StellarScp {
                network_id: [4u8; 32],
                validators: vec![[1u8; 32], [2u8; 32], [3u8; 32], [5u8; 32]],
                threshold: 3,
            },
            LightClientKind::EthereumSyncCommittee => unreachable!(),
        })
    }

    fn ibc_route(version: IbcVersion) -> BridgeRoute {
        let ibc = IbcRoute {
            version,
            counterparty_client_id: "08-wasm-3".into(),
            counterparty_connection_id: (version == IbcVersion::Classic)
                .then(|| "connection-12".into()),
            counterparty_channel_id: (version == IbcVersion::Classic).then(|| "channel-141".into()),
            packet_timeout_secs: 3_600,
        };
        let mut r = BridgeRoute {
            ibc: None,
            ..route(BridgeRouteAdapter::Ccip)
        };
        r.adapter = BridgeRouteAdapter::Ibc;
        r.family = ChainFamily::Cosmos;
        r.blessing = None;
        r.lane_limits = None;
        r.light_client = required_anchor(ChainFamily::Cosmos);
        r.peer = IbcRoute::end_hash(ibc.counterparty_packet_id());
        r.local_endpoint = IbcRoute::end_hash(&ibc.tenzro_packet_id(&r.source_chain));
        {
            use sha2::Digest;
            r.remote_token = sha2::Sha256::digest(ibc.tnzo_trace().as_bytes()).into();
        }
        r.ibc = Some(ibc);
        r
    }

    fn route(adapter: BridgeRouteAdapter) -> BridgeRoute {
        if adapter == BridgeRouteAdapter::Ibc {
            return ibc_route(IbcVersion::Classic);
        }
        let family = adapter.families()[0];
        BridgeRoute {
            adapter,
            family,
            source_chain: "ethereum".into(),
            source_chain_id: 2,
            local_selector: 3,
            peer: [7u8; 32],
            ramp: [8u8; 32],
            local_endpoint: [9u8; 32],
            remote_token: [6u8; 32],
            verifiers: committee(5, 4),
            blessing: (adapter == BridgeRouteAdapter::Ccip).then(|| VerifierQuorum {
                set_index: 0,
                size: 3,
                members: (101..=103)
                    .map(|i| member(i, &format!("rmn{i}"), &format!("rrpc{i}")))
                    .collect(),
                threshold: 2,
            }),
            light_client: required_anchor(adapter.families()[0]),
            mint_limit: MintRateLimit {
                per_mint: 100,
                per_epoch: 1_000,
            },
            outflow: LaneRateLimit {
                capacity: 500,
                rate: 5,
            },
            lane_limits: (adapter == BridgeRouteAdapter::Ccip).then_some(CcipLane {
                version: CcipLaneVersion::V1_6,
                off_ramp: [0u8; 20],
                ccv_and_executor_hash: [0u8; 32],
                inbound: LaneRateLimit {
                    capacity: 500,
                    rate: 5,
                },
            }),
            ibc: None,
            settlement_lock: None,
            native_asset: None,
            assets: Vec::new(),
        }
    }

    #[test]
    fn an_ibc_route_names_its_ends_for_its_version() {
        for version in [IbcVersion::Classic, IbcVersion::V2] {
            let good = ibc_route(version);
            assert_eq!(good.validate(), Ok(()));
            let ibc = good.ibc.clone().unwrap();
            // SHA-256("ethereum") begins 0xb60d7bdd334cd376.
            let n = 0xb60d_7bdd_334c_d376_u64;
            assert_eq!(IbcRoute::identifier_number("ethereum"), n);
            assert_eq!(
                ibc.tenzro_packet_id("ethereum"),
                match version {
                    IbcVersion::Classic => format!("channel-{n}"),
                    IbcVersion::V2 => format!("07-tendermint-{n}"),
                }
            );

            let mut r = good.clone();
            r.ibc = None;
            assert_eq!(r.validate(), Err(BridgeRouteError::IbcRouteRequired));
            // The 32-byte fields must be the derived hashes.
            for field in 0..3 {
                let mut r = good.clone();
                match field {
                    0 => r.peer[0] ^= 1,
                    1 => r.local_endpoint[0] ^= 1,
                    _ => r.remote_token[0] ^= 1,
                }
                assert!(matches!(
                    r.validate(),
                    Err(BridgeRouteError::InvalidIbcRoute(_))
                ));
            }
            // A classic route names the connection and channel; v2 names none.
            let mut r = good.clone();
            let i = r.ibc.as_mut().unwrap();
            i.counterparty_connection_id = match version {
                IbcVersion::Classic => None,
                IbcVersion::V2 => Some("connection-1".into()),
            };
            assert!(matches!(
                r.validate(),
                Err(BridgeRouteError::InvalidIbcRoute(_))
            ));
            for timeout in [0, MAX_IBC_PACKET_TIMEOUT_SECS + 1] {
                let mut r = good.clone();
                r.ibc.as_mut().unwrap().packet_timeout_secs = timeout;
                assert!(matches!(
                    r.validate(),
                    Err(BridgeRouteError::InvalidIbcRoute(_))
                ));
            }
            let mut r = good.clone();
            r.ibc.as_mut().unwrap().counterparty_client_id = "short".into();
            assert!(matches!(
                r.validate(),
                Err(BridgeRouteError::InvalidIbcRoute(_))
            ));
        }
        let mut deposit = route(BridgeRouteAdapter::Deposit);
        deposit.ibc = ibc_route(IbcVersion::V2).ibc;
        assert!(matches!(
            deposit.validate(),
            Err(BridgeRouteError::IbcNotApplicable(_))
        ));
    }

    #[test]
    fn a_well_formed_route_passes_for_every_transport() {
        for adapter in BridgeRouteAdapter::ALL {
            route(adapter).validate().unwrap();
        }
    }

    #[test]
    fn a_tnzo_only_transport_carries_no_listed_asset() {
        let asset = CarriedAsset {
            symbol: "USDC".into(),
            name: "USD Coin (bridged)".into(),
            decimals: 6,
            pool: [0x61; 32],
            remote_token: [0x62; 32],
            caip19: "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
            transfer: AssetTransfer::LockAndMint,
            mint_limit: MintRateLimit {
                per_mint: 100,
                per_epoch: 1_000,
            },
            outflow: LaneRateLimit {
                capacity: 500,
                rate: 5,
            },
            lane: None,
            max_outstanding: 1_000,
            enabled: true,
        };
        for adapter in [BridgeRouteAdapter::Ibc, BridgeRouteAdapter::Deposit] {
            let mut r = route(adapter);
            r.assets = vec![asset.clone()];
            assert!(matches!(
                r.validate(),
                Err(BridgeRouteError::InvalidCarriedAsset { .. })
            ));
        }
    }

    #[test]
    fn a_transport_serves_only_its_families() {
        let mut r = route(BridgeRouteAdapter::Ccip);
        r.family = ChainFamily::Solana;
        r.validate().unwrap();
        r.family = ChainFamily::Cosmos;
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::FamilyNotServed { .. })
        ));
        let mut r = route(BridgeRouteAdapter::Deposit);
        r.family = ChainFamily::Evm;
        assert!(r.validate().is_err());
    }

    #[test]
    fn a_committee_of_one_or_two_is_refused() {
        let mut r = route(BridgeRouteAdapter::Ccip);
        r.verifiers = committee(1, 1);
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::CommitteeTooSmall { size: 1, .. })
        ));
        r.verifiers = committee(2, 2);
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::CommitteeTooSmall { size: 2, .. })
        ));
    }

    #[test]
    fn a_threshold_below_strict_majority_is_refused() {
        let mut r = route(BridgeRouteAdapter::Ccip);
        r.verifiers = committee(4, 2);
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::ThresholdOutOfRange { min: 3, .. })
        ));
        r.verifiers = committee(4, 3);
        r.validate().unwrap();
        r.verifiers = committee(4, 5);
        assert!(r.validate().is_err());
    }

    #[test]
    fn one_rpc_provider_feeding_a_quorum_is_refused() {
        let mut r = route(BridgeRouteAdapter::Ccip);
        for m in r.verifiers.members.iter_mut().take(4) {
            m.rpc_provider = "shared-rpc".into();
        }
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::RpcProviderCanReachQuorum { members: 4, .. })
        ));
    }

    #[test]
    fn one_operator_running_a_quorum_is_refused() {
        let mut r = route(BridgeRouteAdapter::Ccip);
        for m in r.verifiers.members.iter_mut().take(4) {
            m.operator = "one-org".into();
        }
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::OperatorCanReachQuorum { .. })
        ));
    }

    #[test]
    fn ccip_blessing_must_exist_and_be_independent() {
        let mut r = route(BridgeRouteAdapter::Ccip);
        r.blessing = None;
        assert_eq!(r.validate(), Err(BridgeRouteError::BlessingRequired));
        let mut r = route(BridgeRouteAdapter::Ccip);
        if let Some(b) = r.blessing.as_mut() {
            b.members[0].address = [1u8; 20];
        }
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::BlessingNotIndependent(_))
        ));
        let mut r = route(BridgeRouteAdapter::Deposit);
        r.blessing = route(BridgeRouteAdapter::Ccip).blessing;
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::BlessingNotApplicable(_))
        ));
    }

    #[test]
    fn ccip_lane_limits_must_exist_and_follow_the_pool_rules() {
        let mut r = route(BridgeRouteAdapter::Ccip);
        r.lane_limits = None;
        assert_eq!(r.validate(), Err(BridgeRouteError::LaneLimitsRequired));

        let good = route(BridgeRouteAdapter::Ccip).lane_limits.unwrap();
        let mut zero_rate = good;
        zero_rate.inbound.rate = 0;
        r.lane_limits = Some(zero_rate);
        assert_eq!(
            r.validate(),
            Err(BridgeRouteError::InvalidLaneLimit("inbound"))
        );

        let mut rate_at_capacity = good;
        rate_at_capacity.inbound.rate = rate_at_capacity.inbound.capacity;
        r.lane_limits = Some(rate_at_capacity);
        assert_eq!(
            r.validate(),
            Err(BridgeRouteError::InvalidLaneLimit("inbound"))
        );

        let mut over_epoch = good;
        over_epoch.inbound.capacity = r.mint_limit.per_epoch + 1;
        r.lane_limits = Some(over_epoch);
        assert_eq!(r.validate(), Err(BridgeRouteError::LaneExceedsEpochLimit));

        let mut deposit = route(BridgeRouteAdapter::Deposit);
        deposit.lane_limits = Some(good);
        assert!(matches!(
            deposit.validate(),
            Err(BridgeRouteError::LaneLimitsNotApplicable(_))
        ));

        // Every EVM lane version is served; Solana lanes run 1.6.0 only.
        for version in CcipLaneVersion::ALL {
            let mut evm = route(BridgeRouteAdapter::Ccip);
            evm.lane_limits = Some(CcipLane { version, ..good });
            assert_eq!(evm.validate(), Ok(()));
            let mut solana = evm.clone();
            solana.family = ChainFamily::Solana;
            let expected = if version == CcipLaneVersion::V1_6 {
                Ok(())
            } else {
                Err(BridgeRouteError::LaneVersionNotServed(version))
            };
            assert_eq!(solana.validate(), expected);
        }
        // The version is part of the route record, spelled as the on-ramp
        // spells it.
        let json = serde_json::to_value(good).unwrap();
        assert_eq!(json["version"], "1.6.0");
        assert!(
            serde_json::from_value::<CcipLane>(serde_json::json!({
                "version": "1.7.0", "inbound": json["inbound"]
            }))
            .is_err()
        );
    }

    #[test]
    fn every_route_and_carried_asset_needs_a_usable_outflow_limit() {
        for adapter in BridgeRouteAdapter::ALL {
            let r = route(adapter);
            if r.validate().is_err() {
                continue;
            }
            for (capacity, rate) in [(0, 0), (500, 0), (500, 500), (5, 500)] {
                let mut bad = r.clone();
                bad.outflow = LaneRateLimit { capacity, rate };
                assert_eq!(
                    bad.validate(),
                    Err(BridgeRouteError::InvalidLaneLimit("outflow")),
                    "{adapter:?} {capacity}/{rate}"
                );
            }
        }
        // A route record without an outflow limit does not even read.
        let mut json = serde_json::to_value(route(BridgeRouteAdapter::Ccip)).unwrap();
        json.as_object_mut().unwrap().remove("outflow");
        assert!(serde_json::from_value::<BridgeRoute>(json).is_err());
    }

    #[test]
    fn one_step_raises_a_cap_by_at_most_the_governed_factor() {
        assert!(raise_within(100, 200, 20_000));
        assert!(!raise_within(100, 201, 20_000));
        assert!(raise_within(100, 0, 20_000));
        assert!(!raise_within(0, 1, 20_000));
        assert!(raise_within(u128::MAX, u128::MAX, 20_000));
        assert!(lower_within(100, 50, 20_000));
        assert!(!lower_within(100, 49, 20_000));

        let current = route(BridgeRouteAdapter::Ccip);
        let mut doubled = current.clone();
        doubled.mint_limit.per_epoch *= 2;
        doubled.outflow.capacity *= 2;
        assert_eq!(doubled.raised_within(&current, 20_000), Ok(()));
        let mut tripled = current.clone();
        tripled.outflow.capacity *= 3;
        assert!(matches!(
            tripled.raised_within(&current, 20_000),
            Err(BridgeRouteError::CapRaisedTooFar { .. })
        ));
        let mut lowered = current.clone();
        lowered.outflow.capacity = 10;
        assert_eq!(lowered.raised_within(&current, 10_000), Ok(()));
    }

    #[test]
    fn network_outflow_limits_name_each_unit_once_with_a_cap() {
        let cap = |unit: &str, per_epoch| OutflowCap {
            unit: unit.into(),
            per_epoch,
        };
        let good = NetworkOutflowLimits {
            caps: vec![cap(TNZO_UNIT, 1_000), cap("USDC", 50)],
        };
        assert_eq!(good.validate(), Ok(()));
        assert_eq!(good.per_epoch("USDC"), Some(50));
        assert_eq!(good.per_epoch("BTC"), None);
        for bad in [
            NetworkOutflowLimits::default(),
            NetworkOutflowLimits {
                caps: vec![cap(TNZO_UNIT, 0)],
            },
            NetworkOutflowLimits {
                caps: vec![cap("usdc", 1)],
            },
            NetworkOutflowLimits {
                caps: vec![cap("USDC", 1), cap("USDC", 2)],
            },
        ] {
            assert!(matches!(
                bad.validate(),
                Err(BridgeRouteError::InvalidOutflowLimits(_))
            ));
        }
        let raised = NetworkOutflowLimits {
            caps: vec![cap(TNZO_UNIT, 2_001), cap("USDC", 50), cap("BTC", 7)],
        };
        assert!(matches!(
            raised.raised_within(&good, 20_000),
            Err(BridgeRouteError::CapRaisedTooFar { .. })
        ));
        let within = NetworkOutflowLimits {
            caps: vec![cap(TNZO_UNIT, 2_000), cap("USDC", 1), cap("BTC", 7)],
        };
        assert_eq!(within.raised_within(&good, 20_000), Ok(()));
    }

    #[test]
    fn zero_addresses_and_chain_ids_are_refused() {
        let mut r = route(BridgeRouteAdapter::Ccip);
        r.peer = [0u8; 32];
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::ZeroAddress { field: "peer" })
        ));
        let mut r = route(BridgeRouteAdapter::Ccip);
        r.ramp = [0u8; 32];
        assert!(matches!(
            r.validate(),
            Err(BridgeRouteError::ZeroAddress { field: "ramp" })
        ));
        let mut r = route(BridgeRouteAdapter::Ccip);
        r.local_selector = 0;
        assert_eq!(r.validate(), Err(BridgeRouteError::ZeroChainId));
    }

    #[test]
    fn mint_limits_must_be_non_zero_and_per_mint_within_epoch() {
        let mut r = route(BridgeRouteAdapter::Ccip);
        r.mint_limit.per_mint = 0;
        assert_eq!(r.validate(), Err(BridgeRouteError::ZeroMintLimit));
        r.mint_limit = MintRateLimit {
            per_mint: 6,
            per_epoch: 5,
        };
        assert_eq!(
            r.validate(),
            Err(BridgeRouteError::MintCapExceedsEpochLimit)
        );
    }

    #[test]
    fn storage_key_is_stable_and_lowercased() {
        assert_eq!(
            bridge_route_storage_key(BridgeRouteAdapter::Ccip, "Ethereum"),
            "bridge_route:ccip:ethereum"
        );
    }

    #[test]
    fn a_route_round_trips_through_json() {
        let r = route(BridgeRouteAdapter::Ccip);
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: BridgeRoute = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, r);
    }

    fn eth_anchor() -> LightClientAnchor {
        LightClientAnchor::EthereumSyncCommittee {
            genesis_validators_root: [1u8; 32],
            fork_version: [6, 0, 0, 0],
            trusted_block_root: [2u8; 32],
        }
    }

    #[test]
    fn a_sync_committee_light_client_is_accepted_only_for_ethereum() {
        let mut eth = route(BridgeRouteAdapter::Ccip);
        eth.source_chain = "ethereum".into();
        eth.light_client = Some(eth_anchor());
        eth.validate().unwrap();

        let mut base = eth.clone();
        base.source_chain = "base".into();
        assert_eq!(
            base.validate(),
            Err(BridgeRouteError::LightClientNotApplicable("base".into()))
        );

        let mut zero = eth.clone();
        zero.light_client = Some(LightClientAnchor::EthereumSyncCommittee {
            genesis_validators_root: [1u8; 32],
            fork_version: [6, 0, 0, 0],
            trusted_block_root: [0u8; 32],
        });
        assert!(zero.validate().is_err());

        let bytes = serde_json::to_vec(&eth).unwrap();
        assert_eq!(serde_json::from_slice::<BridgeRoute>(&bytes).unwrap(), eth);
    }

    #[test]
    fn families_with_published_commitments_require_their_light_client() {
        for adapter in BridgeRouteAdapter::ALL {
            for &family in adapter.families() {
                let mut r = route(adapter);
                r.family = family;
                r.light_client = required_anchor(family);
                let Some(kind) = family.required_light_client() else {
                    continue;
                };
                r.validate().unwrap();
                let bytes = serde_json::to_vec(&r).unwrap();
                assert_eq!(serde_json::from_slice::<BridgeRoute>(&bytes).unwrap(), r);

                r.light_client = None;
                assert_eq!(
                    r.validate(),
                    Err(BridgeRouteError::LightClientRequired(family))
                );
                // Another family's anchor does not stand in for its own.
                let other = [ChainFamily::Cosmos, ChainFamily::Sui]
                    .into_iter()
                    .find(|f| f.required_light_client() != Some(kind))
                    .unwrap();
                r.light_client = required_anchor(other);
                assert!(r.validate().is_err());
            }
        }
    }

    #[test]
    fn light_client_anchors_are_checked() {
        let mut btc = route(BridgeRouteAdapter::Deposit);
        if let Some(LightClientAnchor::BitcoinHeaders { confirmations, .. }) =
            btc.light_client.as_mut()
        {
            *confirmations = MIN_BITCOIN_CONFIRMATIONS - 1;
        }
        assert!(matches!(
            btc.validate(),
            Err(BridgeRouteError::InvalidAnchor(_))
        ));
        let mut off = route(BridgeRouteAdapter::Deposit);
        if let Some(LightClientAnchor::BitcoinHeaders { trusted_height, .. }) =
            off.light_client.as_mut()
        {
            *trusted_height += 1;
        }
        assert!(off.validate().is_err());
        // A descriptor that one signer could satisfy, that names a signer
        // twice, or that pays no withdrawal fee is refused.
        for change in 0..3 {
            let mut weak = route(BridgeRouteAdapter::Deposit);
            if let Some(LightClientAnchor::BitcoinHeaders {
                signers,
                threshold,
                fee_rate,
                ..
            }) = weak.light_client.as_mut()
            {
                match change {
                    0 => *threshold = 1,
                    1 => signers[1] = signers[0],
                    _ => *fee_rate = 0,
                }
            }
            assert!(weak.validate().is_err(), "change {change}");
        }

        let mut stellar = route(BridgeRouteAdapter::Contract);
        stellar.family = ChainFamily::Stellar;
        stellar.light_client = required_anchor(ChainFamily::Stellar);
        stellar.validate().unwrap();
        if let Some(LightClientAnchor::StellarScp { threshold, .. }) = stellar.light_client.as_mut()
        {
            *threshold = 2;
        }
        assert!(
            stellar.validate().is_err(),
            "a threshold of two thirds or less"
        );
    }

    #[test]
    fn a_ton_route_must_follow_its_key_blocks() {
        let mut ton = route(BridgeRouteAdapter::Contract);
        ton.family = ChainFamily::Ton;
        ton.light_client = required_anchor(ChainFamily::Ton);
        ton.validate().unwrap();
        ton.light_client = None;
        assert_eq!(
            ton.validate(),
            Err(BridgeRouteError::LightClientRequired(ChainFamily::Ton))
        );
        ton.light_client = Some(LightClientAnchor::TonKeyBlock {
            trusted_seqno: 0,
            trusted_root_hash: [4u8; 32],
        });
        assert!(ton.validate().is_err());
    }
}
