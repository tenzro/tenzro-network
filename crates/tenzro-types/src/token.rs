//! TNZO token economics and governance types
//!
//! This module defines types for the TNZO token, role stakes, treasury
//! management, and governance on Tenzro Network.

use crate::primitives::Address;
use serde::{Deserialize, Serialize};

/// Treasury management
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Treasury {
    /// Treasury address
    pub address: Address,
    /// Current balance (in smallest unit)
    #[serde(with = "crate::primitives::u128_serde")]
    pub balance: u128,
    /// Total allocated to grants
    #[serde(with = "crate::primitives::u128_serde")]
    pub allocated_grants: u128,
    /// Total spent on development
    #[serde(with = "crate::primitives::u128_serde")]
    pub spent_development: u128,
    /// Total spent on marketing
    #[serde(with = "crate::primitives::u128_serde")]
    pub spent_marketing: u128,
    /// Reserved for future use
    #[serde(with = "crate::primitives::u128_serde")]
    pub reserved: u128,
    /// Treasury parameters
    pub parameters: TreasuryParameters,
}

impl Treasury {
    /// Creates a new treasury
    pub fn new(address: Address, initial_balance: u128) -> Self {
        Self {
            address,
            balance: initial_balance,
            allocated_grants: 0,
            spent_development: 0,
            spent_marketing: 0,
            reserved: 0,
            parameters: TreasuryParameters::default(),
        }
    }

    /// Returns the available balance using checked arithmetic
    pub fn available_balance(&self) -> Option<u128> {
        self.balance
            .checked_sub(self.allocated_grants)?
            .checked_sub(self.reserved)
    }
}

/// Treasury parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryParameters {
    /// Maximum grant amount per proposal
    #[serde(with = "crate::primitives::u128_serde")]
    pub max_grant_amount: u128,
    /// Minimum proposal threshold
    #[serde(with = "crate::primitives::u128_serde")]
    pub min_proposal_threshold: u128,
    /// Grant approval quorum (basis points)
    pub grant_approval_quorum: u32,
}

impl Default for TreasuryParameters {
    fn default() -> Self {
        Self {
            max_grant_amount: 1_000_000u128 * 10u128.pow(18), // 1M TNZO
            min_proposal_threshold: 10_000u128 * 10u128.pow(18), // 10K TNZO
            grant_approval_quorum: 5000,                      // 50%
        }
    }
}

/// Class of a pledged accelerator, which sets its share of the compute bond.
///
/// Multipliers track the spread observed across per-GPU bonds in comparable
/// networks, where a datacentre card carries roughly five times the collateral
/// of a consumer card and integrated memory carries about half.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorClass {
    /// Integrated or unified memory — Apple Silicon, iGPU
    Integrated,
    /// Consumer discrete card
    Consumer,
    /// Workstation or inference card
    Workstation,
    /// Datacentre training card
    Datacentre,
}

impl AcceleratorClass {
    /// Share of [`COMPUTE_STAKE_PER_ACCELERATOR`] this class carries, in basis
    /// points of that base.
    ///
    /// [`COMPUTE_STAKE_PER_ACCELERATOR`]: crate::constants::COMPUTE_STAKE_PER_ACCELERATOR
    pub const fn stake_multiplier_bps(&self) -> u32 {
        match self {
            Self::Integrated => 5_000,
            Self::Consumer => 10_000,
            Self::Workstation => 20_000,
            Self::Datacentre => 50_000,
        }
    }
}

/// Capacity a provider declares when bonding, for the roles whose bond scales.
///
/// Roles that collateralise a privilege rather than a quantity pass
/// [`StakeCapacity::None`] and take their flat bond.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StakeCapacity {
    /// No capacity dimension — the role's flat bond applies.
    #[default]
    None,
    /// Accelerators pledged for rental.
    Accelerators(Vec<AcceleratorClass>),
    /// Whole terabytes of disk pledged.
    Terabytes(u32),
    /// The relying-party domain a wallet provider's passkeys are bound to,
    /// a lowercase DNS name. Only the wallet provider role declares one, and
    /// it must.
    Domain(String),
    /// The keys an attestor signs bridge deliveries with, which make it
    /// eligible to be drawn onto bridge route committees, and the RPC
    /// provider it reads source chains from. A delivery needs both legs of a
    /// member: the secp256k1 key (`address`, `proof`) and the ML-DSA-65 key
    /// (`pq_public_key`, `pq_proof`). `proof` is the secp256k1 key's
    /// recoverable signature over [`bridge_signer_digest`] of the bonding
    /// account; `pq_proof` is the ML-DSA-65 key's signature over the same
    /// digest under [`BRIDGE_SIGNER_PQ_CONTEXT`]. Only the attestor role
    /// declares one; an attestor that does not attests settlement and
    /// reserves only.
    BridgeSigner {
        /// The 20-byte signing address.
        address: [u8; 20],
        /// The RPC provider the attestor reads source chains from.
        rpc_provider: String,
        /// Recoverable secp256k1 signature, 65 bytes, hex.
        #[serde(with = "hex::serde")]
        proof: Vec<u8>,
        /// The ML-DSA-65 verifying key, 1952 bytes, hex.
        #[serde(with = "hex::serde")]
        pq_public_key: Vec<u8>,
        /// ML-DSA-65 signature, 3309 bytes, hex.
        #[serde(with = "hex::serde")]
        pq_proof: Vec<u8>,
    },
}

/// FIPS 204 context under which a bridge signer's ML-DSA-65 key signs
/// [`bridge_signer_digest`] to bind itself to a bonding account.
pub const BRIDGE_SIGNER_PQ_CONTEXT: &[u8] = b"tenzro/bridge/signer/ml-dsa-65";

/// Digest a bridge signer key signs to bind itself to the `account` bonding
/// with it.
pub fn bridge_signer_digest(account: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(b"tenzro/bridge/signer");
    h.update(account);
    h.finalize().into()
}

/// An operation on the sender's stake for one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakeOp {
    /// Add `amount` to the sender's bond for `role`, declaring `capacity`.
    /// The bond after it must meet the role's required stake for that
    /// capacity. The validator role bonds through `RegisterValidator`.
    Bond {
        /// The role.
        #[serde(with = "crate::network::role_token")]
        role: crate::network::NetworkRole,
        /// Amount to bond, wei.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// Capacity the bond backs.
        #[serde(default)]
        capacity: StakeCapacity,
    },
    /// Move `amount` of the bond for `role` into unbonding. What stays bonded
    /// must be zero or still meet the role's required stake.
    Unbond {
        /// The role.
        #[serde(with = "crate::network::role_token")]
        role: crate::network::NetworkRole,
        /// Amount to unbond, wei.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// Return the sender's unbonded stake for `role` once its unbonding
    /// period has passed.
    Withdraw {
        /// The role.
        #[serde(with = "crate::network::role_token")]
        role: crate::network::NetworkRole,
    },
    /// Publish the public `https` URL the sender serves `role` at, or clear
    /// it with an empty `url`. Needs a bond for the role. Clients find a
    /// role's operators from these URLs in consensus state, so no one list
    /// or domain decides which operators they can reach.
    Endpoint {
        /// The role.
        #[serde(with = "crate::network::role_token")]
        role: crate::network::NetworkRole,
        /// `https://host[:port][/path]`, at most [`MAX_ROLE_ENDPOINT_LEN`]
        /// bytes; empty clears it.
        url: String,
    },
}

/// Longest role endpoint URL, bytes.
pub const MAX_ROLE_ENDPOINT_LEN: usize = 256;

/// Check a role endpoint URL: `https`, a host name or public address, no
/// credentials, whitespace or fragment, and at most
/// [`MAX_ROLE_ENDPOINT_LEN`] bytes.
pub fn check_role_endpoint(url: &str) -> Result<(), String> {
    if url.len() > MAX_ROLE_ENDPOINT_LEN {
        return Err(format!(
            "the endpoint is longer than {MAX_ROLE_ENDPOINT_LEN} bytes"
        ));
    }
    if url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err("the endpoint contains whitespace or control characters".into());
    }
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "the endpoint must be an https:// URL".to_string())?;
    if rest.contains('#') {
        return Err("the endpoint carries a fragment".into());
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.contains('@') {
        return Err("the endpoint carries credentials".into());
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split_once(']').map(|(h, _)| h).unwrap_or(""),
        None => authority.rsplit_once(':').map_or(authority, |(h, port)| {
            if port.parse::<u16>().is_ok() {
                h
            } else {
                authority
            }
        }),
    };
    if host.is_empty() {
        return Err("the endpoint has no host".into());
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
    {
        return Err("the endpoint names a local host".into());
    }
    if let Ok(ip) = lower.parse::<std::net::IpAddr>() {
        let public = match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || (o[0] == 100 && (64..128).contains(&o[1])))
            }
            std::net::IpAddr::V6(v6) => {
                let seg = v6.segments();
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || (seg[0] & 0xfe00) == 0xfc00
                    || (seg[0] & 0xffc0) == 0xfe80)
            }
        };
        if !public {
            return Err("the endpoint names a non-public address".into());
        }
    }
    Ok(())
}

/// One account's stake for one role, as consensus state holds it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleStake {
    /// Bonded, wei.
    #[serde(with = "crate::primitives::u128_serde")]
    pub bonded: u128,
    /// Capacity the bond backs.
    pub capacity: StakeCapacity,
    /// Unbonding, wei.
    #[serde(with = "crate::primitives::u128_serde")]
    pub unbonding: u128,
    /// Block time the unbonding stake can be withdrawn at, ms.
    pub release_at_ms: i64,
    /// Block time the bond last grew or changed capacity, ms; zero for a
    /// genesis bond. A draw counts a bond only once it predates the draw's
    /// randomness.
    #[serde(default)]
    pub bonded_at_ms: i64,
    /// The public URL the account serves the role at, when it published one
    /// (see [`StakeOp::Endpoint`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl std::str::FromStr for AcceleratorClass {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "integrated" | "unified" | "igpu" => Ok(Self::Integrated),
            "consumer" => Ok(Self::Consumer),
            "workstation" => Ok(Self::Workstation),
            "datacentre" | "datacenter" => Ok(Self::Datacentre),
            _ => Err(format!(
                "unknown accelerator class '{s}' (expected one of: integrated, \
                 consumer, workstation, datacentre)"
            )),
        }
    }
}

/// A change to network policy decided by on-chain governance
/// (`ProposalAction::PolicyUpdate` in tenzro-vm). Consensus records the
/// decision; every node applies it to the subsystem it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyUpdate {
    /// Protocol upgrade: the release version and the SHA-256 of its code.
    ProtocolUpgrade { version: String, code_hash: Vec<u8> },
    /// Sets the live [`crate::economics::EconomicPolicy`] — every rate the
    /// network charges, in one proposal.
    ///
    /// Carries the whole policy rather than a field at a time so a proposal is
    /// self-describing and cannot leave the schedules half-applied: a change
    /// that moved the operator's share without moving anyone else's would not
    /// sum to a whole payment, and would be refused at execution anyway.
    /// Validation runs before it is stored, so a rejected proposal leaves the
    /// previous policy live.
    EconomicPolicyUpdate {
        /// The complete policy to apply.
        policy: crate::economics::EconomicPolicy,
    },
    /// Adaptive-burn dial update. Sets the live `BurnRateConfig`
    /// applied by the EIP-1559 fee market and the local-fee router.
    AdaptiveBurnConfigUpdate {
        base_fee_burn_bps: u16,
        local_fee_burn_bps: u16,
    },
    /// Adaptive-burn supply-targets update. Adjusts the rolling
    /// window, neutral band, alarm thresholds, gain, and magnitude caps
    /// the auto-proposal generator uses to draft `AdaptiveBurnConfigUpdate`
    /// proposals. `target_annual_supply_bps` is at most 0: TNZO supply is
    /// fixed at genesis, so a proposal aiming at a rising supply is refused.
    /// `inflation_alarm_bps` is the supply-increase alarm threshold.
    SupplyTargetsUpdate {
        epoch_neutral_band_bps: u16,
        rolling_window_epochs: u32,
        inflation_alarm_bps: u16,
        deflation_alarm_bps: u16,
        target_annual_supply_bps: i32,
        gain_bps_per_pct: u16,
        magnitude_cap_normal_bps: u16,
        magnitude_cap_alarm_bps: u16,
        auto_proposal_min_magnitude_bps: u16,
        alarm_fast_track_enabled: bool,
    },
    /// Replace the TPM manufacturer roots (PEM) an endorsement certificate
    /// must chain to where the network asks for a manufacturer-certified
    /// TPM. Empty recognises none.
    TpmEndorsementRootsSet { roots_pem: Vec<String> },
    /// Replace the GPU device identity roots (PEM) a GPU's per-device
    /// certificate chain must end at for the GPU to count as a second
    /// hardware scheme. Empty recognises none.
    GpuDeviceRootsSet { roots_pem: Vec<String> },
    /// Replace NVIDIA's reference values a GPU report's measurements must
    /// match for the GPU to count. Empty recognises none.
    GpuReferenceValuesSet {
        references: Vec<crate::hardware_level::GpuReferenceValue>,
    },
    /// Set what one bridge route may carry: open it, disable it (wind it
    /// down) or pause it. Governance is the only way to open a route,
    /// whoever stopped it; disabling or pausing may take the expedited track.
    BridgeCircuitSet {
        /// The route's bridge protocol.
        adapter: crate::bridge_route::BridgeRouteAdapter,
        /// The route's external chain, as the route names it.
        source_chain: String,
        /// The mode to set.
        mode: crate::bridge_route::BridgeRouteMode,
        /// Why, recorded with a disable or a pause.
        reason: String,
    },
    /// Set the network-wide mint limits every bridge route is bound by, on
    /// top of the route's own limits.
    BridgeMintLimitsSet {
        /// The limits.
        limits: crate::bridge_route::NetworkMintLimits,
    },
    /// Set the network-wide outflow caps: for each unit, the most that may
    /// leave Tenzro over every bridge route together in one epoch.
    BridgeOutflowLimitsSet {
        /// The caps.
        limits: crate::bridge_route::NetworkOutflowLimits,
    },
    /// Set the finality program: the image id of the zkVM guest whose
    /// wrapped proofs the chain accepts as finality proofs.
    FinalityProgramSet {
        /// The guest program's image id.
        #[serde(with = "crate::agent_audit::hex32")]
        image_id: [u8; 32],
    },
    /// Set the handover program: the image id of the zkVM guest whose
    /// proofs of the epoch handover chain nodes keep in place of the
    /// handovers themselves.
    HandoverProgramSet {
        /// The guest program's image id.
        #[serde(with = "crate::agent_audit::hex32")]
        image_id: [u8; 32],
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkRole;

    #[test]
    fn a_wallet_bond_round_trips_through_json_and_the_binary_codec() {
        let op = StakeOp::Bond {
            role: NetworkRole::WalletProvider,
            amount: crate::constants::MIN_WALLET_PROVIDER_STAKE,
            capacity: StakeCapacity::Domain("wallet.example".into()),
        };
        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["bond"]["role"], "wallet");
        assert_eq!(json["bond"]["capacity"]["domain"], "wallet.example");
        assert_eq!(serde_json::from_value::<StakeOp>(json).unwrap(), op);
        let tx = crate::transaction::TransactionType::Stake { op: op.clone() };
        let bin = bincode::serialize(&tx).unwrap();
        let back: crate::transaction::TransactionType = bincode::deserialize(&bin).unwrap();
        assert!(matches!(back, crate::transaction::TransactionType::Stake { op: o } if o == op));
    }
}

#[cfg(test)]
mod role_endpoint_tests {
    use super::check_role_endpoint;

    #[test]
    fn a_role_endpoint_is_a_public_https_url() {
        for ok in [
            "https://rpc.operator.example",
            "https://rpc.operator.example:8443/rpc",
            "https://[2001:4860::8888]/",
        ] {
            assert!(check_role_endpoint(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://rpc.operator.example",
            "https://",
            "https://localhost:8545",
            "https://10.0.0.5",
            "https://100.64.0.2",
            "https://127.0.0.1",
            "https://[fd00::1]",
            "https://user:pw@rpc.operator.example",
            "https://rpc.operator.example/#x",
            "https://rpc.operator.example/ x",
        ] {
            assert!(check_role_endpoint(bad).is_err(), "{bad}");
        }
        assert!(check_role_endpoint(&format!("https://{}.example", "a".repeat(260))).is_err());
    }
}
