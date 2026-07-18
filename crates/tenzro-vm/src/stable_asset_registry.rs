//! StableAssetRegistry — per-issuer stable-asset policy store.
//!
//! A *stable asset* is a unit token an issuer mints against a tiered
//! backing: a hard reserve floor (enforced by
//! [`crate::secure_mint::SecureMintRegistry`] on the same `unit_token`) plus
//! an AI-tuned crypto buffer above it managed by
//! [`crate::stable_controller::StableController`]. This registry holds the
//! *configuration* for each issuer's unit — it does not itself mint, hold
//! reserves, or run the controller; it is the binding that ties those
//! components together and the lookup the issuance RPC consults.
//!
//! The registry is issuer-agnostic. Any subject that holds an `issuer`-scoped
//! API key can register a unit; isolation is by `(issuer, unit_token)` so two
//! issuers' policies never collide.
//!
//! Persistence mirrors [`SecureMintRegistry`]: write-through to
//! [`tenzro_storage::CF_TOKENS`] under `stable_asset:<issuer32><unit20>` with
//! hydration on startup.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use tenzro_types::primitives::Address;

use crate::stable_controller::StableControllerConfig;

/// Errors raised by the stable-asset registry.
#[derive(Debug, Error)]
pub enum StableAssetError {
    /// No policy registered for this `(issuer, unit)` pair.
    #[error("no stable-asset policy for issuer {issuer} unit {unit}")]
    NotConfigured {
        /// Hex issuer address.
        issuer: String,
        /// Hex unit-token address.
        unit: String,
    },

    /// The supplied controller config failed validation.
    #[error("invalid controller config: {0}")]
    InvalidController(String),

    /// A rail listed in `allowed_rails` is not a recognized rail tag.
    #[error("unknown payment rail: {0}")]
    UnknownRail(String),

    /// `allowed_rails` was empty — a unit with no settlement rail can never
    /// be spent by an agent.
    #[error("allowed_rails must list at least one rail")]
    NoRails,
}

/// Where the hard reserve floor is sourced from. The registry stores the
/// descriptor; the actual attestation lives in the SecureMint policy on the
/// same `unit_token`. This field records the issuer's declared intent for
/// audit and for the PoR adapter to resolve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ReserveSource {
    /// Off-chain fiat / RWA custody attested by a named attester DID.
    Custodial {
        /// DID of the custodian attester.
        attester_did: String,
        /// CAIP-19 id of the reserve asset (e.g. tokenized T-bill).
        asset_caip19: String,
    },
    /// On-chain collateral held in a vault contract on this chain.
    OnChainVault {
        /// Vault contract address.
        vault: Address,
        /// CAIP-19 id of the collateral asset.
        asset_caip19: String,
    },
}

/// A payment rail an issuer permits its unit to settle over. Mirrors the
/// rail tags routed by `tenzro-payments`' gateway; the registry validates
/// against this closed set so a typo can't silently disable settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentRail {
    /// HTTP 402 agent-native micropayments.
    X402,
    /// Agent Payments Protocol mandate/cart flow.
    Ap2,
    /// Merchant payment protocol.
    Mpp,
    /// Visa Tokenized Asset Platform.
    VisaTap,
    /// Mastercard rail.
    Mastercard,
    /// Tempo settlement rail.
    Tempo,
    /// Open Standard consortium settlement (OUSD and other Open Standard
    /// units). Issuer-neutral rail; the unit settled is carried by the
    /// reserve `asset_caip19`, not the rail tag.
    OpenStandard,
    /// Direct on-chain transfer (no external rail).
    Native,
}

impl PaymentRail {
    /// Parse a lowercase rail tag, the form carried in RPC params.
    pub fn parse(tag: &str) -> Result<Self, StableAssetError> {
        Ok(match tag {
            "x402" => Self::X402,
            "ap2" => Self::Ap2,
            "mpp" => Self::Mpp,
            "visa_tap" | "visa-tap" => Self::VisaTap,
            "mastercard" => Self::Mastercard,
            "tempo" => Self::Tempo,
            "open_standard" | "open-standard" | "ousd" => Self::OpenStandard,
            "native" => Self::Native,
            other => return Err(StableAssetError::UnknownRail(other.to_string())),
        })
    }
}

/// Per-issuer stable-asset policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableAssetPolicy {
    /// Issuer subject — the API-key subject that registered this unit.
    pub issuer: Address,
    /// The unit token (20-byte EVM address). The SecureMint policy keyed by
    /// the same 20 bytes enforces the reserve floor.
    pub unit_token: [u8; 20],
    /// Human label for the unit (e.g. "USDX").
    pub symbol: String,
    /// Declared reserve source for the hard floor.
    pub reserve_source: ReserveSource,
    /// PoR feed id resolving the reserve attestation. Format is opaque;
    /// canonical adapters are `chainlink:<addr>` and `tenzro:<did>`.
    pub por_feed_id: String,
    /// The leaky-PI controller config for the buffer above the floor.
    pub controller: StableControllerConfig,
    /// Rails this unit may settle over.
    pub allowed_rails: Vec<PaymentRail>,
    /// Destination address that receives converted proceeds on settlement.
    pub settlement_dst: Address,
    /// Unix-seconds creation time.
    pub created_at: u64,
}

impl StableAssetPolicy {
    /// Whether `rail` is permitted for this unit.
    pub fn allows_rail(&self, rail: PaymentRail) -> bool {
        self.allowed_rails.contains(&rail)
    }
}

const PREFIX: &[u8] = b"stable_asset:";
// issuer is Address([u8;32]); unit is [u8;20].
const ISSUER_LEN: usize = 32;
const UNIT_LEN: usize = 20;

fn policy_key(issuer: &Address, unit: &[u8; 20]) -> Vec<u8> {
    let mut k = PREFIX.to_vec();
    k.extend_from_slice(&issuer.0);
    k.extend_from_slice(unit);
    k
}

/// In-memory registry of stable-asset policies keyed by `(issuer, unit)`.
#[derive(Default)]
pub struct StableAssetRegistry {
    inner: RwLock<HashMap<(Address, [u8; 20]), StableAssetPolicy>>,
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl std::fmt::Debug for StableAssetRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StableAssetRegistry")
            .field("policies", &self.inner.read().len())
            .field("persistent", &self.storage.is_some())
            .finish()
    }
}

impl StableAssetRegistry {
    /// Build an empty registry (test-only; production should use
    /// `with_storage`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Production constructor: write-through to `CF_TOKENS` with hydration
    /// on startup. Without persistence, every restart drops issuer policies
    /// and the issuance RPC reports every unit as unconfigured.
    pub fn with_storage(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        let r = Self {
            inner: RwLock::new(HashMap::new()),
            storage: Some(storage),
        };
        r.hydrate();
        r
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        let entries = match storage.scan_prefix(tenzro_storage::CF_TOKENS, PREFIX) {
            Ok(e) => e,
            Err(_) => return,
        };
        let want = PREFIX.len() + ISSUER_LEN + UNIT_LEN;
        let mut map = self.inner.write();
        for (key, value) in entries {
            if key.len() < want {
                continue;
            }
            let mut issuer = [0u8; ISSUER_LEN];
            issuer.copy_from_slice(&key[PREFIX.len()..PREFIX.len() + ISSUER_LEN]);
            let mut unit = [0u8; UNIT_LEN];
            unit.copy_from_slice(&key[PREFIX.len() + ISSUER_LEN..want]);
            if let Ok(policy) = serde_json::from_slice::<StableAssetPolicy>(&value) {
                map.insert((Address(issuer), unit), policy);
            }
        }
    }

    fn persist(&self, policy: &StableAssetPolicy) {
        if let Some(ref storage) = self.storage
            && let Ok(bytes) = serde_json::to_vec(policy)
        {
            let _ = storage.put(
                tenzro_storage::CF_TOKENS,
                &policy_key(&policy.issuer, &policy.unit_token),
                &bytes,
            );
        }
    }

    fn forget(&self, issuer: &Address, unit: &[u8; 20]) {
        if let Some(ref storage) = self.storage {
            let _ = storage.delete(tenzro_storage::CF_TOKENS, &policy_key(issuer, unit));
        }
    }

    /// Register or replace an issuer's stable-asset policy. Validates the
    /// controller config and the rail set before storing. Returns the prior
    /// policy if one existed.
    pub fn register(
        &self,
        policy: StableAssetPolicy,
    ) -> Result<Option<StableAssetPolicy>, StableAssetError> {
        policy
            .controller
            .validate()
            .map_err(StableAssetError::InvalidController)?;
        if policy.allowed_rails.is_empty() {
            return Err(StableAssetError::NoRails);
        }
        self.persist(&policy);
        let key = (policy.issuer, policy.unit_token);
        Ok(self.inner.write().insert(key, policy))
    }

    /// Snapshot the policy for `(issuer, unit)`.
    pub fn policy(&self, issuer: &Address, unit: &[u8; 20]) -> Option<StableAssetPolicy> {
        self.inner.read().get(&(*issuer, *unit)).cloned()
    }

    /// Look up a policy by unit token alone, scanning across issuers. The
    /// settlement path knows the unit being spent but not necessarily the
    /// issuer; `(issuer, unit)` is unique per the SecureMint floor binding,
    /// so the first match is authoritative.
    pub fn policy_by_unit(&self, unit: &[u8; 20]) -> Option<StableAssetPolicy> {
        self.inner
            .read()
            .values()
            .find(|p| &p.unit_token == unit)
            .cloned()
    }

    /// Snapshot every registered policy. The controller driver enumerates
    /// these to run one peg/buffer epoch per issued unit.
    pub fn all(&self) -> Vec<StableAssetPolicy> {
        self.inner.read().values().cloned().collect()
    }

    /// Require a policy for `(issuer, unit)`, erroring if absent.
    pub fn require(
        &self,
        issuer: &Address,
        unit: &[u8; 20],
    ) -> Result<StableAssetPolicy, StableAssetError> {
        self.policy(issuer, unit)
            .ok_or_else(|| StableAssetError::NotConfigured {
                issuer: hex::encode(issuer.0),
                unit: hex::encode(unit),
            })
    }

    /// Remove the policy for `(issuer, unit)`. Returns true if one was
    /// removed.
    pub fn deregister(&self, issuer: &Address, unit: &[u8; 20]) -> bool {
        let removed = self.inner.write().remove(&(*issuer, *unit)).is_some();
        if removed {
            self.forget(issuer, unit);
        }
        removed
    }

    /// Active policy count.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether no policies are installed.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

/// Shareable handle around a [`StableAssetRegistry`].
pub type SharedStableAssetRegistry = Arc<StableAssetRegistry>;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> StableAssetPolicy {
        StableAssetPolicy {
            issuer: Address([7u8; 32]),
            unit_token: [9u8; 20],
            symbol: "TEST".into(),
            reserve_source: ReserveSource::Custodial {
                attester_did: "did:tenzro:human:custodian".into(),
                asset_caip19: "eip155:539/erc20:0xreserve".into(),
            },
            por_feed_id: "chainlink:0xfeed".into(),
            controller: StableControllerConfig::default(),
            allowed_rails: vec![PaymentRail::X402, PaymentRail::Ap2],
            settlement_dst: Address([3u8; 32]),
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn register_and_lookup() {
        let reg = StableAssetRegistry::new();
        let p = sample_policy();
        assert!(reg.register(p.clone()).unwrap().is_none());
        let got = reg.policy(&p.issuer, &p.unit_token).unwrap();
        assert_eq!(got.symbol, "TEST");
        assert!(got.allows_rail(PaymentRail::X402));
        assert!(!got.allows_rail(PaymentRail::Tempo));
    }

    #[test]
    fn register_rejects_empty_rails() {
        let reg = StableAssetRegistry::new();
        let mut p = sample_policy();
        p.allowed_rails.clear();
        assert!(matches!(
            reg.register(p).unwrap_err(),
            StableAssetError::NoRails
        ));
    }

    #[test]
    fn register_rejects_bad_controller() {
        let reg = StableAssetRegistry::new();
        let mut p = sample_policy();
        // trip >= warn must fail validation.
        p.controller.trip_buffer_bps = p.controller.warn_buffer_bps + 1;
        assert!(matches!(
            reg.register(p).unwrap_err(),
            StableAssetError::InvalidController(_)
        ));
    }

    #[test]
    fn replace_returns_prior() {
        let reg = StableAssetRegistry::new();
        let p = sample_policy();
        reg.register(p.clone()).unwrap();
        let mut p2 = p.clone();
        p2.symbol = "TEST2".into();
        let prior = reg.register(p2).unwrap().unwrap();
        assert_eq!(prior.symbol, "TEST");
        assert_eq!(reg.policy(&p.issuer, &p.unit_token).unwrap().symbol, "TEST2");
    }

    #[test]
    fn lookup_by_unit() {
        let reg = StableAssetRegistry::new();
        let p = sample_policy();
        reg.register(p.clone()).unwrap();
        let got = reg.policy_by_unit(&p.unit_token).unwrap();
        assert_eq!(got.issuer, p.issuer);
    }

    #[test]
    fn require_errors_when_absent() {
        let reg = StableAssetRegistry::new();
        let err = reg.require(&Address([1u8; 32]), &[2u8; 20]).unwrap_err();
        assert!(matches!(err, StableAssetError::NotConfigured { .. }));
    }

    #[test]
    fn deregister_removes() {
        let reg = StableAssetRegistry::new();
        let p = sample_policy();
        reg.register(p.clone()).unwrap();
        assert!(reg.deregister(&p.issuer, &p.unit_token));
        assert!(reg.policy(&p.issuer, &p.unit_token).is_none());
        assert!(!reg.deregister(&p.issuer, &p.unit_token));
    }

    #[test]
    fn rail_parse_roundtrip() {
        assert_eq!(PaymentRail::parse("x402").unwrap(), PaymentRail::X402);
        assert_eq!(PaymentRail::parse("visa-tap").unwrap(), PaymentRail::VisaTap);
        assert_eq!(PaymentRail::parse("visa_tap").unwrap(), PaymentRail::VisaTap);
        assert!(matches!(
            PaymentRail::parse("paypal").unwrap_err(),
            StableAssetError::UnknownRail(_)
        ));
    }
}
