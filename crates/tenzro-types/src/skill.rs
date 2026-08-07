//! Skill registry types for Tenzro Network
//!
//! Defines types for the decentralized skills registry where
//! agents and providers can publish callable skills for others to
//! discover, invoke, and pay for autonomously.

use crate::primitives::Address;
use serde::{Deserialize, Serialize};

/// Creator DID reserved for node-provided builtin skills and tools.
/// Rows with this creator are registered by the node itself at boot:
/// their liveness is the node's liveness, so the staleness sweeper
/// exempts them, and the registration RPCs refuse third-party rows
/// claiming this DID.
pub const SYSTEM_CREATOR_DID: &str = "did:tenzro:system:tenzro-network";

/// Status of a skill in the registry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum SkillStatus {
    /// Skill is published and available for invocation
    #[default]
    Active,
    /// Skill has been deactivated by its creator
    Inactive,
    /// Skill has been deprecated (superseded by a newer version)
    Deprecated,
}

/// URI prefix for a content-addressed blob locator.
pub const BLOB_URI_PREFIX: &str = "tenzro://blob/";

/// Content-addressed executable artifact backing a skill.
///
/// The registry is permissionless: nothing decides who may publish, so a
/// caller's protection is naming the exact bytes it is willing to run.
/// `uri` is a `tenzro://blob/<blake3-hex>` locator, so iroh-blobs verifies
/// BLAKE3 over the wire on fetch. `sha256` is the canonical Tenzro hash of
/// the same bytes, declared by the publisher, so a caller can pin the
/// artifact without having to trust the transport that delivered it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillBundle {
    /// `tenzro://blob/<blake3-hex>` locator for the artifact bytes.
    pub uri: String,

    /// Hex-encoded SHA-256 of the artifact bytes (64 lowercase chars).
    pub sha256: String,

    /// Size of the artifact in bytes.
    pub size_bytes: u64,
}

impl SkillBundle {
    /// The 64-char BLAKE3 hex from the `tenzro://blob/` locator.
    pub fn blake3_hex(&self) -> &str {
        &self.uri[BLOB_URI_PREFIX.len()..]
    }

    /// Reject a bundle whose locator or hash cannot name bytes.
    pub fn validate(&self) -> Result<(), SkillPinError> {
        let Some(blake3_hex) = self.uri.strip_prefix(BLOB_URI_PREFIX) else {
            return Err(SkillPinError::MalformedBundle(format!(
                "bundle uri must start with {BLOB_URI_PREFIX}"
            )));
        };
        if !is_hash_hex(blake3_hex) {
            return Err(SkillPinError::MalformedBundle(
                "bundle uri must carry a 64-char lowercase hex BLAKE3 hash".to_string(),
            ));
        }
        if !is_hash_hex(&self.sha256) {
            return Err(SkillPinError::MalformedBundle(
                "bundle sha256 must be a 64-char lowercase hex digest".to_string(),
            ));
        }
        if self.size_bytes == 0 {
            return Err(SkillPinError::MalformedBundle(
                "bundle size_bytes must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

fn is_hash_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Why a caller's version/hash pin was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillPinError {
    /// The registry row declares a different version than the caller pinned.
    VersionMismatch { expected: String, actual: String },
    /// The caller pinned an artifact hash but the row publishes no bundle.
    NoBundlePublished,
    /// The registry row's artifact is not the one the caller pinned.
    HashMismatch { expected: String, actual: String },
    /// The bundle recorded on the row (or the pin itself) is not well-formed.
    MalformedBundle(String),
}

impl std::fmt::Display for SkillPinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionMismatch { expected, actual } => write!(
                f,
                "version pin refused: caller pinned '{expected}', registry holds '{actual}'"
            ),
            Self::NoBundlePublished => write!(
                f,
                "artifact pin refused: skill publishes no content-addressed bundle to pin against"
            ),
            Self::HashMismatch { expected, actual } => write!(
                f,
                "artifact pin refused: caller pinned sha256 {expected}, registry holds {actual}"
            ),
            Self::MalformedBundle(why) => write!(f, "malformed bundle: {why}"),
        }
    }
}

impl std::error::Error for SkillPinError {}

/// A callable skill published to the Tenzro Network skills registry
///
/// Skills are atomic, reusable capabilities that agents can discover
/// and invoke autonomously. Each skill specifies its interface (input/output
/// schemas), pricing, and the endpoint to call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDefinition {
    /// Unique skill identifier (UUID v4)
    pub skill_id: String,

    /// Human-readable skill name (e.g., "web-search", "code-review")
    pub name: String,

    /// Semantic version string (e.g., "1.0.0")
    pub version: String,

    /// DID of the agent or human who registered this skill
    pub creator_did: String,

    /// Payout wallet for the creator's share of paid invocations.
    /// **Mandatory** for any non-zero `price_per_call`; registration
    /// fails (`SkillError::MissingCreatorWallet`) if omitted for a
    /// paid skill. Free skills (`price_per_call == 0`) may leave this
    /// `None`.
    pub creator_wallet: Option<Address>,

    /// Description of what this skill does
    pub description: String,

    /// JSON Schema describing the expected input payload
    pub input_schema: serde_json::Value,

    /// JSON Schema describing the output payload
    pub output_schema: serde_json::Value,

    /// Price per invocation in TNZO atto-tokens (1 TNZO = 10^18 atto)
    #[serde(with = "crate::primitives::u128_serde")]
    pub price_per_call: u128,

    /// Discoverability tags (e.g., ["search", "web", "retrieval"])
    pub tags: Vec<String>,

    /// Required agent capabilities to invoke this skill
    pub required_capabilities: Vec<String>,

    /// Optional HTTP/RPC endpoint for remote invocation
    /// If None, the skill is executed locally by the registered agent
    pub endpoint: Option<String>,

    /// Content-addressed artifact the skill runs, when the publisher supplies
    /// bytes rather than only pointing at an `endpoint`. Callers pin
    /// `bundle.sha256` at invocation time to fix exactly which artifact
    /// they are paying to run.
    pub bundle: Option<SkillBundle>,

    /// Unix timestamp (seconds) when the skill was registered
    pub created_at: u64,

    /// Current status of the skill
    pub status: SkillStatus,

    /// Category for organization (e.g., "ai", "defi", "data", "general")
    #[serde(default = "default_skill_category")]
    pub category: String,

    /// Number of times this skill has been invoked
    pub invocation_count: u64,

    /// Average rating (0–100, weighted by stake of raters)
    pub rating: u8,

    /// Unix timestamp (seconds) of the last liveness signal (registration,
    /// invocation, or explicit `tenzro_heartbeatSkill` call). The liveness
    /// sweeper uses this to flip `status` to `Inactive` once the skill goes
    /// silent past the configured TTL, and eventually purges rows that stay
    /// inactive past the purge window. Existing rows without this field
    /// hydrate as "seen now" via the `default_last_seen` serde default —
    /// stale entries surface only after they actually go silent post-upgrade.
    #[serde(default = "default_last_seen")]
    pub last_seen_at: u64,
}

fn default_skill_category() -> String {
    "general".to_string()
}

fn default_last_seen() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl SkillDefinition {
    /// Creates a new skill definition with default values
    pub fn new(
        name: String,
        version: String,
        creator_did: String,
        description: String,
        price_per_call: u128,
    ) -> Self {
        let skill_id = uuid::Uuid::new_v4().to_string();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            skill_id,
            name,
            version,
            creator_did,
            creator_wallet: None,
            description,
            input_schema: serde_json::Value::Object(serde_json::Map::new()),
            output_schema: serde_json::Value::Object(serde_json::Map::new()),
            price_per_call,
            tags: Vec::new(),
            required_capabilities: Vec::new(),
            endpoint: None,
            bundle: None,
            created_at,
            status: SkillStatus::Active,
            category: default_skill_category(),
            invocation_count: 0,
            rating: 0,
            last_seen_at: created_at,
        }
    }

    /// Returns true if the skill is available for invocation
    pub fn is_available(&self) -> bool {
        self.status == SkillStatus::Active
    }

    /// Bumps `last_seen_at` to the current wall-clock time. Called by the
    /// heartbeat RPC and by any successful invocation path that wants to
    /// keep the skill from being swept as stale.
    pub fn touch(&mut self) {
        self.last_seen_at = default_last_seen();
    }

    /// Returns `true` when this skill is paid (non-zero `price_per_call`).
    pub fn is_paid(&self) -> bool {
        self.price_per_call > 0
    }

    /// Validate registration invariants. Any paid skill must declare a
    /// `creator_wallet` to receive the creator share of each invocation;
    /// otherwise the creator share would have no destination and the
    /// marketplace commission would have nothing to split against. Free
    /// skills (`price_per_call == 0`) may omit `creator_wallet`.
    pub fn validate_for_registration(&self) -> Result<(), String> {
        if self.is_paid() && self.creator_wallet.is_none() {
            return Err("Paid skill (price_per_call > 0) requires a creator_wallet".to_string());
        }
        if let Some(ref bundle) = self.bundle {
            bundle.validate().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Check a caller-supplied pin against what the registry actually holds.
    ///
    /// A permissionless registry has no admission gate, so this is where a
    /// caller gets certainty: pin the version and/or the artifact digest and
    /// the invocation is refused unless the row names exactly those bytes.
    /// Pinning nothing accepts whatever the publisher currently serves.
    pub fn check_pin(
        &self,
        expected_version: Option<&str>,
        expected_sha256: Option<&str>,
    ) -> Result<(), SkillPinError> {
        if let Some(want) = expected_version
            && want != self.version
        {
            return Err(SkillPinError::VersionMismatch {
                expected: want.to_string(),
                actual: self.version.clone(),
            });
        }

        if let Some(want) = expected_sha256 {
            let want = want.trim().to_ascii_lowercase();
            if !is_hash_hex(&want) {
                return Err(SkillPinError::MalformedBundle(
                    "expected_sha256 must be a 64-char hex digest".to_string(),
                ));
            }
            let Some(ref bundle) = self.bundle else {
                return Err(SkillPinError::NoBundlePublished);
            };
            bundle.validate()?;
            if bundle.sha256 != want {
                return Err(SkillPinError::HashMismatch {
                    expected: want,
                    actual: bundle.sha256.clone(),
                });
            }
        }

        Ok(())
    }
}

/// Filter parameters for listing and searching skills
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillFilter {
    /// Filter by tag (must include this tag)
    pub tag: Option<String>,

    /// Filter by creator DID
    pub creator_did: Option<String>,

    /// Filter by required capability
    pub capability: Option<String>,

    /// Filter by category (e.g. "ai", "defi", "data")
    pub category: Option<String>,

    /// Only return skills that publish a content-addressed bundle, i.e.
    /// skills whose artifact a caller can pin.
    pub bundled_only: Option<bool>,

    /// Maximum price per call in atto-TNZO (inclusive)
    pub max_price: Option<u128>,

    /// Only return active skills
    pub active_only: Option<bool>,

    /// Free-text search in name and description
    pub query: Option<String>,

    /// Maximum number of results to return
    pub limit: Option<usize>,

    /// Pagination offset
    pub offset: Option<usize>,
}

/// Result of using/invoking a skill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillInvocationResult {
    /// The skill that was invoked
    pub skill_id: String,

    /// Invocation identifier for tracking
    pub invocation_id: String,

    /// The output payload returned by the skill
    pub output: serde_json::Value,

    /// Settlement transaction hash (if payment was made)
    pub settlement_tx: Option<String>,

    /// Amount paid in atto-TNZO
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount_paid: u128,

    /// Unix timestamp when the invocation completed
    pub completed_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skill_definition_new() {
        let skill = SkillDefinition::new(
            "web-search".to_string(),
            "1.0.0".to_string(),
            "did:tenzro:human:test-123".to_string(),
            "Searches the web and returns results".to_string(),
            1_000_000_000_000_000_000, // 1 TNZO
        );

        assert!(!skill.skill_id.is_empty());
        assert_eq!(skill.name, "web-search");
        assert_eq!(skill.version, "1.0.0");
        assert!(skill.is_available());
        assert!(skill.is_paid());
        assert!(
            skill.creator_wallet.is_none(),
            "wallet starts unset; caller must populate before paid registration"
        );
        assert_eq!(skill.status, SkillStatus::Active);
        assert_eq!(skill.invocation_count, 0);
    }

    #[test]
    fn paid_skill_without_wallet_fails_validation() {
        let skill = SkillDefinition::new(
            "premium-skill".to_string(),
            "1.0.0".to_string(),
            "did:tenzro:human:creator".to_string(),
            "Paid skill".to_string(),
            1_000_000_000_000_000_000, // 1 TNZO
        );
        // creator_wallet starts as None — validate should reject.
        assert!(skill.validate_for_registration().is_err());
    }

    #[test]
    fn free_skill_without_wallet_passes_validation() {
        let skill = SkillDefinition::new(
            "free-skill".to_string(),
            "1.0.0".to_string(),
            "did:tenzro:human:creator".to_string(),
            "Free skill".to_string(),
            0,
        );
        assert!(skill.validate_for_registration().is_ok());
    }

    #[test]
    fn paid_skill_with_wallet_passes_validation() {
        let mut skill = SkillDefinition::new(
            "paid-skill".to_string(),
            "1.0.0".to_string(),
            "did:tenzro:human:creator".to_string(),
            "Paid skill".to_string(),
            500,
        );
        skill.creator_wallet = Some(Address::default());
        assert!(skill.validate_for_registration().is_ok());
    }

    fn bundled_skill() -> SkillDefinition {
        let mut skill = SkillDefinition::new(
            "web-search".to_string(),
            "1.2.0".to_string(),
            "did:tenzro:human:creator".to_string(),
            "Bundled skill".to_string(),
            0,
        );
        skill.bundle = Some(SkillBundle {
            uri: format!("{BLOB_URI_PREFIX}{}", "ab".repeat(32)),
            sha256: "cd".repeat(32),
            size_bytes: 4096,
        });
        skill
    }

    #[test]
    fn no_pin_accepts_whatever_the_publisher_serves() {
        assert!(bundled_skill().check_pin(None, None).is_ok());
    }

    #[test]
    fn matching_version_and_hash_pin_pass() {
        let skill = bundled_skill();
        let sha = skill.bundle.as_ref().unwrap().sha256.clone();
        assert!(skill.check_pin(Some("1.2.0"), Some(&sha)).is_ok());
    }

    #[test]
    fn version_pin_refuses_a_different_version() {
        let skill = bundled_skill();
        assert_eq!(
            skill.check_pin(Some("1.3.0"), None),
            Err(SkillPinError::VersionMismatch {
                expected: "1.3.0".to_string(),
                actual: "1.2.0".to_string(),
            })
        );
    }

    #[test]
    fn hash_pin_refuses_a_different_artifact() {
        let skill = bundled_skill();
        let other = "ef".repeat(32);
        assert_eq!(
            skill.check_pin(None, Some(&other)),
            Err(SkillPinError::HashMismatch {
                expected: other,
                actual: "cd".repeat(32),
            })
        );
    }

    #[test]
    fn hash_pin_is_case_insensitive_on_the_caller_side() {
        let skill = bundled_skill();
        let upper = "CD".repeat(32);
        assert!(skill.check_pin(None, Some(&upper)).is_ok());
    }

    #[test]
    fn hash_pin_refuses_an_unbundled_skill() {
        let skill = SkillDefinition::new(
            "endpoint-only".to_string(),
            "1.0.0".to_string(),
            "did:tenzro:human:creator".to_string(),
            "No bundle".to_string(),
            0,
        );
        assert_eq!(
            skill.check_pin(None, Some(&"cd".repeat(32))),
            Err(SkillPinError::NoBundlePublished)
        );
    }

    #[test]
    fn malformed_pin_is_rejected_before_comparison() {
        let skill = bundled_skill();
        assert!(matches!(
            skill.check_pin(None, Some("not-a-digest")),
            Err(SkillPinError::MalformedBundle(_))
        ));
    }

    #[test]
    fn bundle_uri_must_be_a_blob_locator() {
        let bundle = SkillBundle {
            uri: format!("https://example.com/{}", "ab".repeat(32)),
            sha256: "cd".repeat(32),
            size_bytes: 1,
        };
        assert!(matches!(
            bundle.validate(),
            Err(SkillPinError::MalformedBundle(_))
        ));
    }

    #[test]
    fn bundle_locator_must_carry_a_full_hex_hash() {
        let bundle = SkillBundle {
            uri: format!("{BLOB_URI_PREFIX}deadbeef"),
            sha256: "cd".repeat(32),
            size_bytes: 1,
        };
        assert!(matches!(
            bundle.validate(),
            Err(SkillPinError::MalformedBundle(_))
        ));
    }

    #[test]
    fn empty_bundle_is_rejected_at_registration() {
        let mut skill = bundled_skill();
        skill.bundle.as_mut().unwrap().size_bytes = 0;
        assert!(skill.validate_for_registration().is_err());
    }

    #[test]
    fn blake3_hex_strips_the_locator_prefix() {
        let skill = bundled_skill();
        assert_eq!(skill.bundle.unwrap().blake3_hex(), "ab".repeat(32));
    }

    #[test]
    fn test_skill_status_default() {
        assert_eq!(SkillStatus::default(), SkillStatus::Active);
    }

    #[test]
    fn test_skill_filter_default() {
        let filter = SkillFilter::default();
        assert!(filter.tag.is_none());
        assert!(filter.creator_did.is_none());
        assert!(filter.max_price.is_none());
        assert!(filter.active_only.is_none());
    }

    #[test]
    fn test_skill_serialization() {
        let skill = SkillDefinition::new(
            "code-review".to_string(),
            "2.0.0".to_string(),
            "did:tenzro:machine:agent-abc".to_string(),
            "Reviews code and suggests improvements".to_string(),
            500_000_000_000_000_000, // 0.5 TNZO
        );

        let json = serde_json::to_string(&skill).unwrap();
        let deserialized: SkillDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(skill.skill_id, deserialized.skill_id);
        assert_eq!(skill.name, deserialized.name);
        assert_eq!(skill.price_per_call, deserialized.price_per_call);
    }
}
