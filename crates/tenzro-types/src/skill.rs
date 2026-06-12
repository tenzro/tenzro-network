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
    pub price_per_call: u128,

    /// Discoverability tags (e.g., ["search", "web", "retrieval"])
    pub tags: Vec<String>,

    /// Required agent capabilities to invoke this skill
    pub required_capabilities: Vec<String>,

    /// Optional HTTP/RPC endpoint for remote invocation
    /// If None, the skill is executed locally by the registered agent
    pub endpoint: Option<String>,

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
    /// network commission would have nothing to split against. Free
    /// skills (`price_per_call == 0`) may omit `creator_wallet`.
    pub fn validate_for_registration(&self) -> Result<(), &'static str> {
        if self.is_paid() && self.creator_wallet.is_none() {
            return Err("Paid skill (price_per_call > 0) requires a creator_wallet");
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
        assert!(skill.creator_wallet.is_none(), "wallet starts unset; caller must populate before paid registration");
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
