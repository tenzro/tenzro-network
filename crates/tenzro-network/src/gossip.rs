//! Gossipsub topics and message handling for Tenzro Network
//!
//! This module provides message deduplication, validation, and topic management
//! for the gossipsub protocol. Message deduplication is handled at two levels:
//!
//! 1. **libp2p gossipsub built-in deduplication**: The gossipsub protocol uses
//!    a custom message ID function (SHA-256 hash of message data) defined in
//!    `behaviour.rs` to automatically deduplicate messages at the protocol level.
//!
//! 2. **Application-level deduplication**: The `MessageDeduplicator` provides
//!    an additional layer of deduplication tracking with configurable cache size
//!    and expiry times for defense-in-depth against amplification attacks.

use libp2p::gossipsub::{IdentTopic, TopicHash};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Topic constants for Tenzro Network
pub struct GossipTopics {
    topics: HashMap<String, IdentTopic>,
}

impl GossipTopics {
    /// Creates a new GossipTopics instance
    pub fn new() -> Self {
        let mut topics = HashMap::new();

        // Core protocol topics
        topics.insert("blocks".to_string(), IdentTopic::new("tenzro/blocks"));
        topics.insert("transactions".to_string(), IdentTopic::new("tenzro/transactions"));
        topics.insert("consensus".to_string(), IdentTopic::new("tenzro/consensus"));

        // Provider topics
        topics.insert("attestations".to_string(), IdentTopic::new("tenzro/attestations"));
        topics.insert("models".to_string(), IdentTopic::new("tenzro/models"));
        topics.insert("inference".to_string(), IdentTopic::new("tenzro/inference"));

        // Status and discovery
        topics.insert("status".to_string(), IdentTopic::new("tenzro/status"));

        // Agent and provider discovery
        topics.insert("agents".to_string(), IdentTopic::new("tenzro/agents"));
        topics.insert("providers".to_string(), IdentTopic::new("tenzro/providers"));

        // Cortex worker discovery (must match tenzro_cortex::CORTEX_TOPIC)
        topics.insert("cortex".to_string(), IdentTopic::new("tenzro/cortex"));

        // Tenzro Train: outer-gradient broadcast and syncer round publication
        topics.insert("training".to_string(), IdentTopic::new("tenzro/training"));
        topics.insert("training_syncer".to_string(), IdentTopic::new("tenzro/training/syncer"));

        Self { topics }
    }

    /// Gets a topic by name
    pub fn get(&self, name: &str) -> Option<&IdentTopic> {
        self.topics.get(name)
    }

    /// Gets all topic hashes
    pub fn all_hashes(&self) -> Vec<TopicHash> {
        self.topics.values().map(|t| t.hash()).collect()
    }

    /// Gets all topics
    pub fn all(&self) -> Vec<&IdentTopic> {
        self.topics.values().collect()
    }

    /// Adds a custom topic
    pub fn add_custom(&mut self, name: String, topic: IdentTopic) {
        self.topics.insert(name, topic);
    }

    /// Blocks topic
    pub fn blocks(&self) -> &IdentTopic {
        self.topics.get("blocks").expect("blocks topic must exist")
    }

    /// Transactions topic
    pub fn transactions(&self) -> &IdentTopic {
        self.topics.get("transactions").expect("transactions topic must exist")
    }

    /// Consensus topic
    pub fn consensus(&self) -> &IdentTopic {
        self.topics.get("consensus").expect("consensus topic must exist")
    }

    /// Attestations topic
    pub fn attestations(&self) -> &IdentTopic {
        self.topics.get("attestations").expect("attestations topic must exist")
    }

    /// Models topic
    pub fn models(&self) -> &IdentTopic {
        self.topics.get("models").expect("models topic must exist")
    }

    /// Inference topic
    pub fn inference(&self) -> &IdentTopic {
        self.topics.get("inference").expect("inference topic must exist")
    }

    /// Status topic
    pub fn status(&self) -> &IdentTopic {
        self.topics.get("status").expect("status topic must exist")
    }

    /// Agents topic
    pub fn agents(&self) -> &IdentTopic {
        self.topics.get("agents").expect("agents topic must exist")
    }

    /// Providers topic
    pub fn providers(&self) -> &IdentTopic {
        self.topics.get("providers").expect("providers topic must exist")
    }

    /// Cortex worker-advertisement topic
    pub fn cortex(&self) -> &IdentTopic {
        self.topics.get("cortex").expect("cortex topic must exist")
    }
}

impl Default for GossipTopics {
    fn default() -> Self {
        Self::new()
    }
}

/// Topic subscription manager
pub struct TopicSubscriptions {
    subscribed: HashMap<TopicHash, bool>,
}

impl TopicSubscriptions {
    /// Creates a new TopicSubscriptions instance
    pub fn new() -> Self {
        Self {
            subscribed: HashMap::new(),
        }
    }

    /// Marks a topic as subscribed
    pub fn subscribe(&mut self, topic: &TopicHash) {
        self.subscribed.insert(topic.clone(), true);
    }

    /// Marks a topic as unsubscribed
    pub fn unsubscribe(&mut self, topic: &TopicHash) {
        self.subscribed.remove(topic);
    }

    /// Checks if subscribed to a topic
    pub fn is_subscribed(&self, topic: &TopicHash) -> bool {
        self.subscribed.get(topic).copied().unwrap_or(false)
    }

    /// Gets all subscribed topics
    pub fn subscribed_topics(&self) -> Vec<&TopicHash> {
        self.subscribed.keys().collect()
    }

    /// Gets the number of subscribed topics
    pub fn count(&self) -> usize {
        self.subscribed.len()
    }
}

impl Default for TopicSubscriptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Message deduplication cache using SHA-256 hashes of message content.
///
/// Tracks recently seen messages to reject duplicates and prevent amplification attacks.
/// Uses a bounded FIFO queue with time-based expiry.
pub struct MessageDeduplicator {
    /// SHA-256 hashes of recently seen messages, ordered by insertion time
    seen: VecDeque<([u8; 32], Instant)>,
    /// Fast lookup set for O(1) duplicate checks
    seen_set: HashMap<[u8; 32], ()>,
    /// Maximum number of entries to retain
    max_entries: usize,
    /// Expiry duration in seconds
    expiry_secs: u64,
}

impl MessageDeduplicator {
    /// Create a new deduplicator with configurable bounds
    pub fn new(max_entries: usize, expiry_secs: u64) -> Self {
        Self {
            seen: VecDeque::with_capacity(max_entries),
            seen_set: HashMap::with_capacity(max_entries),
            max_entries,
            expiry_secs,
        }
    }

    /// Check if a message has been seen. If not, insert it and return false.
    /// Returns true if the message is a duplicate.
    pub fn is_duplicate(&mut self, data: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(data).into();

        // Evict expired entries
        let now = Instant::now();
        while let Some(&(_, ts)) = self.seen.front() {
            if now.duration_since(ts).as_secs() > self.expiry_secs {
                if let Some((old_hash, _)) = self.seen.pop_front() {
                    self.seen_set.remove(&old_hash);
                }
            } else {
                break;
            }
        }

        // Evict oldest if at capacity
        if self.seen.len() >= self.max_entries
            && let Some((old_hash, _)) = self.seen.pop_front()
        {
            self.seen_set.remove(&old_hash);
        }

        if self.seen_set.contains_key(&hash) {
            return true;
        }

        self.seen_set.insert(hash, ());
        self.seen.push_back((hash, now));
        false
    }

    /// Return the number of cached message hashes
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Return whether the cache is empty
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for MessageDeduplicator {
    fn default() -> Self {
        // Default: 100k messages, 5 minute expiry
        Self::new(100_000, 300)
    }
}

/// Message validation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageValidation {
    /// Message is valid and should be propagated
    Accept,
    /// Message is invalid and should be rejected
    Reject,
    /// Message validation is pending (for async validation)
    Ignore,
}

/// Validates gossip messages based on topic and content
pub fn validate_gossip_message(_topic: &TopicHash, data: &[u8]) -> MessageValidation {
    // Basic validation: check if message is not empty
    if data.is_empty() {
        return MessageValidation::Reject;
    }

    // Check message size (hardened 1 MiB cap — matches gossipsub max_transmit_size
    // and prevents large-message flood amplification attacks).
    if data.len() > 1_048_576 {
        return MessageValidation::Reject;
    }

    // Try to parse as NetworkMessage
    match crate::message::NetworkMessage::from_bytes(data) {
        Ok(msg) => {
            // Validate message structure
            if let Err(e) = crate::message::validate_message(&msg) {
                tracing::warn!("Message validation failed: {}", e);
                return MessageValidation::Reject;
            }
            MessageValidation::Accept
        }
        Err(e) => {
            tracing::warn!("Failed to parse network message: {}", e);
            MessageValidation::Reject
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gossip_topics() {
        let topics = GossipTopics::new();
        assert!(topics.get("blocks").is_some());
        assert!(topics.get("transactions").is_some());
        assert!(topics.get("consensus").is_some());
        assert!(topics.get("nonexistent").is_none());
    }

    #[test]
    fn test_topic_subscriptions() {
        let mut subs = TopicSubscriptions::new();
        let topics = GossipTopics::new();
        let blocks_hash = topics.blocks().hash();

        assert!(!subs.is_subscribed(&blocks_hash));

        subs.subscribe(&blocks_hash);
        assert!(subs.is_subscribed(&blocks_hash));
        assert_eq!(subs.count(), 1);

        subs.unsubscribe(&blocks_hash);
        assert!(!subs.is_subscribed(&blocks_hash));
        assert_eq!(subs.count(), 0);
    }

    #[test]
    fn test_message_deduplication() {
        let mut dedup = MessageDeduplicator::new(100, 60);

        let msg1 = b"message one";
        let msg2 = b"message two";

        // First time seeing msg1 — not a duplicate
        assert!(!dedup.is_duplicate(msg1));
        // Second time — duplicate
        assert!(dedup.is_duplicate(msg1));
        // Different message — not a duplicate
        assert!(!dedup.is_duplicate(msg2));

        assert_eq!(dedup.len(), 2);
    }

    #[test]
    fn test_dedup_capacity_eviction() {
        let mut dedup = MessageDeduplicator::new(3, 300);

        assert!(!dedup.is_duplicate(b"a"));
        assert!(!dedup.is_duplicate(b"b"));
        assert!(!dedup.is_duplicate(b"c"));
        // At capacity, inserting a new one should evict the oldest
        assert!(!dedup.is_duplicate(b"d"));
        assert_eq!(dedup.len(), 3);
        // "a" was evicted, so it's no longer a duplicate
        assert!(!dedup.is_duplicate(b"a"));
    }

    #[test]
    fn test_message_validation() {
        // Empty message should be rejected
        assert_eq!(
            validate_gossip_message(&TopicHash::from_raw("test"), &[]),
            MessageValidation::Reject
        );

        // Valid message should be accepted
        let msg = crate::message::NetworkMessage::new(crate::message::MessagePayload::Ping);
        let bytes = msg.to_bytes().unwrap();
        let topics = GossipTopics::new();
        let result = validate_gossip_message(&topics.status().hash(), &bytes);
        assert_eq!(result, MessageValidation::Accept);
    }
}
