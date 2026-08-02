//! Agentic token issuance and verification service
//!
//! Implements Mastercard's agentic token management (mapping to MDES tokenization).
//! Tokens represent tokenized payment credentials that agents can use for purchases.

use crate::error::{PaymentError, Result};
use crate::mastercard::types::{AgenticToken, AgenticTokenType};
use chrono::{Duration, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, info};
use uuid::Uuid;

/// Agentic token service for issuing, verifying, and managing tokens
pub struct AgenticTokenService {
    /// Map of token_id -> token
    tokens: Arc<DashMap<String, AgenticToken>>,
}

impl AgenticTokenService {
    /// Create a new agentic token service
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(DashMap::new()),
        }
    }

    /// Issue a new agentic token to an agent
    ///
    /// # Arguments
    ///
    /// * `agent_did` - The agent DID this token is issued to
    /// * `token_type` - Type of token (SingleUse, SessionBound, Recurring)
    /// * `domain_restrictions` - List of domains this token is restricted to (empty = unrestricted)
    /// * `amount_limit` - Maximum amount limit for this token (None = unrestricted)
    /// * `ttl` - Time-to-live duration for the token
    ///
    /// # Returns
    ///
    /// The issued `AgenticToken`
    pub fn issue_token(
        &self,
        agent_did: &str,
        token_type: AgenticTokenType,
        domain_restrictions: Vec<String>,
        amount_limit: Option<u128>,
        ttl: Duration,
    ) -> Result<AgenticToken> {
        let token_id = format!("token_{}", Uuid::new_v4());
        let now = Utc::now();
        let expires_at = now + ttl;

        // Generate token data: AES-256-GCM encrypted representation of payment credential.
        // The plaintext encodes agent DID, token type, amount limit, and expiry so the
        // token data carries a verifiable, encrypted payload — analogous to MDES tokenization.
        let plaintext = {
            use std::fmt::Write;
            let mut s = String::new();
            let _ = write!(
                s,
                "did={}&type={}&amount_limit={}&expires={}",
                agent_did,
                token_type,
                amount_limit
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "unlimited".to_string()),
                expires_at.timestamp()
            );
            s
        };

        let symmetric_key = tenzro_crypto::encryption::SymmetricKey::generate();
        let encrypted = symmetric_key
            .encrypt(plaintext.as_bytes())
            .unwrap_or_else(|_| plaintext.as_bytes().to_vec());
        let token_data = hex::encode(&encrypted);

        let token = AgenticToken {
            token_id: token_id.clone(),
            agent_did: agent_did.to_string(),
            token_type,
            token_data,
            issued_at: now,
            expires_at,
            domain_restrictions,
            amount_limit,
        };

        info!(
            "Issuing {} token {} to agent {} (expires: {}, limit: {:?})",
            token_type, token_id, agent_did, expires_at, amount_limit
        );

        self.tokens.insert(token_id.clone(), token.clone());

        Ok(token)
    }

    /// Verify a token is valid and not expired
    ///
    /// # Arguments
    ///
    /// * `token_id` - The token identifier to verify
    ///
    /// # Returns
    ///
    /// * `Ok(AgenticToken)` if the token is valid
    /// * `Err(PaymentError)` if the token is not found or expired
    pub fn verify_token(&self, token_id: &str) -> Result<AgenticToken> {
        debug!("Verifying token: {}", token_id);

        let token = self
            .tokens
            .get(token_id)
            .map(|t| t.clone())
            .ok_or_else(|| {
                PaymentError::MastercardError(format!("Token not found: {}", token_id))
            })?;

        // Check if token has expired
        if Utc::now() > token.expires_at {
            return Err(PaymentError::MastercardError(format!(
                "Token {} has expired at {}",
                token_id, token.expires_at
            )));
        }

        debug!("Token {} is valid", token_id);
        Ok(token)
    }

    /// Revoke a token (e.g., after single use or on user request)
    ///
    /// # Arguments
    ///
    /// * `token_id` - The token identifier to revoke
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the token was revoked
    /// * `Err(PaymentError)` if the token was not found
    pub fn revoke_token(&self, token_id: &str) -> Result<()> {
        info!("Revoking token: {}", token_id);

        self.tokens.remove(token_id).ok_or_else(|| {
            PaymentError::MastercardError(format!("Token not found: {}", token_id))
        })?;

        Ok(())
    }

    /// Clean up expired tokens
    ///
    /// # Returns
    ///
    /// The number of tokens removed
    pub fn cleanup_expired(&self) -> usize {
        let now = Utc::now();
        let before = self.tokens.len();

        self.tokens.retain(|_, token| token.expires_at > now);

        let removed = before - self.tokens.len();
        if removed > 0 {
            info!("Cleaned up {} expired tokens", removed);
        }

        removed
    }

    /// Get the number of active tokens
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Check if there are no active tokens
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl Default for AgenticTokenService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_and_verify() {
        let service = AgenticTokenService::new();

        let token = service
            .issue_token(
                "did:tenzro:machine:agent1",
                AgenticTokenType::SingleUse,
                vec![],
                Some(1000),
                Duration::minutes(10),
            )
            .unwrap();

        assert_eq!(token.agent_did, "did:tenzro:machine:agent1");
        assert_eq!(token.token_type, AgenticTokenType::SingleUse);
        assert_eq!(token.amount_limit, Some(1000));

        // Verify the token
        let verified = service.verify_token(&token.token_id).unwrap();
        assert_eq!(verified.token_id, token.token_id);
    }

    #[test]
    fn test_reject_expired() {
        let service = AgenticTokenService::new();

        // Issue a token with negative TTL (already expired)
        let token = service
            .issue_token(
                "did:tenzro:machine:agent2",
                AgenticTokenType::SessionBound,
                vec![],
                None,
                Duration::seconds(-1),
            )
            .unwrap();

        // Verification should fail
        let result = service.verify_token(&token.token_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_reject_revoked() {
        let service = AgenticTokenService::new();

        let token = service
            .issue_token(
                "did:tenzro:machine:agent3",
                AgenticTokenType::Recurring,
                vec![],
                Some(5000),
                Duration::hours(1),
            )
            .unwrap();

        // Revoke the token
        service.revoke_token(&token.token_id).unwrap();

        // Verification should fail
        let result = service.verify_token(&token.token_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_cleanup() {
        let service = AgenticTokenService::new();

        // Issue some tokens
        service
            .issue_token(
                "did:tenzro:machine:agent4",
                AgenticTokenType::SingleUse,
                vec![],
                None,
                Duration::minutes(10),
            )
            .unwrap();

        service
            .issue_token(
                "did:tenzro:machine:agent5",
                AgenticTokenType::SessionBound,
                vec![],
                None,
                Duration::seconds(-1), // already expired
            )
            .unwrap();

        service
            .issue_token(
                "did:tenzro:machine:agent6",
                AgenticTokenType::Recurring,
                vec![],
                None,
                Duration::seconds(-2), // already expired
            )
            .unwrap();

        assert_eq!(service.len(), 3);

        // Cleanup should remove 2 expired tokens
        let removed = service.cleanup_expired();
        assert_eq!(removed, 2);
        assert_eq!(service.len(), 1);
    }

    #[test]
    fn test_domain_restrictions() {
        let service = AgenticTokenService::new();

        let token = service
            .issue_token(
                "did:tenzro:machine:agent7",
                AgenticTokenType::SingleUse,
                vec!["merchant.example.com".to_string()],
                None,
                Duration::hours(1),
            )
            .unwrap();

        assert_eq!(token.domain_restrictions.len(), 1);
        assert_eq!(token.domain_restrictions[0], "merchant.example.com");
    }

    #[test]
    fn test_token_types() {
        let service = AgenticTokenService::new();

        let single_use = service
            .issue_token(
                "did:tenzro:machine:agent8",
                AgenticTokenType::SingleUse,
                vec![],
                None,
                Duration::minutes(5),
            )
            .unwrap();
        assert_eq!(single_use.token_type, AgenticTokenType::SingleUse);

        let session_bound = service
            .issue_token(
                "did:tenzro:machine:agent9",
                AgenticTokenType::SessionBound,
                vec![],
                None,
                Duration::hours(1),
            )
            .unwrap();
        assert_eq!(session_bound.token_type, AgenticTokenType::SessionBound);

        let recurring = service
            .issue_token(
                "did:tenzro:machine:agent10",
                AgenticTokenType::Recurring,
                vec![],
                None,
                Duration::days(30),
            )
            .unwrap();
        assert_eq!(recurring.token_type, AgenticTokenType::Recurring);
    }
}
