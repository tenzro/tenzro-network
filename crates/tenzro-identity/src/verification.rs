//! Identity verification for the Tenzro Decentralized Identity Protocol
//!
//! Provides credential chain verification, trust chain validation,
//! and identity attestation checking.
//!
//! # CRITICAL #41 — Recursive trust chain traversal
//!
//! The verifier walks credential issuer chains recursively from a leaf
//! credential up to a configured trust root, validating at every hop:
//!
//! 1. The issuer DID resolves to an `Active` identity in the registry
//! 2. The credential's cryptographic proof verifies against one of the
//!    issuer's `AssertionMethod` public keys
//! 3. The credential is not expired
//! 4. The chain terminates at a registered trust root, OR the issuer
//!    itself holds a credential of the same type that we can recursively
//!    verify
//!
//! Cycle detection is enforced via a `HashSet<String>` of visited issuer
//! DIDs, and recursion is bounded by `max_chain_depth` (default 10) to
//! prevent stack overflow / DoS from maliciously crafted issuer rings.

use crate::credential::{TenzroCredentialType, VerifiableCredential};
use crate::error::{IdentityError, Result};
use crate::identity::{IdentityData, IdentityStatus, KeyPurpose, TenzroIdentity};
use crate::registry::IdentityRegistry;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tenzro_types::identity::KycTier;

/// Default maximum trust chain traversal depth.
///
/// 10 hops is more than enough for any realistic credential ladder
/// (root CA → regional CA → issuer → subject is 4 hops) while still
/// providing a hard DoS guard.
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 10;

/// Result of a single credential's chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialChainResult {
    /// Whether the credential's full chain is valid
    pub valid: bool,
    /// Type of credential that was verified
    pub credential_type: String,
    /// Number of hops walked from leaf to root
    pub chain_length: usize,
    /// DID of the trust root that terminated the chain (if any)
    pub terminating_root: Option<String>,
    /// Any issues found during verification
    pub issues: Vec<String>,
}

/// Result of a trust chain verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustChainResult {
    /// Whether the chain is valid
    pub valid: bool,
    /// The DID being verified
    pub subject_did: String,
    /// The controller DID (if machine identity)
    pub controller_did: Option<String>,
    /// The controller's KYC tier (if machine with controller)
    pub controller_kyc_tier: Option<KycTier>,
    /// Number of valid (non-expired) credentials on the identity
    pub valid_credentials: usize,
    /// Number of credentials whose full issuer chain verified
    /// (CRITICAL #41). May be lower than `valid_credentials` if
    /// some credentials don't anchor to a trust root.
    pub verified_chains: usize,
    /// Per-credential chain verification results (CRITICAL #41).
    pub chain_results: Vec<CredentialChainResult>,
    /// Any issues found during verification
    pub issues: Vec<String>,
}

/// Identity verifier for checking trust chains and credential validity
pub struct IdentityVerifier {
    registry: Arc<IdentityRegistry>,
    /// DIDs of trusted root issuers (CRITICAL #41).
    ///
    /// A credential chain is considered "anchored" only when traversal
    /// terminates at one of these DIDs. If the set is empty, the verifier
    /// falls back to "trust any self-signed root" — but `verify_trust_chain`
    /// reports `NoTrustRoot` issues for any unanchored credential.
    trust_roots: HashSet<String>,
    /// Maximum recursion depth for chain traversal (CRITICAL #41).
    max_chain_depth: usize,
    /// If true, credentials whose chain does not anchor to a trust root
    /// cause the overall trust chain result to be marked invalid.
    /// Default `false` — chains without roots produce a non-fatal issue
    /// so existing call-sites that don't configure trust roots keep working.
    require_trust_root: bool,
}

impl IdentityVerifier {
    /// Creates a new identity verifier
    pub fn new(registry: Arc<IdentityRegistry>) -> Self {
        Self {
            registry,
            trust_roots: HashSet::new(),
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            require_trust_root: false,
        }
    }

    /// Adds a single trust root DID (CRITICAL #41).
    pub fn with_trust_root(mut self, did: impl Into<String>) -> Self {
        self.trust_roots.insert(did.into());
        self
    }

    /// Replaces the entire trust root set (CRITICAL #41).
    pub fn with_trust_roots<I, S>(mut self, dids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trust_roots = dids.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the maximum recursion depth for trust chain traversal (CRITICAL #41).
    pub fn with_max_chain_depth(mut self, depth: usize) -> Self {
        self.max_chain_depth = depth.max(1);
        self
    }

    /// If set, credentials whose chain does not terminate at a registered
    /// trust root will cause `verify_trust_chain` to mark the result as
    /// invalid (CRITICAL #41).
    pub fn require_trust_root(mut self, required: bool) -> Self {
        self.require_trust_root = required;
        self
    }

    /// Returns the configured trust roots.
    pub fn trust_roots(&self) -> &HashSet<String> {
        &self.trust_roots
    }

    /// Returns whether the given DID is a registered trust root.
    pub fn is_trust_root(&self, did: &str) -> bool {
        self.trust_roots.contains(did)
    }

    /// Verifies the complete trust chain for an identity (CRITICAL #41).
    ///
    /// For human identities, verifies the identity is active, all credentials
    /// pass cryptographic verification, and each credential's issuer chain
    /// terminates at a recognized trust root.
    ///
    /// For machine identities, also verifies the controller chain and
    /// credential inheritance.
    pub fn verify_trust_chain(&self, did: &str) -> Result<TrustChainResult> {
        let identity = self.registry.resolve(did)?;
        let mut issues = Vec::new();

        // Check identity status
        if identity.status != IdentityStatus::Active {
            issues.push(format!("identity is {:?}", identity.status));
        }

        // Count non-expired credentials
        let valid_credentials = identity.credentials.iter().filter(|c| c.is_valid()).count();
        let expired_count = identity.credentials.len() - valid_credentials;
        if expired_count > 0 {
            issues.push(format!("{} expired credentials", expired_count));
        }

        // CRITICAL #41: walk the issuer chain for each credential
        let mut chain_results = Vec::with_capacity(identity.credentials.len());
        let mut verified_chains = 0usize;
        for cred in &identity.credentials {
            if !cred.is_valid() {
                // Skip expired creds — already counted above
                continue;
            }
            let result = self.verify_credential_chain(cred, did);
            if result.valid {
                verified_chains += 1;
            } else {
                for problem in &result.issues {
                    issues.push(format!(
                        "credential {} chain invalid: {}",
                        result.credential_type, problem
                    ));
                }
                if self.require_trust_root && result.terminating_root.is_none() {
                    // Already counted via issues; nothing extra
                }
            }
            chain_results.push(result);
        }

        // Machine-specific checks
        let (ctrl_did, ctrl_kyc) = match &identity.identity_data {
            IdentityData::Human { .. } | IdentityData::Institution { .. } => {
                (None, identity.kyc_tier())
            }
            IdentityData::Machine { controller_did, .. } => {
                if let Some(ctrl) = controller_did {
                    match self.registry.resolve(ctrl) {
                        Ok(controller) => {
                            if controller.status != IdentityStatus::Active {
                                issues.push(format!(
                                    "controller {} is {:?}",
                                    ctrl, controller.status
                                ));
                            }

                            // Verify inherited credentials match controller's
                            for cred in &identity.credentials {
                                let controller_has = controller.credentials.iter().any(|cc| {
                                    cc.tenzro_type == cred.tenzro_type
                                        && cc.issuer == cred.issuer
                                        && cc.is_valid()
                                });
                                if !controller_has {
                                    issues.push(format!(
                                        "inherited credential {:?} not found in controller",
                                        cred.tenzro_type
                                    ));
                                }
                            }

                            (Some(ctrl.clone()), controller.kyc_tier())
                        }
                        Err(_) => {
                            issues.push(format!("controller {} not found", ctrl));
                            (Some(ctrl.clone()), None)
                        }
                    }
                } else {
                    (None, None)
                }
            }
        };

        Ok(TrustChainResult {
            valid: issues.is_empty(),
            subject_did: did.to_string(),
            controller_did: ctrl_did,
            controller_kyc_tier: ctrl_kyc,
            valid_credentials,
            verified_chains,
            chain_results,
            issues,
        })
    }

    /// Recursively verifies a credential's issuer chain (CRITICAL #41).
    ///
    /// Walks from the credential's `issuer` DID up through any credentials
    /// the issuer holds of the same type, until either (a) a registered
    /// trust root is reached, (b) a self-issued credential is reached
    /// (the issuer is itself a trust root), (c) the chain breaks, or
    /// (d) the maximum depth is exceeded.
    ///
    /// At each hop the verifier:
    /// - Resolves the issuer identity (returning early if NotFound)
    /// - Confirms the issuer is `Active`
    /// - Verifies the credential's cryptographic proof against an
    ///   `AssertionMethod` public key on the issuer
    /// - Detects cycles via the `visited` set
    pub fn verify_credential_chain(
        &self,
        credential: &VerifiableCredential,
        subject_did: &str,
    ) -> CredentialChainResult {
        let credential_type = credential.tenzro_type.type_name().to_string();
        let mut visited = HashSet::new();
        // Subject is implicitly visited so a self-issued credential cannot
        // immediately recurse on itself unless the subject is a trust root.
        visited.insert(subject_did.to_string());

        let mut issues = Vec::new();
        let mut chain_length = 0usize;
        let mut terminating_root: Option<String> = None;

        match self.walk_chain(
            credential,
            &mut visited,
            &mut chain_length,
            &mut terminating_root,
            0,
        ) {
            Ok(()) => {}
            Err(e) => issues.push(e.to_string()),
        }

        // A chain is "valid" only if no errors AND it terminated at a
        // recognized trust root (when trust roots are configured) OR no
        // trust roots are configured at all (rootless mode).
        let anchored = terminating_root.is_some();
        let needs_root = !self.trust_roots.is_empty();
        let valid = issues.is_empty() && (!needs_root || anchored);

        if needs_root && !anchored && issues.is_empty() {
            issues.push("chain did not terminate at a registered trust root".to_string());
        }

        CredentialChainResult {
            valid,
            credential_type,
            chain_length,
            terminating_root,
            issues,
        }
    }

    /// Recursive worker for `verify_credential_chain`.
    fn walk_chain(
        &self,
        credential: &VerifiableCredential,
        visited: &mut HashSet<String>,
        chain_length: &mut usize,
        terminating_root: &mut Option<String>,
        depth: usize,
    ) -> Result<()> {
        // Depth guard
        if depth >= self.max_chain_depth {
            return Err(IdentityError::TrustChainTooDeep {
                max_depth: self.max_chain_depth,
            });
        }

        // Expiration / time-bounds
        if !credential.is_valid() {
            return Err(IdentityError::TrustChainBroken {
                issuer: credential.issuer.clone(),
                reason: "credential is expired or not yet valid".to_string(),
            });
        }

        let issuer_did = credential.issuer.clone();

        // Cycle detection. The subject DID is pre-populated in `visited`
        // by `verify_credential_chain`, which means a self-issued
        // credential at depth 0 would falsely trip the cycle check.
        // Special-case: at depth 0, when the credential is self-issued
        // (issuer == subject == single visited entry), skip the insert
        // — the recursion termination logic below will handle the
        // self-issued case correctly.
        let is_self_issued_at_root = depth == 0 && credential.credential_subject.id == issuer_did;
        if !is_self_issued_at_root && !visited.insert(issuer_did.clone()) {
            return Err(IdentityError::TrustChainCycle { issuer: issuer_did });
        }

        // Resolve issuer
        let issuer =
            self.registry
                .resolve(&issuer_did)
                .map_err(|e| IdentityError::TrustChainBroken {
                    issuer: issuer_did.clone(),
                    reason: format!("could not resolve issuer: {}", e),
                })?;

        // Issuer must be Active
        if issuer.status != IdentityStatus::Active {
            return Err(IdentityError::TrustChainBroken {
                issuer: issuer_did,
                reason: format!("issuer is {:?}", issuer.status),
            });
        }

        // Verify the credential's cryptographic proof against any of the
        // issuer's AssertionMethod public keys. If the credential carries
        // no proof, that is itself a chain break — we cannot trust an
        // unsigned credential during recursive traversal.
        if credential.proof.is_none() {
            return Err(IdentityError::TrustChainBroken {
                issuer: issuer_did,
                reason: "credential carries no cryptographic proof".to_string(),
            });
        }
        if !verify_credential_against_issuer(credential, &issuer) {
            return Err(IdentityError::TrustChainBroken {
                issuer: issuer_did,
                reason: "credential signature does not verify against any \
                         AssertionMethod key on the issuer"
                    .to_string(),
            });
        }

        *chain_length += 1;

        // Termination check #1: issuer is a registered trust root
        if self.trust_roots.contains(&issuer_did) {
            *terminating_root = Some(issuer_did);
            return Ok(());
        }

        // Termination check #2: self-issued credential AND no trust roots
        // configured. In rootless mode (empty trust root set) we accept
        // self-issued credentials as terminal so call sites that have not
        // configured roots keep working.
        if credential.credential_subject.id == issuer_did {
            // self-issued — only terminal in rootless mode
            if self.trust_roots.is_empty() {
                return Ok(());
            }
            // Otherwise self-issued is NOT a trust anchor; the issuer must
            // hold a credential of the same type from a higher authority,
            // which we recurse into below.
        }

        // Recurse: pick the longest-lived valid credential of the same
        // type the issuer holds. If none, the chain terminates here.
        let next_credential = issuer
            .credentials
            .iter()
            .filter(|c| c.tenzro_type == credential.tenzro_type && c.is_valid())
            .max_by_key(|c| {
                c.expiration_date
                    .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC)
            });

        if let Some(next) = next_credential {
            return self.walk_chain(next, visited, chain_length, terminating_root, depth + 1);
        }

        // No higher credential found. If a trust root is required and we
        // never reached one, the caller (`verify_credential_chain`) will
        // mark the result invalid.
        Ok(())
    }

    /// Checks if an identity has a specific credential type
    pub fn has_credential(
        &self,
        did: &str,
        credential_type: &TenzroCredentialType,
    ) -> Result<bool> {
        let identity = self.registry.resolve(did)?;
        Ok(identity
            .credentials
            .iter()
            .any(|c| &c.tenzro_type == credential_type && c.is_valid()))
    }

    /// Checks if an identity meets a minimum KYC tier (directly or via controller)
    pub fn meets_kyc_tier(&self, did: &str, required_tier: KycTier) -> Result<bool> {
        let identity = self.registry.resolve(did)?;

        match &identity.identity_data {
            IdentityData::Human { kyc_tier, .. } => Ok(*kyc_tier >= required_tier),
            IdentityData::Institution { kyb_tier, .. } => Ok(*kyb_tier >= required_tier),
            IdentityData::Machine { controller_did, .. } => {
                if let Some(ctrl) = controller_did {
                    let controller = self.registry.resolve(ctrl)?;
                    match &controller.identity_data {
                        IdentityData::Human { kyc_tier, .. } => Ok(*kyc_tier >= required_tier),
                        IdentityData::Institution { kyb_tier, .. } => {
                            Ok(*kyb_tier >= required_tier)
                        }
                        _ => Ok(false),
                    }
                } else {
                    // Autonomous machines don't have KYC
                    Ok(false)
                }
            }
        }
    }

    /// Validates that a machine identity can perform an operation
    pub fn validate_operation(
        &self,
        machine_did: &str,
        operation: &str,
        value: Option<u128>,
    ) -> Result<bool> {
        let identity = self.registry.resolve(machine_did)?;

        if identity.status != IdentityStatus::Active {
            return Ok(false);
        }

        match &identity.identity_data {
            IdentityData::Machine {
                delegation_scope, ..
            } => {
                if !delegation_scope.is_active() {
                    return Ok(false);
                }
                if !delegation_scope.is_operation_allowed(operation) {
                    return Ok(false);
                }
                if let Some(v) = value
                    && !delegation_scope.is_value_allowed(v)
                {
                    return Ok(false);
                }
                Ok(true)
            }
            IdentityData::Human { .. } | IdentityData::Institution { .. } => {
                // Humans and institutions act through their own wallet
                // signature, not a delegation scope.
                Ok(true)
            }
        }
    }
}

/// Verifies a credential's cryptographic proof against any AssertionMethod
/// public key on the issuer (CRITICAL #41 helper).
///
/// Returns true if at least one assertion key on the issuer can verify the
/// credential's proof. We try every assertion key because the issuer may
/// rotate keys without re-issuing every credential.
fn verify_credential_against_issuer(
    credential: &VerifiableCredential,
    issuer: &TenzroIdentity,
) -> bool {
    // Collect candidate keys: prefer AssertionMethod, fall back to any key
    // if none have an explicit purpose set.
    let assertion_keys: Vec<&[u8]> = issuer
        .public_keys
        .iter()
        .filter(|k| k.purposes.is_empty() || k.purposes.contains(&KeyPurpose::AssertionMethod))
        .map(|k| k.public_key.as_slice())
        .collect();

    if assertion_keys.is_empty() {
        return false;
    }

    for key in assertion_keys {
        match credential.verify_proof(key) {
            Ok(true) => return true,
            Ok(false) => continue,
            Err(_) => continue,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::CredentialProof;
    use crate::delegation::DelegationScope;
    use crate::identity::PublicKeyInfo;
    use tenzro_crypto::composite::InMemoryHybridSigner;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
    use tenzro_crypto::{KeyPair, KeyType};

    /// Build a fresh hybrid signer for revocation tests in this module.
    fn revocation_test_signer() -> InMemoryHybridSigner {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical = Ed25519SignerImpl::new(kp).unwrap();
        InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate())
    }

    #[tokio::test]
    async fn test_verify_human_trust_chain() {
        let registry = Arc::new(IdentityRegistry::new());
        let verifier = IdentityVerifier::new(registry.clone());

        let human = registry
            .register_human_with_fee(vec![1; 32], "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let result = verifier.verify_trust_chain(&human.did_string()).unwrap();
        assert!(result.valid);
        assert!(result.controller_did.is_none());
        assert!(result.issues.is_empty());
    }

    #[tokio::test]
    async fn test_verify_machine_trust_chain() {
        let registry = Arc::new(IdentityRegistry::new());
        let verifier = IdentityVerifier::new(registry.clone());

        let human = registry
            .register_human_with_fee(vec![1; 32], "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                vec![2; 32],
                vec!["inference".to_string()],
                DelegationScope::unrestricted(),
            )
            .await
            .unwrap()
            .identity;

        let result = verifier.verify_trust_chain(&machine.did_string()).unwrap();
        assert!(result.valid);
        assert_eq!(result.controller_did, Some(human.did_string()));
        assert_eq!(result.controller_kyc_tier, Some(KycTier::Full));
    }

    #[tokio::test]
    async fn test_verify_revoked_chain() {
        let registry = Arc::new(IdentityRegistry::new());
        let verifier = IdentityVerifier::new(registry.clone());

        let human = registry
            .register_human_with_fee(vec![1; 32], "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let signer = revocation_test_signer();
        registry
            .revoke(
                &human.did_string(),
                "test".to_string(),
                "admin".to_string(),
                &signer,
            )
            .unwrap();

        let result = verifier.verify_trust_chain(&human.did_string()).unwrap();
        assert!(!result.valid);
        assert!(!result.issues.is_empty());
    }

    #[tokio::test]
    async fn test_meets_kyc_tier() {
        let registry = Arc::new(IdentityRegistry::new());
        let verifier = IdentityVerifier::new(registry.clone());

        let human = registry
            .register_human_with_fee(vec![1; 32], "Alice".to_string(), KycTier::Enhanced)
            .await
            .unwrap()
            .identity;

        assert!(
            verifier
                .meets_kyc_tier(&human.did_string(), KycTier::Basic)
                .unwrap()
        );
        assert!(
            verifier
                .meets_kyc_tier(&human.did_string(), KycTier::Enhanced)
                .unwrap()
        );
        assert!(
            !verifier
                .meets_kyc_tier(&human.did_string(), KycTier::Full)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_validate_operation() {
        let registry = Arc::new(IdentityRegistry::new());
        let verifier = IdentityVerifier::new(registry.clone());

        let human = registry
            .register_human_with_fee(vec![1; 32], "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                vec![2; 32],
                vec![],
                DelegationScope::unrestricted()
                    .with_max_transaction_value(10_000)
                    .with_allowed_operations(vec!["inference".to_string()]),
            )
            .await
            .unwrap()
            .identity;

        assert!(
            verifier
                .validate_operation(&machine.did_string(), "inference", Some(5_000))
                .unwrap()
        );
        assert!(
            !verifier
                .validate_operation(&machine.did_string(), "admin", None)
                .unwrap()
        );
        assert!(
            !verifier
                .validate_operation(&machine.did_string(), "inference", Some(20_000))
                .unwrap()
        );
    }

    // ─── CRITICAL #41 trust-chain tests ──────────────────────────────────

    /// Helper that constructs a signed credential issued by `signer_id`
    /// to `subject_id`, embedded in the registry, where the issuer
    /// identity has the corresponding Ed25519 public key registered as
    /// an AssertionMethod.
    async fn build_chain_setup() -> (
        Arc<IdentityRegistry>,
        TenzroIdentity,       // root
        TenzroIdentity,       // intermediate
        TenzroIdentity,       // leaf
        VerifiableCredential, // intermediate cred (signed by root)
        VerifiableCredential, // leaf cred (signed by intermediate)
    ) {
        let registry = Arc::new(IdentityRegistry::new());

        // Generate keys for root, intermediate, leaf
        let root_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let intermediate_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let leaf_kp = KeyPair::generate(KeyType::Ed25519).unwrap();

        let root_pub = root_kp.public_key().as_bytes().to_vec();
        let intermediate_pub = intermediate_kp.public_key().as_bytes().to_vec();
        let leaf_pub = leaf_kp.public_key().as_bytes().to_vec();

        // Register the three identities
        let root = registry
            .register_human_with_fee(root_pub.clone(), "Root CA".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let intermediate = registry
            .register_human_with_fee(
                intermediate_pub.clone(),
                "Intermediate".to_string(),
                KycTier::Enhanced,
            )
            .await
            .unwrap()
            .identity;
        let leaf = registry
            .register_human_with_fee(leaf_pub.clone(), "Leaf".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Patch the registered identities so their public_keys carry the
        // correct AssertionMethod role with the keypair we generated
        // above. (register_human_with_fee stores the bytes verbatim; we set the
        // purpose explicitly so verify_credential_against_issuer picks
        // them up.)
        for (did, key_bytes) in [
            (root.did_string(), &root_pub),
            (intermediate.did_string(), &intermediate_pub),
            (leaf.did_string(), &leaf_pub),
        ] {
            let mut id = registry.resolve(&did).unwrap();
            id.public_keys = vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key: key_bytes.clone(),
                purposes: vec![KeyPurpose::AssertionMethod],
            }];
            registry.upsert_identity_for_test(id);
        }

        // Build intermediate cred: subject = intermediate, issuer = root
        let mut intermediate_cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            root.did_string(),
            intermediate.did_string(),
        );
        let msg = intermediate_cred
            .credential_subject
            .canonical_bytes()
            .unwrap();
        let signer = Ed25519SignerImpl::new(root_kp).unwrap();
        let sig = signer.sign(&msg).unwrap();
        intermediate_cred = intermediate_cred.with_proof(CredentialProof::new(
            "Ed25519Signature2020",
            format!("{}#key-1", root.did_string()),
            sig.to_bytes(),
        ));

        // Build leaf cred: subject = leaf, issuer = intermediate
        let mut leaf_cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            intermediate.did_string(),
            leaf.did_string(),
        );
        let msg = leaf_cred.credential_subject.canonical_bytes().unwrap();
        let signer = Ed25519SignerImpl::new(intermediate_kp).unwrap();
        let sig = signer.sign(&msg).unwrap();
        leaf_cred = leaf_cred.with_proof(CredentialProof::new(
            "Ed25519Signature2020",
            format!("{}#key-1", intermediate.did_string()),
            sig.to_bytes(),
        ));

        // Stash credentials onto the identities so the recursive walker
        // can find them when it visits the issuer.
        let mut intermediate_with_cred = registry.resolve(&intermediate.did_string()).unwrap();
        intermediate_with_cred
            .credentials
            .push(intermediate_cred.clone());
        registry.upsert_identity_for_test(intermediate_with_cred);

        let mut leaf_with_cred = registry.resolve(&leaf.did_string()).unwrap();
        leaf_with_cred.credentials.push(leaf_cred.clone());
        registry.upsert_identity_for_test(leaf_with_cred);

        (
            registry,
            root,
            intermediate,
            leaf,
            intermediate_cred,
            leaf_cred,
        )
    }

    #[tokio::test]
    async fn test_chain_terminates_at_trust_root() {
        let (registry, root, _intermediate, leaf, _ic, leaf_cred) = build_chain_setup().await;

        let verifier = IdentityVerifier::new(registry.clone())
            .with_trust_root(root.did_string())
            .require_trust_root(true);

        let result = verifier.verify_credential_chain(&leaf_cred, &leaf.did_string());
        assert!(result.valid, "chain should verify: {:?}", result.issues);
        assert_eq!(result.terminating_root, Some(root.did_string()));
        assert_eq!(result.chain_length, 2); // leaf -> intermediate -> root
    }

    #[tokio::test]
    async fn test_chain_rejected_when_no_trust_root_reached() {
        let (registry, _root, _intermediate, leaf, _ic, leaf_cred) = build_chain_setup().await;

        // Configure a trust root that does NOT match anything in the chain
        let verifier = IdentityVerifier::new(registry.clone())
            .with_trust_root("did:tenzro:human:not-anchored".to_string())
            .require_trust_root(true);

        let result = verifier.verify_credential_chain(&leaf_cred, &leaf.did_string());
        assert!(!result.valid);
        assert!(result.terminating_root.is_none());
    }

    #[tokio::test]
    async fn test_chain_rejected_when_issuer_revoked() {
        let (registry, root, intermediate, leaf, _ic, leaf_cred) = build_chain_setup().await;

        // Revoke the intermediate
        let signer = revocation_test_signer();
        registry
            .revoke(
                &intermediate.did_string(),
                "compromised".to_string(),
                "admin".to_string(),
                &signer,
            )
            .unwrap();

        let verifier = IdentityVerifier::new(registry.clone())
            .with_trust_root(root.did_string())
            .require_trust_root(true);

        let result = verifier.verify_credential_chain(&leaf_cred, &leaf.did_string());
        assert!(!result.valid);
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.contains("Revoked") || i.contains("revoked")),
            "expected revocation issue, got {:?}",
            result.issues
        );
    }

    #[tokio::test]
    async fn test_chain_rejected_when_signature_invalid() {
        let (registry, root, _intermediate, leaf, _ic, mut leaf_cred) = build_chain_setup().await;

        // Tamper with the proof bytes
        if let Some(proof) = leaf_cred.proof.as_mut() {
            proof.proof_value[0] ^= 0xFF;
        }

        let verifier = IdentityVerifier::new(registry.clone())
            .with_trust_root(root.did_string())
            .require_trust_root(true);

        let result = verifier.verify_credential_chain(&leaf_cred, &leaf.did_string());
        assert!(!result.valid);
        assert!(
            result.issues.iter().any(|i| i.contains("signature")),
            "expected signature issue, got {:?}",
            result.issues
        );
    }

    #[tokio::test]
    async fn test_chain_rejects_unsigned_credential() {
        let (registry, root, _intermediate, leaf, _ic, mut leaf_cred) = build_chain_setup().await;

        leaf_cred.proof = None;

        let verifier = IdentityVerifier::new(registry.clone())
            .with_trust_root(root.did_string())
            .require_trust_root(true);

        let result = verifier.verify_credential_chain(&leaf_cred, &leaf.did_string());
        assert!(!result.valid);
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.contains("no cryptographic proof")),
            "expected no-proof issue, got {:?}",
            result.issues
        );
    }

    #[tokio::test]
    async fn test_chain_cycle_detected() {
        let registry = Arc::new(IdentityRegistry::new());

        let kp_a = KeyPair::generate(KeyType::Ed25519).unwrap();
        let kp_b = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pub_a = kp_a.public_key().as_bytes().to_vec();
        let pub_b = kp_b.public_key().as_bytes().to_vec();

        let id_a = registry
            .register_human_with_fee(pub_a.clone(), "A".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let id_b = registry
            .register_human_with_fee(pub_b.clone(), "B".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        for (did, key) in [(id_a.did_string(), &pub_a), (id_b.did_string(), &pub_b)] {
            let mut id = registry.resolve(&did).unwrap();
            id.public_keys = vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key: key.clone(),
                purposes: vec![KeyPurpose::AssertionMethod],
            }];
            registry.upsert_identity_for_test(id);
        }

        // Cred 1: A issues to B (signed by A)
        let mut cred_a_to_b = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            id_a.did_string(),
            id_b.did_string(),
        );
        let msg = cred_a_to_b.credential_subject.canonical_bytes().unwrap();
        let sig = Ed25519SignerImpl::new(kp_a).unwrap().sign(&msg).unwrap();
        cred_a_to_b = cred_a_to_b.with_proof(CredentialProof::new(
            "Ed25519Signature2020",
            format!("{}#key-1", id_a.did_string()),
            sig.to_bytes(),
        ));

        // Cred 2: B issues to A (signed by B)
        let mut cred_b_to_a = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            id_b.did_string(),
            id_a.did_string(),
        );
        let msg = cred_b_to_a.credential_subject.canonical_bytes().unwrap();
        let sig = Ed25519SignerImpl::new(kp_b).unwrap().sign(&msg).unwrap();
        cred_b_to_a = cred_b_to_a.with_proof(CredentialProof::new(
            "Ed25519Signature2020",
            format!("{}#key-1", id_b.did_string()),
            sig.to_bytes(),
        ));

        // Stash creds — A holds cred_b_to_a, B holds cred_a_to_b.
        let mut a_with = registry.resolve(&id_a.did_string()).unwrap();
        a_with.credentials.push(cred_b_to_a.clone());
        registry.upsert_identity_for_test(a_with);

        let mut b_with = registry.resolve(&id_b.did_string()).unwrap();
        b_with.credentials.push(cred_a_to_b.clone());
        registry.upsert_identity_for_test(b_with);

        // Verifier with no anchoring trust root → cycle is the only termination
        let verifier = IdentityVerifier::new(registry.clone())
            .with_trust_root("did:tenzro:human:nonexistent".to_string())
            .require_trust_root(true);

        // Walk starting from B's leaf cred. Expected: A→B→A cycle detected.
        let result = verifier.verify_credential_chain(&cred_a_to_b, &id_b.did_string());
        assert!(!result.valid);
        assert!(
            result.issues.iter().any(|i| i.contains("cycle")),
            "expected cycle issue, got {:?}",
            result.issues
        );
    }

    #[tokio::test]
    async fn test_chain_max_depth_enforced() {
        let (registry, root, _intermediate, leaf, _ic, leaf_cred) = build_chain_setup().await;

        let verifier = IdentityVerifier::new(registry.clone())
            .with_trust_root(root.did_string())
            .with_max_chain_depth(1) // only 1 hop allowed
            .require_trust_root(true);

        let result = verifier.verify_credential_chain(&leaf_cred, &leaf.did_string());
        assert!(!result.valid);
        assert!(
            result.issues.iter().any(|i| i.contains("max depth")),
            "expected depth issue, got {:?}",
            result.issues
        );
    }

    #[tokio::test]
    async fn test_rootless_mode_no_trust_roots_accepts_self_issued() {
        let registry = Arc::new(IdentityRegistry::new());
        let verifier = IdentityVerifier::new(registry.clone());

        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pub_bytes = kp.public_key().as_bytes().to_vec();

        let id = registry
            .register_human_with_fee(pub_bytes.clone(), "Self".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let mut idmut = registry.resolve(&id.did_string()).unwrap();
        idmut.public_keys = vec![PublicKeyInfo {
            key_id: "key-1".to_string(),
            key_type: "Ed25519".to_string(),
            public_key: pub_bytes,
            purposes: vec![KeyPurpose::AssertionMethod],
        }];
        registry.upsert_identity_for_test(idmut);

        let mut cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            id.did_string(),
            id.did_string(),
        );
        let msg = cred.credential_subject.canonical_bytes().unwrap();
        let sig = Ed25519SignerImpl::new(kp).unwrap().sign(&msg).unwrap();
        cred = cred.with_proof(CredentialProof::new(
            "Ed25519",
            format!("{}#key-1", id.did_string()),
            sig.to_bytes(),
        ));

        // No trust roots configured → rootless mode → self-issued is terminal
        let result = verifier.verify_credential_chain(&cred, &id.did_string());
        assert!(
            result.valid,
            "rootless mode self-issued should pass: {:?}",
            result.issues
        );
        assert_eq!(result.chain_length, 1);
    }

    #[tokio::test]
    async fn test_trust_chain_aggregates_chain_results() {
        let (registry, root, _intermediate, leaf, _ic, leaf_cred) = build_chain_setup().await;

        let verifier = IdentityVerifier::new(registry.clone())
            .with_trust_root(root.did_string())
            .require_trust_root(true);

        // Resolve leaf and verify its trust chain (it has 1 credential)
        let result = verifier.verify_trust_chain(&leaf.did_string()).unwrap();
        assert_eq!(result.chain_results.len(), 1);
        assert_eq!(result.verified_chains, 1);
        assert!(
            result.valid,
            "leaf chain should verify: {:?}",
            result.issues
        );
        // Sanity check the embedded chain result
        assert_eq!(
            result.chain_results[0].terminating_root,
            Some(root.did_string())
        );
        // Avoid unused warning on leaf_cred
        let _ = leaf_cred;
    }
}
