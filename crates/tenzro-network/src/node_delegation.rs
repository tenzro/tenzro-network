//! A human's authorisation for a machine that has no hardware root of its own.
//!
//! Identity is rooted in a TPM when authority is delegated to the machine, and
//! in a passkey when it is delegated to a human. There is no third option, so a
//! node without a TPM needs a passkey — and this is what that looks like on the
//! wire.
//!
//! # Why this is a delegation and not a derivation
//!
//! The obvious design is the symmetric one: derive the node's key from the
//! passkey exactly as the TPM path derives it from the chip, using the WebAuthn
//! `prf` extension. That does not work, for two independent reasons, and
//! neither is a maturity problem that will resolve:
//!
//! - **A synced passkey is transferable by construction.** The `hmac-secret`
//!   an authenticator holds is replicated across every device the user signs
//!   in on, and at least one major implementation derives it from the synced
//!   private key. A secret that the platform copies for you is not a hardware
//!   root.
//! - **`prf` cannot be evaluated unattended.** `hmac-secret` returns
//!   `CTAP2_ERR_UNSUPPORTED_OPTION` when user presence is not asserted, in
//!   CTAP 2.1 and still in 2.3, and the `prf` extension additionally forces
//!   user verification. A node that must survive a reboot at 03:00 cannot
//!   re-derive anything.
//!
//! Caching the derived secret to disk would "solve" it and would also destroy
//! the property being bought: a cached 32-byte seed in the data directory is
//! precisely the unrooted random key this scheme exists to forbid.
//!
//! So the passkey signs a **binding over a key the machine generated**, rather
//! than producing that key. The assertion's challenge commits to the exact node
//! public key, so the signature cannot be lifted onto a different one. This is
//! the shape of ACME's External Account Binding and of Sigstore's ephemeral-key
//! flow, and it is what every production system that had this problem
//! converged on.
//!
//! # What this proves, and what it does not
//!
//! It proves a human, present and verified at a known time, authorised *this*
//! node key for *this* network until *this* expiry. It does not prove the node
//! key is non-exportable — nothing can, since the machine has no secure element
//! — which is why the delegation expires and why a node carrying one must be
//! recorded as a different trust tier from a TPM-rooted node. Compensate with
//! short lifetimes and re-enrolment, not with a longer expiry.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{NetworkError, Result};

/// Domain separator for the delegation challenge.
///
/// Distinct from every other challenge this codebase asks a passkey to sign, so
/// an assertion collected for one purpose cannot be replayed as a node
/// delegation. Versioned: changing the preimage means changing this string, so
/// old delegations fail closed rather than being silently reinterpreted.
const DELEGATION_DOMAIN: &[u8] = b"tenzro/node-delegation/v1";

/// The longest a delegation may run, regardless of what it claims.
///
/// The node key it authorises has no hardware protection, so the compensating
/// control is that the authorisation decays. A delegation asking for longer
/// than this is rejected outright rather than clamped — an operator who meant
/// to grant a year should learn that now, not discover in a year that they
/// were silently granted thirty days.
pub const MAX_DELEGATION_SECS: i64 = 30 * 24 * 60 * 60;

/// A passkey assertion authorising a node key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDelegation {
    /// The Ed25519 public key this delegation authorises, raw 32 bytes.
    pub node_pubkey: Vec<u8>,
    /// Opaque WebAuthn credential ID of the authorising passkey. Recorded so a
    /// verifier can tell which human authorised this node, and so a revoked
    /// credential can be matched without re-deriving anything.
    pub credential_id: Vec<u8>,
    /// The passkey's P-256 public key, uncompressed `x || y` (64 bytes).
    pub passkey_pubkey_xy: Vec<u8>,
    /// Unix seconds after which this delegation is void.
    pub not_after: i64,
    /// Unix seconds at which it was issued. Used only to bound the total span;
    /// the authority for "now" is the verifier's clock, never this field.
    pub issued_at: i64,
    /// What this delegation is valid for: the node's data-directory path.
    ///
    /// The same discriminator the TPM path puts in its derivation label, so
    /// both roots scope identically — one machine may host several nodes, and
    /// a delegation issued for one must not authorise another. Enforced at
    /// load time against the directory the node is actually running from.
    pub scope: String,
    /// Relying-party origin or RP ID the assertion was collected under.
    pub relying_party: String,
    /// Whether `relying_party` is an exact origin or a registrable RP ID.
    pub relying_party_is_rp_id: bool,
    /// Raw `authenticatorData` from the assertion.
    pub authenticator_data: Vec<u8>,
    /// Raw `clientDataJSON` bytes — byte-exact, never re-serialised.
    pub client_data_json: Vec<u8>,
    /// The authenticator's signature.
    pub signature: Vec<u8>,
}

/// The bytes a passkey signs to authorise a node key.
///
/// Every field that scopes the authorisation is inside the hash, so none of
/// them can be edited after the fact without invalidating the assertion. The
/// node key is first because it is the thing being authorised.
fn delegation_challenge(node_pubkey: &[u8], scope: &str, not_after: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DELEGATION_DOMAIN);
    h.update((node_pubkey.len() as u32).to_be_bytes());
    h.update(node_pubkey);
    h.update((scope.len() as u32).to_be_bytes());
    h.update(scope.as_bytes());
    h.update(not_after.to_be_bytes());
    h.finalize().into()
}

/// The challenge as it appears in `clientDataJSON`: base64url, unpadded.
pub fn delegation_challenge_b64url(node_pubkey: &[u8], scope: &str, not_after: i64) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(delegation_challenge(node_pubkey, scope, not_after))
}

impl NodeDelegation {
    /// Verify this delegation authorises `node_pubkey` on `scope` at
    /// `now_unix`.
    ///
    /// `node_pubkey` is passed in rather than read from the struct: the caller
    /// knows which key it is actually about to run as, and checking the
    /// delegation against *that* is the whole point. Trusting the struct's own
    /// field would verify only that the delegation is internally consistent.
    ///
    /// User verification is required. A delegation is a grant of authority, so
    /// mere presence — someone touched a key — is not enough; the ceremony has
    /// to prove a human, not a finger.
    ///
    /// # Errors
    ///
    /// Every failure is a refusal to start. There is no partial credit: a
    /// delegation that does not verify leaves the node with no root at all.
    pub fn verify(&self, node_pubkey: &[u8], scope: &str, now_unix: i64) -> Result<()> {
        if self.node_pubkey != node_pubkey {
            return Err(NetworkError::NoHardwareRoot(
                "delegation authorises a different node key than this node runs as".to_string(),
            ));
        }
        if self.scope != scope {
            return Err(NetworkError::NoHardwareRoot(format!(
                "delegation is scoped to `{}`, not `{scope}`",
                self.scope
            )));
        }
        if now_unix >= self.not_after {
            return Err(NetworkError::NoHardwareRoot(format!(
                "delegation expired at {} (now {now_unix}); re-enrol with a passkey",
                self.not_after
            )));
        }
        // A delegation claiming a span longer than policy allows is rejected
        // even while unexpired — otherwise a single ceremony could mint an
        // effectively permanent grant and the expiry would be decorative.
        if self.not_after.saturating_sub(self.issued_at) > MAX_DELEGATION_SECS {
            return Err(NetworkError::NoHardwareRoot(format!(
                "delegation spans {}s, longer than the {MAX_DELEGATION_SECS}s maximum",
                self.not_after.saturating_sub(self.issued_at)
            )));
        }

        let assertion = tenzro_crypto::webauthn::WebAuthnAssertion {
            authenticator_data: self.authenticator_data.clone(),
            client_data_json: self.client_data_json.clone(),
            signature: self.signature.clone(),
            user_handle: None,
        };
        let rp = if self.relying_party_is_rp_id {
            tenzro_crypto::webauthn::WebAuthnRelyingParty::RegistrableDomain {
                rp_id: self.relying_party.clone(),
            }
        } else {
            tenzro_crypto::webauthn::WebAuthnRelyingParty::Origin(self.relying_party.clone())
        };
        let expected =
            delegation_challenge_b64url(&self.node_pubkey, &self.scope, self.not_after);

        tenzro_crypto::webauthn::verify_webauthn_assertion_require_uv(
            &assertion,
            &self.passkey_pubkey_xy,
            &expected,
            &rp,
            tenzro_crypto::webauthn::WebAuthnCeremonyType::Get,
        )
        .map_err(|e| {
            NetworkError::NoHardwareRoot(format!("delegation assertion did not verify: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_commits_to_every_scoping_field() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let base = delegation_challenge(&key_a, "/var/lib/tenzro/a", 1000);

        // Changing any field must change the challenge, or that field is not
        // actually bound and could be edited after the ceremony.
        assert_ne!(base, delegation_challenge(&key_b, "/var/lib/tenzro/a", 1000));
        assert_ne!(base, delegation_challenge(&key_a, "/var/lib/tenzro/b", 1000));
        assert_ne!(base, delegation_challenge(&key_a, "/var/lib/tenzro/a", 1001));
        assert_eq!(base, delegation_challenge(&key_a, "/var/lib/tenzro/a", 1000));
    }

    /// Length-prefixing matters: without it, (`node_pubkey`, `scope`)
    /// pairs that concatenate to the same bytes would collide, letting one
    /// ceremony authorise a key it was never shown.
    #[test]
    fn concatenation_is_unambiguous() {
        let a = delegation_challenge(b"AB", "C", 0);
        let b = delegation_challenge(b"A", "BC", 0);
        assert_ne!(a, b);
    }

    fn delegation_for(node_pubkey: &[u8], scope: &str, not_after: i64) -> NodeDelegation {
        NodeDelegation {
            node_pubkey: node_pubkey.to_vec(),
            credential_id: b"cred".to_vec(),
            passkey_pubkey_xy: vec![0u8; 64],
            not_after,
            issued_at: 0,
            scope: scope.to_string(),
            relying_party: "https://keys.tenzro.xyz".to_string(),
            relying_party_is_rp_id: false,
            authenticator_data: Vec::new(),
            client_data_json: Vec::new(),
            signature: Vec::new(),
        }
    }

    /// The scoping checks must run before the cryptographic one, so a
    /// mis-scoped delegation is rejected for the honest reason rather than as
    /// an opaque signature failure.
    #[test]
    fn scope_is_checked_before_the_signature() {
        let key = [7u8; 32];
        let d = delegation_for(&key, "/var/lib/tenzro/a", 10_000);

        let wrong_key = d.verify(&[8u8; 32], "/var/lib/tenzro/a", 0).unwrap_err().to_string();
        assert!(wrong_key.contains("different node key"), "{wrong_key}");

        let wrong_scope = d
            .verify(&key, "/var/lib/tenzro/b", 0)
            .unwrap_err()
            .to_string();
        assert!(wrong_scope.contains("scoped to"), "{wrong_scope}");

        let expired = d.verify(&key, "/var/lib/tenzro/a", 10_001).unwrap_err().to_string();
        assert!(expired.contains("expired"), "{expired}");
    }

    /// An unexpired delegation with an over-long span is still refused, or the
    /// expiry would be a formality an operator could opt out of.
    #[test]
    fn an_over_long_span_is_refused_even_while_unexpired() {
        let key = [7u8; 32];
        let d = delegation_for(&key, "/var/lib/tenzro/a", MAX_DELEGATION_SECS + 1);
        let err = d.verify(&key, "/var/lib/tenzro/a", 0).unwrap_err().to_string();
        assert!(err.contains("longer than the"), "{err}");
    }

    /// WebAuthn L3 §6.1. Not re-exported by `tenzro-crypto`, so named here.
    const FLAG_UP: u8 = 0x01;

    const RP: &str = "https://keys.tenzro.xyz";

    /// Mint a delegation the way an enrolment ceremony would: build the
    /// challenge, put it in `clientDataJSON`, and have a real P-256 key sign
    /// the real WebAuthn payload over it.
    fn enrol(
        kp: &tenzro_crypto::p256::P256KeyPair,
        node_pubkey: &[u8],
        scope: &str,
        not_after: i64,
        flags: u8,
    ) -> NodeDelegation {
        let challenge = delegation_challenge_b64url(node_pubkey, scope, not_after);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{RP}","crossOrigin":false}}"#
        )
        .into_bytes();

        let mut auth_data = vec![0u8; 32];
        auth_data.push(flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes());

        let signer = tenzro_crypto::p256::P256Signer::from_keypair(kp);
        let prehash = tenzro_crypto::webauthn::webauthn_signed_hash(&auth_data, &cdj);
        let sig = signer.sign_prehash(&prehash);

        NodeDelegation {
            node_pubkey: node_pubkey.to_vec(),
            credential_id: b"cred-1".to_vec(),
            passkey_pubkey_xy: kp.public_key_bytes().to_vec(),
            not_after,
            issued_at: 0,
            scope: scope.to_string(),
            relying_party: RP.to_string(),
            relying_party_is_rp_id: false,
            authenticator_data: auth_data,
            client_data_json: cdj,
            signature: sig.as_bytes().to_vec(),
        }
    }

    /// The happy path, through the real signature check rather than stopping
    /// at a scope comparison.
    #[test]
    fn a_genuine_delegation_verifies() {
        let kp = tenzro_crypto::p256::P256KeyPair::generate();
        let node = [9u8; 32];
        let d = enrol(
            &kp,
            &node,
            "/var/lib/tenzro/a",
            1_000,
            FLAG_UP | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV,
        );
        d.verify(&node, "/var/lib/tenzro/a", 0).unwrap();
    }

    /// **The property the whole design exists for.** An attacker holding a
    /// valid delegation cannot retarget it at a node key the human never
    /// authorised. Rewriting `node_pubkey` to the victim's key passes the
    /// equality check but changes the recomputed challenge, so the assertion
    /// — signed over the original challenge — no longer matches.
    ///
    /// This is what makes the passkey a delegation rather than a bearer token.
    #[test]
    fn a_delegation_cannot_be_lifted_onto_another_node_key() {
        let kp = tenzro_crypto::p256::P256KeyPair::generate();
        let authorised = [9u8; 32];
        let attacker_key = [0xAAu8; 32];

        let mut stolen = enrol(
            &kp,
            &authorised,
            "/var/lib/tenzro/a",
            1_000,
            FLAG_UP | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV,
        );
        // Edit the record to claim the attacker's key. The scope check now
        // passes — the cryptography is the only thing left standing.
        stolen.node_pubkey = attacker_key.to_vec();

        let err = stolen
            .verify(&attacker_key, "/var/lib/tenzro/a", 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not verify"), "{err}");
    }

    /// Same argument for the expiry: extending `not_after` after the ceremony
    /// changes the challenge, so a delegation cannot outlive what was signed.
    #[test]
    fn the_expiry_cannot_be_extended_after_the_ceremony() {
        let kp = tenzro_crypto::p256::P256KeyPair::generate();
        let node = [9u8; 32];
        let mut d = enrol(
            &kp,
            &node,
            "/var/lib/tenzro/a",
            1_000,
            FLAG_UP | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV,
        );
        // A one-second extension, well inside the span policy, so the
        // rejection below is the signature and not the span check.
        d.not_after = 1_001;

        let err = d.verify(&node, "/var/lib/tenzro/a", 0).unwrap_err().to_string();
        assert!(err.contains("did not verify"), "{err}");
    }

    /// A touch is not a human. Presence alone must not grant authority, so an
    /// assertion without the UV flag is refused even though it is genuinely
    /// signed over the right challenge.
    #[test]
    fn presence_without_user_verification_is_refused() {
        let kp = tenzro_crypto::p256::P256KeyPair::generate();
        let node = [9u8; 32];
        let d = enrol(&kp, &node, "/var/lib/tenzro/a", 1_000, FLAG_UP);

        let err = d.verify(&node, "/var/lib/tenzro/a", 0).unwrap_err().to_string();
        assert!(err.contains("did not verify"), "{err}");
    }

    /// A delegation is only as good as the passkey named in it; swapping in a
    /// different credential's public key must not verify.
    #[test]
    fn another_passkey_cannot_vouch_for_the_delegation() {
        let real = tenzro_crypto::p256::P256KeyPair::generate();
        let impostor = tenzro_crypto::p256::P256KeyPair::generate();
        let node = [9u8; 32];

        let mut d = enrol(
            &real,
            &node,
            "/var/lib/tenzro/a",
            1_000,
            FLAG_UP | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV,
        );
        d.passkey_pubkey_xy = impostor.public_key_bytes().to_vec();

        let err = d.verify(&node, "/var/lib/tenzro/a", 0).unwrap_err().to_string();
        assert!(err.contains("did not verify"), "{err}");
    }
}
