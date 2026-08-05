//! The proofs this CLI mints are checked against the *node's own* verifier.
//!
//! Two independent implementations have to agree byte-for-byte here: the
//! client builds a canonical JWK, hashes it to a thumbprint and signs a
//! compact JWS; the node re-derives the thumbprint from the JWK it was handed,
//! re-splits the JWS and verifies the signature over its first two segments.
//! A disagreement in any of that — a space in the canonical form, a padded
//! base64 alphabet, the wrong signing input — produces a proof that looks
//! well-formed and is refused at the door.
//!
//! So rather than assert the client's output against a hand-written fixture,
//! this feeds it to `tenzro_auth::DpopProof`, which is the code that runs on
//! the other side of the wire.

use tenzro_auth::DpopProof;
use tenzro_cli::dpop::DpopKey;

/// Point `HOME` at a scratch dir so the test neither reads nor overwrites the
/// operator's real key.
fn scratch_key(tmp: &std::path::Path) -> DpopKey {
    unsafe { std::env::set_var("HOME", tmp) };
    DpopKey::load_or_create().expect("create key")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[test]
fn node_verifier_accepts_a_cli_minted_proof() {
    let tmp = tempfile::tempdir().expect("tmp");
    let key = scratch_key(tmp.path());

    let htu = "http://127.0.0.1:8545/";
    let token = "access.token.value";
    let proof = key.proof("POST", htu, Some(token)).expect("mint");

    let (parsed, signed_input, signature) =
        DpopProof::parse_with_signed_input(&proof).expect("node parses the proof");

    let verified = parsed
        .verify("POST", htu, now(), &signed_input, &signature)
        .expect("node verifies the proof");

    // The thumbprint the node derives independently must be the one the client
    // advertises — this is the value a token's `cnf.jkt` is compared against,
    // so a mismatch makes every bound token unusable.
    assert_eq!(
        verified.jkt,
        key.jkt(),
        "client and node disagree on the JWK thumbprint"
    );
    assert!(!verified.jti.is_empty());

    // And `ath` binds the proof to the token being presented.
    let expected_ath = {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
    };
    assert_eq!(parsed.ath.as_deref(), Some(expected_ath.as_str()));
}

/// A proof is for one request. The node binds method and URL precisely so one
/// cannot be replayed as another, and this is the assertion that keeps the
/// client from quietly minting something broader than it claims.
#[test]
fn a_proof_does_not_authorise_a_different_request() {
    let tmp = tempfile::tempdir().expect("tmp");
    let key = scratch_key(tmp.path());

    let proof = key
        .proof("POST", "http://127.0.0.1:8545", None)
        .expect("mint");
    let (parsed, signed_input, signature) =
        DpopProof::parse_with_signed_input(&proof).expect("parse");

    assert!(
        parsed
            .verify(
                "GET",
                "http://127.0.0.1:8545",
                now(),
                &signed_input,
                &signature
            )
            .is_err(),
        "a proof minted for POST must not verify for GET"
    );
    assert!(
        parsed
            .verify(
                "POST",
                "http://127.0.0.1:9999",
                now(),
                &signed_input,
                &signature
            )
            .is_err(),
        "a proof minted for one URL must not verify for another"
    );
}

/// Tampering with the payload must invalidate the signature — otherwise the
/// signing input is not covering what we think it covers.
#[test]
fn an_altered_proof_fails_verification() {
    let tmp = tempfile::tempdir().expect("tmp");
    let key = scratch_key(tmp.path());

    let proof = key
        .proof("POST", "http://127.0.0.1:8545", None)
        .expect("mint");
    let (parsed, signed_input, mut signature) =
        DpopProof::parse_with_signed_input(&proof).expect("parse");

    signature[0] ^= 0xff;
    assert!(
        parsed
            .verify(
                "POST",
                "http://127.0.0.1:8545",
                now(),
                &signed_input,
                &signature
            )
            .is_err(),
        "a corrupted signature must not verify"
    );
}

/// The client strips query strings because the node compares against
/// origin+path. A proof minted from a URL carrying one still has to verify.
#[test]
fn a_url_with_a_query_still_produces_a_matching_proof() {
    let tmp = tempfile::tempdir().expect("tmp");
    let key = scratch_key(tmp.path());

    let proof = key
        .proof("POST", "http://127.0.0.1:8545/?trace=1", None)
        .expect("mint");
    let (parsed, signed_input, signature) =
        DpopProof::parse_with_signed_input(&proof).expect("parse");

    parsed
        .verify(
            "POST",
            "http://127.0.0.1:8545/",
            now(),
            &signed_input,
            &signature,
        )
        .expect("query-stripped htu matches what the node compares");
}
