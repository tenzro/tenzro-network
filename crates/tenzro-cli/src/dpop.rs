//! Client-side RFC 9449 DPoP: the key this CLI holds, and the per-request
//! proofs it signs with it.
//!
//! # Why this exists
//!
//! Every signing RPC on a node is DPoP-bound. `tenzro auth link-wallet` and
//! `tenzro auth refresh` already accept a `--dpop-jkt` and will bind an access
//! token to a client-held key — but nothing on this side *held* a key or
//! *minted* a proof, so the bound half of the flow was unreachable. The RPC
//! client forwarded a `TENZRO_DPOP_PROOF` environment variable and left the
//! caller to produce its contents.
//!
//! Which cannot work for more than one call. A proof commits to the method and
//! URL it is for, carries a `jti` the node caches against replay, and is
//! accepted only within ±60s of its `iat`. A proof is therefore a per-request
//! artifact, not a credential to export — so this mints one per call rather
//! than asking anyone to paste one.
//!
//! # Shape
//!
//! The key is Ed25519 (`OKP`/`Ed25519` is the only JWK form the node's
//! verifier accepts), persisted at `~/.tenzro/dpop.key` with `0600`
//! permissions. The proof is a compact JWS:
//!
//! ```text
//! header  = {"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":…}}
//! payload = {"htm":…,"htu":…,"iat":…,"jti":…[,"ath":…]}
//! ```
//!
//! `ath` is `base64url(SHA-256(access_token))` and is present whenever a token
//! is being presented — the node requires it on access-token requests, and
//! omitting it is the difference between a proof that authorises this call and
//! one that authorises any call the holder ever makes.
//!
//! The `jkt` is the RFC 7638 thumbprint over the canonical member set
//! `{"crv","kty","x"}`, byte-for-byte what `tenzro_auth::DpopProof::compute_jkt`
//! recomputes on the other side. It is the value `--dpop-jkt` wants.

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};
use tenzro_crypto::keys::{KeyPair, KeyType};

/// Where the client's DPoP key lives. One key per machine: the token is bound
/// to its thumbprint, so rotating it invalidates every token already issued
/// against the old one.
pub fn key_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".tenzro")
        .join("dpop.key")
}

/// The client's DPoP signing key.
pub struct DpopKey {
    keypair: KeyPair,
}

impl DpopKey {
    /// Load the stored key, generating and persisting one on first use.
    pub fn load_or_create() -> Result<Self> {
        let path = key_path();
        if path.exists() {
            return Self::load();
        }

        let keypair = KeyPair::generate(KeyType::Ed25519)
            .map_err(|e| anyhow::anyhow!("generate DPoP key: {e}"))?;
        let seed = keypair.secret_key().as_bytes().to_vec();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(&path, hex::encode(&seed))
            .with_context(|| format!("write {}", path.display()))?;
        restrict(&path)?;

        Ok(Self { keypair })
    }

    /// Load the stored key, failing if there is none.
    pub fn load() -> Result<Self> {
        let path = key_path();
        let hexed =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let seed =
            hex::decode(hexed.trim()).with_context(|| format!("{} is not hex", path.display()))?;
        let keypair = KeyPair::from_bytes(KeyType::Ed25519, &seed)
            .map_err(|e| anyhow::anyhow!("load DPoP key: {e}"))?;
        Ok(Self { keypair })
    }

    /// Whether a key has been created yet. Used to decide whether to mint a
    /// proof automatically rather than making every unrelated call pay for a
    /// key it does not need.
    pub fn exists() -> bool {
        key_path().exists()
    }

    /// The public key as a JWK, in RFC 7638 canonical form — sorted members,
    /// no whitespace. The canonical form is what gets hashed, so it is built
    /// once here and reused for both the thumbprint and the proof header.
    pub fn jwk(&self) -> String {
        let x = B64.encode(self.keypair.public_key().as_bytes());
        format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#)
    }

    /// RFC 7638 SHA-256 thumbprint of the JWK, base64url unpadded. This is the
    /// `--dpop-jkt` value, and what the node compares a token's `cnf.jkt`
    /// against.
    pub fn jkt(&self) -> String {
        B64.encode(Sha256::digest(self.jwk().as_bytes()))
    }

    /// Sign a proof for one request.
    ///
    /// `htu` is normalised to origin + path: the node strips the query before
    /// comparing, so a proof carrying one would never match.
    pub fn proof(&self, htm: &str, htu: &str, access_token: Option<&str>) -> Result<String> {
        let header = format!(r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{}}}"#, self.jwk());

        let iat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let jti = uuid::Uuid::new_v4().to_string();

        let mut payload = format!(
            r#"{{"htm":"{}","htu":"{}","iat":{},"jti":"{}""#,
            htm.to_uppercase(),
            normalize_htu(htu),
            iat,
            jti,
        );
        if let Some(token) = access_token.filter(|t| !t.is_empty()) {
            // Binds the proof to the token being presented. Without it a proof
            // is valid for any token the holder has.
            payload.push_str(&format!(
                r#","ath":"{}""#,
                B64.encode(Sha256::digest(token.as_bytes()))
            ));
        }
        payload.push('}');

        let signing_input = format!("{}.{}", B64.encode(&header), B64.encode(&payload));

        // `KeyPair` is not `Clone` and the signer consumes one, so rebuild it
        // from the stored seed rather than holding a second copy of the key.
        use tenzro_crypto::signatures::Signer;
        let keypair = KeyPair::from_bytes(KeyType::Ed25519, self.keypair.secret_key().as_bytes())
            .map_err(|e| anyhow::anyhow!("rebuild DPoP key: {e}"))?;
        let signer = tenzro_crypto::signatures::Ed25519SignerImpl::new(keypair)
            .map_err(|e| anyhow::anyhow!("build DPoP signer: {e}"))?;
        let sig = signer
            .sign(signing_input.as_bytes())
            .map_err(|e| anyhow::anyhow!("sign DPoP proof: {e}"))?;

        Ok(format!("{signing_input}.{}", B64.encode(sig.as_bytes())))
    }
}

/// Origin + path, query and fragment removed — the form the node compares
/// against.
///
/// The path is preserved exactly, including a bare trailing `/`. The node
/// derives its expected `htu` from the request URI it actually received, and
/// for a call to the root that is `http://host:port/` *with* the slash — so
/// trimming it produces a proof that is refused with an `htu mismatch`. A URL
/// given without any path gets one added for the same reason.
fn normalize_htu(url: &str) -> String {
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    let base = &url[..cut];

    // Does a path component exist at all? Look past `scheme://`.
    let after_scheme = base.find("://").map(|i| i + 3).unwrap_or(0);
    if base[after_scheme..].contains('/') {
        base.to_string()
    } else {
        format!("{base}/")
    }
}

#[cfg(unix)]
fn restrict(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DpopKey {
        DpopKey {
            keypair: KeyPair::generate(KeyType::Ed25519).unwrap(),
        }
    }

    /// The thumbprint must be computed over exactly the canonical member set,
    /// in order, with no whitespace — the node recomputes it independently and
    /// compares, so any drift makes every bound token unusable.
    #[test]
    fn jkt_matches_the_nodes_canonical_form() {
        let k = key();
        let jwk = k.jwk();
        assert!(
            jwk.starts_with(r#"{"crv":"Ed25519","kty":"OKP","x":""#),
            "{jwk}"
        );
        assert!(
            !jwk.contains(' '),
            "canonical JWK carries no whitespace: {jwk}"
        );

        // Recompute the way `tenzro_auth::DpopProof::compute_jkt` does.
        let v: serde_json::Value = serde_json::from_str(&jwk).unwrap();
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#,
            v["crv"].as_str().unwrap(),
            v["kty"].as_str().unwrap(),
            v["x"].as_str().unwrap(),
        );
        assert_eq!(canonical, jwk);
        assert_eq!(k.jkt(), B64.encode(Sha256::digest(canonical.as_bytes())));
    }

    #[test]
    fn proof_is_three_segments_and_verifies_against_its_own_jwk() {
        let k = key();
        let proof = k.proof("post", "http://127.0.0.1:8545/", None).unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS has three segments");

        let header: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["jwk"]["kty"], "OKP");

        let payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["htm"], "POST", "method is upper-cased");
        assert!(payload["iat"].as_u64().unwrap() > 0);
        assert!(!payload["jti"].as_str().unwrap().is_empty());

        // Signature is over `header.payload` and verifies under the embedded key.
        let x = B64.decode(header["jwk"]["x"].as_str().unwrap()).unwrap();
        let pubkey = tenzro_crypto::keys::PublicKey::new(KeyType::Ed25519, x);
        let sig = tenzro_crypto::signatures::Signature::new(
            KeyType::Ed25519,
            B64.decode(parts[2]).unwrap(),
        );
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        tenzro_crypto::signatures::verify(&pubkey, signing_input.as_bytes(), &sig)
            .expect("proof verifies under the key its own header advertises");
    }

    /// Presenting a token without binding the proof to it would leave the
    /// proof good for any other token the holder has.
    #[test]
    fn ath_is_present_and_is_the_token_digest() {
        let k = key();
        let token = "header.payload.sig";
        let proof = k.proof("POST", "http://n/", Some(token)).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(proof.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!(
            payload["ath"].as_str().unwrap(),
            B64.encode(Sha256::digest(token.as_bytes()))
        );

        // Absent when no token is presented, and an empty token is no token.
        let bare = k.proof("POST", "http://n/", Some("")).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(bare.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert!(payload.get("ath").is_none());
    }

    /// The node compares against the URI it received, so the path must survive
    /// verbatim — including the root slash. Trimming it cost a live request an
    /// `htu mismatch` before this was pinned.
    #[test]
    fn htu_drops_the_query_but_keeps_the_path() {
        assert_eq!(normalize_htu("http://n:8545/?x=1"), "http://n:8545/");
        assert_eq!(normalize_htu("http://n:8545/rpc#frag"), "http://n:8545/rpc");
        assert_eq!(normalize_htu("http://n:8545/rpc"), "http://n:8545/rpc");
        // A URL with no path at all still needs one.
        assert_eq!(normalize_htu("http://n:8545"), "http://n:8545/");
        assert_eq!(normalize_htu("http://n:8545?x=1"), "http://n:8545/");
    }

    /// Two proofs for the same request must differ, or the node's replay cache
    /// would reject the second.
    #[test]
    fn each_proof_carries_a_fresh_jti() {
        let k = key();
        let jti = |p: String| -> String {
            let payload: serde_json::Value =
                serde_json::from_slice(&B64.decode(p.split('.').nth(1).unwrap()).unwrap()).unwrap();
            payload["jti"].as_str().unwrap().to_string()
        };
        let a = jti(k.proof("POST", "http://n/", None).unwrap());
        let b = jti(k.proof("POST", "http://n/", None).unwrap());
        assert_ne!(a, b);
    }
}
