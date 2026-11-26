//! Short-lived self-signed certificates a client pins by hash.
//!
//! A listener that has no certificate from an authority a client already
//! trusts serves one the node mints for itself. The client does not check a
//! chain: it holds the SHA-256 of the certificate, taken from a
//! [`Publication`] the node signed with the key its access tokens verify
//! under, and accepts that certificate alone.
//!
//! Browsers accept a pinned certificate only when it carries an ECDSA P-256
//! key and is valid for under fourteen days, so certificates here live
//! [`VALID_SECS`] and are replaced every [`ROTATE_SECS`]. Two exist at any
//! time: the one being served and the one that takes over at the next
//! rotation. A publication names both, so a client that read it before a
//! rotation still connects after it.
//!
//! The keys are made at start and held in memory only. A restarted node
//! serves new certificates, and its clients read the publication again.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_auth::TokenSigner;
use zeroize::Zeroizing;

/// How long one certificate is valid, start to end.
pub const VALID_SECS: u64 = 13 * 24 * 60 * 60;

/// How long one certificate is served before the next takes over.
pub const ROTATE_SECS: u64 = 5 * 24 * 60 * 60;

/// How far before its minting a certificate's validity starts, for clients
/// whose clocks run behind.
const BACKDATE_SECS: u64 = 60 * 60;

/// The longest the rotation task sleeps between looks at the clock, so a
/// machine that was suspended notices a rotation that came due meanwhile.
const LONGEST_SLEEP: Duration = Duration::from_secs(60 * 60);

/// Domain of the digest a [`Publication`] is signed over.
pub const PUBLICATION_DOMAIN: &[u8] = b"tenzro/pinned-cert/v1";

/// One certificate and when it holds.
#[derive(Debug, Clone)]
struct Pinned {
    key: Arc<CertifiedKey>,
    sha256: [u8; 32],
    not_before: u64,
    not_after: u64,
    /// When this certificate starts being served.
    serves_from: u64,
}

impl Pinned {
    /// A certificate for `names` minted at `now`, served from `serves_from`.
    fn mint(names: &[String], now: u64, serves_from: u64) -> Result<Self, String> {
        let not_before = now.saturating_sub(BACKDATE_SECS);
        let not_after = not_before + VALID_SECS;
        let at = |secs: u64| {
            time::OffsetDateTime::from_unix_timestamp(secs as i64)
                .map_err(|e| format!("certificate time {secs}: {e}"))
        };
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("certificate key: {e}"))?;
        let mut params = rcgen::CertificateParams::new(names.to_vec())
            .map_err(|e| format!("certificate names: {e}"))?;
        params.not_before = at(not_before)?;
        params.not_after = at(not_after)?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Tenzro node");
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("certificate: {e}"))?;
        let der: CertificateDer<'static> = cert.der().clone();
        let sha256: [u8; 32] = Sha256::digest(der.as_ref()).into();
        let pkcs8 = Zeroizing::new(key_pair.serialize_der());
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
        ))
        .map_err(|e| format!("certificate signing key: {e}"))?;
        Ok(Self {
            key: Arc::new(CertifiedKey::new(vec![der], signing_key)),
            sha256,
            not_before,
            not_after,
            serves_from,
        })
    }

    fn hash(&self) -> PinnedHash {
        PinnedHash {
            sha256: hex::encode(self.sha256),
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }
}

/// The certificate a listener serves now and the one it serves next.
#[derive(Debug)]
pub struct PinnedCerts {
    names: Vec<String>,
    /// `(serving, next)`.
    pair: RwLock<(Pinned, Pinned)>,
}

impl PinnedCerts {
    /// Certificates for a listener reached under `names` (DNS names or IP
    /// addresses), the first served from `now` (seconds since the epoch).
    pub fn mint(names: Vec<String>, now: u64) -> Result<Self, String> {
        if names.is_empty() {
            return Err("a certificate needs at least one name".to_string());
        }
        let serving = Pinned::mint(&names, now, now)?;
        let next = Pinned::mint(&names, now, now + ROTATE_SECS)?;
        Ok(Self {
            names,
            pair: RwLock::new((serving, next)),
        })
    }

    /// When the next certificate takes over, in seconds since the epoch.
    pub fn next_rotation(&self) -> u64 {
        self.pair.read().1.serves_from
    }

    /// Puts the next certificate into service once its time has come, and
    /// mints the one after it. Returns whether a rotation happened.
    pub fn rotate_if_due(&self, now: u64) -> Result<bool, String> {
        if now < self.next_rotation() {
            return Ok(false);
        }
        let following = Pinned::mint(&self.names, now, now + ROTATE_SECS)?;
        let mut pair = self.pair.write();
        // A clock that jumped far ahead can leave the waiting certificate
        // too close to its end to serve a whole period.
        let serving = if pair.1.not_after >= now + ROTATE_SECS {
            Pinned {
                serves_from: now,
                ..pair.1.clone()
            }
        } else {
            Pinned::mint(&self.names, now, now)?
        };
        *pair = (serving, following);
        Ok(true)
    }

    /// Rotates the certificates as they come due, for as long as the task
    /// lives.
    pub async fn run(self: Arc<Self>) {
        loop {
            let now = unix_now();
            match self.rotate_if_due(now) {
                Ok(true) => tracing::info!("pinned certificate rotated"),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, "pinned certificate rotation failed"),
            }
            let wait = Duration::from_secs(self.next_rotation().saturating_sub(now).max(1));
            tokio::time::sleep(wait.min(LONGEST_SLEEP)).await;
        }
    }

    /// The hashes a client may pin: the certificate served now, then the one
    /// served next.
    pub fn hashes(&self) -> Vec<PinnedHash> {
        let pair = self.pair.read();
        vec![pair.0.hash(), pair.1.hash()]
    }

    /// The hashes, signed by `signer` as `issuer` for the listener named
    /// `listener` at `now`.
    pub fn publish(
        &self,
        signer: &dyn TokenSigner,
        issuer: &str,
        listener: &str,
        now: u64,
    ) -> Result<Publication, String> {
        let hashes = self.hashes();
        let digest = publication_digest(issuer, listener, &hashes, now)?;
        let signature = signer.sign_prehash(&digest)?;
        let public_key = signer.public_key();
        Ok(Publication {
            issuer: issuer.to_string(),
            listener: listener.to_string(),
            hashes,
            signed_at: now,
            kid: tenzro_auth::key_id(&public_key),
            signature: URL_SAFE_NO_PAD.encode(signature),
        })
    }
}

impl ResolvesServerCert for PinnedCerts {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.pair.read().0.key.clone())
    }
}

/// One certificate a client may pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedHash {
    /// SHA-256 of the certificate's DER encoding, in hex.
    pub sha256: String,
    /// Start of its validity, seconds since the epoch.
    pub not_before: u64,
    /// End of its validity, seconds since the epoch.
    pub not_after: u64,
}

/// The certificates of one listener, signed by the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Publication {
    /// The node that serves the listener.
    pub issuer: String,
    /// Which of the node's listeners these certificates belong to.
    pub listener: String,
    /// The certificate served now, then the one served next.
    pub hashes: Vec<PinnedHash>,
    /// When the node signed this, seconds since the epoch.
    pub signed_at: u64,
    /// Key id of the signing key: the one the node's access tokens name.
    pub kid: String,
    /// ECDSA P-256 signature (`r || s`, base64url) over
    /// [`publication_digest`].
    pub signature: String,
}

/// The SHA-256 digest a publication's signature covers: the domain, then the
/// issuer and the listener each behind its length, the signing time, and
/// every hash with its validity, all integers big-endian.
pub fn publication_digest(
    issuer: &str,
    listener: &str,
    hashes: &[PinnedHash],
    signed_at: u64,
) -> Result<[u8; 32], String> {
    let mut h = Sha256::new();
    h.update(PUBLICATION_DOMAIN);
    for text in [issuer, listener] {
        h.update((text.len() as u64).to_be_bytes());
        h.update(text.as_bytes());
    }
    h.update(signed_at.to_be_bytes());
    h.update((hashes.len() as u64).to_be_bytes());
    for hash in hashes {
        let mut sha256 = [0u8; 32];
        hex::decode_to_slice(&hash.sha256, &mut sha256)
            .map_err(|e| format!("certificate hash {}: {e}", hash.sha256))?;
        h.update(sha256);
        h.update(hash.not_before.to_be_bytes());
        h.update(hash.not_after.to_be_bytes());
    }
    Ok(h.finalize().into())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;

    struct SoftwareSigner(p256::ecdsa::SigningKey);

    impl SoftwareSigner {
        fn new() -> Self {
            let mut bytes = [7u8; 32];
            bytes[0] = 1;
            Self(p256::ecdsa::SigningKey::from_slice(&bytes).expect("a valid P-256 scalar"))
        }
    }

    impl TokenSigner for SoftwareSigner {
        fn public_key(&self) -> [u8; 64] {
            let point = self.0.verifying_key().to_sec1_point(false);
            let mut out = [0u8; 64];
            out.copy_from_slice(&point.as_bytes()[1..]);
            out
        }

        fn sign_prehash(&self, prehash: &[u8; 32]) -> Result<[u8; 64], String> {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let sig: p256::ecdsa::Signature =
                self.0.sign_prehash(prehash).map_err(|e| e.to_string())?;
            let mut out = [0u8; 64];
            out.copy_from_slice(&sig.to_bytes());
            Ok(out)
        }
    }

    fn certs() -> PinnedCerts {
        PinnedCerts::mint(vec!["localhost".to_string(), "127.0.0.1".to_string()], NOW).unwrap()
    }

    fn served(certs: &PinnedCerts) -> CertificateDer<'static> {
        certs.pair.read().0.key.cert[0].clone()
    }

    #[test]
    fn a_certificate_is_p256_and_valid_for_under_fourteen_days() {
        let certs = certs();
        for hash in certs.hashes() {
            assert!(hash.not_after - hash.not_before < 14 * DAY);
            assert!(hash.not_before < NOW);
        }
        let der = served(&certs);
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        assert_eq!(
            cert.public_key().algorithm.algorithm.to_id_string(),
            "1.2.840.10045.2.1"
        );
        assert_eq!(
            cert.public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| oid.to_id_string())
                .as_deref(),
            Some("1.2.840.10045.3.1.7")
        );
        assert_eq!(
            cert.validity().not_after.timestamp() as u64,
            NOW - BACKDATE_SECS + VALID_SECS
        );
    }

    #[test]
    fn the_published_hash_is_the_sha256_of_the_served_certificate() {
        let certs = certs();
        let hashes = certs.hashes();
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes[0].sha256,
            hex::encode(Sha256::digest(served(&certs).as_ref()))
        );
        assert_ne!(hashes[0].sha256, hashes[1].sha256);
    }

    #[test]
    fn the_next_certificate_takes_over_when_its_time_comes_and_not_before() {
        let certs = certs();
        let before = certs.hashes();
        assert_eq!(certs.next_rotation(), NOW + ROTATE_SECS);
        assert!(!certs.rotate_if_due(NOW + ROTATE_SECS - 1).unwrap());
        assert_eq!(certs.hashes(), before);

        assert!(certs.rotate_if_due(NOW + ROTATE_SECS).unwrap());
        let after = certs.hashes();
        assert_eq!(
            after[0], before[1],
            "a hash pinned before the rotation still holds"
        );
        assert_ne!(after[1], before[1]);
        assert_eq!(certs.next_rotation(), NOW + 2 * ROTATE_SECS);
    }

    #[test]
    fn every_certificate_outlives_the_time_it_is_served() {
        let certs = certs();
        for _ in 0..4 {
            let serving_until = certs.next_rotation();
            assert!(certs.hashes()[0].not_after > serving_until);
            assert!(certs.rotate_if_due(serving_until).unwrap());
        }
    }

    #[test]
    fn a_clock_that_jumped_past_the_waiting_certificate_gets_a_fresh_one() {
        let certs = certs();
        let before = certs.hashes();
        let later = NOW + 30 * DAY;
        assert!(certs.rotate_if_due(later).unwrap());
        let after = certs.hashes();
        assert_ne!(after[0], before[1]);
        assert!(after[0].not_before <= later && later + ROTATE_SECS <= after[0].not_after);
    }

    #[test]
    fn the_publication_digest_is_the_one_clients_compute() {
        // The TypeScript SDK's test pins the same vector.
        let hash = |byte: u8, not_before, not_after| PinnedHash {
            sha256: hex::encode([byte; 32]),
            not_before,
            not_after,
        };
        let digest = publication_digest(
            "did:tenzro:machine:a",
            "app-transport",
            &[
                hash(0x11, 1_799_996_400, 1_801_119_600),
                hash(0x22, 1_800_428_400, 1_801_551_600),
            ],
            1_800_000_005,
        )
        .unwrap();
        assert_eq!(
            hex::encode(digest),
            "f0265744139c6181317242e4ea16ffa9228d02f096b2d85dcdc93c552bbfc400"
        );
    }

    #[test]
    fn a_publication_verifies_under_the_signer_and_names_what_it_covers() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let certs = certs();
        let signer = SoftwareSigner::new();
        let publication = certs
            .publish(&signer, "did:tenzro:machine:a", "app-transport", NOW + 5)
            .unwrap();
        assert_eq!(publication.hashes, certs.hashes());
        assert_eq!(publication.kid, tenzro_auth::key_id(&signer.public_key()));

        let verify = |p: &Publication| {
            let digest =
                publication_digest(&p.issuer, &p.listener, &p.hashes, p.signed_at).unwrap();
            let bytes = URL_SAFE_NO_PAD.decode(&p.signature).unwrap();
            let signature = p256::ecdsa::Signature::from_slice(&bytes).unwrap();
            signer
                .0
                .verifying_key()
                .verify_prehash(&digest, &signature)
                .is_ok()
        };
        assert!(verify(&publication));

        let mut other_listener = publication.clone();
        other_listener.listener = "pairing".to_string();
        assert!(!verify(&other_listener));
        let mut other_issuer = publication.clone();
        other_issuer.issuer = "did:tenzro:machine:b".to_string();
        assert!(!verify(&other_issuer));
        let mut other_hash = publication.clone();
        other_hash.hashes[0].sha256 = hex::encode([9u8; 32]);
        assert!(!verify(&other_hash));
        let mut longer_life = publication.clone();
        longer_life.hashes[1].not_after += 1;
        assert!(!verify(&longer_life));
    }

    /// Carries everything `from` has to send into `to`.
    fn carry<A, B>(from: &mut rustls::ConnectionCommon<A>, to: &mut rustls::ConnectionCommon<B>) {
        let mut wire = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut wire).unwrap();
        }
        let mut rest = wire.as_slice();
        while !rest.is_empty() {
            to.read_tls(&mut rest).unwrap();
            to.process_new_packets().unwrap();
        }
    }

    #[test]
    fn a_tls_client_that_pins_the_hash_completes_a_handshake() {
        let certs = Arc::new(PinnedCerts::mint(vec!["localhost".to_string()], unix_now()).unwrap());
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(certs.clone());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(served(&certs)).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(client),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
        while client.is_handshaking() || server.is_handshaking() {
            carry(&mut client, &mut server);
            carry(&mut server, &mut client);
        }
        let presented = client.peer_certificates().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(presented[0].as_ref())),
            certs.hashes()[0].sha256
        );
    }
}
