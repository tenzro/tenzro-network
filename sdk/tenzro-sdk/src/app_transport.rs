//! The app transport (preview): a device of an application signs in to a
//! Tenzro node over WebTransport and opens streams to devices of other
//! identities, which the node carries and counts against the opener.
//!
//! Whatever travels inside a stream is the application's own: seal it end to
//! end before writing it. The node only moves the bytes.
//!
//! The node serves this only when its operator turned it on, and the wire
//! format may still change. Built with the `app-transport` feature.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

use crate::access::AccessCredential;
use crate::error::{SdkError, SdkResult};

/// Frames above this size are refused, as the node refuses them.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// The name a node publishes the app transport's certificates under.
pub const LISTENER: &str = "app-transport";

/// FIPS 204 context of a welcome's ML-DSA-65 signature.
pub const WELCOME_PQ_CONTEXT: &[u8] = b"tenzro/app-transport/welcome";

const WELCOME_DOMAIN: &[u8] = b"tenzro/app-transport/welcome/v1";
const PUBLICATION_DOMAIN: &[u8] = b"tenzro/pinned-cert/v1";
const CLOCK_SKEW_SECS: u64 = 5 * 60;
const ML_DSA_65_VK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;

/// What is said on a session's control stream and at the head of a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    /// Node to device: the nonce a sign-in proof is made over.
    Challenge { nonce: String },
    /// Device to node: an access token, a DPoP proof over the nonce and,
    /// answering `payment_required`, a payment credential (JSON).
    Hello {
        access_token: String,
        dpop: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        payment: Option<String>,
        /// Keying material (hex) exported from the session's TLS secrets,
        /// binding the proof to this session.
        #[serde(skip_serializing_if = "Option::is_none")]
        binding: Option<String>,
    },
    /// Node to device: the node's access policy asks payment of `price` of
    /// `asset` per mebibyte carried; `challenge` (JSON) names the ceiling.
    PaymentRequired {
        challenge: String,
        price: String,
        asset: String,
    },
    /// Node to device: who the node took it for, until when, signed.
    Welcome {
        did: String,
        device: String,
        expires_at: u64,
        signature: String,
        pq_signature: String,
    },
    /// Device to node: who may open streams to it.
    Listen {
        from: Vec<String>,
        apps: Vec<String>,
    },
    /// Node to device: the listen took effect.
    Listening,
    /// Device to node: open a stream to `to`, signed in to `via` if given.
    Open {
        to: String,
        device: Option<String>,
        via: Option<String>,
        app: String,
    },
    /// Node to device: somebody opened this stream to it.
    Incoming {
        from: String,
        device: String,
        via: Option<String>,
        app: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        flow: Option<u32>,
    },
    /// Device to node: it takes the stream.
    Accept,
    /// Device to node: it does not.
    Decline,
    /// Node to device: the stream reaches `device`; bytes follow, and
    /// datagrams under `flow` when it is given.
    Opened {
        device: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        flow: Option<u32>,
    },
    /// Node to device: no, and why.
    Refused { reason: String },
}

async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> SdkResult<Frame> {
    let len = recv
        .read_u32_le()
        .await
        .map_err(|e| SdkError::ConnectionError(format!("app transport: {e}")))?
        as usize;
    if len > MAX_FRAME_BYTES {
        return Err(SdkError::ConnectionError(format!(
            "app transport frame of {len} bytes exceeds {MAX_FRAME_BYTES}"
        )));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|e| SdkError::ConnectionError(format!("app transport: {e}")))?;
    serde_json::from_slice(&body)
        .map_err(|e| SdkError::ConnectionError(format!("app transport frame: {e}")))
}

async fn write_frame<W: AsyncWrite + Unpin>(send: &mut W, frame: &Frame) -> SdkResult<()> {
    let body = serde_json::to_vec(frame)
        .map_err(|e| SdkError::InvalidParameter(format!("app transport frame: {e}")))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(SdkError::InvalidParameter(format!(
            "app transport frame of {} bytes exceeds {MAX_FRAME_BYTES}",
            body.len()
        )));
    }
    let mut wire = (body.len() as u32).to_le_bytes().to_vec();
    wire.extend(body);
    send.write_all(&wire)
        .await
        .map_err(|e| SdkError::ConnectionError(format!("app transport: {e}")))
}

/// The URI a sign-in proof names: the session's nonce.
pub fn sign_in_htu(nonce: &str) -> String {
    format!("tenzro-app://{nonce}")
}

fn framed(parts: &[&[u8]], tail: &[u64], domain: &[u8]) -> Sha256 {
    let mut h = Sha256::new();
    h.update(domain);
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    for n in tail {
        h.update(n.to_be_bytes());
    }
    h
}

/// The digest a node signs a welcome over.
pub fn welcome_digest(nonce: &str, did: &str, device: &str, expires_at: u64) -> [u8; 32] {
    framed(
        &[nonce.as_bytes(), did.as_bytes(), device.as_bytes()],
        &[expires_at],
        WELCOME_DOMAIN,
    )
    .finalize()
    .into()
}

/// One certificate a client may pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedHash {
    /// SHA-256 of the certificate's DER encoding, hex.
    pub sha256: String,
    /// Start of its validity, seconds since the epoch.
    pub not_before: u64,
    /// End of its validity, seconds since the epoch.
    pub not_after: u64,
}

/// The certificates of one listener of a node, signed by that node.
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
    /// ECDSA P-256 signature (`r || s`, base64url) over the publication.
    pub signature: String,
}

/// `tenzro_getAppTransportInfo`: where devices reach a node's app transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppTransportInfo {
    /// The URL to open a session at.
    pub url: String,
    /// The certificates to pin; `None` when the node serves a certificate
    /// the platform trusts on its own.
    pub publication: Option<Publication>,
}

fn hash32(hex_text: &str) -> SdkResult<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_text, &mut out)
        .map_err(|e| SdkError::InvalidParameter(format!("certificate hash {hex_text}: {e}")))?;
    Ok(out)
}

fn signature_of(text: &str) -> SdkResult<p256::ecdsa::Signature> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| SdkError::AuthenticationError(format!("signature: {e}")))?;
    p256::ecdsa::Signature::from_slice(&bytes)
        .map_err(|e| SdkError::AuthenticationError(format!("signature: {e}")))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The digest a node signs a publication over.
pub fn publication_digest(publication: &Publication) -> SdkResult<[u8; 32]> {
    let mut h = framed(
        &[
            publication.issuer.as_bytes(),
            publication.listener.as_bytes(),
        ],
        &[publication.signed_at, publication.hashes.len() as u64],
        PUBLICATION_DOMAIN,
    );
    for hash in &publication.hashes {
        h.update(hash32(&hash.sha256)?);
        h.update(hash.not_before.to_be_bytes());
        h.update(hash.not_after.to_be_bytes());
    }
    Ok(h.finalize().into())
}

/// Checks a node's certificate publication against the node's access-token
/// key and returns the hashes to pin: those valid at `now`. Refused when it
/// names another node or listener, is not signed by `node_key`, was signed
/// in the future or more than `max_age_secs` ago.
pub fn verify_publication(
    publication: &Publication,
    issuer: &str,
    node_key: &p256::ecdsa::VerifyingKey,
    now: u64,
    max_age_secs: u64,
) -> SdkResult<Vec<[u8; 32]>> {
    let refuse = |why: String| Err(SdkError::AuthenticationError(why));
    if publication.issuer != issuer {
        return refuse(format!(
            "publication is from {}, not {issuer}",
            publication.issuer
        ));
    }
    if publication.listener != LISTENER {
        return refuse(format!(
            "publication is for {}, not {LISTENER}",
            publication.listener
        ));
    }
    if publication.signed_at > now + CLOCK_SKEW_SECS {
        return refuse("publication is signed in the future".to_string());
    }
    if now.saturating_sub(publication.signed_at) > max_age_secs {
        return refuse("publication is too old; fetch it again".to_string());
    }
    let digest = publication_digest(publication)?;
    node_key
        .verify_prehash(&digest, &signature_of(&publication.signature)?)
        .map_err(|_| {
            SdkError::AuthenticationError("publication is not signed by the node's key".into())
        })?;
    let current: Vec<[u8; 32]> = publication
        .hashes
        .iter()
        .filter(|h| h.not_before <= now + CLOCK_SKEW_SECS && now < h.not_after)
        .map(|h| hash32(&h.sha256))
        .collect::<SdkResult<_>>()?;
    if current.is_empty() {
        return refuse("no certificate in the publication is valid now".to_string());
    }
    Ok(current)
}

/// The node keys a welcome is checked against.
#[derive(Debug, Clone)]
pub struct WelcomeKeys {
    /// The node's access-token key.
    pub node_key: p256::ecdsa::VerifyingKey,
    /// The node's ML-DSA-65 key (`#pq-key-1` of its DID document); the
    /// ML-DSA-65 signature is checked too when given.
    pub ml_dsa_key: Option<Vec<u8>>,
}

fn ml_dsa_verify(vk: &[u8], ctx: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
    if vk.len() != ML_DSA_65_VK_LEN || sig.len() != ML_DSA_65_SIG_LEN {
        return false;
    }
    let mut vk_arr: EncodedVerifyingKey<MlDsa65> = Default::default();
    let dst: &mut [u8] = vk_arr.as_mut();
    dst.copy_from_slice(vk);
    let key = VerifyingKey::<MlDsa65>::decode(&vk_arr);
    let mut sig_arr: EncodedSignature<MlDsa65> = Default::default();
    let dst: &mut [u8] = sig_arr.as_mut();
    dst.copy_from_slice(sig);
    let Some(sig) = Signature::<MlDsa65>::decode(&sig_arr) else {
        return false;
    };
    key.verify_with_context(msg, ctx, &sig)
}

/// Checks that `welcome` was signed by the node over the session's `nonce`.
pub fn verify_welcome(welcome: &Frame, nonce: &str, keys: &WelcomeKeys) -> SdkResult<()> {
    let Frame::Welcome {
        did,
        device,
        expires_at,
        signature,
        pq_signature,
    } = welcome
    else {
        return Err(SdkError::AuthenticationError("not a welcome".into()));
    };
    let digest = welcome_digest(nonce, did, device, *expires_at);
    keys.node_key
        .verify_prehash(&digest, &signature_of(signature)?)
        .map_err(|_| {
            SdkError::AuthenticationError("the welcome is not signed by the node's key".into())
        })?;
    if let Some(ml_dsa_key) = &keys.ml_dsa_key {
        let pq = URL_SAFE_NO_PAD
            .decode(pq_signature)
            .map_err(|e| SdkError::AuthenticationError(format!("ML-DSA-65 signature: {e}")))?;
        if !ml_dsa_verify(ml_dsa_key, WELCOME_PQ_CONTEXT, &digest, &pq) {
            return Err(SdkError::AuthenticationError(
                "the welcome is not signed by the node's ML-DSA-65 key".into(),
            ));
        }
    }
    Ok(())
}

/// Pays for carriage when a node's access policy asks it.
pub trait CarriagePayer: Send + Sync {
    /// A payment credential (JSON) answering `challenge` (JSON), whose
    /// amount is the most the session may be charged at `price` of `asset`
    /// per mebibyte.
    fn pay<'a>(
        &'a self,
        challenge: &'a str,
        price: &'a str,
        asset: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SdkResult<String>> + Send + 'a>>;
}

/// The label a sign-in's TLS binding is exported under (RFC 5705).
const EXPORTER_LABEL: &[u8] = b"EXPORTER-tenzro-app-transport-sign-in";

/// The keying material `connection` exports for a sign-in over `nonce`.
fn binding(connection: &Connection, nonce: &str) -> SdkResult<String> {
    let mut out = [0u8; 32];
    connection
        .export_keying_material(&mut out, EXPORTER_LABEL, nonce.as_bytes())
        .map_err(|_| SdkError::ConnectionError("the session exports no keying material".into()))?;
    Ok(hex::encode(out))
}

/// A hello bound to `connection`'s TLS session.
fn hello(
    connection: &Connection,
    credential: &AccessCredential,
    nonce: &str,
    payment: Option<String>,
) -> SdkResult<Frame> {
    let binding = binding(connection, nonce)?;
    Ok(Frame::Hello {
        access_token: credential.token.clone(),
        dpop: credential.prover.proof(
            "POST",
            &format!("tenzro-app://{nonce}/{binding}"),
            &credential.token,
        )?,
        payment,
        binding: Some(binding),
    })
}

/// A stream between two devices, once the far device took it.
#[derive(Debug)]
pub struct AppStream {
    /// The device at the other end.
    pub device: String,
    /// The flow datagrams to and from that device travel under, while the
    /// stream lasts; none for a stream through another node.
    pub flow: Option<u32>,
    /// Bytes to the other device. Shut it down to say you are done sending.
    pub send: SendStream,
    /// Bytes from the other device.
    pub recv: RecvStream,
}

/// A stream another device opened to this one, waiting for an answer.
#[derive(Debug)]
pub struct IncomingStream {
    /// The identity that opened it.
    pub from: String,
    /// The device it was opened from.
    pub device: String,
    /// The node that carried it here, when not the one this device uses.
    pub via: Option<String>,
    /// The application label it was opened with.
    pub app: String,
    flow: Option<u32>,
    send: SendStream,
    recv: RecvStream,
}

impl IncomingStream {
    /// Takes the stream.
    pub async fn accept(mut self) -> SdkResult<AppStream> {
        write_frame(&mut self.send, &Frame::Accept).await?;
        Ok(AppStream {
            device: self.device,
            flow: self.flow,
            send: self.send,
            recv: self.recv,
        })
    }

    /// Turns it down.
    pub async fn decline(mut self) -> SdkResult<()> {
        write_frame(&mut self.send, &Frame::Decline).await?;
        let _ = self.send.shutdown().await;
        Ok(())
    }
}

/// A device's session with a node's app transport.
pub struct AppSession {
    _endpoint: Endpoint<wtransport::endpoint::endpoint_side::Client>,
    connection: Connection,
    control: (SendStream, RecvStream),
    nonce: String,
    keys: Option<WelcomeKeys>,
    /// The identity the node took this device for.
    pub did: String,
    /// This device, as the node names it.
    pub device: String,
    /// When the session ends unless renewed, seconds since the epoch.
    pub expires_at: u64,
}

impl std::fmt::Debug for AppSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppSession")
            .field("did", &self.did)
            .field("device", &self.device)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl AppSession {
    /// Opens a session at `url`, pinning `pinned` (from
    /// [`verify_publication`]; empty for a certificate the platform trusts),
    /// and signs in with `credential`. With `keys`, the node's welcome must
    /// carry its signatures. When the node asks payment for carriage, `payer`
    /// pays; without one the sign-in fails.
    pub async fn connect(
        url: &str,
        credential: &AccessCredential,
        pinned: &[[u8; 32]],
        keys: Option<WelcomeKeys>,
        payer: Option<&dyn CarriagePayer>,
    ) -> SdkResult<Self> {
        let config = if pinned.is_empty() {
            ClientConfig::builder()
                .with_bind_default()
                .with_native_certs()
                .build()
        } else {
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes(pinned.iter().map(|h| Sha256Digest::new(*h)))
                .build()
        };
        let endpoint = Endpoint::client(config)
            .map_err(|e| SdkError::ConnectionError(format!("app transport client: {e}")))?;
        let connection = endpoint
            .connect(url)
            .await
            .map_err(|e| SdkError::ConnectionError(format!("app transport {url}: {e}")))?;
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| SdkError::ConnectionError(format!("app transport control stream: {e}")))?;
        let Frame::Challenge { nonce } = read_frame(&mut recv).await? else {
            return Err(SdkError::AuthenticationError(
                "the node sent no challenge".into(),
            ));
        };
        write_frame(&mut send, &hello(&connection, credential, &nonce, None)?).await?;
        let mut welcome = read_frame(&mut recv).await?;
        if let Frame::PaymentRequired {
            challenge,
            price,
            asset,
        } = &welcome
        {
            let payer = payer.ok_or_else(|| {
                SdkError::AuthenticationError(format!(
                    "the node asks {price} {asset} a mebibyte for carriage; give a payer"
                ))
            })?;
            let payment = payer.pay(challenge, price, asset).await?;
            write_frame(
                &mut send,
                &hello(&connection, credential, &nonce, Some(payment))?,
            )
            .await?;
            welcome = read_frame(&mut recv).await?;
        }
        let Frame::Welcome {
            did,
            device,
            expires_at,
            ..
        } = &welcome
        else {
            let reason = match welcome {
                Frame::Refused { reason } => reason,
                _ => "the node refused the sign-in".to_string(),
            };
            return Err(SdkError::AuthenticationError(reason));
        };
        if let Some(keys) = &keys {
            verify_welcome(&welcome, &nonce, keys)?;
        }
        Ok(Self {
            did: did.clone(),
            device: device.clone(),
            expires_at: *expires_at,
            _endpoint: endpoint,
            connection,
            control: (send, recv),
            nonce,
            keys,
        })
    }

    async fn ask(&mut self, frame: &Frame) -> SdkResult<Frame> {
        write_frame(&mut self.control.0, frame).await?;
        read_frame(&mut self.control.1).await
    }

    /// Says who may open streams to this device from now on: the identities
    /// in `from`, and anyone opening with a label in `apps`. Until it is
    /// called, nobody can.
    pub async fn listen(&mut self, from: Vec<String>, apps: Vec<String>) -> SdkResult<()> {
        match self.ask(&Frame::Listen { from, apps }).await? {
            Frame::Listening => Ok(()),
            _ => Err(SdkError::ConnectionError(
                "the node did not take the listen".into(),
            )),
        }
    }

    /// Keeps the session past its token's end with a fresh token for the
    /// same identity and device.
    pub async fn renew(&mut self, credential: &AccessCredential) -> SdkResult<()> {
        let hello = hello(&self.connection, credential, &self.nonce, None)?;
        let welcome = self.ask(&hello).await?;
        let Frame::Welcome { expires_at, .. } = &welcome else {
            return Err(SdkError::AuthenticationError(
                "the node refused the renewal".into(),
            ));
        };
        if let Some(keys) = &self.keys {
            verify_welcome(&welcome, &self.nonce, keys)?;
        }
        self.expires_at = *expires_at;
        Ok(())
    }

    /// Opens a stream to a device of `to` with the application label `app`:
    /// `device` picks one, and `via` names the node `to` is signed in to when
    /// it is not this one.
    pub async fn open(
        &self,
        to: &str,
        app: &str,
        device: Option<&str>,
        via: Option<&str>,
    ) -> SdkResult<AppStream> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| SdkError::ConnectionError(format!("app transport: {e}")))?
            .await
            .map_err(|e| SdkError::ConnectionError(format!("app transport: {e}")))?;
        let open = Frame::Open {
            to: to.to_string(),
            device: device.map(str::to_string),
            via: via.map(str::to_string),
            app: app.to_string(),
        };
        write_frame(&mut send, &open).await?;
        match read_frame(&mut recv).await? {
            Frame::Opened { device, flow } => Ok(AppStream {
                device,
                flow,
                send,
                recv,
            }),
            Frame::Refused { reason } => Err(SdkError::ConnectionError(reason)),
            _ => Err(SdkError::ConnectionError(
                "the stream was not opened".into(),
            )),
        }
    }

    /// Sends `payload` as a datagram on `flow` (an [`AppStream::flow`]). A
    /// datagram may be lost, and the node drops one its meter has no room
    /// for at once.
    pub fn send_datagram(&self, flow: u32, payload: &[u8]) -> SdkResult<()> {
        let mut datagram = flow.to_le_bytes().to_vec();
        datagram.extend_from_slice(payload);
        self.connection
            .send_datagram(datagram)
            .map_err(|e| SdkError::ConnectionError(format!("app transport datagram: {e}")))
    }

    /// The next datagram from a device at the other end of a flow: the flow
    /// and the payload.
    pub async fn receive_datagram(&self) -> SdkResult<(u32, Vec<u8>)> {
        loop {
            let datagram = self
                .connection
                .receive_datagram()
                .await
                .map_err(|e| SdkError::ConnectionError(format!("app transport: {e}")))?;
            let payload = datagram.payload();
            if let Some((head, rest)) = payload.split_first_chunk::<4>() {
                return Ok((u32::from_le_bytes(*head), rest.to_vec()));
            }
        }
    }

    /// The next stream another device opens to this one.
    pub async fn incoming(&self) -> SdkResult<IncomingStream> {
        loop {
            let (send, mut recv) = self
                .connection
                .accept_bi()
                .await
                .map_err(|e| SdkError::ConnectionError(format!("app transport: {e}")))?;
            if let Ok(Frame::Incoming {
                from,
                device,
                via,
                app,
                flow,
            }) = read_frame(&mut recv).await
            {
                return Ok(IncomingStream {
                    from,
                    device,
                    via,
                    app,
                    flow,
                    send,
                    recv,
                });
            }
        }
    }
}

/// Checks a publication against `node_key` as of now, accepting one signed
/// within the last day.
pub fn pinned_hashes(
    info: &AppTransportInfo,
    issuer: &str,
    node_key: &p256::ecdsa::VerifyingKey,
) -> SdkResult<Vec<[u8; 32]>> {
    match &info.publication {
        Some(publication) => {
            verify_publication(publication, issuer, node_key, now_secs(), 24 * 60 * 60)
        }
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    fn node_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    fn signed(key: &p256::ecdsa::SigningKey, digest: &[u8; 32]) -> String {
        let signature: p256::ecdsa::Signature = key.sign_prehash(digest).unwrap();
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    /// The same vectors the node's tests and the TypeScript client pin.
    #[test]
    fn digests_match_the_shared_vectors() {
        assert_eq!(
            hex::encode(welcome_digest(
                "n1",
                "did:tenzro:human:a",
                "phone",
                1_800_000_000
            )),
            "ee32d5fe974bb82fd5895ad0e237a9d282a0cae8a425a75edc4ba7e8fc19dd94"
        );
        assert_eq!(
            hex::encode(publication_digest(&vector()).unwrap()),
            "f0265744139c6181317242e4ea16ffa9228d02f096b2d85dcdc93c552bbfc400"
        );
    }

    fn vector() -> Publication {
        Publication {
            issuer: "did:tenzro:machine:a".into(),
            listener: LISTENER.into(),
            hashes: vec![
                PinnedHash {
                    sha256: "11".repeat(32),
                    not_before: 1_799_996_400,
                    not_after: 1_801_119_600,
                },
                PinnedHash {
                    sha256: "22".repeat(32),
                    not_before: 1_800_428_400,
                    not_after: 1_801_551_600,
                },
            ],
            signed_at: 1_800_000_005,
            kid: "kid".into(),
            signature: String::new(),
        }
    }

    #[test]
    fn a_publication_gives_the_hashes_valid_now_and_only_from_the_node_it_names() {
        let mut publication = vector();
        publication.signature = signed(&node_key(), &publication_digest(&publication).unwrap());
        let key = node_key();
        let check = |p: &Publication, issuer: &str, now: u64| {
            verify_publication(p, issuer, key.verifying_key(), now, 86_400)
        };
        assert_eq!(
            check(&publication, "did:tenzro:machine:a", 1_800_000_100).unwrap(),
            vec![[0x11; 32]],
            "the next certificate is not valid yet"
        );
        assert!(check(&publication, "did:tenzro:machine:b", 1_800_000_100).is_err());
        assert!(check(&publication, "did:tenzro:machine:a", 1_800_000_005 + 86_401).is_err());
        let mut tampered = publication.clone();
        tampered.hashes[0].not_after += 1;
        assert!(check(&tampered, "did:tenzro:machine:a", 1_800_000_100).is_err());
    }

    #[test]
    fn a_welcome_passes_only_with_the_nodes_signature_over_this_nonce() {
        let key = node_key();
        let welcome = Frame::Welcome {
            did: "did:a".into(),
            device: "phone".into(),
            expires_at: 99,
            signature: signed(&key, &welcome_digest("n1", "did:a", "phone", 99)),
            pq_signature: String::new(),
        };
        let keys = WelcomeKeys {
            node_key: *key.verifying_key(),
            ml_dsa_key: None,
        };
        assert!(verify_welcome(&welcome, "n1", &keys).is_ok());
        assert!(verify_welcome(&welcome, "n2", &keys).is_err());
        let with_pq = WelcomeKeys {
            ml_dsa_key: Some(vec![0u8; ML_DSA_65_VK_LEN]),
            ..keys
        };
        assert!(verify_welcome(&welcome, "n1", &with_pq).is_err());
    }

    #[test]
    fn frames_read_back_as_written_and_large_ones_are_refused() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut a, mut b) = tokio::io::duplex(16 * 1024);
            let frame = Frame::Open {
                to: "did:b".into(),
                device: None,
                via: Some("did:tenzro:machine:y".into()),
                app: "messenger".into(),
            };
            write_frame(&mut a, &frame).await.unwrap();
            assert_eq!(read_frame(&mut b).await.unwrap(), frame);
            let large = Frame::Refused {
                reason: "x".repeat(MAX_FRAME_BYTES),
            };
            assert!(write_frame(&mut a, &large).await.is_err());
        });
    }
}
