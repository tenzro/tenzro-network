//! Who may call the extensions.
//!
//! An extension answers only calls it has authenticated, on every call:
//!
//! - A bearer token the gateway signed: an OpenShell extension token (EdDSA
//!   under the gateway's JWT key, `typ` [`EXTENSION_JWT_TYP`]) naming this
//!   service's audience and the gateway's issuer, unexpired and at most an
//!   hour long. The gateway sends one to each interceptor, and each sandbox's
//!   supervisor sends its own, naming its sandbox, to each middleware.
//! - Over a Unix socket, the process at the other end: it must run as the
//!   gateway's user and, when the binary is named, be that binary. The
//!   gateway sends no token to a credential driver, so this is how the driver
//!   knows its caller.
//!
//! A [`Guard`] holds one or both checks and runs as the service's tonic
//! interceptor. It puts the authenticated [`Caller`] into the request, and
//! every handler refuses a request that carries none, so a service served
//! without its guard answers nothing.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use tonic::Status;

/// The `typ` every OpenShell extension token carries.
pub const EXTENSION_JWT_TYP: &str = "openshell-ext+jwt";
/// The longest an extension token may live.
pub const MAX_TOKEN_SECS: i64 = 3600;
/// Clock skew allowed on a token's issue time.
pub const SKEW_SECS: i64 = 60;
/// The subject prefix of a supervisor's token.
pub const SANDBOX_SUBJECT_PREFIX: &str = "spiffe://openshell/sandbox/";

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The OpenShell component that called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerKind {
    /// The gateway itself.
    Gateway,
    /// A sandbox's supervisor.
    Supervisor,
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    jti: String,
    caller_kind: CallerKind,
    #[serde(default)]
    sandbox_id: Option<String>,
}

/// An authenticated caller, as the guard put it into the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// Gateway or supervisor.
    pub kind: CallerKind,
    /// The sandbox a supervisor acts for.
    pub sandbox_id: Option<String>,
    /// The token's subject, or the peer's user for a socket caller.
    pub subject: String,
}

/// The gateway's token-signing key and issuer.
#[derive(Debug, Clone)]
pub struct GatewayKey {
    key: VerifyingKey,
    kid: Option<String>,
    issuer: String,
}

impl GatewayKey {
    /// The key from its PEM SubjectPublicKeyInfo, the key id the gateway
    /// stamps into tokens (when it stamps one) and the gateway's id.
    pub fn from_pem(pem: &str, kid: Option<String>, gateway_id: &str) -> Result<Self, String> {
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(str::trim)
            .collect();
        let der = STANDARD
            .decode(body)
            .map_err(|_| "the gateway key is not PEM".to_string())?;
        let raw = der
            .strip_prefix(&ED25519_SPKI_PREFIX[..])
            .filter(|k| k.len() == 32)
            .ok_or("the gateway key is not an Ed25519 public key")?;
        let key = VerifyingKey::from_bytes(raw.try_into().expect("32 bytes"))
            .map_err(|e| format!("the gateway key: {e}"))?;
        if gateway_id.is_empty() {
            return Err("the gateway id is empty".to_string());
        }
        Ok(Self {
            key,
            kid: kid.map(|k| k.trim().to_string()).filter(|k| !k.is_empty()),
            issuer: format!("openshell-gateway:{gateway_id}"),
        })
    }

    /// [`GatewayKey::from_pem`] from the files the gateway's
    /// `gateway_jwt` configuration names.
    pub fn from_files(
        public_key: &Path,
        kid: Option<&Path>,
        gateway_id: &str,
    ) -> Result<Self, String> {
        let pem = std::fs::read_to_string(public_key)
            .map_err(|e| format!("{}: {e}", public_key.display()))?;
        let kid = kid
            .map(|p| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display())))
            .transpose()?;
        Self::from_pem(&pem, kid, gateway_id)
    }

    /// The issuer the gateway's tokens name.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// The tokens one service accepts.
#[derive(Debug, Clone)]
pub struct TokenRule {
    key: Arc<GatewayKey>,
    audience: String,
    callers: Vec<CallerKind>,
}

impl TokenRule {
    /// Tokens `key` signed for `audience` from any of `callers`.
    pub fn new(key: Arc<GatewayKey>, audience: impl Into<String>, callers: &[CallerKind]) -> Self {
        Self {
            key,
            audience: audience.into(),
            callers: callers.to_vec(),
        }
    }

    /// The audience this service verifies, which it advertises to the
    /// gateway.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Check `token` at `now_s` (seconds since the Unix epoch).
    pub fn verify(&self, token: &str, now_s: i64) -> Result<Caller, String> {
        let mut parts = token.split('.');
        let (Some(h), Some(c), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("the bearer token is not a JWT".to_string());
        };
        let header: Header = serde_json::from_slice(&B64.decode(h).map_err(|_| "token header")?)
            .map_err(|e| format!("token header: {e}"))?;
        if header.alg != "EdDSA" {
            return Err(format!("token algorithm {} is not EdDSA", header.alg));
        }
        if header.typ.as_deref() != Some(EXTENSION_JWT_TYP) {
            return Err("the token is not an extension token".to_string());
        }
        if let Some(kid) = &self.key.kid
            && header.kid.as_deref() != Some(kid.as_str())
        {
            return Err("the token names another signing key".to_string());
        }
        let sig = B64.decode(s).map_err(|_| "token signature")?;
        let sig = Signature::from_slice(&sig).map_err(|_| "token signature length")?;
        let signed = &token[..h.len() + 1 + c.len()];
        self.key
            .key
            .verify_strict(signed.as_bytes(), &sig)
            .map_err(|_| "the token signature does not verify".to_string())?;
        let claims: Claims = serde_json::from_slice(&B64.decode(c).map_err(|_| "token claims")?)
            .map_err(|e| format!("token claims: {e}"))?;
        if claims.iss != self.key.issuer {
            return Err(format!("token issuer {} is not this gateway", claims.iss));
        }
        if claims.aud != self.audience {
            return Err(format!("token audience {} is not this service", claims.aud));
        }
        if !self.callers.contains(&claims.caller_kind) {
            return Err(format!(
                "a {:?} may not call this service",
                claims.caller_kind
            ));
        }
        if claims.exp <= now_s {
            return Err("the token expired".to_string());
        }
        if claims.iat > now_s + SKEW_SECS {
            return Err("the token is issued in the future".to_string());
        }
        if claims.exp - claims.iat > MAX_TOKEN_SECS || claims.exp <= claims.iat {
            return Err("the token lives longer than an hour".to_string());
        }
        if claims.jti.is_empty() {
            return Err("the token has no id".to_string());
        }
        match (claims.caller_kind, claims.sandbox_id.as_deref()) {
            (CallerKind::Gateway, None) if claims.sub == claims.iss => {}
            (CallerKind::Supervisor, Some(id))
                if !id.is_empty()
                    && claims.sub.strip_prefix(SANDBOX_SUBJECT_PREFIX) == Some(id) => {}
            _ => return Err("the token subject does not match its caller".to_string()),
        }
        Ok(Caller {
            kind: claims.caller_kind,
            sandbox_id: claims.sandbox_id,
            subject: claims.sub,
        })
    }
}

/// The process a Unix-socket caller must be.
#[derive(Debug, Clone)]
pub struct PeerRule {
    uid: u32,
    exe: Option<PathBuf>,
}

impl PeerRule {
    /// A process running as `uid`, and as the binary `exe` when given.
    pub fn new(uid: u32, exe: Option<&Path>) -> Result<Self, String> {
        let exe = exe
            .map(|p| std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display())))
            .transpose()?;
        Ok(Self { uid, exe })
    }

    /// A process running as this process's user, and as `exe` when given.
    pub fn same_user(exe: Option<&Path>) -> Result<Self, String> {
        Self::new(current_uid()?, exe)
    }

    /// Without Unix sockets there is no peer to check, and no caller passes.
    #[cfg(not(unix))]
    fn check(&self, _info: Option<&()>) -> Result<Caller, String> {
        let _ = (self.uid, &self.exe);
        Err("the caller is not on a Unix socket".to_string())
    }

    #[cfg(unix)]
    fn check(
        &self,
        info: Option<&tonic::transport::server::UdsConnectInfo>,
    ) -> Result<Caller, String> {
        let cred = info
            .and_then(|i| i.peer_cred)
            .ok_or("the caller is not on a Unix socket")?;
        if cred.uid() != self.uid {
            return Err(format!(
                "the caller runs as uid {}, not the gateway's",
                cred.uid()
            ));
        }
        if let Some(exe) = &self.exe {
            let pid = cred.pid().ok_or("the caller's process is unknown")?;
            let theirs = std::fs::read_link(format!("/proc/{pid}/exe"))
                .map_err(|e| format!("the caller's binary: {e}"))?;
            if &theirs != exe {
                return Err(format!(
                    "the caller is {}, not the gateway",
                    theirs.display()
                ));
            }
        }
        Ok(Caller {
            kind: CallerKind::Gateway,
            sandbox_id: None,
            subject: format!("uid:{}", cred.uid()),
        })
    }
}

/// This process's effective user: the owner of its `/proc` entry.
#[cfg(unix)]
fn current_uid() -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .map_err(|e| format!("this process's user: {e}"))
}

/// A host without Unix sockets has no peer user to match.
#[cfg(not(unix))]
fn current_uid() -> Result<u32, String> {
    Err("peer credentials need a Unix socket".to_string())
}

/// A service's authentication: a token rule, a peer rule, or both.
#[derive(Debug, Clone)]
pub struct Guard {
    token: Option<TokenRule>,
    peer: Option<PeerRule>,
}

impl Guard {
    /// Accept calls carrying a token `rule` accepts.
    pub fn token(rule: TokenRule) -> Self {
        Self {
            token: Some(rule),
            peer: None,
        }
    }

    /// Accept calls from the process `rule` names.
    pub fn peer(rule: PeerRule) -> Self {
        Self {
            token: None,
            peer: Some(rule),
        }
    }

    /// Also require the caller to be the process `rule` names.
    pub fn and_peer(mut self, rule: PeerRule) -> Self {
        self.peer = Some(rule);
        self
    }

    /// The audience the token rule verifies, if any.
    pub fn audience(&self) -> Option<&str> {
        self.token.as_ref().map(TokenRule::audience)
    }

    /// Authenticate one request's metadata and connection.
    pub fn authenticate(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<Caller, String> {
        let mut caller = None;
        if let Some(peer) = &self.peer {
            caller = Some(peer.check(extensions.get())?);
        }
        if let Some(rule) = &self.token {
            let header = metadata
                .get("authorization")
                .ok_or("no bearer token")?
                .to_str()
                .map_err(|_| "the authorization header is not text")?;
            let token = header
                .strip_prefix("Bearer ")
                .or_else(|| header.strip_prefix("bearer "))
                .ok_or("the authorization is not a bearer token")?;
            caller = Some(rule.verify(token.trim(), chrono::Utc::now().timestamp())?);
        }
        caller.ok_or_else(|| "the guard checks nothing".to_string())
    }
}

impl tonic::service::Interceptor for Guard {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        match self.authenticate(request.metadata(), request.extensions()) {
            Ok(caller) => {
                request.extensions_mut().insert(caller);
                Ok(request)
            }
            Err(why) => {
                tracing::warn!("extension call refused: {why}");
                Err(Status::unauthenticated(why))
            }
        }
    }
}

/// The caller the guard authenticated for `request`; refused when the
/// service runs without its guard.
pub fn caller<T>(request: &tonic::Request<T>) -> Result<&Caller, Status> {
    request
        .extensions()
        .get::<Caller>()
        .ok_or_else(|| Status::unauthenticated("the call was not authenticated"))
}

/// Bind a Unix socket only this user can reach, replacing a stale socket
/// left by an earlier run.
#[cfg(unix)]
pub fn unix_listener(path: &Path) -> std::io::Result<tokio_stream::wrappers::UnixListenerStream> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if !m.file_type().is_socket() {
            return Err(std::io::Error::other(format!(
                "{} exists and is not a socket",
                path.display()
            )));
        }
        std::fs::remove_file(path)?;
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(tokio_stream::wrappers::UnixListenerStream::new(listener))
}

/// Requests as an authenticated caller, for tests of the handlers.
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// `message` as a call from the gateway.
    pub fn from_gateway<T>(message: T) -> tonic::Request<T> {
        let mut r = tonic::Request::new(message);
        r.extensions_mut().insert(Caller {
            kind: CallerKind::Gateway,
            sandbox_id: None,
            subject: "openshell-gateway:test".to_string(),
        });
        r
    }

    /// `message` as a call from the supervisor of `sandbox_id`.
    pub fn from_supervisor<T>(message: T, sandbox_id: &str) -> tonic::Request<T> {
        let mut r = tonic::Request::new(message);
        r.extensions_mut().insert(Caller {
            kind: CallerKind::Supervisor,
            sandbox_id: Some(sandbox_id.to_string()),
            subject: format!("{SANDBOX_SUBJECT_PREFIX}{sandbox_id}"),
        });
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const GATEWAY: &str = "gw-a";
    const AUD: &str = "urn:tenzro:openshell:interceptor";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pem(k: &SigningKey) -> String {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(k.verifying_key().as_bytes());
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(der)
        )
    }

    fn token(k: &SigningKey, header: serde_json::Value, claims: serde_json::Value) -> String {
        let h = B64.encode(serde_json::to_vec(&header).unwrap());
        let c = B64.encode(serde_json::to_vec(&claims).unwrap());
        let sig = k.sign(format!("{h}.{c}").as_bytes());
        format!("{h}.{c}.{}", B64.encode(sig.to_bytes()))
    }

    fn header() -> serde_json::Value {
        serde_json::json!({"alg": "EdDSA", "typ": EXTENSION_JWT_TYP, "kid": "k1"})
    }

    fn gateway_claims(now: i64) -> serde_json::Value {
        serde_json::json!({
            "iss": format!("openshell-gateway:{GATEWAY}"), "aud": AUD,
            "sub": format!("openshell-gateway:{GATEWAY}"), "iat": now, "exp": now + 300,
            "jti": "j", "caller_kind": "gateway"
        })
    }

    fn rule(k: &SigningKey, callers: &[CallerKind]) -> TokenRule {
        let key = GatewayKey::from_pem(&pem(k), Some("k1\n".into()), GATEWAY).unwrap();
        TokenRule::new(Arc::new(key), AUD, callers)
    }

    #[test]
    fn the_gateways_token_is_accepted() {
        let k = key(1);
        let now = 1_000_000;
        let c = rule(&k, &[CallerKind::Gateway])
            .verify(&token(&k, header(), gateway_claims(now)), now)
            .unwrap();
        assert_eq!(c.kind, CallerKind::Gateway);
    }

    #[test]
    fn a_token_another_key_signed_is_refused() {
        let now = 1_000_000;
        let forged = token(&key(2), header(), gateway_claims(now));
        assert!(
            rule(&key(1), &[CallerKind::Gateway])
                .verify(&forged, now)
                .is_err()
        );
    }

    #[test]
    fn expiry_audience_issuer_type_and_caller_are_each_checked() {
        let k = key(1);
        let now = 1_000_000;
        let r = rule(&k, &[CallerKind::Gateway]);
        let with = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut c = gateway_claims(now);
            f(&mut c);
            r.verify(&token(&k, header(), c), now)
        };
        assert!(with(&|c| c["exp"] = (now - 1).into()).is_err());
        assert!(with(&|c| c["exp"] = (now + 7200).into()).is_err());
        assert!(with(&|c| c["iat"] = (now + 600).into()).is_err());
        assert!(with(&|c| c["aud"] = "urn:other".into()).is_err());
        assert!(with(&|c| c["iss"] = "openshell-gateway:gw-b".into()).is_err());
        assert!(with(&|c| c["caller_kind"] = "supervisor".into()).is_err());
        assert!(with(&|c| c["sub"] = "someone".into()).is_err());
        let mut h = header();
        h["typ"] = "JWT".into();
        assert!(r.verify(&token(&k, h, gateway_claims(now)), now).is_err());
        let mut h = header();
        h["kid"] = "k2".into();
        assert!(r.verify(&token(&k, h, gateway_claims(now)), now).is_err());
        let mut h = header();
        h["alg"] = "none".into();
        assert!(r.verify(&token(&k, h, gateway_claims(now)), now).is_err());
    }

    #[test]
    fn a_supervisor_token_names_its_sandbox() {
        let k = key(1);
        let now = 1_000_000;
        let r = rule(&k, &[CallerKind::Supervisor]);
        let claims = |sub: &str| {
            serde_json::json!({
                "iss": format!("openshell-gateway:{GATEWAY}"), "aud": AUD, "sub": sub,
                "iat": now, "exp": now + 300, "jti": "j", "caller_kind": "supervisor",
                "sandbox_id": "sb-1"
            })
        };
        let c = r
            .verify(
                &token(&k, header(), claims("spiffe://openshell/sandbox/sb-1")),
                now,
            )
            .unwrap();
        assert_eq!(c.sandbox_id.as_deref(), Some("sb-1"));
        assert!(
            r.verify(
                &token(&k, header(), claims("spiffe://openshell/sandbox/sb-2")),
                now
            )
            .is_err()
        );
    }

    #[test]
    fn a_request_without_a_token_or_from_another_process_is_refused() {
        let k = key(1);
        let guard = Guard::token(rule(&k, &[CallerKind::Gateway]));
        let ext = tonic::Extensions::new();
        assert!(
            guard
                .authenticate(&tonic::metadata::MetadataMap::new(), &ext)
                .is_err()
        );
        let mut md = tonic::metadata::MetadataMap::new();
        md.insert("authorization", "Basic abc".parse().unwrap());
        assert!(guard.authenticate(&md, &ext).is_err());
        let peer = Guard::peer(PeerRule::new(0, None).unwrap());
        assert!(
            peer.authenticate(&tonic::metadata::MetadataMap::new(), &ext)
                .is_err()
        );
    }

    #[test]
    fn a_handler_refuses_a_request_the_guard_did_not_see() {
        let r = tonic::Request::new(());
        assert_eq!(caller(&r).unwrap_err().code(), tonic::Code::Unauthenticated);
        assert!(caller(&testing::from_gateway(())).is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_unix_socket_caller_must_be_this_user_and_the_named_binary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let incoming = unix_listener(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(incoming);
        let me = std::env::current_exe().unwrap();
        let rule = PeerRule::same_user(Some(&me)).unwrap();
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        let info = tonic::transport::server::UdsConnectInfo {
            peer_addr: None,
            peer_cred: a.peer_cred().ok(),
        };
        assert!(rule.check(Some(&info)).is_ok());
        let other = PeerRule::same_user(Some(Path::new("/bin/sh"))).unwrap();
        assert!(other.check(Some(&info)).is_err());
        let stranger = PeerRule::new(current_uid().unwrap().wrapping_add(1), None).unwrap();
        assert!(stranger.check(Some(&info)).is_err());
    }
}
