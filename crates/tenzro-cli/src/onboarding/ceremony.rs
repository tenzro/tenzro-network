//! The browser passkey ceremony behind `tenzro join` and `tenzro setup` for a
//! human operator.
//!
//! A human identity is rooted in a passkey, and the wallet key lives in that
//! passkey's authenticator. The node refuses to mint one (it answers
//! `Missing public_key`), so the CLI has to get the key material from a page
//! that can run WebAuthn. This module is the CLI half of that exchange:
//!
//! 1. bind a one-shot HTTP listener on `127.0.0.1` (ephemeral port);
//! 2. draw a random registration `challenge` and `state` token;
//! 3. print the wallet onboarding URL and a terminal QR code, and try to open
//!    the URL in a browser;
//! 4. wait for the wallet page to `POST` the result to the listener;
//! 5. check the state token, the registration `clientDataJSON` (type,
//!    challenge, origin) and the shape of every field;
//! 6. hand the verified material to `tenzro_onboardHuman`.
//!
//! No private key is created, held or written here: the P-256 key stays in
//! the authenticator and the ML-DSA-65 key stays in the wallet page. The CLI
//! relays public keys and signatures only.
//!
//! # Contract with the wallet app (`wallet.tenzro.com`)
//!
//! The wallet app is a separate repository. The route and payload below are
//! what this CLI serves and expects; the wallet app must implement them.
//!
//! The CLI opens `GET {wallet}/onboard` with these query parameters:
//!
//! | name        | meaning                                                      |
//! |-------------|--------------------------------------------------------------|
//! | `state`     | opaque token, echoed back unchanged                          |
//! | `challenge` | base64url (no padding) of 32 random bytes; the registration  |
//! |             | `challenge` for `navigator.credentials.create()`             |
//! | `callback`  | `http://127.0.0.1:{port}/callback`                           |
//! | `rpc`       | the node JSON-RPC endpoint the page uses for                 |
//! |             | `tenzro_createCustodyChallenge`                              |
//! | `name`      | display name for the identity                                |
//!
//! The page creates the passkey (RP ID `tenzro.com`), generates its ML-DSA-65
//! key, calls `tenzro_createCustodyChallenge` with operation `enroll_passkey`
//! (`account_address` = the 64-byte P-256 key `x || y`, `target_hex` = the
//! credential id), signs the returned `webauthn_challenge` with the passkey,
//! signs the returned digest with the ML-DSA-65 key, and then sends
//! `POST /callback` with `Content-Type: application/json`:
//!
//! ```json
//! {
//!   "state": "<echoed>",
//!   "credential_id_hex": "...",
//!   "public_key_hex": "<P-256: raw x||y, SEC1 0x04||x||y, or SPKI DER>",
//!   "ml_dsa_public_key_hex": "...",
//!   "client_data_json": "<base64url of the registration clientDataJSON>",
//!   "attestation_object": "<base64url of the attestationObject>",
//!   "authorization": {
//!     "challenge_id": "...",
//!     "credential_id_hex": "...",
//!     "assertion": { "authenticator_data": [..], "client_data_json": [..],
//!                    "signature": [..], "user_handle": null },
//!     "ml_dsa_signature_hex": "..."
//!   }
//! }
//! ```
//!
//! The listener answers CORS preflight for the wallet origin only, with
//! `Access-Control-Allow-Private-Network: true`, so a page served over HTTPS
//! may call the loopback address.

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Default wallet base URL; `TENZRO_WALLET_URL` overrides it (staging).
pub const DEFAULT_WALLET_URL: &str = "https://wallet.tenzro.com";

/// How long the ceremony waits for the wallet page before giving up.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// Largest request body the listener reads.
const MAX_BODY: usize = 256 * 1024;
/// Largest request head (request line plus headers) the listener reads.
const MAX_HEAD: usize = 16 * 1024;
/// How long one connection may take to deliver its request.
const CONN_TIMEOUT: Duration = Duration::from_secs(10);

/// The random values that tie one callback to one ceremony.
#[derive(Debug, Clone)]
pub struct Session {
    /// Opaque token the wallet page must echo back.
    pub state: String,
    /// base64url registration challenge, the `challenge` of the passkey
    /// creation; its `clientDataJSON` must carry it.
    pub challenge: String,
}

impl Session {
    /// A fresh session from the operating system's random source.
    pub fn random() -> Self {
        use rand::RngCore as _;
        let mut state = [0u8; 32];
        let mut challenge = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut state);
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        Self {
            state: URL_SAFE_NO_PAD.encode(state),
            challenge: URL_SAFE_NO_PAD.encode(challenge),
        }
    }
}

/// The wallet base URL in force: `TENZRO_WALLET_URL` or the default.
pub fn wallet_url_from_env() -> String {
    std::env::var("TENZRO_WALLET_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WALLET_URL.to_string())
}

/// The origin (`scheme://host[:port]`) of a wallet base URL, as the passkey
/// ceremony reports it in `clientDataJSON`.
pub fn origin_of(wallet_url: &str) -> Result<String> {
    let (scheme, rest) = wallet_url.split_once("://").ok_or_else(|| {
        anyhow!("wallet URL `{wallet_url}` has no scheme; set TENZRO_WALLET_URL to https://host")
    })?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || !matches!(scheme, "https" | "http") {
        bail!(
            "wallet URL `{wallet_url}` is not an http(s) URL; set TENZRO_WALLET_URL to https://host"
        );
    }
    Ok(format!("{scheme}://{host}"))
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The wallet onboarding URL for one ceremony.
pub fn onboarding_url(
    wallet_url: &str,
    port: u16,
    session: &Session,
    rpc_url: &str,
    display_name: &str,
) -> String {
    format!(
        "{}/onboard?state={}&challenge={}&callback={}&rpc={}&name={}",
        wallet_url.trim_end_matches('/'),
        pct_encode(&session.state),
        pct_encode(&session.challenge),
        pct_encode(&format!("http://127.0.0.1:{port}/callback")),
        pct_encode(rpc_url),
        pct_encode(display_name),
    )
}

/// A terminal QR code for `url`, two rows of modules per text row.
pub fn qr_text(url: &str) -> Result<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(url.as_bytes())
        .map_err(|e| anyhow!("cannot encode the onboarding URL as a QR code: {e}"))?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

/// Whether this machine very likely has no browser to open: a Linux session
/// with no display, or a login over SSH.
pub fn looks_headless() -> bool {
    if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
        return std::env::var_os("SSH_CONNECTION").is_some();
    }
    std::env::var_os("SSH_CONNECTION").is_some()
        || (std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none())
}

/// Try to open `url` in the user's browser. `true` only when an opener
/// process started; it says nothing about whether a page was shown.
pub fn try_open_browser(url: &str) -> bool {
    if looks_headless() {
        return false;
    }
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(target_os = "windows")]
    let opener = "explorer";
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let opener = "xdg-open";
    std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// The verified output of the ceremony: public material only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyResult {
    /// The passkey credential id.
    pub credential_id: Vec<u8>,
    /// The passkey's P-256 public key, raw `x || y`.
    pub p256_xy: [u8; 64],
    /// The ML-DSA-65 verifying key enrolled with the passkey.
    pub ml_dsa_public_key: Vec<u8>,
    /// The custody authorization: challenge id, assertion and ML-DSA-65
    /// signature over the `enroll_passkey` challenge.
    pub authorization: Value,
}

#[derive(Debug, Deserialize)]
struct CallbackPayload {
    state: String,
    credential_id_hex: String,
    public_key_hex: String,
    ml_dsa_public_key_hex: String,
    client_data_json: String,
    attestation_object: String,
    authorization: Value,
}

fn unhex(field: &str, s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|e| format!("`{field}` is not hex ({e})"))
}

/// Raw 64-byte `x || y` from a raw, SEC1 or SPKI P-256 public key.
pub fn normalize_p256(bytes: &[u8]) -> Result<[u8; 64], String> {
    // SubjectPublicKeyInfo header for an uncompressed prime256v1 key.
    const SPKI_PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let raw: &[u8] = match bytes.len() {
        64 => bytes,
        65 if bytes[0] == 0x04 => &bytes[1..],
        91 if bytes.starts_with(&SPKI_PREFIX) && bytes[26] == 0x04 => &bytes[27..],
        n => {
            return Err(format!(
                "`public_key_hex` is {n} bytes; expected a P-256 key as raw x||y (64), SEC1 (65) or SPKI (91)"
            ));
        }
    };
    let mut xy = [0u8; 64];
    xy.copy_from_slice(raw);
    Ok(xy)
}

/// Validate a callback body against `session`. Returns the reason on refusal.
fn validate_payload(
    body: &[u8],
    session: &Session,
    expected_origin: &str,
) -> Result<CeremonyResult, (u16, String)> {
    let bad = |m: String| (400u16, m);
    let payload: CallbackPayload = serde_json::from_slice(body)
        .map_err(|e| bad(format!("the callback body is not the expected JSON: {e}")))?;

    if !constant_time_eq(payload.state.as_bytes(), session.state.as_bytes()) {
        return Err((
            403,
            "the state token does not match this ceremony; start `tenzro join` again".to_string(),
        ));
    }

    let credential_id = unhex("credential_id_hex", &payload.credential_id_hex).map_err(bad)?;
    if credential_id.is_empty() || credential_id.len() > 1023 {
        return Err(bad(
            "`credential_id_hex` must be 1 to 1023 bytes".to_string()
        ));
    }
    let p256_xy = normalize_p256(&unhex("public_key_hex", &payload.public_key_hex).map_err(bad)?)
        .map_err(bad)?;
    let ml_dsa_public_key =
        unhex("ml_dsa_public_key_hex", &payload.ml_dsa_public_key_hex).map_err(bad)?;
    if ml_dsa_public_key.is_empty() {
        return Err(bad("`ml_dsa_public_key_hex` is empty".to_string()));
    }

    // The registration must have been made for this ceremony: its
    // clientDataJSON carries our challenge, the create type, and the wallet
    // origin.
    let cdj = URL_SAFE_NO_PAD
        .decode(payload.client_data_json.trim_end_matches('='))
        .map_err(|e| bad(format!("`client_data_json` is not base64url ({e})")))?;
    let cdj: Value = serde_json::from_slice(&cdj)
        .map_err(|e| bad(format!("`client_data_json` is not JSON ({e})")))?;
    if cdj.get("type").and_then(Value::as_str) != Some("webauthn.create") {
        return Err(bad(
            "`client_data_json` is not a passkey registration (type webauthn.create)".to_string(),
        ));
    }
    if cdj.get("challenge").and_then(Value::as_str) != Some(session.challenge.as_str()) {
        return Err((
            403,
            "the passkey was registered for a different challenge than this ceremony issued"
                .to_string(),
        ));
    }
    if cdj.get("origin").and_then(Value::as_str) != Some(expected_origin) {
        return Err((
            403,
            format!(
                "the passkey was registered on an unexpected origin; expected {expected_origin}"
            ),
        ));
    }
    let att = URL_SAFE_NO_PAD
        .decode(payload.attestation_object.trim_end_matches('='))
        .map_err(|e| bad(format!("`attestation_object` is not base64url ({e})")))?;
    if att.is_empty() {
        return Err(bad("`attestation_object` is empty".to_string()));
    }

    let auth = &payload.authorization;
    let challenge_id = auth
        .get("challenge_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("`authorization.challenge_id` is missing".to_string()))?;
    let auth_cred = unhex(
        "authorization.credential_id_hex",
        auth.get("credential_id_hex")
            .and_then(Value::as_str)
            .unwrap_or(""),
    )
    .map_err(bad)?;
    if auth_cred != credential_id {
        return Err(bad(
            "`authorization.credential_id_hex` is not the credential that was registered"
                .to_string(),
        ));
    }
    let assertion = auth
        .get("assertion")
        .filter(|v| v.is_object())
        .ok_or_else(|| bad("`authorization.assertion` is missing".to_string()))?;
    let ml_sig = auth
        .get("ml_dsa_signature_hex")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("`authorization.ml_dsa_signature_hex` is missing".to_string()))?;

    Ok(CeremonyResult {
        credential_id,
        p256_xy,
        ml_dsa_public_key,
        authorization: json!({
            "challenge_id": challenge_id,
            "credential_id_hex": hex::encode(&auth_cred),
            "assertion": assertion,
            "ml_dsa_signature_hex": ml_sig,
        }),
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The `tenzro_onboardHuman` parameters for a finished ceremony.
pub fn build_onboard_params(result: &CeremonyResult, display_name: &str) -> Value {
    json!({
        "display_name": display_name,
        "credential_id": hex::encode(&result.credential_id),
        "public_key": hex::encode(result.p256_xy),
        "ml_dsa_public_key_hex": hex::encode(&result.ml_dsa_public_key),
        "authorization": result.authorization,
    })
}

/// Why the ceremony did not finish.
#[derive(Debug)]
pub enum CeremonyError {
    /// Nothing valid arrived before the deadline.
    Timeout(Duration),
    /// The listener failed.
    Io(std::io::Error),
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CeremonyError::Timeout(d) => write!(
                f,
                "the passkey was not created within {} seconds, so no identity was made. \
                 The wallet page never reported back to this machine. Run the command again and \
                 finish the passkey prompt in the browser; if the browser is on another machine, \
                 forward the callback port first (ssh -L PORT:127.0.0.1:PORT this-machine).",
                d.as_secs()
            ),
            CeremonyError::Io(e) => write!(
                f,
                "the local callback listener failed: {e}. The passkey result cannot reach the CLI. \
                 Check that loopback networking is available and run the command again."
            ),
        }
    }
}

impl std::error::Error for CeremonyError {}

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, (u16, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err((431, "request head too large".to_string()));
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| (400, format!("read failed: {e}")))?;
        if n == 0 {
            return Err((
                400,
                "connection closed before the request was complete".to_string(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    if len > MAX_BODY {
        return Err((413, "request body too large".to_string()));
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| (400, format!("read failed: {e}")))?;
        if n == 0 {
            return Err((
                400,
                "connection closed before the body was complete".to_string(),
            ));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn response(status: u16, cors_origin: Option<&str>, body: &Value) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let body = if status == 204 {
        String::new()
    } else {
        body.to_string()
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n",
        body.len()
    );
    if let Some(o) = cors_origin {
        head.push_str(&format!(
            "Access-Control-Allow-Origin: {o}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Private-Network: true\r\n"
        ));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

/// What one request amounted to.
enum Outcome {
    Reply(Vec<u8>),
    Done(Vec<u8>, CeremonyResult),
}

fn handle(req: &HttpRequest, port: u16, session: &Session, expected_origin: &str) -> Outcome {
    let err =
        |status: u16, msg: &str| Outcome::Reply(response(status, None, &json!({ "error": msg })));

    // A page on another site must not be able to talk to this listener by
    // rebinding a name to 127.0.0.1.
    let host_ok = matches!(
        req.header("host"),
        Some(h) if h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}")
    );
    if !host_ok {
        return err(403, "unexpected Host header");
    }
    let origin = req.header("origin");
    if let Some(o) = origin
        && o != expected_origin
    {
        return err(403, "request origin is not the Tenzro wallet");
    }
    if req.path != "/callback" {
        return err(404, "not found");
    }
    match req.method.as_str() {
        "OPTIONS" => Outcome::Reply(response(204, origin, &Value::Null)),
        "POST" => match validate_payload(&req.body, session, expected_origin) {
            Ok(result) => Outcome::Done(response(200, origin, &json!({ "ok": true })), result),
            Err((status, msg)) => {
                Outcome::Reply(response(status, origin, &json!({ "error": msg })))
            }
        },
        _ => err(405, "use POST"),
    }
}

/// Bind the one-shot listener on `127.0.0.1` at an ephemeral port.
pub async fn bind() -> Result<(TcpListener, u16), CeremonyError> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(CeremonyError::Io)?;
    let port = listener.local_addr().map_err(CeremonyError::Io)?.port();
    Ok((listener, port))
}

/// Serve `listener` until a callback passes validation or `timeout` elapses.
///
/// Requests that fail validation (wrong state, malformed body, foreign
/// origin) are answered with an error and do not end the wait, so a stray
/// request cannot cancel a ceremony in progress. The first valid callback
/// ends the wait and the listener is dropped.
pub async fn wait_for_callback(
    listener: TcpListener,
    session: &Session,
    expected_origin: &str,
    timeout: Duration,
) -> Result<CeremonyResult, CeremonyError> {
    let port = listener.local_addr().map_err(CeremonyError::Io)?.port();
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let accepted = tokio::time::timeout(remaining, listener.accept())
            .await
            .map_err(|_| CeremonyError::Timeout(timeout))?;
        let (mut stream, _) = accepted.map_err(CeremonyError::Io)?;
        let outcome = tokio::time::timeout(CONN_TIMEOUT, async {
            match read_request(&mut stream).await {
                Ok(req) => handle(&req, port, session, expected_origin),
                Err((status, msg)) => {
                    Outcome::Reply(response(status, None, &json!({ "error": msg })))
                }
            }
        })
        .await;
        match outcome {
            Ok(Outcome::Done(reply, result)) => {
                let _ = stream.write_all(&reply).await;
                let _ = stream.shutdown().await;
                return Ok(result);
            }
            Ok(Outcome::Reply(reply)) => {
                let _ = stream.write_all(&reply).await;
                let _ = stream.shutdown().await;
            }
            Err(_) => {}
        }
    }
}

/// Run the whole ceremony and return the verified key material.
///
/// Prints the URL and QR code, opens the browser when one can open, and
/// waits. It says it is opening a browser only when an opener process
/// started.
pub async fn run(rpc_url: &str, display_name: &str, timeout: Duration) -> Result<CeremonyResult> {
    let wallet_url = wallet_url_from_env();
    let origin = origin_of(&wallet_url)?;
    let session = Session::random();
    let (listener, port) = bind().await?;
    let url = onboarding_url(&wallet_url, port, &session, rpc_url, display_name);

    println!();
    let opened = try_open_browser(&url);
    if opened {
        println!("Opening your browser to create a passkey.");
    } else {
        println!(
            "No browser could be opened on this machine; open the link below on one that has a passkey or a phone."
        );
    }
    println!("  {url}");
    match qr_text(&url) {
        Ok(qr) => {
            println!();
            println!("Or scan this code with your phone:");
            println!("{qr}");
        }
        Err(e) => println!("(no QR code: {e})"),
    }
    if !opened {
        println!(
            "The browser must be able to reach this machine's 127.0.0.1:{port}. From another machine run: ssh -L {port}:127.0.0.1:{port} <this-machine>"
        );
    }
    let waiting = crate::progress::global().wait(
        "Passkey",
        &format!(
            "waiting for you to approve it (up to {} minutes)",
            timeout.as_secs() / 60
        ),
    );
    match wait_for_callback(listener, &session, &origin, timeout).await {
        Ok(result) => {
            waiting.finish_with("passkey received");
            Ok(result)
        }
        Err(e) => {
            waiting.fail(&e.to_string());
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://wallet.tenzro.com";

    fn payload(session: &Session, state: &str) -> Value {
        let cdj = json!({
            "type": "webauthn.create",
            "challenge": session.challenge,
            "origin": ORIGIN,
        });
        json!({
            "state": state,
            "credential_id_hex": "0a0b0c",
            "public_key_hex": hex::encode([7u8; 64]),
            "ml_dsa_public_key_hex": "aabbcc",
            "client_data_json": URL_SAFE_NO_PAD.encode(cdj.to_string()),
            "attestation_object": URL_SAFE_NO_PAD.encode([1u8, 2, 3]),
            "authorization": {
                "challenge_id": "ch-1",
                "credential_id_hex": "0a0b0c",
                "assertion": { "authenticator_data": [1], "client_data_json": [2], "signature": [3], "user_handle": null },
                "ml_dsa_signature_hex": "ddeeff",
            },
        })
    }

    async fn post(port: u16, body: &str, host_port: Option<u16>) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let req = format!(
            "POST /callback HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: {ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            host_port.unwrap_or(port),
            body.len(),
            body
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn state_mismatch_is_refused_and_ceremony_continues() {
        let session = Session::random();
        let (listener, port) = bind().await.unwrap();
        let s2 = session.clone();
        let waiter = tokio::spawn(async move {
            wait_for_callback(listener, &s2, ORIGIN, Duration::from_secs(20)).await
        });
        let wrong = post(port, &payload(&session, "not-the-state").to_string(), None).await;
        assert!(wrong.starts_with("HTTP/1.1 403"), "{wrong}");
        assert!(
            !waiter.is_finished(),
            "a refused callback must not end the wait"
        );
        let good = post(port, &payload(&session, &session.state).to_string(), None).await;
        assert!(good.starts_with("HTTP/1.1 200"), "{good}");
        let result = waiter.await.unwrap().unwrap();
        assert_eq!(result.credential_id, vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(result.p256_xy, [7u8; 64]);
    }

    #[tokio::test]
    async fn malformed_payload_is_refused() {
        let session = Session::random();
        let (listener, port) = bind().await.unwrap();
        let s2 = session.clone();
        let waiter = tokio::spawn(async move {
            wait_for_callback(listener, &s2, ORIGIN, Duration::from_millis(1500)).await
        });
        let not_json = post(port, "{not json", None).await;
        assert!(not_json.starts_with("HTTP/1.1 400"), "{not_json}");
        let mut p = payload(&session, &session.state);
        p["public_key_hex"] = json!("zz");
        let bad_key = post(port, &p.to_string(), None).await;
        assert!(bad_key.starts_with("HTTP/1.1 400"), "{bad_key}");
        let mut p = payload(&session, &session.state);
        p["authorization"]["credential_id_hex"] = json!("ffff");
        let wrong_cred = post(port, &p.to_string(), None).await;
        assert!(wrong_cred.starts_with("HTTP/1.1 400"), "{wrong_cred}");
        assert!(matches!(
            waiter.await.unwrap(),
            Err(CeremonyError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn registration_for_another_challenge_is_refused() {
        let session = Session::random();
        let other = Session::random();
        let (code, msg) = validate_payload(
            payload(&other, &session.state).to_string().as_bytes(),
            &session,
            ORIGIN,
        )
        .unwrap_err();
        assert_eq!(code, 403);
        assert!(msg.contains("different challenge"), "{msg}");
    }

    #[tokio::test]
    async fn foreign_host_header_is_refused() {
        let session = Session::random();
        let (listener, port) = bind().await.unwrap();
        let s2 = session.clone();
        let waiter = tokio::spawn(async move {
            wait_for_callback(listener, &s2, ORIGIN, Duration::from_millis(800)).await
        });
        let r = post(
            port,
            &payload(&session, &session.state).to_string(),
            Some(port + 1),
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        assert!(matches!(
            waiter.await.unwrap(),
            Err(CeremonyError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn timeout_says_what_why_and_fix() {
        let session = Session::random();
        let (listener, _) = bind().await.unwrap();
        let err = wait_for_callback(listener, &session, ORIGIN, Duration::from_millis(100))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, CeremonyError::Timeout(_)));
        assert!(text.contains("no identity was made"), "{text}");
        assert!(text.contains("never reported back"), "{text}");
        assert!(text.contains("Run the command again"), "{text}");
    }

    #[tokio::test]
    async fn preflight_allows_only_the_wallet_origin() {
        let session = Session::random();
        let req = |origin: &str| HttpRequest {
            method: "OPTIONS".into(),
            path: "/callback".into(),
            headers: vec![
                ("Host".into(), "127.0.0.1:9".into()),
                ("Origin".into(), origin.into()),
            ],
            body: vec![],
        };
        let Outcome::Reply(ok) = handle(&req(ORIGIN), 9, &session, ORIGIN) else {
            panic!()
        };
        let ok = String::from_utf8(ok).unwrap();
        assert!(ok.starts_with("HTTP/1.1 204"));
        assert!(ok.contains("Access-Control-Allow-Private-Network: true"));
        let Outcome::Reply(no) = handle(&req("https://evil.example"), 9, &session, ORIGIN) else {
            panic!()
        };
        assert!(String::from_utf8(no).unwrap().starts_with("HTTP/1.1 403"));
    }

    #[test]
    fn onboard_params_carry_public_material_only() {
        let session = Session::random();
        let result = validate_payload(
            payload(&session, &session.state).to_string().as_bytes(),
            &session,
            ORIGIN,
        )
        .unwrap();
        let p = build_onboard_params(&result, "Ada");
        assert_eq!(p["display_name"], "Ada");
        assert_eq!(p["credential_id"], "0a0b0c");
        assert_eq!(p["public_key"], hex::encode([7u8; 64]));
        assert_eq!(p["ml_dsa_public_key_hex"], "aabbcc");
        assert_eq!(p["authorization"]["challenge_id"], "ch-1");
        assert_eq!(p["authorization"]["ml_dsa_signature_hex"], "ddeeff");
    }

    #[test]
    fn url_carries_state_challenge_and_loopback_callback() {
        let session = Session {
            state: "st".into(),
            challenge: "ch".into(),
        };
        let u = onboarding_url(
            "https://wallet.tenzro.com/",
            4321,
            &session,
            "https://rpc.tenzro.com",
            "A B",
        );
        assert!(u.starts_with("https://wallet.tenzro.com/onboard?state=st&challenge=ch&"));
        assert!(u.contains("callback=http%3A%2F%2F127.0.0.1%3A4321%2Fcallback"));
        assert!(u.contains("rpc=https%3A%2F%2Frpc.tenzro.com"));
        assert!(u.ends_with("name=A%20B"));
    }

    #[test]
    fn p256_forms_normalize() {
        let xy = [9u8; 64];
        let mut sec1 = vec![4u8];
        sec1.extend_from_slice(&xy);
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(&sec1);
        assert_eq!(normalize_p256(&xy).unwrap(), xy);
        assert_eq!(normalize_p256(&sec1).unwrap(), xy);
        assert_eq!(normalize_p256(&spki).unwrap(), xy);
        assert!(normalize_p256(&[1, 2, 3]).is_err());
    }

    #[test]
    fn origin_of_strips_path() {
        assert_eq!(origin_of("https://wallet.tenzro.com/x").unwrap(), ORIGIN);
        assert!(origin_of("wallet.tenzro.com").is_err());
    }

    #[test]
    fn qr_renders() {
        assert!(
            qr_text("https://wallet.tenzro.com/onboard?state=a")
                .unwrap()
                .lines()
                .count()
                > 10
        );
    }
}
