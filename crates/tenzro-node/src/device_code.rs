//! Signing in a device that holds no passkey and no hardware key, such as a
//! television, in the shape of the OAuth device authorization grant
//! (RFC 8628).
//!
//! The device asks for a code ([`handle_request`]) naming the key its tokens
//! will be bound to, shows the short user code, and polls ([`handle_poll`]).
//! The operator approves the user code ([`handle_approve`]) with a passkey
//! bound to the operator, on that call. The device is then listed with the
//! paired devices, as kind `tv`, and each poll with its device code gets an
//! access token for the open reads and nothing else ([`VIEWER_PURPOSE`]).
//! Unpairing the device ends that: its tokens are refused and its device code
//! gets no more.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use parking_lot::Mutex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::access::{admin_or_named, bad, first_param, refused, str_param};
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// The purpose of a token a device signed in by device code gets: the open
/// reads.
pub(crate) const VIEWER_PURPOSE: &str = "viewer";
/// How long a device code waits for the operator.
const CODE_TTL: Duration = Duration::from_secs(600);
/// How often a device may poll, at the least.
const INTERVAL: Duration = Duration::from_secs(5);
/// Device codes waiting at one time.
const MAX_WAITING: usize = 16;
/// Device codes waiting at one time for one source.
const MAX_WAITING_PER_SOURCE: usize = 2;
/// Approved devices whose last poll is remembered at one time.
const MAX_POLLERS: usize = 256;
/// The characters of a user code: consonants, none mistaken for another.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
/// Characters in a user code.
const USER_CODE_CHARS: usize = 8;

/// A device code waiting for the operator, or answered and not yet collected.
struct Waiting {
    user_code: String,
    label: String,
    dpop_jkt: String,
    source: Option<String>,
    issued: Instant,
    /// What the operator's passkey signs to approve; fresh after each answer.
    challenge: [u8; 32],
    answer: Answer,
    last_poll: Option<Instant>,
    interval: Duration,
}

#[derive(Clone)]
enum Answer {
    Pending,
    Approved,
    Denied,
}

#[derive(Default)]
struct Inner {
    /// By the digest of the device code; the code itself is not kept.
    waiting: HashMap<[u8; 32], Waiting>,
    /// When each approved device last polled, by the digest of its code.
    polls: HashMap<[u8; 32], Instant>,
}

/// The node's device codes, in memory: one that outlives the process buys
/// nothing, the device asks again.
#[derive(Default)]
pub(crate) struct DeviceCodes(Mutex<Inner>);

impl std::fmt::Debug for DeviceCodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCodes")
            .field("waiting", &self.0.lock().waiting.len())
            .finish()
    }
}

/// An RFC 8628 error: its name is the message and `data.error`.
fn grant_error(name: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32000,
        message: name.to_string(),
        data: Some(json!({ "error": name })),
    }
}

fn digest(device_code: &[u8]) -> [u8; 32] {
    Sha256::digest(device_code).into()
}

/// The identity a device approved for the code with `digest` signs in as.
fn viewer_did(digest: &[u8; 32]) -> String {
    format!("did:tenzro:viewer:{}", hex::encode(&digest[..16]))
}

fn user_code() -> String {
    (0..USER_CODE_CHARS)
        .map(|_| {
            let i = rand::random::<u32>() as usize % USER_CODE_ALPHABET.len();
            char::from(USER_CODE_ALPHABET[i])
        })
        .collect()
}

/// A user code as typed or read aloud: case, spaces and dashes do not count.
fn normalise_user_code(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

impl Inner {
    fn forget_expired(&mut self, now: Instant) {
        self.waiting
            .retain(|_, w| now.duration_since(w.issued) < CODE_TTL);
        self.polls
            .retain(|_, at| now.duration_since(*at) < INTERVAL);
    }
}

/// `tenzro_requestDeviceCode { dpop_jkt, label? }`: a device with no key the
/// node can check asks to be signed in. Returns `{ device_code, user_code,
/// expires_in, interval }`: the device shows the user code, keeps the device
/// code secret and polls `tenzro_pollDeviceCode` with it no more often than
/// every `interval` seconds. Tokens it gets are bound to `dpop_jkt`.
pub(crate) async fn handle_request(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = first_param(params);
    let dpop_jkt = str_param(&p, "dpop_jkt")?.to_string();
    let label = match p.get("label") {
        None | Some(Value::Null) => "Television".to_string(),
        Some(_) => crate::pairing_rpc::label_of(&p)?,
    };
    let source = crate::pairing_rpc::source_of_call();
    let now = Instant::now();
    let mut inner = node.access().device_codes().0.lock();
    inner.forget_expired(now);
    if inner.waiting.len() >= MAX_WAITING {
        return Err(refused(
            "too many devices are waiting to sign in; try again in a few minutes",
        ));
    }
    let from_source = inner
        .waiting
        .values()
        .filter(|w| w.source.is_some() && w.source == source)
        .count();
    if from_source >= MAX_WAITING_PER_SOURCE {
        return Err(refused(
            "this address already has devices waiting to sign in; finish those first",
        ));
    }
    let device_code: [u8; 32] = rand::random();
    let user_code = std::iter::repeat_with(user_code)
        .find(|code| inner.waiting.values().all(|w| &w.user_code != code))
        .unwrap_or_default();
    inner.waiting.insert(
        digest(&device_code),
        Waiting {
            user_code: user_code.clone(),
            label,
            dpop_jkt,
            source,
            issued: now,
            challenge: rand::random(),
            answer: Answer::Pending,
            last_poll: None,
            interval: INTERVAL,
        },
    );
    Ok(json!({
        "device_code": URL_SAFE_NO_PAD.encode(device_code),
        "user_code": format!("{}-{}", &user_code[..4], &user_code[4..]),
        "expires_in": CODE_TTL.as_secs(),
        "interval": INTERVAL.as_secs(),
    }))
}

/// `tenzro_approveDeviceCode { user_code, approve, assertion? }`: the
/// operator answers a device waiting with that user code, from an
/// administrator's session or a paired device. Declining needs nothing more.
/// Approving needs the operator's passkey on this call: without `assertion`
/// the call is refused with `data` carrying the `challenge` (base64url) to
/// sign, the `rp_id` and the device's `label`; with it (`credential_id`,
/// `authenticator_data`, `client_data_json`, `signature`) the device is listed
/// as paired and its next poll signs it in. A challenge answers once.
pub(crate) async fn handle_approve(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    admin_or_named(node, "tenzro_approveDeviceCode", caller)?;
    let p = first_param(params);
    let user_code = normalise_user_code(str_param(&p, "user_code")?);
    let approve = p
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| bad("Missing 'approve': true or false"))?;
    let now = Instant::now();
    let mut inner = node.access().device_codes().0.lock();
    inner.forget_expired(now);
    let (code_digest, waiting) = inner
        .waiting
        .iter_mut()
        .find(|(_, w)| w.user_code == user_code && matches!(w.answer, Answer::Pending))
        .ok_or_else(|| bad("no device is waiting with that code"))?;
    let code_digest = *code_digest;
    if !approve {
        waiting.answer = Answer::Denied;
        return Ok(json!({ "approved": false }));
    }
    let Some(assertion) = p.get("assertion").cloned() else {
        waiting.challenge = rand::random();
        let mut refusal = refused(
            "approving a device needs the operator's passkey on this call: sign the challenge and call again with the assertion",
        );
        refusal.data = Some(json!({
            "challenge": URL_SAFE_NO_PAD.encode(waiting.challenge),
            "rp_id": node.http_surface().webauthn_rp_id(),
            "label": waiting.label,
        }));
        return Err(refusal);
    };
    let challenge = std::mem::replace(&mut waiting.challenge, rand::random());
    let label = waiting.label.clone();
    let dpop_jkt = waiting.dpop_jkt.clone();
    drop(inner);
    let assertion: crate::conditions::Assertion =
        serde_json::from_value(assertion).map_err(|e| bad(format!("assertion: {e}")))?;
    let operator = node
        .operator_did()
        .ok_or_else(|| refused("this node has no operator whose passkey could approve"))?;
    crate::device_rpc::require_operator_assertion(node, &operator, &challenge, &assertion)?;
    let did = viewer_did(&code_digest);
    crate::pairing_rpc::record_viewer(node, &did, &label, &code_digest, &dpop_jkt)?;
    if let Some(waiting) = node
        .access()
        .device_codes()
        .0
        .lock()
        .waiting
        .get_mut(&code_digest)
    {
        waiting.answer = Answer::Approved;
    }
    Ok(json!({
        "approved": true,
        "device": { "id": did, "label": label, "kind": "tv" },
    }))
}

/// `tenzro_pollDeviceCode { device_code }`: a device asks whether it is signed
/// in. Until the operator answers: `authorization_pending`, or `slow_down`
/// when it polls sooner than its interval (which grows by five seconds each
/// time); `access_denied` once declined; `expired_token` once the code ran out
/// or the device was unpaired. Once approved, and for as long as the device
/// stays paired, each poll returns `{ access_token, token_type: "DPoP",
/// expires_in, did, jwk }`: a token bound to the key the device named, for the
/// open reads alone.
pub(crate) async fn handle_poll(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = first_param(params);
    let device_code = URL_SAFE_NO_PAD
        .decode(str_param(&p, "device_code")?.trim_end_matches('='))
        .map_err(|_| bad("'device_code' is not base64url"))?;
    let code_digest = digest(&device_code);
    let now = Instant::now();
    {
        let mut inner = node.access().device_codes().0.lock();
        inner.forget_expired(now);
        match inner.waiting.get_mut(&code_digest) {
            Some(waiting) => {
                if waiting
                    .last_poll
                    .is_some_and(|at| now.duration_since(at) < waiting.interval)
                {
                    waiting.interval += INTERVAL;
                    return Err(grant_error("slow_down"));
                }
                waiting.last_poll = Some(now);
                let answer = waiting.answer.clone();
                match answer {
                    Answer::Pending => return Err(grant_error("authorization_pending")),
                    Answer::Denied => {
                        inner.waiting.remove(&code_digest);
                        return Err(grant_error("access_denied"));
                    }
                    Answer::Approved => {
                        inner.waiting.remove(&code_digest);
                    }
                }
            }
            None => {
                if inner.polls.contains_key(&code_digest) {
                    return Err(grant_error("slow_down"));
                }
                if inner.polls.len() >= MAX_POLLERS {
                    return Err(refused("too many devices are polling; try again shortly"));
                }
            }
        }
        inner.polls.insert(code_digest, now);
    }
    let (did, dpop_jkt) = crate::pairing_rpc::viewer_of(node, &code_digest)
        .ok_or_else(|| grant_error("expired_token"))?;
    let engine = node
        .auth_engine()
        .ok_or_else(|| refused("this node issues no access tokens"))?;
    let ttl = node.access().policy().token_ttl_secs;
    let token = engine
        .issue_purpose_jwt(VIEWER_PURPOSE, &did, &dpop_jkt, Some(ttl))
        .map_err(|e| refused(format!("token issuance failed: {e}")))?;
    Ok(json!({
        "access_token": token,
        "token_type": "DPoP",
        "expires_in": ttl,
        "did": did,
        "jwk": engine.public_jwk(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_code_is_read_back_whatever_its_case_spaces_and_dashes() {
        let code = user_code();
        assert_eq!(code.len(), USER_CODE_CHARS);
        assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
        let shown = format!("{}-{}", &code[..4], &code[4..]);
        assert_eq!(normalise_user_code(&shown.to_ascii_lowercase()), code);
        assert_eq!(
            normalise_user_code(&format!(" {} {} ", &code[..4], &code[4..])),
            code
        );
    }

    #[test]
    fn a_device_signs_in_as_an_identity_named_by_its_code_alone() {
        let a = digest(b"one device code");
        let b = digest(b"another device code");
        assert_eq!(viewer_did(&a), viewer_did(&a));
        assert_ne!(viewer_did(&a), viewer_did(&b));
        assert!(viewer_did(&a).starts_with("did:tenzro:viewer:"));
    }

    #[test]
    fn codes_outlive_neither_their_time_nor_the_poll_interval() {
        let t0 = Instant::now();
        let mut inner = Inner::default();
        inner.waiting.insert(
            [1; 32],
            Waiting {
                user_code: "BCDFGHJK".into(),
                label: "TV".into(),
                dpop_jkt: "jkt".into(),
                source: None,
                issued: t0,
                challenge: [0; 32],
                answer: Answer::Pending,
                last_poll: None,
                interval: INTERVAL,
            },
        );
        inner.polls.insert([2; 32], t0);
        inner.forget_expired(t0 + INTERVAL);
        assert!(inner.waiting.contains_key(&[1; 32]));
        assert!(inner.polls.is_empty());
        inner.forget_expired(t0 + CODE_TTL);
        assert!(inner.waiting.is_empty());
    }
}
