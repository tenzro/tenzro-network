//! Pairing a device with this node.
//!
//! An administrator starts a pairing and is handed a one-time code, also
//! drawn as a QR code. A device signs in as its own identity, with a key it
//! holds, and presents the code. From then on the access policy names that
//! identity for the few admin calls a paired device may make
//! ([`PAIRED_DEVICE_METHODS`]) and for nothing else: the device never acts as
//! the operator. Restarting the node and installing an update also need the
//! operator's passkey on that very call ([`operator_consent`]), and approving
//! a waiting condition needs it in any case. Unpairing takes the identity out
//! of the policy and drops the device's record.
//!
//! Starting a pairing opens the paired-device listener
//! ([`crate::paired_listener`]), and the QR code carries its addresses and
//! the hashes of the certificates it serves under: a device on the
//! operator's own networks dials the node there, with nothing set by hand.
//!
//! A code is four characters that name its pairing, which are no secret, and
//! sixteen that carry eighty random bits. It is held in memory only, as a
//! digest, for five minutes, and works once. A wrong secret counts against
//! the pairing the code names, which is cancelled at the fifth, and every
//! wrong code counts against where it came from, which is refused after five
//! until five minutes have passed: guessing a secret is hopeless, and nobody
//! cancels a pairing whose name they were not shown.
//!
//! A device the node has not seen before may present the code when it signs
//! in ([`sign_in_grant`]). The token it is then issued is good for redeeming
//! the code and for nothing else ([`REDEEM_PURPOSE`]); once paired, the
//! device signs in again and is admitted as the access policy names it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use parking_lot::{Mutex, MutexGuard};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tenzro_storage::{CF_IDENTITIES, KvStore};
use tenzro_types::node_access::{NodeAccessPolicy, ResourceRule, Rule};

use crate::access::{admin_or_named, bad, first_param, method_resource, refused, require_admin};
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// The admin calls a paired device may make. Pairing names the device for
/// each of these in the access policy; every other admin call stays with the
/// node's administrators.
pub(crate) const PAIRED_DEVICE_METHODS: &[&str] = &[
    "tenzro_approveDeviceCode",
    "tenzro_installUpdate",
    "tenzro_listConditions",
    "tenzro_listPairedDevices",
    "tenzro_restartNode",
    "tenzro_submitApproval",
    "tenzro_unpairDevice",
];

/// The paired-device calls that also need the operator's passkey on the call
/// itself: the pairing names the device for them, the passkey decides each.
pub(crate) const CONSENT_METHODS: &[&str] = &["tenzro_installUpdate", "tenzro_restartNode"];

/// How long a challenge for a call the operator approves can be signed.
const CONSENT_TTL: Duration = Duration::from_secs(300);

/// The method a pairing is started, read and redeemed through.
pub(crate) const PAIR_METHOD: &str = "tenzro_pairDevice";
/// The one purpose of an access token issued on the strength of a pairing
/// code: redeeming that code through [`PAIR_METHOD`].
pub(crate) const REDEEM_PURPOSE: &str = "pair-device";
/// The purpose of an access token a paired device gets for a passkey without
/// its ML-DSA-65 leg: the calls in [`PAIRED_DEVICE_METHODS`].
pub(crate) const PAIRED_PURPOSE: &str = "paired-device";
/// Every purpose pairing issues tokens for.
pub(crate) const PURPOSES: &[&str] = &[
    REDEEM_PURPOSE,
    PAIRED_PURPOSE,
    crate::device_code::VIEWER_PURPOSE,
];

/// The purpose of the pairing token a call to `method` also admits, if any.
pub(crate) fn purpose_for(method: &str) -> Option<&'static str> {
    if method == PAIR_METHOD {
        Some(REDEEM_PURPOSE)
    } else if PAIRED_DEVICE_METHODS.contains(&method) {
        Some(PAIRED_PURPOSE)
    } else if crate::rpc_gates::OPEN_METHODS.contains(&method) {
        Some(crate::device_code::VIEWER_PURPOSE)
    } else {
        None
    }
}

/// How a device signed in to redeem its code, as its record names it.
const SIGNED_IN_PASSKEY_ONLY: &str = "passkey (no post-quantum leg)";
const SIGNED_IN_POST_QUANTUM: &str = "hardware key, or passkey with its post-quantum leg";
const SIGNED_IN_DEVICE_CODE: &str = "device code, approved with the operator's passkey";

/// How long a pairing code can be redeemed, and how long a source of wrong
/// codes is remembered.
pub(crate) const CODE_TTL: Duration = Duration::from_secs(300);
/// How long a pairing's outcome can be read after it started.
const OUTCOME_KEPT: Duration = Duration::from_secs(900);
/// Pairings that may wait for a device at one time.
const MAX_WAITING: usize = 8;
/// Bytes of randomness in a pairing code's secret part.
const SECRET_BYTES: usize = 10;
/// Characters of a pairing code's secret part.
const SECRET_CHARS: usize = 16;
/// Characters of the part of a pairing code that names its pairing.
const NAME_CHARS: usize = 4;
/// Characters in a pairing code.
const CODE_CHARS: usize = NAME_CHARS + SECRET_CHARS;
/// Wrong codes after which the pairing they name is cancelled, and after
/// which their source is refused.
const MAX_WRONG_CODES: u8 = 5;
/// Sources of wrong codes remembered at one time.
const MAX_SOURCES: usize = 1024;
/// The code's alphabet: digits and capitals without I, L, O and U, so no two
/// characters are mistaken for each other when read aloud or typed.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Longest label a device may give itself, in characters.
const MAX_LABEL_CHARS: usize = 64;
/// The kinds of device a pairing records.
const KINDS: &[&str] = &["phone", "tablet", "tv", "car", "browser", "desktop"];
/// Storage prefix of paired-device records.
const RECORD_PREFIX: &str = "paired_device:";

/// A device paired with this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PairedDevice {
    /// The identity the device signs in as.
    id: String,
    /// What the device calls itself.
    label: String,
    /// One of [`KINDS`].
    kind: String,
    /// When it was paired, RFC 3339.
    created_at: String,
    /// How it signed in to redeem its code.
    signed_in_with: String,
    /// For a browser, the web page it was paired from, when that page is at
    /// or under the node's relying-party id ([`origin_under`]).
    origin: Option<String>,
    /// For a device signed in by device code, what its tokens come from.
    viewer: Option<Viewer>,
}

/// What a device signed in by device code ([`crate::device_code`]) holds:
/// the digest of its device code, hex, and the key its tokens are bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Viewer {
    code_digest: String,
    dpop_jkt: String,
}

/// Where a pairing stands.
#[derive(Debug, Clone)]
enum Outcome {
    Waiting,
    Done(PairedDevice),
    Failed(String),
}

struct Pairing {
    /// The part of the code that names this pairing.
    name: String,
    /// Digest of the code; the code itself is not kept.
    secret: [u8; 32],
    /// Wrong secrets presented under this pairing's name.
    wrong: u8,
    /// The administrator who started it.
    started_by: String,
    issued: Instant,
    outcome: Outcome,
    /// Identities that presented this pairing's code with a passkey and no
    /// ML-DSA-65 leg.
    passkey_only: Vec<String>,
}

/// The pairings started on this node and not yet forgotten.
#[derive(Default)]
struct OpenPairings {
    by_id: HashMap<String, Pairing>,
    /// Wrong codes by where they came from.
    wrong_from: HashMap<String, WrongCodes>,
    /// The nonce each paired device was given for a call the operator's
    /// passkey approves, by device and method, with when it was given: the
    /// challenge to sign is made from it and the call ([`consent_challenge`]).
    consents: HashMap<(String, String), ([u8; 32], Instant)>,
}

/// The wrong codes one source presented.
struct WrongCodes {
    count: u8,
    /// When the first of them arrived.
    since: Instant,
}

/// Why a presented code opens no pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeRefusal {
    /// It is not the code of a pairing that is waiting.
    Wrong,
    /// Its source presented too many wrong codes; the code was not looked at.
    TooManyFromSource,
}

impl From<CodeRefusal> for JsonRpcError {
    fn from(why: CodeRefusal) -> Self {
        match why {
            CodeRefusal::Wrong => bad(
                "this pairing code is not one this node is waiting for: it is mistyped, already used or expired",
            ),
            CodeRefusal::TooManyFromSource => refused(format!(
                "{MAX_WRONG_CODES} wrong pairing codes came from this address; wait {} minutes",
                CODE_TTL.as_secs() / 60
            )),
        }
    }
}

/// Why a sign-in is let through for an identity the node may know nothing
/// else about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignInGrant {
    /// The access policy names the identity as a paired device.
    PairedDevice,
    /// The identity presented the code of a pairing that is waiting.
    PairingCode,
}

/// What pairing says about a sign-in as `did`, which the caller has proved
/// it holds, presenting `pairing_code` or none; `passkey_only` when it proved
/// it with a passkey and no ML-DSA-65 leg.
///
/// A paired device is granted without its code being looked at. A code is
/// checked without being used up: a wrong one is refused and counted, so
/// this runs once for a sign-in. An administrator is refused a code, since
/// that identity is never paired as a device.
pub(crate) fn sign_in_grant(
    node: &Arc<TenzroNode>,
    did: &str,
    pairing_code: Option<&str>,
    passkey_only: bool,
) -> Result<Option<SignInGrant>, JsonRpcError> {
    if named(&node.access().policy(), did) {
        return Ok(Some(SignInGrant::PairedDevice));
    }
    let Some(code) = pairing_code else {
        return Ok(None);
    };
    if node.access().is_admin(node, did) {
        return Err(administers());
    }
    let mut open = node.access().pairings().lock();
    let (id, _) = open.redeem_secret(code, source_of_call().as_deref(), Instant::now())?;
    if passkey_only && let Some(pairing) = open.by_id.get_mut(&id) {
        pairing.passkey_only.push(did.to_string());
    }
    Ok(Some(SignInGrant::PairingCode))
}

/// The purpose of the token a sign-in is issued, by what pairing says of it
/// ([`sign_in_grant`]): `None` for a token the access policy alone scopes.
/// A passkey without its ML-DSA-65 leg is refused unless pairing grants it.
pub(crate) fn token_purpose(
    grant: Option<SignInGrant>,
    passkey_only: bool,
) -> Result<Option<&'static str>, &'static str> {
    match (grant, passkey_only) {
        (Some(SignInGrant::PairingCode), _) => Ok(Some(REDEEM_PURPOSE)),
        (Some(SignInGrant::PairedDevice), true) => Ok(Some(PAIRED_PURPOSE)),
        (None, true) => Err(
            "a passkey without its ML-DSA-65 leg signs in only a paired device, or one presenting a pairing code",
        ),
        (_, false) => Ok(None),
    }
}

/// `origin`, as a browser sends it, when it is an `https` page at or under
/// `rp_id`, the only pages a passkey of that relying party works on; `None`
/// for every other origin, which pairing never records.
fn origin_under(origin: &str, rp_id: &str) -> Option<String> {
    let authority = origin.strip_prefix("https://")?.to_ascii_lowercase();
    if authority.contains(['/', '@', '?', '#', '[']) {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
        Some(_) => return None,
        None => authority.as_str(),
    };
    let rp_id = rp_id.to_ascii_lowercase();
    (!rp_id.is_empty() && (host == rp_id || host.ends_with(&format!(".{rp_id}"))))
        .then(|| format!("https://{authority}"))
}

/// Why the node answers a browser page whose origin its configuration does
/// not list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    /// A paired browser was paired from it.
    Paired,
    /// It is at or under the relying-party id, and a pairing is waiting.
    Pairing,
}

/// The calls a page that is pairing makes: signing in and redeeming.
const PAIRING_PAGE_CALLS: &[&str] = &[
    "tenzro_accessChallenge",
    "tenzro_issueAccessToken",
    PAIR_METHOD,
];

/// Whether a page answered because of `page` may make a call to `method`:
/// a paired browser's page the paired-device calls and the open reads, a
/// page that is pairing only signing in and redeeming.
fn page_may_call(page: Page, method: &str) -> bool {
    match page {
        Page::Paired => {
            PAIRED_DEVICE_METHODS.contains(&method)
                || crate::rpc_gates::OPEN_METHODS.contains(&method)
        }
        Page::Pairing => PAIRING_PAGE_CALLS.contains(&method),
    }
}

/// What pairing says of a page at `origin`.
fn page_of(node: &Arc<TenzroNode>, origin: &str) -> Option<Page> {
    let paired = storage(node).ok().and_then(|store| {
        store
            .scan_prefix(CF_IDENTITIES, RECORD_PREFIX.as_bytes())
            .ok()
    });
    if paired.into_iter().flatten().any(|(_, record)| {
        serde_json::from_slice::<PairedDevice>(&record)
            .is_ok_and(|d| d.origin.as_deref() == Some(origin))
    }) {
        return Some(Page::Paired);
    }
    let now = Instant::now();
    let waiting = node
        .access()
        .pairings()
        .lock()
        .by_id
        .values()
        .any(|p| p.redeemable(now));
    (waiting
        && origin_under(origin, node.http_surface().webauthn_rp_id()).as_deref() == Some(origin))
    .then_some(Page::Pairing)
}

/// Whether CORS lets a page at `origin`, which the node's configuration does
/// not list, read the node's answers: a page a browser was paired from, or
/// one at or under the relying-party id while a pairing waits.
pub(crate) fn cors_admits(node: &Arc<TenzroNode>, origin: &str) -> bool {
    page_of(node, origin).is_some()
}

/// Refuse a call to `method` from a page the node answers only because of
/// pairing ([`cors_admits`]) when it is not a call such a page makes. A page
/// the configuration lists, and a request from no page, are not limited here.
pub(crate) fn origin_admits(node: &Arc<TenzroNode>, method: &str) -> Result<(), JsonRpcError> {
    let Some(origin) = crate::admin_audit::current_origin().web_origin else {
        return Ok(());
    };
    if node.config().cors_allowed_origins.contains(&origin) {
        return Ok(());
    }
    match page_of(node, &origin) {
        Some(page) if !page_may_call(page, method) => Err(refused(format!(
            "a page at {origin} answered for pairing does not call {method}"
        ))),
        _ => Ok(()),
    }
}

fn administers() -> JsonRpcError {
    bad("this identity administers the node already and is not paired as a device")
}

/// Where the request being handled came from: the client's address, or the
/// overlay peer's endpoint id. `None` for a call made inside this process.
pub(crate) fn source_of_call() -> Option<String> {
    let origin = crate::admin_audit::current_origin();
    origin
        .client_ip
        .map(|ip| ip.to_string())
        .or(origin.overlay_peer)
}

/// The node's pairings. Its lock is held across every change pairing makes to
/// the access policy, so a redeem and an unpair never write over each other.
#[derive(Default)]
pub(crate) struct Pairings(Mutex<OpenPairings>);

impl std::fmt::Debug for Pairings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pairings")
            .field("held", &self.0.lock().by_id.len())
            .finish()
    }
}

impl Pairings {
    fn lock(&self) -> MutexGuard<'_, OpenPairings> {
        self.0.lock()
    }
}

impl OpenPairings {
    /// Start a pairing for administrator `by`: its id and its code.
    fn start(&mut self, by: &str, now: Instant) -> Result<(String, String), String> {
        self.by_id
            .retain(|_, p| now.duration_since(p.issued) < OUTCOME_KEPT);
        let waiting = self.by_id.values().filter(|p| p.redeemable(now)).count();
        if waiting >= MAX_WAITING {
            return Err(format!(
                "{MAX_WAITING} pairings are already waiting for a device; finish one or let it expire"
            ));
        }
        let mut rng = rand::thread_rng();
        let mut random = [0u8; SECRET_BYTES + 8];
        rand::Rng::fill(&mut rng, &mut random[..]);
        let mut secret = [0u8; SECRET_BYTES];
        secret.copy_from_slice(&random[..SECRET_BYTES]);
        let id = hex::encode(&random[SECRET_BYTES..]);
        // A name no held pairing has, so a code names one pairing at most.
        let name = loop {
            let mut picks = [0u8; NAME_CHARS];
            rand::Rng::fill(&mut rng, &mut picks[..]);
            let name: String = picks
                .iter()
                .map(|pick| ALPHABET[usize::from(pick & 31)] as char)
                .collect();
            if self.by_id.values().all(|p| p.name != name) {
                break name;
            }
        };
        let code = format!("{name}{}", encode(&secret));
        self.by_id.insert(
            id.clone(),
            Pairing {
                name,
                secret: digest(&code),
                wrong: 0,
                started_by: by.to_string(),
                issued: now,
                outcome: Outcome::Waiting,
                passkey_only: Vec::new(),
            },
        );
        Ok((id, code))
    }

    /// The pairing a code presented from `source` opens, with the
    /// administrator who started it: the code must be one this node issued,
    /// still in time and not yet used. The caller that pairs settles the
    /// pairing before releasing the lock, which is what makes a code work
    /// once.
    ///
    /// A wrong secret counts against the pairing the code names and cancels
    /// it at the fifth. Every wrong code counts against its source, which is
    /// refused from the fifth, before its code is looked at, until
    /// [`CODE_TTL`] has passed since its first.
    fn redeem_secret(
        &mut self,
        presented: &str,
        source: Option<&str>,
        now: Instant,
    ) -> Result<(String, String), CodeRefusal> {
        self.wrong_from
            .retain(|_, wrong| now.duration_since(wrong.since) < CODE_TTL);
        if source
            .and_then(|source| self.wrong_from.get(source))
            .is_some_and(|wrong| wrong.count >= MAX_WRONG_CODES)
        {
            return Err(CodeRefusal::TooManyFromSource);
        }
        let opened = normalise(presented).and_then(|code| {
            let (id, pairing) = self
                .by_id
                .iter_mut()
                .find(|(_, p)| p.redeemable(now) && code[..NAME_CHARS] == p.name)?;
            if bool::from(pairing.secret.ct_eq(&digest(&code))) {
                return Some((id.clone(), pairing.started_by.clone()));
            }
            pairing.wrong += 1;
            if pairing.wrong >= MAX_WRONG_CODES {
                pairing.outcome = Outcome::Failed(format!(
                    "{MAX_WRONG_CODES} wrong codes were presented for this pairing; start a new one"
                ));
            }
            None
        });
        if let Some(opened) = opened {
            return Ok(opened);
        }
        if let Some(source) = source {
            let room = self.wrong_from.len() < MAX_SOURCES;
            match self.wrong_from.get_mut(source) {
                Some(wrong) => wrong.count += 1,
                None if room => {
                    self.wrong_from.insert(
                        source.to_string(),
                        WrongCodes {
                            count: 1,
                            since: now,
                        },
                    );
                }
                // The table is full: the count against the pairing still holds.
                None => {}
            }
        }
        Err(CodeRefusal::Wrong)
    }

    fn settle(&mut self, id: &str, outcome: Outcome) {
        if let Some(p) = self.by_id.get_mut(id) {
            p.outcome = outcome;
        }
    }

    /// The ceremony's state as the apps read it.
    fn status(&self, id: &str, now: Instant) -> Option<Value> {
        let p = self.by_id.get(id)?;
        Some(match &p.outcome {
            Outcome::Waiting if p.redeemable(now) => {
                json!({ "id": id, "state": "waiting", "reason": "" })
            }
            Outcome::Waiting => json!({
                "id": id,
                "state": "expired",
                "reason": "the pairing code was not used in time",
            }),
            Outcome::Done(device) => {
                json!({ "id": id, "state": "done", "reason": "", "device": device })
            }
            Outcome::Failed(why) => json!({ "id": id, "state": "failed", "reason": why }),
        })
    }
}

impl Pairing {
    fn redeemable(&self, now: Instant) -> bool {
        matches!(self.outcome, Outcome::Waiting) && now.duration_since(self.issued) < CODE_TTL
    }
}

/// Eighty random bits as sixteen characters of [`ALPHABET`].
fn encode(bytes: &[u8; SECRET_BYTES]) -> String {
    let bits = bytes.iter().fold(0u128, |n, b| (n << 8) | u128::from(*b));
    (0..SECRET_CHARS)
        .rev()
        .map(|i| ALPHABET[((bits >> (i * 5)) & 31) as usize] as char)
        .collect()
}

/// The code as a person reads it: groups of four.
fn grouped(code: &str) -> String {
    code.as_bytes()
        .chunks(4)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// What a person typed or a scanner read, as the code it stands for. Case,
/// dashes and spaces do not matter, and a letter the alphabet leaves out reads
/// as the digit it resembles. `None` when it cannot be a code.
fn normalise(presented: &str) -> Option<String> {
    let mut code = String::with_capacity(CODE_CHARS);
    for c in presented.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        code.push(c);
    }
    (code.len() == CODE_CHARS).then_some(code)
}

fn digest(code: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"tenzro/pairing-code/v1")
        .chain_update(code.as_bytes())
        .finalize()
        .into()
}

/// Where a device on the operator's own networks reaches the node: the
/// addresses of the paired-device listener, the hashes of the certificates it
/// serves under, and why there are none when it did not open.
#[derive(Debug, Default, Serialize)]
struct Lan {
    addresses: Vec<String>,
    pins: Vec<String>,
    unavailable: String,
}

impl Lan {
    /// The listener as it opened for a pairing.
    #[cfg(feature = "paired-devices")]
    async fn open(node: &Arc<TenzroNode>) -> Self {
        match node.access().paired_listener().open().await {
            Ok(Some(serving)) => Self {
                addresses: serving.addresses().iter().map(|a| a.to_string()).collect(),
                pins: serving.pins().into_iter().map(|pin| pin.sha256).collect(),
                unavailable: String::new(),
            },
            Ok(None) => Self {
                unavailable: "this process runs no paired-device listener".to_string(),
                ..Self::default()
            },
            Err(why) => {
                tracing::warn!(%why, "the paired-device listener did not open for a pairing");
                Self {
                    unavailable: why,
                    ..Self::default()
                }
            }
        }
    }

    /// A build without the listener: devices pair through the RPC address alone.
    #[cfg(not(feature = "paired-devices"))]
    async fn open(_node: &Arc<TenzroNode>) -> Self {
        Self {
            unavailable: "this build has no paired-device listener".to_string(),
            ..Self::default()
        }
    }
}

/// Whether any device is paired with this node.
#[cfg(feature = "paired-devices")]
pub(crate) fn any_paired(node: &Arc<TenzroNode>) -> bool {
    storage(node)
        .ok()
        .and_then(|store| {
            store
                .scan_prefix(CF_IDENTITIES, RECORD_PREFIX.as_bytes())
                .ok()
        })
        .is_some_and(|records| !records.is_empty())
}

/// The link a pairing QR code opens: the Control apps claim it, and a
/// browser opens the Control web app there.
const PAIR_LINK: &str = "https://control.tenzro.com/pair";

/// What the QR code says: [`PAIR_LINK`] with, in the fragment, which a
/// browser sends to no server, the node's published RPC address when it has
/// one, the node's identity when it has one, each address of the
/// paired-device listener with the certificate hashes a device pins there,
/// and the code.
fn pairing_url(
    code: &str,
    published_rpc: Option<&str>,
    node_did: Option<&str>,
    lan: &Lan,
) -> String {
    let mut url = format!("{PAIR_LINK}#");
    if let Some(rpc) = published_rpc {
        url.push_str(&format!("node={}&", urlencoding::encode(rpc)));
    }
    if let Some(did) = node_did {
        url.push_str(&format!("did={}&", urlencoding::encode(did)));
    }
    for address in &lan.addresses {
        url.push_str(&format!("lan={}&", urlencoding::encode(address)));
    }
    for pin in &lan.pins {
        url.push_str(&format!("pin={pin}&"));
    }
    url.push_str(&format!("secret={code}"));
    url
}

/// `text` as a QR code: one string per row, `1` for a dark module and `0` for
/// a light one, without a quiet zone.
fn qr_rows(text: &str) -> Result<Vec<String>, String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .to_colors()
        .chunks(code.width())
        .map(|row| {
            row.iter()
                .map(|module| match module {
                    qrcode::Color::Dark => '1',
                    qrcode::Color::Light => '0',
                })
                .collect()
        })
        .collect())
}

/// Name `did` in the policy for every call a paired device may make.
fn grant(policy: &mut NodeAccessPolicy, did: &str) -> Result<(), String> {
    for method in PAIRED_DEVICE_METHODS {
        let resource = method_resource(method);
        match policy.resources.iter_mut().find(|r| r.resource == resource) {
            Some(ResourceRule {
                rule: Rule::Allow { dids, .. },
                ..
            }) => {
                if !dids.iter().any(|d| d == did) {
                    dids.push(did.to_string());
                }
            }
            Some(_) => {
                return Err(format!(
                    "the access policy's rule for {resource} is not a list of identities, and pairing adds to such a list only"
                ));
            }
            None => policy.resources.push(ResourceRule {
                resource,
                rule: Rule::Allow {
                    dids: vec![did.to_string()],
                    orgs: Vec::new(),
                },
            }),
        }
    }
    Ok(())
}

/// Take `did` out of every paired-device call's list, and drop a list that
/// names nobody afterwards.
fn withdraw(policy: &mut NodeAccessPolicy, did: &str) {
    policy.resources.retain_mut(|r| {
        let paired = PAIRED_DEVICE_METHODS
            .iter()
            .any(|method| method_resource(method) == r.resource);
        match &mut r.rule {
            Rule::Allow { dids, orgs } if paired => {
                dids.retain(|d| d != did);
                !(dids.is_empty() && orgs.is_empty())
            }
            _ => true,
        }
    });
}

/// Whether the policy names `did` for any paired-device call.
fn named(policy: &NodeAccessPolicy, did: &str) -> bool {
    PAIRED_DEVICE_METHODS.iter().any(|method| {
        matches!(
            policy.resource_rule(&method_resource(method)),
            Some(Rule::Allow { dids, .. }) if dids.iter().any(|d| d == did)
        )
    })
}

/// Apply `change` to the policy in force and store the result as `by`'s
/// change.
fn change_policy(
    node: &Arc<TenzroNode>,
    by: &str,
    change: impl FnOnce(&mut NodeAccessPolicy) -> Result<(), String>,
) -> Result<(), String> {
    let mut policy = (*node.access().policy()).clone();
    change(&mut policy)?;
    node.access().store().set(policy, by).map(|_| ())
}

fn storage(node: &Arc<TenzroNode>) -> Result<Arc<dyn KvStore>, JsonRpcError> {
    node.storage()
        .map(|s| s.clone() as Arc<dyn KvStore>)
        .ok_or_else(|| JsonRpcError {
            code: -32000,
            message: "Storage not initialized".to_string(),
            data: None,
        })
}

fn internal(what: &str, e: impl std::fmt::Display) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: format!("{what}: {e}"),
        data: None,
    }
}

fn record_key(did: &str) -> Vec<u8> {
    format!("{RECORD_PREFIX}{did}").into_bytes()
}

/// Record `device` and name it in the policy. The record is written first: a
/// record without its rule is a listed device with no access, while a rule
/// without its record would be access nobody can see or remove.
fn pair(
    node: &Arc<TenzroNode>,
    store: &dyn KvStore,
    by: &str,
    device: &PairedDevice,
) -> Result<(), String> {
    let key = record_key(&device.id);
    let record = serde_json::to_vec(device).map_err(|e| e.to_string())?;
    store
        .put(CF_IDENTITIES, &key, &record)
        .map_err(|e| format!("could not record the device: {e}"))?;
    change_policy(node, by, |policy| grant(policy, &device.id)).inspect_err(|_| {
        if let Err(e) = store.delete(CF_IDENTITIES, &key) {
            tracing::warn!("a device that was not paired stays listed: {e}");
        }
    })
}

/// List a device the operator approved by device code: kind `tv`, named
/// `did`, with no rule in the access policy, since its tokens open only the
/// open reads ([`purpose_for`]). Unpairing it removes the record and with it
/// every token the device could still get.
pub(crate) fn record_viewer(
    node: &Arc<TenzroNode>,
    did: &str,
    label: &str,
    code_digest: &[u8; 32],
    dpop_jkt: &str,
) -> Result<(), JsonRpcError> {
    let store = storage(node)?;
    let device = PairedDevice {
        id: did.to_string(),
        label: label.to_string(),
        kind: "tv".to_string(),
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        signed_in_with: SIGNED_IN_DEVICE_CODE.to_string(),
        origin: None,
        viewer: Some(Viewer {
            code_digest: hex::encode(code_digest),
            dpop_jkt: dpop_jkt.to_string(),
        }),
    };
    let record =
        serde_json::to_vec(&device).map_err(|e| internal("could not record the device", e))?;
    let _open = node.access().pairings().lock();
    store
        .put(CF_IDENTITIES, &record_key(did), &record)
        .map_err(|e| internal("could not record the device", e))
}

/// The identity, and the key its tokens are bound to, of the listed device
/// approved for the device code with `code_digest`.
pub(crate) fn viewer_of(
    node: &Arc<TenzroNode>,
    code_digest: &[u8; 32],
) -> Option<(String, String)> {
    let wanted = hex::encode(code_digest);
    storage(node)
        .ok()?
        .scan_prefix(CF_IDENTITIES, RECORD_PREFIX.as_bytes())
        .ok()?
        .into_iter()
        .filter_map(|(_, record)| serde_json::from_slice::<PairedDevice>(&record).ok())
        .find_map(|d| {
            d.viewer
                .filter(|v| v.code_digest == wanted)
                .map(|v| (d.id, v.dpop_jkt))
        })
}

/// Whether `did` is a device signed in by device code that is still listed.
pub(crate) fn is_viewer(node: &Arc<TenzroNode>, did: &str) -> bool {
    storage(node)
        .ok()
        .and_then(|store| store.get(CF_IDENTITIES, &record_key(did)).ok().flatten())
        .and_then(|record| serde_json::from_slice::<PairedDevice>(&record).ok())
        .is_some_and(|d| d.viewer.is_some())
}

/// The label a device gave itself, trimmed.
pub(crate) fn label_of(p: &Value) -> Result<String, JsonRpcError> {
    let label = p.get("label").and_then(Value::as_str).unwrap_or("").trim();
    if label.is_empty() {
        return Err(bad("Missing 'label': what this device is called"));
    }
    if label.chars().count() > MAX_LABEL_CHARS || label.chars().any(char::is_control) {
        return Err(bad(format!(
            "'label' is at most {MAX_LABEL_CHARS} characters of plain text"
        )));
    }
    Ok(label.to_string())
}

fn kind_of(p: &Value) -> Result<String, JsonRpcError> {
    match p.get("kind").and_then(Value::as_str) {
        Some(kind) if KINDS.contains(&kind) => Ok(kind.to_string()),
        _ => Err(bad(format!("'kind' is one of: {}", KINDS.join(", ")))),
    }
}

/// `tenzro_pairDevice`, three forms.
///
/// `{}` from an administrator starts a pairing and returns the ceremony:
/// `{id, state: "waiting", url, qr, qr_rows, code, lan, reason,
/// expires_in_secs}`. `lan` is where a device on the operator's own networks
/// reaches the node, which the URL repeats: `{addresses, pins, unavailable}`.
///
/// `{id}` from an administrator returns where that pairing stands:
/// `{id, state, reason}`, with `device` once it is done.
///
/// `{secret, label, kind}` from a signed-in device redeems the code and pairs
/// the caller's own identity: `{device, methods, node_key}`, the key being
/// the one this node signs under. A device this node does
/// not know signs in for this by presenting the same code as `pairing_code`
/// to `tenzro_issueAccessToken`.
pub(crate) async fn handle_pair_device(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let p = first_param(params);
    let now = Instant::now();
    if let Some(secret) = p.get("secret") {
        let secret = secret
            .as_str()
            .ok_or_else(|| bad("'secret' is the pairing code, as text"))?;
        let did = caller.ok_or_else(|| {
            refused("sign in with this device's own key, then present the pairing code")
        })?;
        if node.access().is_admin(node, did) {
            return Err(administers());
        }
        let label = label_of(&p)?;
        let kind = kind_of(&p)?;
        let origin = (kind == "browser")
            .then(|| crate::admin_audit::current_origin().web_origin)
            .flatten()
            .and_then(|o| origin_under(&o, node.http_surface().webauthn_rp_id()));
        let store = storage(node)?;
        let mut open = node.access().pairings().lock();
        let (id, started_by) = open.redeem_secret(secret, source_of_call().as_deref(), now)?;
        let passkey_only = open
            .by_id
            .get(&id)
            .is_some_and(|p| p.passkey_only.iter().any(|d| d == did));
        let device = PairedDevice {
            id: did.to_string(),
            label,
            kind,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            signed_in_with: if passkey_only {
                SIGNED_IN_PASSKEY_ONLY
            } else {
                SIGNED_IN_POST_QUANTUM
            }
            .to_string(),
            origin,
            viewer: None,
        };
        return match pair(node, store.as_ref(), &started_by, &device) {
            Ok(()) => {
                open.settle(&id, Outcome::Done(device.clone()));
                Ok(json!({
                    "device": device,
                    "methods": PAIRED_DEVICE_METHODS,
                    "node_key": node.auth_engine().map(|engine| engine.public_jwk()),
                }))
            }
            Err(why) => {
                open.settle(&id, Outcome::Failed(why.clone()));
                Err(internal("the device was not paired", why))
            }
        };
    }

    let admin = require_admin(node, caller)?;
    if let Some(id) = p.get("id") {
        let id = id
            .as_str()
            .ok_or_else(|| bad("'id' is a pairing's id, as text"))?;
        let status = node.access().pairings().lock().status(id, now);
        return status.ok_or_else(|| bad(format!("no pairing {id} is held by this node")));
    }
    let started = node.access().pairings().lock().start(&admin, now);
    let (id, code) = started.map_err(|why| JsonRpcError {
        code: -32000,
        message: why,
        data: None,
    })?;
    let node_did = crate::identity_bootstrap::machine_did();
    // No pairing lock is held while the listener opens.
    let lan = Lan::open(node).await;
    let url = pairing_url(
        &code,
        node.config().external_rpc_addr.as_deref(),
        node_did.as_deref(),
        &lan,
    );
    let rows = qr_rows(&url).map_err(|e| internal("could not draw the pairing code", e))?;
    Ok(json!({
        "id": id,
        "state": "waiting",
        "url": url,
        "qr": url,
        "qr_rows": rows,
        "node_did": node_did,
        "code": grouped(&code),
        "lan": lan,
        "reason": "",
        "expires_in_secs": CODE_TTL.as_secs(),
    }))
}

/// `tenzro_listPairedDevices`: `{devices: [{id, label, kind, created_at,
/// this_device}]}`, for an administrator or a paired device.
pub(crate) async fn handle_list_paired_devices(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let (did, _) = admin_or_named(node, "tenzro_listPairedDevices", caller)?;
    let mut devices: Vec<PairedDevice> = storage(node)?
        .scan_prefix(CF_IDENTITIES, RECORD_PREFIX.as_bytes())
        .map_err(|e| internal("could not read the paired devices", e))?
        .into_iter()
        .filter_map(|(_, record)| serde_json::from_slice(&record).ok())
        .collect();
    devices.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    let devices: Vec<Value> = devices
        .into_iter()
        .map(|d| {
            json!({
                "id": d.id,
                "label": d.label,
                "kind": d.kind,
                "created_at": d.created_at,
                "signed_in_with": d.signed_in_with,
                "origin": d.origin,
                "this_device": d.id == did,
            })
        })
        .collect();
    Ok(json!({ "devices": devices }))
}

/// `tenzro_unpairDevice {id}`: end a device's access and drop its record. An
/// administrator removes any device; a paired device removes only itself.
pub(crate) async fn handle_unpair_device(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let (did, admin) = admin_or_named(node, "tenzro_unpairDevice", caller)?;
    let p = first_param(params);
    let id = crate::access::str_param(&p, "id")?;
    if !admin && id != did {
        return Err(refused("a paired device can remove only itself"));
    }
    let store = storage(node)?;
    let key = record_key(id);
    let mut open = node.access().pairings().lock();
    let recorded = store
        .contains(CF_IDENTITIES, &key)
        .map_err(|e| internal("could not read the paired device", e))?;
    if !recorded && !named(&node.access().policy(), id) {
        return Err(bad(format!("no paired device {id}")));
    }
    // Access ends first; a record left behind by a failed delete is a listed
    // device with no access, and unpairing it again removes it.
    change_policy(node, &did, |policy| {
        withdraw(policy, id);
        Ok(())
    })
    .map_err(|e| internal("could not change the access policy", e))?;
    store
        .delete(CF_IDENTITIES, &key)
        .map_err(|e| internal("could not drop the device's record", e))?;
    open.consents.retain(|(device, _), _| device != id);
    Ok(json!({ "unpaired": id }))
}

/// `value` as JSON with every object's keys in order: the same bytes for the
/// same call whichever order its client wrote the keys in.
fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::from(k.as_str()), canonical(&map[k])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", items.join(","))
        }
        other => other.to_string(),
    }
}

/// What the operator's passkey signs to approve one call: this node's
/// one-time `nonce` for the device and method, and the call itself, its
/// method and its parameters without the assertion that answers it, so an
/// assertion authorises that call and no other.
fn consent_challenge(nonce: &[u8; 32], method: &str, params: Option<&Value>) -> [u8; 32] {
    let mut call = first_param(params.cloned());
    if let Some(fields) = call.as_object_mut() {
        fields.remove("assertion");
    }
    let mut h = Sha256::new();
    h.update(b"tenzro/paired-call-consent/v1");
    h.update(nonce);
    h.update((method.len() as u32).to_be_bytes());
    h.update(method.as_bytes());
    h.update(canonical(&call).as_bytes());
    h.finalize().into()
}

/// Admit a call to `method`, one of [`CONSENT_METHODS`], by `caller`. An
/// administrator makes it as it is. Anyone else, which the gate admits only
/// as a paired device, makes it only with the operator's passkey assertion
/// (`assertion`, as `tenzro_submitApproval` takes it) over the challenge the
/// node gave that device for this method, which covers the call's parameters
/// too: the same call, repeated with the assertion, is the one approved. A
/// call without one is refused with a fresh challenge in its `data`
/// (`challenge`, base64url, and `rp_id`), good once and for five minutes.
pub(crate) fn operator_consent(
    node: &Arc<TenzroNode>,
    method: &str,
    caller: Option<&str>,
    params: Option<&Value>,
) -> Result<(), JsonRpcError> {
    debug_assert!(
        CONSENT_METHODS.contains(&method),
        "{method} is not a call the operator decides"
    );
    let Some(did) = caller else {
        return Ok(());
    };
    if node.access().is_admin(node, did) {
        return Ok(());
    }
    let assertion = params.and_then(|p| first_param(Some(p.clone())).get("assertion").cloned());
    let now = Instant::now();
    let key = (did.to_string(), method.to_string());
    let mut open = node.access().pairings().lock();
    open.consents
        .retain(|_, (_, given)| now.duration_since(*given) < CONSENT_TTL);
    let Some(assertion) = assertion else {
        let nonce: [u8; 32] = rand::random();
        let challenge = consent_challenge(&nonce, method, params);
        open.consents.insert(key, (nonce, now));
        let mut refusal = refused(format!(
            "{method} from a paired device needs the operator's passkey on this call: sign the challenge and call again with the assertion"
        ));
        refusal.data = Some(json!({
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "rp_id": node.http_surface().webauthn_rp_id(),
        }));
        return Err(refusal);
    };
    let (nonce, _) = open.consents.remove(&key).ok_or_else(|| {
        refused(format!(
            "no challenge is waiting for {method} from this device: call it without an assertion for one"
        ))
    })?;
    drop(open);
    let challenge = consent_challenge(&nonce, method, params);
    let assertion: crate::conditions::Assertion =
        serde_json::from_value(assertion).map_err(|e| bad(format!("assertion: {e}")))?;
    let operator = node
        .operator_did()
        .ok_or_else(|| refused("this node has no operator whose passkey could approve"))?;
    crate::device_rpc::require_operator_assertion(node, &operator, &challenge, &assertion)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "did:tenzro:machine:device-one";
    const OTHER: &str = "did:tenzro:machine:device-two";

    const OPERATOR: &str = "did:tenzro:human:op";

    /// `code` with its secret part changed and its name kept.
    fn wrong_secret(code: &str) -> String {
        let last = if code.ends_with('0') { '1' } else { '0' };
        format!("{}{last}", &code[..CODE_CHARS - 1])
    }

    /// A well-formed code that names none of the pairings `open` holds.
    fn names_no_pairing(open: &OpenPairings) -> String {
        let name = ["0000", "1111", "2222", "3333"]
            .into_iter()
            .find(|name| open.by_id.values().all(|p| p.name != *name))
            .expect("fewer than four pairings are held");
        format!("{name}{}", encode(&[0u8; SECRET_BYTES]))
    }

    #[test]
    fn a_code_names_its_pairing_and_carries_eighty_bits() {
        assert_eq!(encode(&[0u8; SECRET_BYTES]), "0000000000000000");
        assert_eq!(encode(&[0xff; SECRET_BYTES]), "ZZZZZZZZZZZZZZZZ");
        // 0x0843 is 2, 2 and 3 as five-bit groups.
        let mut bytes = [0u8; SECRET_BYTES];
        bytes[8] = 0x08;
        bytes[9] = 0x43;
        assert_eq!(encode(&bytes), "0000000000000223");
        assert_eq!(SECRET_CHARS * 5, SECRET_BYTES * 8);
        assert_eq!(grouped("0123456789ABCDEFGHJK"), "0123-4567-89AB-CDEF-GHJK");

        let mut open = OpenPairings::default();
        let (id, code) = open.start(OPERATOR, Instant::now()).unwrap();
        assert_eq!(code.len(), CODE_CHARS);
        assert!(code.bytes().all(|c| ALPHABET.contains(&c)), "{code}");
        assert_eq!(code[..NAME_CHARS], open.by_id[&id].name);
        assert_eq!(normalise(&code).as_deref(), Some(code.as_str()));
    }

    #[test]
    fn a_typed_code_reads_as_the_code_it_stands_for() {
        let code = "0123456789ABCDEFGHJK";
        assert_eq!(normalise(code).as_deref(), Some(code));
        assert_eq!(normalise("0123-4567-89ab-cdef-ghjk").as_deref(), Some(code));
        assert_eq!(normalise(" o12345 6789abcdef ghjk ").as_deref(), Some(code));
        assert_eq!(normalise("0I23456789ABCDEFGHJK").as_deref(), Some(code));
        assert_eq!(normalise("0l23456789ABCDEFGHJK").as_deref(), Some(code));
        assert_eq!(normalise("0123456789ABCDEFGHJ"), None, "too short");
        assert_eq!(normalise("0123456789ABCDEFGHJK0"), None, "too long");
        assert_eq!(
            normalise("U123456789ABCDEFGHJK"),
            None,
            "U is not in the alphabet"
        );
        assert_eq!(normalise("é123456789ABCDEFGHJK"), None);
        assert_eq!(normalise(""), None);
    }

    #[test]
    fn five_wrong_codes_cancel_the_pairing_they_name_and_no_other() {
        let mut open = OpenPairings::default();
        let t0 = Instant::now();
        let (a, a_code) = open.start(OPERATOR, t0).unwrap();
        let (b, b_code) = open.start(OPERATOR, t0).unwrap();

        for _ in 1..MAX_WRONG_CODES {
            assert_eq!(
                open.redeem_secret(&wrong_secret(&a_code), None, t0),
                Err(CodeRefusal::Wrong)
            );
        }
        // One short of the bound, the pairing still waits and its code opens it.
        assert_eq!(open.status(&a, t0).unwrap()["state"], "waiting");
        assert_eq!(
            open.redeem_secret(&a_code, None, t0),
            Ok((a.clone(), OPERATOR.to_string()))
        );
        assert_eq!(
            open.redeem_secret(&wrong_secret(&a_code), None, t0),
            Err(CodeRefusal::Wrong)
        );
        let status = open.status(&a, t0).unwrap();
        assert_eq!(status["state"], "failed");
        assert_eq!(
            status["reason"],
            "5 wrong codes were presented for this pairing; start a new one"
        );
        assert_eq!(
            open.redeem_secret(&a_code, None, t0),
            Err(CodeRefusal::Wrong)
        );

        // The other pairing was not touched.
        assert_eq!(open.by_id[&b].wrong, 0);
        assert_eq!(open.status(&b, t0).unwrap()["state"], "waiting");

        // A code that names no waiting pairing cancels nothing, however often.
        let unknown = names_no_pairing(&open);
        for _ in 0..=MAX_WRONG_CODES {
            assert_eq!(
                open.redeem_secret(&unknown, None, t0),
                Err(CodeRefusal::Wrong)
            );
            assert_eq!(
                open.redeem_secret("not a code", None, t0),
                Err(CodeRefusal::Wrong)
            );
        }
        assert_eq!(open.by_id[&b].wrong, 0);
        assert_eq!(open.status(&b, t0).unwrap()["state"], "waiting");
        assert_eq!(
            open.redeem_secret(&b_code, None, t0),
            Ok((b, OPERATOR.to_string()))
        );
    }

    #[test]
    fn a_source_of_wrong_codes_is_refused_for_a_while() {
        let mut open = OpenPairings::default();
        let t0 = Instant::now();
        let (a, a_code) = open.start(OPERATOR, t0).unwrap();
        let unknown = names_no_pairing(&open);
        let here = Some("192.0.2.1");

        for _ in 0..MAX_WRONG_CODES {
            assert_eq!(
                open.redeem_secret(&unknown, here, t0),
                Err(CodeRefusal::Wrong)
            );
        }
        // From then on its code is not looked at, right or wrong.
        assert_eq!(
            open.redeem_secret(&a_code, here, t0),
            Err(CodeRefusal::TooManyFromSource)
        );
        assert_eq!(
            open.redeem_secret(&wrong_secret(&a_code), here, t0),
            Err(CodeRefusal::TooManyFromSource)
        );
        assert_eq!(open.by_id[&a].wrong, 0);
        // Another source, and a call made inside this process, are not held to it.
        assert_eq!(
            open.redeem_secret(&a_code, Some("192.0.2.2"), t0),
            Ok((a.clone(), OPERATOR.to_string()))
        );
        assert_eq!(
            open.redeem_secret(&a_code, None, t0),
            Ok((a, OPERATOR.to_string()))
        );

        // The source is forgotten five minutes after its first wrong code.
        let later = t0 + CODE_TTL - Duration::from_secs(1);
        let (c, c_code) = open.start(OPERATOR, later).unwrap();
        assert_eq!(
            open.redeem_secret(&c_code, here, later),
            Err(CodeRefusal::TooManyFromSource)
        );
        assert_eq!(
            open.redeem_secret(&c_code, here, t0 + CODE_TTL),
            Ok((c, OPERATOR.to_string()))
        );
        assert!(open.wrong_from.is_empty());
    }

    #[test]
    fn only_so_many_sources_of_wrong_codes_are_remembered() {
        let mut open = OpenPairings::default();
        let t0 = Instant::now();
        let unknown = names_no_pairing(&open);
        for n in 0..MAX_SOURCES {
            let source = format!("source-{n}");
            assert_eq!(
                open.redeem_secret(&unknown, Some(source.as_str()), t0),
                Err(CodeRefusal::Wrong)
            );
        }
        for _ in 0..=MAX_WRONG_CODES {
            assert_eq!(
                open.redeem_secret(&unknown, Some("one-more"), t0),
                Err(CodeRefusal::Wrong)
            );
        }
        assert_eq!(open.wrong_from.len(), MAX_SOURCES);
        assert!(!open.wrong_from.contains_key("one-more"));
    }

    #[test]
    fn a_code_opens_its_own_pairing_once_and_only_in_time() {
        let mut open = OpenPairings::default();
        let t0 = Instant::now();
        let (first, first_code) = open.start(OPERATOR, t0).unwrap();
        let (second, second_code) = open.start(OPERATOR, t0).unwrap();
        assert_ne!(first, second);
        assert_ne!(first_code[..NAME_CHARS], second_code[..NAME_CHARS]);

        let just_in_time = t0 + CODE_TTL - Duration::from_secs(1);
        // Checking a code does not use it up; settling its pairing does.
        for _ in 0..2 {
            assert_eq!(
                open.redeem_secret(&grouped(&first_code).to_lowercase(), None, just_in_time),
                Ok((first.clone(), OPERATOR.to_string()))
            );
        }
        let wrong = Err(CodeRefusal::Wrong);
        assert_eq!(
            open.redeem_secret(&names_no_pairing(&open), None, just_in_time),
            wrong
        );
        assert_eq!(open.redeem_secret("not a code", None, just_in_time), wrong);

        // Settled either way, the code is spent.
        open.settle(&first, Outcome::Failed("refused".to_string()));
        assert_eq!(open.redeem_secret(&first_code, None, just_in_time), wrong);
        assert_eq!(
            open.status(&first, just_in_time).unwrap()["state"],
            "failed"
        );
        assert_eq!(
            open.status(&first, just_in_time).unwrap()["reason"],
            "refused"
        );

        // Out of time, the other code opens nothing and reads as expired.
        assert_eq!(
            open.status(&second, just_in_time).unwrap()["state"],
            "waiting"
        );
        assert_eq!(open.redeem_secret(&second_code, None, t0 + CODE_TTL), wrong);
        assert_eq!(
            open.status(&second, t0 + CODE_TTL).unwrap()["state"],
            "expired"
        );
        assert!(open.status("unknown", t0).is_none());
    }

    #[test]
    fn only_so_many_pairings_wait_and_old_ones_are_forgotten() {
        let mut open = OpenPairings::default();
        let t0 = Instant::now();
        let mut ids = Vec::new();
        for _ in 0..MAX_WAITING {
            ids.push(open.start("did:tenzro:human:op", t0).unwrap().0);
        }
        assert!(open.start("did:tenzro:human:op", t0).is_err());
        // A settled pairing no longer waits.
        open.settle(&ids[0], Outcome::Failed("refused".to_string()));
        open.start("did:tenzro:human:op", t0).unwrap();
        assert!(open.start("did:tenzro:human:op", t0).is_err());
        // Expired pairings do not wait either, and are forgotten in the end.
        open.start("did:tenzro:human:op", t0 + CODE_TTL).unwrap();
        assert!(open.status(&ids[1], t0 + CODE_TTL).is_some());
        open.start("did:tenzro:human:op", t0 + OUTCOME_KEPT)
            .unwrap();
        assert!(open.status(&ids[1], t0 + OUTCOME_KEPT).is_none());
        assert_eq!(open.by_id.len(), 2);
    }

    #[test]
    fn the_qr_code_is_square_rows_of_zeros_and_ones() {
        let url = pairing_url("0123456789ABCDEF", None, None, &Lan::default());
        assert_eq!(
            url,
            "https://control.tenzro.com/pair#secret=0123456789ABCDEF"
        );
        let rows = qr_rows(&url).unwrap();
        assert!(rows.len() >= 21);
        for row in &rows {
            assert_eq!(row.len(), rows.len());
            assert!(row.bytes().all(|b| b == b'0' || b == b'1'));
        }
        // The finder pattern's corner: seven dark modules, then a light one.
        assert!(rows[0].starts_with("11111110"));
        assert_eq!(
            pairing_url(
                "0123456789ABCDEF",
                Some("https://node.example/rpc"),
                None,
                &Lan::default()
            ),
            "https://control.tenzro.com/pair#node=https%3A%2F%2Fnode.example%2Frpc&secret=0123456789ABCDEF"
        );
        // The node's identity travels with the code, so a device knows which
        // node it pairs with before it signs in.
        assert_eq!(
            pairing_url(
                "0123456789ABCDEF",
                Some("https://node.example/rpc"),
                Some("did:tenzro:machine:abc"),
                &Lan::default()
            ),
            "https://control.tenzro.com/pair#node=https%3A%2F%2Fnode.example%2Frpc\
             &did=did%3Atenzro%3Amachine%3Aabc&secret=0123456789ABCDEF"
        );
        // The listener's addresses and the hashes a device pins travel with
        // the code, each address before each hash.
        let lan = Lan {
            addresses: vec!["192.168.1.20:8543".to_string(), "10.0.0.4:8543".to_string()],
            pins: vec!["aa".repeat(32), "bb".repeat(32)],
            unavailable: String::new(),
        };
        let url = pairing_url("0123456789ABCDEF", None, None, &lan);
        assert_eq!(
            url,
            format!(
                "https://control.tenzro.com/pair#lan=192.168.1.20%3A8543&lan=10.0.0.4%3A8543&pin={}&pin={}\
                 &secret=0123456789ABCDEF",
                "aa".repeat(32),
                "bb".repeat(32)
            )
        );
        assert!(qr_rows(&url).is_ok(), "the longest pairing URL fits a code");
    }

    #[test]
    fn pairing_names_the_device_for_the_paired_calls_and_nothing_else() {
        let mut policy = NodeAccessPolicy::default();
        grant(&mut policy, DEVICE).unwrap();
        grant(&mut policy, DEVICE).unwrap();
        grant(&mut policy, OTHER).unwrap();
        policy.validate().unwrap();
        assert_eq!(policy.resources.len(), PAIRED_DEVICE_METHODS.len());
        for method in PAIRED_DEVICE_METHODS {
            assert_eq!(
                policy.resource_rule(&method_resource(method)),
                Some(&Rule::Allow {
                    dids: vec![DEVICE.to_string(), OTHER.to_string()],
                    orgs: Vec::new(),
                })
            );
        }
        assert!(policy.admins.is_empty());
        assert!(named(&policy, DEVICE));

        withdraw(&mut policy, DEVICE);
        assert!(!named(&policy, DEVICE));
        assert!(named(&policy, OTHER));
        withdraw(&mut policy, OTHER);
        assert!(
            policy.resources.is_empty(),
            "a list naming nobody is dropped"
        );
        policy.validate().unwrap();
    }

    #[test]
    fn pairing_leaves_other_rules_as_the_operator_wrote_them() {
        let mut policy = NodeAccessPolicy::default();
        let bucket = ResourceRule {
            resource: "bucket:photos".to_string(),
            rule: Rule::Allow {
                dids: vec![DEVICE.to_string()],
                orgs: Vec::new(),
            },
        };
        policy.resources.push(bucket.clone());
        grant(&mut policy, DEVICE).unwrap();
        withdraw(&mut policy, DEVICE);
        assert_eq!(policy.resources, vec![bucket]);

        // A rule for a paired call that is not a list of identities is the
        // operator's own; pairing fails with the reason instead of replacing it.
        let mut closed = NodeAccessPolicy::default();
        closed.resources.push(ResourceRule {
            resource: method_resource(PAIRED_DEVICE_METHODS[0]),
            rule: Rule::Closed,
        });
        let before = closed.clone();
        let why = grant(&mut closed.clone(), DEVICE).unwrap_err();
        assert!(why.contains("not a list of identities"), "{why}");
        withdraw(&mut closed, DEVICE);
        assert_eq!(closed, before);
    }

    #[test]
    fn a_paired_device_may_make_admin_calls_only() {
        for method in PAIRED_DEVICE_METHODS {
            assert_eq!(
                crate::rpc_gates::gate_class(method),
                Some(crate::rpc_gates::GateClass::Admin),
                "{method}"
            );
        }
    }

    #[test]
    fn a_label_is_short_plain_text_and_a_kind_is_a_known_one() {
        assert_eq!(
            label_of(&json!({ "label": "  Kitchen TV " })).unwrap(),
            "Kitchen TV"
        );
        assert!(label_of(&json!({})).is_err());
        assert!(label_of(&json!({ "label": "   " })).is_err());
        assert!(label_of(&json!({ "label": "a\nb" })).is_err());
        assert!(label_of(&json!({ "label": "x".repeat(MAX_LABEL_CHARS) })).is_ok());
        assert!(label_of(&json!({ "label": "x".repeat(MAX_LABEL_CHARS + 1) })).is_err());
        assert_eq!(kind_of(&json!({ "kind": "phone" })).unwrap(), "phone");
        assert!(kind_of(&json!({ "kind": "toaster" })).is_err());
        assert!(kind_of(&json!({})).is_err());
    }

    #[test]
    fn an_assertion_approves_the_call_it_was_signed_for_and_no_other() {
        let nonce = [7u8; 32];
        let call = json!({ "version": "0.2.9", "url": "https://example.org/a" });
        let signed = consent_challenge(&nonce, "tenzro_installUpdate", Some(&call));
        // The assertion that answers the call, and the order of its fields, do not change it.
        let answered = json!([{
            "url": "https://example.org/a",
            "assertion": { "signature": "x" },
            "version": "0.2.9",
        }]);
        assert_eq!(
            consent_challenge(&nonce, "tenzro_installUpdate", Some(&answered)),
            signed
        );
        // Another release, another source, another method, another nonce: another challenge.
        let other_version = json!({ "version": "0.2.4", "url": "https://example.org/a" });
        let other_url = json!({ "version": "0.2.9", "url": "https://example.org/b" });
        for (method, nonce, params) in [
            ("tenzro_installUpdate", nonce, &other_version),
            ("tenzro_installUpdate", nonce, &other_url),
            ("tenzro_restartNode", nonce, &call),
            ("tenzro_installUpdate", [8u8; 32], &call),
        ] {
            assert_ne!(consent_challenge(&nonce, method, Some(params)), signed);
        }
        assert_ne!(
            consent_challenge(&nonce, "tenzro_installUpdate", None),
            signed
        );
    }

    #[test]
    fn every_call_the_operator_decides_is_a_paired_call() {
        for method in CONSENT_METHODS {
            assert!(PAIRED_DEVICE_METHODS.contains(method), "{method}");
        }
        assert!(PAIRED_DEVICE_METHODS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn a_passkey_without_its_post_quantum_leg_signs_in_only_for_pairing() {
        assert!(token_purpose(None, true).is_err());
        assert_eq!(
            token_purpose(Some(SignInGrant::PairingCode), true),
            Ok(Some(REDEEM_PURPOSE))
        );
        assert_eq!(
            token_purpose(Some(SignInGrant::PairedDevice), true),
            Ok(Some(PAIRED_PURPOSE))
        );
        assert_eq!(
            token_purpose(Some(SignInGrant::PairingCode), false),
            Ok(Some(REDEEM_PURPOSE))
        );
        assert_eq!(
            token_purpose(Some(SignInGrant::PairedDevice), false),
            Ok(None)
        );
        assert_eq!(token_purpose(None, false), Ok(None));
    }

    #[test]
    fn a_pairing_token_is_admitted_on_its_own_calls_and_no_other() {
        let gates = crate::rpc_gates::ADMIN_METHODS
            .iter()
            .chain(crate::rpc_gates::OWNER_METHODS)
            .chain(crate::rpc_gates::OPEN_METHODS);
        for method in gates {
            let expected = if *method == PAIR_METHOD {
                Some(REDEEM_PURPOSE)
            } else if PAIRED_DEVICE_METHODS.contains(method) {
                Some(PAIRED_PURPOSE)
            } else if crate::rpc_gates::OPEN_METHODS.contains(method) {
                Some(crate::device_code::VIEWER_PURPOSE)
            } else {
                None
            };
            assert_eq!(purpose_for(method), expected, "{method}");
        }
        assert_eq!(
            PURPOSES,
            [
                REDEEM_PURPOSE,
                PAIRED_PURPOSE,
                crate::device_code::VIEWER_PURPOSE
            ]
        );
    }

    #[test]
    fn only_an_https_page_at_or_under_the_relying_party_is_recorded() {
        let rp = "tenzro.com";
        assert_eq!(
            origin_under("https://control.tenzro.com", rp).as_deref(),
            Some("https://control.tenzro.com")
        );
        assert_eq!(
            origin_under("https://Tenzro.com:8443", rp).as_deref(),
            Some("https://tenzro.com:8443")
        );
        for outside in [
            "http://control.tenzro.com",
            "https://tenzro.com.evil.example",
            "https://eviltenzro.com",
            "https://evil.example",
            "https://control.tenzro.com/path",
            "https://user@control.tenzro.com",
            "https://control.tenzro.com:port",
            "https://[::1]",
            "null",
            "",
        ] {
            assert_eq!(origin_under(outside, rp), None, "{outside}");
        }
        assert_eq!(origin_under("https://control.tenzro.com", ""), None);
    }

    #[test]
    fn a_page_answered_for_pairing_makes_only_its_own_calls() {
        for method in PAIRED_DEVICE_METHODS {
            assert!(page_may_call(Page::Paired, method), "{method}");
            assert!(!page_may_call(Page::Pairing, method), "{method}");
        }
        assert!(page_may_call(Page::Paired, "tenzro_getNodeStatus"));
        for method in PAIRING_PAGE_CALLS {
            assert!(page_may_call(Page::Pairing, method), "{method}");
        }
        for method in crate::rpc_gates::ADMIN_METHODS
            .iter()
            .chain(crate::rpc_gates::OWNER_METHODS)
        {
            if !PAIRED_DEVICE_METHODS.contains(method) {
                assert!(!page_may_call(Page::Paired, method), "{method}");
            }
            if !PAIRING_PAGE_CALLS.contains(method) {
                assert!(!page_may_call(Page::Pairing, method), "{method}");
            }
        }
        assert!(!page_may_call(Page::Pairing, "tenzro_getNodeStatus"));
    }
}
