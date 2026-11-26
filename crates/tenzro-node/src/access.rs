//! Operator access gating: who may use this node's service surfaces.
//!
//! One policy, `access.toml` in the data directory, maps each (surface,
//! method class) to a rule ([`tenzro_types::node_access`]). The wizard
//! (`tenzro-node access`), the loopback admin page and the file itself all go
//! through [`AccessPolicyStore`]: validate, write atomically, bump the
//! version, append an audit line, reload. The file is the only copy; a node
//! watching it applies an edit without a restart.
//!
//! Callers prove who they are once, with a passkey or a hardware key, and
//! receive a short-lived ES256 access token bound to a DPoP key
//! (`tenzro_accessChallenge`, `tenzro_issueAccessToken`). No shared secret
//! exists: tokens are signed by the node's hardware-rooted key and every
//! request re-evaluates the policy for the token's DID, so a policy change
//! applies to tokens already issued.
//!
//! Gating is local policy over service surfaces only. Consensus, gossip and
//! voting never pass through it, and it can only refuse: what an agent may do
//! is decided by its consensus Terms, and no rule here grants beyond them.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::{Mutex, RwLock};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_types::node_access::{MethodClass, NodeAccessPolicy, Rule, Surface};
use tracing::{info, warn};

use crate::node::TenzroNode;
use crate::rpc::{AuthContext, JsonRpcError};

/// The policy file's name in the data directory.
pub const POLICY_FILE: &str = "access.toml";
/// The append-only log of accepted policy changes, beside the policy.
pub const POLICY_LOG: &str = "access.log";
/// How often a running node looks for an edited policy file.
const RELOAD_POLL: Duration = Duration::from_secs(2);
/// How long a sign-in challenge stays answerable.
const CHALLENGE_TTL: Duration = Duration::from_secs(300);
/// Most sign-in challenges outstanding at once.
const MAX_CHALLENGES: usize = 10_000;

/// The node's access policy and the file it lives in.
pub struct AccessPolicyStore {
    path: PathBuf,
    current: RwLock<Arc<NodeAccessPolicy>>,
    modified: Mutex<Option<SystemTime>>,
}

impl std::fmt::Debug for AccessPolicyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessPolicyStore")
            .field("path", &self.path)
            .field("version", &self.current.read().version)
            .finish()
    }
}

fn modified_at(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Parse and validate a policy document.
pub fn parse_policy(text: &str) -> Result<NodeAccessPolicy, String> {
    let policy: NodeAccessPolicy = toml::from_str(text).map_err(|e| format!("access.toml: {e}"))?;
    policy.validate()?;
    Ok(policy)
}

/// Render a policy as the file stores it.
pub fn render_policy(policy: &NodeAccessPolicy) -> Result<String, String> {
    toml::to_string_pretty(policy).map_err(|e| format!("access.toml: {e}"))
}

impl AccessPolicyStore {
    /// The store for the node whose data directory is `data_dir`: the policy
    /// in its `access.toml`, or the open default when there is none. A file
    /// that does not parse or validate refuses to open, so a node never
    /// starts on a policy its operator did not write.
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let path = data_dir.join(POLICY_FILE);
        let policy = match std::fs::read_to_string(&path) {
            Ok(text) => parse_policy(&text)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => NodeAccessPolicy::default(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(Self {
            modified: Mutex::new(modified_at(&path)),
            current: RwLock::new(Arc::new(policy)),
            path,
        })
    }

    /// The policy in force.
    pub fn policy(&self) -> Arc<NodeAccessPolicy> {
        self.current.read().clone()
    }

    /// Validate `policy`, give it the next version, write it atomically,
    /// log the change and put it in force. Returns the new version.
    pub fn set(&self, mut policy: NodeAccessPolicy, by: &str) -> Result<u64, String> {
        policy.validate()?;
        let mut current = self.current.write();
        policy.version = current.version + 1;
        let text = render_policy(&policy)?;
        let tmp = self.path.with_extension("toml.tmp");
        std::fs::write(&tmp, &text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("install {}: {e}", self.path.display()))?;
        let line = json!({
            "version": policy.version,
            "by": by,
            "sha256": hex::encode(Sha256::digest(text.as_bytes())),
            "at_ms": chrono::Utc::now().timestamp_millis(),
        });
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path.with_file_name(POLICY_LOG))
            .and_then(|mut f| writeln!(f, "{line}"))
            .map_err(|e| format!("access log: {e}"))?;
        *self.modified.lock() = modified_at(&self.path);
        let version = policy.version;
        *current = Arc::new(policy);
        info!(version, by, "access policy changed");
        Ok(version)
    }

    /// Re-read the file when it changed on disk. An edit that does not parse
    /// or validate is refused and the policy in force stays.
    pub fn reload_if_changed(&self) {
        let now = modified_at(&self.path);
        if now == *self.modified.lock() {
            return;
        }
        *self.modified.lock() = now;
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return;
        };
        match parse_policy(&text) {
            Ok(policy) => {
                info!(
                    version = policy.version,
                    "access policy reloaded from {}",
                    self.path.display()
                );
                *self.current.write() = Arc::new(policy);
            }
            Err(e) => warn!("access policy edit refused, keeping the policy in force: {e}"),
        }
    }

    /// Watch the file and apply edits as they land.
    pub fn spawn_watcher(self: &Arc<Self>) {
        let store = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(RELOAD_POLL).await;
                let Some(store) = store.upgrade() else { return };
                store.reload_if_changed();
            }
        });
    }
}

/// A KYA credential a caller presented at sign-in, verified.
#[derive(Debug, Clone)]
struct HeldCredential {
    issuer: String,
    valid_until_ms: i64,
}

/// The node's access gating: the policy, the tier meter, outstanding
/// sign-in challenges, and the credentials callers presented at sign-in.
#[derive(Debug)]
pub struct Access {
    store: Arc<AccessPolicyStore>,
    meter: TierMeter,
    challenges: SignInChallenges,
    credentials: Mutex<HashMap<String, Vec<HeldCredential>>>,
    pairings: crate::pairing_rpc::Pairings,
    device_codes: crate::device_code::DeviceCodes,
    #[cfg(feature = "paired-devices")]
    paired_listener: crate::paired_listener::Door,
}

impl Access {
    /// Gating over the policy in `store`.
    pub fn new(store: Arc<AccessPolicyStore>) -> Self {
        Self {
            store,
            meter: TierMeter::default(),
            challenges: SignInChallenges::default(),
            credentials: Mutex::new(HashMap::new()),
            pairings: crate::pairing_rpc::Pairings::default(),
            device_codes: crate::device_code::DeviceCodes::default(),
            #[cfg(feature = "paired-devices")]
            paired_listener: crate::paired_listener::Door::default(),
        }
    }

    /// The device pairings started on this node.
    pub(crate) fn pairings(&self) -> &crate::pairing_rpc::Pairings {
        &self.pairings
    }

    /// The device codes devices with no key of their own sign in with.
    pub(crate) fn device_codes(&self) -> &crate::device_code::DeviceCodes {
        &self.device_codes
    }

    /// The listener paired devices reach this node on.
    #[cfg(feature = "paired-devices")]
    pub(crate) fn paired_listener(&self) -> &crate::paired_listener::Door {
        &self.paired_listener
    }

    /// The policy store.
    pub fn store(&self) -> &Arc<AccessPolicyStore> {
        &self.store
    }

    /// The policy in force.
    pub fn policy(&self) -> Arc<NodeAccessPolicy> {
        self.store.policy()
    }

    /// Whether `did` administers `node`: its operator (the configured
    /// `operator_did`, else the machine itself), or an admin the policy names.
    pub fn is_admin(&self, node: &TenzroNode, did: &str) -> bool {
        node.administrator_did().as_deref() == Some(did)
            || self.policy().admins.iter().any(|a| a == did)
    }

    /// Charge one request by `who` to tier `tier`, or say when to retry.
    pub fn charge_tier(
        &self,
        policy: &NodeAccessPolicy,
        tier: &str,
        who: &str,
    ) -> Result<(), String> {
        self.meter.charge(policy, tier, who)
    }

    /// The issuers of the live KYA credentials `did` presented.
    fn kya_issuers(&self, did: &str) -> Vec<String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut held = self.credentials.lock();
        let Some(list) = held.get_mut(did) else {
            return Vec::new();
        };
        list.retain(|c| c.valid_until_ms > now);
        list.iter().map(|c| c.issuer.clone()).collect()
    }
}

/// The method class of a JSON-RPC method.
///
/// Admin methods are the admin class whatever they serve. Every other method
/// is classed by what it serves, so closing a class closes its writes too;
/// an owner-proved write that serves none of them is `owner_write`.
pub fn method_class(method: &str) -> MethodClass {
    use crate::rpc_gates::{GateClass, gate_class};
    let gate = gate_class(method);
    if gate == Some(GateClass::Admin) {
        return MethodClass::Admin;
    }
    let m = method.strip_prefix("tenzro_").unwrap_or(method);
    let has = |words: &[&str]| words.iter().any(|w| m.starts_with(w) || m.contains(w));
    if has(&[
        "mediaGen",
        "segment",
        "detect",
        "transcribe",
        "speak",
        "image",
        "video",
        "vision",
        "Video",
        "Vision",
        "Image",
    ]) {
        MethodClass::Media
    } else if has(&[
        "chat",
        "infer",
        "Inference",
        "embed",
        "rerank",
        "decide",
        "DecisionModel",
        "DecisionCatalog",
        "forecast",
        "moe",
        "quoteInference",
    ]) {
        MethodClass::Inference
    } else if has(&["storage", "Storage"]) {
        MethodClass::Storage
    } else if has(&["queryEvents", "subscribe", "Event", "Index", "index"]) {
        MethodClass::Index
    } else if has(&[
        "ayment",
        "Channel",
        "settle",
        "Settlement",
        "x402",
        "Escrow",
        "voucher",
        "Voucher",
    ]) {
        MethodClass::Payments
    } else if has(&[
        "dentity", "Did", "did", "asskey", "onboard", "Token", "Kya", "access",
    ]) {
        MethodClass::Identity
    } else if gate == Some(GateClass::Owner) {
        MethodClass::OwnerWrite
    } else {
        MethodClass::Read
    }
}

/// Who is calling, as far as the node can tell.
#[derive(Debug, Clone, Default)]
pub struct Caller {
    /// The DID of a valid access token's bearer.
    pub did: Option<String>,
    /// Where the request came from.
    pub ip: Option<IpAddr>,
}

/// What the policy says about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Served; held to the named tier's rate when one applies. `named` is
    /// true when the rule admitted the caller for who it is (an allow list, a
    /// credential, Terms, a sign-in tier) rather than because the surface is
    /// open to anyone.
    Allow { tier: Option<String>, named: bool },
    /// Served once a payment settles.
    Pay {
        via: tenzro_types::node_access::PaidVia,
        price: String,
        asset: String,
    },
    /// Refused, with the reason.
    Refuse(String),
}

/// Whether `did` is one of `orgs` or an identity delegated under one: a root
/// (a human or an autonomous machine) admits the agents and machines derived
/// under it.
fn in_orgs(orgs: &[String], did: &str) -> bool {
    orgs.iter()
        .any(|o| o == did || tenzro_types::identity::is_delegated_under(did, o))
}

/// What one rule says about `caller`.
pub(crate) fn admits_rule(node: &TenzroNode, rule: &Rule, caller: &Caller) -> Decision {
    match rule {
        Rule::Open => Decision::Allow {
            tier: None,
            named: false,
        },
        Rule::Closed => Decision::Refuse("this surface is closed".to_string()),
        Rule::Paid { via, price, asset } => Decision::Pay {
            via: *via,
            price: price.clone(),
            asset: asset.clone(),
        },
        Rule::Allow { dids, orgs } => match &caller.did {
            Some(did) if dids.contains(did) || in_orgs(orgs, did) => Decision::Allow {
                tier: None,
                named: true,
            },
            Some(did) => Decision::Refuse(format!("{did} is not on this node's allow list")),
            None => {
                Decision::Refuse("sign in: this surface admits named identities only".to_string())
            }
        },
        Rule::Credential { kind, issuers } => match &caller.did {
            Some(did) if holds_credential(node, did, *kind, issuers) => Decision::Allow {
                tier: None,
                named: true,
            },
            Some(did) => Decision::Refuse(format!("{did} holds no accepted {kind:?} credential")),
            None => Decision::Refuse("sign in: this surface requires a credential".to_string()),
        },
        Rule::Terms { action } => match &caller.did {
            Some(did) => match terms_allow(node, did, action) {
                Ok(()) => Decision::Allow {
                    tier: None,
                    named: true,
                },
                Err(why) => Decision::Refuse(why),
            },
            None => Decision::Refuse(
                "sign in: this surface admits agents acting under Terms".to_string(),
            ),
        },
        Rule::Tier { name } => match &caller.did {
            Some(_) => Decision::Allow {
                tier: Some(name.clone()),
                named: true,
            },
            None => Decision::Refuse("sign in to use this surface".to_string()),
        },
        Rule::All { rules } => {
            let (mut tier, mut named) = (None, false);
            for r in rules {
                match admits_rule(node, r, caller) {
                    Decision::Allow { tier: t, named: n } => {
                        tier = t.or(tier);
                        named |= n;
                    }
                    other => return other,
                }
            }
            Decision::Allow { tier, named }
        }
        Rule::Any { rules } => {
            let mut last = Decision::Refuse("no rule admits this caller".to_string());
            for r in rules {
                match admits_rule(node, r, caller) {
                    allow @ Decision::Allow { .. } => return allow,
                    pay @ Decision::Pay { .. } => last = pay,
                    refuse => {
                        if !matches!(last, Decision::Pay { .. }) {
                            last = refuse
                        }
                    }
                }
            }
            last
        }
        Rule::Not { inner } => match admits_rule(node, inner, caller) {
            Decision::Allow { .. } => Decision::Refuse("this caller is excluded".to_string()),
            _ => Decision::Allow {
                tier: None,
                named: false,
            },
        },
    }
}

/// Whether `did` holds a verified credential of `kind` from an accepted
/// issuer (any issuer when `issuers` is empty).
fn holds_credential(
    node: &TenzroNode,
    did: &str,
    kind: tenzro_types::node_access::CredentialKind,
    issuers: &[String],
) -> bool {
    use tenzro_types::node_access::CredentialKind;
    match kind {
        CredentialKind::Kya => node
            .access()
            .kya_issuers(did)
            .iter()
            .any(|issuer| issuers.is_empty() || issuers.contains(issuer)),
    }
}

/// Whether `did` is an agent whose live consensus Terms allow `action` now.
fn terms_allow(node: &TenzroNode, did: &str, action: &str) -> Result<(), String> {
    let chain = crate::rpc::chain_state_of(node).ok_or("this node follows no chain")?;
    tenzro_vm::native::check_agent_status(
        &chain,
        did,
        chrono::Utc::now().timestamp_millis().max(0) as u64,
    )?;
    let stored = tenzro_vm::native::agent_terms::read_agent_terms(&chain, did)
        .ok_or_else(|| format!("{did} acts under no Terms"))?;
    if stored
        .terms
        .expires_at_ms
        .is_some_and(|exp| exp <= chrono::Utc::now().timestamp_millis() as u64)
    {
        return Err(format!("{did}'s Terms have expired"));
    }
    if stored
        .terms
        .delegation_scope
        .allowed_operations
        .iter()
        .any(|op| op == action)
    {
        Ok(())
    } else {
        Err(format!("{did}'s Terms do not allow {action}"))
    }
}

/// The policy's decision for `caller` on `class` of `surface`.
///
/// Admin-class methods admit the operator and the policy's admins whatever
/// the rule says; owner-class methods still check the owner's proof in their
/// handler after the rule admits.
pub fn evaluate(
    node: &TenzroNode,
    policy: &NodeAccessPolicy,
    caller: &Caller,
    surface: Surface,
    class: MethodClass,
) -> Decision {
    if class == MethodClass::Admin {
        return match &caller.did {
            Some(did)
                if node.administrator_did().as_deref() == Some(did.as_str())
                    || policy.admins.contains(did) =>
            {
                Decision::Allow {
                    tier: None,
                    named: true,
                }
            }
            Some(did) => Decision::Refuse(format!("{did} is not an administrator of this node")),
            None => Decision::Refuse("sign in as this node's operator".to_string()),
        };
    }
    admits_rule(node, policy.rule_for(surface, class), caller)
}

/// Per-caller rate and quota counters for the policy's tiers.
#[derive(Debug, Default)]
pub struct TierMeter {
    buckets: Mutex<HashMap<(String, String), Bucket>>,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: std::time::Instant,
    period_start: u64,
    used: u64,
}

impl TierMeter {
    /// Charge one request by `who` to tier `tier`, or say when to retry.
    pub fn charge(&self, policy: &NodeAccessPolicy, tier: &str, who: &str) -> Result<(), String> {
        self.charge_at(
            policy,
            tier,
            who,
            std::time::Instant::now(),
            chrono::Utc::now().timestamp() as u64,
        )
    }

    /// [`Self::charge`] at `now` (for the rate) and `epoch`, seconds since the
    /// Unix epoch (for the quota period).
    fn charge_at(
        &self,
        policy: &NodeAccessPolicy,
        tier: &str,
        who: &str,
        now: std::time::Instant,
        epoch: u64,
    ) -> Result<(), String> {
        let Some(t) = policy.tier(tier) else {
            return Err(format!("tier {tier} is not defined"));
        };
        let mut buckets = self.buckets.lock();
        let b = buckets
            .entry((tier.to_string(), who.to_string()))
            .or_insert(Bucket {
                tokens: f64::from(t.burst.max(1)),
                at: now,
                period_start: epoch,
                used: 0,
            });
        let rate = f64::from(t.rate_per_minute) / 60.0;
        b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * rate)
            .min(f64::from(t.burst.max(1)));
        b.at = now;
        if b.tokens < 1.0 {
            return Err(format!(
                "tier {tier} allows {} requests a minute; slow down",
                t.rate_per_minute
            ));
        }
        if t.quota_per_period > 0 {
            if epoch.saturating_sub(b.period_start) >= t.period_secs {
                b.period_start = epoch;
                b.used = 0;
            }
            if b.used >= t.quota_per_period {
                return Err(format!(
                    "tier {tier} quota of {} requests is used up",
                    t.quota_per_period
                ));
            }
            b.used += 1;
        }
        b.tokens -= 1.0;
        Ok(())
    }
}

/// Resolve the caller of a request from its access token, if it carries
/// one. Only a DPoP-bound access token names a caller; a request carrying
/// none, or another scheme, is anonymous here. A DPoP token that does not
/// verify is refused.
pub(crate) async fn caller_of(
    node: &Arc<TenzroNode>,
    auth: &AuthContext,
    ip: Option<IpAddr>,
) -> Result<Caller, JsonRpcError> {
    Ok(Caller {
        did: proved_token(node, auth)?.map(|claims| claims.sub),
        ip,
    })
}

/// The claims of a request's DPoP-bound access token, once it verifies.
/// `None` when the request carries none, or another scheme.
pub(crate) fn proved_token(
    node: &Arc<TenzroNode>,
    auth: &AuthContext,
) -> Result<Option<tenzro_auth::AuthClaims>, JsonRpcError> {
    proved_token_for(node, auth, None)
}

/// [`proved_token`] for a call to `method`, with the token pairing issues
/// for that call alone verifying too ([`crate::pairing_rpc::purpose_for`]).
pub(crate) fn proved_token_of(
    node: &Arc<TenzroNode>,
    auth: &AuthContext,
    method: &str,
) -> Result<Option<tenzro_auth::AuthClaims>, JsonRpcError> {
    let claims = proved_token_for(node, auth, crate::pairing_rpc::purpose_for(method))?;
    // A device signed in by device code holds its tokens only while listed.
    if let Some(c) = &claims
        && c.aud
            .ends_with(&format!("#{}", crate::device_code::VIEWER_PURPOSE))
        && !crate::pairing_rpc::is_viewer(node, &c.sub)
    {
        return Err(refused("that device is no longer paired with this node"));
    }
    Ok(claims)
}

/// The claims of the token pairing issued for a few calls only that the
/// request presents, once it verifies. Such a token names no caller until
/// the gate knows the method it is for; its proof counts once, so the claims
/// are kept for the gate ([`crate::rpc::with_proved_token`]).
pub(crate) fn proved_pairing_token(
    node: &Arc<TenzroNode>,
    auth: &AuthContext,
) -> Option<(tenzro_auth::AuthClaims, &'static str)> {
    crate::pairing_rpc::PURPOSES.iter().find_map(|&purpose| {
        proved_token_for(node, auth, Some(purpose))
            .ok()
            .flatten()
            .map(|claims| (claims, purpose))
    })
}

/// [`proved_token`], with a token issued for `purpose` alone verifying too.
fn proved_token_for(
    node: &Arc<TenzroNode>,
    auth: &AuthContext,
    purpose: Option<&str>,
) -> Result<Option<tenzro_auth::AuthClaims>, JsonRpcError> {
    let is_dpop = auth.authorization.as_deref().is_some_and(|a| {
        a.trim_start()
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case("dpop "))
    });
    if !is_dpop {
        return Ok(None);
    }
    Ok(crate::rpc::validate_access_token_for(node, auth, purpose)?.map(|(_, claims)| claims))
}

/// The DPoP `htu` a request over iroh signs: the ALPN it arrived on, as
/// `tenzro-iroh://{alpn}`, with `htm` `POST`.
pub fn iroh_htu(alpn: &str) -> String {
    format!("tenzro-iroh://{}", alpn.trim_start_matches('/'))
}

/// The caller of a JSON-RPC frame that arrived over iroh: the DID of the
/// DPoP-bound access token at the frame's top level (`access_token`, with its
/// proof in `dpop`), if it carries one.
pub(crate) async fn iroh_caller(
    node: &Arc<TenzroNode>,
    frame: &Value,
    alpn: &str,
) -> Result<Caller, JsonRpcError> {
    let field = |k: &str| frame.get(k).and_then(Value::as_str).map(str::to_string);
    let auth = AuthContext::from_mcp(
        field("access_token").map(|t| format!("DPoP {t}")),
        field("dpop"),
        "POST".to_string(),
        iroh_htu(alpn),
    );
    caller_of(node, &auth, None).await
}

pub(crate) fn refused(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32004,
        message: message.into(),
        data: None,
    }
}

/// Apply the policy to one JSON-RPC request on `surface`. Reserved methods
/// pass through to the dispatcher, which answers them with their own refusal.
pub(crate) async fn gate(
    node: &Arc<TenzroNode>,
    surface: Surface,
    method: &str,
    params: Option<&Value>,
    auth: &AuthContext,
    ip: Option<IpAddr>,
) -> Result<Caller, JsonRpcError> {
    let caller = Caller {
        did: proved_token_of(node, auth, method)?.map(|claims| claims.sub),
        ip,
    };
    admit(node, surface, method, params, caller)
}

/// The resource a rule names to admit identities to one JSON-RPC method.
pub(crate) fn method_resource(method: &str) -> String {
    format!("rpc:{method}")
}

/// Whether the policy names `caller` for one admin method: a resource rule
/// for that method which admits the caller by identity. Only the admin calls
/// a paired device may make are opened this way, whatever the policy says of
/// any other method, and never to a caller the rule does not name.
fn named_for_method(
    node: &TenzroNode,
    policy: &NodeAccessPolicy,
    method: &str,
    caller: &Caller,
) -> bool {
    crate::pairing_rpc::PAIRED_DEVICE_METHODS.contains(&method)
        && policy
            .resource_rule(&method_resource(method))
            .is_some_and(|rule| {
                matches!(
                    admits_rule(node, rule, caller),
                    Decision::Allow {
                        tier: None,
                        named: true
                    }
                )
            })
}

/// Apply the policy, and an agent's Terms, to `caller` calling `method`.
pub(crate) fn admit(
    node: &Arc<TenzroNode>,
    surface: Surface,
    method: &str,
    params: Option<&Value>,
    caller: Caller,
) -> Result<Caller, JsonRpcError> {
    // An agent reaches only what its consensus Terms allow, whatever the
    // policy admits.
    if let Some(did) = &caller.did
        && let Err(why) = crate::agent_guardrails::counted(
            crate::agent_delegation::check_agent_key_request(node, did, method, params),
        )
    {
        return Err(JsonRpcError {
            code: -32003,
            message: why,
            data: None,
        });
    }
    // A write the identity rule gives to the caller's registered identity.
    {
        use crate::rpc_gates::{EdgeSubject, edge_subject};
        if edge_subject(method) == Some(EdgeSubject::Caller) {
            crate::identity_gate::edge_admits(node, method, caller.did.as_deref(), false)
                .map_err(refused)?;
        }
    }
    let policy = node.access().policy();
    let decision = match evaluate(node, &policy, &caller, surface, method_class(method)) {
        Decision::Refuse(_)
            if surface == Surface::Rpc && named_for_method(node, &policy, method, &caller) =>
        {
            Decision::Allow {
                tier: None,
                named: true,
            }
        }
        decision => decision,
    };
    match decision {
        Decision::Allow { tier: None, .. } => Ok(caller),
        Decision::Allow {
            tier: Some(tier), ..
        } => {
            let who = caller.did.clone().unwrap_or_default();
            node.access()
                .charge_tier(&policy, &tier, &who)
                .map_err(|m| JsonRpcError {
                    code: -32005,
                    message: m,
                    data: None,
                })?;
            Ok(caller)
        }
        Decision::Pay { via, price, asset } => Err(JsonRpcError {
            code: -32402,
            message: "payment required".to_string(),
            data: Some(json!({ "via": via, "price": price, "asset": asset })),
        }),
        Decision::Refuse(why) => Err(refused(why)),
    }
}

/// Route prefixes of the media class: requests carrying or returning an
/// image, a recording or a video.
const MEDIA_ROUTES: &[&str] = &[
    "/v1/images",
    "/v1/video",
    "/v1/audio",
    "/tenzro/realtime",
    "/tenzro/detections",
    "/tenzro/segmentations",
    "/tenzro/video",
];

/// Route prefixes of the inference class.
const INFERENCE_ROUTES: &[&str] = &[
    "/v1/chat",
    "/v1/responses",
    "/v1/embeddings",
    "/tenzro/rerank",
    "/tenzro/forecasts",
    "/tenzro/decide",
];

/// The method class an HTTP route serves.
pub fn route_class(path: &str) -> MethodClass {
    let has = |p: &[&str]| p.iter().any(|x| path.starts_with(x));
    if has(MEDIA_ROUTES) {
        MethodClass::Media
    } else if has(INFERENCE_ROUTES) {
        MethodClass::Inference
    } else {
        MethodClass::Read
    }
}

/// The policy gate for an HTTP surface's routes. The caller is the one
/// [`crate::inference_admission::identify_caller`] named from the request's
/// access token, so that layer must run first. Inference routes leave a
/// `paid` decision to the payment gate behind them, which charges the
/// operator's price; any other paid route answers `402` with the terms.
pub async fn http_gate(
    axum::extract::State((node, surface)): axum::extract::State<(Arc<TenzroNode>, Surface)>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let class = route_class(req.uri().path());
    let payable = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .is_some_and(|m| crate::web::server::PAYABLE_ROUTES.contains(&m.as_str()));
    let caller = Caller {
        did: crate::rpc::current_caller_did(),
        ip: None,
    };
    let policy = node.access().policy();
    let deny =
        |status: axum::http::StatusCode, body: Value| (status, axum::Json(body)).into_response();
    match evaluate(&node, &policy, &caller, surface, class) {
        Decision::Allow { tier, .. } => {
            if let Some(tier) = tier
                && let Err(m) = node.access().charge_tier(
                    &policy,
                    &tier,
                    caller.did.as_deref().unwrap_or_default(),
                )
            {
                return deny(
                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                    json!({ "error": { "code": "rate_limited", "message": m } }),
                );
            }
        }
        // Inference and the payable web routes collect the payment
        // themselves, at the policy's price.
        Decision::Pay { .. }
            if class == MethodClass::Inference || (surface == Surface::Web && payable) => {}
        Decision::Pay { via, price, asset } => {
            return deny(
                axum::http::StatusCode::PAYMENT_REQUIRED,
                json!({ "error": { "code": "payment_required", "message": "payment required", "via": via, "price": price, "asset": asset } }),
            );
        }
        // An anonymous caller is told to sign in; a signed-in one that the
        // policy does not admit is told so.
        Decision::Refuse(why) if caller.did.is_none() => {
            return deny(
                axum::http::StatusCode::UNAUTHORIZED,
                json!({ "error": { "code": "sign_in_required", "message": why } }),
            );
        }
        Decision::Refuse(why) => {
            return deny(
                axum::http::StatusCode::FORBIDDEN,
                json!({ "error": { "code": "not_admitted", "message": why } }),
            );
        }
    }
    next.run(req).await
}

/// What a web request owes under the access policy: `Some((amount, asset))`
/// when the policy's rule for the caller on the web surface is `paid`.
pub fn web_pricing(node: Arc<TenzroNode>) -> crate::web::server::PriceFor {
    Arc::new(move |path: &str| {
        let caller = Caller {
            did: crate::rpc::current_caller_did(),
            ip: None,
        };
        match evaluate(
            &node,
            &node.access().policy(),
            &caller,
            Surface::Web,
            route_class(path),
        ) {
            Decision::Pay { price, asset, .. } => {
                price.parse::<u128>().ok().map(|amount| (amount, asset))
            }
            _ => None,
        }
    })
}

/// An issued, not yet answered sign-in challenge.
#[derive(Debug, Clone)]
struct PendingSignIn {
    /// The identity named when the challenge was asked for; a passkey
    /// sign-in may name none and is then the identity its passkey's account
    /// belongs to.
    did: Option<String>,
    dpop_jkt: String,
    challenge: [u8; 32],
    issued: std::time::Instant,
}

/// Single-use sign-in challenges, in memory: one that outlives the process
/// buys nothing, the caller asks again.
#[derive(Debug, Default)]
pub struct SignInChallenges {
    pending: Mutex<HashMap<String, PendingSignIn>>,
}

impl SignInChallenges {
    fn issue(&self, did: Option<&str>, dpop_jkt: &str) -> Result<(String, [u8; 32]), String> {
        let mut pending = self.pending.lock();
        pending.retain(|_, p| p.issued.elapsed() < CHALLENGE_TTL);
        if pending.len() >= MAX_CHALLENGES {
            return Err("too many sign-ins in flight; try again shortly".to_string());
        }
        let mut challenge = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut challenge);
        let id = hex::encode(&challenge[..16]);
        pending.insert(
            id.clone(),
            PendingSignIn {
                did: did.map(str::to_string),
                dpop_jkt: dpop_jkt.to_string(),
                challenge,
                issued: std::time::Instant::now(),
            },
        );
        Ok((id, challenge))
    }

    fn take(&self, id: &str) -> Result<PendingSignIn, String> {
        let p = self
            .pending
            .lock()
            .remove(id)
            .ok_or("unknown or used sign-in challenge")?;
        if p.issued.elapsed() >= CHALLENGE_TTL {
            return Err("the sign-in challenge expired".to_string());
        }
        Ok(p)
    }
}

/// The message a hardware key signs to sign in: binds the node, the DID, the
/// DPoP key and the challenge. Each part is length-prefixed and the first is
/// the domain `tenzro/access/sign-in`, so a key holder that signs only
/// messages in a Tenzro domain signs this one.
pub fn sign_in_message(issuer: &str, did: &str, dpop_jkt: &str, challenge: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::new();
    for part in [
        b"tenzro/access/sign-in".as_slice(),
        issuer.as_bytes(),
        did.as_bytes(),
        dpop_jkt.as_bytes(),
        challenge,
    ] {
        m.extend_from_slice(&(part.len() as u32).to_be_bytes());
        m.extend_from_slice(part);
    }
    m
}

pub(crate) fn bad(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

pub(crate) fn str_param<'a>(p: &'a Value, key: &str) -> Result<&'a str, JsonRpcError> {
    p.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| bad(format!("Missing '{key}'")))
}

pub(crate) fn first_param(params: Option<Value>) -> Value {
    match params {
        Some(Value::Array(mut a)) if !a.is_empty() => a.swap_remove(0),
        Some(v) => v,
        None => Value::Null,
    }
}

/// `tenzro_accessChallenge { did?, dpop_jkt }`: a single-use challenge the
/// caller answers with its passkey or hardware key. A hardware key names its
/// `did` and signs `device_message`; a passkey may name none, and is then
/// found from its credential when it answers.
pub(crate) async fn handle_challenge(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = first_param(params);
    let did = match p.get("did") {
        None | Some(Value::Null) => None,
        Some(_) => Some(str_param(&p, "did")?),
    };
    let jkt = str_param(&p, "dpop_jkt")?;
    let engine = node
        .auth_engine()
        .ok_or_else(|| refused("this node issues no access tokens"))?;
    let (id, challenge) = node.access().challenges.issue(did, jkt).map_err(refused)?;
    use base64::Engine as _;
    let mut answer = json!({
        "challenge_id": id,
        "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        "expires_in": CHALLENGE_TTL.as_secs(),
    });
    if let Some(did) = did {
        answer["device_message"] = json!(hex::encode(sign_in_message(
            &engine.config().issuer,
            did,
            jkt,
            &challenge
        )));
    }
    Ok(answer)
}

/// Verify a hardware-key answer: `public_key` (hex, the key `did` derives
/// from, one registered on it, or for a delegated agent the key a serving
/// machine holds for it under its Terms, `serving`) signed `message` (ECDSA
/// P-256 raw r||s over SHA-256 of the message, or Ed25519 over the message).
fn verify_device_answer(
    node: &TenzroNode,
    did: &str,
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    serving: bool,
) -> Result<(), String> {
    let derived = tenzro_identity::TenzroDid::from_device_key(public_key)
        .map(|d| d.to_string() == did)
        .unwrap_or(false);
    let registered = node
        .identity_registry()
        .and_then(|r| r.resolve(did).ok())
        .is_some_and(|id| id.public_keys.iter().any(|k| k.public_key == public_key));
    if !derived && !registered && !serving {
        return Err(format!("that key is not {did}'s"));
    }
    match public_key.len() {
        32 => {
            let key = ed25519_dalek::VerifyingKey::from_bytes(
                public_key.try_into().map_err(|_| "bad key")?,
            )
            .map_err(|e| format!("Ed25519 key: {e}"))?;
            let sig = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|e| format!("signature: {e}"))?;
            key.verify_strict(message, &sig)
                .map_err(|_| "the signature does not verify".to_string())
        }
        64 | 65 => {
            use p256::ecdsa::signature::Verifier;
            let mut sec1 = Vec::with_capacity(65);
            if public_key.len() == 64 {
                sec1.push(0x04);
            }
            sec1.extend_from_slice(public_key);
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| format!("P-256 key: {e}"))?;
            let sig = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|e| format!("signature: {e}"))?;
            key.verify(message, &sig)
                .map_err(|_| "the signature does not verify".to_string())
        }
        n => Err(format!("a {n}-byte key is neither Ed25519 nor P-256")),
    }
}

/// `tenzro_issueAccessToken { challenge_id, proof }`: answer a challenge and
/// receive an access token bound to the challenge's DPoP key.
///
/// `proof` is `{ kind: "passkey", account_address, credential_id,
/// authenticator_data, client_data_json, signature, ml_dsa_signature }`
/// (base64url, a `webauthn.get` over the challenge, with the ML-DSA-65 leg
/// over the challenge in hex) or `{ kind: "device", public_key,
/// signature }` (hex, over `device_message`). Optional `credentials` are KYA
/// credentials about the DID, which `credential` rules accept. Optional
/// `pairing_code` is the code of a pairing that is waiting: the token issued
/// on its strength redeems that code through `tenzro_pairDevice` and is
/// refused everywhere else.
///
/// A passkey proof may leave out `ml_dsa_signature` only to present a
/// pairing code or to sign in a paired device; the token a paired device gets
/// that way opens the paired-device calls and nothing else.
pub(crate) async fn handle_issue(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = first_param(params);
    let id = str_param(&p, "challenge_id")?;
    let proof = p.get("proof").ok_or_else(|| bad("Missing 'proof'"))?;
    let engine = node
        .auth_engine()
        .ok_or_else(|| refused("this node issues no access tokens"))?;
    let pending = node.access().challenges.take(id).map_err(refused)?;
    let (did, credential, passkey_only) = match str_param(proof, "kind")? {
        "passkey" => {
            let validator = node
                .webauthn_validator()
                .ok_or_else(|| refused("this node verifies no passkeys"))?;
            let registry = node
                .identity_registry()
                .ok_or_else(|| refused("no identity registry"))?;
            let account = proof.get("account_address").and_then(Value::as_str);
            let login = crate::mcp::oauth::PasskeyLogin {
                account_address: account.unwrap_or_default(),
                credential_id_b64: str_param(proof, "credential_id")?,
                authenticator_data_b64: str_param(proof, "authenticator_data")?,
                client_data_json_b64: str_param(proof, "client_data_json")?,
                signature_b64: str_param(proof, "signature")?,
                ml_dsa_signature_hex: proof.get("ml_dsa_signature").and_then(Value::as_str),
            };
            let active = |did: &str| {
                registry
                    .resolve(did)
                    .is_ok_and(|i| i.status == tenzro_identity::IdentityStatus::Active)
            };
            let pq_key = |did: &str| registry.resolve(did).ok().map(|i| i.pq_verifying_key);
            let (did, post_quantum) = match account {
                Some(_) => crate::mcp::oauth::verify_passkey_login_for_pairing(
                    validator,
                    &pending.challenge,
                    &login,
                    active,
                    |account| crate::mcp::oauth::registered_genesis_key(registry, account),
                    pq_key,
                ),
                // No account named: the node finds it from the credential.
                None => crate::mcp::oauth::verify_passkey_login_by_credential(
                    validator,
                    &pending.challenge,
                    node.http_surface().webauthn_rp_id(),
                    &login,
                    active,
                    pq_key,
                ),
            }
            .map_err(refused)?;
            if let Some(expected) = &pending.did
                && did != *expected
            {
                return Err(refused(format!(
                    "that passkey signs in {did}, not {expected}"
                )));
            }
            (did, crate::admin_audit::Credential::Passkey, !post_quantum)
        }
        "device" => {
            let did = pending.did.clone().ok_or_else(|| {
                bad("a hardware-key sign-in names its 'did' to tenzro_accessChallenge")
            })?;
            let key = hex::decode(str_param(proof, "public_key")?.trim_start_matches("0x"))
                .map_err(|_| bad("public_key is not hex"))?;
            let sig = hex::decode(str_param(proof, "signature")?.trim_start_matches("0x"))
                .map_err(|_| bad("signature is not hex"))?;
            let message = sign_in_message(
                &engine.config().issuer,
                &did,
                &pending.dpop_jkt,
                &pending.challenge,
            );
            // A delegated agent signs in on a machine that serves it, with that machine's key for it: the key its
            // approved Terms name for the machine. The token is then bound to the same key, as a delivered one is.
            let serving =
                crate::agent_delegation::is_serving_key(node, &did, &key, &pending.dpop_jkt);
            verify_device_answer(node, &did, &key, &sig, &message, serving).map_err(refused)?;
            let credential = if serving {
                crate::admin_audit::Credential::DelegatedAgentKey
            } else {
                crate::admin_audit::Credential::HardwareKey
            };
            (did, credential, false)
        }
        other => return Err(bad(format!("unknown proof kind '{other}'"))),
    };
    let pairing_code = match p.get("pairing_code") {
        None | Some(Value::Null) => None,
        Some(code) => Some(
            code.as_str()
                .ok_or_else(|| bad("'pairing_code' is the pairing code, as text"))?,
        ),
    };
    let grant = crate::pairing_rpc::sign_in_grant(node, &did, pairing_code, passkey_only)?;
    // A token is for a registered identity. A delegated agent signing in with
    // the key its Terms name for this machine is known by those Terms.
    let serving = grant.is_some()
        || matches!(
            credential,
            crate::admin_audit::Credential::DelegatedAgentKey
        );
    crate::identity_gate::edge_admits(node, "tenzro_issueAccessToken", Some(&did), serving)
        .map_err(refused)?;
    let purpose = crate::pairing_rpc::token_purpose(grant, passkey_only).map_err(refused)?;
    let chain = crate::rpc::chain_state_of(node);
    if let Some(chain) = &chain {
        tenzro_vm::native::check_agent_status(
            chain,
            &did,
            chrono::Utc::now().timestamp_millis().max(0) as u64,
        )
        .map_err(refused)?;
    }
    if let Some(vcs) = p.get("credentials").and_then(Value::as_array) {
        let roots = chain
            .as_ref()
            .map(|c| tenzro_vm::native::read_endorsement_roots(c))
            .unwrap_or_default();
        let mut held = Vec::new();
        for vc in vcs.iter().take(16) {
            let v = crate::kya_credential::verify(vc, chrono::Utc::now(), &roots)
                .map_err(|e| bad(format!("credential: {e}")))?;
            if v.subject != did {
                return Err(bad(format!("a credential names {}, not {did}", v.subject)));
            }
            let valid_until_ms = vc
                .get("validUntil")
                .and_then(Value::as_str)
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map_or(0, |t| t.timestamp_millis());
            held.push(HeldCredential {
                issuer: v.issuer,
                valid_until_ms,
            });
        }
        node.access().credentials.lock().insert(did.clone(), held);
    }
    let policy = node.access().policy();
    let caller = Caller {
        did: Some(did.clone()),
        ip: None,
    };
    let classes: Vec<&str> = tenzro_types::node_access::MethodClass::ALL
        .into_iter()
        .filter(|c| {
            purpose.is_none()
                && Surface::ALL.into_iter().any(|s| {
                    matches!(
                        evaluate(node, &policy, &caller, s, *c),
                        Decision::Allow { .. } | Decision::Pay { .. }
                    )
                })
        })
        .map(|c| c.as_str())
        .collect();
    let (token, expires_in) = if let Some(purpose) = purpose {
        // A token that only redeems a pairing code lasts no longer than a code.
        let ttl = if purpose == crate::pairing_rpc::REDEEM_PURPOSE {
            policy
                .token_ttl_secs
                .min(crate::pairing_rpc::CODE_TTL.as_secs())
        } else {
            policy.token_ttl_secs
        };
        let token = engine.issue_purpose_jwt(purpose, &did, &pending.dpop_jkt, Some(ttl));
        (token, ttl)
    } else {
        let token = engine.issue_jwt(
            &did,
            &did,
            &pending.dpop_jkt,
            tenzro_auth::AuthorizationDetails::empty(),
            Some(policy.token_ttl_secs),
        );
        (token, policy.token_ttl_secs)
    };
    let token = token.map_err(|e| refused(format!("token issuance failed: {e}")))?;
    crate::admin_audit::record_sign_in(
        node,
        &did,
        &token,
        &pending.dpop_jkt,
        credential,
        chrono::Utc::now().timestamp().max(0) as u64 + expires_in,
    )
    .await?;
    Ok(json!({
        "access_token": token,
        "token_type": "DPoP",
        "expires_in": expires_in,
        "did": did,
        "classes": classes,
        "jwk": engine.public_jwk(),
    }))
}

/// The operator check every access-management RPC shares: `caller` is the
/// DID the request's access token proved.
pub(crate) fn require_admin(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
) -> Result<String, JsonRpcError> {
    match caller {
        Some(did) if node.access().is_admin(node, did) => Ok(did.to_string()),
        Some(did) => Err(refused(format!(
            "{did} is not an administrator of this node"
        ))),
        None => Err(refused("sign in as this node's operator")),
    }
}

/// The check of an admin call the policy may also name other identities for:
/// the caller's DID, and whether it administers the node. A caller that does
/// not is admitted only when a rule for `method` names it.
pub(crate) fn admin_or_named(
    node: &Arc<TenzroNode>,
    method: &str,
    caller: Option<&str>,
) -> Result<(String, bool), JsonRpcError> {
    let did = caller.ok_or_else(|| refused("sign in as this node's operator"))?;
    if node.access().is_admin(node, did) {
        return Ok((did.to_string(), true));
    }
    let named = Caller {
        did: Some(did.to_string()),
        ip: None,
    };
    if named_for_method(node, &node.access().policy(), method, &named) {
        Ok((did.to_string(), false))
    } else {
        Err(refused(format!(
            "{did} is not an administrator of this node"
        )))
    }
}

/// `tenzro_revokeAccessToken { jti } | { did }`: withdraw one token, or
/// every live token of a DID.
pub(crate) async fn handle_revoke(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let by = require_admin(node, caller)?;
    let p = first_param(params);
    let engine = node
        .auth_engine()
        .ok_or_else(|| refused("this node issues no access tokens"))?;
    let reason = format!("withdrawn by {by}");
    let jtis: Vec<String> = match (
        p.get("jti").and_then(Value::as_str),
        p.get("did").and_then(Value::as_str),
    ) {
        (Some(jti), None) => vec![jti.to_string()],
        (None, Some(did)) => engine
            .live_tokens(chrono::Utc::now().timestamp() as u64)
            .map_err(|e| refused(e.to_string()))?
            .into_iter()
            .filter(|t| t.bearer_did == did)
            .map(|t| t.jti)
            .collect(),
        _ => return Err(bad("give exactly one of 'jti' or 'did'")),
    };
    for jti in &jtis {
        engine
            .revoke_token(jti, reason.clone())
            .map_err(|e| refused(e.to_string()))?;
    }
    Ok(json!({ "revoked": jtis }))
}

/// `tenzro_listAccessTokens`: the live tokens this node issued.
pub(crate) async fn handle_list(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    require_admin(node, caller)?;
    let engine = node
        .auth_engine()
        .ok_or_else(|| refused("this node issues no access tokens"))?;
    let tokens = engine
        .live_tokens(chrono::Utc::now().timestamp() as u64)
        .map_err(|e| refused(e.to_string()))?;
    Ok(json!({ "tokens": tokens }))
}

/// `tenzro_getAccessPolicy`: the policy in force, as data and as the file.
pub(crate) async fn handle_get_policy(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    require_admin(node, caller)?;
    let policy = node.access().policy();
    Ok(json!({
        "policy": *policy,
        "toml": render_policy(&policy).map_err(refused)?,
    }))
}

/// `tenzro_setAccessPolicy { policy } | { toml }`: replace the policy.
pub(crate) async fn handle_set_policy(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let by = require_admin(node, caller)?;
    let p = first_param(params);
    let policy: NodeAccessPolicy = match (p.get("policy"), p.get("toml").and_then(Value::as_str)) {
        (Some(v), None) => {
            serde_json::from_value(v.clone()).map_err(|e| bad(format!("policy: {e}")))?
        }
        (None, Some(text)) => toml::from_str(text).map_err(|e| bad(format!("toml: {e}")))?,
        _ => return Err(bad("give exactly one of 'policy' or 'toml'")),
    };
    let version = node.access().store().set(policy, &by).map_err(bad)?;
    Ok(json!({ "version": version }))
}

/// `tenzro_previewAccess { surface, method | class, did? }`: what the policy
/// would decide for a caller, without serving anything.
pub(crate) async fn handle_preview(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    require_admin(node, caller)?;
    let p = first_param(params);
    let surface =
        Surface::parse(str_param(&p, "surface")?).ok_or_else(|| bad("unknown surface"))?;
    let class = match (
        p.get("method").and_then(Value::as_str),
        p.get("class").and_then(Value::as_str),
    ) {
        (Some(m), None) => method_class(m),
        (None, Some(c)) => MethodClass::parse(c).ok_or_else(|| bad("unknown class"))?,
        _ => return Err(bad("give exactly one of 'method' or 'class'")),
    };
    let caller = Caller {
        did: p.get("did").and_then(Value::as_str).map(str::to_string),
        ip: None,
    };
    let policy = node.access().policy();
    let decision = match evaluate(node, &policy, &caller, surface, class) {
        Decision::Allow { tier, named } => {
            json!({ "decision": "allow", "tier": tier, "named": named })
        }
        Decision::Pay { via, price, asset } => {
            json!({ "decision": "pay", "via": via, "price": price, "asset": asset })
        }
        Decision::Refuse(why) => json!({ "decision": "refuse", "reason": why }),
    };
    Ok(
        json!({ "surface": surface.as_str(), "class": class.as_str(), "caller": caller.did, "result": decision }),
    )
}

/// The admin page's ticket file in the data directory.
pub const PAGE_TICKET_FILE: &str = "access-page.ticket";
/// How long a ticket opens the admin page.
pub const PAGE_TICKET_TTL: Duration = Duration::from_secs(15 * 60);
/// The header the admin page presents its ticket in.
pub const PAGE_TICKET_HEADER: &str = "x-tenzro-access-ticket";

/// Write a fresh admin-page ticket into `data_dir` and return it.
///
/// The page's authority is the same as the wizard's and the file's: whoever
/// can write the node's data directory administers its access policy. The
/// ticket is readable by the data directory's owner only and stops opening
/// the page after [`PAGE_TICKET_TTL`].
pub fn issue_page_ticket(data_dir: &Path) -> Result<String, String> {
    let ticket = hex::encode(rand::random::<[u8; 32]>());
    let path = data_dir.join(PAGE_TICKET_FILE);
    let tmp = path.with_extension("ticket.tmp");
    std::fs::write(&tmp, &ticket).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("protect {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("install {}: {e}", path.display()))?;
    Ok(ticket)
}

/// Whether `presented` is the live ticket in `data_dir`.
fn page_ticket_valid(data_dir: &Path, presented: &str) -> bool {
    let path = data_dir.join(PAGE_TICKET_FILE);
    let fresh = modified_at(&path)
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < PAGE_TICKET_TTL);
    let Ok(ticket) = std::fs::read_to_string(&path) else {
        return false;
    };
    use subtle::ConstantTimeEq as _;
    fresh
        && !presented.is_empty()
        && bool::from(ticket.trim().as_bytes().ct_eq(presented.as_bytes()))
}

/// The admin page's routes: `GET /access` (the page), `GET /access/policy`
/// and `PUT /access/policy` (the policy file, as TOML), and
/// `GET /access/connectivity` (what `tenzro-node doctor` reads). Loopback
/// peers with a live ticket only.
pub fn page_routes(node: Arc<TenzroNode>) -> axum::Router {
    use axum::routing::get;
    axum::Router::new()
        .route(
            "/access",
            get(|| async { axum::response::Html(ADMIN_PAGE) }),
        )
        .route("/access/policy", get(page_get_policy).put(page_put_policy))
        .route("/access/connectivity", get(page_get_connectivity))
        .route("/access/tpm", get(page_get_tpm))
        .with_state(node)
}

type PageReply = (axum::http::StatusCode, String);

fn page_admit(
    node: &TenzroNode,
    peer: std::net::SocketAddr,
    headers: &axum::http::HeaderMap,
) -> Result<(), PageReply> {
    use axum::http::StatusCode;
    if !peer.ip().is_loopback() {
        return Err((
            StatusCode::FORBIDDEN,
            "the admin page answers loopback callers only".to_string(),
        ));
    }
    let presented = headers
        .get(PAGE_TICKET_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !page_ticket_valid(&node.config().data_dir, presented) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "no live ticket: run `tenzro-node access --page` on this machine".to_string(),
        ));
    }
    Ok(())
}

/// `GET /access/connectivity`: how reachable the node is (its NAT, the
/// addresses peers see it at, its relays), as JSON. It names the node's
/// network addresses, so only the operator's own machine reads it.
async fn page_get_connectivity(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> PageReply {
    if let Err(reply) = page_admit(&node, peer, &headers) {
        return reply;
    }
    match (node.identity_transport.as_ref(), node.iroh_resolver()) {
        (Some(transport), Some(resolver)) => {
            match serde_json::to_string(&transport.connectivity(resolver.endpoint())) {
                Ok(json) => (axum::http::StatusCode::OK, json),
                Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            }
        }
        _ => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "the node's iroh endpoint is not up yet".to_string(),
        ),
    }
}

/// `GET /access/tpm`: how the TPM is answering (healthy, degraded or
/// stalled, with the counters behind it), as JSON.
async fn page_get_tpm(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> PageReply {
    if let Err(reply) = page_admit(&node, peer, &headers) {
        return reply;
    }
    match tenzro_device_key::tpm_health() {
        Some(h) => (axum::http::StatusCode::OK, h.to_string()),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            "this platform has no TPM backend".to_string(),
        ),
    }
}

async fn page_get_policy(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> PageReply {
    if let Err(reply) = page_admit(&node, peer, &headers) {
        return reply;
    }
    match render_policy(&node.access().policy()) {
        Ok(text) => (axum::http::StatusCode::OK, text),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn page_put_policy(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: String,
) -> PageReply {
    if let Err(reply) = page_admit(&node, peer, &headers) {
        return reply;
    }
    let policy = match parse_policy(&body) {
        Ok(p) => p,
        Err(e) => return (axum::http::StatusCode::BAD_REQUEST, e),
    };
    match node.access().store().set(policy, "admin page") {
        Ok(version) => (
            axum::http::StatusCode::OK,
            format!("version {version} in force"),
        ),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e),
    }
}

/// The admin page: edit `access.toml` in the browser, validated by the node
/// before it is written.
const ADMIN_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Node access</title>
<style>
:root{--bg:#fafaf8;--fg:#1a1a1a;--muted:#666;--line:#d8d8d4;--ok:#1d6b3a;--err:#a32020}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#ececec;--muted:#999;--line:#333;--ok:#6fcf8f;--err:#ff8a8a}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:880px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px}p{color:var(--muted);margin:0 0 16px}
textarea{box-sizing:border-box;width:100%;min-height:60vh;padding:12px;border:1px solid var(--line);border-radius:6px;background:transparent;color:var(--fg);font:13px/1.5 ui-monospace,monospace}
button{height:36px;padding:0 16px;border:0;border-radius:6px;background:var(--fg);color:var(--bg);font-weight:600;cursor:pointer;margin-top:12px}
#status{margin-left:12px;font-weight:600}.ok{color:var(--ok)}.err{color:var(--err)}
</style></head><body><main>
<h1>Node access</h1>
<p>The policy in this node's <code>access.toml</code>. Saving validates it, writes the file and applies it at once.</p>
<textarea id="policy" spellcheck="false"></textarea>
<div><button id="save">Save</button><span id="status"></span></div>
</main><script>
const ticket = location.hash.slice(1);
const status = document.getElementById("status");
const show = (text, ok) => { status.textContent = text; status.className = ok ? "ok" : "err"; };
async function load() {
  const r = await fetch("/access/policy", { headers: { "x-tenzro-access-ticket": ticket } });
  const text = await r.text();
  if (r.ok) document.getElementById("policy").value = text; else show(text, false);
}
document.getElementById("save").onclick = async () => {
  const r = await fetch("/access/policy", { method: "PUT", headers: { "x-tenzro-access-ticket": ticket }, body: document.getElementById("policy").value });
  show(await r.text(), r.ok);
  if (r.ok) load();
};
load();
</script></body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// The paths the HTTP routers in `rpc.rs` serve, read from its source
    /// with its test modules and comment lines left out, so a route named in
    /// a comment or a test string does not count as served.
    fn served_paths(source: &str) -> Vec<String> {
        let mut kept = String::new();
        let mut rest = source;
        // A test module runs from its `#[cfg(test)]` to the brace closing it
        // in the first column.
        while let Some(start) = rest.find("\n#[cfg(test)]") {
            kept.push_str(&rest[..start]);
            rest = rest[start..]
                .find("\n}\n")
                .map_or("", |end| &rest[start + end + 3..]);
        }
        kept.push_str(rest);
        let code: String = kept
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut out = Vec::new();
        let mut rest = code.as_str();
        while let Some(i) = rest.find(".route(") {
            rest = &rest[i + ".route(".len()..];
            let trimmed = rest.trim_start();
            if let Some(path) = trimmed.strip_prefix('"').and_then(|t| t.split('"').next()) {
                out.push(path.to_string());
            }
        }
        out
    }

    /// The paths served by the function `name` in `source`.
    fn served_by(source: &str, name: &str) -> Vec<String> {
        let start = source
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("rpc.rs has no fn {name}"));
        let body = &source[start..];
        served_paths(&body[..body.find("\n}\n").expect("the function ends")])
    }

    /// Every route prefix the access policy classes is one a router serves,
    /// and every route a paid router serves is classed for what it charges:
    /// a class named for a path nobody serves is dead, and a paid route that
    /// falls to the read class is gated as a read.
    #[test]
    fn every_classed_route_is_served_and_every_paid_route_is_classed() {
        let source = include_str!("rpc.rs");
        let served = served_paths(source);
        for prefix in MEDIA_ROUTES.iter().chain(INFERENCE_ROUTES) {
            assert!(
                served.iter().any(|p| p.starts_with(prefix)),
                "{prefix} is classed but no router serves it"
            );
        }
        for router in [
            "paid_json_routes",
            "paid_media_routes",
            "paid_audio_routes",
            "realtime_routes",
        ] {
            let paths = served_by(source, router);
            assert!(!paths.is_empty(), "{router} serves no route");
            for path in paths {
                assert_ne!(
                    route_class(&path),
                    MethodClass::Read,
                    "{path} from {router} is a paid route classed as a read"
                );
            }
        }
    }
    use tenzro_types::node_access::{SurfaceRule, TierDef};

    #[test]
    fn methods_fall_into_the_classes_their_surfaces_serve() {
        assert_eq!(method_class("tenzro_chat"), MethodClass::Inference);
        assert_eq!(method_class("tenzro_mediaGen_render"), MethodClass::Media);
        assert_eq!(method_class("tenzro_storageStatus"), MethodClass::Storage);
        assert_eq!(method_class("tenzro_getBalance"), MethodClass::Read);
        assert_eq!(method_class("tenzro_queryEvents"), MethodClass::Index);
        // The HTTP inference routes the RPC server serves.
        for path in [
            "/v1/chat/completions",
            "/v1/responses",
            "/v1/embeddings",
            "/tenzro/rerank",
            "/tenzro/forecasts",
        ] {
            assert_eq!(route_class(path), MethodClass::Inference, "{path}");
        }
    }

    #[test]
    fn the_store_writes_atomically_bumps_the_version_logs_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let store = AccessPolicyStore::open(dir.path()).unwrap();
        assert_eq!(store.policy().version, 0);
        let mut p = NodeAccessPolicy::default();
        p.rules.push(SurfaceRule {
            surface: Some(Surface::Openai),
            class: MethodClass::Inference,
            rule: Rule::Closed,
        });
        assert_eq!(store.set(p.clone(), "did:tenzro:human:op").unwrap(), 1);
        let reopened = AccessPolicyStore::open(dir.path()).unwrap();
        assert_eq!(reopened.policy().version, 1);
        assert_eq!(
            reopened
                .policy()
                .rule_for(Surface::Openai, MethodClass::Inference),
            &Rule::Closed
        );
        let log = std::fs::read_to_string(dir.path().join(POLICY_LOG)).unwrap();
        assert!(log.contains("\"version\":1"));
    }

    #[test]
    fn an_edit_on_disk_applies_and_an_invalid_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = AccessPolicyStore::open(dir.path()).unwrap();
        let p = NodeAccessPolicy {
            version: 7,
            default_rule: Rule::Closed,
            ..Default::default()
        };
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(dir.path().join(POLICY_FILE), render_policy(&p).unwrap()).unwrap();
        store.reload_if_changed();
        assert_eq!(store.policy().version, 7);
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(
            dir.path().join(POLICY_FILE),
            "default_rule = { rule = \"tier\", name = \"gold\" }",
        )
        .unwrap();
        store.reload_if_changed();
        assert_eq!(
            store.policy().version,
            7,
            "an invalid edit keeps the policy in force"
        );
    }

    #[test]
    fn an_org_admits_what_is_delegated_under_it_whatever_its_root() {
        for root in ["did:tenzro:human:aa", "did:tenzro:machine:aa"] {
            let orgs = vec![root.to_string()];
            assert!(in_orgs(&orgs, root));
            assert!(in_orgs(&orgs, "did:tenzro:machine:aa:bot"), "{root}");
            assert!(!in_orgs(&orgs, "did:tenzro:machine:bb:bot"), "{root}");
            assert!(!in_orgs(&orgs, "did:tenzro:machine:aa:bot:x"), "{root}");
        }
        // Before, a machine root's agents read as a human's of the same id.
        let machine = vec!["did:tenzro:machine:aa".to_string()];
        assert!(in_orgs(&machine, "did:tenzro:machine:aa:bot"));
    }

    #[test]
    fn the_file_and_the_rpc_form_store_identical_policies() {
        let p = NodeAccessPolicy {
            default_rule: Rule::Any {
                rules: vec![
                    Rule::Allow {
                        dids: vec!["did:tenzro:human:a".into()],
                        orgs: vec![],
                    },
                    Rule::Tier {
                        name: "standard".into(),
                    },
                ],
            },
            ..Default::default()
        };
        let via_file = parse_policy(&render_policy(&p).unwrap()).unwrap();
        let via_json: NodeAccessPolicy =
            serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
        assert_eq!(
            render_policy(&via_file).unwrap(),
            render_policy(&via_json).unwrap()
        );
    }

    #[test]
    fn a_tier_holds_each_caller_to_its_rate_and_quota() {
        let p = NodeAccessPolicy {
            tiers: vec![TierDef {
                name: "tiny".into(),
                rate_per_minute: 60,
                burst: 2,
                quota_per_period: 3,
                period_secs: 3600,
            }],
            ..Default::default()
        };
        // A fixed clock: how fast the machine runs the test changes nothing.
        let t0 = std::time::Instant::now();
        let at = |ms: u64| t0 + std::time::Duration::from_millis(ms);
        let m = TierMeter::default();
        let charge = |who: &str, ms: u64, epoch: u64| m.charge_at(&p, "tiny", who, at(ms), epoch);
        assert!(charge("a", 0, 1_000).is_ok());
        assert!(charge("a", 0, 1_000).is_ok());
        let slow = charge("a", 999, 1_000).unwrap_err();
        assert!(slow.contains("60 requests a minute"), "burst of 2: {slow}");
        assert!(charge("b", 999, 1_000).is_ok(), "per caller");
        // One request a second refills one token, and the quota of 3 binds.
        assert!(charge("a", 2_000, 1_002).is_ok());
        let used = charge("a", 4_000, 1_004).unwrap_err();
        assert!(used.contains("quota of 3"), "{used}");
        // A new period opens the quota again.
        assert!(charge("a", 6_000, 1_000 + 3_600).is_ok());
    }

    #[test]
    fn the_sign_in_message_opens_with_its_tenzro_domain() {
        // A key holder signs a TPM key only over a message whose first
        // length-prefixed field begins with `tenzro/`.
        let m = sign_in_message("http://n", "did:a", "jkt", &[7u8; 32]);
        let domain = b"tenzro/access/sign-in";
        assert_eq!(&m[..4], &(domain.len() as u32).to_be_bytes());
        assert!(m[4..].starts_with(domain));
    }

    #[test]
    fn the_sign_in_message_binds_every_part() {
        let c = [7u8; 32];
        let d = sign_in_message("http://n", "did:a", "jkt", &c);
        assert_ne!(d, sign_in_message("http://m", "did:a", "jkt", &c));
        assert_ne!(d, sign_in_message("http://n", "did:b", "jkt", &c));
        assert_ne!(d, sign_in_message("http://n", "did:a", "jkt2", &c));
        assert_ne!(d, sign_in_message("http://n", "did:a", "jkt", &[8u8; 32]));
    }
}
