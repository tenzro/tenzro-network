//! AP2 (Agent Payments Protocol) v0.2 mandates, checked against the paying
//! agent's consensus Terms.
//!
//! AP2 mandates are SD-JWT VCs (`dc+sd-jwt`, ES256) told apart by `vct`:
//!
//! | `vct` | Mandate |
//! | --- | --- |
//! | `mandate.checkout.1` | closed Checkout Mandate: one merchant-signed checkout |
//! | `mandate.payment.1` | closed Payment Mandate: one payment for that checkout |
//! | `mandate.payment.open.1` | open Payment Mandate: constraints plus the agent key (`cnf`) |
//!
//! A mandate never grants authority. The paying agent's Terms decide every
//! payment; a mandate can only narrow what the Terms already allow, and a
//! payment that passes its mandates still has to pass the Terms. Nothing is
//! stored: constraints that can only be enforced by remembering earlier
//! payments (`payment.budget`, `payment.agent_recurrence`) are refused, and
//! the agent's root expresses them as the Terms' period limits instead.
//!
//! Who signs what:
//!
//! - the merchant signs the checkout (`checkout_jwt`, ES256); the closed
//!   Payment Mandate's `transaction_id` is the hash of that JWT;
//! - the closed Payment Mandate is signed by the agent's controller (the
//!   `controller_did` of its Terms), or, when an open Payment Mandate the
//!   controller signed is presented beside it, by the agent key that open
//!   mandate names in `cnf`;
//! - the open Payment Mandate is signed by the controller.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{PaymentError, Result};
use crate::terms_gate::{PaymentIntent, TermsGate};

/// The AP2 version these mandates follow.
pub const AP2_VERSION: &str = "0.2";
/// Protocol name the Terms check sees for an AP2 payment.
pub const AP2_PROTOCOL: &str = "ap2";
/// x402 payload `extensions` key carrying an [`Ap2Presentation`].
pub const AP2_EXTENSION_KEY: &str = "ap2";
/// AP2's A2A extension URI.
pub const AP2_A2A_EXTENSION_URI: &str = "https://github.com/google-agentic-commerce/ap2/v1";

/// `vct` of a closed Checkout Mandate.
pub const VCT_CHECKOUT: &str = "mandate.checkout.1";
/// `vct` of a closed Payment Mandate.
pub const VCT_PAYMENT: &str = "mandate.payment.1";
/// `vct` of an open Payment Mandate.
pub const VCT_PAYMENT_OPEN: &str = "mandate.payment.open.1";

fn refuse(msg: impl Into<String>) -> PaymentError {
    PaymentError::VerificationFailed(format!("ap2: {}", msg.into()))
}

fn b64_json(part: &str) -> Result<Value> {
    let bytes = B64
        .decode(part)
        .map_err(|e| refuse(format!("base64url: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| refuse(format!("json: {e}")))
}

/// base64url of the SHA-256 of `data`, as AP2 and SD-JWT hash.
pub fn b64_sha256(data: &[u8]) -> String {
    B64.encode(Sha256::digest(data))
}

/// A P-256 key from a JWK (`kty` `EC`, `crv` `P-256`).
pub fn key_from_jwk(jwk: &Value) -> Result<VerifyingKey> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err(refuse("only P-256 keys are accepted"));
    }
    let coord = |name: &str| -> Result<Vec<u8>> {
        let s = jwk
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| refuse(format!("jwk has no {name}")))?;
        let b = B64
            .decode(s)
            .map_err(|e| refuse(format!("jwk {name}: {e}")))?;
        if b.len() != 32 {
            return Err(refuse(format!("jwk {name} is not 32 bytes")));
        }
        Ok(b)
    };
    let mut sec1 = vec![0x04];
    sec1.extend(coord("x")?);
    sec1.extend(coord("y")?);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| refuse(format!("jwk: {e}")))
}

/// A compact JWS whose ES256 signature verified.
#[derive(Debug, Clone)]
struct Jws {
    header: Value,
    claims: Value,
}

/// Parse a compact JWS and check its ES256 signature with `key`, or with the
/// key its header carries when `key` is `None` (the caller then checks who
/// that key belongs to).
fn verify_jws(compact: &str, key: Option<&VerifyingKey>) -> Result<(Jws, VerifyingKey)> {
    let mut parts = compact.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(refuse("not a compact JWS"));
    };
    let header = b64_json(h)?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(refuse("only ES256 is accepted"));
    }
    let key = match key {
        Some(k) => *k,
        None => key_from_jwk(
            header
                .get("jwk")
                .ok_or_else(|| refuse("the JWS names no key"))?,
        )?,
    };
    let sig = B64
        .decode(s)
        .map_err(|e| refuse(format!("signature: {e}")))?;
    let sig = Signature::from_slice(&sig).map_err(|e| refuse(format!("signature: {e}")))?;
    key.verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| refuse("signature does not verify"))?;
    Ok((
        Jws {
            header,
            claims: b64_json(p)?,
        },
        key,
    ))
}

/// Replace every selectively disclosed digest in `value` by its disclosure.
fn disclose(value: &mut Value, disclosures: &HashMap<String, Value>) -> Result<()> {
    match value {
        Value::Object(map) => {
            if let Some(sd) = map.remove("_sd") {
                for digest in sd.as_array().into_iter().flatten() {
                    let Some(d) = digest.as_str().and_then(|d| disclosures.get(d)) else {
                        continue;
                    };
                    let (Some(name), Some(v)) =
                        (d.get(1).and_then(Value::as_str), d.get(2).cloned())
                    else {
                        return Err(refuse("an object disclosure is [salt, name, value]"));
                    };
                    if map.insert(name.to_string(), v).is_some() {
                        return Err(refuse(format!("claim {name} is disclosed twice")));
                    }
                }
            }
            map.remove("_sd_alg");
            for v in map.values_mut() {
                disclose(v, disclosures)?;
            }
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for mut item in items.drain(..) {
                let digest = item
                    .as_object()
                    .filter(|o| o.len() == 1)
                    .and_then(|o| o.get("..."))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                match digest {
                    Some(d) => {
                        if let Some(disc) = disclosures.get(&d) {
                            let mut v = disc
                                .get(1)
                                .cloned()
                                .ok_or_else(|| refuse("an array disclosure is [salt, value]"))?;
                            disclose(&mut v, disclosures)?;
                            out.push(v);
                        }
                    }
                    None => {
                        disclose(&mut item, disclosures)?;
                        out.push(item);
                    }
                }
            }
            *items = out;
        }
        _ => {}
    }
    Ok(())
}

/// An SD-JWT whose issuer signature verified, with its disclosed claims.
#[derive(Debug, Clone)]
pub struct VerifiedSdJwt {
    /// The claims after every presented disclosure is applied.
    pub claims: Value,
    /// The key the issuer signed with.
    pub issuer_key: VerifyingKey,
    /// The issuer JWT's `iss`, when it names one.
    pub iss: Option<String>,
}

/// Verify an SD-JWT (`<issuer-jwt>~<disclosure>~...~[<kb-jwt>]`) and apply
/// its disclosures. The issuer key is taken from the issuer JWT's header and
/// returned for the caller to attribute. A key-binding JWT, when present,
/// must be signed by the key in `cnf` and cover this exact presentation.
pub fn verify_sd_jwt(presentation: &str) -> Result<VerifiedSdJwt> {
    let parts: Vec<&str> = presentation.split('~').collect();
    if parts.len() < 2 {
        return Err(refuse("not an SD-JWT"));
    }
    let (issuer_jwt, rest) = (parts[0], &parts[1..]);
    let (kb, disclosures) = match rest.split_last() {
        Some((last, ds)) if !last.is_empty() => (Some(*last), ds),
        Some((_, ds)) => (None, ds),
        None => (None, rest),
    };
    let (jws, issuer_key) = verify_jws(issuer_jwt, None)?;
    if let Some(alg) = jws.claims.get("_sd_alg").and_then(Value::as_str)
        && alg != "sha-256"
    {
        return Err(refuse(format!("_sd_alg {alg} is not supported")));
    }
    let mut map = HashMap::new();
    for d in disclosures.iter().filter(|d| !d.is_empty()) {
        if map.insert(b64_sha256(d.as_bytes()), b64_json(d)?).is_some() {
            return Err(refuse("a disclosure is presented twice"));
        }
    }
    // Every presented disclosure must be referenced by the signed claims
    // or by another disclosure; a stray one is refused, not ignored.
    let referenced = format!(
        "{}{}",
        jws.claims,
        map.values().map(Value::to_string).collect::<String>()
    );
    if let Some(stray) = map.keys().find(|d| !referenced.contains(d.as_str())) {
        return Err(refuse(format!("disclosure {stray} is not referenced")));
    }
    let mut claims = jws.claims.clone();
    disclose(&mut claims, &map)?;

    if let Some(kb) = kb {
        let holder = key_from_jwk(
            claims
                .pointer("/cnf/jwk")
                .ok_or_else(|| refuse("a key-binding JWT needs cnf.jwk"))?,
        )?;
        let (kb, _) = verify_jws(kb, Some(&holder))?;
        if kb.header.get("typ").and_then(Value::as_str) != Some("kb+jwt") {
            return Err(refuse("the key-binding JWT is not typ kb+jwt"));
        }
        let presented = &presentation[..presentation.len() - kb_len(presentation)];
        if kb.claims.get("sd_hash").and_then(Value::as_str)
            != Some(b64_sha256(presented.as_bytes()).as_str())
        {
            return Err(refuse("the key-binding JWT covers another presentation"));
        }
    }
    Ok(VerifiedSdJwt {
        iss: claims
            .get("iss")
            .and_then(Value::as_str)
            .map(str::to_string),
        claims,
        issuer_key,
    })
}

fn kb_len(presentation: &str) -> usize {
    presentation.rsplit('~').next().map(str::len).unwrap_or(0)
}

/// The AP2 mandates presented for one payment.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ap2Presentation {
    /// The merchant-signed checkout JWT the payment is for.
    pub checkout_jwt: String,
    /// The closed Payment Mandate (SD-JWT).
    pub payment_mandate: String,
    /// The open Payment Mandate (SD-JWT) whose `cnf` key signed the closed
    /// one, in human-not-present flows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_payment_mandate: Option<String>,
}

/// The payment the mandates must cover.
#[derive(Debug, Clone, Copy)]
pub struct ProposedPayment<'a> {
    /// The paying agent's DID.
    pub agent_did: &'a str,
    /// The payee as the mandate names it (`payee.id`).
    pub payee: &'a str,
    /// Amount in the currency's minor units, as AP2 states amounts.
    pub amount: u128,
    /// Currency or asset code.
    pub currency: &'a str,
    /// The chain the payment settles on, for the Terms check.
    pub chain: &'a str,
}

/// What the verifier reads about identities.
pub trait MandateKeys: Send + Sync {
    /// The controller (root) DID the agent's Terms name, if it has Terms.
    fn controller_of(&self, agent_did: &str) -> Option<String>;
    /// Whether `did` lists `key` for authentication or assertion.
    fn did_lists_key(&self, did: &str, key: &VerifyingKey) -> Result<bool>;
}

/// What a verified presentation established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMandates {
    /// The checkout the payment is for (`transaction_id`).
    pub transaction_id: String,
    /// The DID that authorized the closed Payment Mandate.
    pub authorized_by: String,
    /// The payment instrument the mandate names.
    pub instrument: Option<String>,
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn check_time(claims: &Value, now: i64, what: &str) -> Result<()> {
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64)
        && now >= exp
    {
        return Err(refuse(format!("the {what} expired")));
    }
    if let Some(iat) = claims.get("iat").and_then(Value::as_i64)
        && iat > now + 300
    {
        return Err(refuse(format!("the {what} is issued in the future")));
    }
    Ok(())
}

fn amount_of(v: &Value) -> Option<u128> {
    match v {
        Value::Number(n) => n.as_u64().map(u128::from),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn matches_payee(allowed: &Value, payee: &str) -> bool {
    allowed.as_array().is_some_and(|list| {
        list.iter().any(|p| {
            p.as_str() == Some(payee) || p.get("id").and_then(Value::as_str) == Some(payee)
        })
    })
}

/// Check the open Payment Mandate's constraints against the payment. Every
/// constraint is checked or refused; none is skipped.
fn check_constraints(
    constraints: &Value,
    pay: &ProposedPayment<'_>,
    transaction_id: &str,
    instrument: Option<&Value>,
    now: i64,
) -> Result<()> {
    let list = constraints
        .as_array()
        .ok_or_else(|| refuse("constraints is not a list"))?;
    let mut referenced = false;
    for c in list {
        let ty = c.get("type").and_then(Value::as_str).unwrap_or_default();
        match ty {
            "payment.reference" => {
                if c.get("conditional_transaction_id").and_then(Value::as_str)
                    != Some(transaction_id)
                {
                    return Err(refuse("the open mandate references another checkout"));
                }
                referenced = true;
            }
            "payment.amount_range" => {
                let cur = c
                    .get("currency")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !cur.eq_ignore_ascii_case(pay.currency) {
                    return Err(refuse("the amount range is in another currency"));
                }
                let max = c
                    .get("max")
                    .and_then(amount_of)
                    .ok_or_else(|| refuse("amount_range.max"))?;
                let min = c.get("min").and_then(amount_of).unwrap_or(0);
                if pay.amount < min || pay.amount > max {
                    return Err(refuse("the amount is outside the mandate's range"));
                }
            }
            "payment.allowed_payees" => {
                if !matches_payee(c.get("allowed").unwrap_or(&Value::Null), pay.payee) {
                    return Err(refuse("the payee is not one the mandate allows"));
                }
            }
            "payment.allowed_payment_instruments" => {
                let allowed = c.get("allowed").and_then(Value::as_array);
                let ok = match (allowed, instrument) {
                    (Some(list), Some(inst)) => list.iter().any(|a| {
                        a == inst
                            || (a.get("id").is_some() && a.get("id") == inst.get("id"))
                            || (a.as_str().is_some()
                                && a.as_str() == inst.get("type").and_then(Value::as_str))
                    }),
                    _ => false,
                };
                if !ok {
                    return Err(refuse(
                        "the payment instrument is not one the mandate allows",
                    ));
                }
            }
            "payment.allowed_pisps" => {
                // A payment on this network is initiated by no PISP; the
                // constraint only narrows card and bank initiation.
            }
            "payment.execution_date" => {
                let parse = |k: &str| {
                    c.get(k)
                        .and_then(Value::as_str)
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|d| d.timestamp())
                };
                if parse("not_before").is_some_and(|t| now < t)
                    || parse("not_after").is_some_and(|t| now > t)
                {
                    return Err(refuse(
                        "the payment is outside the mandate's execution dates",
                    ));
                }
            }
            "payment.budget" | "payment.agent_recurrence" => {
                return Err(refuse(format!(
                    "{ty} needs a record of earlier payments; express it as a period limit \
                     in the agent's Terms"
                )));
            }
            other => return Err(refuse(format!("unknown constraint {other}"))),
        }
    }
    if !referenced {
        return Err(refuse(
            "an open Payment Mandate must contain payment.reference",
        ));
    }
    Ok(())
}

/// Verify `presented` for `pay`, then hold the payment to the agent's Terms.
///
/// Checks, in order: the checkout JWT's signature (by the merchant key,
/// when `merchant_key` is given); the closed Payment Mandate's `vct`,
/// signature, expiry, `transaction_id`, payee, amount and currency; who
/// signed it (the agent's controller, or the open mandate's `cnf` key); the
/// open mandate's signature by the controller and its constraints; and
/// finally the payment against the agent's Terms through `terms`.
pub fn verify(
    presented: &Ap2Presentation,
    pay: &ProposedPayment<'_>,
    merchant_key: Option<&VerifyingKey>,
    keys: &dyn MandateKeys,
    terms: &dyn TermsGate,
) -> Result<VerifiedMandates> {
    let now = now_secs();
    let (checkout, _) = verify_jws(&presented.checkout_jwt, merchant_key)?;
    check_time(&checkout.claims, now, "checkout")?;
    let transaction_id = b64_sha256(presented.checkout_jwt.as_bytes());

    let closed = verify_sd_jwt(&presented.payment_mandate)?;
    let c = &closed.claims;
    if c.get("vct").and_then(Value::as_str) != Some(VCT_PAYMENT) {
        return Err(refuse(format!(
            "the payment mandate's vct is not {VCT_PAYMENT}"
        )));
    }
    check_time(c, now, "payment mandate")?;
    if c.get("transaction_id").and_then(Value::as_str) != Some(transaction_id.as_str()) {
        return Err(refuse("the payment mandate is for another checkout"));
    }
    if c.pointer("/payee/id").and_then(Value::as_str) != Some(pay.payee) {
        return Err(refuse("the payment mandate pays another payee"));
    }
    let amount = c
        .pointer("/payment_amount/amount")
        .and_then(amount_of)
        .ok_or_else(|| refuse("the payment mandate states no amount"))?;
    let currency = c
        .pointer("/payment_amount/currency")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if amount != pay.amount || !currency.eq_ignore_ascii_case(pay.currency) {
        return Err(refuse(
            "the payment mandate states another amount or currency",
        ));
    }
    let instrument = c.get("payment_instrument");

    let controller = keys
        .controller_of(pay.agent_did)
        .ok_or_else(|| refuse("the paying agent holds no Terms"))?;
    let controller_signed = |key: &VerifyingKey| keys.did_lists_key(&controller, key);

    let authorized_by = match &presented.open_payment_mandate {
        None => {
            if !controller_signed(&closed.issuer_key)? {
                return Err(refuse(
                    "the payment mandate is not signed by the agent's controller",
                ));
            }
            controller.clone()
        }
        Some(open) => {
            let open = verify_sd_jwt(open)?;
            let o = &open.claims;
            if o.get("vct").and_then(Value::as_str) != Some(VCT_PAYMENT_OPEN) {
                return Err(refuse(format!(
                    "the open mandate's vct is not {VCT_PAYMENT_OPEN}"
                )));
            }
            check_time(o, now, "open payment mandate")?;
            if !controller_signed(&open.issuer_key)? {
                return Err(refuse(
                    "the open mandate is not signed by the agent's controller",
                ));
            }
            let agent_key = key_from_jwk(
                o.pointer("/cnf/jwk")
                    .ok_or_else(|| refuse("the open mandate names no agent key"))?,
            )?;
            if closed.issuer_key != agent_key && !controller_signed(&closed.issuer_key)? {
                return Err(refuse(
                    "the payment mandate is signed by neither the controller nor the agent key \
                     the open mandate names",
                ));
            }
            if !keys.did_lists_key(pay.agent_did, &agent_key)? {
                return Err(refuse(
                    "the open mandate's agent key is not the paying agent's",
                ));
            }
            check_constraints(
                o.get("constraints").unwrap_or(&Value::Null),
                pay,
                &transaction_id,
                instrument,
                now,
            )?;
            controller.clone()
        }
    };

    terms.authorize(&PaymentIntent {
        payer_did: pay.agent_did,
        amount: pay.amount,
        operation: "payment",
        protocol: Some(AP2_PROTOCOL),
        chain: Some(pay.chain),
        counterparty: Some(pay.payee),
    })?;

    Ok(VerifiedMandates {
        transaction_id,
        authorized_by,
        instrument: instrument
            .and_then(|i| i.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// Read an [`Ap2Presentation`] from x402 payload `extensions`, if present.
pub fn presentation_in(extensions: Option<&Value>) -> Result<Option<Ap2Presentation>> {
    match extensions.and_then(|e| e.get(AP2_EXTENSION_KEY)) {
        None => Ok(None),
        Some(v) => serde_json::from_value(v.clone())
            .map(Some)
            .map_err(|e| refuse(format!("extensions.ap2: {e}"))),
    }
}

/// Whether the identity registry lists `key` for `did` (authentication or
/// assertion), as `x || y` or in compressed or uncompressed SEC1 form. A node's
/// [`MandateKeys`] answers `did_lists_key` with this.
pub fn identity_lists_key(
    registry: &tenzro_identity::IdentityRegistry,
    did: &str,
    key: &VerifyingKey,
) -> Result<bool> {
    use subtle::ConstantTimeEq;
    let identity = registry
        .resolve(did)
        .map_err(|e| PaymentError::IdentityError(format!("{did}: {e}")))?;
    if !identity.is_active() {
        return Err(PaymentError::IdentityError(format!("{did} is not active")));
    }
    // Identities created from a passkey or hardware key record it as
    // `x || y`; others as SEC1.
    let uncompressed = key.to_sec1_point(false).as_bytes().to_vec();
    let forms = [
        uncompressed[1..].to_vec(),
        key.to_sec1_point(true).as_bytes().to_vec(),
        uncompressed,
    ];
    Ok(identity
        .public_keys
        .iter()
        .filter(|k| {
            k.purposes
                .contains(&tenzro_identity::KeyPurpose::Authentication)
                || k.purposes
                    .contains(&tenzro_identity::KeyPurpose::AssertionMethod)
        })
        .any(|k| {
            forms.iter().any(|f| {
                k.public_key.len() == f.len() && bool::from(k.public_key.as_slice().ct_eq(f))
            })
        }))
}

/// Build a compact ES256 JWS. Used by tests and by a node signing its own
/// checkout JWTs.
pub fn sign_jws(
    header: &Map<String, Value>,
    claims: &Value,
    sign: impl FnOnce(&[u8]) -> Signature,
) -> String {
    let h = B64.encode(serde_json::to_vec(header).unwrap_or_default());
    let p = B64.encode(serde_json::to_vec(claims).unwrap_or_default());
    let sig = sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", B64.encode(sig.to_bytes()))
}

/// The JWK of a P-256 key.
pub fn jwk_of(key: &VerifyingKey) -> Value {
    let point = key.to_sec1_point(false);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": B64.encode(point.x().map(|x| x.to_vec()).unwrap_or_default()),
        "y": B64.encode(point.y().map(|y| y.to_vec()).unwrap_or_default()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use parking_lot::Mutex;

    const AGENT: &str = "did:tenzro:machine:agent";
    const ROOT: &str = "did:tenzro:human:root";
    const PAYEE: &str = "did:tenzro:machine:seller";

    fn key() -> SigningKey {
        use ::p256::elliptic_curve::Generate;
        use getrandom_0_4::{SysRng, rand_core::UnwrapErr};
        SigningKey::generate_from_rng(&mut UnwrapErr(SysRng))
    }

    fn jws(k: &SigningKey, claims: Value) -> String {
        let mut h = Map::new();
        h.insert("alg".into(), "ES256".into());
        h.insert("jwk".into(), jwk_of(k.verifying_key()));
        sign_jws(&h, &claims, |m| k.sign(m))
    }

    /// An SD-JWT with every top-level claim but `vct` selectively disclosed.
    fn sd_jwt(k: &SigningKey, claims: Value, kb: Option<&SigningKey>) -> String {
        let mut digests = Vec::new();
        let mut discs = Vec::new();
        let mut body = Map::new();
        for (name, v) in claims.as_object().unwrap() {
            if name == "vct" || name == "cnf" {
                body.insert(name.clone(), v.clone());
                continue;
            }
            let d = B64.encode(serde_json::to_vec(&serde_json::json!(["salt", name, v])).unwrap());
            digests.push(Value::String(b64_sha256(d.as_bytes())));
            discs.push(d);
        }
        body.insert("_sd".into(), Value::Array(digests));
        body.insert("_sd_alg".into(), "sha-256".into());
        let mut out = jws(k, Value::Object(body));
        for d in discs {
            out.push('~');
            out.push_str(&d);
        }
        out.push('~');
        if let Some(holder) = kb {
            let mut h = Map::new();
            h.insert("alg".into(), "ES256".into());
            h.insert("typ".into(), "kb+jwt".into());
            let claims = serde_json::json!({
                "iat": now_secs(), "aud": PAYEE, "nonce": "n",
                "sd_hash": b64_sha256(out.as_bytes()),
            });
            out.push_str(&sign_jws(&h, &claims, |m| holder.sign(m)));
        }
        out
    }

    struct Keys {
        root: VerifyingKey,
        agent: VerifyingKey,
    }
    impl MandateKeys for Keys {
        fn controller_of(&self, agent_did: &str) -> Option<String> {
            (agent_did == AGENT).then(|| ROOT.to_string())
        }
        fn did_lists_key(&self, did: &str, key: &VerifyingKey) -> Result<bool> {
            Ok((did == ROOT && *key == self.root) || (did == AGENT && *key == self.agent))
        }
    }

    /// Terms allowing at most `0` per payment; records what it was asked.
    struct Terms(u128, Mutex<Vec<(String, u128)>>);
    impl TermsGate for Terms {
        fn authorize(&self, i: &PaymentIntent<'_>) -> Result<()> {
            self.1
                .lock()
                .push((i.protocol.unwrap_or("").to_string(), i.amount));
            if i.amount > self.0 {
                return Err(PaymentError::VerificationFailed(
                    "over the Terms limit".into(),
                ));
            }
            Ok(())
        }
    }

    struct World {
        root: SigningKey,
        agent: SigningKey,
        merchant: SigningKey,
        checkout: String,
    }

    fn world() -> World {
        let merchant = key();
        let checkout = jws(
            &merchant,
            serde_json::json!({"id": "chk_1", "line_items": [{"id": "inference", "quantity": 1}],
                               "exp": now_secs() + 600}),
        );
        World {
            root: key(),
            agent: key(),
            merchant,
            checkout,
        }
    }

    fn keys(w: &World) -> Keys {
        Keys {
            root: *w.root.verifying_key(),
            agent: *w.agent.verifying_key(),
        }
    }

    fn closed(w: &World, signer: &SigningKey, amount: u64) -> String {
        sd_jwt(
            signer,
            serde_json::json!({
                "vct": VCT_PAYMENT,
                "transaction_id": b64_sha256(w.checkout.as_bytes()),
                "payee": {"id": PAYEE, "name": "seller"},
                "payment_amount": {"amount": amount, "currency": "TNZO"},
                "payment_instrument": {"id": "tenzro-wallet", "type": "tenzro"},
                "exp": now_secs() + 600,
            }),
            None,
        )
    }

    fn open(w: &World, constraints: Value) -> String {
        sd_jwt(
            &w.root,
            serde_json::json!({
                "vct": VCT_PAYMENT_OPEN,
                "cnf": {"jwk": jwk_of(w.agent.verifying_key())},
                "constraints": constraints,
                "exp": now_secs() + 600,
            }),
            Some(&w.agent),
        )
    }

    /// A controller onboarded from its passkey lists the key as `x || y`,
    /// the form the registry records passkey and hardware keys in; a
    /// mandate it signed is attributed to it.
    #[test]
    fn a_key_the_registry_records_as_x_y_is_listed() {
        let k = key();
        let point = k.verifying_key().to_sec1_point(false);
        let registry = tenzro_identity::IdentityRegistry::new();
        registry.upsert_identity_for_test(tenzro_identity::TenzroIdentity {
            did: tenzro_identity::TenzroDid::parse(
                "did:tenzro:human:7b0c2f3e-5d2a-4d55-9a3e-1c2b3d4e5f61",
            )
            .unwrap(),
            public_keys: vec![tenzro_identity::PublicKeyInfo {
                key_id: "key-1".into(),
                key_type: "P-256".into(),
                public_key: point.as_bytes()[1..].to_vec(),
                purposes: vec![tenzro_identity::KeyPurpose::AssertionMethod],
            }],
            identity_data: tenzro_identity::IdentityData::Human {
                display_name: "root".into(),
                controlled_machines: Vec::new(),
            },
            status: tenzro_identity::IdentityStatus::Active,
            wallet_address: tenzro_types::primitives::Address::new([1; 32]),
            wallet_id: String::new(),
            pq_verifying_key: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: Default::default(),
        });
        let did = "did:tenzro:human:7b0c2f3e-5d2a-4d55-9a3e-1c2b3d4e5f61";
        assert!(identity_lists_key(&registry, did, k.verifying_key()).unwrap());
        assert!(!identity_lists_key(&registry, did, key().verifying_key()).unwrap());
    }

    fn pay(amount: u128) -> ProposedPayment<'static> {
        ProposedPayment {
            agent_did: AGENT,
            payee: PAYEE,
            amount,
            currency: "TNZO",
            chain: "tenzro:1337",
        }
    }

    fn reference(w: &World) -> Value {
        serde_json::json!({"type": "payment.reference",
                           "conditional_transaction_id": b64_sha256(w.checkout.as_bytes())})
    }

    #[test]
    fn a_controller_signed_mandate_pays_inside_the_terms_and_not_beyond_them() {
        let w = world();
        let p = Ap2Presentation {
            checkout_jwt: w.checkout.clone(),
            payment_mandate: closed(&w, &w.root, 400),
            open_payment_mandate: None,
        };
        let terms = Terms(500, Mutex::new(vec![]));
        let ok = verify(
            &p,
            &pay(400),
            Some(w.merchant.verifying_key()),
            &keys(&w),
            &terms,
        )
        .unwrap();
        assert_eq!(ok.authorized_by, ROOT);
        assert_eq!(ok.instrument.as_deref(), Some("tenzro-wallet"));
        assert_eq!(terms.1.lock()[0], ("ap2".to_string(), 400));

        // The same mandate for 900 is still refused by the Terms.
        let p = Ap2Presentation {
            payment_mandate: closed(&w, &w.root, 900),
            ..p
        };
        assert!(verify(&p, &pay(900), None, &keys(&w), &terms).is_err());
    }

    #[test]
    fn a_mandate_never_widens_what_it_states() {
        let w = world();
        let terms = Terms(10_000, Mutex::new(vec![]));
        let p = Ap2Presentation {
            checkout_jwt: w.checkout.clone(),
            payment_mandate: closed(&w, &w.root, 400),
            open_payment_mandate: None,
        };
        // Another amount, another payee, another currency.
        assert!(verify(&p, &pay(401), None, &keys(&w), &terms).is_err());
        let other = ProposedPayment {
            payee: "did:tenzro:machine:other",
            ..pay(400)
        };
        assert!(verify(&p, &other, None, &keys(&w), &terms).is_err());
        let usd = ProposedPayment {
            currency: "USD",
            ..pay(400)
        };
        assert!(verify(&p, &usd, None, &keys(&w), &terms).is_err());
        // Another checkout.
        let other_checkout = jws(&w.merchant, serde_json::json!({"id": "chk_2"}));
        let p2 = Ap2Presentation {
            checkout_jwt: other_checkout,
            ..p.clone()
        };
        assert!(verify(&p2, &pay(400), None, &keys(&w), &terms).is_err());
        // A checkout another merchant signed.
        assert!(
            verify(
                &p,
                &pay(400),
                Some(key().verifying_key()),
                &keys(&w),
                &terms
            )
            .is_err()
        );
        // Signed by a key that is not the controller's.
        let p3 = Ap2Presentation {
            payment_mandate: closed(&w, &key(), 400),
            ..p
        };
        assert!(verify(&p3, &pay(400), None, &keys(&w), &terms).is_err());
        // Nothing reached the Terms check.
        assert!(terms.1.lock().is_empty());
    }

    #[test]
    fn an_agent_signs_under_an_open_mandate_only_within_its_constraints() {
        let w = world();
        let terms = Terms(10_000, Mutex::new(vec![]));
        let open_m = open(
            &w,
            serde_json::json!([
                reference(&w),
                {"type": "payment.amount_range", "currency": "TNZO", "max": 500},
                {"type": "payment.allowed_payees", "allowed": [{"id": PAYEE, "name": "seller"}]},
                {"type": "payment.allowed_payment_instruments", "allowed": [{"id": "tenzro-wallet", "type": "tenzro"}]},
            ]),
        );
        let p = Ap2Presentation {
            checkout_jwt: w.checkout.clone(),
            payment_mandate: closed(&w, &w.agent, 400),
            open_payment_mandate: Some(open_m.clone()),
        };
        assert!(verify(&p, &pay(400), None, &keys(&w), &terms).is_ok());

        let over = Ap2Presentation {
            payment_mandate: closed(&w, &w.agent, 600),
            ..p.clone()
        };
        assert!(verify(&over, &pay(600), None, &keys(&w), &terms).is_err());

        // A tampered key-binding presentation is refused.
        let mut cut = open_m.clone();
        cut.insert_str(cut.find('~').unwrap() + 1, "AAAA");
        let bad = Ap2Presentation {
            open_payment_mandate: Some(cut),
            ..p.clone()
        };
        assert!(verify(&bad, &pay(400), None, &keys(&w), &terms).is_err());
    }

    #[test]
    fn constraints_that_need_a_store_are_refused_not_skipped() {
        let w = world();
        let terms = Terms(10_000, Mutex::new(vec![]));
        for c in [
            serde_json::json!({"type": "payment.budget", "currency": "TNZO", "max": 1000}),
            serde_json::json!({"type": "payment.agent_recurrence", "frequency": "monthly"}),
            serde_json::json!({"type": "payment.something_new"}),
        ] {
            let p = Ap2Presentation {
                checkout_jwt: w.checkout.clone(),
                payment_mandate: closed(&w, &w.agent, 400),
                open_payment_mandate: Some(open(&w, serde_json::json!([reference(&w), c]))),
            };
            assert!(verify(&p, &pay(400), None, &keys(&w), &terms).is_err());
        }
        // payment.reference is required.
        let p = Ap2Presentation {
            checkout_jwt: w.checkout.clone(),
            payment_mandate: closed(&w, &w.agent, 400),
            open_payment_mandate: Some(open(&w, serde_json::json!([]))),
        };
        assert!(verify(&p, &pay(400), None, &keys(&w), &terms).is_err());
    }

    #[test]
    fn an_agent_without_terms_cannot_pay_by_mandate() {
        let w = world();
        let terms = Terms(10_000, Mutex::new(vec![]));
        let p = Ap2Presentation {
            checkout_jwt: w.checkout.clone(),
            payment_mandate: closed(&w, &w.root, 1),
            open_payment_mandate: None,
        };
        let stranger = ProposedPayment {
            agent_did: "did:tenzro:machine:stranger",
            ..pay(1)
        };
        assert!(verify(&p, &stranger, None, &keys(&w), &terms).is_err());
    }
}
