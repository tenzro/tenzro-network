//! The Tenzro light client for JavaScript and TypeScript (preview).
//!
//! The `tenzro-light` checks compiled to WebAssembly, so a browser or Node
//! app runs the same verifier as the Rust SDK and the Kotlin and Swift
//! packages. The caller supplies the transport: an async function
//! `(method, paramsJson) => resultJson` over its own `fetch`. Numbers that
//! are 64-bit on the chain (chain id, epochs, indexes, milliseconds) are
//! `bigint`.

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::{Function, Promise};
use serde_json::{Value, json};
use tenzro_light::{Checkpoint, Clock, TrustAnchor, identity, rpc, wire};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, future_to_promise};

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsError::new(&e.to_string()).into()
}

fn clock(now_ms: u64, max_age_ms: u64, max_ahead_ms: u64) -> Clock {
    Clock {
        now_ms,
        max_age_ms,
        max_ahead_ms,
    }
}

fn checkpoint_json(cp: &Checkpoint) -> Result<String, JsValue> {
    serde_json::to_string(cp).map_err(js_err)
}

/// One JSON-RPC call through the caller's transport.
async fn call(transport: &Function, method: &str, params: Value) -> Result<Value, JsValue> {
    let pending = transport.call2(
        &JsValue::NULL,
        &JsValue::from_str(method),
        &JsValue::from_str(&params.to_string()),
    )?;
    let reply = JsFuture::from(Promise::resolve(&pending)).await?;
    let text = reply
        .as_string()
        .ok_or_else(|| js_err(format!("{method}: the transport answered with no string")))?;
    serde_json::from_str(&text).map_err(|e| js_err(format!("{method}: the reply is not JSON: {e}")))
}

/// The value of (`namespace`, `key`) in the state `checkpoint` certifies,
/// checked against its root, while the checkpoint is within `clock`.
async fn read(
    transport: &Function,
    checkpoint: &Checkpoint,
    clock: &Clock,
    namespace: &str,
    key: &[u8],
) -> Result<Option<Vec<u8>>, JsValue> {
    clock.check(checkpoint).map_err(js_err)?;
    let reply = call(
        transport,
        "tenzro_getStateProof",
        json!({
            "namespace": namespace,
            "key": hex::encode(key),
            "height": checkpoint.state_height,
        }),
    )
    .await?;
    rpc::state_value(checkpoint, namespace, key, &reply).map_err(js_err)
}

/// Moves `inner` through every epoch handover until it trusts the committee
/// of `epoch`.
async fn follow(
    inner: &RefCell<tenzro_light::LightClient>,
    transport: &Function,
    epoch: u64,
) -> Result<(), JsValue> {
    loop {
        let held = inner.borrow().epoch();
        if held >= epoch {
            return Ok(());
        }
        let handover = call(
            transport,
            "tenzro_getEpochHandover",
            json!({ "epoch": held }),
        )
        .await?;
        rpc::hand_over(&mut inner.borrow_mut(), &handover).map_err(js_err)?;
    }
}

/// A light client of one chain.
#[wasm_bindgen]
pub struct LightClient {
    inner: Rc<RefCell<tenzro_light::LightClient>>,
    transport: Function,
}

#[wasm_bindgen]
impl LightClient {
    /// A client trusting the committee of `epoch` whose root is
    /// `committeeRoot` (32 bytes, hex). `committeeReplyJson` is a node's reply
    /// to `tenzro_getCommittee` for that epoch; its members are kept only when
    /// they hash to the root.
    #[wasm_bindgen(constructor)]
    pub fn new(
        transport: Function,
        chain_id: u64,
        genesis_hash: &str,
        epoch: u64,
        committee_root: &str,
        committee_reply_json: &str,
    ) -> Result<LightClient, JsValue> {
        let anchor = TrustAnchor {
            chain_id,
            genesis_hash: wire::digest("genesis hash", genesis_hash).map_err(js_err)?,
            epoch,
            committee_root: wire::digest("committee root", committee_root).map_err(js_err)?,
        };
        let reply: Value = serde_json::from_str(committee_reply_json).map_err(js_err)?;
        let members = rpc::committee_members(&reply).map_err(js_err)?;
        let inner = tenzro_light::LightClient::new(&anchor, members).map_err(js_err)?;
        Ok(LightClient {
            inner: Rc::new(RefCell::new(inner)),
            transport,
        })
    }

    /// A client from bytes `save` wrote, refused when damaged, of another
    /// chain, or behind `atLeastIndex`.
    pub fn restore(
        transport: Function,
        saved: &[u8],
        chain_id: u64,
        genesis_hash: &str,
        at_least_index: u64,
    ) -> Result<LightClient, JsValue> {
        let genesis = wire::digest("genesis hash", genesis_hash).map_err(js_err)?;
        let inner = tenzro_light::LightClient::restore(saved, chain_id, &genesis, at_least_index)
            .map_err(js_err)?;
        Ok(LightClient {
            inner: Rc::new(RefCell::new(inner)),
            transport,
        })
    }

    /// The client's state for the caller to keep.
    pub fn save(&self) -> Vec<u8> {
        self.inner.borrow().save()
    }

    /// The epoch of the committee the client trusts now.
    pub fn epoch(&self) -> u64 {
        self.inner.borrow().epoch()
    }

    /// The newest checkpoint the client accepted, as JSON.
    pub fn latest(&self) -> Result<Option<String>, JsValue> {
        self.inner
            .borrow()
            .latest()
            .map(checkpoint_json)
            .transpose()
    }

    /// Follows the node to its newest certified checkpoint, through every
    /// epoch handover since the client's committee; resolves to the
    /// checkpoint as JSON. It must be within the clock's bounds.
    pub fn sync(&self, now_ms: u64, max_age_ms: u64, max_ahead_ms: u64) -> Promise {
        let inner = self.inner.clone();
        let transport = self.transport.clone();
        let clock = clock(now_ms, max_age_ms, max_ahead_ms);
        future_to_promise(async move {
            let newest = call(&transport, "tenzro_getCheckpointCertificate", json!({})).await?;
            let epoch = newest
                .get("epoch")
                .and_then(Value::as_u64)
                .ok_or_else(|| js_err("certificate reply has no 'epoch'"))?;
            follow(&inner, &transport, epoch).await?;
            let cp = rpc::advance(&mut inner.borrow_mut(), &newest, &clock).map_err(js_err)?;
            Ok(JsValue::from_str(&checkpoint_json(&cp)?))
        })
    }

    /// Moves the client through every epoch handover until it trusts the
    /// committee of `epoch`; resolves when it does.
    pub fn follow(&self, epoch: u64) -> Promise {
        let inner = self.inner.clone();
        let transport = self.transport.clone();
        future_to_promise(async move {
            follow(&inner, &transport, epoch).await?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Checks a `tenzro_getCheckpointCertificate` reply of the current epoch
    /// and makes its checkpoint the newest; returns it as JSON.
    pub fn advance(
        &self,
        reply_json: &str,
        now_ms: u64,
        max_age_ms: u64,
        max_ahead_ms: u64,
    ) -> Result<String, JsValue> {
        let reply: Value = serde_json::from_str(reply_json).map_err(js_err)?;
        let clock = clock(now_ms, max_age_ms, max_ahead_ms);
        let cp = rpc::advance(&mut self.inner.borrow_mut(), &reply, &clock).map_err(js_err)?;
        checkpoint_json(&cp)
    }

    /// Checks a `tenzro_getCompactCertificate` reply and makes its checkpoint
    /// the newest; returns it as JSON. The first compact certificate of an
    /// epoch builds the proof set-up, the costly part.
    #[cfg(feature = "compact")]
    pub fn advance_compact(
        &self,
        reply_json: &str,
        now_ms: u64,
        max_age_ms: u64,
        max_ahead_ms: u64,
    ) -> Result<String, JsValue> {
        let reply: Value = serde_json::from_str(reply_json).map_err(js_err)?;
        let clock = clock(now_ms, max_age_ms, max_ahead_ms);
        let cp =
            rpc::advance_compact(&mut self.inner.borrow_mut(), &reply, &clock).map_err(js_err)?;
        checkpoint_json(&cp)
    }

    /// The value (hex) of the entry (`namespace`, `keyHex`) in the state of
    /// the newest certified checkpoint, checked against its root; `null` is
    /// a proven absence.
    pub fn state_value(
        &self,
        namespace: String,
        key_hex: &str,
        now_ms: u64,
        max_age_ms: u64,
        max_ahead_ms: u64,
    ) -> Result<Promise, JsValue> {
        let key = wire::bytes("key", key_hex).map_err(js_err)?;
        let checkpoint = self.certified()?;
        let transport = self.transport.clone();
        let clock = clock(now_ms, max_age_ms, max_ahead_ms);
        Ok(future_to_promise(async move {
            let value = read(&transport, &checkpoint, &clock, &namespace, &key).await?;
            Ok(value.map_or(JsValue::NULL, |v| JsValue::from_str(&hex::encode(v))))
        }))
    }

    /// `did`'s keys and whether it is revoked, proven against the newest
    /// certified checkpoint, as JSON; `null` is a proof that the DID is not
    /// registered.
    pub fn resolve_identity(
        &self,
        did: String,
        now_ms: u64,
        max_age_ms: u64,
        max_ahead_ms: u64,
    ) -> Result<Promise, JsValue> {
        let checkpoint = self.certified()?;
        let transport = self.transport.clone();
        let clock = clock(now_ms, max_age_ms, max_ahead_ms);
        Ok(future_to_promise(async move {
            let ns = identity::STATE_NAMESPACE;
            let record_slot = identity::system_slot(&identity::registration_slot(&did));
            let Some(record) = read(&transport, &checkpoint, &clock, ns, &record_slot).await?
            else {
                return Ok(JsValue::NULL);
            };
            let revocation_slot = identity::system_slot(&identity::revocation_slot(&did));
            let revocation = read(&transport, &checkpoint, &clock, ns, &revocation_slot).await?;
            let Some(id) =
                identity::proven(&checkpoint, &did, Some(record), revocation).map_err(js_err)?
            else {
                return Ok(JsValue::NULL);
            };
            let out = json!({
                "did": id.did,
                "identity_type": id.identity_type,
                "key_type": id.key_type,
                "controller_key": hex::encode(&id.controller_key),
                "ml_dsa_key": hex::encode(&id.ml_dsa_key),
                "revoked": id.revoked,
                "checkpoint_index": id.checkpoint_index,
                "checkpoint_time_ms": id.checkpoint_time_ms,
                "key_digest": hex::encode(id.key_digest()),
            });
            Ok(JsValue::from_str(&out.to_string()))
        }))
    }

    /// `did`'s key history and the head of its logs, proven against the
    /// newest certified checkpoint, as JSON: `epochs` oldest first, each with
    /// `version`, `ed25519`, `ml_dsa`, `effective_from_ms`,
    /// `compromised_from_ms` and `next_commitment`. A record made at time t
    /// was signed with the newest key in force at t, unless that key was
    /// declared compromised at or before t.
    pub fn key_history(
        &self,
        did: String,
        now_ms: u64,
        max_age_ms: u64,
        max_ahead_ms: u64,
    ) -> Result<Promise, JsValue> {
        let checkpoint = self.certified()?;
        let transport = self.transport.clone();
        let clock = clock(now_ms, max_age_ms, max_ahead_ms);
        Ok(future_to_promise(async move {
            let ns = identity::STATE_NAMESPACE;
            let keys_slot = identity::system_slot(&identity::key_history_slot(&did));
            let keys = read(&transport, &checkpoint, &clock, ns, &keys_slot).await?;
            let head_slot = identity::system_slot(&identity::head_slot(&did));
            let head = read(&transport, &checkpoint, &clock, ns, &head_slot).await?;
            let h = identity::proven_key_history(&checkpoint, &did, keys, head).map_err(js_err)?;
            let out = json!({
                "did": h.did,
                "epochs": h.epochs,
                "head": h.head,
                "checkpoint_index": h.checkpoint_index,
                "checkpoint_time_ms": h.checkpoint_time_ms,
            });
            Ok(JsValue::from_str(&out.to_string()))
        }))
    }
}

impl LightClient {
    fn certified(&self) -> Result<Checkpoint, JsValue> {
        self.inner
            .borrow()
            .latest()
            .cloned()
            .ok_or_else(|| js_err("the light client holds no certified checkpoint: sync first"))
    }
}
