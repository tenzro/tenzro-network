//! The Tenzro DID envelope on A2A task calls.
//!
//! A node answers `SendMessage`, `SendStreamingMessage`, `CancelTask`,
//! `GetTask` and `ListTasks` only when the request names its sender and the
//! sender signed it, and it shows a task only to the DID that opened it. The
//! envelope is five metadata fields, six for an account with an ML-DSA-65
//! key: for the two message methods in `params.message.metadata`, for the
//! others in `params.metadata`.
//!
//! The sender signs the UTF-8 bytes of
//!
//! ```text
//! tenzro:a2a:{audience_did}:{method}:{task_id_or_empty}:{sender_did}:{nonce_hex}:{timestamp_ms}:{params_sha256_hex}
//! ```
//!
//! where `audience_did` is the machine DID of the node addressed (the DID its
//! signed agent card names), so an envelope made for one node does not verify
//! on another, and `params_sha256_hex` is the SHA-256 of the RFC 8785 canonical form
//! of `params` without the envelope fields. Here the signature is made by the
//! account's hardware P-256 key ([`HybridSigner::sign_p256`]): the public key
//! goes out as `x || y` and the signature as `r || s`.
//!
//! An account that enrolled an ML-DSA-65 key also signs the preimage with
//! it, as the ML-DSA-65 leg of a composite under the context
//! [`A2A_ENVELOPE_SIGNATURE_CONTEXT`], sent as a sixth field. The node
//! requires that leg from such an account and refuses it from any other.
//!
//! A passkey cannot sign an envelope: it signs WebAuthn client data, never a
//! message of the caller's choosing. An identity whose only key is a passkey
//! makes these calls from a device bound to it whose key is in a TPM or
//! Secure Enclave, with that device's account as the sender.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{SdkError, SdkResult};
use crate::wallet::{HybridSigner, composite_message_representative};

/// Metadata key of the sender DID.
pub const KEY_SENDER: &str = "tenzro.a2a.envelope.sender";
/// Metadata key of the signing public key, hex.
pub const KEY_PUBLIC_KEY: &str = "tenzro.a2a.envelope.public_key";
/// Metadata key of the signature, hex.
pub const KEY_SIGNATURE: &str = "tenzro.a2a.envelope.signature";
/// Metadata key of the 16-byte nonce, hex.
pub const KEY_NONCE: &str = "tenzro.a2a.envelope.nonce";
/// Metadata key of the signing time, unix milliseconds.
pub const KEY_TIMESTAMP: &str = "tenzro.a2a.envelope.timestamp";
/// Metadata key of the ML-DSA-65 leg, hex.
pub const KEY_PQ_SIGNATURE: &str = "tenzro.a2a.envelope.pq_signature";

/// Signature context of the ML-DSA-65 leg.
pub const A2A_ENVELOPE_SIGNATURE_CONTEXT: &[u8] = b"tenzro/a2a/envelope";

const ENVELOPE_KEYS: [&str; 6] = [
    KEY_SENDER,
    KEY_PUBLIC_KEY,
    KEY_SIGNATURE,
    KEY_NONCE,
    KEY_TIMESTAMP,
    KEY_PQ_SIGNATURE,
];

fn is_message_method(method: &str) -> bool {
    matches!(method, "SendMessage" | "SendStreamingMessage")
}

/// The task id an envelope binds to: `params.message.taskId` for the message
/// methods, `params.id` for the others, empty when there is none.
pub fn task_id(method: &str, params: &Value) -> String {
    let found = if is_message_method(method) {
        params.get("message").and_then(|m| m.get("taskId"))
    } else {
        params.get("id")
    };
    found.and_then(Value::as_str).unwrap_or("").to_string()
}

/// The text the sender signs for the node whose machine DID is `audience_did`.
pub fn preimage(
    audience_did: &str,
    method: &str,
    task_id: &str,
    sender_did: &str,
    nonce_hex: &str,
    timestamp_ms: i64,
    params_sha256_hex: &str,
) -> String {
    format!(
        "tenzro:a2a:{audience_did}:{method}:{task_id}:{sender_did}:{nonce_hex}:{timestamp_ms}:{params_sha256_hex}"
    )
}

/// RFC 8785 canonical text of `value`. Numbers must be integers no larger
/// in magnitude than 2^53: those are written the same way in every JSON
/// implementation, which a fraction or a larger number is not.
pub fn canonical_json(value: &Value) -> SdkResult<String> {
    let mut out = String::new();
    canonical(value, &mut out)?;
    Ok(out)
}

fn canonical(value: &Value, out: &mut String) -> SdkResult<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            const SAFE: u64 = 1 << 53;
            let exact = match (n.as_i64(), n.as_u64()) {
                (Some(i), _) if i.unsigned_abs() <= SAFE => true,
                (None, Some(u)) if u <= SAFE => true,
                _ => false,
            };
            if !exact {
                return Err(SdkError::InvalidParameter(format!(
                    "an A2A envelope signs whole numbers up to 2^53 only, not {n}"
                )));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).map_err(|_| SdkError::SerializationError)?)
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Member names in UTF-16 code unit order.
            let mut names: Vec<&String> = map.keys().collect();
            names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, name) in names.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(name).map_err(|_| SdkError::SerializationError)?,
                );
                out.push(':');
                canonical(&map[name], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Lowercase hex SHA-256 of the canonical `params` with the envelope fields
/// removed, and the metadata object they sat in dropped when nothing else is
/// left in it.
pub fn params_digest_hex(method: &str, params: &Value) -> SdkResult<String> {
    let mut body = params.clone();
    let holder = if is_message_method(method) {
        body.get_mut("message")
    } else {
        Some(&mut body)
    };
    if let Some(Value::Object(holder)) = holder {
        let emptied = match holder.get_mut("metadata") {
            Some(Value::Object(metadata)) => {
                for key in ENVELOPE_KEYS {
                    metadata.remove(key);
                }
                metadata.is_empty()
            }
            _ => false,
        };
        if emptied {
            holder.remove("metadata");
        }
    }
    Ok(hex::encode(Sha256::digest(
        canonical_json(&body)?.as_bytes(),
    )))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Attach to `params` the envelope for `method` to the node whose machine DID
/// is `audience_did`, signed now by `signer` as `sender_did`. `params` must be a JSON object; for a message method it must
/// hold the `message` object.
pub async fn sign(
    audience_did: &str,
    method: &str,
    params: &mut Value,
    sender_did: &str,
    signer: &dyn HybridSigner,
) -> SdkResult<()> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| SdkError::AuthenticationError(format!("no randomness for the nonce: {e}")))?;
    sign_at(
        audience_did,
        method,
        params,
        sender_did,
        signer,
        &hex::encode(nonce),
        now_ms(),
    )
    .await
}

async fn sign_at(
    audience_did: &str,
    method: &str,
    params: &mut Value,
    sender_did: &str,
    signer: &dyn HybridSigner,
    nonce_hex: &str,
    timestamp_ms: i64,
) -> SdkResult<()> {
    let digest = params_digest_hex(method, params)?;
    let text = preimage(
        audience_did,
        method,
        &task_id(method, params),
        sender_did,
        nonce_hex,
        timestamp_ms,
        &digest,
    );
    let signature = signer.sign_p256(text.as_bytes()).await?;
    let pq_leg = match signer.ml_dsa_public_key() {
        Some(_) => {
            let m_prime =
                composite_message_representative(A2A_ENVELOPE_SIGNATURE_CONTEXT, text.as_bytes());
            Some(signer.sign_ml_dsa_leg(&m_prime).await?)
        }
        None => None,
    };
    let holder = if is_message_method(method) {
        params.get_mut("message")
    } else {
        Some(params)
    };
    let Some(Value::Object(holder)) = holder else {
        return Err(SdkError::InvalidParameter(format!(
            "{method} params have no object to carry the envelope"
        )));
    };
    let metadata = holder
        .entry("metadata")
        .or_insert_with(|| Value::Object(Default::default()));
    let Value::Object(metadata) = metadata else {
        return Err(SdkError::InvalidParameter(
            "metadata must be a JSON object".to_string(),
        ));
    };
    metadata.insert(KEY_SENDER.into(), sender_did.into());
    metadata.insert(
        KEY_PUBLIC_KEY.into(),
        hex::encode(signer.p256_public_key()).into(),
    );
    metadata.insert(KEY_SIGNATURE.into(), hex::encode(signature).into());
    metadata.insert(KEY_NONCE.into(), nonce_hex.into());
    metadata.insert(KEY_TIMESTAMP.into(), timestamp_ms.into());
    if let Some(leg) = pq_leg {
        metadata.insert(KEY_PQ_SIGNATURE.into(), hex::encode(leg).into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The machine DID of the node test envelopes are addressed to.
    pub(crate) const AUDIENCE: &str = "did:tenzro:machine:node";
    use async_trait::async_trait;
    use p256::ecdsa::signature::{Signer as _, Verifier as _};

    /// A signer over a software P-256 key, standing in for the hardware.
    pub(crate) struct SoftSigner(p256::ecdsa::SigningKey);

    impl SoftSigner {
        pub(crate) fn new(seed: u8) -> Self {
            Self(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("key"))
        }
    }

    #[async_trait]
    impl HybridSigner for SoftSigner {
        fn p256_public_key(&self) -> [u8; 64] {
            let point = self.0.verifying_key().to_encoded_point(false);
            point.as_bytes()[1..].try_into().expect("x || y")
        }
        fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
            None
        }
        async fn sign_composite(&self, _m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
            unreachable!("a signer with no ML-DSA-65 key makes no ML-DSA-65 leg")
        }
        async fn sign_ml_dsa_leg(&self, _m_prime: &[u8]) -> SdkResult<Vec<u8>> {
            unreachable!("this signer holds no ML-DSA-65 key")
        }
        async fn sign_p256(&self, message: &[u8]) -> SdkResult<[u8; 64]> {
            let sig: p256::ecdsa::Signature = self.0.sign(message);
            Ok(sig.to_bytes().into())
        }
    }

    /// Check an envelope the way the node does: the fields are present, the
    /// signature is by the key sent, over the preimage rebuilt from the
    /// request as received.
    pub(crate) fn verified_sender(
        audience_did: &str,
        method: &str,
        params: &Value,
    ) -> Option<String> {
        let metadata = if is_message_method(method) {
            params.get("message")?.get("metadata")?
        } else {
            params.get("metadata")?
        };
        let text = |k: &str| metadata.get(k)?.as_str().map(str::to_string);
        let sender = text(KEY_SENDER)?;
        let key = hex::decode(text(KEY_PUBLIC_KEY)?).ok()?;
        let signature = hex::decode(text(KEY_SIGNATURE)?).ok()?;
        let at = metadata.get(KEY_TIMESTAMP)?.as_i64()?;
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&key);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()?;
        let signed = preimage(
            audience_did,
            method,
            &task_id(method, params),
            &sender,
            &text(KEY_NONCE)?,
            at,
            &params_digest_hex(method, params).ok()?,
        );
        let sig = p256::ecdsa::Signature::from_slice(&signature).ok()?;
        vk.verify(signed.as_bytes(), &sig).ok()?;
        Some(sender)
    }

    #[test]
    fn the_params_digest_is_the_sha256_of_the_canonical_form() {
        let digest = |v: Value| params_digest_hex("GetTask", &v).unwrap();
        // Member order does not matter; these are the node's own vectors.
        assert_eq!(
            digest(serde_json::json!({"id": "t-1", "historyLength": 3})),
            "b9b45dcffe8b8a7288299bd82bdabdcad1c19fed43d1006937db7e3777a8e3f1"
        );
        assert_eq!(
            digest(serde_json::json!({})),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
        assert_eq!(
            params_digest_hex(
                "ListTasks",
                &serde_json::json!({"pageSize": 10, "includeArtifacts": true, "contextId": "c\u{e9}\n"})
            )
            .unwrap(),
            "c34b1beab72fb98be2c7b9169a727921ea65a64890f39840a2812ac0935ec973"
        );
    }

    #[test]
    fn a_number_that_is_not_a_whole_number_is_refused_rather_than_signed() {
        for bad in [
            serde_json::json!({"x": 1.5}),
            serde_json::json!({"x": u64::MAX}),
        ] {
            assert!(matches!(
                params_digest_hex("ListTasks", &bad),
                Err(SdkError::InvalidParameter(_))
            ));
        }
        assert!(params_digest_hex("ListTasks", &serde_json::json!({"x": -3})).is_ok());
    }

    #[tokio::test]
    async fn the_digest_is_the_same_before_and_after_the_envelope_is_attached() {
        let signer = SoftSigner::new(7);
        for (method, params) in [
            ("ListTasks", serde_json::json!({})),
            ("GetTask", serde_json::json!({"id": "t-1"})),
            (
                "CancelTask",
                serde_json::json!({"id": "t-1", "metadata": {"note": "kept"}}),
            ),
            (
                "SendMessage",
                serde_json::json!({"message": {"messageId": "m", "role": "ROLE_USER", "parts": [{"text": "hi"}]}}),
            ),
        ] {
            let before = params_digest_hex(method, &params).unwrap();
            let mut signed = params.clone();
            sign(
                AUDIENCE,
                method,
                &mut signed,
                "did:tenzro:machine:a",
                &signer,
            )
            .await
            .unwrap();
            assert_ne!(signed, params, "{method}: the envelope was attached");
            assert_eq!(
                params_digest_hex(method, &signed).unwrap(),
                before,
                "{method}"
            );
            assert_eq!(
                verified_sender(AUDIENCE, method, &signed).as_deref(),
                Some("did:tenzro:machine:a"),
                "{method}"
            );
        }
    }

    #[tokio::test]
    async fn an_envelope_binds_the_method_the_task_and_the_body() {
        let signer = SoftSigner::new(7);
        let mut get = serde_json::json!({"id": "t-1"});
        sign(
            AUDIENCE,
            "GetTask",
            &mut get,
            "did:tenzro:machine:a",
            &signer,
        )
        .await
        .unwrap();
        assert!(verified_sender(AUDIENCE, "GetTask", &get).is_some());
        assert!(
            verified_sender(AUDIENCE, "CancelTask", &get).is_none(),
            "another method"
        );
        assert!(
            verified_sender("did:tenzro:machine:other", "GetTask", &get).is_none(),
            "another node"
        );
        let mut other_task = get.clone();
        other_task["id"] = "t-2".into();
        assert!(verified_sender(AUDIENCE, "GetTask", &other_task).is_none());
        let mut other_body = get.clone();
        other_body["historyLength"] = 5.into();
        assert!(verified_sender(AUDIENCE, "GetTask", &other_body).is_none());
        let mut other_sender = get.clone();
        other_sender["metadata"][KEY_SENDER] = "did:tenzro:machine:b".into();
        assert!(verified_sender(AUDIENCE, "GetTask", &other_sender).is_none());
    }

    #[tokio::test]
    async fn two_envelopes_for_the_same_call_differ_by_nonce() {
        let signer = SoftSigner::new(7);
        let mut a = serde_json::json!({});
        let mut b = serde_json::json!({});
        sign(
            AUDIENCE,
            "ListTasks",
            &mut a,
            "did:tenzro:machine:a",
            &signer,
        )
        .await
        .unwrap();
        sign(
            AUDIENCE,
            "ListTasks",
            &mut b,
            "did:tenzro:machine:a",
            &signer,
        )
        .await
        .unwrap();
        assert_ne!(a["metadata"][KEY_NONCE], b["metadata"][KEY_NONCE]);
        assert_eq!(a["metadata"][KEY_NONCE].as_str().unwrap().len(), 32);
    }

    /// [`SoftSigner`] with an ML-DSA-65 key: records the message it was asked
    /// to sign and returns a fixed leg.
    struct PqSigner(SoftSigner, std::sync::Mutex<Vec<u8>>);

    #[async_trait]
    impl HybridSigner for PqSigner {
        fn p256_public_key(&self) -> [u8; 64] {
            self.0.p256_public_key()
        }
        fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
            Some(vec![1; 1952])
        }
        async fn sign_composite(&self, _m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
            unreachable!("an envelope's P-256 leg is made over its own text, not the composite's")
        }
        async fn sign_ml_dsa_leg(&self, m_prime: &[u8]) -> SdkResult<Vec<u8>> {
            *self.1.lock().unwrap() = m_prime.to_vec();
            Ok(vec![7; 3309])
        }
        async fn sign_p256(&self, message: &[u8]) -> SdkResult<[u8; 64]> {
            self.0.sign_p256(message).await
        }
    }

    #[tokio::test]
    async fn an_account_with_an_ml_dsa_key_adds_its_leg_over_the_preimage() {
        let signer = PqSigner(SoftSigner::new(7), Default::default());
        let mut get = serde_json::json!({"id": "t-1"});
        sign(
            AUDIENCE,
            "GetTask",
            &mut get,
            "did:tenzro:machine:a",
            &signer,
        )
        .await
        .unwrap();
        assert!(verified_sender(AUDIENCE, "GetTask", &get).is_some());
        let metadata = &get["metadata"];
        assert_eq!(metadata[KEY_PQ_SIGNATURE], hex::encode(vec![7u8; 3309]));
        let signed = preimage(
            AUDIENCE,
            "GetTask",
            "t-1",
            "did:tenzro:machine:a",
            metadata[KEY_NONCE].as_str().unwrap(),
            metadata[KEY_TIMESTAMP].as_i64().unwrap(),
            &params_digest_hex("GetTask", &get).unwrap(),
        );
        assert_eq!(
            *signer.1.lock().unwrap(),
            composite_message_representative(A2A_ENVELOPE_SIGNATURE_CONTEXT, signed.as_bytes())
        );

        let mut plain = serde_json::json!({"id": "t-1"});
        sign(
            AUDIENCE,
            "GetTask",
            &mut plain,
            "did:tenzro:machine:a",
            &SoftSigner::new(7),
        )
        .await
        .unwrap();
        assert!(plain["metadata"].get(KEY_PQ_SIGNATURE).is_none());
    }
}
