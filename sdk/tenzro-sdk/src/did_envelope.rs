//! DID envelopes over whole JSON-RPC requests.
//!
//! Some methods change something that belongs to a DID (registering a machine
//! under a controller is one), so the request carries `did_envelope`: the
//! DID's signature over the method name and a hash of every other parameter.
//! The node rebuilds the same bytes and checks the signature against the key
//! the DID resolves to. The signature comes from a [`HybridSigner`] over the
//! hardware; the SDK never holds a private key.

use crate::error::{SdkError, SdkResult};
use crate::wallet::{HybridSigner, composite_message_representative, composite_signature_json};
use sha2::{Digest, Sha256};

/// Signature context of a DID envelope.
pub const DID_ENVELOPE_CONTEXT: &[u8] = b"tenzro/did-envelope";

/// Domain tag at the start of every envelope preimage.
const ENVELOPE_DOMAIN: &[u8] = b"tenzro-did-envelope:v1";

/// The bytes a request envelope binds: the params object without its
/// `did_envelope` field, as JSON with object keys sorted at every level and no
/// whitespace.
pub fn request_binding(params: &serde_json::Value) -> Vec<u8> {
    fn write(v: &serde_json::Value, skip_envelope: bool, out: &mut String) {
        match v {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map
                    .keys()
                    .filter(|k| !(skip_envelope && *k == "did_envelope"))
                    .collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::Value::String(k.clone()).to_string());
                    out.push(':');
                    write(&map[k], false, out);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, false, out);
                }
                out.push(']');
            }
            scalar => out.push_str(&scalar.to_string()),
        }
    }
    let mut out = String::new();
    write(params, true, &mut out);
    out.into_bytes()
}

/// The fields of an envelope before its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidEnvelopeFields {
    /// The signing DID.
    pub did: String,
    /// The method the envelope authorizes.
    pub method: String,
    /// SHA-256 of the bound bytes.
    pub params_hash: [u8; 32],
    /// Unix milliseconds at signing; the node accepts 60 s either side of
    /// its clock.
    pub timestamp_ms: u64,
    /// 16 random bytes; the node refuses a nonce it has seen.
    pub nonce: [u8; 16],
}

impl DidEnvelopeFields {
    /// The preimage the DID signs: the domain tag, then `did` and `method`
    /// each prefixed with its length (u32 big-endian), `params_hash`,
    /// `timestamp_ms` (u64 big-endian) and `nonce`.
    pub fn preimage(&self) -> Vec<u8> {
        let mut buf = ENVELOPE_DOMAIN.to_vec();
        buf.extend_from_slice(&(self.did.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.did.as_bytes());
        buf.extend_from_slice(&(self.method.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.method.as_bytes());
        buf.extend_from_slice(&self.params_hash);
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf
    }

    /// The hex header value the node takes as `did_envelope`: `did` and
    /// `method` length-prefixed, `params_hash`, `timestamp_ms`, `nonce`, then
    /// the JSON of the composite `signature`, length-prefixed.
    pub fn header(&self, signature: &serde_json::Value) -> SdkResult<String> {
        let sig = serde_json::to_vec(signature)
            .map_err(|e| SdkError::InvalidParameter(format!("envelope signature: {e}")))?;
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.did.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.did.as_bytes());
        buf.extend_from_slice(&(self.method.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.method.as_bytes());
        buf.extend_from_slice(&self.params_hash);
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        buf.extend_from_slice(&sig);
        Ok(hex::encode(buf))
    }
}

/// `did`'s envelope, signed by `signer`, authorizing `method` over every
/// field of `params` but `did_envelope`, at `timestamp_ms` with `nonce`.
pub async fn sign_request_envelope_at(
    signer: &dyn HybridSigner,
    did: &str,
    method: &str,
    params: &serde_json::Value,
    timestamp_ms: u64,
    nonce: [u8; 16],
) -> SdkResult<String> {
    let fields = DidEnvelopeFields {
        did: did.to_string(),
        method: method.to_string(),
        params_hash: Sha256::digest(request_binding(params)).into(),
        timestamp_ms,
        nonce,
    };
    let m_prime = composite_message_representative(DID_ENVELOPE_CONTEXT, &fields.preimage());
    let (p256, pq) = signer.sign_composite(&m_prime).await?;
    fields.header(&composite_signature_json(&p256, pq.as_deref()))
}

/// `params` with `did_envelope` set: `did`'s envelope, signed now by
/// `signer`, authorizing `method` over every other field. `signer` must hold
/// the key `did` resolves to on the node.
pub async fn with_request_envelope(
    signer: &dyn HybridSigner,
    did: &str,
    method: &str,
    mut params: serde_json::Value,
) -> SdkResult<serde_json::Value> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| SdkError::InvalidParameter(format!("nonce: {e}")))?;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| SdkError::InvalidParameter(format!("clock: {e}")))?
        .as_millis() as u64;
    let envelope =
        sign_request_envelope_at(signer, did, method, &params, timestamp_ms, nonce).await?;
    params["did_envelope"] = serde_json::Value::String(envelope);
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    fn vector() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../fixtures/did_envelope/machine_registration.json"
        );
        serde_json::from_slice(&std::fs::read(path).expect("the shared fixture")).unwrap()
    }

    fn bytes(v: &serde_json::Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap()).unwrap()
    }

    /// Answers only for the vector's message representative, with the
    /// vector's signature.
    pub(crate) struct VectorSigner(pub serde_json::Value);

    #[async_trait]
    impl HybridSigner for VectorSigner {
        fn p256_public_key(&self) -> [u8; 64] {
            bytes(&self.0, "controller_public_key").try_into().unwrap()
        }
        fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
            None
        }
        async fn sign_composite(&self, m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
            assert_eq!(hex::encode(m_prime), self.0["m_prime"].as_str().unwrap());
            let rs = hex::decode(
                self.0["signature"]["classical"]["signature"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            Ok((rs.try_into().unwrap(), None))
        }
        async fn sign_p256(&self, _message: &[u8]) -> SdkResult<[u8; 64]> {
            unreachable!("an envelope is a composite signature")
        }
    }

    #[test]
    fn the_binding_preimage_and_header_match_the_shared_vector() {
        let v = vector();
        let binding = request_binding(&v["request"]);
        assert_eq!(
            String::from_utf8(binding.clone()).unwrap(),
            v["request_binding"].as_str().unwrap()
        );
        let mut with_envelope = v["request"].clone();
        with_envelope["did_envelope"] = serde_json::json!("ff");
        assert_eq!(request_binding(&with_envelope), binding);
        let fields = DidEnvelopeFields {
            did: v["did"].as_str().unwrap().to_string(),
            method: v["method"].as_str().unwrap().to_string(),
            params_hash: Sha256::digest(&binding).into(),
            timestamp_ms: v["timestamp_ms"].as_u64().unwrap(),
            nonce: bytes(&v, "nonce").try_into().unwrap(),
        };
        assert_eq!(fields.params_hash.to_vec(), bytes(&v, "params_hash"));
        assert_eq!(fields.preimage(), bytes(&v, "preimage"));
        assert_eq!(
            composite_message_representative(DID_ENVELOPE_CONTEXT, &fields.preimage()),
            bytes(&v, "m_prime")
        );
        assert_eq!(
            fields.header(&v["signature"]).unwrap(),
            v["did_envelope"].as_str().unwrap()
        );
    }

    #[tokio::test]
    async fn the_signer_signs_the_vector_envelope() {
        let v = vector();
        let envelope = sign_request_envelope_at(
            &VectorSigner(v.clone()),
            v["did"].as_str().unwrap(),
            v["method"].as_str().unwrap(),
            &v["request"],
            v["timestamp_ms"].as_u64().unwrap(),
            bytes(&v, "nonce").try_into().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(envelope, v["did_envelope"].as_str().unwrap());
    }
}
