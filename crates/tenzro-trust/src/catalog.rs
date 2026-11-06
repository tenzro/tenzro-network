//! Catalog entries: a publisher's signed description of one model.
//!
//! A publisher signs an entry naming a model id, the engine that runs it, its
//! licence and the hash of every file it downloads. Only a higher sequence
//! from the same publisher replaces an entry, and an entry of `null`
//! withdraws the model. Anyone can publish; which publishers a node serves
//! from is its operator's choice, named in its configuration.
//!
//! The ledger checks the signature and the envelope. The entry body is
//! interpreted by the node that serves it, so an entry for an engine this
//! build does not know is kept, not refused, and becomes usable once the
//! operator runs an engine that does.

use serde_json::{Value, json};

use crate::{Result, has_type, invalid, str_field, verify_proof_by};

pub const CATALOG_ENTRY_TYPE: &str = "TenzroCatalogEntry";
/// Largest signed entry the ledger holds.
pub const MAX_ENTRY_BYTES: usize = 256 * 1024;

/// A verified catalog record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRecord {
    /// Hex SHA-256 of the canonical signed document.
    pub digest: String,
    pub publisher: String,
    /// The model id the record describes.
    pub model: String,
    pub sequence: u64,
    /// The entry as published; `None` when the publisher withdrew the model.
    pub entry: Option<Value>,
    pub document: Value,
}

fn valid_model_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
}

impl CatalogRecord {
    /// The unsigned document for `publisher` to sign. `entry: None` withdraws
    /// the model.
    pub fn unsigned(publisher: &str, model: &str, sequence: u64, entry: Option<&Value>) -> Value {
        json!({
            "type": [CATALOG_ENTRY_TYPE],
            "publisher": publisher,
            "model": model,
            "sequence": sequence,
            "entry": entry.cloned().unwrap_or(Value::Null),
        })
    }

    pub fn parse(document: &Value) -> Result<Self> {
        if !has_type(document, CATALOG_ENTRY_TYPE) {
            return Err(invalid(format!("not a {CATALOG_ENTRY_TYPE}")));
        }
        if crate::jcs::canonical_json(document).len() > MAX_ENTRY_BYTES {
            return Err(invalid(format!(
                "a catalog entry is at most {MAX_ENTRY_BYTES} bytes"
            )));
        }
        let publisher = str_field(document, "/publisher")?.to_string();
        verify_proof_by(document, &publisher)?;
        let model = str_field(document, "/model")?.to_string();
        if !valid_model_id(&model) {
            return Err(invalid(
                "the model id must be 1-128 characters of a-z 0-9 - . _",
            ));
        }
        let sequence = document
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("sequence must be an unsigned integer"))?;
        let entry = match document.get("entry") {
            Some(Value::Null) => None,
            Some(e @ Value::Object(_)) => {
                if e.pointer("/model/spec/id").and_then(Value::as_str) != Some(model.as_str()) {
                    return Err(invalid(format!(
                        "the entry describes a model other than {model}"
                    )));
                }
                Some(e.clone())
            }
            _ => {
                return Err(invalid(
                    "entry must be an object, or null to withdraw the model",
                ));
            }
        };
        Ok(CatalogRecord {
            digest: crate::record_digest(document),
            publisher,
            model,
            sequence,
            entry,
            document: document.clone(),
        })
    }

    /// Hex SHA-256 of the canonical entry body. Two publishers agree on a
    /// model exactly when their entries hash the same.
    pub fn entry_digest(&self) -> Option<String> {
        use sha2::{Digest, Sha256};
        self.entry
            .as_ref()
            .map(|e| hex::encode(Sha256::digest(crate::jcs::canonical_json(e))))
    }

    /// The ledger account of the key that signed the entry: where the
    /// publisher's model provider bond is held.
    pub fn signer_account(&self) -> Option<[u8; 32]> {
        let proof = crate::proof::verify(&self.document).ok()?;
        Some(tenzro_crypto::composite::account_slot(
            &proof.public_key_sec1[1..],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::testkit::TestKey;

    fn body(id: &str) -> Value {
        json!({"model": {"engine": "gguf", "spec": {"id": id, "temperature": 0.7}}, "gated": false})
    }

    #[test]
    fn a_signed_entry_verifies_with_fractional_numbers_in_its_body() {
        let k = TestKey::new(4);
        let doc = k.sign(CatalogRecord::unsigned(
            &k.did(),
            "m-1",
            1,
            Some(&body("m-1")),
        ));
        let r = CatalogRecord::parse(&doc).unwrap();
        assert_eq!(
            (r.publisher.as_str(), r.model.as_str(), r.sequence),
            (k.did().as_str(), "m-1", 1)
        );
        assert!(r.entry_digest().is_some());
    }

    #[test]
    fn an_edited_entry_or_another_signer_is_refused() {
        let k = TestKey::new(4);
        let mut doc = k.sign(CatalogRecord::unsigned(
            &k.did(),
            "m-1",
            1,
            Some(&body("m-1")),
        ));
        doc["entry"]["gated"] = json!(true);
        assert!(CatalogRecord::parse(&doc).is_err());

        let other = TestKey::new(5);
        let forged = other.sign(CatalogRecord::unsigned(
            &k.did(),
            "m-1",
            1,
            Some(&body("m-1")),
        ));
        assert!(CatalogRecord::parse(&forged).is_err());
    }

    #[test]
    fn an_entry_for_another_model_id_is_refused() {
        let k = TestKey::new(4);
        let doc = k.sign(CatalogRecord::unsigned(
            &k.did(),
            "m-1",
            1,
            Some(&body("m-2")),
        ));
        assert!(CatalogRecord::parse(&doc).is_err());
    }

    #[test]
    fn a_withdrawal_carries_no_entry() {
        let k = TestKey::new(4);
        let doc = k.sign(CatalogRecord::unsigned(&k.did(), "m-1", 2, None));
        let r = CatalogRecord::parse(&doc).unwrap();
        assert!(r.entry.is_none() && r.entry_digest().is_none());
    }
}
