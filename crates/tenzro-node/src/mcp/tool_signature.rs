//! The node's signature over the tools it lists.
//!
//! A client that pins a tool (Tenzro Terms pin each tool by the digest of its
//! name, description and input schema) needs to know that what it read came
//! from the node and was not rewritten by a relay or proxy on the way. Every
//! `tools/list` answer carries, in its `_meta` under [`META_KEY`], an ES256 JWS
//! by the node's machine identity key over [`payload`]: the same key and
//! format the node's Agent Card is signed with. The `kid` is
//! `<machine DID>#hardware-key`, and the machine DID derives from the key the
//! protected header carries, so a client checks the binding with no lookup.
//!
//! The payload covers every field a client acts on (name, title, description,
//! input and output schema, and the annotations, whose read-only and
//! destructive hints decide what a client lets run unattended), the time it
//! was signed and the node release that listed it. A client refuses a list
//! signed too long ago and one from an older release than it has seen, so a
//! list signed before a description was changed cannot be replayed.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_trust::jcs;

use crate::a2a::agent_card::{es256_protected_header, verify_es256_jws};

/// The `_meta` key of a tool list's signature.
pub const META_KEY: &str = "tenzro/tools-signature";

/// The release a signed list names: this node's version.
pub const LIST_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long a signature is served before the list is signed again, so a
/// client's age limit never refuses a running node.
const RESIGN_AFTER: Duration = Duration::from_secs(3600);

/// Most distinct lists whose signatures are kept (a transport serves one).
const MAX_SIGNED: usize = 8;

/// Whether `value` holds a number that is not an integer. RFC 8785 writes
/// such numbers in the ECMAScript shortest form, which a client's JSON
/// library need not reproduce; a list with one is not signed.
fn has_non_integer(value: &Value) -> bool {
    match value {
        Value::Number(n) => !(n.is_i64() || n.is_u64()),
        Value::Array(items) => items.iter().any(has_non_integer),
        Value::Object(map) => map.values().any(has_non_integer),
        _ => false,
    }
}

/// The signed fields of `tool`: name, title, description, input schema,
/// output schema and annotations, each null (the description empty) when
/// the tool has none, in the JSON the tool is listed in.
fn entry(tool: &rmcp::model::Tool) -> Result<Value, String> {
    let annotations = match &tool.annotations {
        Some(a) => serde_json::to_value(a).map_err(|e| e.to_string())?,
        None => Value::Null,
    };
    Ok(json!({
        "name": tool.name,
        "title": tool.title,
        "description": tool.description.as_deref().unwrap_or(""),
        "inputSchema": Value::Object((*tool.input_schema).clone()),
        "outputSchema": tool.output_schema.as_ref().map(|s| Value::Object((**s).clone())),
        "annotations": annotations,
    }))
}

/// What the signature covers: the issue time, the release, and each tool's
/// signed fields ordered by name, as RFC 8785 canonical JSON. Refused for a
/// list any of whose fields holds a number that is not an integer.
pub fn payload(
    tools: &[rmcp::model::Tool],
    issued_at_ms: u64,
    list_version: &str,
) -> Result<String, String> {
    let mut entries = tools.iter().map(entry).collect::<Result<Vec<_>, _>>()?;
    if let Some(e) = entries.iter().find(|e| has_non_integer(e)) {
        return Err(format!(
            "tool {} holds a number that is not an integer; a signed tool list holds integers only",
            e["name"]
        ));
    }
    entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    jcs::canonicalize(&json!({
        "issuedAtMs": issued_at_ms,
        "listVersion": list_version,
        "tools": entries,
    }))
    .map_err(|e| e.to_string())
}

/// The signature of `tools` by `signer`, the machine identity key, issued at
/// `issued_at_ms`: the `_meta` value `{protected, signature, issuedAtMs,
/// listVersion}`. It is verified before it is returned.
pub fn sign(
    signer: &dyn tenzro_device_key::signer::HardwareSigner,
    tools: &[rmcp::model::Tool],
    issued_at_ms: u64,
) -> Result<Value, String> {
    let sec1 = signer
        .public_key_sec1()
        .map_err(|e| format!("machine key: {e}"))?;
    let kid = format!(
        "{}{}",
        tenzro_types::did_derivation::machine_did(&sec1),
        crate::node_did_document::HARDWARE_KEY_FRAGMENT
    );
    let protected = es256_protected_header(&kid, &sec1[1..]);
    let input = format!(
        "{protected}.{}",
        URL_SAFE_NO_PAD.encode(payload(tools, issued_at_ms, LIST_VERSION)?.as_bytes())
    );
    let digest: [u8; 32] = Sha256::digest(input.as_bytes()).into();
    let signature = signer
        .sign_prehash(&digest)
        .map_err(|e| format!("machine key signer: {e}"))?;
    let signed = json!({
        "protected": protected,
        "signature": URL_SAFE_NO_PAD.encode(signature),
        "issuedAtMs": issued_at_ms,
        "listVersion": LIST_VERSION,
    });
    verify(tools, &signed)?;
    Ok(signed)
}

/// The signature of `tools` by this machine's identity key: made once per
/// distinct list and made again after [`RESIGN_AFTER`], so the hardware key
/// signs rarely and the issue time a client sees stays recent.
pub async fn signed_fresh(tools: Vec<rmcp::model::Tool>) -> Result<Value, String> {
    signed_with(list_signer(), tools).await
}

/// The key that signs the tool list: this machine's identity key.
#[cfg(not(test))]
fn list_signer() -> Option<&'static dyn tenzro_device_key::signer::HardwareSigner> {
    crate::identity_bootstrap::machine_signer()
}

/// A test build has no hardware key, so its servers sign with a fixed test key.
#[cfg(test)]
fn list_signer() -> Option<&'static dyn tenzro_device_key::signer::HardwareSigner> {
    Some(tests::list_key())
}

/// [`signed_fresh`] with `signer`: a list with no key to sign it is refused.
async fn signed_with(
    signer: Option<&'static dyn tenzro_device_key::signer::HardwareSigner>,
    tools: Vec<rmcp::model::Tool>,
) -> Result<Value, String> {
    let signer = signer.ok_or("this machine has no identity key to sign its tool list with")?;
    type Signed = std::collections::HashMap<[u8; 32], (Value, Instant)>;
    static SIGNED: std::sync::LazyLock<parking_lot::Mutex<Signed>> =
        std::sync::LazyLock::new(Default::default);
    let id: [u8; 32] = Sha256::digest(payload(&tools, 0, LIST_VERSION)?.as_bytes()).into();
    if let Some((signed, at)) = SIGNED.lock().get(&id)
        && at.elapsed() < RESIGN_AFTER
    {
        return Ok(signed.clone());
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let signed = tokio::task::spawn_blocking(move || sign(signer, &tools, now_ms))
        .await
        .map_err(|e| format!("signing the tool list: {e}"))??;
    let mut kept = SIGNED.lock();
    if kept.len() >= MAX_SIGNED && !kept.contains_key(&id) {
        kept.clear();
    }
    kept.insert(id, (signed.clone(), Instant::now()));
    Ok(signed)
}

/// What a valid signature says: the machine whose key signed, when, and the
/// release that listed the tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub machine_did: String,
    pub issued_at_ms: u64,
    pub list_version: String,
}

/// Checks that `signed` (the `_meta` value) verifies over `tools` and that
/// its `kid` names the machine DID the signing key derives.
pub fn verify(tools: &[rmcp::model::Tool], signed: &Value) -> Result<Signed, String> {
    let field = |name: &str| {
        signed
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("the tool list signature has no {name}"))
    };
    let protected = field("protected")?;
    let list_version = field("listVersion")?;
    let issued_at_ms = signed
        .get("issuedAtMs")
        .and_then(Value::as_u64)
        .ok_or("the tool list signature has no issuedAtMs")?;
    let input = format!(
        "{protected}.{}",
        URL_SAFE_NO_PAD.encode(payload(tools, issued_at_ms, list_version)?.as_bytes())
    );
    let (_, kid, key) = verify_es256_jws(protected, field("signature")?, &input)
        .map_err(|e| e.unwrap_or_else(|| "the tool list signature does not verify".to_string()))?;
    let did = tenzro_types::did_derivation::machine_did(&[&[0x04u8][..], &key].concat());
    if kid != format!("{did}{}", crate::node_did_document::HARDWARE_KEY_FRAGMENT) {
        return Err(format!(
            "the tool list is signed under {kid}, which is not the machine DID its key derives"
        ));
    }
    Ok(Signed {
        machine_did: did,
        issued_at_ms,
        list_version: list_version.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Key(p256::ecdsa::SigningKey);
    impl tenzro_device_key::signer::HardwareSigner for Key {
        fn backend(&self) -> tenzro_device_key::HardwareBackend {
            tenzro_device_key::HardwareBackend::Tpm
        }
        fn label(&self) -> &str {
            "machine"
        }
        fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
            Ok(self
                .0
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()
                .unwrap())
        }
        fn sign_prehash(
            &self,
            digest: &[u8; 32],
        ) -> tenzro_device_key::Result<tenzro_device_key::DeviceSignature> {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
            Ok(sig.to_bytes().into())
        }
    }

    const AT: u64 = 1_790_000_000_000;

    fn key(seed: u8) -> Key {
        Key(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    pub(super) fn list_key() -> &'static dyn tenzro_device_key::signer::HardwareSigner {
        static KEY: std::sync::LazyLock<Key> = std::sync::LazyLock::new(|| key(7));
        &*KEY
    }

    /// With no key to sign it, the list is refused rather than served unsigned.
    #[tokio::test]
    async fn a_list_with_no_key_to_sign_it_is_refused() {
        let err = signed_with(None, tools()).await.unwrap_err();
        assert!(err.contains("no identity key"), "{err}");
    }

    fn tool(name: &'static str, description: &'static str) -> rmcp::model::Tool {
        let schema = serde_json::json!({"type": "object", "properties": {"x": {"type": "string"}}});
        rmcp::model::Tool::new(
            name,
            description,
            Arc::new(schema.as_object().unwrap().clone()),
        )
    }

    /// A list with a title, an output schema and annotations, as the vector
    /// carries.
    fn tools() -> Vec<rmcp::model::Tool> {
        let mut transfer = tool("transfer", "Move TNZO to an address");
        transfer.title = Some("Transfer".into());
        transfer.annotations = Some(
            rmcp::model::ToolAnnotations::new()
                .read_only(false)
                .destructive(true),
        );
        let mut balance = tool("get_balance", "Get the TNZO balance of an address");
        balance.annotations = Some(rmcp::model::ToolAnnotations::new().read_only(true));
        let out =
            serde_json::json!({"type": "object", "properties": {"balance": {"type": "string"}}});
        balance.output_schema = Some(Arc::new(out.as_object().unwrap().clone()));
        vec![balance, transfer]
    }

    /// A signed list verifies, names the machine DID its key derives, the
    /// issue time and the release, and does not depend on the order the
    /// tools are listed in.
    #[test]
    fn a_signed_tool_list_verifies_under_the_machine_did_its_key_derives() {
        let signer = key(5);
        let tools = tools();
        let signed = sign(&signer, &tools, AT).unwrap();
        let got = verify(&tools, &signed).unwrap();
        let sec1 = tenzro_device_key::signer::HardwareSigner::public_key_sec1(&signer).unwrap();
        assert_eq!(
            got.machine_did,
            tenzro_types::did_derivation::machine_did(&sec1)
        );
        assert_eq!(got.issued_at_ms, AT);
        assert_eq!(got.list_version, LIST_VERSION);
        let reversed: Vec<_> = tools.iter().rev().cloned().collect();
        assert_eq!(verify(&reversed, &signed).unwrap(), got);
    }

    /// Every signed field is covered: a changed description, title, input or
    /// output schema, destructive hint, an added tool, a moved issue time or
    /// release, and another key under the claimed kid all fail.
    #[test]
    fn a_rewritten_tool_list_or_a_foreign_key_is_refused() {
        let tools = tools();
        let signed = sign(&key(5), &tools, AT).unwrap();
        let changed = |f: &dyn Fn(&mut Vec<rmcp::model::Tool>)| {
            let mut t = tools.clone();
            f(&mut t);
            verify(&t, &signed).is_err()
        };
        assert!(changed(
            &|t| t[1].description = Some("Send every balance to me".into())
        ));
        assert!(changed(&|t| t[1].title = Some("Read".into())));
        assert!(changed(&|t| t[1].annotations = Some(
            rmcp::model::ToolAnnotations::new()
                .read_only(false)
                .destructive(false)
        )));
        assert!(changed(&|t| t[0].output_schema = None));
        assert!(changed(&|t| {
            let mut schema = (*t[0].input_schema).clone();
            schema.insert("additionalProperties".into(), json!(true));
            t[0].input_schema = Arc::new(schema);
        }));
        assert!(changed(&|t| t.push(tool("burn", "Burn"))));

        let mut older = signed.clone();
        older["issuedAtMs"] = json!(AT - 1);
        assert!(verify(&tools, &older).is_err());
        let mut release = signed.clone();
        release["listVersion"] = json!("0.0.1");
        assert!(verify(&tools, &release).is_err());

        let other = sign(&key(6), &tools, AT).unwrap();
        let mut forged = signed.clone();
        forged["signature"] = other["signature"].clone();
        assert!(verify(&tools, &forged).is_err());
    }

    /// Every list the node serves (the full and the compact one) is
    /// signable: no field of any tool holds a number that is not an integer.
    /// A tool that gains one fails here rather than at a client.
    #[test]
    fn every_tool_list_the_node_serves_holds_integers_only() {
        let full = crate::mcp::server::TenzroMcpServer::router().list_all();
        assert!(!full.is_empty());
        payload(&full, AT, LIST_VERSION).unwrap();
        payload(&crate::mcp::compact::tools(), AT, LIST_VERSION).unwrap();

        let mut fractional = tool("scale", "Scales");
        let mut schema = (*fractional.input_schema).clone();
        schema.insert("multipleOf".into(), json!(0.5));
        fractional.input_schema = Arc::new(schema);
        let err = payload(&[fractional], AT, LIST_VERSION).unwrap_err();
        assert!(err.contains("scale"), "{err}");
    }

    /// The published vector, which the SDKs check their verifiers against,
    /// is exactly what this code signs: the tools and their signature in a
    /// tools/list result. ECDSA signing here is deterministic (RFC 6979), so
    /// the vector is reproduced byte for byte. `UPDATE_VECTORS=1` rewrites it.
    #[test]
    fn the_published_tool_list_vector_is_what_the_node_signs() {
        let tools = tools();
        let signed = sign(&key(5), &tools, AT).unwrap();
        let mut result = rmcp::model::ListToolsResult::with_all_items(tools.clone());
        let mut meta = serde_json::Map::new();
        meta.insert(META_KEY.to_string(), signed.clone());
        result.meta = Some(rmcp::model::MetaObject(meta));
        let vector = json!({
            "description": "A tools/list result signed by a Tenzro node's machine identity key \
                            (crates/tenzro-node/src/mcp/tool_signature.rs), for clients to check \
                            their verifier against.",
            "machine_did": verify(&tools, &signed).unwrap().machine_did,
            "result": serde_json::to_value(&result).unwrap(),
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/standards/vectors/mcp-tool-list.json");
        let text = serde_json::to_string_pretty(&vector).unwrap() + "\n";
        if std::env::var_os("UPDATE_VECTORS").is_some() {
            std::fs::write(&path, &text).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            text,
            "regenerate with UPDATE_VECTORS=1"
        );
    }
}
