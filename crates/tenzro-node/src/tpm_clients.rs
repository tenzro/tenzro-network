//! `tenzro-node tpm clients`: the machines a TPM provider signs for, listed,
//! added and removed by command instead of by editing the provider file by
//! hand. The file stays the record: the command writes its `[[clients]]`,
//! keeps every other line and comment, and a running provider picks the
//! change up by itself.

use std::path::Path;

use crate::error::{NodeError, Result};
use crate::remote_tpm::{ClientEntry, ProviderFile, enrolled_passkeys};

/// The passkey key a registration (the `PublicKeyCredential` JSON a browser's
/// `navigator.credentials.create` returns, as `toJSON()` writes it) carries:
/// read from its authenticator data, checked to be a P-256 key created for
/// `rp_id` on its own origin with a person present. Returned as hex `x || y`.
///
/// Enrolling from the registration takes the key the passkey gave when it
/// was made, not one recovered later from a signature (which yields two
/// candidates). The challenge is not checked: nothing was issued for it, and
/// a registration copied from elsewhere enrols only a key whose private half
/// the copier does not hold.
pub fn passkey_from_registration(registration: &str, rp_id: &str) -> Result<String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let bad = |why: String| NodeError::Config(format!("the registration: {why}"));
    let json: serde_json::Value =
        serde_json::from_str(registration).map_err(|e| bad(format!("not JSON: {e}")))?;
    let field = |name: &str| -> Result<Vec<u8>> {
        let text = json
            .get("response")
            .and_then(|r| r.get(name))
            .and_then(|v| v.as_str())
            .ok_or_else(|| bad(format!("no response.{name}")))?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text.trim_end_matches('='))
            .map_err(|e| bad(format!("response.{name} is not base64url: {e}")))
    };
    let client_data = field("clientDataJSON")?;
    let client: serde_json::Value = serde_json::from_slice(&client_data)
        .map_err(|e| bad(format!("clientDataJSON is not JSON: {e}")))?;
    if client.get("type").and_then(|v| v.as_str()) != Some("webauthn.create") {
        return Err(bad("it is not from a passkey's creation".into()));
    }
    if client.get("crossOrigin").and_then(|v| v.as_bool()) == Some(true) {
        return Err(bad("it was made inside a cross-origin frame".into()));
    }
    let origin = client.get("origin").and_then(|v| v.as_str()).unwrap_or("");
    let own_origin = origin == format!("https://{rp_id}")
        || (rp_id == "localhost"
            && (origin == "http://localhost"
                || origin
                    .strip_prefix("http://localhost:")
                    .is_some_and(|port| port.parse::<u16>().is_ok())));
    if !own_origin {
        return Err(bad(format!(
            "it was made on {origin:?}, not on the relying party's own origin https://{rp_id}"
        )));
    }
    let client_data_hash: [u8; 32] = Sha256::digest(&client_data).into();
    let facts = tenzro_auth::parse_attestation(
        &field("attestationObject")?,
        &client_data_hash,
        &[],
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
    .map_err(|e| bad(e.to_string()))?;
    let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if facts.rp_id_hash != rp_id_hash {
        return Err(bad(format!(
            "the passkey was created for another relying party than {rp_id}"
        )));
    }
    if !facts.user_present {
        return Err(bad(
            "no person was present when the passkey was created".into()
        ));
    }
    match facts.credential_key {
        tenzro_auth::CredentialKey::P256(sec1) => Ok(hex::encode(&sec1[1..])),
        tenzro_auth::CredentialKey::Rsa { .. } => Err(bad(
            "the passkey is an RSA key; a grant is signed with a P-256 (ES256) passkey".into(),
        )),
    }
}

/// What each field of a client entry means, for `list` and the help text.
pub const FIELD_NOTES: &str = "\
label               the key label a grant from this passkey opens: the key the client machine signs with
rp_id               the passkey's relying party id (the site it was created on)
passkey_public_key  the operator passkey's P-256 public key, hex x || y, from when it was created
derived             whether the client may also use keys derived from this machine's root \
(validator, VRF, sealing and access-token keys); no unless the client is a validator";

/// The clients `text` (a provider file) enrols, checked as the provider
/// checks them.
pub fn list(text: &str) -> Result<Vec<ClientEntry>> {
    let file = parse(text)?;
    enrolled_passkeys(&file)?;
    Ok(file.clients)
}

/// `text` with `new` enrolled (passkeys for one label). A label enrolled
/// for the first time takes two passkeys, from two of the operator's
/// devices, so losing one device does not lock the machine out; `one_device`
/// accepts a single one knowingly. The result is checked as the provider
/// will read it; nothing else in the file changes.
pub fn add(text: &str, new: &[ClientEntry], one_device: bool) -> Result<String> {
    let first = new
        .first()
        .ok_or_else(|| NodeError::Config("no passkey to enrol".into()))?;
    if new.iter().any(|c| c.label != first.label) {
        return Err(NodeError::Config(
            "one enrolment is for one key label".into(),
        ));
    }
    for c in new {
        crate::remote_tpm::enrolled_passkey(c)?;
    }
    let enrolled_before = match text.trim().is_empty() {
        true => 0,
        false => toml::from_str::<toml::Value>(text)
            .ok()
            .and_then(|v| v.get("clients").and_then(|c| c.as_array()).cloned())
            .map(|a| {
                a.iter()
                    .filter(|t| t.get("label").and_then(|l| l.as_str()) == Some(&first.label))
                    .count()
            })
            .unwrap_or(0),
    };
    if enrolled_before + new.len() < 2 && !one_device {
        return Err(NodeError::Config(format!(
            "{:?} would have one passkey: enrol a second from another of your devices in the              same command (--registration twice), or pass --one-device to accept that losing              that device locks the machine out until it is enrolled again",
            first.label
        )));
    }
    let mut doc = edit(text)?;
    let clients = clients_of(&mut doc)?;
    for client in new {
        let mut table = toml_edit::Table::new();
        table.insert("label", toml_edit::value(client.label.as_str()));
        table.insert("rp_id", toml_edit::value(client.rp_id.as_str()));
        table.insert(
            "passkey_public_key",
            toml_edit::value(client.passkey_public_key.as_str()),
        );
        table.insert("derived", toml_edit::value(client.derived));
        clients.push(table);
    }
    let out = doc.to_string();
    list(&out)?;
    Ok(out)
}

/// `text` without the clients for `label` (with `passkey_public_key`, only
/// that passkey's). Refused when none matches.
pub fn remove(text: &str, label: &str, passkey_public_key: Option<&str>) -> Result<String> {
    let key = passkey_public_key.map(normal_key).transpose()?;
    let mut doc = edit(text)?;
    let clients = clients_of(&mut doc)?;
    let before = clients.len();
    clients.retain(|t| {
        let same_label = t.get("label").and_then(|v| v.as_str()) == Some(label);
        let same_key = match &key {
            None => true,
            Some(k) => {
                t.get("passkey_public_key")
                    .and_then(|v| v.as_str())
                    .map(normal_key)
                    .and_then(|r| r.ok())
                    .as_ref()
                    == Some(k)
            }
        };
        !(same_label && same_key)
    });
    if clients.len() == before {
        return Err(NodeError::Config(match passkey_public_key {
            None => format!("no client is enrolled for the key label {label:?}"),
            Some(_) => format!("that passkey is not enrolled for the key label {label:?}"),
        }));
    }
    // Every client gone: the file keeps naming them, as an empty list.
    if doc
        .get("clients")
        .and_then(|c| c.as_array_of_tables())
        .is_some_and(|c| c.is_empty())
    {
        doc.insert("clients", toml_edit::value(toml_edit::Array::new()));
    }
    let out = doc.to_string();
    list(&out)?;
    Ok(out)
}

/// Writes `text` to `path` in one step: a sibling file, then a rename, so a
/// provider reading the file sees the old list or the new one, never half.
/// The file keeps its permissions.
pub fn write(path: &Path, text: &str) -> Result<()> {
    let tmp = path.with_extension("toml.new");
    let io = |e: std::io::Error| NodeError::Config(format!("{}: {e}", path.display()));
    std::fs::write(&tmp, text).map_err(io)?;
    if let Ok(meta) = std::fs::metadata(path) {
        std::fs::set_permissions(&tmp, meta.permissions()).map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)
}

fn parse(text: &str) -> Result<ProviderFile> {
    toml::from_str(text).map_err(|e| NodeError::Config(format!("the provider file: {e}")))
}

fn edit(text: &str) -> Result<toml_edit::DocumentMut> {
    text.parse()
        .map_err(|e| NodeError::Config(format!("the provider file: {e}")))
}

fn clients_of(doc: &mut toml_edit::DocumentMut) -> Result<&mut toml_edit::ArrayOfTables> {
    doc.entry("clients")
        .or_insert(toml_edit::Item::ArrayOfTables(Default::default()))
        .as_array_of_tables_mut()
        .ok_or_else(|| {
            NodeError::Config("the provider file's clients are not a [[clients]] list".into())
        })
}

/// A passkey key as compared: lower-case hex `x || y`.
fn normal_key(k: &str) -> Result<String> {
    let raw = hex::decode(k.trim_start_matches("0x"))
        .map_err(|e| NodeError::Config(format!("passkey_public_key: {e}")))?;
    match raw.len() {
        64 => Ok(hex::encode(raw)),
        65 if raw[0] == 0x04 => Ok(hex::encode(&raw[1..])),
        _ => Err(NodeError::Config(
            "passkey_public_key is not a P-256 key (x || y, 64 bytes)".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A passkey public key: a real P-256 point, hex x || y.
    fn key(seed: u8) -> String {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let sk = p256::SecretKey::from_slice(&[seed; 32]).unwrap();
        hex::encode(&sk.public_key().to_sec1_point(false).as_bytes()[1..])
    }

    fn client(label: &str, seed: u8) -> ClientEntry {
        ClientEntry {
            passkey_public_key: key(seed),
            rp_id: "control.tenzro.com".into(),
            label: label.into(),
            derived: false,
        }
    }

    const FILE: &str = "\
# The machines this TPM signs for.
listen = [\"100.64.0.2:7400\"]
per_minute = 120 # a busy validator

[[clients]]
# the Pi in the hall
label = \"pi-hall\"
rp_id = \"control.tenzro.com\"
passkey_public_key = \"PI_KEY\"
";

    fn file() -> String {
        FILE.replace("PI_KEY", &key(1))
    }

    #[test]
    fn adding_a_client_keeps_every_other_line_and_comment() {
        let out = add(&file(), &[client("laptop", 2)], true).unwrap();
        assert!(out.starts_with(&file()), "{out}");
        let clients = list(&out).unwrap();
        assert_eq!(
            clients.iter().map(|c| c.label.as_str()).collect::<Vec<_>>(),
            ["pi-hall", "laptop"]
        );
        assert!(out.contains("per_minute = 120 # a busy validator"));
    }

    #[test]
    fn a_second_passkey_for_one_label_is_the_operators_other_device() {
        let out = add(&file(), &[client("pi-hall", 3)], false).unwrap();
        assert_eq!(list(&out).unwrap().len(), 2);
        // The same passkey twice for one label is refused.
        assert!(add(&file(), &[client("pi-hall", 1)], false).is_err());
    }

    #[test]
    fn a_new_label_takes_two_devices_unless_one_is_accepted() {
        let err = add(&file(), &[client("laptop", 2)], false).unwrap_err();
        assert!(err.to_string().contains("--one-device"), "{err}");
        let out = add(&file(), &[client("laptop", 2), client("laptop", 3)], false).unwrap();
        assert_eq!(list(&out).unwrap().len(), 3);
        assert!(add(&file(), &[client("laptop", 2)], true).is_ok());
        assert!(add(&file(), &[client("laptop", 2), client("other", 3)], true).is_err());
        assert!(add(&file(), &[], true).is_err());
    }

    #[test]
    fn a_client_the_provider_would_refuse_is_not_written() {
        let mut bad = client("x", 2);
        bad.passkey_public_key = "ab".repeat(64);
        assert!(
            add(&file(), &[bad], true).is_err(),
            "not a point on the curve"
        );
        let mut bad = client("x", 2);
        bad.rp_id.clear();
        assert!(add(&file(), &[bad], true).is_err());
        let mut bad = client("", 2);
        bad.rp_id = "r".into();
        assert!(add(&file(), &[bad], true).is_err());
    }

    #[test]
    fn removing_takes_out_a_label_or_one_of_its_passkeys() {
        let two = add(&file(), &[client("pi-hall", 3)], false).unwrap();
        let one = remove(&two, "pi-hall", Some(&format!("04{}", key(3)))).unwrap();
        assert_eq!(list(&one).unwrap().len(), 1);
        assert_eq!(list(&one).unwrap()[0].passkey_public_key, key(1));
        let none = remove(&two, "pi-hall", None).unwrap();
        assert!(list(&none).unwrap().is_empty());
        assert!(none.contains("# The machines this TPM signs for."));
        assert!(none.contains("clients = []"), "{none}");
        assert!(remove(&file(), "laptop", None).is_err());
        assert!(remove(&file(), "pi-hall", Some(&key(9))).is_err());
    }

    #[test]
    fn a_file_with_no_clients_yet_takes_its_first() {
        let out = add("listen = []\nclients = []\n", &[client("pi", 4)], true).unwrap_err();
        // An inline empty array is not a [[clients]] list: said so, not rewritten.
        assert!(out.to_string().contains("[[clients]]"), "{out}");
        let out = add("listen = []\n", &[client("pi", 4)], true).unwrap();
        assert_eq!(list(&out).unwrap().len(), 1);
    }

    #[test]
    fn the_file_is_replaced_in_one_step_with_its_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.toml");
        std::fs::write(&path, file()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let out = add(&file(), &[client("laptop", 2)], true).unwrap();
        write(&path, &out).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), out);
        assert!(!dir.path().join("provider.toml.new").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// A registration as a browser returns it: a "none" attestation over
    /// authenticator data carrying a P-256 credential for `rp_id`.
    fn registration(rp_id: &str, origin: &str, kind: &str, seed: u8, flags: u8) -> String {
        use base64::Engine;
        use ciborium::value::Value;
        use p256::elliptic_curve::sec1::ToSec1Point;
        use sha2::{Digest, Sha256};
        let sk = p256::SecretKey::from_slice(&[seed; 32]).unwrap();
        let point = sk.public_key().to_sec1_point(false);
        let cose = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ]);
        let mut cose_bytes = Vec::new();
        ciborium::into_writer(&cose, &mut cose_bytes).unwrap();
        let mut auth = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend_from_slice(&0u32.to_be_bytes());
        auth.extend_from_slice(&[0u8; 16]);
        auth.extend_from_slice(&16u16.to_be_bytes());
        auth.extend_from_slice(&[seed; 16]);
        auth.extend_from_slice(&cose_bytes);
        let object = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth)),
        ]);
        let mut object_bytes = Vec::new();
        ciborium::into_writer(&object, &mut object_bytes).unwrap();
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let client =
            serde_json::json!({"type": kind, "challenge": b64(&[1; 32]), "origin": origin});
        serde_json::json!({
            "id": b64(&[seed; 16]), "type": "public-key",
            "response": {
                "clientDataJSON": b64(client.to_string().as_bytes()),
                "attestationObject": b64(&object_bytes),
            },
        })
        .to_string()
    }

    /// UP and AT set.
    const PRESENT: u8 = 0x01 | 0x40;

    #[test]
    fn a_passkey_is_enrolled_from_the_key_it_gave_when_it_was_made() {
        let rp = "control.tenzro.com";
        let reg = registration(
            rp,
            "https://control.tenzro.com",
            "webauthn.create",
            5,
            PRESENT,
        );
        assert_eq!(passkey_from_registration(&reg, rp).unwrap(), key(5));
        // On localhost, the page the operator ran on this machine.
        let reg = registration(
            "localhost",
            "http://localhost:8080",
            "webauthn.create",
            6,
            PRESENT,
        );
        assert_eq!(
            passkey_from_registration(&reg, "localhost").unwrap(),
            key(6)
        );
    }

    #[test]
    fn a_registration_for_another_site_or_ceremony_is_refused() {
        let rp = "control.tenzro.com";
        for reg in [
            registration(
                "evil.example",
                "https://control.tenzro.com",
                "webauthn.create",
                5,
                PRESENT,
            ),
            registration(rp, "https://evil.example", "webauthn.create", 5, PRESENT),
            registration(rp, "https://control.tenzro.com", "webauthn.get", 5, PRESENT),
            registration(rp, "https://control.tenzro.com", "webauthn.create", 5, 0x40),
            registration(
                "localhost",
                "http://localhost:x",
                "webauthn.create",
                5,
                PRESENT,
            ),
            "{}".to_string(),
        ] {
            assert!(
                passkey_from_registration(
                    &reg,
                    if reg.contains("localhost") {
                        "localhost"
                    } else {
                        rp
                    }
                )
                .is_err(),
                "{reg}"
            );
        }
    }
}
