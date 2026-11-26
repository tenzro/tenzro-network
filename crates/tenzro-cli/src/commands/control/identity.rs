//! `control_identity`: the operator this machine was set up for and the
//! devices that approve for them.

use serde_json::{Value, json};

use super::Helper;

impl Helper {
    /// The identity from the CLI's configuration and the devices the node
    /// has bound to it. `devices` is `null` when the operator has no identity
    /// yet or the node gave no list.
    pub(super) async fn identity(&self) -> Value {
        let local = (self.local)(false).await;
        let devices = match &local.did {
            Some(did) => {
                let asked = json!({ "identity_did": did });
                self.read("tenzro_listBoundDevices", asked, self.node_has_until())
                    .await
                    .and_then(|listed| devices(&listed))
            }
            None => None,
        };
        json!({
            "did": local.did,
            "wallet_address": local.wallet_address,
            "keys_in": local.keys_in,
            "key_holder_label": local.key_holder_label,
            "devices": devices,
        })
    }
}

/// The devices in the node's answer to `tenzro_listBoundDevices`, as the
/// apps list them. Every bound device approves with a passkey.
fn devices(listed: &Value) -> Option<Value> {
    let devices = listed.get("devices")?.as_array()?;
    Some(
        devices
            .iter()
            .map(|device| {
                let created_at = device
                    .get("bound_at_ms")
                    .and_then(Value::as_i64)
                    .and_then(chrono::DateTime::from_timestamp_millis)
                    .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
                json!({
                    "id": device.get("credential_id"),
                    "label": device.get("label"),
                    "kind": "passkey",
                    "created_at": created_at,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::{helper, machine};
    use super::*;
    use crate::rpc::nonce_and_chain_id_tests::node_answering;

    #[test]
    fn a_bound_device_reads_as_a_passkey_with_its_time() {
        let listed = json!({
            "identity_did": "did:tenzro:human:saved",
            "count": 1,
            "devices": [{
                "credential_id": "a1b2",
                "label": "Phone",
                "hardware_bound": true,
                "bound_at_ms": 1_763_200_800_000_i64,
            }],
        });
        assert_eq!(
            devices(&listed),
            Some(json!([{
                "id": "a1b2",
                "label": "Phone",
                "kind": "passkey",
                "created_at": "2025-11-15T10:00:00Z",
            }]))
        );
        assert_eq!(devices(&json!({ "count": 0 })), None);
    }

    #[tokio::test]
    async fn the_identity_is_the_saved_one_with_the_nodes_devices() {
        let node = node_answering(&[(
            "tenzro_listBoundDevices",
            r#"{"count":1,"devices":[{"credential_id":"c3","label":"Laptop","bound_at_ms":0}]}"#,
        )])
        .await;
        let answer = helper(&node, machine())
            .answer(br#"{"jsonrpc":"2.0","id":3,"method":"control_identity"}"#)
            .await
            .unwrap();
        let answer: Value = serde_json::from_str(&answer).unwrap();
        assert_eq!(
            answer["result"],
            json!({
                "did": "did:tenzro:human:saved",
                "wallet_address": "0x00000000000000000000000000000000000000cc",
                "keys_in": "tpm",
                "key_holder_label": null,
                "devices": [{
                    "id": "c3",
                    "label": "Laptop",
                    "kind": "passkey",
                    "created_at": "1970-01-01T00:00:00Z",
                }],
            })
        );
    }

    #[tokio::test]
    async fn without_a_node_the_identity_has_no_device_list() {
        let mut local = machine();
        local.key_holder_label = Some("Desk".into());
        let answer = helper("http://127.0.0.1:1", local)
            .answer(br#"{"jsonrpc":"2.0","id":4,"method":"control_identity"}"#)
            .await
            .unwrap();
        let answer: Value = serde_json::from_str(&answer).unwrap();
        assert_eq!(answer["result"]["did"], "did:tenzro:human:saved");
        assert_eq!(answer["result"]["key_holder_label"], "Desk");
        assert_eq!(answer["result"]["devices"], Value::Null);
    }
}
