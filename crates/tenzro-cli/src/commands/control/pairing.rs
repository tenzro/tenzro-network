//! `control_pairDevice`: pair another device with this node.
//!
//! The node runs the pairing (`tenzro_pairDevice`) and answers the ceremony
//! the device scans or types: a link, its QR rows and a short code. Pairing
//! grants that device access to this node, so starting one needs
//! `confirm: "pairDevice"`; asking where a pairing stands (`{id}`) does not.
//!
//! `control_listPairedDevices` and `control_unpairDevice {id}` list and
//! remove the devices paired with the node. The node answers both only to
//! its administrators and the paired devices, so the helper asks with the
//! operator's session; removing one ends that device's access, so it needs
//! `confirm: "unpairDevice"`.

use serde_json::{Value, json};

use super::{Helper, INVALID_PARAMS, METHOD_NOT_FOUND, REFUSED, error};

impl Helper {
    /// `control_pairDevice {confirm: "pairDevice"}` starts a pairing;
    /// `control_pairDevice {id}` answers where it stands.
    pub(super) async fn pair_device(&self, params: &Value) -> Result<Value, Value> {
        let asked = match params.get("id") {
            Some(id) => json!({ "id": id }),
            None if params.get("confirm").and_then(Value::as_str) == Some("pairDevice") => {
                json!({})
            }
            None => {
                return Err(error(
                    REFUSED,
                    "Pairing grants a device access to this node: send it again with confirm set to \"pairDevice\"",
                ));
            }
        };
        match self
            .ask_node("tenzro_pairDevice", asked, self.node_has_until())
            .await
        {
            Some(answer) => answer,
            None => Err(error(REFUSED, "This machine's node is not answering.")),
        }
    }

    /// `control_listPairedDevices`: the node's `{devices: [...]}`.
    pub(super) async fn list_paired_devices(&self) -> Result<Value, Value> {
        self.ask_for_operator("tenzro_listPairedDevices", json!({}))
            .await
    }

    /// `control_unpairDevice {id, confirm: "unpairDevice"}`.
    pub(super) async fn unpair_device(&self, params: &Value) -> Result<Value, Value> {
        let id = params
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| error(INVALID_PARAMS, "id names the paired device"))?;
        if params.get("confirm").and_then(Value::as_str) != Some("unpairDevice") {
            return Err(error(
                REFUSED,
                "Removing a device ends its access to this node: send it again with confirm set to \"unpairDevice\"",
            ));
        }
        self.ask_for_operator("tenzro_unpairDevice", json!({ "id": id }))
            .await
    }

    /// One of the node's calls for its administrators, made with the
    /// operator's session. A node that refuses is told as a refusal; one
    /// without the call says so as a method it does not serve.
    async fn ask_for_operator(&self, method: &str, params: Value) -> Result<Value, Value> {
        match self.ask_node(method, params, self.node_has_until()).await {
            Some(Ok(answer)) => Ok(answer),
            Some(Err(refused)) if refused["code"] == METHOD_NOT_FOUND => Err(error(
                METHOD_NOT_FOUND,
                "This machine's node does not pair devices.",
            )),
            Some(Err(refused)) => {
                let why = refused["message"].as_str().unwrap_or("no reason given");
                Err(error(
                    REFUSED,
                    &format!("This machine's node refused: {why}"),
                ))
            }
            None => Err(error(REFUSED, "This machine's node is not answering.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{helper, machine};
    use super::*;
    use crate::rpc::nonce_and_chain_id_tests::node_answering;

    const CEREMONY: &str = r#"{"id":"p1","state":"waiting","url":"https://tenzro.com/pair#c","qr":"https://tenzro.com/pair#c","qr_rows":["101"],"code":"ABCD-EFGH","reason":"","expires_in_secs":600}"#;

    async fn ask(node: &str, params: Value) -> Value {
        call(node, "control_pairDevice", params).await
    }

    async fn call(node: &str, method: &str, params: Value) -> Value {
        let line = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let answer = helper(node, machine())
            .answer(line.to_string().as_bytes())
            .await
            .unwrap();
        serde_json::from_str(&answer).unwrap()
    }

    #[tokio::test]
    async fn a_pairing_starts_only_when_confirmed_and_its_ceremony_comes_back() {
        let node = node_answering(&[("tenzro_pairDevice", CEREMONY)]).await;
        for params in [
            json!({}),
            json!({ "confirm": "bindDevice" }),
            json!({ "confirm": true }),
        ] {
            let refused = ask(&node, params.clone()).await;
            assert_eq!(refused["error"]["code"], REFUSED, "{params}");
        }
        let started = ask(&node, json!({ "confirm": "pairDevice" })).await;
        assert_eq!(
            started["result"],
            serde_json::from_str::<Value>(CEREMONY).unwrap()
        );
        let standing = ask(&node, json!({ "id": "p1" })).await;
        assert_eq!(standing["result"]["state"], "waiting");

        let silent = ask("http://127.0.0.1:1", json!({ "confirm": "pairDevice" })).await;
        assert_eq!(
            silent["error"],
            json!({ "code": REFUSED, "message": "This machine's node is not answering." })
        );
    }

    const DEVICES: &str = r#"{"devices":[{"id":"d1","label":"Phone","kind":"phone","created_at":"2026-11-17T09:00:00Z","this_device":false}]}"#;

    #[tokio::test]
    async fn the_paired_devices_are_listed_and_removed_with_the_operators_say() {
        let node = node_answering(&[
            ("tenzro_listPairedDevices", DEVICES),
            ("tenzro_unpairDevice", r#"{"removed":true}"#),
        ])
        .await;
        let listed = call(&node, "control_listPairedDevices", json!({})).await;
        assert_eq!(
            listed["result"],
            serde_json::from_str::<Value>(DEVICES).unwrap()
        );
        for params in [
            json!({ "id": "d1" }),
            json!({ "id": "d1", "confirm": "pairDevice" }),
        ] {
            let refused = call(&node, "control_unpairDevice", params.clone()).await;
            assert_eq!(refused["error"]["code"], REFUSED, "{params}");
        }
        let removed = call(
            &node,
            "control_unpairDevice",
            json!({ "id": "d1", "confirm": "unpairDevice" }),
        )
        .await;
        assert_eq!(removed["result"], json!({ "removed": true }));
    }

    #[tokio::test]
    async fn a_node_that_refuses_the_devices_is_told_as_a_refusal() {
        let node = node_answering(&[(
            "tenzro_listPairedDevices",
            r#"{"code":-32003,"message":"administrators only"}"#,
        )])
        .await;
        let refused = call(&node, "control_listPairedDevices", json!({})).await;
        assert!(refused.get("result").is_none(), "{refused}");
        assert_eq!(
            refused["error"],
            json!({ "code": REFUSED, "message": "This machine's node refused: administrators only" })
        );
        let no_pairing = node_answering(&[]).await;
        let unpaired = call(&no_pairing, "control_listPairedDevices", json!({})).await;
        assert_eq!(unpaired["error"]["code"], METHOD_NOT_FOUND);
    }
}
