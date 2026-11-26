//! `control_listConditions`: the conditions waiting for the operator, as the
//! console shows them to decide on.
//!
//! The node lists its conditions only to who may administer it, so the
//! helper asks with the operator's session and returns what the console
//! needs of each. The list is answered to whoever the helper admits, like
//! every `control_` call: any program running as the operator's user reads
//! it.

use serde_json::{Map, Value, json};

use super::{Helper, METHOD_NOT_FOUND, REFUSED, error};

/// What the console shows of a condition and needs to decide on it.
const SHOWN: &[&str] = &[
    "id",
    "kind",
    "code",
    "severity",
    "title",
    "detail",
    "since",
    "ack",
    "needs",
    "challenge",
    "rp_id",
];

impl Helper {
    /// `control_listConditions`. A node that refuses the list is told as a
    /// refusal, never as an empty list; one that has no list says so as a
    /// method it does not serve.
    pub(super) async fn list_conditions(&self) -> Result<Value, Value> {
        let until = self.node_has_until();
        let rows = match self
            .ask_node("tenzro_listConditions", json!([]), until)
            .await
        {
            Some(Ok(rows)) => rows,
            Some(Err(refused)) if refused["code"] == METHOD_NOT_FOUND => {
                return Err(error(
                    METHOD_NOT_FOUND,
                    "This machine's node serves no list of conditions.",
                ));
            }
            Some(Err(refused)) => {
                let why = refused["message"].as_str().unwrap_or("no reason given");
                return Err(error(
                    REFUSED,
                    &format!("This machine's node did not list its conditions: {why}"),
                ));
            }
            None => return Err(error(REFUSED, "This machine's node is not answering.")),
        };
        let rows = rows
            .as_array()
            .ok_or_else(|| error(REFUSED, "This machine's node gave no list of conditions."))?;
        Ok(rows.iter().map(shown).collect())
    }
}

/// The fields of `row` the console needs; the rest stay with the helper.
fn shown(row: &Value) -> Value {
    let fields: Map<String, Value> = SHOWN
        .iter()
        .filter_map(|&field| Some((field.to_string(), row.get(field)?.clone())))
        .collect();
    Value::Object(fields)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{helper, machine};
    use super::*;
    use crate::rpc::nonce_and_chain_id_tests::node_answering;

    async fn list(node: &str) -> Value {
        let helper = helper(node, machine());
        let line = helper
            .answer(br#"{"id":1,"method":"control_listConditions"}"#)
            .await
            .expect("an answer");
        serde_json::from_str(&line).unwrap()
    }

    #[tokio::test]
    async fn the_console_gets_the_conditions_it_decides_on_and_no_more() {
        let node = node_answering(&[(
            "tenzro_listConditions",
            r#"[{"id":"update:0.2.9","kind":"update","code":"security_update",
                "severity":"warning","title":"Tenzro 0.2.9 is ready","detail":"",
                "since":"2026-11-16T09:00:00Z","ack":null,"needs":"passkey",
                "challenge":"q83vEjRWeJA","rp_id":"wallet.tenzro.com",
                "operator_did":"did:tenzro:human:op","internal":{"path":"/var/lib/tenzro"}}]"#,
        )])
        .await;
        assert_eq!(
            list(&node).await["result"],
            json!([{
                "id": "update:0.2.9",
                "kind": "update",
                "code": "security_update",
                "severity": "warning",
                "title": "Tenzro 0.2.9 is ready",
                "detail": "",
                "since": "2026-11-16T09:00:00Z",
                "ack": null,
                "needs": "passkey",
                "challenge": "q83vEjRWeJA",
                "rp_id": "wallet.tenzro.com",
            }])
        );
    }

    #[tokio::test]
    async fn a_node_that_refuses_the_list_is_told_as_a_refusal() {
        let node = node_answering(&[(
            "tenzro_listConditions",
            r#"{"code":-32003,"message":"this session may not read the conditions"}"#,
        )])
        .await;
        let refused = list(&node).await;
        assert!(refused.get("result").is_none(), "{refused}");
        assert_eq!(refused["error"]["code"], REFUSED);
        assert_eq!(
            refused["error"]["message"],
            "This machine's node did not list its conditions: this session may not read the conditions"
        );
        // A node without the list says it serves none, as a node without a
        // method does.
        let unlisted = list(&node_answering(&[]).await).await;
        assert!(unlisted.get("result").is_none(), "{unlisted}");
        assert_eq!(unlisted["error"]["code"], METHOD_NOT_FOUND);
    }
}
