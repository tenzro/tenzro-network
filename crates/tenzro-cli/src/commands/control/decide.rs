//! `control_decide`: the operator's answer to a condition the node lists.
//!
//! A condition that asks (`needs: "passkey"`) is approved with an assertion
//! of the operator's passkey over its challenge, or declined, through the
//! node's `tenzro_submitApproval`. Approving runs what the condition asks
//! for, so it also needs `confirm: "decide"`; without an assertion the
//! answer is `needs_passkey` with the challenge to sign. A condition that
//! does not ask is acknowledged through `tenzro_acknowledgeCondition`.

use serde_json::{Value, json};

use super::{Helper, INVALID_PARAMS, REFUSED, error};

/// The reason an acknowledgement carries when the caller gives none.
const ACKNOWLEDGED: &str = "Seen in Tenzro Control";

impl Helper {
    /// `control_decide {id, approve, confirm?, assertion?, reason?}`.
    pub(super) async fn decide(&self, params: &Value) -> Result<Value, Value> {
        let id = params
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| error(INVALID_PARAMS, "id names the condition"))?;
        let approve = params
            .get("approve")
            .and_then(Value::as_bool)
            .ok_or_else(|| error(INVALID_PARAMS, "approve is true or false"))?;
        let until = self.node_has_until();
        let rows = match self
            .ask_node("tenzro_listConditions", json!([]), until)
            .await
        {
            Some(Ok(rows)) => rows,
            Some(Err(refused)) => return Err(refused),
            None => return Err(error(REFUSED, "This machine's node is not answering.")),
        };
        let row = rows
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == id))
            .ok_or_else(|| {
                error(
                    INVALID_PARAMS,
                    &format!("No open condition has the id {id}."),
                )
            })?;

        let (method, asked) = if row["needs"] == "passkey" {
            if !approve {
                (
                    "tenzro_submitApproval",
                    json!({ "condition_id": id, "approve": false }),
                )
            } else if params.get("confirm").and_then(Value::as_str) != Some("decide") {
                return Err(error(
                    REFUSED,
                    "Approving runs what the condition asks for: send it again with confirm set to \"decide\"",
                ));
            } else if let Some(assertion) = params.get("assertion") {
                (
                    "tenzro_submitApproval",
                    json!({ "condition_id": id, "approve": true, "assertion": assertion }),
                )
            } else {
                return Ok(json!({
                    "state": "needs_passkey",
                    "ceremony": null,
                    "challenge": row["challenge"],
                    "rp_id": row["rp_id"],
                    "reason": "Approve with the operator's passkey: sign the challenge and send the assertion",
                }));
            }
        } else {
            let reason = params
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or(ACKNOWLEDGED);
            (
                "tenzro_acknowledgeCondition",
                json!({ "id": id, "since": row["since"], "reason": reason }),
            )
        };
        Ok(match self.ask_node(method, asked, until).await {
            Some(Ok(_)) => json!({ "state": "done", "ceremony": null, "reason": null }),
            Some(Err(refused)) => json!({
                "state": "failed",
                "ceremony": null,
                "reason": refused.get("message"),
            }),
            None => json!({
                "state": "failed",
                "ceremony": null,
                "reason": "This machine's node is not answering.",
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{helper, machine};
    use super::*;
    use crate::rpc::nonce_and_chain_id_tests::node_answering;

    const ROWS: &str = r#"[
        {"id":"update:0.2.9","kind":"update","code":"security_update","severity":"warning",
         "title":"Tenzro 0.2.9 is ready","detail":"","since":"2026-11-16T09:00:00Z","ack":null,
         "needs":"passkey","challenge":"q83vEjRWeJA","rp_id":"wallet.tenzro.com"},
        {"id":"follow","kind":"follow","code":"catching_up","severity":"info",
         "title":"Catching up","detail":"","since":"2026-11-16T08:00:00Z","ack":null}
    ]"#;

    async fn decide(node: &str, params: Value) -> Value {
        let line =
            json!({ "jsonrpc": "2.0", "id": 1, "method": "control_decide", "params": params });
        let answer = helper(node, machine())
            .answer(line.to_string().as_bytes())
            .await
            .unwrap();
        serde_json::from_str(&answer).unwrap()
    }

    #[tokio::test]
    async fn approving_a_condition_that_asks_needs_its_name_then_a_passkey() {
        let node = node_answering(&[
            ("tenzro_listConditions", ROWS),
            ("tenzro_submitApproval", r#"{"ok":true,"approved":true}"#),
        ])
        .await;
        let refused = decide(&node, json!({ "id": "update:0.2.9", "approve": true })).await;
        assert_eq!(refused["error"]["code"], REFUSED);

        let sign = decide(
            &node,
            json!({ "id": "update:0.2.9", "approve": true, "confirm": "decide" }),
        )
        .await;
        assert_eq!(sign["result"]["state"], "needs_passkey");
        assert_eq!(sign["result"]["challenge"], "q83vEjRWeJA");
        assert_eq!(sign["result"]["rp_id"], "wallet.tenzro.com");

        let assertion = json!({ "credential_id": "a", "authenticator_data": "b", "client_data_json": "c", "signature": "d" });
        let done = decide(
            &node,
            json!({ "id": "update:0.2.9", "approve": true, "confirm": "decide", "assertion": assertion }),
        )
        .await;
        assert_eq!(
            done["result"],
            json!({ "state": "done", "ceremony": null, "reason": null })
        );
        let declined = decide(&node, json!({ "id": "update:0.2.9", "approve": false })).await;
        assert_eq!(declined["result"]["state"], "done");
    }

    #[tokio::test]
    async fn a_condition_that_does_not_ask_is_acknowledged_and_a_refusal_is_told() {
        let node = node_answering(&[
            ("tenzro_listConditions", ROWS),
            (
                "tenzro_acknowledgeCondition",
                r#"{"ok":true,"id":"follow"}"#,
            ),
        ])
        .await;
        let done = decide(&node, json!({ "id": "follow", "approve": true })).await;
        assert_eq!(done["result"]["state"], "done");

        let missing = decide(&node, json!({ "id": "quorum", "approve": true })).await;
        assert_eq!(
            missing["error"],
            json!({ "code": INVALID_PARAMS, "message": "No open condition has the id quorum." })
        );
        let bad = decide(&node, json!({ "id": "follow" })).await;
        assert_eq!(bad["error"]["code"], INVALID_PARAMS);

        // The stand-in answers no approval, so the node's refusal is the reason.
        let refused = node_answering(&[("tenzro_listConditions", ROWS)]).await;
        let failed = decide(&refused, json!({ "id": "update:0.2.9", "approve": false })).await;
        assert_eq!(failed["result"]["state"], "failed");
        assert!(failed["result"]["reason"].is_string(), "{failed}");
    }
}
