//! `tenzro_getAccountOutflow { account }`: an account's opt-in outflow policy
//! (cap, window, hold, guardian, any loosening waiting out the hold) and its
//! queued payments, read from chain state. Read-only.

use std::sync::Arc;

use serde_json::Value;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn bad(message: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.to_string(),
        data: None,
    }
}

/// `tenzro_getAccountOutflow`.
pub(crate) async fn handle_get_account_outflow(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let account = params
        .as_ref()
        .and_then(|p| {
            p.get("account")
                .or_else(|| p.as_array().and_then(|a| a.first()))
        })
        .and_then(Value::as_str)
        .ok_or_else(|| bad("account (hex) is required"))?;
    let account =
        hex::decode(account.trim_start_matches("0x")).map_err(|_| bad("account is not hex"))?;
    let chain = crate::rpc::chain_state(node)?;
    let now_ms = tenzro_types::primitives::Timestamp::now().0;
    Ok(tenzro_vm::account_outflow::view(&chain, &account, now_ms))
}

/// `tenzro_checkDelegateTarget { address }`: whether a delegate's code is on
/// the governed list, and whether the network enforces the list.
pub(crate) async fn handle_check_delegate_target(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let target = params
        .as_ref()
        .and_then(|p| {
            p.get("address")
                .or_else(|| p.as_array().and_then(|a| a.first()))
        })
        .and_then(Value::as_str)
        .ok_or_else(|| bad("address (hex) is required"))?;
    let bytes =
        hex::decode(target.trim_start_matches("0x")).map_err(|_| bad("address is not hex"))?;
    let chain = crate::rpc::chain_state(node)?;
    let clears = bytes.iter().all(|b| *b == 0);
    Ok(serde_json::json!({
        "address": hex::encode(&bytes),
        "allowlist_enforced": tenzro_vm::native::network_param(
            &chain,
            tenzro_vm::delegation_guard::ALLOWLIST_ENFORCED_PARAM
        ) != 0,
        "listed": tenzro_vm::delegation_guard::delegate_listed(&chain, &bytes),
        "clears": clears,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn the_account_is_required_and_must_be_hex() {
        let (node, _tmp) = crate::bare_node().await;
        for params in [
            None,
            Some(json!({})),
            Some(json!({"account": 5})),
            Some(json!([])),
        ] {
            let e = handle_get_account_outflow(&node, params).await.unwrap_err();
            assert_eq!(e.code, -32602);
            assert!(e.message.contains("required"), "{}", e.message);
        }
        let e = handle_get_account_outflow(&node, Some(json!({"account": "0xzz"})))
            .await
            .unwrap_err();
        assert_eq!((e.code, e.message.as_str()), (-32602, "account is not hex"));
    }

    #[tokio::test]
    async fn a_valid_account_needs_chain_storage() {
        let (node, _tmp) = crate::bare_node().await;
        let e = handle_get_account_outflow(&node, Some(json!({"account": "0xab"})))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32000);
        let e = handle_get_account_outflow(&node, Some(json!(["ab"])))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32000, "the positional form is read the same way");
    }

    #[tokio::test]
    async fn the_delegate_check_requires_a_hex_address_and_chain_storage() {
        let (node, _tmp) = crate::bare_node().await;
        let e = handle_check_delegate_target(&node, None).await.unwrap_err();
        assert_eq!(e.code, -32602);
        let e = handle_check_delegate_target(&node, Some(json!({"address": "not hex"})))
            .await
            .unwrap_err();
        assert_eq!((e.code, e.message.as_str()), (-32602, "address is not hex"));
        let e = handle_check_delegate_target(&node, Some(json!({"address": "00"})))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32000);
    }
}
